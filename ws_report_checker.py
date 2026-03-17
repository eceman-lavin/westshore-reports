#!/usr/bin/env python3
"""
WestShore Report Inbox Checker
───────────────────────────────
Scans Gmail for WestShore daily reports, detects CSV header changes over time,
and flags any days where a report was not received.

Header comparison uses the LATEST received report as the current standard.
Walking backwards, any email whose headers differ from the latest is flagged
and shown as a diff against current — so you see what changed and exactly when.

For missing-days analysis the script auto-detects when each report "really
started" (most recent gap > GAP_DAYS followed by MIN_RUN consecutive emails),
so new reports like FHF or WIT don't show every day before their launch as missing.

Usage:
    python ws_report_checker.py               # default 90-day lookback
    python ws_report_checker.py --days 180    # custom lookback window
    python ws_report_checker.py --gap 14      # custom gap threshold in days (default: 21)
"""

import argparse
import base64
import contextlib
import csv
import io
import sys
from collections import Counter
from datetime import date, datetime, timedelta
from email.mime.text import MIMEText
from email.utils import parsedate_to_datetime

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from funcs.gmail import build_gmail_service

# ── Report configuration ───────────────────────────────────────────────────────

SENDER    = "noreply@westshorehome.com"
NOTIFY_TO = "e.ceman@lavinmedia.com"   # recipient for --notify emails

MWF = {0, 2, 4}   # Monday=0, Wednesday=2, Friday=4

REPORTS = {
    # schedule omitted → daily (every calendar day expected)
    "CPL Inquiries": {
        "subject": "Lavin CPL - Inquiries (Report Out)",
        # Freshness check: majority of rows must be from yesterday (email date − 1)
        "data_date_check": {"column": "Created Time", "date_format": "%m/%d/%Y %I:%M %p"},
    },
    "CPL Sets":      {"subject": "Lavin CPL- Sets (Report Out)"},  # no space before "Sets" — intentional
    "CPL Issued":    {"subject": "Lavin CPL - Issued (Report Out)"},
    "FHF Issued":    {"subject": "Lavin FHF - Issued (Report Out)"},
    # schedule={MWF} → only Mon/Wed/Fri expected
    "WIT Issued":    {"subject": "Lavin (WIT)-Issued",    "schedule": MWF},
    "WIT Sets":      {"subject": "Lavin (WIT)-Sets",      "schedule": MWF},
    "WIT Inquiries": {"subject": "Lavin (WIT)-Inquiries", "schedule": MWF},
}

# ── Active-start detection config ─────────────────────────────────────────────
#
# A new "active run" is declared when both conditions are met:
#   1. There is a gap of at least GAP_DAYS between two consecutive emails.
#   2. At least MIN_RUN emails follow that gap (confirms it's a real resumption,
#      not a one-off).
#
# The effective start = first email after the LAST qualifying gap.
# If no qualifying gap exists → effective start = first email in the lookback.

DEFAULT_GAP_DAYS = 21   # days of silence that signals a pause/new start
DEFAULT_MIN_RUN  = 3    # min emails after the gap to confirm active delivery

# ── Gmail helpers ──────────────────────────────────────────────────────────────

def fetch_all_messages(service, query: str) -> list:
    """Return all message stubs matching the Gmail search query (handles pagination)."""
    results = []
    params = {"userId": "me", "q": query, "maxResults": 500}
    while True:
        resp = service.users().messages().list(**params).execute()
        results.extend(resp.get("messages", []))
        token = resp.get("nextPageToken")
        if not token:
            break
        params["pageToken"] = token
    return results


def get_full_message(service, msg_id: str) -> dict:
    return service.users().messages().get(
        userId="me", id=msg_id, format="full"
    ).execute()


def parse_date_from_header(value: str) -> date | None:
    try:
        return parsedate_to_datetime(value).date()
    except Exception:
        return None


def find_csv_parts(parts: list) -> list:
    """Recursively collect all CSV attachment parts from a message payload."""
    found = []
    for part in parts:
        filename = part.get("filename", "")
        mime = part.get("mimeType", "")
        if filename.lower().endswith(".csv") or mime in ("text/csv", "application/csv"):
            found.append(part)
        if "parts" in part:
            found.extend(find_csv_parts(part["parts"]))
    return found


def _get_csv_bytes(service, msg_id: str, part: dict) -> tuple:
    """Return (raw_csv_bytes, error_str) from a CSV attachment part."""
    body = part.get("body", {})
    att_id = body.get("attachmentId")

    if att_id:
        att = service.users().messages().attachments().get(
            userId="me", messageId=msg_id, id=att_id
        ).execute()
        raw = att.get("data", "")
    else:
        raw = body.get("data", "")

    if not raw:
        return None, "empty attachment body"

    return base64.urlsafe_b64decode(raw), None


def decode_csv_part(service, msg_id: str, part: dict) -> tuple:
    """Return (headers_list, error_str) from a CSV attachment part."""
    csv_bytes, err = _get_csv_bytes(service, msg_id, part)
    if err:
        return None, err
    return _parse_csv_headers(csv_bytes)


def _parse_csv_headers(csv_bytes: bytes) -> tuple:
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            text = csv_bytes.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        return None, "could not decode CSV"

    reader = csv.reader(io.StringIO(text))
    try:
        row = next(reader)
        return [h.strip() for h in row if h.strip()], None
    except StopIteration:
        return None, "CSV is empty"


def _parse_csv_data_dates(csv_bytes: bytes, column: str, date_format: str) -> dict:
    """
    Parse every data row of a CSV and return {date: row_count} for the given column.
    Rows whose date can't be parsed are counted under the key None.
    """
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            text = csv_bytes.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        return {}

    counts: Counter = Counter()
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        raw = (row.get(column) or "").strip()
        if not raw:
            counts[None] += 1
            continue
        try:
            counts[datetime.strptime(raw, date_format).date()] += 1
        except ValueError:
            counts[None] += 1

    return dict(counts)


# ── Active-start detection ─────────────────────────────────────────────────────

def detect_active_start(
    received_dates: list,
    gap_days: int = DEFAULT_GAP_DAYS,
    min_run: int = DEFAULT_MIN_RUN,
) -> tuple:
    """
    Find the effective start of the most recent active delivery run.

    Scans backwards through sorted dates looking for the last gap > gap_days
    that is followed by at least min_run emails. Returns:

        (effective_start_date, explanation_string)

    Logic:
    - Walk backward through gaps between consecutive dates.
    - At each gap > gap_days, check if there are >= min_run dates after it.
    - First one that qualifies = effective start.
    - If nothing qualifies, return the very first date (whole window is one run).
    """
    if not received_dates:
        return None, "no data"

    dates = sorted(received_dates)

    # Walk from the most recent gap backwards
    for i in range(len(dates) - 1, 0, -1):
        gap = (dates[i] - dates[i - 1]).days
        if gap > gap_days:
            run_after = dates[i:]
            if len(run_after) >= min_run:
                return (
                    dates[i],
                    f"gap of {gap}d detected before {dates[i]} "
                    f"({len(run_after)} emails in current run)",
                )
            # Gap found but too few emails after it — keep scanning for an
            # earlier gap that has enough emails following it.

    # No qualifying gap found — the whole lookback window is one continuous run
    return (
        dates[0],
        f"no gap >{gap_days}d found — continuous run since first observed email",
    )


# ── Analysis ───────────────────────────────────────────────────────────────────

def analyze_report(
    service,
    name: str,
    config: dict,
    since: date,
    today: date,
    gap_days: int,
) -> None:
    subject         = config["subject"]
    schedule        = config.get("schedule")       # set of weekday ints, or None = every day
    data_date_check = config.get("data_date_check")  # {"column": ..., "date_format": ...} or None
    BAR = "─" * 68

    print(f"\n{'═' * 68}")
    print(f"  {name}  —  \"{subject}\"")
    print(f"{'═' * 68}")

    after_str = since.strftime("%Y/%m/%d")
    query = f'from:{SENDER} subject:"{subject}" after:{after_str}'
    print(f"  Query  : {query}")

    stubs = fetch_all_messages(service, query)
    print(f"  Found  : {len(stubs)} email(s)\n")

    # ── Collect (email_date, csv_headers) ─────────────────────────────────────
    records: list[tuple[date, list[str]]] = []
    data_dist: dict[date, dict] = {}  # email_date → {data_date: row_count}; only for reports with data_date_check
    errors: list[str] = []
    seen_dates: set[date] = set()
    duplicates: list[date] = []

    for stub in stubs:
        msg = get_full_message(service, stub["id"])

        meta = {h["name"]: h["value"] for h in msg["payload"].get("headers", [])}
        msg_date = parse_date_from_header(meta.get("Date", ""))
        if not msg_date:
            errors.append(f"! could not parse date for msg {stub['id']}")
            continue

        payload = msg.get("payload", {})
        csv_parts = find_csv_parts(payload.get("parts", [payload]))

        if not csv_parts:
            errors.append(f"! {msg_date}: no CSV attachment found")
            continue

        if msg_date in seen_dates:
            duplicates.append(msg_date)
        seen_dates.add(msg_date)

        # Get raw bytes once; use for both header parse and optional data-date parse
        csv_bytes, err = _get_csv_bytes(service, stub["id"], csv_parts[0])
        if err:
            errors.append(f"! {msg_date}: {err}")
            continue

        headers, err = _parse_csv_headers(csv_bytes)
        if err:
            errors.append(f"! {msg_date}: {err}")
            continue

        records.append((msg_date, headers))

        if data_date_check:
            data_dist[msg_date] = _parse_csv_data_dates(
                csv_bytes, data_date_check["column"], data_date_check["date_format"]
            )

    records.sort(key=lambda x: x[0])

    if errors:
        print(f"  Warnings ({len(errors)}):")
        for e in errors:
            print(f"    {e}")
        print()

    if duplicates:
        print(f"  Duplicate sends — {len(set(duplicates))} day(s) received more than once:")
        for d in sorted(set(duplicates)):
            print(f"    • {d.strftime('%Y-%m-%d (%a)')}")
        print()

    if not records:
        print("  No usable emails found in the lookback window.")
        return

    print(f"  Oldest email : {records[0][0]}")
    print(f"  Newest email : {records[-1][0]}")
    print(f"  Usable total : {len(records)}")

    # ── Active-start detection ─────────────────────────────────────────────────
    all_dates = [r[0] for r in records]
    active_start, start_reason = detect_active_start(all_dates, gap_days=gap_days)
    print(f"  Active since : {active_start}  ({start_reason})")
    print()

    # ── 1. Header changes ──────────────────────────────────────────────────────
    print(f"  HEADER CHANGES")
    print(f"  {BAR}")

    # Build chronological list of distinct header versions (full lookback)
    versions: list[tuple[date, list[str]]] = []
    prev_key = None
    for msg_date, hdrs in records:
        key = tuple(hdrs)
        if key != prev_key:
            versions.append((msg_date, hdrs))
            prev_key = key

    # Latest received headers are the standard — everything is diffed against them
    current_hdrs = versions[-1][1]
    current_date = records[-1][0]  # date of the most recent email, not when this version first appeared
    print(f"  Current standard: headers as of {current_date} ({len(current_hdrs)} columns)")
    for col in current_hdrs:
        print(f"    · \"{col}\"")
    print()

    if len(versions) == 1:
        print(f"  ✓ No prior versions found — headers unchanged since {versions[0][0]} (first observed).")
    else:
        # Walk backwards through older versions, diff each against current
        older = versions[:-1]  # everything except the current/latest
        print(f"  ⚠  {len(older)} earlier version(s) found (shown as diff vs current):\n")
        for i, (first_seen, hdrs) in enumerate(reversed(older)):
            # "in use until" = day before the next version started
            next_version_date = versions[len(older) - i][0]
            in_use_until = next_version_date - timedelta(days=1)
            print(f"  [superseded {next_version_date}]  in use: {first_seen} → {in_use_until}")
            _print_diff(current_hdrs, hdrs, indent="    ", label="vs current")
            print()

    # ── 2. Missing days (from active start only) ───────────────────────────────
    schedule_label = "Mon/Wed/Fri" if schedule == MWF else "daily"
    print(f"\n  MISSING DAYS  (from active start {active_start} through yesterday, {schedule_label})")
    print(f"  {BAR}")

    received = {r[0] for r in records}
    check_from  = active_start
    check_until = today - timedelta(days=1)

    if check_from > check_until:
        print(f"  Active run started today or yesterday — nothing to check yet.")
        return

    missing = []
    total_days = 0
    d = check_from
    while d <= check_until:
        if schedule is None or d.weekday() in schedule:
            total_days += 1
            if d not in received:
                missing.append(d)
        d += timedelta(days=1)

    if not missing:
        print(f"  ✓ No missing days — received every day from {check_from} through {check_until}.")
    else:
        gaps = _group_consecutive(missing)
        pct = len(missing) / total_days * 100
        print(f"  ✗ {len(missing)} missing day(s) out of {total_days} ({pct:.1f}% gap rate):\n")
        for gap_start, gap_end in gaps:
            if gap_start == gap_end:
                print(f"    • {gap_start.strftime('%Y-%m-%d (%a)')}")
            else:
                n = (gap_end - gap_start).days + 1
                span = f"{gap_start.strftime('%a')}–{gap_end.strftime('%a')}"
                print(f"    • {gap_start.strftime('%Y-%m-%d')} → {gap_end.strftime('%Y-%m-%d')}  ({n} days, {span})")

    # ── 3. Data freshness check (CPL Inquiries only) ───────────────────────────
    if not data_date_check or not data_dist:
        return

    col = data_date_check["column"]
    print(f"\n  DATA FRESHNESS  (\"{col}\" majority must be from yesterday)")
    print(f"  {BAR}")

    stale = []   # (email_date, total_rows, yesterday_count, actual_majority_date)
    fresh = 0

    for email_date, dist in sorted(data_dist.items()):
        yesterday = email_date - timedelta(days=1)
        total_rows = sum(c for d, c in dist.items() if d is not None)
        if total_rows == 0:
            stale.append((email_date, 0, 0, None))
            continue
        yesterday_count = dist.get(yesterday, 0)
        if yesterday_count > total_rows / 2:
            fresh += 1
        else:
            majority_date = max((d for d in dist if d is not None), key=lambda d: dist[d])
            stale.append((email_date, total_rows, yesterday_count, majority_date))

    total_checked = fresh + len(stale)
    if not stale:
        print(f"  ✓ All {total_checked} emails had fresh data (yesterday's rows in majority).")
    else:
        print(f"  ✓ Fresh : {fresh} of {total_checked} emails")
        print(f"  ✗ Stale : {len(stale)} email(s) — data was NOT from yesterday:\n")
        for email_date, total_rows, yest_count, majority_date in stale:
            yesterday = email_date - timedelta(days=1)
            if majority_date is None:
                detail = "no parseable dates in data"
            else:
                lag = (email_date - majority_date).days - 1   # how many days old the data was
                detail = (
                    f"majority from {majority_date} ({lag}d old) — "
                    f"only {yest_count}/{total_rows} rows from yesterday ({yesterday})"
                )
            print(f"    ✗ {email_date.strftime('%Y-%m-%d (%a)')} — {detail}")


# ── Diff helpers ───────────────────────────────────────────────────────────────

def _print_diff(baseline: list, actual: list, indent: str = "  ", label: str = "") -> None:
    if label:
        print(f"{indent}({label})")

    missing_cols = [c for c in baseline if c not in actual]
    added_cols   = [c for c in actual if c not in baseline]
    reordered    = not missing_cols and not added_cols and baseline != actual

    if not missing_cols and not added_cols and not reordered:
        print(f"{indent}  ✓ Exact match")
        return

    if missing_cols:
        print(f"{indent}  Removed ({len(missing_cols)}):")
        for c in missing_cols:
            print(f"{indent}    − \"{c}\"")
    if added_cols:
        print(f"{indent}  Added ({len(added_cols)}):")
        for c in added_cols:
            print(f"{indent}    + \"{c}\"")
    if reordered:
        print(f"{indent}  Same columns, ORDER changed:")
        for i, (e, a) in enumerate(zip(baseline, actual)):
            if e != a:
                print(f"{indent}    col[{i}]: \"{e}\"  →  \"{a}\"")


def _group_consecutive(dates: list) -> list:
    """Group a sorted list of dates into (start, end) consecutive spans."""
    if not dates:
        return []
    spans = []
    start = end = dates[0]
    for d in dates[1:]:
        if d == end + timedelta(days=1):
            end = d
        else:
            spans.append((start, end))
            start = end = d
    spans.append((start, end))
    return spans


# ── Email notification ─────────────────────────────────────────────────────────

def _send_email(service, subject: str, body: str) -> None:
    msg = MIMEText(body, "plain", "utf-8")
    msg["To"]      = NOTIFY_TO
    msg["Subject"] = subject
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    service.users().messages().send(userId="me", body={"raw": raw}).execute()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Check Gmail inbox for WestShore daily reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Reports checked:\n"
            "  CPL  — Inquiries, Sets, Issued\n"
            "  FHF  — Issued\n"
            "  WIT  — Inquiries, Sets, Issued\n"
            f"Sender: {SENDER}"
        ),
    )
    parser.add_argument(
        "--days",
        type=int,
        default=90,
        help="How many calendar days to look back (default: 90)",
    )
    parser.add_argument(
        "--gap",
        type=int,
        default=DEFAULT_GAP_DAYS,
        help=f"Gap threshold in days for detecting a new active run (default: {DEFAULT_GAP_DAYS})",
    )
    parser.add_argument(
        "--notify",
        action="store_true",
        help=f"Send email to {NOTIFY_TO} if any issues are found (used by the daily scheduled run)",
    )
    args = parser.parse_args()

    # Ensure stdout can handle Unicode (needed when redirected to a file on Windows)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    today = date.today()
    since = today - timedelta(days=args.days)

    print("Authenticating with Gmail...", end=" ", flush=True)
    service = build_gmail_service()
    print("OK\n")

    def _run(out):
        print("=" * 68, file=out)
        print("  WestShore Report Inbox Checker", file=out)
        print("=" * 68, file=out)
        print(f"  Lookback  : {args.days} days  ({since} → {today})", file=out)
        print(f"  Gap limit : {args.gap} days  (gap > this triggers a new active-run start)", file=out)
        print(f"  Sender    : {SENDER}", file=out)
        print(f"  Reports   : {len(REPORTS)} total", file=out)
        print(file=out)
        for report_name, config in REPORTS.items():
            with contextlib.redirect_stdout(out):
                analyze_report(service, report_name, config, since, today, args.gap)
        print(f"\n{'═' * 68}", file=out)
        print("  Done.", file=out)
        print(f"{'═' * 68}\n", file=out)

    if not args.notify:
        _run(sys.stdout)
        return

    # --notify mode: capture output, print it, then email if issues found
    buf = io.StringIO()
    _run(buf)
    output = buf.getvalue()
    print(output)   # always show in terminal too

    has_issues = "✗" in output
    if has_issues:
        subject = f"⚠ WestShore Report Issues — {today}"
        try:
            _send_email(service, subject, output)
            print(f"  Notification sent → {NOTIFY_TO}")
        except Exception as exc:
            print(f"  Failed to send notification email: {exc}")


if __name__ == "__main__":
    main()

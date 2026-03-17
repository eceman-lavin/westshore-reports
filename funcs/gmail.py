import json
import os
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
]

CREDENTIALS_PATH = "creds/personal_gmail_credentials.json"
TOKEN_PATH = "creds/personal_gmail_token.json"


def _write_secrets_to_files():
    """In CI, write env-var secrets to the expected file paths."""
    os.makedirs("creds", exist_ok=True)
    for env_var, path in [
        ("GMAIL_CREDENTIALS", CREDENTIALS_PATH),
        ("GMAIL_TOKEN", TOKEN_PATH),
    ]:
        value = os.environ.get(env_var)
        if value and not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write(value)


def _get_creds():
    """Load or refresh credentials, running the OAuth flow if needed."""
    _write_secrets_to_files()

    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_PATH, "w", encoding="utf-8") as f:
            f.write(creds.to_json())

    return creds


def build_gmail_service():
    """Return an authenticated Gmail API v1 service for e.ceman@lavinmedia.com."""
    return build("gmail", "v1", credentials=_get_creds())

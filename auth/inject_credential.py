"""
Credential injection endpoint for n8n OAuth callback integration.

Accepts a POST to /inject-credential with the Google OAuth tokens obtained
by the n8n OAuth callback workflow, and writes them to the MCP server's
credential store. Protected by INJECT_CREDENTIAL_SECRET env var.
"""

import logging
import os
from datetime import datetime, timedelta

from fastapi.responses import JSONResponse
from google.oauth2.credentials import Credentials
from starlette.requests import Request

from auth.credential_store import get_credential_store

logger = logging.getLogger(__name__)

INJECT_SECRET = os.getenv("INJECT_CREDENTIAL_SECRET", "")

SCOPES = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/spreadsheets",
]


async def inject_credential(request: Request) -> JSONResponse:
    """
    POST /inject-credential
    Headers: X-Inject-Secret: <INJECT_CREDENTIAL_SECRET>
    Body (JSON):
      {
        "email": "user@gmail.com",
        "access_token": "ya29.xxx",
        "refresh_token": "1//xxx",
        "client_id": "xxx.apps.googleusercontent.com",
        "client_secret": "xxx",
        "expires_in": 3599  (optional, seconds until expiry)
      }
    """
    if not INJECT_SECRET:
        return JSONResponse(
            {"error": "Credential injection is disabled (INJECT_CREDENTIAL_SECRET not set)"},
            status_code=403,
        )

    secret = request.headers.get("X-Inject-Secret", "")
    if secret != INJECT_SECRET:
        logger.warning("inject_credential: unauthorized attempt")
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    email = body.get("email", "").strip()
    access_token = body.get("access_token", "").strip()
    refresh_token = body.get("refresh_token", "").strip()
    client_id = body.get("client_id", "").strip()
    client_secret = body.get("client_secret", "").strip()
    expires_in = body.get("expires_in", 3599)

    if not all([email, access_token, refresh_token, client_id, client_secret]):
        return JSONResponse(
            {"error": "Missing required fields: email, access_token, refresh_token, client_id, client_secret"},
            status_code=400,
        )

    expiry = datetime.utcnow() + timedelta(seconds=int(expires_in))

    credentials = Credentials(
        token=access_token,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=client_id,
        client_secret=client_secret,
        scopes=SCOPES,
        expiry=expiry,
    )

    store = get_credential_store()
    success = store.store_credential(email, credentials)

    if success:
        logger.info(f"inject_credential: stored credentials for {email}")
        return JSONResponse({"status": "ok", "email": email})
    else:
        logger.error(f"inject_credential: failed to store credentials for {email}")
        return JSONResponse({"error": "Failed to store credentials"}, status_code=500)

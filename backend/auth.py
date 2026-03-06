"""
auth.py — Token verification middleware.

This module does one job: take an incoming HTTP request,
extract the JWT from the Authorization header, validate it
against the database, and return the user if everything checks out.

The handler functions in routes call require_auth() at the top
of any endpoint that needs a logged-in user. If the token is
missing, expired, or revoked, require_auth() raises an
AuthError which main.py catches and converts to a 401 response.

Nothing in this file knows about signup or signin — that logic
lives in routes/auth_routes.py (Phase 3).
"""

import os
import hashlib
import logging
from datetime import datetime, timezone

import jwt
from dotenv import load_dotenv

import db

load_dotenv()
log = logging.getLogger(__name__)

JWT_SECRET  = os.getenv("JWT_SECRET", "insecure-default-change-me")
JWT_ALGO    = "HS256"


# ─────────────────────────────────────────────────────────────
#  EXCEPTIONS
#  Raising AuthError is how any part of the app signals "401".
#  main.py catches it and writes the HTTP response.
# ─────────────────────────────────────────────────────────────
class AuthError(Exception):
    """Raised when a request fails authentication."""
    def __init__(self, message: str = "Unauthorised"):
        self.message = message
        super().__init__(message)


# ─────────────────────────────────────────────────────────────
#  TOKEN HELPERS
# ─────────────────────────────────────────────────────────────
def hash_token(raw_token: str) -> str:
    """
    SHA-256 hash of the raw JWT string.
    This is what gets stored in the sessions table — never the
    raw token itself. If the database is compromised, the stored
    hashes cannot be used to authenticate as a user.
    """
    return hashlib.sha256(raw_token.encode()).hexdigest()


def decode_token(raw_token: str) -> dict:
    """
    Verify the JWT signature and expiry.
    Returns the payload dict on success.
    Raises AuthError on any failure — expired, bad signature, malformed.
    """
    try:
        payload = jwt.decode(raw_token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired. Please sign in again.")
    except jwt.InvalidTokenError as e:
        log.debug("JWT decode failed: %s", e)
        raise AuthError("Invalid token.")


def extract_token(handler_self) -> str:
    """
    Pull the raw JWT out of the Authorization header.
    Expects the format:  Authorization: Bearer <token>
    Raises AuthError if the header is missing or malformed.
    """
    header = handler_self.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise AuthError("Missing or malformed Authorization header.")
    return header[len("Bearer "):]


# ─────────────────────────────────────────────────────────────
#  MAIN MIDDLEWARE FUNCTION
#  Call this at the top of any route handler that needs auth.
#
#  Returns the full user row as a dict so the route knows
#  who is making the request (user["id"], user["role"], etc.)
#
#  Checks in order:
#    1. Header present and well-formed
#    2. JWT signature valid and not expired
#    3. Session exists in DB and has not been revoked
#    4. User account is active (not suspended/pending)
# ─────────────────────────────────────────────────────────────
def require_auth(handler_self) -> dict:
    """
    Validate the request's Bearer token and return the user dict.

    Usage in a route handler:
        user = require_auth(self)
        # user["id"], user["operator_id"], user["role"] etc. now available
    """
    # Step 1 — extract raw token from header
    raw_token = extract_token(handler_self)

    # Step 2 — verify JWT signature and expiry
    payload = decode_token(raw_token)
    user_id  = payload.get("sub")
    if not user_id:
        raise AuthError("Token payload is missing subject.")

    # Step 3 — check session is in the DB and not revoked
    token_hash = hash_token(raw_token)
    session = db.fetchone(
        """
        SELECT id, revoked, expires_at
        FROM   sessions
        WHERE  token_hash = %s
          AND  user_id    = %s
        """,
        (token_hash, user_id),
    )

    if not session:
        raise AuthError("Session not found. Please sign in again.")

    if session["revoked"]:
        raise AuthError("Session has been revoked. Please sign in again.")

    # Belt-and-braces expiry check (JWT library already checks this,
    # but we double-check against the DB record in case clocks drift)
    now = datetime.now(timezone.utc)
    if session["expires_at"].replace(tzinfo=timezone.utc) < now:
        raise AuthError("Session has expired. Please sign in again.")

    # Step 4 — load user and check account status
    user = db.fetchone(
        """
        SELECT id, operator_id, email, display_name,
               role, organisation, network_scale,
               status, totp_enabled
        FROM   users
        WHERE  id = %s
        """,
        (user_id,),
    )

    if not user:
        raise AuthError("User account no longer exists.")

    if user["status"] == "suspended":
        raise AuthError("Account suspended. Contact an administrator.")

    if user["status"] == "pending":
        raise AuthError("Account pending activation. Check your email.")

    return user
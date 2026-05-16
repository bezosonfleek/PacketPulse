"""
auth.py — Token verification middleware.

JWT is transported via httpOnly cookie (pp_token) set by the server
on login. JavaScript cannot read httpOnly cookies, which eliminates
the XSS token-theft risk present with localStorage.

The Authorization: Bearer header is kept as a fallback so the test
suite and API clients (curl, Postman) continue to work unchanged.

extract_token()  — reads cookie first, header as fallback
require_auth()   — full validation chain, returns user dict
hash_token()     — SHA-256 of raw JWT for DB storage
decode_token()   — verifies JWT signature and expiry
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

JWT_SECRET = os.getenv("JWT_SECRET", "insecure-default-change-me")
JWT_ALGO   = "HS256"

# ─────────────────────────────────────────────────────────────
#  EXCEPTIONS
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
    SHA-256 hash of the raw JWT.
    Stored in the sessions table — never the raw token itself.
    """
    return hashlib.sha256(raw_token.encode()).hexdigest()


def decode_token(raw_token: str) -> dict:
    """
    Verify JWT signature and expiry.
    Returns payload dict on success, raises AuthError on any failure.
    """
    try:
        return jwt.decode(raw_token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired. Please sign in again.")
    except jwt.InvalidTokenError as e:
        log.debug("JWT decode failed: %s", e)
        raise AuthError("Invalid token.")

def extract_token(handler_self) -> str:
    """
    Pull the raw JWT from the request.

    Priority:
      1. pp_token httpOnly cookie — set by the server on login,
                                    invisible to all JavaScript
      2. Authorization: Bearer   — fallback for API clients and
                                   the test suite (no browser cookie)

    Raises AuthError if neither source yields a token.
    """
    # 1. httpOnly cookie
    cookie_header = handler_self.headers.get("Cookie", "")
    if cookie_header:
        for part in cookie_header.split(";"):
            name, _, value = part.strip().partition("=")
            if name.strip() == "pp_token" and value.strip():
                return value.strip()

    # 2. Authorization header fallback
    auth_header = handler_self.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[len("Bearer "):]

    raise AuthError("No authentication token found. Please sign in.")

# ─────────────────────────────────────────────────────────────
#  MAIN MIDDLEWARE
#  Call at the top of any route that needs a logged-in user.
#  Returns the full user row dict on success.
#
#  Validation chain:
#    1. Token present (cookie or header)
#    2. JWT signature valid and not expired
#    3. Session exists in DB and not revoked
#    4. User account is active
# ─────────────────────────────────────────────────────────────
def require_auth(handler_self) -> dict:
    """
    Validate the request token and return the user dict.

    Usage:
        user = require_auth(self)
        # user["id"], user["operator_id"], user["role"] now available
    """
    raw_token = extract_token(handler_self)
    payload   = decode_token(raw_token)
    user_id   = payload.get("sub")

    if not user_id:
        raise AuthError("Token payload is missing subject.")

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

    now = datetime.now(timezone.utc)
    if session["expires_at"].replace(tzinfo=timezone.utc) < now:
        raise AuthError("Session has expired. Please sign in again.")

    user = db.fetchone(
        """
        SELECT id, operator_id, email, display_name,
               role, organisation, network_scale,
               status, totp_enabled, email_verified, created_at
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
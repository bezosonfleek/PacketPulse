"""
routes/auth_routes.py — Signup, login, logout, me endpoints.

Routes handled here:
    POST /api/auth/signup   → create a new operator account
    POST /api/auth/login   → verify credentials, issue JWT
    POST /api/auth/logout  → revoke the current session
    GET  /api/auth/me       → return current user profile

All responses follow the same shape:
    Success: {"data": {...}}
    Error:   {"error": "human readable message"}
"""

import os
import re
import sys
import datetime
import logging
import uuid
import secrets

import bcrypt
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import jwt as pyjwt
from dotenv import load_dotenv

import db
from auth import AuthError, require_auth, hash_token, extract_token

load_dotenv()
log = logging.getLogger(__name__)

JWT_SECRET         = os.getenv("JWT_SECRET", "insecure-default-change-me")
JWT_ALGO           = "HS256"
JWT_EXPIRY_HOURS   = int(os.getenv("JWT_EXPIRY_HOURS", 8))
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", 5))
RATE_LIMIT_SIGNIN  = int(os.getenv("RATE_LIMIT_SIGNIN", 10))


# ─────────────────────────────────────────────────────────────
#  ROUTER
# ─────────────────────────────────────────────────────────────
def handle(path: str, method: str, handler_self) -> bool:
    from main import send_json, send_error, read_json_body

    if path == "/api/auth/signup" and method == "POST":
        _signup(handler_self, read_json_body(handler_self), send_json, send_error)
        return True

    if path == "/api/auth/login" and method == "POST":
        _login(handler_self, read_json_body(handler_self), send_json, send_error)
        return True

    if path == "/api/auth/logout" and method == "POST":
        _logout(handler_self, send_json, send_error)
        return True

    if path == "/api/auth/me" and method == "GET":
        _me(handler_self, send_json, send_error)
        return True

    if path == "/api/auth/profile" and method == "PATCH":
        _update_profile(handler_self, read_json_body(handler_self), send_json, send_error)
        return True

    if path == "/api/auth/change-password" and method == "POST":
        _change_password(handler_self, read_json_body(handler_self), send_json, send_error)
        return True

    if path == "/api/auth/send-verification" and method == "POST":
        _send_verification(handler_self, send_json, send_error)
        return True

    if path == "/api/auth/verify-email" and method == "POST":
        _verify_email(handler_self, read_json_body(handler_self), send_json, send_error)
        return True

    if path == "/api/auth/forgot-password" and method == "POST":
        _forgot_password(handler_self, read_json_body(handler_self), send_json, send_error)
        return True

    if path == "/api/auth/reset-password" and method == "POST":
        _reset_password(handler_self, read_json_body(handler_self), send_json, send_error)
        return True

    return False


# ─────────────────────────────────────────────────────────────
#  VALIDATION
# ─────────────────────────────────────────────────────────────
_EMAIL_RE    = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_OP_ID_RE    = re.compile(r"^[a-zA-Z0-9_.]{3,40}$")
VALID_ROLES  = {"security", "sysadmin", "devops", "other", "admin"}
VALID_SCALES = {"1-10", "11-50", "51-200", "200+"}


def _validate_signup(body: dict) -> list:
    errors = []

    op_id = (body.get("operator_id") or "").strip()
    if not op_id:
        errors.append("Operator ID is required.")
    elif not _OP_ID_RE.match(op_id):
        errors.append("Operator ID must be 3-40 chars: letters, numbers, underscores, dots.")

    email = (body.get("email") or "").strip()
    if not email:
        errors.append("Email is required.")
    elif not _EMAIL_RE.match(email):
        errors.append("Email address is not valid.")

    display_name = (body.get("display_name") or "").strip()
    if not display_name:
        errors.append("Display name is required.")
    elif len(display_name) > 120:
        errors.append("Display name must be 120 characters or fewer.")

    password = body.get("password") or ""
    if not password:
        errors.append("Password is required.")
    elif len(password) < 12:
        errors.append("Password must be at least 12 characters.")

    role = (body.get("role") or "other").strip()
    if role not in VALID_ROLES:
        errors.append(f"Role must be one of: {', '.join(VALID_ROLES)}.")

    scale = (body.get("network_scale") or "").strip()
    if scale and scale not in VALID_SCALES:
        errors.append(f"Network scale must be one of: {', '.join(VALID_SCALES)}.")

    return errors


# ─────────────────────────────────────────────────────────────
#  RATE LIMITING  (DB-backed, per IP, 60-second window)
# ─────────────────────────────────────────────────────────────
def _is_rate_limited(ip: str) -> bool:
    try:
        row = db.fetchone(
            """
            SELECT COUNT(*) AS cnt
            FROM   login_attempts
            WHERE  ip_address   = %s::inet
              AND  attempted_at > NOW() - INTERVAL '60 seconds'
            """,
            (ip,),
        )
        return row and int(row["cnt"]) >= RATE_LIMIT_SIGNIN
    except Exception as e:
        log.warning("Rate limit check failed: %s", e)
        return False  # fail open — never block on a DB error


def _get_client_ip(handler_self) -> str:
    forwarded = handler_self.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return handler_self.client_address[0]


# ─────────────────────────────────────────────────────────────
#  AUDIT LOG  — every login attempt, success or failure
#  Never raises — a log failure must not break the auth flow.
# ─────────────────────────────────────────────────────────────
def _log_attempt(operator_id, ip, user_agent, success, reason):
    try:
        db.execute(
            """
            INSERT INTO login_attempts
              (operator_id, ip_address, user_agent, success, failure_reason)
            VALUES (%s, %s::inet, %s, %s, %s)
            """,
            (operator_id, ip, user_agent, success, reason),
        )
    except Exception as e:
        log.warning("Failed to write login_attempts: %s", e)


# ─────────────────────────────────────────────────────────────
#  POST /api/auth/signup
# ─────────────────────────────────────────────────────────────
def _signup(handler_self, body, send_json, send_error):
    if not body:
        send_error(handler_self, "Request body is required.", 400)
        return

    errors = _validate_signup(body)
    if errors:
        send_error(handler_self, errors[0], 400)
        return

    op_id        = body["operator_id"].strip()
    email        = body["email"].strip().lower()
    display_name = body["display_name"].strip()
    password     = body["password"]
    role         = (body.get("role") or "other").strip()
    org          = (body.get("organisation") or "").strip() or None
    scale        = (body.get("network_scale") or "").strip() or None

    # Uniqueness checks
    if db.fetchone("SELECT id FROM users WHERE operator_id = %s", (op_id,)):
        send_error(handler_self, "Operator ID is already taken.", 409)
        return

    if db.fetchone("SELECT id FROM users WHERE email = %s", (email,)):
        send_error(handler_self, "An account with that email already exists.", 409)
        return

    # Hash password — plain text is gone after this line
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("utf-8")

    # Reference code for the signup success screen
    ref = f"PP-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"

    verify_token = secrets.token_urlsafe(48)

    try:
        new_user = db.execute_returning(
            """
            INSERT INTO users
              (operator_id, email, display_name, password_hash,
               role, organisation, network_scale, status,
               email_verified, email_verify_token, email_verify_expiry)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending',
                    FALSE, %s, NOW() + INTERVAL '24 hours')
            RETURNING id, operator_id, email, display_name, role, status, created_at
            """,
            (op_id, email, display_name, password_hash, role, org, scale, verify_token),
        )
    except Exception as e:
        log.error("Signup DB error: %s", e)
        send_error(handler_self, "Failed to create account. Please try again.", 500)
        return

    log.info("New operator registered: %s (%s)", op_id, email)

    try:
        email_utils.send_verification_email(email, display_name, verify_token)
    except Exception as e:
        log.error("Failed to send verification email to %s: %s", email, e, exc_info=True)

    send_json(handler_self, {
        "data": {
            "message":     "Account created! Check your email to verify your address before logging in.",
            "reference":   ref,
            "operator_id": new_user["operator_id"],
            "status":      new_user["status"],
        }
    }, 201)


# ─────────────────────────────────────────────────────────────
#  POST /api/auth/login
# ─────────────────────────────────────────────────────────────
def _login(handler_self, body, send_json, send_error):
    if not body:
        send_error(handler_self, "Request body is required.", 400)
        return

    op_id    = (body.get("operator_id") or "").strip()
    password = body.get("password") or ""
    ip       = _get_client_ip(handler_self)
    ua       = handler_self.headers.get("User-Agent", "")[:500]

    if not op_id or not password:
        send_error(handler_self, "Operator ID and password are required.", 400)
        return

    # Rate limit before any user lookup
    if _is_rate_limited(ip):
        _log_attempt(op_id, ip, ua, False, "rate_limited")
        send_error(handler_self,
            "Too many attempts. Please wait 60 seconds and try again.", 429)
        return

    # Load user record
    user = db.fetchone(
        """
        SELECT id, operator_id, email, display_name, password_hash,
               status, failed_attempts, locked_until, totp_enabled, role
        FROM   users
        WHERE  operator_id = %s
        """,
        (op_id,),
    )

    if not user:
        _log_attempt(op_id, ip, ua, False, "user_not_found")
        # Dummy bcrypt check — prevents timing attacks that reveal
        # whether an operator_id exists based on response time difference
        bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt(4)))
        send_error(handler_self, "Invalid credentials.", 401)
        return

    # Account state
    if user["status"] == "suspended":
        _log_attempt(op_id, ip, ua, False, "account_suspended")
        send_error(handler_self, "Account suspended. Contact an administrator.", 403)
        return

    if user["status"] == "pending":
        _log_attempt(op_id, ip, ua, False, "account_pending")
        send_error(handler_self, "Account pending activation. Check your email.", 403)
        return

    # Lockout check (uses the stored function from init.sql)
    if db.call_function("SELECT is_account_locked(%s)", (op_id,)):
        _log_attempt(op_id, ip, ua, False, "account_locked")
        send_error(handler_self,
            "Account temporarily locked due to failed attempts. "
            "Try again in 15 minutes.", 403)
        return

    # Password verification
    if not bcrypt.checkpw(password.encode("utf-8"),
                          user["password_hash"].encode("utf-8")):
        db.call_function("SELECT record_failed_login(%s, %s)",
                         (op_id, LOGIN_MAX_ATTEMPTS))
        _log_attempt(op_id, ip, ua, False, "bad_password")
        remaining = max(0, LOGIN_MAX_ATTEMPTS - (user["failed_attempts"] + 1))
        msg = "Invalid credentials."
        if remaining <= 2:
            msg += f" {remaining} attempt(s) remaining before lockout."
        send_error(handler_self, msg, 401)
        return

    # ── Credentials valid ────────────────────────────────────
    db.call_function("SELECT clear_failed_logins(%s)", (op_id,))

    # Build and sign the JWT
    now    = datetime.datetime.now(datetime.timezone.utc)
    expiry = now + datetime.timedelta(hours=JWT_EXPIRY_HOURS)
    raw_token = pyjwt.encode(
        {"sub": str(user["id"]), "iat": now, "exp": expiry, "op": op_id},
        JWT_SECRET,
        algorithm=JWT_ALGO,
    )

    # Persist session (store token hash, not raw token)
    try:
        db.execute(
            """
            INSERT INTO sessions
              (user_id, token_hash, ip_address, user_agent, expires_at)
            VALUES (%s, %s, %s::inet, %s, %s)
            """,
            (str(user["id"]), hash_token(raw_token), ip, ua, expiry),
        )
    except Exception as e:
        log.error("Session insert failed: %s", e)
        send_error(handler_self, "Sign in failed. Please try again.", 500)
        return

    _log_attempt(op_id, ip, ua, True, None)
    log.info("Operator logged in: %s from %s", op_id, ip)

    send_json(handler_self, {
        "data": {
            "token":        raw_token,
            "expires_at":   expiry.isoformat(),
            "operator_id":  user["operator_id"],
            "display_name": user["display_name"],
            "role":         user["role"],
        }
    })


# ─────────────────────────────────────────────────────────────
#  POST /api/auth/logout
# ─────────────────────────────────────────────────────────────
def _logout(handler_self, send_json, send_error):
    try:
        user = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    try:
        raw_token = extract_token(handler_self)
        db.execute(
            """
            UPDATE sessions
            SET    revoked = TRUE, revoked_at = NOW()
            WHERE  token_hash = %s
            """,
            (hash_token(raw_token),),
        )
    except Exception as e:
        log.error("Signout error: %s", e)
        send_error(handler_self, "Signout failed. Please try again.", 500)
        return

    log.info("Operator logged out: %s", user["operator_id"])
    send_json(handler_self, {"data": {"message": "Logged out successfully."}})


# ─────────────────────────────────────────────────────────────
#  GET /api/auth/me
#  Returns the current user's profile — used by the frontend
#  to restore session state on page load without re-logging in.
# ─────────────────────────────────────────────────────────────
def _me(handler_self, send_json, send_error):
    try:
        user = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    send_json(handler_self, {
        "data": {
            "operator_id":    user["operator_id"],
            "email":          user["email"],
            "display_name":   user["display_name"],
            "role":           user["role"],
            "organisation":   user.get("organisation"),
            "network_scale":  user.get("network_scale"),
            "totp_enabled":   user["totp_enabled"],
            "status":         user["status"],
            "email_verified": user.get("email_verified", False),
            "created_at":     user.get("created_at"),
        }
    })


# ─────────────────────────────────────────────────────────────
#  PATCH /api/auth/profile
#  Update display_name, email, organisation, network_scale
# ─────────────────────────────────────────────────────────────
def _update_profile(handler_self, body, send_json, send_error):
    try:
        user = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    if not body:
        send_error(handler_self, "Request body is required.", 400)
        return

    updates = {}
    errors  = []

    # display_name
    if "display_name" in body:
        val = (body["display_name"] or "").strip()
        if not val:
            errors.append("Display name cannot be empty.")
        elif len(val) > 120:
            errors.append("Display name must be 120 characters or fewer.")
        else:
            updates["display_name"] = val

    # email
    if "email" in body:
        val = (body["email"] or "").strip().lower()
        if not val:
            errors.append("Email cannot be empty.")
        elif not _EMAIL_RE.match(val):
            errors.append("Email address is not valid.")
        else:
            # Check uniqueness — exclude current user
            existing = db.fetchone(
                "SELECT id FROM users WHERE email = %s AND id != %s",
                (val, str(user["id"])),
            )
            if existing:
                errors.append("An account with that email already exists.")
            else:
                updates["email"] = val

    # organisation
    if "organisation" in body:
        val = (body.get("organisation") or "").strip() or None
        updates["organisation"] = val

    # network_scale
    if "network_scale" in body:
        val = (body.get("network_scale") or "").strip() or None
        if val and val not in VALID_SCALES:
            errors.append(f"Network scale must be one of: {', '.join(VALID_SCALES)}.")
        else:
            updates["network_scale"] = val

    if errors:
        send_error(handler_self, errors[0], 400)
        return

    if not updates:
        send_error(handler_self, "No fields provided to update.", 400)
        return

    # Build dynamic UPDATE
    set_clauses = ", ".join(f"{k} = %s" for k in updates)
    values      = list(updates.values()) + [str(user["id"])]

    try:
        db.execute(
            f"UPDATE users SET {set_clauses} WHERE id = %s",
            values,
        )
    except Exception as e:
        log.error("Profile update error: %s", e)
        send_error(handler_self, "Failed to update profile. Please try again.", 500)
        return

    log.info("Profile updated: %s", user["operator_id"])

    # Return fresh user data
    updated = db.fetchone(
        """
        SELECT operator_id, email, display_name, role,
               organisation, network_scale, status, totp_enabled
        FROM   users WHERE id = %s
        """,
        (str(user["id"]),),
    )
    send_json(handler_self, {
        "data": {
            "message":      "Profile updated successfully.",
            "display_name": updated["display_name"],
            "email":        updated["email"],
            "organisation": updated.get("organisation"),
            "network_scale":updated.get("network_scale"),
        }
    })


# ─────────────────────────────────────────────────────────────
#  POST /api/auth/change-password
#  Requires current password before setting new one
# ─────────────────────────────────────────────────────────────
def _change_password(handler_self, body, send_json, send_error):
    try:
        user = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    if not body:
        send_error(handler_self, "Request body is required.", 400)
        return

    current_password = body.get("current_password") or ""
    new_password     = body.get("new_password")     or ""

    if not current_password or not new_password:
        send_error(handler_self, "Current and new passwords are required.", 400)
        return

    if len(new_password) < 12:
        send_error(handler_self, "New password must be at least 12 characters.", 400)
        return

    if current_password == new_password:
        send_error(handler_self, "New password must be different from current password.", 400)
        return

    # Load password hash
    row = db.fetchone(
        "SELECT password_hash FROM users WHERE id = %s",
        (str(user["id"]),),
    )

    if not bcrypt.checkpw(current_password.encode("utf-8"),
                          row["password_hash"].encode("utf-8")):
        send_error(handler_self, "Current password is incorrect.", 401)
        return

    new_hash = bcrypt.hashpw(
        new_password.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("utf-8")

    try:
        db.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (new_hash, str(user["id"])),
        )
        # Revoke all existing sessions — force re-login on all devices
        db.execute(
            "UPDATE sessions SET revoked = TRUE, revoked_at = NOW() WHERE user_id = %s",
            (str(user["id"]),),
        )
    except Exception as e:
        log.error("Password change error: %s", e)
        send_error(handler_self, "Failed to change password. Please try again.", 500)
        return

    log.info("Password changed: %s", user["operator_id"])
    send_json(handler_self, {
        "data": {"message": "Password changed successfully. Please log in again."}
    })


# ─────────────────────────────────────────────────────────────
#  POST /api/auth/send-verification
#  (Re)sends a verification email to the logged-in user
# ─────────────────────────────────────────────────────────────
def _send_verification(handler_self, send_json, send_error):
    try:
        user = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    if user.get("email_verified"):
        send_error(handler_self, "Your email is already verified.", 400)
        return

    token  = secrets.token_urlsafe(48)
    expiry = "NOW() + INTERVAL '24 hours'"

    db.execute(
        "UPDATE users SET email_verify_token = %s, email_verify_expiry = NOW() + INTERVAL '24 hours' WHERE id = %s",
        (token, str(user["id"])),
    )

    try:
        email_utils.send_verification_email(user["email"], user["display_name"], token)
    except Exception:
        log.error("Failed to send verification email to %s", user["email"])

    send_json(handler_self, {"data": {"message": "Verification email sent. Check your inbox."}})


# ─────────────────────────────────────────────────────────────
#  POST /api/auth/verify-email   { token }
#  Marks the user's email as verified
# ─────────────────────────────────────────────────────────────
def _verify_email(handler_self, body, send_json, send_error):
    if not body or not body.get("token"):
        send_error(handler_self, "Verification token is required.", 400)
        return

    token = body["token"].strip()

    row = db.fetchone(
        """
        SELECT id, display_name, email_verified, email_verify_expiry
        FROM   users
        WHERE  email_verify_token = %s
        """,
        (token,),
    )

    if not row:
        send_error(handler_self, "Invalid or expired verification link.", 400)
        return

    if row["email_verified"]:
        send_json(handler_self, {"data": {"message": "Email already verified. You can log in."}})
        return

    import datetime
    if row["email_verify_expiry"] and row["email_verify_expiry"] < datetime.datetime.now(datetime.timezone.utc):
        send_error(handler_self, "Verification link has expired. Please request a new one.", 400)
        return

    db.execute(
        """
        UPDATE users
        SET    email_verified      = TRUE,
               email_verify_token  = NULL,
               email_verify_expiry = NULL,
               status              = CASE WHEN status = 'pending' THEN 'active' ELSE status END
        WHERE  id = %s
        """,
        (str(row["id"]),),
    )

    log.info("Email verified for user id=%s", row["id"])
    send_json(handler_self, {"data": {"message": "Email verified successfully! You can now log in."}})


# ─────────────────────────────────────────────────────────────
#  POST /api/auth/forgot-password   { email }
#  Sends a password reset link — always responds 200 to
#  prevent email enumeration
# ─────────────────────────────────────────────────────────────
def _forgot_password(handler_self, body, send_json, send_error):
    SAFE_MSG = "If an account with that email exists, a reset link has been sent."

    if not body or not body.get("email"):
        send_json(handler_self, {"data": {"message": SAFE_MSG}})
        return

    email = body["email"].strip().lower()

    row = db.fetchone(
        "SELECT id, display_name, email, status FROM users WHERE email = %s",
        (email,),
    )

    if not row or row["status"] == "suspended":
        # Always return the same message regardless
        send_json(handler_self, {"data": {"message": SAFE_MSG}})
        return

    token = secrets.token_urlsafe(48)

    db.execute(
        "UPDATE users SET pw_reset_token = %s, pw_reset_expiry = NOW() + INTERVAL '1 hour' WHERE id = %s",
        (token, str(row["id"])),
    )

    try:
        email_utils.send_password_reset_email(row["email"], row["display_name"], token)
    except Exception:
        log.error("Failed to send reset email to %s", email)

    send_json(handler_self, {"data": {"message": SAFE_MSG}})


# ─────────────────────────────────────────────────────────────
#  POST /api/auth/reset-password   { token, new_password }
#  Consumes the reset token and sets a new password
# ─────────────────────────────────────────────────────────────
def _reset_password(handler_self, body, send_json, send_error):
    if not body:
        send_error(handler_self, "Request body is required.", 400)
        return

    token        = (body.get("token")        or "").strip()
    new_password = (body.get("new_password") or "").strip()

    if not token or not new_password:
        send_error(handler_self, "Token and new password are required.", 400)
        return

    if len(new_password) < 12:
        send_error(handler_self, "Password must be at least 12 characters.", 400)
        return

    row = db.fetchone(
        "SELECT id, pw_reset_expiry FROM users WHERE pw_reset_token = %s",
        (token,),
    )

    if not row:
        send_error(handler_self, "Invalid or expired reset link.", 400)
        return

    import datetime
    if row["pw_reset_expiry"] and row["pw_reset_expiry"] < datetime.datetime.now(datetime.timezone.utc):
        send_error(handler_self, "Reset link has expired. Please request a new one.", 400)
        return

    new_hash = bcrypt.hashpw(
        new_password.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("utf-8")

    db.execute(
        """
        UPDATE users
        SET    password_hash   = %s,
               pw_reset_token  = NULL,
               pw_reset_expiry = NULL
        WHERE  id = %s
        """,
        (new_hash, str(row["id"])),
    )

    # Revoke all sessions — force re-login everywhere
    db.execute(
        "UPDATE sessions SET revoked = TRUE, revoked_at = NOW() WHERE user_id = %s",
        (str(row["id"]),),
    )

    log.info("Password reset for user id=%s", row["id"])
    send_json(handler_self, {"data": {"message": "Password reset successfully. You can now log in."}})
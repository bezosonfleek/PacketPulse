"""
routes/admin_routes.py — Admin dashboard endpoints.

All routes require role = 'admin'. Any other role gets 403.

Routes:
    GET  /api/admin/users              → list all users
    GET  /api/admin/users/<id>         → single user detail + scan stats
    POST /api/admin/users/<id>/status  → activate / suspend an account
    POST /api/admin/users/<id>/role    → change a user's role
    GET  /api/admin/stats              → platform-wide stats
    GET  /api/admin/logins             → recent login attempts (audit log)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import logging

import db
from auth import AuthError, require_auth

log = logging.getLogger(__name__)

_UUID_RE = re.compile(
    r'^/api/admin/users/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
    r'(?:/(\w+))?$',
    re.IGNORECASE,
)

VALID_STATUSES = {"active", "suspended", "pending"}
VALID_ROLES    = {"security", "sysadmin", "devops", "other", "admin"}


# ─────────────────────────────────────────────────────────────
#  ROUTER
# ─────────────────────────────────────────────────────────────
def handle(path: str, method: str, handler_self) -> bool:
    from main import send_json, send_error, read_json_body

    if path == "/api/admin/users" and method == "GET":
        _list_users(handler_self, send_json, send_error)
        return True

    if path == "/api/admin/stats" and method == "GET":
        _stats(handler_self, send_json, send_error)
        return True

    if path == "/api/admin/logins" and method == "GET":
        _login_audit(handler_self, send_json, send_error)
        return True

    # /api/admin/users/<uuid> or /api/admin/users/<uuid>/status|role
    match = _UUID_RE.match(path)
    if match:
        user_id = match.group(1)
        action  = match.group(2)  # None | 'status' | 'role'

        if method == "GET" and action is None:
            _user_detail(handler_self, user_id, send_json, send_error)
            return True

        if method == "POST" and action == "status":
            _set_status(handler_self, user_id,
                        read_json_body(handler_self), send_json, send_error)
            return True

        if method == "POST" and action == "role":
            _set_role(handler_self, user_id,
                      read_json_body(handler_self), send_json, send_error)
            return True

    return False


# ─────────────────────────────────────────────────────────────
#  ADMIN GUARD
#  All endpoints call this first. Returns user dict or raises.
# ─────────────────────────────────────────────────────────────
def _require_admin(handler_self):
    from main import send_error
    user = require_auth(handler_self)
    if user.get("role") != "admin":
        send_error(handler_self, "Admin access required.", 403)
        return None
    return user


# ─────────────────────────────────────────────────────────────
#  GET /api/admin/users
# ─────────────────────────────────────────────────────────────
def _list_users(handler_self, send_json, send_error):
    try:
        admin = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    if admin.get("role") != "admin":
        send_error(handler_self, "Admin access required.", 403)
        return

    try:
        users = db.fetchall(
            """
            SELECT u.id, u.operator_id, u.email, u.display_name,
                   u.role, u.organisation, u.network_scale,
                   u.status, u.failed_attempts, u.locked_until,
                   u.created_at, u.last_login_at,
                   COUNT(s.id) AS scan_count
            FROM   users u
            LEFT JOIN scans s ON s.user_id = u.id
            GROUP  BY u.id
            ORDER  BY u.created_at DESC
            """,
            (),
        )
    except Exception as e:
        log.error("Admin list users error: %s", e)
        send_error(handler_self, "Failed to retrieve users.", 500)
        return

    for u in users:
        u["id"]            = str(u["id"])
        u["created_at"]    = u["created_at"].isoformat()    if u["created_at"]    else None
        u["last_login_at"] = u["last_login_at"].isoformat() if u["last_login_at"] else None
        u["locked_until"]  = u["locked_until"].isoformat()  if u["locked_until"]  else None
        u["scan_count"]    = int(u["scan_count"])

    send_json(handler_self, {"data": {"users": users}})


# ─────────────────────────────────────────────────────────────
#  GET /api/admin/users/<id>
# ─────────────────────────────────────────────────────────────
def _user_detail(handler_self, user_id, send_json, send_error):
    try:
        admin = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    if admin.get("role") != "admin":
        send_error(handler_self, "Admin access required.", 403)
        return

    user = db.fetchone(
        """
        SELECT id, operator_id, email, display_name, role,
               organisation, network_scale, status,
               failed_attempts, locked_until,
               created_at, last_login_at, totp_enabled
        FROM   users WHERE id = %s
        """,
        (user_id,),
    )

    if not user:
        send_error(handler_self, "User not found.", 404)
        return

    # Recent scans for this user
    scans = db.fetchall(
        """
        SELECT id, subnet, range_start, range_end, status,
               hosts_scanned, hosts_alive, open_ports,
               duration_ms, started_at, completed_at
        FROM   scans
        WHERE  user_id = %s
        ORDER  BY started_at DESC
        LIMIT  10
        """,
        (user_id,),
    )

    # Recent login attempts
    attempts = db.fetchall(
        """
        SELECT success, failure_reason, ip_address::text,
               attempted_at
        FROM   login_attempts
        WHERE  operator_id = %s
        ORDER  BY attempted_at DESC
        LIMIT  10
        """,
        (user["operator_id"],),
    )

    user["id"]            = str(user["id"])
    user["created_at"]    = user["created_at"].isoformat()    if user["created_at"]    else None
    user["last_login_at"] = user["last_login_at"].isoformat() if user["last_login_at"] else None
    user["locked_until"]  = user["locked_until"].isoformat()  if user["locked_until"]  else None

    for s in scans:
        s["id"]           = str(s["id"])
        s["started_at"]   = s["started_at"].isoformat()   if s["started_at"]   else None
        s["completed_at"] = s["completed_at"].isoformat() if s["completed_at"] else None

    for a in attempts:
        a["attempted_at"] = a["attempted_at"].isoformat() if a["attempted_at"] else None

    send_json(handler_self, {
        "data": {
            "user":     user,
            "scans":    scans,
            "attempts": attempts,
        }
    })


# ─────────────────────────────────────────────────────────────
#  POST /api/admin/users/<id>/status
#  Body: {"status": "active" | "suspended" | "pending"}
# ─────────────────────────────────────────────────────────────
def _set_status(handler_self, user_id, body, send_json, send_error):
    try:
        admin = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    if admin.get("role") != "admin":
        send_error(handler_self, "Admin access required.", 403)
        return

    if not body:
        send_error(handler_self, "Request body required.", 400)
        return

    new_status = (body.get("status") or "").strip()
    if new_status not in VALID_STATUSES:
        send_error(handler_self,
            f"Status must be one of: {', '.join(VALID_STATUSES)}.", 400)
        return

    # Prevent admin from suspending themselves
    if str(admin["id"]) == user_id and new_status == "suspended":
        send_error(handler_self, "You cannot suspend your own account.", 400)
        return

    rows = db.execute(
        "UPDATE users SET status = %s WHERE id = %s",
        (new_status, user_id),
    )

    if rows == 0:
        send_error(handler_self, "User not found.", 404)
        return

    log.info("Admin %s set user %s status → %s",
             admin["operator_id"], user_id, new_status)
    send_json(handler_self, {
        "data": {"message": f"Account status updated to '{new_status}'."}
    })


# ─────────────────────────────────────────────────────────────
#  POST /api/admin/users/<id>/role
#  Body: {"role": "security" | "sysadmin" | "devops" | "other" | "admin"}
# ─────────────────────────────────────────────────────────────
def _set_role(handler_self, user_id, body, send_json, send_error):
    try:
        admin = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    if admin.get("role") != "admin":
        send_error(handler_self, "Admin access required.", 403)
        return

    if not body:
        send_error(handler_self, "Request body required.", 400)
        return

    new_role = (body.get("role") or "").strip()
    if new_role not in VALID_ROLES:
        send_error(handler_self,
            f"Role must be one of: {', '.join(VALID_ROLES)}.", 400)
        return

    rows = db.execute(
        "UPDATE users SET role = %s WHERE id = %s",
        (new_role, user_id),
    )

    if rows == 0:
        send_error(handler_self, "User not found.", 404)
        return

    log.info("Admin %s set user %s role → %s",
             admin["operator_id"], user_id, new_role)
    send_json(handler_self, {
        "data": {"message": f"Role updated to '{new_role}'."}
    })


# ─────────────────────────────────────────────────────────────
#  GET /api/admin/stats
#  Platform-wide summary numbers for the dashboard cards.
# ─────────────────────────────────────────────────────────────
def _stats(handler_self, send_json, send_error):
    try:
        admin = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    if admin.get("role") != "admin":
        send_error(handler_self, "Admin access required.", 403)
        return

    try:
        stats = db.fetchone(
            """
            SELECT
                (SELECT COUNT(*) FROM users)                         AS total_users,
                (SELECT COUNT(*) FROM users WHERE status = 'active') AS active_users,
                (SELECT COUNT(*) FROM users WHERE status = 'pending') AS pending_users,
                (SELECT COUNT(*) FROM users WHERE status = 'suspended') AS suspended_users,
                (SELECT COUNT(*) FROM scans)                         AS total_scans,
                (SELECT COUNT(*) FROM scans WHERE status = 'complete') AS complete_scans,
                (SELECT COALESCE(SUM(hosts_alive), 0) FROM scans)   AS total_hosts_found,
                (SELECT COALESCE(SUM(open_ports), 0) FROM scans)    AS total_ports_found,
                (SELECT COUNT(*) FROM login_attempts WHERE attempted_at > NOW() - INTERVAL '24 hours') AS logins_24h,
                (SELECT COUNT(*) FROM login_attempts WHERE success = false AND attempted_at > NOW() - INTERVAL '24 hours') AS failed_logins_24h
            """,
            (),
        )
    except Exception as e:
        log.error("Admin stats error: %s", e)
        send_error(handler_self, "Failed to retrieve stats.", 500)
        return

    # Convert to plain ints
    for key in stats:
        stats[key] = int(stats[key]) if stats[key] is not None else 0

    send_json(handler_self, {"data": stats})


# ─────────────────────────────────────────────────────────────
#  GET /api/admin/logins
#  Recent login attempts across all users — audit log view.
# ─────────────────────────────────────────────────────────────
def _login_audit(handler_self, send_json, send_error):
    try:
        admin = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    if admin.get("role") != "admin":
        send_error(handler_self, "Admin access required.", 403)
        return

    try:
        attempts = db.fetchall(
            """
            SELECT operator_id, ip_address::text, user_agent,
                   success, failure_reason, attempted_at
            FROM   login_attempts
            ORDER  BY attempted_at DESC
            LIMIT  100
            """,
            (),
        )
    except Exception as e:
        log.error("Admin logins error: %s", e)
        send_error(handler_self, "Failed to retrieve login attempts.", 500)
        return

    for a in attempts:
        a["attempted_at"] = a["attempted_at"].isoformat() if a["attempted_at"] else None

    send_json(handler_self, {"data": {"attempts": attempts}})
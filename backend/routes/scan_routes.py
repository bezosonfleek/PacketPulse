"""
routes/scan_routes.py — Scan execution and history endpoints.

Routes handled here:
    GET  /api/scan/init        → local IP + subnet prefix for console pre-fill
    POST /api/scan/run         → execute a two-phase scan (auth required)
    GET  /api/scan/history     → list past scans for current user (auth required)
    GET  /api/scan/<id>        → full results for one past scan (auth required)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import logging
import time
import re

import db
from auth import AuthError, require_auth

log = logging.getLogger(__name__)

# UUID pattern for scan detail route matching
_UUID_RE = re.compile(
    r'^/api/scan/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$',
    re.IGNORECASE
)

# Valid subnet pattern e.g. "192.168.1"
_SUBNET_RE = re.compile(
    r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
)


# ─────────────────────────────────────────────────────────────
#  ROUTER
# ─────────────────────────────────────────────────────────────
def handle(path: str, method: str, handler_self) -> bool:
    from main import send_json, send_error, read_json_body

    if path == "/api/scan/init" and method == "GET":
        _init(handler_self, send_json, send_error)
        return True

    if path == "/api/scan/run" and method == "POST":
        _run_scan(handler_self, read_json_body(handler_self), send_json, send_error)
        return True

    if path == "/api/scan/history" and method == "GET":
        _history(handler_self, send_json, send_error)
        return True

    # /api/scan/<uuid> — detail for one scan
    match = _UUID_RE.match(path)
    if match and method == "GET":
        _scan_detail(handler_self, match.group(1), send_json, send_error)
        return True

    return False


# ─────────────────────────────────────────────────────────────
#  GET /api/scan/init
#  No auth required — used to pre-fill the subnet field before
#  the user has interacted with the page.
# ─────────────────────────────────────────────────────────────
def _init(handler_self, send_json, send_error):
    try:
        from packetpulse import get_network_details
        details = get_network_details()
        send_json(handler_self, {"data": details})
    except Exception as e:
        log.error("Init error: %s", e)
        send_json(handler_self, {"data": {
            "local_ip":      "Unavailable",
            "public_ip":     "Unavailable",
            "subnet_prefix": "192.168.1",
        }})


# ─────────────────────────────────────────────────────────────
#  INPUT VALIDATION
# ─────────────────────────────────────────────────────────────
def _validate_scan(body: dict) -> list:
    errors = []

    subnet = (body.get("subnet") or "").strip()
    if not subnet:
        errors.append("Subnet is required (e.g. 192.168.1).")
    else:
        m = _SUBNET_RE.match(subnet)
        if not m:
            errors.append("Subnet must be in format X.X.X (e.g. 192.168.1).")
        else:
            # Each octet must be 0-255
            if any(int(m.group(i)) > 255 for i in range(1, 4)):
                errors.append("Each subnet octet must be between 0 and 255.")

    start = body.get("start")
    end   = body.get("end")

    try:
        start = int(start)
        if not 1 <= start <= 254:
            errors.append("Range start must be between 1 and 254.")
    except (TypeError, ValueError):
        errors.append("Range start must be a number.")

    try:
        end = int(end)
        if not 1 <= end <= 254:
            errors.append("Range end must be between 1 and 254.")
    except (TypeError, ValueError):
        errors.append("Range end must be a number.")

    if not errors and isinstance(start, int) and isinstance(end, int):
        if start > end:
            errors.append("Range start must be less than or equal to range end.")
        if (end - start) > 253:
            errors.append("Range cannot exceed 254 hosts.")

    return errors


# ─────────────────────────────────────────────────────────────
#  POST /api/scan/run
# ─────────────────────────────────────────────────────────────
def _run_scan(handler_self, body, send_json, send_error):
    # Auth required
    try:
        user = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    if not body:
        send_error(handler_self, "Request body is required.", 400)
        return

    errors = _validate_scan(body)
    if errors:
        send_error(handler_self, errors[0], 400)
        return

    subnet = body["subnet"].strip()
    start  = int(body["start"])
    end    = int(body["end"])
    # Optional port filter — list of ints; None means scan all known ports
    ports  = body.get("ports") or None
    if ports:
        try:
            ports = [int(p) for p in ports if 1 <= int(p) <= 65535]
        except (TypeError, ValueError):
            send_error(handler_self, "Ports must be a list of integers.", 400)
            return

    # Create a scan record with status=running so the frontend
    # can see it immediately if you add a live-status feature later
    try:
        scan_row = db.execute_returning(
            """
            INSERT INTO scans
              (user_id, subnet, range_start, range_end, ports_filter, status)
            VALUES (%s, %s, %s, %s, %s, 'running')
            RETURNING id, started_at
            """,
            (
                str(user["id"]),
                subnet,
                start,
                end,
                ",".join(str(p) for p in ports) if ports else None,
            ),
        )
    except Exception as e:
        log.error("Failed to create scan record: %s", e)
        send_error(handler_self, "Failed to initialise scan. Please try again.", 500)
        return

    scan_id = str(scan_row["id"])
    log.info("Scan %s started by %s — target %s.%d-%d",
             scan_id, user["operator_id"], subnet, start, end)

    # ── Run the scan ─────────────────────────────────────────
    t_start = time.time()
    try:
        from packetpulse import run_scan
        results = run_scan(subnet, start, end, ports)
    except Exception as e:
        log.error("Scan %s engine error: %s", scan_id, e)
        db.execute(
            "UPDATE scans SET status = 'failed', completed_at = NOW() WHERE id = %s",
            (scan_id,)
        )
        send_error(handler_self, "Scan failed. Check server logs for details.", 500)
        return

    duration_ms  = int((time.time() - t_start) * 1000)
    alive_hosts  = [h for h in results if h["is_up"]]
    total_ports  = sum(len(h["ports"]) for h in alive_hosts)

    # ── Write results to DB ──────────────────────────────────
    try:
        # Update the scan metadata row
        db.execute(
            """
            UPDATE scans
            SET status        = 'complete',
                hosts_scanned = %s,
                hosts_alive   = %s,
                open_ports    = %s,
                duration_ms   = %s,
                completed_at  = NOW()
            WHERE id = %s
            """,
            (len(results), len(alive_hosts), total_ports, duration_ms, scan_id),
        )

        # Write one row per host evaluated (alive and dead)
        for host in results:
            db.execute(
                """
                INSERT INTO scan_hosts
                  (scan_id, ip_address, hostname, is_up, ports)
                VALUES (%s, %s::inet, %s, %s, %s)
                """,
                (
                    scan_id,
                    host["ip"],
                    host.get("hostname") or None,
                    host["is_up"],
                    json.dumps(host["ports"]),
                ),
            )

    except Exception as e:
        log.error("Failed to write scan %s results to DB: %s", scan_id, e)
        # Don't fail the response — results are still returned to frontend

    log.info(
        "Scan %s complete — %d/%d alive, %d open ports, %dms",
        scan_id, len(alive_hosts), len(results), total_ports, duration_ms,
    )

    # Return full results to the frontend (same shape as before)
    send_json(handler_self, {
        "data": {
            "scan_id":       scan_id,
            "subnet":        subnet,
            "range_start":   start,
            "range_end":     end,
            "hosts_scanned": len(results),
            "hosts_alive":   len(alive_hosts),
            "open_ports":    total_ports,
            "duration_ms":   duration_ms,
            "results":       results,
        }
    })


# ─────────────────────────────────────────────────────────────
#  GET /api/scan/history
#  Returns the 20 most recent scans for the current user.
#  Only metadata — no per-host detail. Use /api/scan/<id> for that.
# ─────────────────────────────────────────────────────────────
def _history(handler_self, send_json, send_error):
    try:
        user = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    is_admin = user.get("role") == "admin"

    try:
        if is_admin:
            # Admins see all scans across all users
            scans = db.fetchall(
                """
                SELECT s.id, s.user_id, s.subnet, s.range_start, s.range_end,
                       s.status, s.hosts_scanned, s.hosts_alive, s.open_ports,
                       s.duration_ms, s.started_at, s.completed_at,
                       u.operator_id, u.display_name
                FROM   scans s
                JOIN   users u ON u.id = s.user_id
                ORDER  BY s.started_at DESC
                LIMIT  100
                """,
                (),
            )
        else:
            # Regular users see only their own scans
            scans = db.fetchall(
                """
                SELECT id, user_id, subnet, range_start, range_end,
                       status, hosts_scanned, hosts_alive, open_ports,
                       duration_ms, started_at, completed_at
                FROM   scans
                WHERE  user_id = %s
                ORDER  BY started_at DESC
                LIMIT  50
                """,
                (str(user["id"]),),
            )
    except Exception as e:
        log.error("History query error: %s", e)
        send_error(handler_self, "Failed to retrieve scan history.", 500)
        return

    # Convert UUIDs and datetimes to strings for JSON serialisation
    for s in scans:
        s["id"]           = str(s["id"])
        if "user_id" in s:
            s["user_id"]  = str(s["user_id"])
        s["started_at"]   = s["started_at"].isoformat()   if s["started_at"]   else None
        s["completed_at"] = s["completed_at"].isoformat() if s["completed_at"] else None

    send_json(handler_self, {
        "data": {
            "scans":    scans,
            "is_admin": is_admin,
        }
    })


# ─────────────────────────────────────────────────────────────
#  GET /api/scan/<id>
#  Returns full host + port detail for one past scan.
#  Only the user who ran the scan can retrieve it.
# ─────────────────────────────────────────────────────────────
def _scan_detail(handler_self, scan_id: str, send_json, send_error):
    try:
        user = require_auth(handler_self)
    except AuthError as e:
        send_error(handler_self, e.message, 401)
        return

    # Verify the scan exists AND belongs to this user
    scan = db.fetchone(
        """
        SELECT id, user_id, subnet, range_start, range_end,
               status, hosts_scanned, hosts_alive, open_ports,
               duration_ms, started_at, completed_at
        FROM   scans
        WHERE  id = %s
        """,
        (scan_id,),
    )

    if not scan:
        send_error(handler_self, "Scan not found.", 404)
        return

    # Ownership check — users must never see each other's results
    if str(scan["user_id"]) != str(user["id"]):
        send_error(handler_self, "Scan not found.", 404)
        # Deliberate 404 not 403 — don't confirm the scan exists to other users
        return

    # Fetch host details
    try:
        hosts = db.fetchall(
            """
            SELECT ip_address::text AS ip,
                   hostname,
                   is_up,
                   ports
            FROM   scan_hosts
            WHERE  scan_id = %s
            ORDER  BY ip_address
            """,
            (scan_id,),
        )
    except Exception as e:
        log.error("Scan detail query error: %s", e)
        send_error(handler_self, "Failed to retrieve scan detail.", 500)
        return

    # Parse the JSONB ports column back into a list
    for h in hosts:
        if isinstance(h["ports"], str):
            h["ports"] = json.loads(h["ports"])

    scan["id"]           = str(scan["id"])
    scan["user_id"]      = str(scan["user_id"])
    scan["started_at"]   = scan["started_at"].isoformat()   if scan["started_at"]   else None
    scan["completed_at"] = scan["completed_at"].isoformat() if scan["completed_at"] else None

    send_json(handler_self, {
        "data": {
            "scan":  scan,
            "hosts": hosts,
        }
    })
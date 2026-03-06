"""
test_phase2.py — Phase 2 backend verification script.

Tests everything that is wired up in Phase 2:
  - DB connection pool (db.py)
  - All four query helpers (fetchone, fetchall, execute, execute_returning)
  - Stored function calls (call_function)
  - Auth token helpers (hash_token, decode_token)
  - AuthError is raised correctly on bad tokens
  - HTTP server is reachable
  - Health endpoint returns 200
  - Unknown routes return 404
  - Missing auth header returns correct error structure

Run from the backend folder with the server already running in another terminal:
    python test_phase2.py

Or run with --no-server to skip the HTTP tests and only test DB + auth logic:
    python test_phase2.py --no-server

Requires: .env to be configured with a reachable Postgres instance.
"""

import sys
import os
import json
import datetime
import traceback
import urllib.request
import urllib.error

# Ensure imports resolve from this folder
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

# ─────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────
PASS  = "\033[92m  PASS\033[0m"
FAIL  = "\033[91m  FAIL\033[0m"
SKIP  = "\033[93m  SKIP\033[0m"
HEAD  = "\033[96m{}\033[0m"

results = {"passed": 0, "failed": 0, "skipped": 0}


def check(label: str, condition: bool, detail: str = ""):
    if condition:
        print(f"{PASS}  {label}")
        results["passed"] += 1
    else:
        print(f"{FAIL}  {label}")
        if detail:
            print(f"        → {detail}")
        results["failed"] += 1


def skip(label: str, reason: str = ""):
    print(f"{SKIP}  {label}  ({reason})")
    results["skipped"] += 1


def section(title: str):
    print(f"\n{HEAD.format('─' * 50)}")
    print(f"{HEAD.format(f'  {title}')}")
    print(f"{HEAD.format('─' * 50)}")


def http_get(path: str, token: str = None) -> tuple[int, dict]:
    """Make a GET request to the local server. Returns (status_code, body_dict)."""
    port = int(os.getenv("SERVER_PORT", 8000))
    url  = f"http://localhost:{port}{path}"
    req  = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {"error": e.reason}
        return e.code, body
    except urllib.error.URLError as e:
        return 0, {"error": str(e)}


def http_post(path: str, body: dict, token: str = None) -> tuple[int, dict]:
    """Make a POST request to the local server. Returns (status_code, body_dict)."""
    port  = int(os.getenv("SERVER_PORT", 8000))
    url   = f"http://localhost:{port}{path}"
    data  = json.dumps(body).encode()
    req   = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type",   "application/json")
    req.add_header("Content-Length", str(len(data)))
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {"error": e.reason}
        return e.code, body
    except urllib.error.URLError as e:
        return 0, {"error": str(e)}


# ─────────────────────────────────────────────────────────────
#  TEST GROUPS
# ─────────────────────────────────────────────────────────────

def test_db_connection():
    section("1. Database — Connection Pool")
    try:
        import db
        db.init_pool()
        check("Pool initialises without error", True)
    except Exception as e:
        check("Pool initialises without error", False, str(e))
        print("  Cannot continue DB tests — aborting this section.")
        return False
    return True


def test_db_queries():
    section("2. Database — Query Helpers")
    import db

    # fetchone — known row (seed admin)
    try:
        row = db.fetchone(
            "SELECT operator_id, status FROM users WHERE operator_id = %s",
            ("pp_admin",)
        )
        check("fetchone returns dict for existing row",   isinstance(row, dict))
        check("fetchone returns correct operator_id",     row and row.get("operator_id") == "pp_admin")
        check("fetchone returns correct status (active)", row and row.get("status") == "active")
    except Exception as e:
        check("fetchone basic query", False, str(e))

    # fetchone — missing row
    try:
        none_row = db.fetchone(
            "SELECT * FROM users WHERE operator_id = %s",
            ("__nonexistent__",)
        )
        check("fetchone returns None for missing row", none_row is None)
    except Exception as e:
        check("fetchone returns None for missing row", False, str(e))

    # fetchall — at least the seed row
    try:
        rows = db.fetchall("SELECT id FROM users")
        check("fetchall returns a list",            isinstance(rows, list))
        check("fetchall returns at least one row",  len(rows) >= 1)
    except Exception as e:
        check("fetchall basic query", False, str(e))

    # execute — insert a temp row then delete it
    try:
        import uuid
        tmp_id = str(uuid.uuid4())
        db.execute(
            """
            INSERT INTO users
              (id, operator_id, email, display_name, password_hash, status)
            VALUES
              (%s, %s, %s, %s, %s, %s)
            """,
            (tmp_id, f"_test_{tmp_id[:8]}", f"_test_{tmp_id[:8]}@test.local",
             "Test User", "not_a_real_hash", "pending")
        )
        check("execute INSERT runs without error", True)

        affected = db.execute(
            "DELETE FROM users WHERE id = %s", (tmp_id,)
        )
        check("execute DELETE returns rowcount = 1", affected == 1)
    except Exception as e:
        check("execute INSERT / DELETE", False, str(e))

    # execute_returning
    try:
        import uuid
        tmp_id2 = str(uuid.uuid4())
        returned = db.execute_returning(
            """
            INSERT INTO users
              (id, operator_id, email, display_name, password_hash, status)
            VALUES
              (%s, %s, %s, %s, %s, %s)
            RETURNING id, operator_id
            """,
            (tmp_id2, f"_test_{tmp_id2[:8]}", f"_test2_{tmp_id2[:8]}@test.local",
             "Test User 2", "not_a_real_hash", "pending")
        )
        check("execute_returning returns a dict",       isinstance(returned, dict))
        check("execute_returning contains correct id",  returned and str(returned.get("id")) == tmp_id2)
        # Cleanup
        db.execute("DELETE FROM users WHERE id = %s", (tmp_id2,))
    except Exception as e:
        check("execute_returning INSERT", False, str(e))


def test_db_functions():
    section("3. Database — Stored Functions")
    import db

    # is_account_locked — should be FALSE after clear
    try:
        db.call_function("SELECT clear_failed_logins(%s)", ("pp_admin",))
        locked = db.call_function("SELECT is_account_locked(%s)", ("pp_admin",))
        check("is_account_locked returns False on clean account", locked is False)
    except Exception as e:
        check("is_account_locked", False, str(e))

    # record_failed_login — increment counter
    try:
        db.call_function("SELECT record_failed_login(%s, %s)", ("pp_admin", 10))
        row = db.fetchone(
            "SELECT failed_attempts FROM users WHERE operator_id = %s",
            ("pp_admin",)
        )
        check("record_failed_login increments counter",
              row and row["failed_attempts"] >= 1)
    except Exception as e:
        check("record_failed_login", False, str(e))

    # Lock threshold — trigger lockout at threshold=1 (to keep test clean)
    try:
        db.call_function("SELECT clear_failed_logins(%s)", ("pp_admin",))
        db.call_function("SELECT record_failed_login(%s, %s)", ("pp_admin", 1))
        locked = db.call_function("SELECT is_account_locked(%s)", ("pp_admin",))
        check("Account locks after reaching threshold", locked is True)
    except Exception as e:
        check("Account lock threshold", False, str(e))

    # clear_failed_logins — reset
    try:
        db.call_function("SELECT clear_failed_logins(%s)", ("pp_admin",))
        row = db.fetchone(
            "SELECT failed_attempts, locked_until FROM users WHERE operator_id = %s",
            ("pp_admin",)
        )
        check("clear_failed_logins resets failed_attempts to 0",
              row and row["failed_attempts"] == 0)
        check("clear_failed_logins clears locked_until",
              row and row["locked_until"] is None)
    except Exception as e:
        check("clear_failed_logins", False, str(e))

    # updated_at trigger
    try:
        import time
        before = db.fetchone(
            "SELECT updated_at FROM users WHERE operator_id = %s", ("pp_admin",)
        )
        time.sleep(1)
        db.execute(
            "UPDATE users SET display_name = %s WHERE operator_id = %s",
            ("Admin", "pp_admin")
        )
        after = db.fetchone(
            "SELECT updated_at FROM users WHERE operator_id = %s", ("pp_admin",)
        )
        check("updated_at trigger fires on UPDATE",
              before and after and after["updated_at"] > before["updated_at"])
    except Exception as e:
        check("updated_at trigger", False, str(e))


def test_auth_helpers():
    section("4. Auth — Token Helpers")
    import jwt as pyjwt
    from auth import hash_token, decode_token, AuthError

    secret  = os.getenv("JWT_SECRET", "insecure-default-change-me")

    # hash_token — same input always same output
    try:
        h1 = hash_token("sometoken")
        h2 = hash_token("sometoken")
        h3 = hash_token("differenttoken")
        check("hash_token is deterministic",          h1 == h2)
        check("hash_token differs for different input", h1 != h3)
        check("hash_token is 64 hex chars (SHA-256)", len(h1) == 64)
    except Exception as e:
        check("hash_token", False, str(e))

    # decode_token — valid JWT
    try:
        expiry  = datetime.datetime.now(datetime.timezone.utc) \
                  + datetime.timedelta(hours=1)
        payload = {"sub": "test-user-id", "exp": expiry}
        token   = pyjwt.encode(payload, secret, algorithm="HS256")
        decoded = decode_token(token)
        check("decode_token succeeds on valid JWT",      decoded is not None)
        check("decode_token returns correct sub claim",  decoded.get("sub") == "test-user-id")
    except Exception as e:
        check("decode_token valid JWT", False, str(e))

    # decode_token — expired JWT
    try:
        expired_payload = {
            "sub": "test-user-id",
            "exp": datetime.datetime.now(datetime.timezone.utc)
                   - datetime.timedelta(seconds=1)
        }
        expired_token = pyjwt.encode(expired_payload, secret, algorithm="HS256")
        try:
            decode_token(expired_token)
            check("decode_token raises AuthError on expired token", False,
                  "No exception raised")
        except AuthError as ae:
            check("decode_token raises AuthError on expired token", True)
    except Exception as e:
        check("decode_token expired token", False, str(e))

    # decode_token — bad signature
    try:
        bad_token = pyjwt.encode({"sub": "x"}, "wrong-secret", algorithm="HS256")
        try:
            decode_token(bad_token)
            check("decode_token raises AuthError on bad signature", False,
                  "No exception raised")
        except AuthError:
            check("decode_token raises AuthError on bad signature", True)
    except Exception as e:
        check("decode_token bad signature", False, str(e))


def test_http_server():
    section("5. HTTP Server — Endpoints")

    # Health check
    status, body = http_get("/api/health")
    check("GET /api/health returns 200",            status == 200,
          f"got {status}")
    check("GET /api/health body is {status: ok}",   body.get("status") == "ok",
          f"got {body}")

    # 404 on unknown route
    status, body = http_get("/api/nonexistent")
    check("GET /api/nonexistent returns 404",       status == 404,
          f"got {status}")
    check("404 response has 'error' key",           "error" in body)

    # Auth stub routes return 404 (not yet implemented)
    status, body = http_post("/api/auth/signin", {"operator_id": "x", "password": "y"})
    check("POST /api/auth/signin returns 404 (stub)", status == 404,
          f"got {status} — if 500, check server logs")

    # Request with malformed auth header — server should not crash
    status, body = http_get("/api/health", token="not.a.real.token")
    check("Server survives malformed token on health (no auth required)", status == 200,
          f"got {status}")

    # OPTIONS preflight — CORS
    port = int(os.getenv("SERVER_PORT", 8000))
    req  = urllib.request.Request(
        f"http://localhost:{port}/api/health",
        method="OPTIONS"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            check("OPTIONS preflight returns 204", resp.status == 204,
                  f"got {resp.status}")
    except urllib.error.HTTPError as e:
        check("OPTIONS preflight returns 204", e.code == 204,
              f"got {e.code}")
    except Exception as e:
        check("OPTIONS preflight", False, str(e))


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    no_server = "--no-server" in sys.argv

    print("\n" + "═" * 52)
    print("  PacketPulse — Phase 2 Test Suite")
    print("═" * 52)

    # DB tests
    if test_db_connection():
        test_db_queries()
        test_db_functions()
    else:
        results["skipped"] += 8  # rough count of skipped sub-tests

    # Auth helper tests (no server needed)
    test_auth_helpers()

    # HTTP tests
    if no_server:
        section("5. HTTP Server — Endpoints")
        skip("All HTTP tests", "--no-server flag set")
    else:
        test_http_server()

    # Summary
    print(f"\n{'═' * 52}")
    print(f"  Results:  "
          f"\033[92m{results['passed']} passed\033[0m  "
          f"\033[91m{results['failed']} failed\033[0m  "
          f"\033[93m{results['skipped']} skipped\033[0m")
    print(f"{'═' * 52}\n")

    sys.exit(0 if results["failed"] == 0 else 1)
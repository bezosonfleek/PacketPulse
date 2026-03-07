"""
test_phase4.py — Phase 4 scan API verification.

Tests every behaviour of /api/scan/init, /api/scan/run,
/api/scan/history, and /api/scan/<id>.

Requires the server running in another terminal:
    python main.py

Run from the backend folder:
    python test_phase4.py

Creates a temporary test account, runs tests, cleans up everything.
"""

import sys
import os
import json
import urllib.request
import urllib.error
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv
load_dotenv()

import db
db.init_pool()

# ─────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────
PASS = "\033[92m  PASS\033[0m"
FAIL = "\033[91m  FAIL\033[0m"
HEAD = "\033[96m{}\033[0m"
results = {"passed": 0, "failed": 0}

PORT   = int(os.getenv("SERVER_PORT", 8000))
BASE   = f"http://localhost:{PORT}"
RUN_ID = uuid.uuid4().hex[:6]

TEST_OP_ID = f"scantest_{RUN_ID}"
TEST_EMAIL = f"scantest_{RUN_ID}@test.local"
TEST_PW    = "ScanTestPass99!"


def check(label, condition, detail=""):
    if condition:
        print(f"{PASS}  {label}")
        results["passed"] += 1
    else:
        print(f"{FAIL}  {label}")
        if detail:
            print(f"        → {detail}")
        results["failed"] += 1


def section(title):
    print(f"\n{HEAD.format('─' * 54)}")
    print(f"{HEAD.format(f'  {title}')}")
    print(f"{HEAD.format('─' * 54)}")


def req(method, path, body=None, token=None):
    url  = BASE + path
    data = json.dumps(body).encode() if body else None
    r    = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            b = json.loads(e.read())
        except Exception:
            b = {"error": e.reason}
        return e.code, b
    except urllib.error.URLError as e:
        return 0, {"error": str(e)}


def get_token():
    """Register a test account and return a valid JWT."""
    req("POST", "/api/auth/signup", {
        "operator_id":  TEST_OP_ID,
        "email":        TEST_EMAIL,
        "display_name": "Scan Tester",
        "password":     TEST_PW,
        "role":         "security",
    })
    status, body = req("POST", "/api/auth/login", {
        "operator_id": TEST_OP_ID,
        "password":    TEST_PW,
    })
    if status != 200:
        print(f"  Could not obtain test token: {body}")
        return None
    return body.get("data", {}).get("token")


def cleanup():
    try:
        db.execute(
            "DELETE FROM users WHERE operator_id LIKE %s",
            (f"scantest_{RUN_ID}%",)
        )
    except Exception as e:
        print(f"  (cleanup warning: {e})")


# ─────────────────────────────────────────────────────────────
#  TESTS
# ─────────────────────────────────────────────────────────────

def test_init():
    section("1. Init — GET /api/scan/init")

    status, body = req("GET", "/api/scan/init")
    check("Returns 200",                    status == 200, f"got {status}")
    check("Has data.local_ip",              "local_ip"      in body.get("data", {}))
    check("Has data.public_ip",             "public_ip"     in body.get("data", {}))
    check("Has data.subnet_prefix",         "subnet_prefix" in body.get("data", {}))

    prefix = body.get("data", {}).get("subnet_prefix", "")
    parts  = prefix.split(".")
    check("Subnet prefix has 3 octets",     len(parts) == 3, f"got '{prefix}'")


def test_scan_auth(token):
    section("2. Scan Auth — unauthenticated requests rejected")

    # No token
    status, body = req("POST", "/api/scan/run", {
        "subnet": "192.168.1", "start": 1, "end": 1
    })
    check("POST /api/scan/run without token returns 401",
          status == 401, f"got {status}")

    # Bad token
    status, body = req("POST", "/api/scan/run", {
        "subnet": "192.168.1", "start": 1, "end": 1
    }, token="not.a.real.token")
    check("POST /api/scan/run with bad token returns 401",
          status == 401, f"got {status}")

    status, body = req("GET", "/api/scan/history")
    check("GET /api/scan/history without token returns 401",
          status == 401, f"got {status}")


def test_scan_validation(token):
    section("3. Scan Input Validation")

    cases = [
        # (description, body, expected_status)
        ("Missing subnet returns 400",
         {"start": 1, "end": 10}, 400),

        ("Bad subnet format returns 400",
         {"subnet": "192.168.1.0/24", "start": 1, "end": 10}, 400),

        ("Missing start returns 400",
         {"subnet": "192.168.1", "end": 10}, 400),

        ("Start > end returns 400",
         {"subnet": "192.168.1", "start": 50, "end": 10}, 400),

        ("Start out of range returns 400",
         {"subnet": "192.168.1", "start": 0, "end": 10}, 400),

        ("End out of range returns 400",
         {"subnet": "192.168.1", "start": 1, "end": 255}, 400),
    ]

    for label, body, expected in cases:
        status, resp = req("POST", "/api/scan/run", body, token=token)
        check(label, status == expected, f"got {status} — {resp.get('error','')}")


def test_scan_run(token):
    section("4. Scan Execution — POST /api/scan/run")

    # Scan just localhost (127.0.0.1) — guaranteed to be up, fast
    print("  (scanning 127.0.0.1 — may take a few seconds...)")
    status, body = req("POST", "/api/scan/run", {
        "subnet": "127.0.0",
        "start":  1,
        "end":    1,
    }, token=token)

    check("Returns 200",                    status == 200, f"got {status} {body.get('error','')}")

    data = body.get("data", {})
    check("Has scan_id",                    bool(data.get("scan_id")))
    check("Has results list",               isinstance(data.get("results"), list))
    check("hosts_scanned = 1",              data.get("hosts_scanned") == 1, f"got {data.get('hosts_scanned')}")
    check("duration_ms is positive",        isinstance(data.get("duration_ms"), int) and data.get("duration_ms") > 0)

    scan_id = data.get("scan_id")

    # Verify scan was written to DB
    if scan_id:
        scan_row = db.fetchone("SELECT status, hosts_scanned FROM scans WHERE id = %s", (scan_id,))
        check("Scan row in DB with status=complete",
              scan_row and scan_row["status"] == "complete",
              f"got {scan_row}")
        check("hosts_scanned matches in DB",
              scan_row and scan_row["hosts_scanned"] == 1)

        host_rows = db.fetchall("SELECT is_up FROM scan_hosts WHERE scan_id = %s", (scan_id,))
        check("scan_hosts rows written to DB",  len(host_rows) == 1, f"got {len(host_rows)}")

    return scan_id


def test_history(token, scan_id):
    section("5. Scan History — GET /api/scan/history")

    status, body = req("GET", "/api/scan/history", token=token)
    check("Returns 200",                    status == 200, f"got {status}")

    scans = body.get("data", {}).get("scans", [])
    check("Returns a list",                 isinstance(scans, list))
    check("At least one scan in history",   len(scans) >= 1, f"got {len(scans)}")

    if scans:
        first = scans[0]
        check("Scan has id",                "id"           in first)
        check("Scan has subnet",            "subnet"       in first)
        check("Scan has started_at",        "started_at"   in first)
        check("Scan has hosts_alive",       "hosts_alive"  in first)
        check("Scan has status=complete",   first.get("status") == "complete",
              f"got {first.get('status')}")

    # Confirm our scan_id appears in history
    if scan_id:
        ids = [s["id"] for s in scans]
        check("Our scan appears in history", scan_id in ids, f"looking for {scan_id}")


def test_scan_detail(token, scan_id):
    section("6. Scan Detail — GET /api/scan/<id>")

    if not scan_id:
        print("  Skipping — no scan_id from previous test.")
        results["failed"] += 1
        return

    status, body = req("GET", f"/api/scan/{scan_id}", token=token)
    check("Returns 200",                    status == 200, f"got {status} {body}")

    data = body.get("data", {})
    check("Has data.scan",                  "scan"  in data)
    check("Has data.hosts",                 "hosts" in data)
    check("Scan id matches",                data.get("scan", {}).get("id") == scan_id)
    check("Hosts is a list",                isinstance(data.get("hosts"), list))

    hosts = data.get("hosts", [])
    if hosts:
        h = hosts[0]
        check("Host has ip field",          "ip"       in h)
        check("Host has is_up field",       "is_up"    in h)
        check("Host has ports list",        isinstance(h.get("ports"), list))

    # Wrong scan ID — should 404
    fake_id = str(uuid.uuid4())
    status, body = req("GET", f"/api/scan/{fake_id}", token=token)
    check("Non-existent scan_id returns 404", status == 404, f"got {status}")


def test_scan_ownership(scan_id):
    section("7. Scan Ownership — cross-user access blocked")

    if not scan_id:
        print("  Skipping — no scan_id available.")
        results["failed"] += 1
        return

    # Create a second user and try to access the first user's scan
    other_op = f"scantest2_{RUN_ID}"
    req("POST", "/api/auth/signup", {
        "operator_id":  other_op,
        "email":        f"{other_op}@test.local",
        "display_name": "Other Tester",
        "password":     TEST_PW,
        "role":         "other",
    })
    _, login_body = req("POST", "/api/auth/login", {
        "operator_id": other_op,
        "password":    TEST_PW,
    })
    other_token = login_body.get("data", {}).get("token")

    if not other_token:
        check("Could not create second user for ownership test", False)
        return

    status, body = req("GET", f"/api/scan/{scan_id}", token=other_token)
    check("Other user gets 404 for foreign scan",
          status == 404, f"got {status} — cross-user data leak!")

    # Other user's history should be empty
    status, body = req("GET", "/api/scan/history", token=other_token)
    scans = body.get("data", {}).get("scans", [])
    check("Other user's history is empty",
          isinstance(scans, list) and len(scans) == 0,
          f"got {len(scans)} scans — data leak!")


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "═" * 56)
    print("  PacketPulse — Phase 4 Scan API Test Suite")
    print("═" * 56)

    token   = None
    scan_id = None

    try:
        token = get_token()
        if not token:
            print("\n  FATAL: Could not obtain auth token. Is the server running?")
            sys.exit(1)

        test_init()
        test_scan_auth(token)
        test_scan_validation(token)
        scan_id = test_scan_run(token)
        test_history(token, scan_id)
        test_scan_detail(token, scan_id)
        test_scan_ownership(scan_id)

    finally:
        cleanup()

    print(f"\n{'═' * 56}")
    print(f"  Results:  "
          f"\033[92m{results['passed']} passed\033[0m  "
          f"\033[91m{results['failed']} failed\033[0m")
    print(f"{'═' * 56}\n")

    sys.exit(0 if results["failed"] == 0 else 1)
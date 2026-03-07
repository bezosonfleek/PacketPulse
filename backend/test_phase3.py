"""
test_phase3.py — Phase 3 auth endpoint verification.

Tests every behaviour of signup, login, signout, and /me.
Requires the server to be running in another terminal:
    python main.py

Run from the backend folder:
    python test_phase3.py

Each test cleans up after itself — no leftover rows in the DB.
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

PORT = int(os.getenv("SERVER_PORT", 8000))
BASE = f"http://localhost:{PORT}"

# Unique suffix so test accounts never collide with real data
RUN_ID = uuid.uuid4().hex[:6]
TEST_OP_ID  = f"tester_{RUN_ID}"
TEST_EMAIL  = f"tester_{RUN_ID}@test.local"
TEST_PW     = "TestPassphrase99!"
TEST_PW_BAD = "wrongpassword123"


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
    print(f"\n{HEAD.format('─' * 52)}")
    print(f"{HEAD.format(f'  {title}')}")
    print(f"{HEAD.format('─' * 52)}")


def req(method, path, body=None, token=None):
    """Make an HTTP request. Returns (status, dict)."""
    url  = BASE + path
    data = json.dumps(body).encode() if body else None
    r    = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            b = json.loads(e.read())
        except Exception:
            b = {"error": e.reason}
        return e.code, b
    except urllib.error.URLError as e:
        return 0, {"error": str(e)}


def cleanup():
    """Remove any test accounts created during this run."""
    try:
        db.execute(
            "DELETE FROM users WHERE operator_id LIKE %s",
            (f"tester_{RUN_ID}%",)
        )
    except Exception as e:
        print(f"  (cleanup warning: {e})")


# ─────────────────────────────────────────────────────────────
#  TESTS
# ─────────────────────────────────────────────────────────────

def test_signup():
    section("1. Signup — POST /api/auth/signup")

    # Valid signup
    status, body = req("POST", "/api/auth/signup", {
        "operator_id":   TEST_OP_ID,
        "email":         TEST_EMAIL,
        "display_name":  "Test Operator",
        "password":      TEST_PW,
        "role":          "security",
        "network_scale": "1-10",
    })
    check("Valid signup returns 201",              status == 201, f"got {status} {body}")
    check("Response has data.reference",           bool(body.get("data", {}).get("reference")))
    check("Response has data.operator_id",         body.get("data", {}).get("operator_id") == TEST_OP_ID)
    check("User row exists in DB", bool(
        db.fetchone("SELECT id FROM users WHERE operator_id = %s", (TEST_OP_ID,))
    ))

    # Missing required field
    status, body = req("POST", "/api/auth/signup", {
        "email": "missing@fields.com",
        "password": "ValidPass123!",
    })
    check("Missing operator_id returns 400",       status == 400, f"got {status}")
    check("Error message is present",              "error" in body)

    # Password too short
    status, body = req("POST", "/api/auth/signup", {
        "operator_id":  f"short_{RUN_ID}",
        "email":        f"short_{RUN_ID}@test.local",
        "display_name": "Short Pw",
        "password":     "tooshort",
    })
    check("Password < 12 chars returns 400",       status == 400, f"got {status}")

    # Duplicate operator_id
    status, body = req("POST", "/api/auth/signup", {
        "operator_id":  TEST_OP_ID,
        "email":        f"other_{RUN_ID}@test.local",
        "display_name": "Duplicate",
        "password":     TEST_PW,
    })
    check("Duplicate operator_id returns 409",     status == 409, f"got {status}")

    # Duplicate email
    status, body = req("POST", "/api/auth/signup", {
        "operator_id":  f"other_{RUN_ID}",
        "email":        TEST_EMAIL,
        "display_name": "Duplicate Email",
        "password":     TEST_PW,
    })
    check("Duplicate email returns 409",           status == 409, f"got {status}")

    # Invalid email format
    status, body = req("POST", "/api/auth/signup", {
        "operator_id":  f"bademail_{RUN_ID}",
        "email":        "not-an-email",
        "display_name": "Bad Email",
        "password":     TEST_PW,
    })
    check("Invalid email format returns 400",      status == 400, f"got {status}")

    # Empty body
    status, body = req("POST", "/api/auth/signup")
    check("Empty body returns 400",                status == 400, f"got {status}")


def test_login():
    section("2. login — POST /api/auth/login")

    # Valid login
    status, body = req("POST", "/api/auth/login", {
        "operator_id": TEST_OP_ID,
        "password":    TEST_PW,
    })
    check("Valid login returns 200",              status == 200, f"got {status} {body}")
    check("Response has data.token",               bool(body.get("data", {}).get("token")))
    check("Response has data.expires_at",          bool(body.get("data", {}).get("expires_at")))
    check("Response has data.display_name",        bool(body.get("data", {}).get("display_name")))

    token = body.get("data", {}).get("token", "")

    # Session was written to DB
    import hashlib
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    session = db.fetchone(
        "SELECT revoked FROM sessions WHERE token_hash = %s", (token_hash,)
    )
    check("Session row written to DB",             session is not None)
    check("Session not revoked on creation",       session and session["revoked"] is False)

    # Login attempt was logged
    attempt = db.fetchone(
        "SELECT success FROM login_attempts WHERE operator_id = %s ORDER BY attempted_at DESC LIMIT 1",
        (TEST_OP_ID,)
    )
    check("Successful attempt logged",             attempt and attempt["success"] is True)

    # Wrong password
    status, body = req("POST", "/api/auth/login", {
        "operator_id": TEST_OP_ID,
        "password":    TEST_PW_BAD,
    })
    check("Wrong password returns 401",            status == 401, f"got {status}")

    # Bad attempt logged
    attempt = db.fetchone(
        "SELECT success, failure_reason FROM login_attempts "
        "WHERE operator_id = %s ORDER BY attempted_at DESC LIMIT 1",
        (TEST_OP_ID,)
    )
    check("Failed attempt logged",                 attempt and attempt["success"] is False)
    check("Failure reason is bad_password",        attempt and attempt["failure_reason"] == "bad_password")

    # Non-existent operator_id — same 401, no info leak
    status, body = req("POST", "/api/auth/login", {
        "operator_id": f"ghost_{RUN_ID}",
        "password":    TEST_PW,
    })
    check("Unknown operator_id returns 401",       status == 401, f"got {status}")
    check("Error message is generic (no leak)",    body.get("error") == "Invalid credentials.")

    # Missing fields
    status, body = req("POST", "/api/auth/login", {"operator_id": TEST_OP_ID})
    check("Missing password returns 400",          status == 400, f"got {status}")

    status, body = req("POST", "/api/auth/login")
    check("Empty body returns 400",                status == 400, f"got {status}")

    return token   # pass token to later tests


def test_me(token):
    section("3. Me — GET /api/auth/me")

    # Valid token
    status, body = req("GET", "/api/auth/me", token=token)
    check("GET /me with valid token returns 200",  status == 200, f"got {status} {body}")
    check("Response has operator_id",              body.get("data", {}).get("operator_id") == TEST_OP_ID)
    check("Response has email",                    bool(body.get("data", {}).get("email")))
    check("Response has role",                     bool(body.get("data", {}).get("role")))

    # No token
    status, body = req("GET", "/api/auth/me")
    check("GET /me without token returns 401",     status == 401, f"got {status}")

    # Garbage token
    status, body = req("GET", "/api/auth/me", token="not.a.real.token")
    check("GET /me with garbage token returns 401",status == 401, f"got {status}")


def test_signout(token):
    section("4. Signout — POST /api/auth/signout")

    # Valid signout
    status, body = req("POST", "/api/auth/signout", token=token)
    check("Signout with valid token returns 200",  status == 200, f"got {status} {body}")
    check("Response confirms signout",             "signed out" in body.get("data", {}).get("message", "").lower())

    # Session is now revoked in DB
    import hashlib
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    session = db.fetchone(
        "SELECT revoked FROM sessions WHERE token_hash = %s", (token_hash,)
    )
    check("Session marked revoked in DB",          session and session["revoked"] is True)

    # Token is now rejected — /me should return 401
    status, body = req("GET", "/api/auth/me", token=token)
    check("Revoked token rejected on /me (401)",   status == 401, f"got {status}")

    # Signout without a token
    status, body = req("POST", "/api/auth/signout")
    check("Signout without token returns 401",     status == 401, f"got {status}")


def test_lockout():
    section("5. Account Lockout")

    # Create a separate throwaway account for lockout testing
    lock_op = f"locktest_{RUN_ID}"
    req("POST", "/api/auth/signup", {
        "operator_id":  lock_op,
        "email":        f"{lock_op}@test.local",
        "display_name": "Lockout Test",
        "password":     TEST_PW,
    })

    # Hammer with bad passwords up to the threshold (default 5)
    for i in range(int(os.getenv("LOGIN_MAX_ATTEMPTS", 5))):
        req("POST", "/api/auth/login", {
            "operator_id": lock_op,
            "password":    "WrongPassword99!",
        })

    # Account should now be locked
    status, body = req("POST", "/api/auth/login", {
        "operator_id": lock_op,
        "password":    TEST_PW,  # even correct password is rejected
    })
    check("Account locked after max failed attempts (403)", status == 403, f"got {status}")
    check("Lock message mentions lockout",
          "locked" in body.get("error", "").lower(), body.get("error"))

    # Verify in DB
    row = db.fetchone(
        "SELECT failed_attempts, locked_until FROM users WHERE operator_id = %s",
        (lock_op,)
    )
    check("failed_attempts at threshold in DB",    row and row["failed_attempts"] >= int(os.getenv("LOGIN_MAX_ATTEMPTS", 5)))
    check("locked_until is set in DB",             row and row["locked_until"] is not None)


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "═" * 54)
    print("  PacketPulse — Phase 3 Auth Test Suite")
    print("═" * 54)

    try:
        test_signup()
        token = test_login()
        if token:
            test_me(token)
            test_signout(token)
        else:
            print("\n  Skipping /me and signout — no token from login.")
            results["failed"] += 1
        test_lockout()
    finally:
        cleanup()

    print(f"\n{'═' * 54}")
    print(f"  Results:  "
          f"\033[92m{results['passed']} passed\033[0m  "
          f"\033[91m{results['failed']} failed\033[0m")
    print(f"{'═' * 54}\n")

    sys.exit(0 if results["failed"] == 0 else 1)
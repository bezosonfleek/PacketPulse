"""
routes/auth_routes.py — Signup, signin, signout endpoints.

STUB — filled in during Phase 3 (Authentication System).

Registered routes (all under /api/auth/):
    POST /api/auth/signup   → create a new operator account
    POST /api/auth/signin   → verify credentials, issue JWT
    POST /api/auth/signout  → revoke the current session
"""


def handle(path: str, method: str, handler_self) -> bool:
    """
    Entry point called by main.py's router.

    Returns True if this module handled the request,
    False if the path doesn't belong here (router tries next module).
    """
    # Stub — no routes active yet
    return False
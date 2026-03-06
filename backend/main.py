"""
main.py — PacketPulse backend entry point.

Responsibilities:
  - Start the HTTP server on the configured host:port
  - Initialise the database connection pool on startup
  - Route every incoming request to the correct handler module
  - Provide shared request/response helpers all routes use
  - Handle CORS so the frontend (served by Nginx) can call the API
  - Catch AuthError and convert it to a clean 401 JSON response
  - Catch unhandled exceptions and return a 500 without leaking internals

No framework — uses Python's built-in http.server, extended with
a structured router and shared helpers.

Run directly during development:
    python3 main.py

In production it runs inside the Docker backend container.
"""

import json
import logging
import os
import signal
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from dotenv import load_dotenv

import db
from auth import AuthError
from routes import auth_routes, scan_routes

# ─────────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────────
load_dotenv()

HOST = os.getenv("SERVER_HOST", "0.0.0.0")
PORT = int(os.getenv("SERVER_PORT", 8000))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("main")


# ─────────────────────────────────────────────────────────────
#  RESPONSE HELPERS
#  Imported by route modules:
#    from main import send_json, send_error, read_json_body
# ─────────────────────────────────────────────────────────────
def send_json(handler, data: dict | list, status: int = 200) -> None:
    """
    Serialise `data` to JSON and write a complete HTTP response.
    Sets Content-Type and CORS headers automatically.
    """
    body = json.dumps(data, default=str).encode()
    handler.send_response(status)
    _set_common_headers(handler, "application/json", len(body))
    handler.end_headers()
    handler.wfile.write(body)


def send_error(handler, message: str, status: int = 400) -> None:
    """
    Send a JSON error response in the standard shape:
        {"error": "<message>"}
    """
    send_json(handler, {"error": message}, status)


def read_json_body(handler) -> dict | list | None:
    """
    Read and parse the request body as JSON.
    Returns None if the body is missing, empty, or not valid JSON.
    Route handlers should call this and check for None before proceeding.
    """
    length = int(handler.headers.get("Content-Length", 0))
    if length == 0:
        return None
    try:
        raw = handler.rfile.read(length)
        return json.loads(raw.decode())
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        log.debug("Failed to parse request body: %s", e)
        return None


def _set_common_headers(handler, content_type: str, length: int) -> None:
    """
    Write headers common to every response.
    CORS headers allow the Nginx-served frontend to call this API.
    Adjust Access-Control-Allow-Origin in production to your exact domain.
    """
    handler.send_header("Content-Type",                content_type)
    handler.send_header("Content-Length",              str(length))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods","GET, POST, OPTIONS")
    handler.send_header(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization",
    )
    # Basic security headers
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options",         "DENY")


# ─────────────────────────────────────────────────────────────
#  REQUEST HANDLER
#  One instance is created per incoming request by HTTPServer.
# ─────────────────────────────────────────────────────────────
class PacketPulseHandler(BaseHTTPRequestHandler):

    # Silence the default access log — we write our own below
    def log_message(self, fmt, *args):
        pass

    # ── Preflight (browser CORS) ─────────────────────────────
    def do_OPTIONS(self):
        self.send_response(204)
        _set_common_headers(self, "text/plain", 0)
        self.end_headers()

    # ── GET ──────────────────────────────────────────────────
    def do_GET(self):
        self._dispatch("GET")

    # ── POST ─────────────────────────────────────────────────
    def do_POST(self):
        self._dispatch("POST")

    # ── ROUTER ───────────────────────────────────────────────
    def _dispatch(self, method: str):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"

        # Attach parsed path and query to self so route modules can read them
        self.parsed_path  = path
        self.query_params = parse_qs(parsed.query)

        log.info("%s %s", method, path)

        try:
            # Health check — useful for Docker health checks
            if path == "/api/health" and method == "GET":
                send_json(self, {"status": "ok"})
                return

            # Delegate to route modules in priority order.
            # Each handle() returns True if it owned the route, False otherwise.
            if auth_routes.handle(path, method, self):
                return

            if scan_routes.handle(path, method, self):
                return

            # Nothing matched
            send_error(self, "Not found.", 404)

        except AuthError as e:
            # Any route that calls require_auth() and fails ends up here
            log.info("Auth rejected [%s %s]: %s", method, path, e.message)
            send_error(self, e.message, 401)

        except Exception as e:
            # Unexpected server error — log full traceback, send generic message
            log.exception("Unhandled error [%s %s]", method, path)
            send_error(self, "Internal server error.", 500)


# ─────────────────────────────────────────────────────────────
#  STARTUP / SHUTDOWN
# ─────────────────────────────────────────────────────────────
def _shutdown(server: HTTPServer, signum, frame):
    log.info("Shutdown signal received — closing server and DB pool.")
    db.close_pool()
    server.server_close()
    sys.exit(0)


def main():
    log.info("PacketPulse backend starting...")

    # Connect to Postgres — fails fast if unreachable
    db.init_pool()

    server = HTTPServer((HOST, PORT), PacketPulseHandler)

    # Graceful shutdown on SIGTERM (Docker stop) and SIGINT (Ctrl-C)
    signal.signal(signal.SIGTERM, lambda s, f: _shutdown(server, s, f))
    signal.signal(signal.SIGINT,  lambda s, f: _shutdown(server, s, f))

    log.info("Listening on http://%s:%d", HOST, PORT)
    log.info("Routes active: /api/health  (auth + scan routes: Phase 3 & 4)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        db.close_pool()
        log.info("Server stopped.")


if __name__ == "__main__":
    main()
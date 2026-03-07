"""
main.py — PacketPulse backend entry point.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import logging
import signal
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from dotenv import load_dotenv
load_dotenv()

import db
from auth import AuthError

# Import route modules — must come after sys.path is set
import routes.auth_routes as auth_routes
import routes.scan_routes as scan_routes
import routes.admin_routes as admin_routes

HOST = os.getenv("SERVER_HOST", "0.0.0.0")
PORT = int(os.getenv("SERVER_PORT", 8000))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("main")


# ─────────────────────────────────────────────────────────────
#  RESPONSE HELPERS  (imported by route modules)
# ─────────────────────────────────────────────────────────────
def send_json(handler, data, status=200):
    body = json.dumps(data, default=str).encode()
    handler.send_response(status)
    _common_headers(handler, "application/json", len(body))
    handler.end_headers()
    handler.wfile.write(body)


def send_error(handler, message, status=400):
    send_json(handler, {"error": message}, status)


def read_json_body(handler):
    length = int(handler.headers.get("Content-Length", 0))
    if length == 0:
        return None
    try:
        return json.loads(handler.rfile.read(length).decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


# Dev frontend origin — credentials: 'include' requires a specific
# origin, not wildcard. In Docker/production, frontend and backend
# share an origin via Nginx so this header can go back to *.
ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "http://localhost:3000")

def _common_headers(handler, content_type, length):
    handler.send_header("Content-Type",                   content_type)
    handler.send_header("Content-Length",                 str(length))
    handler.send_header("Access-Control-Allow-Origin",    ALLOWED_ORIGIN)
    handler.send_header("Access-Control-Allow-Methods",   "GET, POST, PATCH, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers",   "Content-Type, Authorization")
    handler.send_header("Access-Control-Allow-Credentials", "true")
    handler.send_header("X-Content-Type-Options",         "nosniff")
    handler.send_header("X-Frame-Options",                "DENY")


# ─────────────────────────────────────────────────────────────
#  REQUEST HANDLER
# ─────────────────────────────────────────────────────────────
class PacketPulseHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # replaced by structured logging below

    def do_OPTIONS(self):
        self.send_response(204)
        _common_headers(self, "text/plain", 0)
        self.end_headers()

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def _dispatch(self, method):
        parsed           = urlparse(self.path)
        path             = parsed.path.rstrip("/") or "/"
        self.parsed_path  = path
        self.query_params = parse_qs(parsed.query)

        log.info("%s %s", method, path)

        try:
            if path == "/api/health" and method == "GET":
                send_json(self, {"status": "ok"})
                return

            if auth_routes.handle(path, method, self):
                return

            if scan_routes.handle(path, method, self):
                return

            if admin_routes.handle(path, method, self):
                return

            send_error(self, "Not found.", 404)

        except AuthError as e:
            log.info("Auth rejected [%s %s]: %s", method, path, e.message)
            send_error(self, e.message, 401)

        except Exception:
            log.exception("Unhandled error [%s %s]", method, path)
            send_error(self, "Internal server error.", 500)


# ─────────────────────────────────────────────────────────────
#  STARTUP / SHUTDOWN
# ─────────────────────────────────────────────────────────────
def _shutdown(server, signum, frame):
    log.info("Shutting down...")
    db.close_pool()
    server.server_close()
    sys.exit(0)


def main():
    log.info("PacketPulse backend starting...")
    db.init_pool()

    server = HTTPServer((HOST, PORT), PacketPulseHandler)
    signal.signal(signal.SIGTERM, lambda s, f: _shutdown(server, s, f))
    signal.signal(signal.SIGINT,  lambda s, f: _shutdown(server, s, f))

    log.info("Listening on http://%s:%d", HOST, PORT)
    log.info("Routes active: /api/health | /api/auth/* | /api/scan/* | /api/admin/*")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        db.close_pool()
        log.info("Server stopped.")


if __name__ == "__main__":
    main()
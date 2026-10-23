"""Vercel serverless endpoint: POST /api/cancel with JSON {"id": "<scheduled message id>", "channel": "<channel id, optional>"}."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import auth, manual  # noqa: E402


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not auth.guard(self):  # signed-in users only; the reply is already sent
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(length, 2000)) or b"{}")
        except (ValueError, json.JSONDecodeError):
            body = None
        if not isinstance(body, dict):
            return self._reply(400, "Invalid request body")
        status, message = manual.cancel(body.get("id"), channel=body.get("channel"))
        self._reply(status, message)

    def _reply(self, status, message):
        data = json.dumps({"ok": status == 200, "message": message}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

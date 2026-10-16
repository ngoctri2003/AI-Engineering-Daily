"""Vercel serverless endpoint: POST /api/send with JSON {"password": "...", "text": "..."}."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import manual  # noqa: E402


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(length, 20000)) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._reply(400, "Invalid request body")
        if not isinstance(body, dict):
            return self._reply(400, "Invalid request body")
        status, message = manual.handle(body.get("password"), body.get("text"))
        self._reply(status, message)

    def _reply(self, status, message):
        data = json.dumps({"ok": status == 200, "message": message}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

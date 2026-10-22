"""Vercel serverless endpoint: POST /api/send with JSON {"title": "...", "text": "...", "post_at": <unix seconds, optional>, "images": [<base64>, ...] (optional)}."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import manual  # noqa: E402

MAX_REQUEST = 4_300_000  # stays under the 4.5 MB Vercel request body limit


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_REQUEST:
                return self._reply(413, "Request is too large (images total over about 3 MB)")
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._reply(400, "Invalid request body")
        if not isinstance(body, dict):
            return self._reply(400, "Invalid request body")
        status, message = manual.handle(body.get("title"), body.get("text"), body.get("post_at"), body.get("images"))
        self._reply(status, message)

    def _reply(self, status, message):
        data = json.dumps({"ok": status == 200, "message": message}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

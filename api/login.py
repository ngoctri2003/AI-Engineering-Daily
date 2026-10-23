"""Vercel serverless endpoint: POST /api/login with JSON {"email": "...", "password": "..."} sets the session cookie."""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import auth  # noqa: E402

FAIL_DELAY = 1.0  # slows down guessing; Vercel keeps no shared counter, so also set a rate limit rule in the firewall


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not auth.configured():
            return auth.reply(self, 503, {"ok": False, "message": "Login is not configured on the server"})
        if not auth.same_origin(self.headers):
            return auth.reply(self, 403, {"ok": False, "message": "Request refused"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(length, 2000)) or b"{}")
        except (ValueError, json.JSONDecodeError):
            body = None
        if not isinstance(body, dict):
            return auth.reply(self, 400, {"ok": False, "message": "Invalid request body"})
        try:
            email = auth.authenticate(body.get("email"), body.get("password"))
        except auth.NotConfigured:
            return auth.reply(self, 503, {"ok": False, "message": "Login is not configured on the server"})
        if not email:
            time.sleep(FAIL_DELAY)
            return auth.reply(self, 401, {"ok": False, "message": "Wrong email or password"})
        auth.reply(self, 200, {"ok": True, "email": email}, auth.session_cookie(auth.make_token(email), self.headers))

"""Vercel serverless endpoint: GET /api/session tells the page whether the visitor is signed in."""
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import auth  # noqa: E402


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not auth.configured():
            return auth.reply(self, 503, {"ok": False, "message": "Login is not configured on the server"})
        email = auth.current_user(self.headers)
        if not email:
            return auth.reply(self, 401, {"ok": False, "message": "Login required"})
        auth.reply(self, 200, {"ok": True, "email": email})

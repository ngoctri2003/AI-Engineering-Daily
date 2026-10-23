"""Vercel serverless endpoint: POST /api/logout clears the session cookie."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import auth  # noqa: E402


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not auth.same_origin(self.headers):
            return auth.reply(self, 403, {"ok": False, "message": "Request refused"})
        auth.reply(self, 200, {"ok": True}, auth.clear_cookie(self.headers))

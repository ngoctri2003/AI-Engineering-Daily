"""Vercel serverless endpoint: GET /api/channels lists the channels the bot is a member of, for the channel picker."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import auth, manual  # noqa: E402


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not auth.guard(self):  # signed-in users only; the reply is already sent
            return
        data = json.dumps(manual.channels()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

"""Vercel serverless endpoint: GET /api/messages?channel=<id> lists scheduled and recently sent bot messages."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import manual  # noqa: E402


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        channel = (parse_qs(urlparse(self.path).query).get("channel") or [""])[0]
        data = json.dumps(manual.activity(channel=channel)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

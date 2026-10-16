"""Manual send: validate a request from the web form and post it through the existing Slack poster."""
import hmac
import os

from . import slack

MAX_LEN = 3500


def handle(password, text, post=slack.post):
    """Return (http_status, message). `post` is injectable for tests."""
    expected = os.environ.get("MANUAL_SEND_PASSWORD", "")
    if not expected:
        return 503, "Manual send is not configured"
    if not hmac.compare_digest(str(password or "").encode(), expected.encode()):
        return 401, "Wrong password"
    text = (text or "").strip()
    if not text:
        return 400, "Message is empty"
    if len(text) > MAX_LEN:
        return 400, f"Message is too long (max {MAX_LEN} characters)"
    try:
        post(text)
    except Exception as ex:
        print(f"[manual] send failed: {type(ex).__name__}: {ex}")
        return 502, "Failed to send to Slack, check the function logs"
    return 200, "Sent"

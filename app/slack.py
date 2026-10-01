"""Đăng Slack. Ưu tiên bot token (chat.postMessage, có thread); fallback incoming webhook."""
import json
import os
import urllib.request


def _post_json(url, body, headers=None):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json; charset=utf-8", **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()


def post(text, notes=None):
    token = os.environ.get("SLACK_BOT_TOKEN")
    channel = os.environ.get("SLACK_CHANNEL_ID")
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    allow = [c for c in os.environ.get("SLACK_ALLOWED_CHANNELS", "").split(",") if c]
    if token and channel:
        if allow and channel not in allow:
            raise RuntimeError(f"Channel {channel} không nằm trong allow-list")
        auth = {"Authorization": f"Bearer {token}"}
        res = json.loads(_post_json("https://slack.com/api/chat.postMessage", {
            "channel": channel, "text": text, "mrkdwn": True,
            "unfurl_links": False, "unfurl_media": False}, auth))
        if not res.get("ok"):
            raise RuntimeError(f"Slack lỗi: {res.get('error')}")
        if notes:
            _post_json("https://slack.com/api/chat.postMessage", {
                "channel": channel, "thread_ts": res["ts"], "text": notes, "mrkdwn": True,
                "unfurl_links": False}, auth)
        return
    if webhook:
        _post_json(webhook, {"text": text, "mrkdwn": True})
        if notes:
            _post_json(webhook, {"text": notes, "mrkdwn": True})
        return
    raise RuntimeError("Thiếu SLACK_BOT_TOKEN+SLACK_CHANNEL_ID hoặc SLACK_WEBHOOK_URL")

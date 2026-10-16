"""Đăng Slack. Ưu tiên bot token (chat.postMessage, có thread); fallback incoming webhook."""
import json
import os
import urllib.parse
import urllib.request


def _post_json(url, body, headers=None):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json; charset=utf-8", **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()


def alert(text):
    """Báo lỗi vận hành. Kênh: ALERT_CHANNEL_ID, nếu trống thì dùng SLACK_CHANNEL_ID."""
    token = os.environ.get("SLACK_BOT_TOKEN")
    channel = os.environ.get("ALERT_CHANNEL_ID") or os.environ.get("SLACK_CHANNEL_ID")
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if token and channel:
        res = json.loads(_post_json("https://slack.com/api/chat.postMessage", {
            "channel": channel, "text": text, "mrkdwn": True, "unfurl_links": False},
            {"Authorization": f"Bearer {token}"}))
        if not res.get("ok"):
            raise RuntimeError(f"Slack lỗi: {res.get('error')}")
        return
    if webhook:
        _post_json(webhook, {"text": text, "mrkdwn": True})
        return
    raise RuntimeError("Thiếu SLACK_BOT_TOKEN+channel hoặc SLACK_WEBHOOK_URL để báo lỗi")


def post(text, notes=None):
    token = os.environ.get("SLACK_BOT_TOKEN")
    channel = os.environ.get("SLACK_CHANNEL_ID")
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    allow = [c for c in os.environ.get("SLACK_ALLOWED_CHANNELS", "").split(",") if c]
    if token and channel:
        if allow and channel not in allow:
            raise RuntimeError(f"Channel {channel} is not in the allow-list")
        auth = {"Authorization": f"Bearer {token}"}
        res = json.loads(_post_json("https://slack.com/api/chat.postMessage", {
            "channel": channel, "text": text, "mrkdwn": True,
            "unfurl_links": False, "unfurl_media": False}, auth))
        if not res.get("ok"):
            raise RuntimeError(f"Slack error: {res.get('error')}")
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
    raise RuntimeError("Missing SLACK_BOT_TOKEN+SLACK_CHANNEL_ID or SLACK_WEBHOOK_URL")


def schedule(text, post_at):
    """Schedule a message with chat.scheduleMessage (bot token only). post_at is a unix timestamp."""
    token = os.environ.get("SLACK_BOT_TOKEN")
    channel = os.environ.get("SLACK_CHANNEL_ID")
    allow = [c for c in os.environ.get("SLACK_ALLOWED_CHANNELS", "").split(",") if c]
    if not (token and channel):
        raise RuntimeError("Scheduling needs SLACK_BOT_TOKEN and SLACK_CHANNEL_ID")
    if allow and channel not in allow:
        raise RuntimeError(f"Channel {channel} is not in the allow-list")
    res = json.loads(_post_json("https://slack.com/api/chat.scheduleMessage", {
        "channel": channel, "text": text, "post_at": int(post_at), "mrkdwn": True,
        "unfurl_links": False, "unfurl_media": False}, {"Authorization": f"Bearer {token}"}))
    if not res.get("ok"):
        raise RuntimeError(f"Slack error: {res.get('error')}")


def _config():
    token = os.environ.get("SLACK_BOT_TOKEN")
    channel = os.environ.get("SLACK_CHANNEL_ID")
    allow = [c for c in os.environ.get("SLACK_ALLOWED_CHANNELS", "").split(",") if c]
    if not (token and channel):
        raise RuntimeError("Missing SLACK_BOT_TOKEN or SLACK_CHANNEL_ID")
    if allow and channel not in allow:
        raise RuntimeError(f"Channel {channel} is not in the allow-list")
    return token, channel


def _get(method, params, token):
    req = urllib.request.Request(
        f"https://slack.com/api/{method}?{urllib.parse.urlencode(params)}",
        headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        res = json.loads(r.read().decode())
    if not res.get("ok"):
        raise RuntimeError(f"Slack error: {res.get('error')}")
    return res


def list_scheduled():
    """Messages this bot has scheduled for the configured channel."""
    token, channel = _config()
    res = _get("chat.scheduledMessages.list", {"channel": channel, "limit": 100}, token)
    return [{"id": m["id"], "post_at": m["post_at"], "text": m.get("text", "")}
            for m in res.get("scheduled_messages", [])]


def list_sent(limit=30):
    """Recent messages posted by this bot in the configured channel (needs channels:history or groups:history)."""
    token, channel = _config()
    bot_user = _get("auth.test", {}, token).get("user_id")
    res = _get("conversations.history", {"channel": channel, "limit": 100}, token)
    out = []
    for m in res.get("messages", []):
        if m.get("user") == bot_user or m.get("bot_id"):
            out.append({"ts": m["ts"], "text": m.get("text", "")})
        if len(out) >= limit:
            break
    return out


def cancel_scheduled(scheduled_id):
    token, channel = _config()
    res = json.loads(_post_json("https://slack.com/api/chat.deleteScheduledMessage", {
        "channel": channel, "scheduled_message_id": scheduled_id}, {"Authorization": f"Bearer {token}"}))
    if not res.get("ok"):
        raise RuntimeError(f"Slack error: {res.get('error')}")

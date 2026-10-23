"""Đăng Slack. Ưu tiên bot token (chat.postMessage, có thread); fallback incoming webhook."""
import json
import os
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor


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


SLACK_SEP = "\n\n" + "\u2501" * 20 + "\n\n"
MAX_MESSAGE = 3800  # Slack splits longer messages on its own, in the middle of a block


def split_message(text, limit=MAX_MESSAGE):
    """Split at block separators so no block is cut; a single over-long block is left whole."""
    if len(text) <= limit:
        return [text]
    parts, current = [], ""
    for block in text.split(SLACK_SEP):
        candidate = block if not current else current + SLACK_SEP + block
        if current and len(candidate) > limit:
            parts.append(current)
            current = block
        else:
            current = candidate
    parts.append(current)
    return parts


def post(text, notes=None, blocks=None):
    if blocks:  # rich message (images): sent as one message, text limits apply per block
        return _post_one(text, notes, blocks)
    chunks = split_message(text)
    for chunk in chunks[:-1]:
        _post_one(chunk)
    return _post_one(chunks[-1], notes)


def _slack_ok(raw):
    res = json.loads(raw)
    if not res.get("ok"):
        raise RuntimeError(f"Slack error: {res.get('error')}")
    return res


def _call_with_retry(call, rich):
    """A file uploaded a moment ago may not be usable in blocks yet (invalid_blocks), so retry briefly."""
    attempts = 4 if rich else 1
    for n in range(attempts):
        try:
            return call()
        except RuntimeError as ex:
            if n == attempts - 1 or "invalid_blocks" not in str(ex):
                raise
            time.sleep(1.5)


def _post_one(text, notes=None, blocks=None):
    token = os.environ.get("SLACK_BOT_TOKEN")
    channel = os.environ.get("SLACK_CHANNEL_ID")
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    allow = [c for c in os.environ.get("SLACK_ALLOWED_CHANNELS", "").split(",") if c]
    if token and channel:
        if allow and channel not in allow:
            raise RuntimeError(f"Channel {channel} is not in the allow-list")
        auth = {"Authorization": f"Bearer {token}"}
        payload = {"channel": channel, "text": text, "mrkdwn": True,
                   "unfurl_links": False, "unfurl_media": False}
        if blocks:
            payload["blocks"] = blocks
        res = _call_with_retry(
            lambda: _slack_ok(_post_json("https://slack.com/api/chat.postMessage", payload, auth)), bool(blocks))
        if notes:
            _post_json("https://slack.com/api/chat.postMessage", {
                "channel": channel, "thread_ts": res["ts"], "text": notes, "mrkdwn": True,
                "unfurl_links": False}, auth)
        return
    if webhook:
        if blocks:
            raise RuntimeError("Images need SLACK_BOT_TOKEN and SLACK_CHANNEL_ID (a webhook cannot attach them)")
        _post_json(webhook, {"text": text, "mrkdwn": True})
        if notes:
            _post_json(webhook, {"text": notes, "mrkdwn": True})
        return
    raise RuntimeError("Missing SLACK_BOT_TOKEN+SLACK_CHANNEL_ID or SLACK_WEBHOOK_URL")


def schedule(text, post_at, blocks=None):
    """Schedule a message with chat.scheduleMessage (bot token only). post_at is a unix timestamp."""
    token = os.environ.get("SLACK_BOT_TOKEN")
    channel = os.environ.get("SLACK_CHANNEL_ID")
    allow = [c for c in os.environ.get("SLACK_ALLOWED_CHANNELS", "").split(",") if c]
    if not (token and channel):
        raise RuntimeError("Scheduling needs SLACK_BOT_TOKEN and SLACK_CHANNEL_ID")
    if allow and channel not in allow:
        raise RuntimeError(f"Channel {channel} is not in the allow-list")
    payload = {"channel": channel, "text": text, "post_at": int(post_at), "mrkdwn": True,
               "unfurl_links": False, "unfurl_media": False}
    if blocks:
        payload["blocks"] = blocks
    _call_with_retry(lambda: _slack_ok(_post_json(
        "https://slack.com/api/chat.scheduleMessage", payload, {"Authorization": f"Bearer {token}"})), bool(blocks))


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


def list_sent(limit=50):
    """Recent messages posted by this bot in the configured channel (needs channels:history or groups:history)."""
    token, channel = _config()
    who = _get("auth.test", {}, token)
    bot_user, base = who.get("user_id"), (who.get("url") or "").rstrip("/")
    res = _get("conversations.history", {"channel": channel, "limit": 200}, token)
    out = []
    for m in res.get("messages", []):
        if m.get("user") == bot_user or m.get("bot_id"):
            out.append({
                "ts": m["ts"], "text": m.get("text", ""),
                "images": sum(1 for b in m.get("blocks", []) if b.get("type") == "image") + len(m.get("files", [])),
                "link": f"{base}/archives/{channel}/p{m['ts'].replace('.', '')}" if base else ""})
        if len(out) >= limit:
            break
    return out


def cancel_scheduled(scheduled_id):
    token, channel = _config()
    res = json.loads(_post_json("https://slack.com/api/chat.deleteScheduledMessage", {
        "channel": channel, "scheduled_message_id": scheduled_id}, {"Authorization": f"Bearer {token}"}))
    if not res.get("ok"):
        raise RuntimeError(f"Slack error: {res.get('error')}")


def upload_images(images):
    """Upload [(filename, bytes)] to Slack without sharing them; return the file ids (needs the files:write scope)."""
    token, _channel = _config()

    def one(item):
        name, data = item
        res = _get("files.getUploadURLExternal", {"filename": name, "length": len(data)}, token)
        req = urllib.request.Request(res["upload_url"], data=data, method="POST",
                                     headers={"Content-Type": "application/octet-stream"})
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
        return res["file_id"]

    with ThreadPoolExecutor(max_workers=5) as pool:
        ids = list(pool.map(one, images))
    _slack_ok(_post_json("https://slack.com/api/files.completeUploadExternal", {
        "files": [{"id": i, "title": n} for i, (n, _data) in zip(ids, images)]},
        {"Authorization": f"Bearer {token}"}))
    return ids

"""Manual send: validate a request from the web form and post or schedule it through the Slack bot."""
import base64
import re
import time

from . import slack

MAX_TITLE = 150
MAX_BODY = 3500
MIN_LEAD = 60                   # Slack rejects times that are too close to now
MAX_LEAD = 120 * 24 * 3600      # Slack allows scheduling up to 120 days ahead
MAX_IMAGES = 10
MAX_IMAGE_BYTES = 3_000_000     # decoded total; Vercel caps the request body at 4.5 MB and base64 adds a third
MAX_BLOCK_TEXT = 3000           # Slack section blocks accept at most 3000 characters
IMAGE_MAGIC = ((b"\xff\xd8\xff", "jpg"), (b"\x89PNG\r\n\x1a\n", "png"), (b"GIF8", "gif"))


def build_text(title, body):
    return f"*{title}*\n\n{body}"


def _image_ext(data):
    for magic, ext in IMAGE_MAGIC:
        if data.startswith(magic):
            return ext
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def decode_images(raw):
    """Check the images of a request (base64 strings) and return [(filename, bytes)]; raise ValueError with a message."""
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise ValueError("Invalid images")
    if len(raw) > MAX_IMAGES:
        raise ValueError(f"Too many images (max {MAX_IMAGES})")
    out, total = [], 0
    for n, item in enumerate(raw, 1):
        if not isinstance(item, str):
            raise ValueError("Invalid images")
        payload = item.split(",", 1)[1] if item.startswith("data:") and "," in item else item
        try:
            data = base64.b64decode(payload, validate=True)
        except ValueError:
            raise ValueError(f"Image {n} is not valid base64") from None
        ext = _image_ext(data)
        if not ext:
            raise ValueError(f"Image {n} is not a JPEG, PNG, GIF or WebP file")
        total += len(data)
        if total > MAX_IMAGE_BYTES:
            raise ValueError("Images are too large in total (max about 3 MB)")
        out.append((f"image-{n}.{ext}", data))
    return out


def _chunks(text, limit):
    out, cur = [], ""
    for line in text.split("\n"):
        while len(line) > limit:
            if cur:
                out.append(cur)
                cur = ""
            out.append(line[:limit])
            line = line[limit:]
        cand = line if not cur else cur + "\n" + line
        if len(cand) > limit:
            out.append(cur)
            cur = line
        else:
            cur = cand
    out.append(cur)
    return [c for c in out if c.strip()]


def build_blocks(text, file_ids, alt):
    """Message text as section blocks (max 3000 characters each) followed by one image block per uploaded file."""
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": part}} for part in _chunks(text, MAX_BLOCK_TEXT)]
    alt = alt[:200]
    for n, file_id in enumerate(file_ids, 1):
        blocks.append({"type": "image", "slack_file": {"id": file_id}, "alt_text": f"{alt} ({n}/{len(file_ids)})"})
    return blocks


def handle(title, body, post_at=None, images=None, post=slack.post, schedule=slack.schedule,
           upload=slack.upload_images, now=time.time):
    """Return (http_status, message). Slack calls are injectable for tests."""
    title = " ".join(str(title or "").split())
    body = str(body or "").strip()
    if not title:
        return 400, "Title is empty"
    if not body:
        return 400, "Message is empty"
    if len(title) > MAX_TITLE:
        return 400, f"Title is too long (max {MAX_TITLE} characters)"
    if len(body) > MAX_BODY:
        return 400, f"Message is too long (max {MAX_BODY} characters)"
    try:
        files = decode_images(images)
    except ValueError as ex:
        return 400, str(ex)
    text = build_text(title, body)
    if post_at in (None, ""):
        when = None
    else:
        try:
            when = int(post_at)
        except (TypeError, ValueError):
            return 400, "Invalid schedule time"
        lead = when - now()
        if lead < MIN_LEAD:
            return 400, "Schedule time must be at least 1 minute in the future"
        if lead > MAX_LEAD:
            return 400, "Schedule time must be within 120 days"
    try:
        extra = {"blocks": build_blocks(text, upload(files), title)} if files else {}
        if when is None:
            post(text, **extra)
            return 200, "Sent"
        schedule(text, when, **extra)
        return 200, "Scheduled"
    except RuntimeError as ex:
        # Raised by app.slack with a Slack error code or a config problem; contains no secrets.
        print(f"[manual] send failed: {ex}")
        hint = " (add the files:write scope to the Slack app and reinstall it)" if files and "missing_scope" in str(ex) else ""
        return 502, f"Failed to send to Slack: {ex}{hint}"
    except Exception as ex:
        print(f"[manual] send failed: {type(ex).__name__}: {ex}")
        return 502, "Failed to send to Slack, check the function logs"


def activity(list_scheduled=slack.list_scheduled, list_sent=slack.list_sent):
    """Return {"scheduled": [...], "sent": [...], "warnings": [...]}. Each list fails independently."""
    out = {"scheduled": [], "sent": [], "warnings": []}
    try:
        out["scheduled"] = sorted(list_scheduled(), key=lambda m: m["post_at"])
    except Exception as ex:
        out["warnings"].append(f"Scheduled list unavailable: {_reason(ex)}")
    try:
        out["sent"] = list_sent()
    except Exception as ex:
        out["warnings"].append(f"Sent history unavailable: {_reason(ex)}"
                               + (" (add the channels:history / groups:history scope and reinstall the app)"
                                  if "missing_scope" in _reason(ex) else ""))
    return out


def cancel(scheduled_id, cancel_fn=slack.cancel_scheduled):
    if not re.fullmatch(r"Q[A-Z0-9]{5,30}", str(scheduled_id or "")):
        return 400, "Invalid scheduled message id"
    try:
        cancel_fn(scheduled_id)
    except Exception as ex:
        print(f"[manual] cancel failed: {type(ex).__name__}: {ex}")
        return 502, f"Failed to cancel: {_reason(ex)}"
    return 200, "Cancelled"


def _reason(ex):
    # RuntimeError comes from app.slack and carries a Slack error code or config problem, never a secret.
    return str(ex) if isinstance(ex, RuntimeError) else "request failed, check the function logs"

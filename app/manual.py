"""Manual send: validate a request from the web form and post or schedule it through the Slack bot."""
import base64
import os
import re
import time

from . import slack

CHANNEL_RE = re.compile(r"[CG][A-Z0-9]{6,20}")  # Slack public / private channel ids

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


def _clean_channel(channel):
    """None for 'use the server default', the id when it looks like a Slack channel id; raise ValueError otherwise."""
    channel = str(channel or "").strip()
    if not channel:
        return None
    if not CHANNEL_RE.fullmatch(channel):
        raise ValueError("Invalid channel")
    return channel


def handle(title, body, post_at=None, images=None, channel=None, post=slack.post, schedule=slack.schedule,
           upload=slack.upload_images, now=time.time, list_channels=slack.list_channels):
    """Return (http_status, message). Slack calls are injectable for tests.

    `channel` is the channel id picked in the form. Empty means the SLACK_CHANNEL_ID default. A picked channel must be
    one the bot is a member of, which replaces the SLACK_ALLOWED_CHANNELS check for manual sends."""
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
        channel = _clean_channel(channel)
        files = decode_images(images)
    except ValueError as ex:
        return 400, str(ex)
    if channel and channel == os.environ.get("SLACK_CHANNEL_ID"):
        channel = None  # same as before this feature: SLACK_CHANNEL_ID and SLACK_ALLOWED_CHANNELS apply
    if channel:
        try:
            known = {c["id"] for c in list_channels()}
        except Exception as ex:
            print(f"[manual] channel check failed: {type(ex).__name__}: {ex}")
            return 502, f"Could not check the channel: {_reason(ex)}"
        if channel not in known:
            return 400, "The bot is not a member of this channel"
    to = {"channel": channel} if channel else {}
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
        extra.update(to)
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


def channels(list_channels=slack.list_channels, default=None):
    """Return {"channels": [{id, name, private}], "default": id, "warnings": [...]} for the channel picker."""
    if default is None:
        default = os.environ.get("SLACK_CHANNEL_ID", "")
    out = {"channels": [], "default": default if CHANNEL_RE.fullmatch(default or "") else "", "warnings": []}
    try:
        out["channels"] = list_channels()
        if out["default"] and all(c["id"] != out["default"] for c in out["channels"]):
            # Keep the old behaviour reachable: the configured channel may work without the bot being a member of it
            # (for example a public channel with chat:write.public), and its scheduled messages live there.
            out["channels"].insert(0, {"id": out["default"], "name": out["default"], "private": False})
    except Exception as ex:
        print(f"[manual] channel list failed: {type(ex).__name__}: {ex}")
        out["warnings"].append(f"Channel list unavailable: {_reason(ex)}"
                               + (" (add the channels:read / groups:read scope and reinstall the app)"
                                  if "missing_scope" in _reason(ex) else ""))
    return out


def activity(list_scheduled=slack.list_scheduled, list_sent=slack.list_sent, channel=None):
    """Return {"scheduled": [...], "sent": [...], "warnings": [...]} for `channel` (default: the server channel).
    Each list fails independently."""
    out = {"scheduled": [], "sent": [], "warnings": []}
    try:
        channel = _clean_channel(channel)
    except ValueError:
        out["warnings"].append("Invalid channel")
        return out
    kw = {"channel": channel} if channel else {}
    try:
        out["scheduled"] = sorted(list_scheduled(**kw), key=lambda m: m["post_at"])
    except Exception as ex:
        out["warnings"].append(f"Scheduled list unavailable: {_reason(ex)}")
    try:
        out["sent"] = list_sent(**kw)
    except Exception as ex:
        out["warnings"].append(f"Sent history unavailable: {_reason(ex)}"
                               + (" (add the channels:history / groups:history scope and reinstall the app)"
                                  if "missing_scope" in _reason(ex) else ""))
    return out


def cancel(scheduled_id, cancel_fn=slack.cancel_scheduled, channel=None):
    if not SCHEDULED_ID_RE.fullmatch(str(scheduled_id or "")):
        return 400, "Invalid scheduled message id"
    try:
        channel = _clean_channel(channel)
    except ValueError as ex:
        return 400, str(ex)
    try:
        cancel_fn(scheduled_id, **({"channel": channel} if channel else {}))
    except Exception as ex:
        print(f"[manual] cancel failed: {type(ex).__name__}: {ex}")
        return 502, f"Failed to cancel: {_reason(ex)}"
    return 200, "Cancelled"


SCHEDULED_ID_RE = re.compile(r"Q[A-Z0-9]{5,30}")


def edit(scheduled_id, title, body, post_at, images=None, channel=None, old_channel=None,
         list_scheduled=slack.list_scheduled, cancel_fn=slack.cancel_scheduled, **handle_kw):
    """Replace a scheduled message. Slack cannot edit one, so the new version is scheduled first and the original is
    cancelled afterwards: a failure in between leaves the original in place (or a duplicate), never a lost message.
    `channel` is where the new version goes, `old_channel` where the original is scheduled (empty = server default).
    Images of the original cannot be read back from Slack, so the new version only has the images sent with it."""
    if not SCHEDULED_ID_RE.fullmatch(str(scheduled_id or "")):
        return 400, "Invalid scheduled message id"
    try:
        old_channel = _clean_channel(old_channel)
    except ValueError as ex:
        return 400, str(ex)
    if post_at in (None, ""):
        return 400, "A scheduled message needs a schedule time"
    old = {"channel": old_channel} if old_channel else {}
    try:
        exists = any(m["id"] == scheduled_id for m in list_scheduled(**old))
    except Exception as ex:
        print(f"[manual] edit lookup failed: {type(ex).__name__}: {ex}")
        return 502, f"Could not check the scheduled message: {_reason(ex)}"
    if not exists:
        return 409, "The scheduled message no longer exists (already sent or cancelled)"
    status, message = handle(title, body, post_at, images, channel, **handle_kw)
    if status != 200:
        return status, message  # nothing changed, the original is still scheduled
    try:
        cancel_fn(scheduled_id, **old)
    except Exception as ex:
        print(f"[manual] edit cancel failed: {type(ex).__name__}: {ex}")
        return 502, (f"The new version is scheduled, but the original could not be cancelled: {_reason(ex)}. "
                     "Cancel the original by hand.")
    return 200, "Updated"


def _reason(ex):
    # RuntimeError comes from app.slack and carries a Slack error code or config problem, never a secret.
    return str(ex) if isinstance(ex, RuntimeError) else "request failed, check the function logs"

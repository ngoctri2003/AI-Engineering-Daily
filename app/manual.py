"""Manual send: validate a request from the web form and post or schedule it through the Slack bot."""
import re
import time

from . import slack

MAX_TITLE = 150
MAX_BODY = 3500
MIN_LEAD = 60                   # Slack rejects times that are too close to now
MAX_LEAD = 120 * 24 * 3600      # Slack allows scheduling up to 120 days ahead


def build_text(title, body):
    return f"*{title}*\n\n{body}"


def handle(title, body, post_at=None, post=slack.post, schedule=slack.schedule, now=time.time):
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
        if when is None:
            post(text)
            return 200, "Sent"
        schedule(text, when)
        return 200, "Scheduled"
    except RuntimeError as ex:
        # Raised by app.slack with a Slack error code or a config problem; contains no secrets.
        print(f"[manual] send failed: {ex}")
        return 502, f"Failed to send to Slack: {ex}"
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

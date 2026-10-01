"""Báo lỗi vận hành lên Slack khi bản tin không đăng được.

Dùng trong workflow: `python -m app.alert` (chạy ở bước `if: failure()`).
Không bao giờ in hoặc gửi secret: giá trị các biến bí mật bị che trước khi ghi/gửi.
"""
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import slack

REASON_FILE = Path(os.environ.get("ERROR_REASON_FILE", "error_reason.txt"))
SECRET_VARS = ("LLM_API_KEY", "SLACK_BOT_TOKEN", "SLACK_WEBHOOK_URL")
MAX_REASON = 300


def mask(text):
    for name in SECRET_VARS:
        val = os.environ.get(name)
        if val and len(val) >= 8:
            text = text.replace(val, "***")
    return text


def clean_reason(text):
    text = " ".join(mask(str(text)).split())
    return text[:MAX_REASON] + ("..." if len(text) > MAX_REASON else "")


def write_reason(text):
    try:
        REASON_FILE.write_text(clean_reason(text))
    except OSError:
        pass


def build_message(reason, run_url, now=None):
    now = now or datetime.now(timezone.utc)
    date_str = f"{now.astimezone(timezone(timedelta(hours=7))):%d/%m/%Y}"
    lines = [f"*AI Engineering Daily: bản tin {date_str} chưa đăng được*"]
    if reason:
        lines.append(f"Lý do: {reason}")
    else:
        lines.append("Lý do: chưa rõ, xem log chạy.")
    if run_url:
        lines.append(f"Log: {run_url}")
    lines.append("Người phụ trách kiểm tra và chạy lại bằng Run workflow nếu cần.")
    return "\n".join(lines)


def main():
    reason = ""
    if REASON_FILE.exists():
        reason = clean_reason(REASON_FILE.read_text())
    msg = build_message(reason, os.environ.get("RUN_URL", ""))
    try:
        slack.alert(msg)
        print("Đã báo lỗi lên Slack.")
    except Exception as ex:  # nếu chính Slack lỗi thì dựa vào email thông báo của GitHub
        print(f"Không báo được lên Slack: {clean_reason(ex)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

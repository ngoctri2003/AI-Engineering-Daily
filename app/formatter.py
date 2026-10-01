"""Ghép định dạng Slack mrkdwn bằng code (không nhờ LLM) và kiểm tra checklist mục 12."""
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

SEP = "━━━━━━━━━━━━━━━━━━━━"
LABELS = {"PRODUCT UPDATE", "MODEL", "ENGINEERING", "SECURITY", "RESEARCH"}
TAGS = {"#ClaudeCode", "#Claude", "#Cursor", "#Codex", "#Copilot", "#OpenAI", "#Gemini",
        "#CodingAgent", "#Agent", "#MCP", "#CodeReview", "#ContextEngineering",
        "#OpenSource", "#Vulnerability", "#Inference", "#DevTools"}
WORDS_MIN, WORDS_MAX = 50, 80
EM_DASH = "—"
# emoji / pictograph (icon chức năng do code tự thêm, nội dung LLM không được chứa)
EMOJI_RE = re.compile("[\U0001F300-\U0001FAFF☀-➿⭐⬆⏩-⏿️]")
VENDOR_WORDS = ("cho biết", "công bố", "tuyên bố", "thông báo", "announced", "claims")


def clean(text):
    """Đổi **bold** kiểu markdown sang *bold* của Slack; bỏ khoảng trắng thừa."""
    text = re.sub(r"\*\*(.+?)\*\*", r"*\1*", text or "")
    return re.sub(r"\s+", " ", text).strip()


def body_words(item):
    parts = [item.get("description"), item.get("noteworthy"), item.get("try"), item.get("caution")]
    return len(" ".join(clean(p) for p in parts if p).split())


def validate_item(item, candidate_urls, now, window_hours=48):
    """Trả list lỗi (rỗng = đạt)."""
    errs = []
    if item.get("label") not in LABELS:
        errs.append(f"label không hợp lệ: {item.get('label')!r}")
    tags = item.get("tags") or []
    if len(tags) > 2:
        errs.append("quá 2 tag")
    bad = [t for t in tags if t not in TAGS]
    if bad:
        errs.append(f"tag ngoài danh sách: {bad}")
    if not clean(item.get("headline")):
        errs.append("thiếu headline")
    if not clean(item.get("noteworthy")):
        errs.append("thiếu Đáng chú ý")
    n = body_words(item)
    if not WORDS_MIN <= n <= WORDS_MAX:
        errs.append(f"{n} từ, cần {WORDS_MIN}-{WORDS_MAX}")
    all_text = " ".join(str(item.get(k) or "") for k in ("headline", "description", "noteworthy", "try", "caution"))
    if EM_DASH in all_text:
        errs.append("có em dash")
    if EMOJI_RE.search(all_text):
        errs.append("có emoji trong nội dung")
    url = item.get("url") or ""
    if not url.startswith("https://") or not urlparse(url).netloc:
        errs.append("link không hợp lệ")
    elif url not in candidate_urls:
        errs.append("link không nằm trong dữ liệu nguồn (nghi bịa link)")
    if item.get("is_primary") is not True:
        errs.append("không phải primary source")
    pub = item.get("published_at")
    try:
        d = datetime.fromisoformat(str(pub).replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        # độ chính xác theo ngày nên cho dư 1 ngày
        if d < now - timedelta(hours=window_hours) - timedelta(days=1) or d > now + timedelta(hours=2):
            errs.append(f"ngoài cửa sổ {window_hours}h: {pub}")
    except ValueError:
        errs.append(f"published_at không hợp lệ: {pub!r}")
    return errs


def render_item(item):
    lines = [f"*[{item['label']}] {clean(item['headline'])}*"]
    if item.get("tags"):
        lines.append(" ".join(f"`{t}`" for t in item["tags"]))
    lines.append(clean(item["description"]))
    lines.append(f"💡 Đáng chú ý: {clean(item['noteworthy'])}")
    if clean(item.get("try")):
        lines.append(f"🧪 Nên thử: {clean(item['try'])}")
    if clean(item.get("caution")):
        lines.append(f"⚠️ Lưu ý: {clean(item['caution'])}")
    lines.append(f"🔗 {item['url']}")
    return "\n".join(lines)


def render_digest(items, trend, date_str):
    head = [f"*AI Engineering Daily: {date_str}*"]
    if clean(trend):
        head.append(clean(trend))
    blocks = ["\n".join(head)] + [render_item(i) for i in items]
    return f"\n\n{SEP}\n\n".join(blocks)


def check_digest(text):
    """Kiểm tra cuối trên bản đã ghép."""
    errs = []
    if EM_DASH in text:
        errs.append("bản tin có em dash")
    n_items = text.count("🔗")
    if text.count(SEP) != n_items:
        errs.append("số đường phân cách không khớp số tin")
    if n_items > 5:
        errs.append("quá 5 tin")
    return errs

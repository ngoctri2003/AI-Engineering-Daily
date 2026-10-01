"""Thu thập ứng viên tin từ feed/HTML. Chỉ dùng stdlib."""
import html
import json
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

UA = {"User-Agent": "ai-eng-daily/1.0 (internal news bot)"}
SNIPPET_CHARS = 1200
HTML_CHARS = 5000


def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def strip_html(raw):
    raw = re.sub(r"(?is)<(script|style|noscript|svg).*?</\1>", " ", raw)
    raw = re.sub(r"(?s)<[^>]+>", " ", raw)
    return re.sub(r"\s+", " ", html.unescape(raw)).strip()


def parse_date(s):
    if not s:
        return None
    s = s.strip()
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        try:
            d = parsedate_to_datetime(s)
        except (TypeError, ValueError):
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d


def _text(el, *names):
    for n in names:
        found = el.find(n)
        if found is not None and (found.text or found.attrib):
            return found
    return None


def parse_feed(xml_text, src, cutoff):
    """Hỗ trợ Atom và RSS. Trả list ứng viên nằm trong cửa sổ cutoff."""
    root = ET.fromstring(xml_text)
    items = []
    atom = "{http://www.w3.org/2005/Atom}"
    entries = root.findall(f".//{atom}entry") or root.findall(".//item")
    for e in entries:
        title = _text(e, f"{atom}title", "title")
        link_el = _text(e, f"{atom}link", "link")
        link = ""
        if link_el is not None:
            link = link_el.attrib.get("href") or (link_el.text or "")
        date_el = _text(e, f"{atom}updated", f"{atom}published", "pubDate", "published")
        body_el = _text(e, f"{atom}content", f"{atom}summary", "description", "summary")
        d = parse_date(date_el.text if date_el is not None else None)
        if d is None or d < cutoff:
            continue
        body = strip_html(html.unescape(body_el.text or "")) if body_el is not None else ""
        items.append({
            "source": src["name"], "priority": src["priority"],
            "title": (title.text or "").strip() if title is not None else "",
            "url": link.strip(), "published_at": d.astimezone(timezone.utc).isoformat(),
            "snippet": body[:SNIPPET_CHARS],
        })
    return items


def fetch_html_source(src):
    """Trang changelog/blog không có feed: đưa text đầu trang cho LLM, LLM tự đọc ngày."""
    text = strip_html(http_get(src["url"]))
    return [{
        "source": src["name"], "priority": src["priority"], "title": src["name"],
        "url": src["url"], "published_at": None,
        "snippet": text[:HTML_CHARS],
        "note": "Trang tổng hợp, ngày nằm trong nội dung; chỉ lấy mục trong 48 giờ gần nhất.",
    }]


def fetch_hn(src, cutoff):
    since = int(cutoff.timestamp())
    q = urllib.parse.quote(src["query"])
    url = (f"https://hn.algolia.com/api/v1/search_by_date?query={q}&tags=story"
           f"&numericFilters=created_at_i>{since},points>20&hitsPerPage=15")
    data = json.loads(http_get(url))
    out = []
    for h in data.get("hits", []):
        if not h.get("url"):
            continue
        out.append({
            "source": src["name"], "priority": src["priority"], "title": h.get("title", ""),
            "url": h["url"], "published_at": h.get("created_at"),
            "snippet": f"HN points={h.get('points')}, comments={h.get('num_comments')}. Nguồn thứ cấp, cần là primary source mới đăng.",
        })
    return out


def collect(sources, now, window_hours=48, log=print):
    cutoff = now - timedelta(hours=window_hours)
    cands, status = [], {}
    for src in sources:
        try:
            if src["type"] == "atom":
                got = parse_feed(http_get(src["url"]), src, cutoff)
            elif src["type"] == "html":
                got = fetch_html_source(src)
            elif src["type"] == "hn":
                got = fetch_hn(src, cutoff)
            else:
                raise ValueError(f"type lạ: {src['type']}")
            status[src["name"]] = f"ok ({len(got)})"
            cands.extend(got)
        except Exception as ex:  # một nguồn lỗi không làm hỏng cả lượt chạy
            status[src["name"]] = f"LỖI: {type(ex).__name__}: {ex}"
    for k, v in status.items():
        log(f"[source] {k}: {v}")
    order = {"P0": 0, "P1": 1, "P2": 2}
    cands.sort(key=lambda c: order.get(c["priority"], 9))
    return cands[:60], status

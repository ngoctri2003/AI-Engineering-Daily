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
ENTRY_CHARS = 2500


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


def extract_entry_links(raw_html, base_url, prefix, limit=4):
    """Lấy link từng mục (theo thứ tự xuất hiện, không trùng) có đường dẫn bắt đầu bằng prefix."""
    out = []
    for m in re.finditer(r'href=["\']([^"\'#?]+)["\']', raw_html):
        full = urllib.parse.urljoin(base_url, m.group(1))
        path = urllib.parse.urlparse(full).path
        if not path.startswith(prefix) or path.rstrip("/") == prefix.rstrip("/"):
            continue
        if urllib.parse.urlparse(full).netloc != urllib.parse.urlparse(base_url).netloc:
            continue
        full = full.rstrip("/")
        if full not in out:
            out.append(full)
        if len(out) >= limit:
            break
    return out


def _page_title(raw_html):
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", raw_html)
    return strip_html(m.group(1)) if m else ""


def fetch_html_source(src):
    """Trang changelog/blog không có feed. Nếu có entry_prefix thì lấy từng mục (link riêng),
    không thì đưa text đầu trang cho LLM, LLM tự đọc ngày."""
    raw = http_get(src["url"])
    prefix = src.get("entry_prefix")
    if prefix:
        entries = []
        for link in extract_entry_links(raw, src["url"], prefix, src.get("max_entries", 4)):
            try:
                page = http_get(link)
            except Exception:
                continue
            entries.append({
                "source": src["name"], "priority": src["priority"],
                "title": _page_title(page) or link, "url": link, "published_at": None,
                "snippet": strip_html(page)[:ENTRY_CHARS],
                "note": "Ngày nằm trong nội dung; chỉ lấy nếu trong 48 giờ gần nhất.",
            })
        if entries:
            return entries
    text = strip_html(raw)
    return [{
        "source": src["name"], "priority": src["priority"], "title": src["name"],
        "url": src["url"], "published_at": None,
        "snippet": text[:HTML_CHARS],
        "note": "Trang tổng hợp, ngày nằm trong nội dung; chỉ lấy mục trong 48 giờ gần nhất.",
    }]


def fetch_hn(src, cutoff):
    since = int(cutoff.timestamp())
    queries = src.get("queries") or [src["query"]]
    out, seen = [], set()
    for query in queries:
        q = urllib.parse.quote(query)
        url = (f"https://hn.algolia.com/api/v1/search_by_date?query={q}&tags=story"
               f"&numericFilters=created_at_i>{since},points>20&hitsPerPage=10")
        for h in json.loads(http_get(url)).get("hits", []):
            if not h.get("url") or h["url"] in seen:
                continue
            seen.add(h["url"])
            out.append({
                "source": src["name"], "priority": src["priority"], "title": h.get("title", ""),
                "url": h["url"], "published_at": h.get("created_at"),
                "snippet": f"HN points={h.get('points')}, comments={h.get('num_comments')}. Nguồn thứ cấp, chỉ dùng nếu link là primary source.",
            })
    return out


def fetch_devto(src, cutoff):
    """Bài nổi bật trên dev.to (nguồn cộng đồng, ý kiến cá nhân, KHÔNG phải primary source)."""
    out, seen = [], set()
    min_score = src.get("min_score", 40)
    urls = ["https://dev.to/api/articles?top=2&per_page=30"] + [
        f"https://dev.to/api/articles?top=2&per_page=30&tag={urllib.parse.quote(t)}" for t in src.get("queries", [])]
    for url in urls:
        try:
            arts = json.loads(http_get(url))
        except Exception:
            continue
        for a in arts:
            u = a.get("url") or ""
            d = parse_date(a.get("published_at") or a.get("published_timestamp"))
            score = a.get("positive_reactions_count", 0) + 2 * a.get("comments_count", 0)
            if not u or u in seen or d is None or d < cutoff or score < min_score:
                continue
            seen.add(u)
            out.append({
                "source": src["name"], "priority": src["priority"], "kind": "community",
                "title": a.get("title", ""), "url": u,
                "published_at": d.astimezone(timezone.utc).isoformat(),
                "score": score,
                "snippet": (f"Bài viết cá nhân trên dev.to (nguồn cộng đồng, không phải nguồn chính thức). "
                            f"reactions={a.get('positive_reactions_count')}, comments={a.get('comments_count')}, "
                            f"tags={a.get('tag_list')}. Mô tả: {a.get('description', '')}"),
            })
    out.sort(key=lambda c: -c["score"])
    return out[:5]


def collect(sources, now, window_hours=48, log=print):
    cutoff = now - timedelta(hours=window_hours)
    cands, status = [], {}
    for src in sources:
        try:
            if src["type"] == "atom":
                got = parse_feed(http_get(src["url"]), src, cutoff)
            elif src["type"] == "html":
                got = fetch_html_source(src)
            elif src["type"] == "devto":
                got = fetch_devto(src, cutoff)
            elif src["type"] == "hn":
                got = fetch_hn(src, cutoff)
            else:
                raise ValueError(f"type lạ: {src['type']}")
            if src["type"] == "html":
                status[src["name"]] = (f"ok ({len(got)} mục có link riêng)" if len(got) > 1 or got[0]["url"] != src["url"]
                                       else f"ok ({len(got[0]['snippet'])} ký tự nội dung trang tổng hợp)")
            else:
                status[src["name"]] = f"ok ({len(got)})"
            cands.extend(got)
        except Exception as ex:  # một nguồn lỗi không làm hỏng cả lượt chạy
            status[src["name"]] = f"LỖI: {type(ex).__name__}: {ex}"
    for k, v in status.items():
        log(f"[source] {k}: {v}")
    order = {"P0": 0, "P1": 1, "P2": 2}
    cands.sort(key=lambda c: order.get(c["priority"], 9))
    return cands[:60], status

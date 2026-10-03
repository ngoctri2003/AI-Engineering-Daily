"""AI Engineering Daily: Research, Verify, Filter, Summarize, Publish.

Chạy: python -m app.main [--dry-run] [--mock FILE]
Biến môi trường: xem README.
"""
import argparse
import json
import os
import sys
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import alert, formatter, llm, slack, sources

HERE = Path(__file__).parent
ROOT = HERE.parent
STATE = ROOT / "state" / "posted.json"
TZ_VN = timezone(timedelta(hours=7))
MAX_ITEMS = 5

SCHEMA = """Trả về DUY NHẤT một object JSON:
{
  "trend": "1 câu xu hướng nổi bật nhất trong ngày, hoặc chuỗi rỗng",
  "items": [
    {
      "label": "PRODUCT UPDATE | MODEL | ENGINEERING | SECURITY | RESEARCH",
      "tags": ["#Tag1", "#Tag2"],
      "headline": "...",
      "description": "1-2 câu fact, không emoji, không em dash",
      "noteworthy": "1 câu engineering implication",
      "try": "tùy chọn, cụ thể làm được ngay, hoặc rỗng",
      "caution": "tùy chọn, hoặc rỗng",
      "url": "PHẢI là đúng một url trong danh sách ứng viên",
      "source_kind": "official hoặc community (community CHỈ cho ứng viên có kind=community, tức dev.to)",
      "is_primary": true,
      "published_at": "ISO 8601, lấy từ dữ liệu ứng viên"
    }
  ],
  "dropped": [{"title": "...", "reason": "..."}],
  "conflicts": ["mô tả nguồn mâu thuẫn nếu có"]
}
Ràng buộc: tối đa 5 items, ưu tiên 3; mỗi item 50-80 từ (description + noteworthy + try + caution);
chỉ dùng thông tin có trong dữ liệu ứng viên; không đủ tin giá trị thì items = [].
Tin cộng đồng (kind=community, dev.to): tối đa 1 tin mỗi ngày, chỉ chọn khi là cuộc thảo luận nổi bật về nghề/kỹ thuật phần mềm với AI,
viết rõ đây là quan điểm của tác giả bài viết ("Tác giả bài viết cho rằng..."), is_primary=false, source_kind="community".
Nếu nội dung nguồn không đủ để người đọc hiểu tin là gì (sản phẩm/tính năng là gì, thay đổi gì) thì LOẠI tin đó vào dropped, không suy đoán.
Mỗi tin chỉ ứng với MỘT link và MỘT sự kiện; giữ số phiên bản/tên chính xác trong headline (ví dụ v2.1.285)."""


class RunError(Exception):
    """Lỗi vận hành cần báo cho người phụ trách."""


def load_state():
    try:
        return json.loads(STATE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {"posted": []}


def save_state(state):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, ensure_ascii=False, indent=2))


def build_user_prompt(cands, now, recent):
    return (
        f"Hôm nay: {now.astimezone(TZ_VN):%Y-%m-%d} (giờ Việt Nam). Cửa sổ: 48 giờ gần nhất.\n"
        f"Tin đã đăng 3 ngày gần đây (không đăng lại): {json.dumps(recent, ensure_ascii=False)}\n\n"
        f"DỮ LIỆU ỨNG VIÊN (JSON):\n{json.dumps(cands, ensure_ascii=False)}\n\n{SCHEMA}")


def make_trend(system, items):
    """Viết dòng xu hướng SAU khi đã chốt tin, chỉ dựa trên các tin này (tránh nhắc tin không có trong bản tin)."""
    if len(items) < 2:
        return ""
    brief = [{"headline": i["headline"], "label": i["label"]} for i in items]
    try:
        res = llm.call_json(
            system,
            "Viết 1 câu xu hướng chung (tối đa 30 từ, không em dash, không emoji) CHỈ dựa trên các tin sau, "
            f"không nhắc sản phẩm hay sự kiện nào ngoài danh sách. Danh sách: {json.dumps(brief, ensure_ascii=False)}\n"
            'Trả JSON: {"trend": "..."}. Nếu không có xu hướng chung rõ ràng thì trend là chuỗi rỗng.')
        t = formatter.clean(res.get("trend", "")) if isinstance(res, dict) else ""
    except Exception as ex:
        print(f"[llm] bỏ dòng xu hướng: {ex}")
        return ""
    return "" if formatter.EM_DASH in t or formatter.EMOJI_RE.search(t) else t


def run(dry_run=False, mock_file=None):
    now = datetime.now(timezone.utc)
    rules = (HERE / "rules.md").read_text()
    system = rules + "\n\nBạn chỉ trả JSON đúng schema. Không thêm lời dẫn."

    if mock_file:
        mock = json.loads(Path(mock_file).read_text())
        for obj in mock["candidates"] + mock["llm_response"]["items"]:
            if "published_hours_ago" in obj:  # fixture dùng ngày tương đối để không bị cũ
                obj["published_at"] = (now - timedelta(hours=obj.pop("published_hours_ago"))).isoformat()
        os.environ["LLM_PROVIDER"] = "mock"
        cands = mock["candidates"]
        status = {"mock": "ok"}
    else:
        mock = None
        srcs = json.loads((HERE / "sources.json").read_text())
        cands, status = sources.collect(srcs, now)
    if not cands:
        if status and all(v.startswith("LỖI") for v in status.values()):
            raise RunError("Mọi nguồn tin đều lỗi, không lấy được dữ liệu. Kiểm tra mạng hoặc sources.json.")
        print("Không có ứng viên nào trong 48 giờ. Không đăng.")
        return 0
    cand_urls = {c["url"] for c in cands}
    community_urls = {c["url"] for c in cands if c.get("kind") == "community"}

    state = load_state()
    recent_cut = (now - timedelta(days=3)).isoformat()
    recent = [{"headline": p["headline"], "url": p["url"]} for p in state["posted"] if p["date"] >= recent_cut]

    print(f"[run] {len(cands)} ứng viên, {len(recent)} tin đã đăng 3 ngày gần đây")
    result = llm.call_json(system, build_user_prompt(cands, now, recent),
                           mock["llm_response"] if mock else None)
    print(f"[run] LLM trả {len(result.get('items', [])) if isinstance(result, dict) else 0} tin, "
          f"{len(result.get('dropped', [])) if isinstance(result, dict) else 0} tin loại")
    items, notes_drop, unusable = [], [], 0
    hub_urls = {x["url"] for x in json.loads((HERE / "sources.json").read_text()) if x["type"] == "html"}
    raw_items = result.get("items", []) if isinstance(result, dict) else []
    for it in raw_items[:MAX_ITEMS]:
        if not isinstance(it, dict) or sum(1 for k in ("label", "headline", "url", "description") if it.get(k)) < 2:
            # item rỗng/sai cấu trúc: không tốn request sửa, in ra để biết model trả gì
            unusable += 1
            print(f"[llm] item không dùng được, bỏ qua sửa: {json.dumps(it, ensure_ascii=False)[:300]}")
            continue
        errs = formatter.validate_item(it, cand_urls, now, community_urls=community_urls)
        if errs and not mock:
            # sửa 1 lần, tốn thêm 1 request
            fix = llm.call_json(
                system,
                "Sửa item JSON sau cho đạt các lỗi liệt kê, giữ nguyên fact. "
                f"Lỗi: {errs}\nItem: {json.dumps(it, ensure_ascii=False)}\n"
                f"Url hợp lệ: {sorted(cand_urls)[:80]}\nTrả về object item JSON duy nhất.")
            it = formatter.unwrap_item(fix)
            if not it.get("headline"):
                print(f"[llm] phản hồi sửa không dùng được: {json.dumps(fix, ensure_ascii=False)[:400]}")
            errs = formatter.validate_item(it, cand_urls, now, community_urls=community_urls)
        if errs:
            notes_drop.append(f"Loại: {it.get('headline', '?')} ({'; '.join(errs)})")
            continue
        # chống trùng theo link (LLM viết lại headline mỗi lần). Trang tổng hợp (changelog) dùng chung link nên so thêm headline
        dup = any(it["url"] == r["url"] and (it["url"] not in hub_urls or it["headline"] == r["headline"]) for r in recent)
        if dup:
            notes_drop.append(f"Trùng tin đã đăng: {it.get('headline')}")
            continue
        if it.get("source_kind") == "community" and any(x.get("source_kind") == "community" for x in items):
            notes_drop.append(f"Quá 1 tin cộng đồng: {it.get('headline')}")
            continue
        items.append(it)

    if not items and raw_items and unusable == len(raw_items[:MAX_ITEMS]):
        raise RunError("LLM trả item rỗng/sai cấu trúc (model có thể quá tải hoặc không theo schema). Xem log bước Run.")
    if not items:
        print("Không có tin đạt chuẩn. Không đăng.")
        for n in notes_drop:
            print(n)
        return 0

    date_str = f"{now.astimezone(TZ_VN):%d/%m/%Y}"
    trend = result.get("trend", "") if mock else make_trend(system, items)
    text = formatter.render_digest(items, trend, date_str)
    problems = formatter.check_digest(text)
    if problems:
        raise RunError(f"Bản tin không đạt kiểm tra cuối: {'; '.join(problems)}")

    notes = []
    notes += [f"Loại: {d.get('title')}: {d.get('reason')}" for d in result.get("dropped", [])]
    notes += notes_drop
    notes += [f"Nguồn mâu thuẫn: {c}" for c in result.get("conflicts", [])]
    notes += [f"Nguồn lỗi: {k}: {v}" for k, v in status.items() if v.startswith("LỖI")]
    # Ghi chú chỉ ghi vào log Actions, không đăng lên Slack
    print(text)
    if notes:
        print("\n--- Ghi chú (chỉ trong log) ---\n" + "\n".join(f"- {n}" for n in notes))
    if dry_run:
        print("\n[dry-run] Không đăng Slack, không ghi state.")
        return 0

    slack.post(text)
    for it in items:
        state["posted"].append({"date": now.isoformat(), "headline": it["headline"], "url": it["url"]})
    state["posted"] = state["posted"][-200:]
    save_state(state)
    print("Đã đăng.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--mock", help="file JSON gồm candidates + llm_response, chạy offline")
    a = ap.parse_args()
    try:
        return run(a.dry_run, a.mock)
    except Exception as ex:  # ghi lý do (đã che secret) để bước báo lỗi Slack đọc
        traceback.print_exc()
        alert.write_reason(f"{type(ex).__name__}: {ex}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

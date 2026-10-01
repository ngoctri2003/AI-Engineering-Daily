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
      "is_primary": true,
      "published_at": "ISO 8601, lấy từ dữ liệu ứng viên"
    }
  ],
  "dropped": [{"title": "...", "reason": "..."}],
  "conflicts": ["mô tả nguồn mâu thuẫn nếu có"]
}
Ràng buộc: tối đa 5 items, ưu tiên 3; mỗi item 50-80 từ (description + noteworthy + try + caution);
chỉ dùng thông tin có trong dữ liệu ứng viên; không đủ tin giá trị thì items = []."""


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


def run(dry_run=False, mock_file=None):
    now = datetime.now(timezone.utc)
    if now.astimezone(TZ_VN).weekday() >= 5 and not os.environ.get("FORCE"):
        print("Cuối tuần (giờ VN), bỏ qua. Đặt FORCE=1 để chạy.")
        return 0

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

    state = load_state()
    recent_cut = (now - timedelta(days=3)).isoformat()
    recent = [{"headline": p["headline"], "url": p["url"]} for p in state["posted"] if p["date"] >= recent_cut]

    result = llm.call_json(system, build_user_prompt(cands, now, recent),
                           mock["llm_response"] if mock else None)
    items, notes_drop = [], []
    for it in result.get("items", [])[:MAX_ITEMS]:
        errs = formatter.validate_item(it, cand_urls, now)
        if errs and not mock:
            # sửa 1 lần, tốn thêm 1 request
            fix = llm.call_json(
                system,
                "Sửa item JSON sau cho đạt các lỗi liệt kê, giữ nguyên fact. "
                f"Lỗi: {errs}\nItem: {json.dumps(it, ensure_ascii=False)}\n"
                f"Url hợp lệ: {sorted(cand_urls)[:80]}\nTrả về object item JSON duy nhất.")
            it = formatter.unwrap_item(fix)
            errs = formatter.validate_item(it, cand_urls, now)
        if errs:
            notes_drop.append(f"Loại: {it.get('headline', '?')} ({'; '.join(errs)})")
            continue
        if any(it["url"] == r["url"] and it["headline"] == r["headline"] for r in recent):
            continue
        items.append(it)

    if not items:
        print("Không có tin đạt chuẩn. Không đăng.")
        for n in notes_drop:
            print(n)
        return 0

    date_str = f"{now.astimezone(TZ_VN):%d/%m/%Y}"
    text = formatter.render_digest(items, result.get("trend", ""), date_str)
    problems = formatter.check_digest(text)
    if problems:
        raise RunError(f"Bản tin không đạt kiểm tra cuối: {'; '.join(problems)}")

    notes = []
    notes += [f"Loại: {d.get('title')}: {d.get('reason')}" for d in result.get("dropped", [])]
    notes += notes_drop
    notes += [f"Nguồn mâu thuẫn: {c}" for c in result.get("conflicts", [])]
    notes += [f"Nguồn lỗi: {k}: {v}" for k, v in status.items() if v.startswith("LỖI")]
    notes_text = ("*Ghi chú (ngoài bản tin)*\n" + "\n".join(f"• {n}" for n in notes)) if notes else None

    print(text)
    if notes_text:
        print("\n---\n" + notes_text)
    if dry_run:
        print("\n[dry-run] Không đăng Slack, không ghi state.")
        return 0

    slack.post(text, notes_text)
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

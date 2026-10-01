import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import formatter as f

NOW = datetime.now(timezone.utc)
URLS = {"https://example.com/a"}
DESC = ("Nhà phát triển công cụ ví dụ cho biết phiên bản mới thêm chế độ chạy nền cho coding agent, "
        "cho phép giao việc dài hơi và quay lại xem kết quả sau. Bản phát hành cũng thêm cấu hình quyền theo thư mục.")
GOOD = {"label": "PRODUCT UPDATE", "tags": ["#CodingAgent"], "headline": "Công cụ A thêm chế độ chạy nền",
        "description": DESC,
        "noteworthy": "Team có thể tách các tác vụ refactor dài khỏi phiên làm việc chính.",
        "try": "Chạy 10 ticket refactor nhỏ ở chế độ nền và so sánh thời gian hoàn thành.",
        "caution": "", "url": "https://example.com/a", "is_primary": True,
        "published_at": (NOW - timedelta(hours=3)).isoformat()}


def errs(**over):
    return f.validate_item({**GOOD, **over}, URLS, NOW)


class T(unittest.TestCase):
    def test_good(self):
        self.assertEqual(errs(), [], errs())

    def test_bad_label(self):
        self.assertTrue(any("label" in e for e in errs(label="NEWS")))

    def test_too_many_tags(self):
        self.assertTrue(any("2 tag" in e for e in errs(tags=["#MCP", "#Agent", "#Cursor"])))

    def test_unknown_tag(self):
        self.assertTrue(any("ngoài danh sách" in e for e in errs(tags=["#Foo"])))

    def test_em_dash(self):
        self.assertTrue(any("em dash" in e for e in errs(headline="A — B")))

    def test_emoji(self):
        self.assertTrue(any("emoji" in e for e in errs(description=DESC + " \U0001F680")))

    def test_word_count(self):
        self.assertTrue(any("từ" in e for e in errs(description="Quá ngắn.", noteworthy="x", **{"try": ""})))

    def test_fabricated_link(self):
        self.assertTrue(any("bịa link" in e for e in errs(url="https://evil.example/x")))

    def test_http_link(self):
        self.assertTrue(any("link không hợp lệ" in e for e in errs(url="http://example.com/a")))

    def test_not_primary(self):
        self.assertTrue(any("primary" in e for e in errs(is_primary=False)))

    def test_old_news(self):
        old = (NOW - timedelta(days=6)).isoformat()
        self.assertTrue(any("ngoài cửa sổ" in e for e in errs(published_at=old)))

    def test_missing_noteworthy(self):
        self.assertTrue(any("Đáng chú ý" in e for e in errs(noteworthy="")))

    def test_render(self):
        text = f.render_digest([GOOD, GOOD], "Xu hướng thử nghiệm.", "01/10/2026")
        self.assertTrue(text.startswith("*AI Engineering Daily: 01/10/2026*"))
        self.assertEqual(text.count(f.SEP), 2)
        self.assertEqual(f.check_digest(text), [])
        self.assertIn("`#CodingAgent`", text)
        self.assertNotIn("**", text)

    def test_bold_conversion(self):
        self.assertEqual(f.clean("có **chế độ** mới"), "có *chế độ* mới")

    def test_fixture(self):
        fx = json.loads((Path(__file__).parent / "fixture.json").read_text())
        urls = {c["url"] for c in fx["candidates"]}
        for it in fx["llm_response"]["items"]:
            it["published_at"] = (NOW - timedelta(hours=it.pop("published_hours_ago"))).isoformat()
            self.assertEqual(f.validate_item(it, urls, NOW), [], it["headline"])


if __name__ == "__main__":
    unittest.main()

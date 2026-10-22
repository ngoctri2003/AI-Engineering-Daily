import base64
import unittest

from app import manual

NOW = 1_000_000


class ManualSendTest(unittest.TestCase):
    def setUp(self):
        self.posted, self.scheduled = [], []

    def call(self, title, body, post_at=None):
        return manual.handle(title, body, post_at, post=self.posted.append,
                             schedule=lambda t, w: self.scheduled.append((t, w)), now=lambda: NOW)

    def test_send_now(self):
        self.assertEqual(self.call("  Hi  ", " body ")[0], 200)
        self.assertEqual(self.posted, ["*Hi*\n\nbody"])
        self.assertEqual(self.scheduled, [])

    def test_schedule(self):
        self.assertEqual(self.call("T", "b", NOW + 3600), (200, "Scheduled"))
        self.assertEqual(self.scheduled, [("*T*\n\nb", NOW + 3600)])
        self.assertEqual(self.posted, [])

    def test_schedule_bounds_and_format(self):
        for bad in (NOW + 10, NOW - 5, NOW + 121 * 24 * 3600, "abc"):
            self.assertEqual(self.call("T", "b", bad)[0], 400)
        self.assertEqual(self.scheduled, [])

    def test_validation(self):
        self.assertEqual(self.call("", "b")[0], 400)
        self.assertEqual(self.call("T", "  ")[0], 400)
        self.assertEqual(self.call("x" * (manual.MAX_TITLE + 1), "b")[0], 400)
        self.assertEqual(self.call("T", "x" * (manual.MAX_BODY + 1))[0], 400)
        self.assertEqual(self.posted, [])

    def test_slack_failure(self):
        def boom(*a):
            raise RuntimeError("x")
        self.assertEqual(manual.handle("T", "b", post=boom)[0], 502)


class ActivityTest(unittest.TestCase):
    def test_sorted_and_independent_failures(self):
        def bad():
            raise RuntimeError("Slack error: missing_scope")
        res = manual.activity(lambda: [{"id": "Q2", "post_at": 20, "text": "b"}, {"id": "Q1", "post_at": 10, "text": "a"}], bad)
        self.assertEqual([m["id"] for m in res["scheduled"]], ["Q1", "Q2"])
        self.assertEqual(res["sent"], [])
        self.assertIn("missing_scope", res["warnings"][0])
        self.assertIn("channels:history", res["warnings"][0])

    def test_unexpected_error_hides_details(self):
        def boom():
            raise ValueError("secret-ish detail")
        res = manual.activity(boom, lambda: [])
        self.assertNotIn("secret-ish", res["warnings"][0])

    def test_cancel(self):
        calls = []
        self.assertEqual(manual.cancel("Q123ABC456", calls.append), (200, "Cancelled"))
        self.assertEqual(calls, ["Q123ABC456"])
        for bad in ("", None, "x", "Q1; drop", "../a"):
            self.assertEqual(manual.cancel(bad, calls.append)[0], 400)
        self.assertEqual(len(calls), 1)


PNG = b"\x89PNG\r\n\x1a\n" + b"x" * 20


def b64(data):
    return base64.b64encode(data).decode()


class ImagesTest(unittest.TestCase):
    def setUp(self):
        self.posted, self.scheduled, self.uploaded = [], [], []

    def call(self, images, post_at=None, upload=None):
        def up(files):
            self.uploaded.append(files)
            return [f"F{i}" for i in range(len(files))]
        return manual.handle("T", "body", post_at, images,
                             post=lambda t, blocks=None: self.posted.append((t, blocks)),
                             schedule=lambda t, w, blocks=None: self.scheduled.append((t, w, blocks)),
                             upload=upload or up, now=lambda: NOW)

    def test_send_with_images(self):
        self.assertEqual(self.call([b64(PNG), "data:image/png;base64," + b64(PNG)]), (200, "Sent"))
        self.assertEqual([n for n, _ in self.uploaded[0]], ["image-1.png", "image-2.png"])
        text, blocks = self.posted[0]
        self.assertEqual(text, "*T*\n\nbody")
        self.assertEqual([b["type"] for b in blocks], ["section", "image", "image"])
        self.assertEqual(blocks[1]["slack_file"], {"id": "F0"})
        self.assertEqual(blocks[2]["slack_file"], {"id": "F1"})
        self.assertTrue(blocks[1]["alt_text"])

    def test_schedule_with_images(self):
        self.assertEqual(self.call([b64(PNG)], NOW + 3600), (200, "Scheduled"))
        text, when, blocks = self.scheduled[0]
        self.assertEqual(when, NOW + 3600)
        self.assertEqual(blocks[-1]["type"], "image")
        self.assertEqual(self.posted, [])

    def test_no_images_does_not_upload(self):
        for empty in (None, "", []):
            self.assertEqual(self.call(empty)[0], 200)
        self.assertEqual(self.uploaded, [])
        self.assertTrue(all(blocks is None for _, blocks in self.posted))

    def test_image_validation(self):
        big = b64(PNG + b"x" * manual.MAX_IMAGE_BYTES)
        for bad in ("abc", [123], ["!!!"], [b64(b"hello")], [b64(PNG)] * (manual.MAX_IMAGES + 1), [big]):
            self.assertEqual(self.call(bad)[0], 400, bad if len(str(bad)) < 40 else "long")
        self.assertEqual(self.uploaded, [])
        self.assertEqual(self.posted, [])

    def test_formats_detected_by_content(self):
        files = manual.decode_images([b64(b"\xff\xd8\xff\xe0abc"), b64(b"GIF89a.."), b64(b"RIFF\0\0\0\0WEBPVP8 ")])
        self.assertEqual([n for n, _ in files], ["image-1.jpg", "image-2.gif", "image-3.webp"])

    def test_upload_failure_hints_scope(self):
        def boom(files):
            raise RuntimeError("Slack error: missing_scope")
        status, message = self.call([b64(PNG)], upload=boom)
        self.assertEqual(status, 502)
        self.assertIn("files:write", message)
        self.assertEqual(self.posted, [])

    def test_long_text_is_split_into_sections(self):
        text = "\n".join(["x" * 1000] * 7)
        blocks = manual.build_blocks(text, ["F1"], "T")
        sections = [b["text"]["text"] for b in blocks if b["type"] == "section"]
        self.assertGreaterEqual(len(sections), 3)
        self.assertTrue(all(len(s) <= manual.MAX_BLOCK_TEXT for s in sections))
        self.assertEqual("\n".join(sections), text)
        self.assertEqual(manual.build_blocks("x" * 7000, [], "T")[0]["text"]["text"], "x" * 3000)


if __name__ == "__main__":
    unittest.main()

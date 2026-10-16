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


if __name__ == "__main__":
    unittest.main()

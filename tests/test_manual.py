import os
import unittest
from unittest import mock

from app import manual


class ManualSendTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(os.environ, {"MANUAL_SEND_PASSWORD": "secret"})
        p.start()
        self.addCleanup(p.stop)
        self.sent = []

    def call(self, pw, text):
        return manual.handle(pw, text, post=self.sent.append)

    def test_ok(self):
        self.assertEqual(self.call("secret", "  hello  ")[0], 200)
        self.assertEqual(self.sent, ["hello"])

    def test_wrong_password(self):
        self.assertEqual(self.call("nope", "hello")[0], 401)
        self.assertEqual(self.sent, [])

    def test_missing_password_config(self):
        with mock.patch.dict(os.environ, {"MANUAL_SEND_PASSWORD": ""}):
            self.assertEqual(self.call("", "hello")[0], 503)

    def test_empty_and_too_long(self):
        self.assertEqual(self.call("secret", "   ")[0], 400)
        self.assertEqual(self.call("secret", "x" * (manual.MAX_LEN + 1))[0], 400)
        self.assertEqual(self.sent, [])

    def test_slack_failure(self):
        def boom(_):
            raise RuntimeError("x")
        self.assertEqual(manual.handle("secret", "hi", post=boom)[0], 502)


if __name__ == "__main__":
    unittest.main()

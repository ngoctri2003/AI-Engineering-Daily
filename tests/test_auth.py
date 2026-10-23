import http.client
import importlib.util
import json
import os
import secrets
import threading
import unittest
from http.server import HTTPServer
from unittest import mock

from app import auth, manual

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EMAIL, OTHER = "someone@example.com", "other@example.com"
PASSWORD = secrets.token_urlsafe(12)  # random per run: no real password is stored in the tests
ROUNDS = auth.MIN_ITERATIONS          # fast hashes for tests


def env(users=None, secret=True):
    users = {EMAIL: auth.hash_password(PASSWORD, ROUNDS), OTHER: auth.hash_password("other-" + PASSWORD, ROUNDS)} if users is None else users
    out = {"AUTH_USERS": json.dumps(users)}
    if secret:
        out["AUTH_SECRET"] = "s" * 40
    return mock.patch.dict(os.environ, out, clear=True)


class PasswordTest(unittest.TestCase):
    def test_hash_roundtrip_and_salt(self):
        a, b = auth.hash_password("pw", ROUNDS), auth.hash_password("pw", ROUNDS)
        self.assertNotEqual(a, b)
        self.assertTrue(auth.verify_password("pw", a))
        self.assertFalse(auth.verify_password("pw2", a))
        self.assertTrue(a.startswith("pbkdf2_sha256$"))

    def test_bad_or_weak_hashes_never_verify(self):
        for bad in ("", "x", "a$b$c$d", "pbkdf2_sha256$1$00$00", "pbkdf2_sha256$600000$zz$00", None, 5):
            self.assertFalse(auth.verify_password("pw", bad))

    def test_authenticate(self):
        with env():
            self.assertEqual(auth.authenticate("  " + EMAIL.upper() + " ", PASSWORD), EMAIL)  # email is case-insensitive
            self.assertIsNone(auth.authenticate(EMAIL, PASSWORD + "x"))
            self.assertIsNone(auth.authenticate("nobody@example.com", PASSWORD))
            self.assertIsNone(auth.authenticate(EMAIL, ""))
            self.assertIsNone(auth.authenticate(EMAIL, "x" * 1000))
            self.assertIsNone(auth.authenticate(None, None))
            self.assertIsNone(auth.authenticate(OTHER, PASSWORD))  # passwords are per user

    def test_unknown_email_still_runs_one_hash(self):
        with env(), mock.patch.object(auth, "verify_password", return_value=False) as v:
            auth.authenticate("nobody@example.com", "pw")
        self.assertEqual(v.call_count, 1)


class ConfigTest(unittest.TestCase):
    def test_fail_closed(self):
        for kw in ({"users": {}}, {"secret": False}):
            with env(**kw):
                self.assertFalse(auth.configured())
                with self.assertRaises(auth.NotConfigured):
                    auth.authenticate(EMAIL, PASSWORD)
        with mock.patch.dict(os.environ, {"AUTH_USERS": "not json", "AUTH_SECRET": "s" * 40}, clear=True):
            self.assertFalse(auth.configured())
        with mock.patch.dict(os.environ, {"AUTH_USERS": '{"a@b.c":"x"}', "AUTH_SECRET": "short"}, clear=True):
            self.assertFalse(auth.configured())
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(auth.configured())


class TokenTest(unittest.TestCase):
    def test_roundtrip_expiry_and_tamper(self):
        with env():
            t = auth.make_token(EMAIL, now=1000)
            self.assertEqual(auth.read_token(t, now=1001), EMAIL)
            self.assertIsNone(auth.read_token(t, now=1000 + auth.SESSION_SECONDS + 1))
            body, sig = t.split(".")
            forged = auth._b64(json.dumps({"e": OTHER, "x": 99999999999}).encode())
            for bad in (forged + "." + sig, body + "." + sig[:-2] + "AA", body, "", "a.b.c", None, 123):
                self.assertIsNone(auth.read_token(bad, now=1001))

    def test_secret_change_and_removed_user_end_the_session(self):
        with env():
            t = auth.make_token(EMAIL, now=1000)
        with mock.patch.dict(os.environ, {"AUTH_SECRET": "n" * 40}):
            self.assertIsNone(auth.read_token(t, now=1001))
        with env(users={OTHER: auth.hash_password("x", ROUNDS)}):
            self.assertIsNone(auth.read_token(t, now=1001))


def load_handler(name):
    spec = importlib.util.spec_from_file_location("api_" + name, os.path.join(ROOT, "api", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.handler


class EndpointTest(unittest.TestCase):
    """Real handlers behind a real HTTP server; Slack is never reached."""

    def setUp(self):
        self.servers = {}
        self.slack_calls = []
        boom = lambda *a, **k: self.slack_calls.append(1) or (200, "Sent")  # noqa: E731
        patches = [mock.patch.object(manual, n, boom) for n in ("handle", "edit", "cancel")]
        patches.append(mock.patch.object(manual, "activity", lambda **k: self.slack_calls.append(1) or {"scheduled": [], "sent": [], "warnings": []}))
        patches.append(mock.patch.object(manual, "channels", lambda: self.slack_calls.append(1) or {"channels": [], "default": "", "warnings": []}))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.close)

    def close(self):
        for s in self.servers.values():
            s.shutdown()
            s.server_close()

    def call(self, name, method="POST", body=None, cookie=None, headers=None):
        if name not in self.servers:
            srv = HTTPServer(("127.0.0.1", 0), load_handler(name))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.servers[name] = srv
        srv = self.servers[name]
        h = {"Content-Type": "application/json", "Host": f"127.0.0.1:{srv.server_port}", **(headers or {})}
        if cookie:
            h["Cookie"] = cookie
        conn = http.client.HTTPConnection("127.0.0.1", srv.server_port, timeout=10)
        conn.request(method, "/api/" + name, None if body is None else json.dumps(body), h)
        r = conn.getresponse()
        data = json.loads(r.read() or b"{}")
        out = (r.status, data, r.getheader("Set-Cookie"))
        conn.close()
        return out

    def login(self, email=EMAIL, password=PASSWORD):
        with mock.patch("time.sleep"):
            return self.call("login", body={"email": email, "password": password})

    def cookie(self):
        status, _data, sc = self.login()
        self.assertEqual(status, 200)
        return sc.split(";")[0]

    PROTECTED = (("send", "POST", {"title": "T", "text": "b"}), ("edit", "POST", {"id": "Q123ABC456", "title": "T", "text": "b", "post_at": 1}),
                 ("cancel", "POST", {"id": "Q123ABC456"}), ("messages", "GET", None), ("channels", "GET", None))

    def test_protected_endpoints_refuse_visitors_without_a_session(self):
        with env():
            for name, method, body in self.PROTECTED:
                self.assertEqual(self.call(name, method, body)[0], 401, name)
                self.assertEqual(self.call(name, method, body, cookie="session=garbage")[0], 401, name)
            self.assertEqual(self.call("session", "GET")[0], 401)
        self.assertEqual(self.slack_calls, [])

    def test_not_configured_locks_everything(self):
        with env(secret=False):
            for name, method, body in self.PROTECTED:
                self.assertEqual(self.call(name, method, body)[0], 503, name)
            self.assertEqual(self.call("session", "GET")[0], 503)
            self.assertEqual(self.login()[0], 503)
        self.assertEqual(self.slack_calls, [])

    def test_wrong_credentials(self):
        with env():
            for e, p in ((EMAIL, "nope"), ("nobody@example.com", PASSWORD), ("", ""), (EMAIL, None)):
                status, data, sc = self.login(e, p)
                self.assertEqual((status, data["message"], sc), (401, "Wrong email or password", None))
            self.assertEqual(self.call("login", body=[1])[0], 400)

    def test_login_session_use_logout(self):
        with env():
            status, data, sc = self.login()
            self.assertEqual((status, data), (200, {"ok": True, "email": EMAIL}))
            for flag in ("HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=%d" % auth.SESSION_SECONDS):
                self.assertIn(flag, sc)
            self.assertNotIn(PASSWORD, sc)
            ck = sc.split(";")[0]
            self.assertEqual(self.call("session", "GET", cookie=ck)[1], {"ok": True, "email": EMAIL})
            for name, method, body in self.PROTECTED:
                self.assertEqual(self.call(name, method, body, cookie=ck)[0], 200, name)
            status, _data, cleared = self.call("logout", body={}, cookie=ck)
            self.assertEqual(status, 200)
            self.assertIn("Max-Age=0", cleared)

    def test_cross_site_posts_are_refused(self):
        with env():
            ck = self.cookie()
            evil = {"Origin": "https://evil.example"}
            self.assertEqual(self.call("send", body={"title": "T", "text": "b"}, cookie=ck, headers=evil)[0], 403)
            self.assertEqual(self.call("login", body={"email": EMAIL, "password": PASSWORD}, headers=evil)[0], 403)
            self.assertEqual(self.call("logout", body={}, headers=evil)[0], 403)
        self.assertEqual(self.slack_calls, [])

    def test_expired_session_is_refused(self):
        with env():
            ck = "session=" + auth.make_token(EMAIL, now=1)  # issued in 1970
            self.assertEqual(self.call("messages", "GET", cookie=ck)[0], 401)


if __name__ == "__main__":
    unittest.main()

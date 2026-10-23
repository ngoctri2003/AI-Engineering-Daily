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


class ChannelTest(unittest.TestCase):
    def setUp(self):
        self.posted, self.scheduled = [], []

    def call(self, channel, post_at=None, known=("CAAAAAAA1", "GBBBBBBB2")):
        return manual.handle("T", "b", post_at, None, channel,
                             post=lambda t, **kw: self.posted.append(kw),
                             schedule=lambda t, w, **kw: self.scheduled.append(kw),
                             now=lambda: NOW, list_channels=lambda: [{"id": c} for c in known])

    def test_picked_channel_is_used(self):
        self.assertEqual(self.call("CAAAAAAA1"), (200, "Sent"))
        self.assertEqual(self.call("GBBBBBBB2", NOW + 3600), (200, "Scheduled"))
        self.assertEqual(self.posted, [{"channel": "CAAAAAAA1"}])
        self.assertEqual(self.scheduled, [{"channel": "GBBBBBBB2"}])

    def test_empty_channel_uses_server_default(self):
        for empty in (None, "", "  "):
            self.assertEqual(self.call(empty)[0], 200)
        self.assertEqual(self.posted, [{}, {}, {}])

    def test_bad_or_foreign_channel_is_refused(self):
        for bad in ("general", "C1", "CAAAAAAA1; x", "caaaaaaa1"):
            self.assertEqual(self.call(bad)[0], 400)
        self.assertEqual(self.call("CZZZZZZZ9"), (400, "The bot is not a member of this channel"))
        self.assertEqual(self.posted, [])

    def test_channel_check_failure_sends_nothing(self):
        def boom():
            raise RuntimeError("Slack error: missing_scope")
        status, message = manual.handle("T", "b", None, None, "CAAAAAAA1", post=self.posted.append, list_channels=boom)
        self.assertEqual(status, 502)
        self.assertEqual(self.posted, [])

    def test_channels_list_and_default(self):
        res = manual.channels(lambda: [{"id": "CAAAAAAA1", "name": "a", "private": False}], "CAAAAAAA1")
        self.assertEqual((res["channels"], res["default"], res["warnings"]),
                         ([{"id": "CAAAAAAA1", "name": "a", "private": False}], "CAAAAAAA1", []))

    def test_default_channel_not_listed_is_still_offered(self):
        res = manual.channels(lambda: [{"id": "C2AAAAAA", "name": "z", "private": False}], "CAAAAAAA1")
        self.assertEqual([c["id"] for c in res["channels"]], ["CAAAAAAA1", "C2AAAAAA"])

    def test_default_channel_uses_server_path(self):
        from unittest import mock
        with mock.patch.dict("os.environ", {"SLACK_CHANNEL_ID": "CAAAAAAA1"}):
            self.assertEqual(self.call("CAAAAAAA1", known=()), (200, "Sent"))  # not in the member list, still allowed
        self.assertEqual(self.posted, [{}])  # no explicit channel is passed, so the env allow-list still applies

    def test_channels_failure_is_a_warning(self):
        def bad():
            raise RuntimeError("Slack error: missing_scope")
        res = manual.channels(bad, "nonsense")
        self.assertEqual((res["channels"], res["default"]), ([], ""))
        self.assertIn("channels:read", res["warnings"][0])

    def test_activity_and_cancel_follow_the_channel(self):
        seen = []
        res = manual.activity(lambda **kw: seen.append(("sched", kw)) or [], lambda **kw: seen.append(("sent", kw)) or [],
                              channel="CAAAAAAA1")
        self.assertEqual(res["warnings"], [])
        self.assertEqual(seen, [("sched", {"channel": "CAAAAAAA1"}), ("sent", {"channel": "CAAAAAAA1"})])
        self.assertEqual(manual.activity(channel="nope")["warnings"], ["Invalid channel"])
        calls = []
        self.assertEqual(manual.cancel("Q123ABC456", lambda i, **kw: calls.append((i, kw)), "CAAAAAAA1")[0], 200)
        self.assertEqual(calls, [("Q123ABC456", {"channel": "CAAAAAAA1"})])
        self.assertEqual(manual.cancel("Q123ABC456", calls.append, "bad")[0], 400)


class SlackChannelTest(unittest.TestCase):
    """app.slack: an explicit channel wins over the env channel and allow-list; the env path is unchanged."""

    def run_post(self, env, channel=None):
        from unittest import mock
        from app import slack
        sent = []
        with mock.patch.dict("os.environ", env, clear=True):
            with mock.patch.object(slack, "_post_json", lambda url, body, headers=None: sent.append(body) or '{"ok": true, "ts": "1"}'):
                slack.post("hi", channel=channel)
        return [b["channel"] for b in sent]

    def test_env_channel_and_allow_list_unchanged(self):
        from app import slack
        env = {"SLACK_BOT_TOKEN": "t", "SLACK_CHANNEL_ID": "CENV", "SLACK_ALLOWED_CHANNELS": "CENV"}
        self.assertEqual(self.run_post(env), ["CENV"])
        with self.assertRaises(RuntimeError):
            self.run_post({**env, "SLACK_ALLOWED_CHANNELS": "COTHER"})

    def test_explicit_channel_skips_env(self):
        env = {"SLACK_BOT_TOKEN": "t", "SLACK_CHANNEL_ID": "CENV", "SLACK_ALLOWED_CHANNELS": "CENV"}
        self.assertEqual(self.run_post(env, "CPICK"), ["CPICK"])
        self.assertEqual(self.run_post({"SLACK_BOT_TOKEN": "t"}, "CPICK"), ["CPICK"])

    def test_explicit_channel_never_falls_back_to_webhook(self):
        with self.assertRaises(RuntimeError):
            self.run_post({"SLACK_WEBHOOK_URL": "https://hooks.example/x"}, "CPICK")

    def test_list_channels_pages_and_sorts(self):
        from unittest import mock
        from app import slack
        pages = [{"channels": [{"id": "C2", "name": "zeta"}], "response_metadata": {"next_cursor": "n"}},
                 {"channels": [{"id": "C1", "name": "Alpha", "is_private": True}], "response_metadata": {"next_cursor": ""}}]
        with mock.patch.dict("os.environ", {"SLACK_BOT_TOKEN": "t"}, clear=True):
            with mock.patch.object(slack, "_get", lambda m, p, t: pages.pop(0)):
                out = slack.list_channels()
        self.assertEqual(out, [{"id": "C1", "name": "Alpha", "private": True}, {"id": "C2", "name": "zeta", "private": False}])


class EditScheduledTest(unittest.TestCase):
    """Editing = schedule the new version, then cancel the original. Order and failure handling matter."""

    def setUp(self):
        self.events = []

    def call(self, post_at=NOW + 3600, existing=("Q123ABC456",), cancel_boom=False, schedule_boom=False, **kw):
        def schedule(t, w, **extra):
            if schedule_boom:
                raise RuntimeError("Slack error: invalid_time")
            self.events.append(("schedule", t, w, extra))

        def cancel(i, **extra):
            if cancel_boom:
                raise RuntimeError("Slack error: invalid_scheduled_message_id")
            self.events.append(("cancel", i, extra))
        return manual.edit("Q123ABC456", "New", "text", post_at, None, kw.get("channel"), kw.get("old_channel"),
                           list_scheduled=lambda **e: [{"id": i, "post_at": 1, "text": ""} for i in existing],
                           cancel_fn=cancel, schedule=schedule, now=lambda: NOW,
                           list_channels=lambda: [{"id": "CAAAAAAA1"}, {"id": "CBBBBBBB2"}])

    def test_schedules_new_then_cancels_original(self):
        self.assertEqual(self.call(), (200, "Updated"))
        self.assertEqual([e[0] for e in self.events], ["schedule", "cancel"])
        self.assertEqual(self.events[0][1:3], ("*New*\n\ntext", NOW + 3600))
        self.assertEqual(self.events[1], ("cancel", "Q123ABC456", {}))

    def test_channels_can_differ(self):
        self.assertEqual(self.call(channel="CBBBBBBB2", old_channel="CAAAAAAA1")[0], 200)
        self.assertEqual(self.events[0][3], {"channel": "CBBBBBBB2"})
        self.assertEqual(self.events[1], ("cancel", "Q123ABC456", {"channel": "CAAAAAAA1"}))

    def test_original_untouched_when_new_version_is_refused(self):
        for bad in (NOW + 5, NOW + 999 * 24 * 3600, "abc"):
            self.assertEqual(self.call(post_at=bad)[0], 400)
        self.assertEqual(self.call(schedule_boom=True)[0], 502)
        self.assertEqual(self.call(channel="CZZZZZZZ9")[0], 400)
        self.assertEqual(self.events, [])  # nothing scheduled, nothing cancelled

    def test_needs_time_and_valid_ids(self):
        self.assertEqual(self.call(post_at=None)[0], 400)
        self.assertEqual(manual.edit("bad", "T", "b", NOW + 3600)[0], 400)
        self.assertEqual(manual.edit("Q123ABC456", "T", "b", NOW + 3600, old_channel="nope")[0], 400)
        self.assertEqual(self.events, [])

    def test_original_already_gone_creates_nothing(self):
        self.assertEqual(self.call(existing=())[0], 409)
        self.assertEqual(self.events, [])

    def test_cancel_failure_is_reported_after_scheduling(self):
        status, message = self.call(cancel_boom=True)
        self.assertEqual(status, 502)
        self.assertIn("Cancel the original by hand", message)
        self.assertEqual([e[0] for e in self.events], ["schedule"])


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


class ListSentTest(unittest.TestCase):
    def test_filters_bot_messages_and_builds_link(self):
        from unittest import mock
        from app import slack

        def fake_get(method, params, token):
            if method == "auth.test":
                return {"user_id": "UBOT", "url": "https://team.slack.com/"}
            return {"messages": [
                {"ts": "1700000002.000100", "user": "UBOT", "text": "*A*\n\nbody",
                 "blocks": [{"type": "section"}, {"type": "image"}, {"type": "image"}]},
                {"ts": "1700000001.000100", "user": "UHUMAN", "text": "chat"},
                {"ts": "1700000000.000100", "bot_id": "B1", "text": "daily"}]}

        with mock.patch.object(slack, "_config", return_value=("tok", "C123")):
            with mock.patch.object(slack, "_get", fake_get):
                out = slack.list_sent()
        self.assertEqual([m["text"] for m in out], ["*A*\n\nbody", "daily"])
        self.assertEqual(out[0]["images"], 2)
        self.assertEqual(out[0]["link"], "https://team.slack.com/archives/C123/p1700000002000100")


if __name__ == "__main__":
    unittest.main()

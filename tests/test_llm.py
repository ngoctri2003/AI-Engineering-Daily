import http.client
import io
import json
import os
import unittest
import urllib.error
from unittest import mock

from app import llm


def http_error(code, body, headers=None):
    msg = http.client.HTTPMessage()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError("https://example.test", code, "err", msg, io.BytesIO(json.dumps(body).encode()))


def ok_response(payload):
    resp = mock.MagicMock()
    resp.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return resp


def claude_reply(text, stop_reason="end_turn", thinking=False):
    content = []
    if thinking:
        content.append({"type": "thinking", "thinking": "", "signature": "sig"})
    content.append({"type": "text", "text": text})
    return {"content": content, "stop_reason": stop_reason}


class EnvTestCase(unittest.TestCase):
    """Restore os.environ after each test and start from a clean LLM_* state."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        for k in ("LLM_PROVIDER", "LLM_MODEL", "LLM_FALLBACK_MODEL", "LLM_EFFORT", "LLM_BASE_URL"):
            os.environ.pop(k, None)
        os.environ["LLM_API_KEY"] = ' "sk-ant-test" \n'


class AnthropicRequestTests(EnvTestCase):
    def call(self, reply, model="claude-sonnet-5-5"):
        with mock.patch.object(llm, "_post", return_value=reply) as post:
            out = llm._anthropic("sys", "usr", model)
        return out, post.call_args[0]

    def test_request_shape(self):
        out, (url, headers, body) = self.call(claude_reply("{}"))
        self.assertEqual(out, "{}")
        self.assertEqual(url, llm.ANTHROPIC_URL)
        self.assertEqual(headers, {"x-api-key": "sk-ant-test", "anthropic-version": "2023-06-01"})
        self.assertEqual(body["model"], "claude-sonnet-5-5")
        self.assertEqual(body["system"], "sys")
        self.assertEqual(body["messages"], [{"role": "user", "content": "usr"}])
        self.assertEqual(body["max_tokens"], llm.ANTHROPIC_MAX_TOKENS)

    def test_no_sampling_or_thinking_fields_by_default(self):
        _, (_, _, body) = self.call(claude_reply("{}"))
        for field in ("temperature", "top_p", "top_k", "thinking", "output_config"):
            self.assertNotIn(field, body)

    def test_effort_is_sent_when_configured(self):
        os.environ["LLM_EFFORT"] = " medium "
        _, (_, _, body) = self.call(claude_reply("{}"))
        self.assertEqual(body["output_config"], {"effort": "medium"})

    def test_skips_thinking_block(self):
        out, _ = self.call(claude_reply('{"a": 1}', thinking=True))
        self.assertEqual(out, '{"a": 1}')

    def test_incomplete_or_refused_output_raises(self):
        for stop in ("max_tokens", "refusal"):
            with self.subTest(stop=stop):
                with self.assertRaises(RuntimeError) as cm:
                    self.call(claude_reply("{}", stop_reason=stop))
                self.assertIn(stop, str(cm.exception))

    def test_no_text_block_raises(self):
        with self.assertRaises(RuntimeError):
            self.call({"content": [{"type": "thinking", "thinking": "", "signature": "s"}], "stop_reason": "end_turn"})


class PostTests(unittest.TestCase):
    def test_retries_on_529_then_succeeds(self):
        overloaded = http_error(529, {"type": "error", "error": {"type": "overloaded_error", "message": "busy"}})
        with mock.patch.object(llm.urllib.request, "urlopen", side_effect=[overloaded, ok_response({"ok": 1})]), \
                mock.patch.object(llm.time, "sleep") as sleep:
            self.assertEqual(llm._post("https://example.test", {}, {}), {"ok": 1})
        sleep.assert_called_once_with(4)

    def test_retry_after_is_honored_and_capped(self):
        for header, expected in (("7", 7), ("120", 30), ("abc", 4)):
            with self.subTest(header=header):
                err = http_error(429, {"error": {"type": "rate_limit_error", "message": "slow down"}},
                                 {"retry-after": header})
                with mock.patch.object(llm.urllib.request, "urlopen", side_effect=[err, ok_response({})]), \
                        mock.patch.object(llm.time, "sleep") as sleep:
                    llm._post("https://example.test", {}, {})
                sleep.assert_called_once_with(expected)

    def test_error_message_has_type_message_and_request_id(self):
        err = http_error(400, {"type": "error", "error": {"type": "invalid_request_error", "message": "bad field"}},
                         {"request-id": "req_123"})
        with mock.patch.object(llm.urllib.request, "urlopen", side_effect=err):
            with self.assertRaises(RuntimeError) as cm:
                llm._post("https://example.test", {}, {})
        msg = str(cm.exception)
        for part in ("LLM HTTP 400", "invalid_request_error", "bad field", "req_123"):
            self.assertIn(part, msg)

    def test_short_error_formats(self):
        self.assertEqual(llm._short_error(b'{"error": {"status": "UNAUTHENTICATED", "message": "x"}}'),
                         "UNAUTHENTICATED x")
        self.assertEqual(llm._short_error(b'{"error": {"type": "overloaded_error", "message": "y"}}'),
                         "overloaded_error y")
        self.assertEqual(llm._short_error(b"not json"), repr(b"not json"))


class CallJsonTests(EnvTestCase):
    def run_call(self, provider, fn_name, results):
        """Run call_json with a fake provider function; return (result_or_exception, models_tried)."""
        os.environ["LLM_PROVIDER"] = provider
        tried = []

        def fake(system, user, model):
            tried.append(model)
            item = results[len(tried) - 1] if len(tried) <= len(results) else results[-1]
            if isinstance(item, Exception):
                raise item
            return item

        with mock.patch.object(llm, fn_name, fake):
            try:
                return llm.call_json("s", "u"), tried
            except RuntimeError as ex:
                return ex, tried

    def test_anthropic_default_models_with_fallback(self):
        out, tried = self.run_call("anthropic", "_anthropic", [RuntimeError("boom"), '{"ok": true}'])
        self.assertEqual(out, {"ok": True})
        self.assertEqual(tried, ["claude-sonnet-5-5", "claude-haiku-5-5"])

    def test_empty_model_env_falls_back_to_provider_defaults(self):
        os.environ["LLM_MODEL"] = ""
        os.environ["LLM_FALLBACK_MODEL"] = ""
        _, tried = self.run_call("anthropic", "_anthropic", [RuntimeError("boom"), "{}"])
        self.assertEqual(tried, ["claude-sonnet-5-5", "claude-haiku-5-5"])

    def test_env_models_override_defaults(self):
        os.environ["LLM_MODEL"] = "m1"
        os.environ["LLM_FALLBACK_MODEL"] = "m2"
        _, tried = self.run_call("anthropic", "_anthropic", [RuntimeError("boom"), "{}"])
        self.assertEqual(tried, ["m1", "m2"])

    def test_gemini_defaults_unchanged(self):
        out, tried = self.run_call("gemini", "_gemini", [RuntimeError("boom")])
        self.assertIsInstance(out, RuntimeError)
        self.assertIn("All models failed", str(out))
        self.assertEqual(tried, ["gemini-3.7-flash", "gemini-3.5-flash-lite"])

    def test_parses_fenced_and_prose_wrapped_json(self):
        for raw in ('```json\n{"a": 1}\n```', 'Here is the result:\n{"a": 1}\nDone.'):
            with self.subTest(raw=raw):
                out, _ = self.run_call("anthropic", "_anthropic", [raw])
                self.assertEqual(out, {"a": 1})

    def test_invalid_json_from_every_model_raises(self):
        out, tried = self.run_call("anthropic", "_anthropic", ["not json at all"])
        self.assertIsInstance(out, RuntimeError)
        self.assertEqual(len(tried), 2)

    def test_unknown_provider_raises(self):
        os.environ["LLM_PROVIDER"] = "nope"
        with self.assertRaises(RuntimeError):
            llm.call_json("s", "u")

    def test_mock_provider_returns_payload(self):
        os.environ["LLM_PROVIDER"] = "mock"
        self.assertEqual(llm.call_json("s", "u", {"x": 1}), {"x": 1})


if __name__ == "__main__":
    unittest.main()

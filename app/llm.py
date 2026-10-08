"""Call an LLM over REST (stdlib only).

Providers: gemini | anthropic | openai (OpenAI-compatible, e.g. GitHub Models) | mock.
"""
import json
import os
import time
import urllib.error
import urllib.request

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
# Thinking tokens count toward max_tokens, so keep generous headroom above the JSON answer size.
ANTHROPIC_MAX_TOKENS = 16000

# Default (primary, fallback) model per provider. LLM_MODEL / LLM_FALLBACK_MODEL override them.
DEFAULT_MODELS = {
    "gemini": ("gemini-3.7-flash", "gemini-3.5-flash-lite"),
    "anthropic": ("claude-sonnet-5-5", "claude-haiku-5-5"),
}
RETRY_STATUS = (429, 500, 502, 503, 529)  # 529 = Anthropic "overloaded"


def _short_error(raw):
    """Summarize an error body. Handles Gemini {"error": {"status", "message"}}
    and Anthropic {"type": "error", "error": {"type", "message"}}."""
    try:
        err = json.loads(raw).get("error", {})
        kind = err.get("status") or err.get("type") or ""
        return f"{kind} {err.get('message', '')}".strip()[:200]
    except (ValueError, AttributeError):
        return repr(raw[:200])


def _retry_wait(err, default=4, cap=30):
    """Seconds to wait before a retry: honor the retry-after header (capped), else a short default."""
    try:
        return max(1, min(int(err.headers.get("retry-after")), cap))
    except (AttributeError, TypeError, ValueError):
        return default


def _post(url, headers, body, retries=2):
    data = json.dumps(body).encode()
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in RETRY_STATUS and attempt < retries - 1:
                time.sleep(_retry_wait(e))  # short wait, then the caller falls back to the backup model; never hang
                continue
            rid = e.headers.get("request-id") if e.headers else None
            suffix = f" (request-id {rid})" if rid else ""
            raise RuntimeError(f"LLM HTTP {e.code}: {_short_error(e.read())}{suffix}")
    raise RuntimeError("LLM retries exhausted")


def _clean_key(raw):
    return raw.strip().strip('"').strip("'")  # drop stray whitespace, newlines and quotes from pasted keys


_GEMINI_AUTH = ["header", "bearer", "query"]  # auth styles tried in order; the working one moves to the front


def _gemini(system, user, model):
    key = _clean_key(os.environ["LLM_API_KEY"])
    base = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    body = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
    }
    last = None
    for style in list(_GEMINI_AUTH):
        url, headers = base, {}
        if style == "header":
            headers = {"x-goog-api-key": key}
        elif style == "bearer":
            headers = {"Authorization": f"Bearer {key}"}
        else:
            url = f"{base}?key={key}"
        try:
            res = _post(url, headers, body)
        except RuntimeError as ex:
            last = ex
            if "HTTP 401" in str(ex) or "HTTP 403" in str(ex):
                print(f"[llm] auth style '{style}' was rejected, trying the next one")
                continue
            raise
        if style != _GEMINI_AUTH[0]:
            _GEMINI_AUTH.remove(style)
            _GEMINI_AUTH.insert(0, style)
        print(f"[llm] model {model} using auth style '{style}'")
        return res["candidates"][0]["content"]["parts"][0]["text"]
    raise last


def _anthropic(system, user, model):
    """Claude Messages API. Sends no temperature/top_p/top_k (non-default values are rejected with HTTP 400 on
    current models) and no thinking field, so the model default applies. Thinking blocks may precede the text block.
    Optional LLM_EFFORT (low | medium | high | xhigh | max) sets output_config.effort."""
    key = _clean_key(os.environ["LLM_API_KEY"])
    body = {
        "model": model,
        "max_tokens": ANTHROPIC_MAX_TOKENS,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }
    effort = os.environ.get("LLM_EFFORT", "").strip()
    if effort:
        body["output_config"] = {"effort": effort}
    res = _post(ANTHROPIC_URL, {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION}, body)
    stop = res.get("stop_reason")
    if stop in ("max_tokens", "refusal"):
        raise RuntimeError(f"Claude stopped early (stop_reason={stop}); the output is incomplete or refused")
    texts = [b.get("text", "") for b in res.get("content", []) if b.get("type") == "text"]
    if not texts:
        raise RuntimeError("Claude response has no text block")
    return "".join(texts)


def _openai(system, user, model):
    base = os.environ.get("LLM_BASE_URL", "https://models.github.ai/inference").rstrip("/")
    key = os.environ["LLM_API_KEY"]
    body = {
        "model": model, "temperature": 0.2,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    res = _post(f"{base}/chat/completions", {"Authorization": f"Bearer {key}"}, body)
    return res["choices"][0]["message"]["content"]


def _parse_json(raw):
    """Parse model output as JSON. Tolerates code fences and prose around a single JSON object."""
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`").removeprefix("json").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise
        return json.loads(text[start:end + 1])


def call_json(system, user, mock_payload=None):
    """Return a JSON object. Try the primary model first, then the fallback model on failure."""
    provider = os.environ.get("LLM_PROVIDER") or "gemini"
    if provider == "mock":
        return mock_payload
    providers = {"gemini": _gemini, "anthropic": _anthropic, "openai": _openai}
    if provider not in providers:
        raise RuntimeError(f"Unknown LLM_PROVIDER: {provider!r} (use gemini, anthropic, openai or mock)")
    fn = providers[provider]
    primary, fallback = DEFAULT_MODELS.get(provider, DEFAULT_MODELS["gemini"])
    models = [os.environ.get("LLM_MODEL") or primary, os.environ.get("LLM_FALLBACK_MODEL") or fallback]
    last = None
    for m in models:
        raw = ""
        try:
            raw = fn(system, user, m)
            return _parse_json(raw)
        except json.JSONDecodeError as ex:
            last = ex
            print(f"[llm] model {m} returned invalid JSON: {ex}; response head: {raw.strip()[:300]!r}")
        except Exception as ex:
            last = ex
            print(f"[llm] model {m} failed: {ex}")
    raise RuntimeError(f"All models failed: {last}")

"""Gọi LLM qua REST (stdlib). Provider: gemini | openai (tương thích OpenAI, vd GitHub Models) | mock."""
import json
import os
import time
import urllib.error
import urllib.request


def _post(url, headers, body, retries=3):
    data = json.dumps(body).encode()
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503) and attempt < retries - 1:
                time.sleep(15 * (attempt + 1))
                continue
            raise RuntimeError(f"LLM HTTP {e.code}: {e.read()[:300]!r}")
    raise RuntimeError("LLM retry hết lượt")


def _gemini(system, user, model):
    key = os.environ["LLM_API_KEY"]
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    body = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
    }
    res = _post(url, {"x-goog-api-key": key}, body)
    return res["candidates"][0]["content"]["parts"][0]["text"]


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


def call_json(system, user, mock_payload=None):
    """Trả về object JSON. Thử model chính, lỗi thì thử model dự phòng."""
    provider = os.environ.get("LLM_PROVIDER", "gemini")
    if provider == "mock":
        return mock_payload
    fn = {"gemini": _gemini, "openai": _openai}[provider]
    models = [os.environ.get("LLM_MODEL", "gemini-3.7-flash")]
    if os.environ.get("LLM_FALLBACK_MODEL", "gemini-3.5-flash-lite"):
        models.append(os.environ.get("LLM_FALLBACK_MODEL", "gemini-3.5-flash-lite"))
    last = None
    for m in models:
        try:
            text = fn(system, user, m)
            text = text.strip()
            if text.startswith("```"):
                text = text.strip("`").removeprefix("json").strip()
            return json.loads(text)
        except Exception as ex:
            last = ex
            print(f"[llm] model {m} lỗi: {ex}")
    raise RuntimeError(f"Mọi model đều lỗi: {last}")

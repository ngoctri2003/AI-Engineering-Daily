"""Gọi LLM qua REST (stdlib). Provider: gemini | openai (tương thích OpenAI, vd GitHub Models) | mock."""
import json
import os
import time
import urllib.error
import urllib.request


def _short_error(raw):
    try:
        err = json.loads(raw).get("error", {})
        return f"{err.get('status', '')} {err.get('message', '')}".strip()[:200]
    except (ValueError, AttributeError):
        return repr(raw[:200])


def _post(url, headers, body, retries=2):
    data = json.dumps(body).encode()
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503) and attempt < retries - 1:
                time.sleep(4)  # chờ ngắn rồi chuyển model dự phòng, không treo lâu
                continue
            raise RuntimeError(f"LLM HTTP {e.code}: {_short_error(e.read())}")
    raise RuntimeError("LLM retry hết lượt")


_GEMINI_AUTH = ["header", "bearer", "query"]  # kiểu xác thực thử lần lượt; kiểu đúng được đưa lên đầu


def _gemini(system, user, model):
    key = os.environ["LLM_API_KEY"].strip().strip('"').strip("'")  # bỏ khoảng trắng/xuống dòng/dấu nháy dán thừa
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
                print(f"[llm] kiểu xác thực '{style}' bị từ chối, thử kiểu khác")
                continue
            raise
        if style != _GEMINI_AUTH[0]:
            _GEMINI_AUTH.remove(style)
            _GEMINI_AUTH.insert(0, style)
        print(f"[llm] model {model} dùng xác thực '{style}'")
        return res["candidates"][0]["content"]["parts"][0]["text"]
    raise last


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
        except json.JSONDecodeError as ex:
            last = ex
            print(f"[llm] model {m} trả JSON hỏng: {ex}; đầu phản hồi: {text[:300]!r}")
        except Exception as ex:
            last = ex
            print(f"[llm] model {m} lỗi: {ex}")
    raise RuntimeError(f"Mọi model đều lỗi: {last}")

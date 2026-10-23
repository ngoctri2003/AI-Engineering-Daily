"""Login for the manual send web page.

Accounts live in the AUTH_USERS environment variable as JSON {"email": "<password hash>"}. Passwords are never stored,
only PBKDF2-SHA256 hashes made with tools/hash_password.py. A successful login sets a signed, HttpOnly session cookie
(HMAC-SHA256 with AUTH_SECRET). Nothing is kept on the server, so a session ends when it expires, when the user is
removed from AUTH_USERS, or when AUTH_SECRET is changed.

Fail closed: if AUTH_USERS or AUTH_SECRET is missing or invalid, every protected endpoint answers 503.
"""
import base64
import hashlib
import hmac
import json
import os
import time
from http.cookies import SimpleCookie
from urllib.parse import urlparse

COOKIE = "session"
SESSION_SECONDS = 8 * 3600
MAX_FIELD = 256                # longest email or password accepted
MIN_SECRET = 32                # characters in AUTH_SECRET
ITERATIONS = 600_000           # PBKDF2 rounds for new hashes (OWASP guidance for PBKDF2-HMAC-SHA256)
MIN_ITERATIONS = 100_000       # a configured hash weaker than this is treated as invalid
HASH_PREFIX = "pbkdf2_sha256"
# Checked when the email is unknown, so a wrong email and a wrong password take the same time.
_DUMMY_HASH = ("pbkdf2_sha256$600000$76756605d520f0fa4d5932beac5db182$"
               "a498f238ac1883284182bc6e1913166e8205f3b9db5d0c7b83754574842c2ac8")


class NotConfigured(Exception):
    """AUTH_USERS or AUTH_SECRET is missing or invalid."""


# ---- passwords ----
def hash_password(password, iterations=ITERATIONS, salt=None):
    salt = salt if salt is not None else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{HASH_PREFIX}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        prefix, rounds, salt, digest = stored.split("$")
        rounds = int(rounds)
        if prefix != HASH_PREFIX or not MIN_ITERATIONS <= rounds <= 10_000_000:
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), rounds)
        return hmac.compare_digest(calc.hex(), digest.lower())
    except (ValueError, AttributeError):
        return False


# ---- configuration ----
def _users():
    """{email: hash} from AUTH_USERS, or None when it is missing or malformed."""
    try:
        raw = json.loads(os.environ.get("AUTH_USERS", ""))
    except ValueError:
        return None
    if not isinstance(raw, dict):
        return None
    users = {str(k).strip().lower(): v for k, v in raw.items() if isinstance(v, str) and str(k).strip()}
    return users or None


def _secret():
    s = os.environ.get("AUTH_SECRET", "")
    return s.encode("utf-8") if len(s) >= MIN_SECRET else None


def configured():
    return bool(_users() and _secret())


def authenticate(email, password):
    """The normalised email when the pair is right, else None. Raises NotConfigured when login is not set up."""
    users = _users()
    if not users or not _secret():
        raise NotConfigured()
    if not isinstance(email, str) or not isinstance(password, str):
        return None
    email = email.strip().lower()
    if not email or len(email) > MAX_FIELD or not password or len(password) > MAX_FIELD:
        return None
    stored = users.get(email)
    ok = verify_password(password, stored or _DUMMY_HASH)  # always one PBKDF2 run
    return email if ok and stored else None


# ---- session token ----
def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(body, secret):
    return _b64(hmac.new(secret, body.encode(), hashlib.sha256).digest())


def make_token(email, now=None):
    secret = _secret()
    if not secret:
        raise NotConfigured()
    now = time.time() if now is None else now
    body = _b64(json.dumps({"e": email, "x": int(now) + SESSION_SECONDS}, separators=(",", ":")).encode())
    return f"{body}.{_sign(body, secret)}"


def read_token(token, now=None):
    """The email of a valid, unexpired session whose user still exists, else None."""
    secret, users = _secret(), _users()
    if not secret or not users or not isinstance(token, str) or token.count(".") != 1:
        return None
    body, sig = token.split(".")
    if not hmac.compare_digest(sig, _sign(body, secret)):
        return None
    try:
        data = json.loads(_unb64(body))
        email, expires = data["e"], int(data["x"])
    except (ValueError, KeyError, TypeError):
        return None
    now = time.time() if now is None else now
    return email if expires > now and email in users else None


# ---- HTTP helpers (used by the api/*.py handlers) ----
def _secure(headers):
    host = (headers.get("Host") or "").split(":")[0]
    return headers.get("X-Forwarded-Proto", "https") == "https" and host not in ("localhost", "127.0.0.1")


def session_cookie(token, headers):
    return f"{COOKIE}={token}; Max-Age={SESSION_SECONDS}; Path=/; HttpOnly; SameSite=Strict" + ("; Secure" if _secure(headers) else "")


def clear_cookie(headers):
    return f"{COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict" + ("; Secure" if _secure(headers) else "")


def current_user(headers, now=None):
    jar = SimpleCookie()
    try:
        jar.load(headers.get("Cookie") or "")
    except Exception:
        return None
    morsel = jar.get(COOKIE)
    return read_token(morsel.value, now) if morsel else None


def same_origin(headers):
    """Browsers send Origin on POST. When it is present it must be this site (a second line behind SameSite=Strict)."""
    origin = headers.get("Origin")
    return not origin or urlparse(origin).netloc == (headers.get("Host") or "")


def reply(handler, status, payload, cookie=None):
    data = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    if cookie:
        handler.send_header("Set-Cookie", cookie)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def guard(handler):
    """Call first in every protected endpoint. Sends the error and returns False unless a valid session is present."""
    if not configured():
        reply(handler, 503, {"ok": False, "message": "Login is not configured on the server"})
        return False
    if handler.command == "POST" and not same_origin(handler.headers):
        reply(handler, 403, {"ok": False, "message": "Request refused"})
        return False
    if not current_user(handler.headers):
        reply(handler, 401, {"ok": False, "message": "Login required"})
        return False
    return True

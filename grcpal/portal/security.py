"""Security middleware: headers, CSRF protection and upload validation."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import time

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
       "base-uri 'none'")

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",  # "no-referrer" makes browsers send Origin: null on form posts
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Cross-Origin-Opener-Policy": "same-origin",
    # Other sites cannot embed our responses (an evidence file as an <img>, a JSON reply as a <script>), so a
    # browser never hands them to another origin's page even through a side channel.
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}

MAX_UPLOAD_BYTES = int(os.getenv("GRCPAL_MAX_UPLOAD_MB", "25")) * 1024 * 1024
# Largest request body accepted at all (the largest upload plus room for the form around it). Checked before the
# body is read or spooled to disk, so an oversized request costs nothing (BodyLimit below).
MAX_BODY_BYTES = int(os.getenv("GRCPAL_MAX_BODY_MB", "0") or 0) * 1024 * 1024 or MAX_UPLOAD_BYTES + 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".csv", ".xlsx", ".docx", ".pptx", ".txt", ".json", ".md", ".eml"}
# Leading bytes for binary formats; text formats must decode as UTF-8 and contain no NUL bytes.
MAGIC = {
    ".pdf": [b"%PDF-"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"],
    ".xlsx": [b"PK\x03\x04"], ".docx": [b"PK\x03\x04"], ".pptx": [b"PK\x03\x04"],
}
TEXT_TYPES = {".csv", ".txt", ".json", ".md", ".eml"}


def _secret() -> bytes:
    value = os.getenv("GRCPAL_SECRET")
    if not value:
        if os.getenv("GRCPAL_ENV", "").lower() == "production":
            raise RuntimeError("GRCPAL_SECRET must be set in production")
        value = _DEV_SECRET
    return value.encode()


_DEV_SECRET = secrets.token_hex(32)


def csrf_token(user_email: str, now: float | None = None) -> str:
    """Token bound to the user and a 12-hour window; no server-side session needed."""
    window = int((now or time.time()) // 43200)
    mac = hmac.new(_secret(), f"{user_email}|{window}".encode(), hashlib.sha256).hexdigest()
    return f"{window}.{mac}"


def csrf_valid(user_email: str, token: str | None, now: float | None = None) -> bool:
    if not token or "." not in token:
        return False
    current = int((now or time.time()) // 43200)
    window_s, mac = token.split(".", 1)
    if not window_s.isdigit() or int(window_s) not in (current, current - 1):
        return False
    expected = hmac.new(_secret(), f"{user_email}|{window_s}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, mac)


def is_production() -> bool:
    return os.getenv("GRCPAL_ENV", "").lower() == "production"


# Cookies. In production every GRC-pal cookie is Secure and carries the __Host- prefix: browsers then accept it
# only over HTTPS, for this exact host and path "/", so a sibling subdomain (another app on
# *.azurecontainerapps.io, say) cannot plant or overwrite it. Cookies set before this change used the bare
# name; they are read once and replaced (see legacy_cookies and the middleware in app.py).
HOST_PREFIX = "__Host-"


def cookie_name(base: str) -> str:
    return HOST_PREFIX + base if is_production() else base


def read_cookie(cookies, base: str) -> str:
    """The cookie's value under its current name, or under its old bare name (accepted until reissued)."""
    return cookies.get(cookie_name(base)) or cookies.get(base) or ""


def cookie_secure(scheme: str) -> bool:
    return is_production() or scheme == "https"


def set_cookie(response, scheme: str, base: str, value: str, max_age: int | None = None) -> None:
    response.set_cookie(cookie_name(base), value, max_age=max_age, path="/", httponly=True, samesite="lax",
                        secure=cookie_secure(scheme))


def clear_cookie(response, scheme: str, base: str) -> None:
    """Remove the cookie under both its current and its old name."""
    names = {cookie_name(base), base}
    for name in sorted(names):
        response.delete_cookie(name, path="/", httponly=True, samesite="lax",
                               secure=name.startswith(HOST_PREFIX) or cookie_secure(scheme))


def legacy_cookies(cookies, bases) -> list[str]:
    """Old bare-name cookies to replace in production (the browser has the old name but not the new one)."""
    if not is_production():
        return []
    return [b for b in bases if cookies.get(b) and not cookies.get(cookie_name(b))]


def session_binding(value: str) -> str:
    """What a form token is tied to besides the person: a hash of their sign-in session cookie (never the
    cookie itself, so a token on a page reveals nothing about the session)."""
    return hashlib.sha256(value.encode()).hexdigest()[:32] if value else ""


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(name: str) -> str:
    base = os.path.basename(name or "").strip().replace(" ", "_")
    base = _SAFE_NAME.sub("", base).lstrip(".")
    return base[:120] or "upload"


def validate_upload(filename: str, data: bytes) -> str | None:
    """Return an error message, or None if the file is acceptable."""
    ext = os.path.splitext(filename.lower())[1]
    if filename.lower() in ("manifest.json", "manifest.sig", "sha256sums"):
        return f"{filename} is a reserved name in the evidence store. Rename the file and upload it again."
    if ext not in ALLOWED_EXTENSIONS:
        return f"File type {ext or '(none)'} is not allowed. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
    if not data:
        return "The file is empty."
    if len(data) > MAX_UPLOAD_BYTES:
        return f"The file is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
    if ext in MAGIC and not any(data.startswith(m) for m in MAGIC[ext]):
        return f"The file content does not match its {ext} extension."
    if ext in TEXT_TYPES:
        if b"\x00" in data:
            return "Text files must not contain binary content."
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return "Text files must be UTF-8."
    return None


def csv_cell(value) -> str:
    """Stop spreadsheet formula injection: text starting with = + - @ (or a tab or carriage return) is prefixed
    with a quote, so Excel shows it as text instead of running it."""
    text = ", ".join(map(str, value)) if isinstance(value, list) else str(value if value is not None else "")
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _address(text: str) -> str:
    """One address from a header or socket value ("203.0.113.9", "203.0.113.9:443", "[2001:db8::5]:443"),
    normalized; "" when it is not an IP address."""
    text = (text or "").strip()
    if text.startswith("["):
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def client_ip(headers, peer: str | None) -> str:
    """The address of the person making the request, for sign-in events, the audit log and request logs.

    X-Forwarded-For is written left to right: whatever the client sent first, then one address per proxy.
    Only the entries added by our own proxies can be believed, so GRCPAL_TRUSTED_PROXY_HOPS says how many
    proxies sit in front of GRC-pal (Azure Container Apps ingress: 1; Caddy on the VM: 1). The address that
    the outermost trusted proxy saw is the hops-th entry from the right. 0 (the default) trusts no header
    and uses the connection's own address. Anything that is not an IP address is never recorded."""
    try:
        hops = max(0, int(os.getenv("GRCPAL_TRUSTED_PROXY_HOPS", "0")))
    except ValueError:
        hops = 0
    if hops:
        getlist = getattr(headers, "getlist", None)
        values = getlist("x-forwarded-for") if getlist else [headers.get("x-forwarded-for") or ""]
        parts = [p.strip() for p in ",".join(values).split(",") if p.strip()]
        if len(parts) >= hops:
            return _address(parts[-hops])
    return _address(peer or "")


class BodyTooLarge(Exception):
    """A request body passed MAX_BODY_BYTES while it was being read."""


class BodyLimit:
    """ASGI middleware: refuse request bodies larger than MAX_BODY_BYTES with 413, before anything parses them.
    A declared Content-Length is checked up front; a body without one is counted as it arrives."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = MAX_BODY_BYTES
        declared = dict(scope.get("headers") or ()).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > limit:
            return await self._refuse(send)
        state = {"seen": 0, "over": False, "started": False}

        async def counted():
            message = await receive()
            if message["type"] == "http.request":
                state["seen"] += len(message.get("body", b""))
                if state["seen"] > limit:
                    state["over"] = True
                    raise BodyTooLarge()
            return message

        async def watched(message):
            if state["over"]:  # whatever the app answers to the cut-off body (often a 400), send 413 instead
                if message["type"] == "http.response.start" and not state["started"]:
                    state["started"] = True
                    await self._refuse(send)
                return
            state["started"] = state["started"] or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, counted, watched)
        except BodyTooLarge:
            if not state["started"]:
                await self._refuse(send)

    @staticmethod
    async def _refuse(send):
        body = b"Request too large."
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                                (b"content-length", str(len(body)).encode()), (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})

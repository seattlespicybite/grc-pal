"""Security middleware: headers, CSRF protection and upload validation."""
from __future__ import annotations

import hashlib
import hmac
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
    "Cache-Control": "no-store",
}

MAX_UPLOAD_BYTES = int(os.getenv("GRCPAL_MAX_UPLOAD_MB", "25")) * 1024 * 1024
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


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(name: str) -> str:
    base = os.path.basename(name or "").strip().replace(" ", "_")
    base = _SAFE_NAME.sub("", base).lstrip(".")
    return base[:120] or "upload"


def validate_upload(filename: str, data: bytes) -> str | None:
    """Return an error message, or None if the file is acceptable."""
    ext = os.path.splitext(filename.lower())[1]
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

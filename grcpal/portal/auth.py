"""Authentication (who is this?) and the role model (what may they do?).

Sign-in modes:

  * local (default): GRC-pal's own accounts. Passwords are stored only as scrypt hashes and sessions
    live on the server (see accounts.py). Meant for a VM on an internal network.
  * easyauth: Azure Container Apps / App Service built-in authentication. The platform
    signs the user in (Microsoft Entra ID, or any OIDC provider it supports) and injects the
    X-MS-CLIENT-PRINCIPAL header. Requests without it are rejected. In production the tenant allow-list
    (GRCPAL_ALLOWED_TENANT_IDS) is required, and each person is bound to their Entra object ID at first
    sign-in (Portal.resolve), because an email address can be reused or renamed and an object ID cannot.
  * proxy: a trusted reverse proxy (oauth2-proxy, Pomerium, Caddy forward_auth) signs the user
    in and sets X-Forwarded-Email. Anyone who reaches the app directly could send that header too, so the
    proxy must also send X-GRCPAL-Proxy-Secret with the value of GRCPAL_PROXY_SECRET; requests without it
    are refused.
  * dev: local development and demos. The user comes from a cookie set on /dev/login, the
    X-Dev-Principal header or GRCPAL_DEV_PRINCIPAL. Anyone can pick any user, so it is allowed only
    when GRCPAL_ENV=dev (or development) is set explicitly (`grcpal serve --demo` sets it and listens on this
    computer only; docker-compose.yml sets it and publishes on 127.0.0.1 only).

Authorization does not come from the identity provider. Each organization's users table holds
exactly one role per person (see ROLES); the service resolves an Identity to a User.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import re
from dataclasses import dataclass, field

from grcpal.portal.security import read_cookie

ROLES = ("admin", "contributor", "auditor")
# "contributor" is stored in the data; people see it as "Control owner".
ROLE_LABELS = {"admin": "Admin", "contributor": "Control owner", "auditor": "Auditor"}
ROLE_HELP = {
    "admin": "Full access: assign work, review evidence, override, manage users, cycles and configuration",
    "contributor": "Sees only the controls assigned to them or owned by them; uploads evidence and comments. "
                   "No access to configuration",
    "auditor": "Read-only: controls, evidence, comments, overrides, audit log and exports, until the access "
               "end date. No access to configuration",
}
AUTH_MODES = ("local", "easyauth", "proxy", "dev")
DEV_COOKIE = "grcpal_dev_user"
_EMAIL = re.compile(r"^[^@\s]{1,64}@(?=[^@\s]{1,253}\Z)[^@\s.]+(?:\.[^@\s.]+)+\Z")  # linear time: labels cannot overlap
EMAIL_RE = _EMAIL
_EMAIL_CLAIMS = ("preferred_username", "email", "upn",
                 "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
                 "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
_NAME_CLAIMS = ("name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
_GROUP_CLAIMS = ("groups", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups")
_TENANT_CLAIMS = ("tid", "http://schemas.microsoft.com/identity/claims/tenantid")
_OBJECT_ID_CLAIMS = ("oid", "http://schemas.microsoft.com/identity/claims/objectidentifier")
PROXY_SECRET_HEADER = "x-grcpal-proxy-secret"
PROXY_SECRET_MIN = 32


class AuthError(Exception):
    """Not signed in, or the identity is not acceptable. status: 401 or 403."""

    def __init__(self, message: str, status: int = 401):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Identity:
    """Who signed in, as asserted by the sign-in layer. Carries no permissions."""
    email: str
    name: str
    groups: frozenset = field(default_factory=frozenset)
    tenant_id: str = ""
    object_id: str = ""   # Microsoft Entra object ID (easyauth); empty when the sign-in layer has none


@dataclass(frozen=True)
class User:
    email: str
    name: str
    role: str

    def has(self, *roles: str) -> bool:
        return self.role in roles

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_contributor(self) -> bool:
        return self.role == "contributor"

    @property
    def is_auditor(self) -> bool:
        return self.role == "auditor"

    @property
    def can_write(self) -> bool:
        return self.role in ("admin", "contributor")

    @property
    def sees_everything(self) -> bool:
        return self.role in ("admin", "auditor")


SYSTEM = User(email="system@grc-pal.local", name="GRC-pal scheduler", role="admin")


def auth_mode() -> str:
    mode = os.getenv("GRCPAL_AUTH_MODE", "local")
    if mode not in AUTH_MODES:
        raise RuntimeError("GRCPAL_AUTH_MODE must be local, easyauth, proxy or dev")
    if mode == "dev" and os.getenv("GRCPAL_ENV", "") not in ("dev", "development"):
        # Fail closed: a missing or mistyped GRCPAL_ENV must never open the password-free sign-in page.
        raise RuntimeError("GRCPAL_AUTH_MODE=dev lets anyone sign in as anyone; it needs GRCPAL_ENV=dev, set "
                           "explicitly (grcpal serve --demo and docker compose do this). Use local, easyauth or proxy otherwise.")
    if mode == "proxy" and len(os.getenv("GRCPAL_PROXY_SECRET", "").strip()) < PROXY_SECRET_MIN:
        raise RuntimeError(f"GRCPAL_AUTH_MODE=proxy needs GRCPAL_PROXY_SECRET (at least {PROXY_SECRET_MIN} characters, "
                           "e.g. openssl rand -hex 32), sent by the proxy as X-GRCPAL-Proxy-Secret on every request, "
                           "so a request that bypasses the proxy cannot claim to be anyone")
    if mode == "easyauth" and os.getenv("GRCPAL_ENV", "").lower() == "production" and not _csv_env("GRCPAL_ALLOWED_TENANT_IDS"):
        raise RuntimeError("GRCPAL_AUTH_MODE=easyauth in production needs GRCPAL_ALLOWED_TENANT_IDS (your Entra tenant "
                           "ID), so people from other organizations' directories cannot sign in")
    return mode


def _csv_env(name: str) -> list[str]:
    return [v.strip().lower() for v in os.getenv(name, "").split(",") if v.strip()]


def bootstrap_admins() -> set[str]:
    """GRCPAL_BOOTSTRAP_ADMINS=a@x.com,b@x.com: created as admins at first sign-in."""
    return set(_csv_env("GRCPAL_BOOTSTRAP_ADMINS"))


def group_role(groups: frozenset) -> str | None:
    """Optional fallback: GRCPAL_GROUP_ADMIN / _CONTRIBUTOR / _AUDITOR = group object IDs.
    The most privileged matching role wins. Used only to create a user row on first sign-in."""
    for role in ROLES:
        if groups & set(_csv_env(f"GRCPAL_GROUP_{role.upper()}")):
            return role
    return None


def _claims(header: str) -> list[dict]:
    try:
        data = json.loads(base64.b64decode(header))
    except (ValueError, json.JSONDecodeError) as exc:
        raise AuthError("malformed principal header") from exc
    return data.get("claims") or []


def _check_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not _EMAIL.match(email):
        raise AuthError("no usable email address in the sign-in identity", 403)
    return email


def identity_from_request(headers, cookies=None) -> Identity:
    mode = auth_mode()
    cookies = cookies or {}
    if mode == "local":  # sessions live in the portal store: see Portal.session_user
        raise AuthError("not signed in")
    if mode == "dev":
        raw = headers.get("x-dev-principal") or os.getenv("GRCPAL_DEV_PRINCIPAL")
        if read_cookie(cookies, DEV_COOKIE):
            raw = json.dumps({"email": read_cookie(cookies, DEV_COOKIE)})
        if not raw:
            raise AuthError("dev mode: choose a user on /dev/login")
        try:
            d = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AuthError("dev mode: malformed principal") from exc
        email = _check_email(d.get("email", ""))
        return Identity(email=email, name=d.get("name") or email, groups=frozenset(d.get("groups", [])),
                        tenant_id=d.get("tid", ""))

    if mode == "proxy":
        expected = os.getenv("GRCPAL_PROXY_SECRET", "").strip()
        sent = headers.get(PROXY_SECRET_HEADER) or ""
        if not hmac.compare_digest(sent.encode(), expected.encode()):
            raise AuthError("this request did not come through the sign-in proxy", 403)
        email = headers.get(os.getenv("GRCPAL_PROXY_EMAIL_HEADER", "x-forwarded-email"))
        if not email:
            raise AuthError("not signed in")
        name = headers.get(os.getenv("GRCPAL_PROXY_NAME_HEADER", "x-forwarded-preferred-username")) or email
        return Identity(email=_check_email(email), name=name)

    header = headers.get("x-ms-client-principal")
    if not header:
        raise AuthError("not signed in")
    claims = _claims(header)
    get = lambda keys: next((c.get("val") for c in claims if c.get("typ") in keys), None)  # noqa: E731
    email = _check_email(get(_EMAIL_CLAIMS) or "")
    tid = (get(_TENANT_CLAIMS) or "").lower()
    allowed = _csv_env("GRCPAL_ALLOWED_TENANT_IDS")
    if allowed and tid not in allowed:
        raise AuthError("your organization's directory is not allowed to use this GRC-pal instance", 403)
    groups = frozenset(c["val"].lower() for c in claims if c.get("typ") in _GROUP_CLAIMS and c.get("val"))
    oid = (get(_OBJECT_ID_CLAIMS) or "").strip().lower()
    return Identity(email=email, name=get(_NAME_CLAIMS) or email, groups=groups, tenant_id=tid, object_id=oid)

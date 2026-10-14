"""Authentication (who is this?) and the role model (what may they do?).

Sign-in modes:

  * local (default): GRC-pal's own accounts. Passwords are stored only as scrypt hashes and sessions
    live on the server (see accounts.py). Meant for a VM on an internal network.
  * easyauth: Azure Container Apps / App Service built-in authentication. The platform
    signs the user in (Microsoft Entra ID, or any OIDC provider it supports) and injects the
    X-MS-CLIENT-PRINCIPAL header. Requests without it are rejected.
  * proxy: a trusted reverse proxy (oauth2-proxy, Pomerium, Caddy forward_auth) signs the user
    in and sets X-Forwarded-Email. Only safe when the app is reachable through that proxy alone.
  * dev: local development and demos. The user comes from a cookie set on /dev/login, the
    X-Dev-Principal header or GRCPAL_DEV_PRINCIPAL. Refused when GRCPAL_ENV=production.

Authorization does not come from the identity provider. Each organization's users table holds
exactly one role per person (see ROLES); the service resolves an Identity to a User.
"""
from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass, field

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
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
EMAIL_RE = _EMAIL
_EMAIL_CLAIMS = ("preferred_username", "email", "upn",
                 "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
                 "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
_NAME_CLAIMS = ("name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
_GROUP_CLAIMS = ("groups", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups")
_TENANT_CLAIMS = ("tid", "http://schemas.microsoft.com/identity/claims/tenantid")


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
    if mode == "dev" and os.getenv("GRCPAL_ENV", "").lower() == "production":
        raise RuntimeError("GRCPAL_AUTH_MODE=dev is not allowed when GRCPAL_ENV=production")
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
        if cookies.get(DEV_COOKIE):
            raw = json.dumps({"email": cookies[DEV_COOKIE]})
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
    return Identity(email=email, name=get(_NAME_CLAIMS) or email, groups=groups, tenant_id=tid)

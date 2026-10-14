"""Local accounts: passwords, one-time setup and reset links, server-side sessions, auditor end dates.

Used when GRCPAL_AUTH_MODE=local (the default; meant for a VM on an internal network). Mixed into Portal,
so every write is authorized in the method and recorded in the audit log.

How secrets are kept:
  * passwords are stored only as scrypt hashes (Python standard library), each with its own random salt;
  * setup/reset links and session cookies are random tokens; only their SHA-256 hash is stored, so a copy
    of the database cannot be used to sign in or to reset a password.

Accepted for the internal-only proof of concept (docs/security.md): no MFA, no lockout. Add both before
the portal is reachable from outside the internal network.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import secrets

from grcpal.evidence import utcnow
from grcpal.portal.auth import EMAIL_RE, AuthError, User

PASSWORD_MIN = 12
PASSWORD_MAX = 256
SESSION_HOURS = 8
ADMIN_LINK_HOURS = 72      # links an admin creates (new account, break-glass reset)
SELF_RESET_HOURS = 1       # "Forgot password" links sent by email
AUDITOR_DEFAULT_DAYS = 90
SESSION_COOKIE = "grcpal_session"
# OWASP minimum for scrypt: N=2^15, r=8, p=3 (about 32 MiB of memory per check). Stored with each hash.
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 3}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = SCRYPT["n"], SCRYPT["r"], SCRYPT["p"]
    key = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=256 * 1024 * 1024)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"scrypt${n}${r}${p}${b64(salt)}${b64(key)}"


def verify_password(stored: str, password: str) -> bool:
    try:
        algo, n, r, p, salt, key = (stored or "").split("$")
        if algo != "scrypt":
            return False
        expected = base64.b64decode(key)
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=256 * 1024 * 1024, dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)


def _digest(token: str) -> str:
    return hashlib.sha256((token or "").encode()).hexdigest()


def _now() -> str:
    return utcnow().isoformat()


def _later(hours: int) -> str:
    return (utcnow() + dt.timedelta(hours=hours)).isoformat()


_DUMMY: list[str] = []


def _dummy_hash() -> str:
    """Checked when the email is unknown, so a wrong email takes as long as a wrong password."""
    if not _DUMMY:
        _DUMMY.append(hash_password(secrets.token_urlsafe(16)))
    return _DUMMY[0]


class AccountsMixin:
    # ================================================================ access checks (every sign-in mode)
    def _check_access(self, row: dict) -> None:
        if not row.get("active", True):
            raise AuthError("your GRC-pal account is disabled; ask an admin", 403)
        until = row.get("access_until") or ""
        if until and until < self.today.isoformat():
            raise AuthError(f"your access ended on {until}; ask an admin to extend it", 403)

    def _auditor_until(self, value: str | None) -> str:
        """Validate an auditor's access end date; blank means the default (90 days from today)."""
        if not (value or "").strip():
            return (self.today + dt.timedelta(days=AUDITOR_DEFAULT_DAYS)).isoformat()
        try:
            day = dt.date.fromisoformat(value.strip())
        except ValueError as exc:
            raise self._invalid("Access end date must be a date (YYYY-MM-DD)") from exc
        if day < self.today:
            raise self._invalid("Access end date cannot be in the past")
        return day.isoformat()

    def set_access_until(self, actor: User, email: str, value: str) -> None:
        self._admin(actor)
        row = self.user_row(email)
        if not row:
            raise self._invalid("User not found")
        if row["role"] != "auditor":
            raise self._invalid("Only auditor accounts have an access end date")
        until = self._auditor_until(value)
        self.store.update("users", "u", row["RowKey"], {"access_until": until})
        self.audit(actor, "user.access_until", row["RowKey"], {"from": row.get("access_until", ""), "to": until})

    # ================================================================ passwords and links
    def check_password(self, password: str, email: str) -> None:
        if len(password or "") < PASSWORD_MIN or not password.strip():
            raise self._invalid(f"Use at least {PASSWORD_MIN} characters. A short sentence is easy to remember.")
        if len(password) > PASSWORD_MAX:
            raise self._invalid(f"Use at most {PASSWORD_MAX} characters")
        local = (email or "").split("@")[0].lower()
        if email and (email.lower() in password.lower() or (len(local) >= 4 and local in password.lower())):
            raise self._invalid("Do not use your email address in your password")

    def _issue_link(self, email: str, purpose: str, by: str, hours: int) -> str:
        # one live link per person: issuing a new one cancels the old one
        for r in self.store.list("account_links", "l"):
            if r.get("email") == email or r.get("expires", "") < _now():
                self.store.delete("account_links", "l", r["RowKey"])
        token = secrets.token_urlsafe(32)
        self.store.insert("account_links", {"PartitionKey": "l", "RowKey": _digest(token), "email": email,
                                            "purpose": purpose, "expires": _later(hours), "created_by": by,
                                            "created_at": _now()})
        return self.link(f"/account/password/{token}")

    def _mail_link(self, email: str, url: str, purpose: str, hours: int) -> None:
        from grcpal.portal import notify

        new = purpose == "setup"
        content = {"subject": "Set up your GRC-pal account" if new else "Reset your GRC-pal password",
                   "title": "Choose your GRC-pal password" if new else "Reset your GRC-pal password",
                   "intro": ("An admin gave you access to GRC-pal. Choose a password to finish setting up your "
                             "account." if new else "Someone asked to reset the password for this account. If it "
                             "was not you, ignore this email; your password stays the same."),
                   "fields": [("Account", email), ("Link expires", f"in {hours} hour{'s' if hours != 1 else ''}")],
                   "button": ("Choose a password", url)}
        self.mailer.send(notify.render(content, email, self.org, f"account.{purpose}"))

    def setup_link(self, actor: User, email: str) -> str:
        """Admin: a one-time link to set (new account) or reset (break-glass) a password. Also emailed."""
        self._admin(actor)
        row = self.user_row(email)
        if not row:
            raise self._invalid("User not found")
        if not row.get("active", True):
            raise self._invalid("Enable the account first")
        purpose = "reset" if row.get("password_hash") else "setup"
        url = self._issue_link(row["RowKey"], purpose, actor.email, ADMIN_LINK_HOURS)
        self._mail_link(row["RowKey"], url, purpose, ADMIN_LINK_HOURS)
        self.audit(actor, "account.link", row["RowKey"], {"purpose": purpose, "hours": ADMIN_LINK_HOURS})
        return url

    def request_reset(self, email: str) -> None:
        """Self-service "Forgot password". Says nothing about whether the account exists."""
        email = (email or "").strip().lower()
        row = self.user_row(email) if EMAIL_RE.match(email) else None
        if not row or not row.get("active", True):
            self.events.security("Password reset requested for an unknown or disabled account", actor=email[:120])
            return
        url = self._issue_link(email, "reset", "self-service", SELF_RESET_HOURS)
        self._mail_link(email, url, "reset", SELF_RESET_HOURS)
        self.audit(email, "account.reset_requested", email, {"hours": SELF_RESET_HOURS})

    def link_row(self, token: str) -> dict | None:
        row = self.store.get("account_links", "l", _digest(token))
        if not row or row.get("expires", "") < _now():
            return None
        user = self.user_row(row["email"])
        return row if user and user.get("active", True) else None

    def set_password_with_link(self, token: str, password: str) -> str:
        row = self.link_row(token)
        if not row:
            raise self._invalid("This link has expired or was already used. Use Forgot password, or ask an "
                                "admin for a new link.")
        email = row["email"]
        self.check_password(password, email)
        self.store.delete("account_links", "l", row["RowKey"])
        self.store.update("users", "u", email, {"password_hash": hash_password(password), "password_set_at": _now()})
        self.revoke_sessions(email)
        self.audit(email, "account.password_set", email, {"via": row["purpose"], "link_by": row.get("created_by", "")})
        return email

    def create_local_admin(self, email: str, name: str, password: str) -> None:
        """Break-glass and first admin, from the VM's command line only. The account never uses SSO."""
        email = (email or "").strip().lower()
        if not EMAIL_RE.match(email):
            raise self._invalid(f"'{email}' is not a valid email address")
        self.check_password(password, email)
        row = self.user_row(email)
        if row is None:
            self._create_user(email, (name or email)[:120], "admin", "cli", "cli")
        self.store.update("users", "u", email, {"role": "admin", "active": True, "local_only": True,
                                                "access_until": "", "password_hash": hash_password(password),
                                                "password_set_at": _now()})
        self.revoke_sessions(email)
        self.audit("cli", "account.break_glass_admin", email, {"existing": row is not None,
                                                               "previous_role": (row or {}).get("role", "")})

    def any_password_set(self) -> bool:
        return any(u.get("password_hash") and u.get("active", True) for u in self.users())

    # ================================================================ sessions
    def sign_in(self, email: str, password: str, ip: str = "") -> str:
        """Check the password and start a session. Returns the session token for the cookie."""
        email = (email or "").strip().lower()
        row = self.user_row(email) if EMAIL_RE.match(email) else None
        stored = (row or {}).get("password_hash") or ""
        ok = verify_password(stored or _dummy_hash(), password or "") and bool(stored)
        if not ok:
            self.events.security("Sign-in failed: wrong email or password", actor=email[:120], ip=ip)
            raise AuthError("Email or password is incorrect", 401)
        try:
            self._check_access(row)
        except AuthError as exc:
            self.events.security(f"Sign-in refused: {exc}", actor=email, ip=ip)
            raise
        token = secrets.token_urlsafe(32)
        self.store.insert("sessions", {"PartitionKey": "s", "RowKey": _digest(token), "email": email,
                                       "created": _now(), "expires": _later(SESSION_HOURS)})
        self.store.update("users", "u", email, {"last_seen": _now()})
        self.audit(email, "auth.signin", email, {"method": "password", "ip": ip})
        return token

    def session_user(self, token: str | None) -> User:
        if not token:
            raise AuthError("not signed in")
        s = self.store.get("sessions", "s", _digest(token))
        if not s or s.get("expires", "") < _now():
            if s:
                self.store.delete("sessions", "s", s["RowKey"])
            raise AuthError("your session ended; sign in again")
        row = self.user_row(s["email"])
        if not row:
            raise AuthError("not signed in")
        try:
            self._check_access(row)
        except AuthError:
            self.store.delete("sessions", "s", s["RowKey"])
            raise
        if (row.get("last_seen") or "") < (utcnow() - dt.timedelta(hours=1)).isoformat():
            self.store.update("users", "u", row["RowKey"], {"last_seen": _now()})
        return User(email=row["RowKey"], name=row.get("name") or row["RowKey"], role=row["role"])

    def sign_out(self, token: str | None) -> None:
        s = self.store.get("sessions", "s", _digest(token)) if token else None
        if s:
            self.store.delete("sessions", "s", s["RowKey"])
            self.audit(s["email"], "auth.signout", s["email"], {})

    def revoke_sessions(self, email: str) -> int:
        """End every session of this person (and drop expired ones while we are here)."""
        gone = 0
        for s in self.store.list("sessions", "s"):
            if s.get("email") == email or s.get("expires", "") < _now():
                self.store.delete("sessions", "s", s["RowKey"])
                gone += s.get("email") == email
        return gone

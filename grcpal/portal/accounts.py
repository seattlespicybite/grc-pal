"""Local accounts: passwords, one-time setup and reset links, server-side sessions, auditor end dates.

Used when GRCPAL_AUTH_MODE=local (the default; meant for a VM on an internal network). Mixed into Portal,
so every write is authorized in the method and recorded in the audit log.

How secrets are kept:
  * passwords are stored only as scrypt hashes (Python standard library), each with its own random salt;
  * setup/reset links and session cookies are random tokens; only their SHA-256 hash is stored, so a copy
    of the database cannot be used to sign in or to reset a password.

Admin sessions also end after ADMIN_IDLE_MINUTES without activity.

Protection of the sign-in itself (hardening batch B6):
  * failed sign-ins are counted per account and per address (table `signinlimits`); past a few, sign-in is
    locked for a while that doubles with each further failure, and is refused before any password hashing;
  * at most GRCPAL_MAX_PASSWORD_CHECKS password hashes run at once, so a flood of sign-ins cannot exhaust memory;
  * emailed links carry their token after "#" (never sent to the server, so never in a log) and are exchanged
    once for a password form that lasts FORM_LINK_MINUTES;
  * "Forgot password" is limited per account and per address, is refused for admins and the break-glass account,
    and does its work after the page has answered;
  * optional two-step sign-in with an authenticator app (TOTP, RFC 6238, standard library only).
For internet-facing installs, use Entra sign-in with Conditional Access MFA instead (docs/security.md).
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import os
import secrets
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from grcpal.evidence import utcnow
from grcpal.portal.auth import EMAIL_RE, AuthError, User
from grcpal.settings import NoKey

PASSWORD_MIN = 12
PASSWORD_MAX = 256
SESSION_HOURS = 8
ADMIN_LINK_HOURS = 72      # links an admin creates (new account, break-glass reset)
SELF_RESET_HOURS = 1       # "Forgot password" links sent by email
AUDITOR_DEFAULT_DAYS = 90
SESSION_COOKIE = "grcpal_session"   # in production the browser stores it as __Host-grcpal_session (security.py)
ADMIN_IDLE_MINUTES = 30    # an admin session unused this long ends (GRCPAL_ADMIN_IDLE_MINUTES to change)
TOUCH_SECONDS = 60         # how often a session's last activity is written (not on every request)
# OWASP minimum for scrypt: N=2^15, r=8, p=3 (about 32 MiB of memory per check). Stored with each hash.
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 3}

# ---- sign-in limits (failures before a lock; the lock then doubles: 1, 2, 4 ... up to LOCK_MAX_MINUTES)
LOGIN_FREE_PER_ACCOUNT = 5
LOGIN_FREE_PER_IP = 20
LOGIN_WINDOW_MINUTES = 15
LOCK_MAX_MINUTES = 15
RESET_PER_ACCOUNT = 3      # "Forgot password" emails per account per hour
RESET_PER_IP = 10          # "Forgot password" requests per address per hour
FORM_LINK_MINUTES = 15     # an opened link's password form lasts this long
# ---- password hashing: at most this many at once (about 32 MiB each); others wait up to CHECK_WAIT_SECONDS
CHECK_WAIT_SECONDS = 5.0
TOTP_STEP = 30
TOTP_ISSUER = "GRC-pal"


def _max_checks() -> int:
    try:
        return max(1, int(os.getenv("GRCPAL_MAX_PASSWORD_CHECKS", "") or 4))
    except ValueError:
        return 4


_CHECKS = threading.BoundedSemaphore(_max_checks())
_LIMITS_LOCK = threading.Lock()
_BACKGROUND = ThreadPoolExecutor(max_workers=1, thread_name_prefix="account")


class PasswordChecksBusy(RuntimeError):
    """Too many password checks are running; the caller should answer "try again" instead of queueing more."""


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, dklen: int = 64, wait: float | None = None) -> bytes:
    if not _CHECKS.acquire(timeout=wait):
        raise PasswordChecksBusy("too many password checks at once")
    try:
        return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=256 * 1024 * 1024, dklen=dklen)
    finally:
        _CHECKS.release()


# ---- two-step sign-in codes (RFC 6238 TOTP, SHA-1, 6 digits, 30 seconds: what authenticator apps expect)
def _step(at: float | None = None) -> int:
    return int((time.time() if at is None else at) // TOTP_STEP)


def totp_code(secret_b32: str, step: int, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = SCRYPT["n"], SCRYPT["r"], SCRYPT["p"]
    key = _scrypt(password, salt, n, r, p)  # waits for a free slot: setting a password is rare and deliberate
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"scrypt${n}${r}${p}${b64(salt)}${b64(key)}"


def verify_password(stored: str, password: str) -> bool:
    try:
        algo, n, r, p, salt, key = (stored or "").split("$")
        if algo != "scrypt":
            return False
        expected = base64.b64decode(key)
        got = _scrypt(password, base64.b64decode(salt), int(n), int(r), int(p), dklen=len(expected),
                      wait=CHECK_WAIT_SECONDS)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)


def _digest(token: str) -> str:
    return hashlib.sha256((token or "").encode()).hexdigest()


def _now() -> str:
    return utcnow().isoformat()


def _admin_idle_minutes() -> int:
    try:
        return max(1, int(os.getenv("GRCPAL_ADMIN_IDLE_MINUTES", "") or ADMIN_IDLE_MINUTES))
    except ValueError:
        return ADMIN_IDLE_MINUTES


def _later(hours: int) -> str:
    return (utcnow() + dt.timedelta(hours=hours)).isoformat()


def _later_min(minutes: int) -> str:
    return (utcnow() + dt.timedelta(minutes=minutes)).isoformat()


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

    # ================================================================ sign-in and reset limits
    # Rows in `signinlimits` are keyed by a hash of (kind, email or address), so the table holds no addresses.
    def _limit_key(self, kind: str, value: str) -> str:
        return hashlib.sha256(f"{kind}|{(value or '').strip().lower()}".encode()).hexdigest()[:40]

    def _locked_minutes(self, kind: str, value: str) -> int:
        row = self.store.get("signinlimits", "k", self._limit_key(kind, value)) if value else None
        until = (row or {}).get("locked_until") or ""
        if until <= _now():
            return 0
        left = dt.datetime.fromisoformat(until) - utcnow()
        return max(1, -(-int(left.total_seconds()) // 60))

    def _count(self, kind: str, value: str, window_minutes: int) -> int:
        """Add one to this key's count in its current window; returns the new count."""
        if not value:
            return 0
        key = self._limit_key(kind, value)
        with _LIMITS_LOCK:
            row = self.store.get("signinlimits", "k", key) or {}
            start = (utcnow() - dt.timedelta(minutes=window_minutes)).isoformat()
            fresh = (row.get("first") or "") < start and (row.get("locked_until") or "") < _now()
            count = 1 if fresh else int(row.get("count") or 0) + 1
            self.store.upsert("signinlimits", {"PartitionKey": "k", "RowKey": key, "kind": kind, "count": count,
                                               "first": _now() if fresh else row.get("first") or _now(),
                                               "locked_until": "" if fresh else row.get("locked_until") or ""})
        return count

    def _lock(self, kind: str, value: str, minutes: int) -> None:
        self.store.update("signinlimits", "k", self._limit_key(kind, value), {"locked_until": _later_min(minutes)})

    def _clear_limit(self, kind: str, value: str) -> None:
        if value and self.store.get("signinlimits", "k", self._limit_key(kind, value)):
            self.store.delete("signinlimits", "k", self._limit_key(kind, value))

    def _sign_in_failed(self, email: str, ip: str, why: str) -> None:
        self.events.security(f"Sign-in failed: {why}", actor=email[:120], ip=ip)
        for kind, value, free in (("login-account", email, LOGIN_FREE_PER_ACCOUNT), ("login-ip", ip, LOGIN_FREE_PER_IP)):
            over = self._count(kind, value, LOGIN_WINDOW_MINUTES) - free
            if over > 0:
                minutes = min(LOCK_MAX_MINUTES, 2 ** (over - 1))
                self._lock(kind, value, minutes)
                self.events.security(f"Sign-in locked for {minutes} minute{'s' if minutes != 1 else ''} after "
                                     f"repeated failures ({'this account' if kind == 'login-account' else 'this address'})",
                                     actor=email[:120], ip=ip)

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
        # After "#": the browser keeps the token to itself (no request line, log, proxy or Referer sees it); the page
        # posts it once to /account/password/open (routes_accounts.py).
        return self.link(f"/account/password#{token}")

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

    def request_reset(self, email: str, ip: str = ""):
        """Self-service "Forgot password". Says nothing about whether the account exists: the work (lookup, limits,
        email) runs after the page has answered, so the answer and its timing are the same for every address."""
        if getattr(self.mailer, "sync", True):
            self._reset_work(email, ip)
            return None
        return _BACKGROUND.submit(self._reset_safely, email, ip)

    def _reset_safely(self, email: str, ip: str) -> None:
        try:
            self._reset_work(email, ip)
        except Exception as exc:  # noqa: BLE001 - a background task must not die silently
            self.events.error("system", f"Password reset request failed: {type(exc).__name__}")

    def _reset_work(self, email: str, ip: str) -> None:
        email = (email or "").strip().lower()[:254]
        for kind, value, limit in (("reset-ip", ip, RESET_PER_IP), ("reset-account", email, RESET_PER_ACCOUNT)):
            if self._count(kind, value, 60) > limit:
                self.events.security(f"Password reset requests paused: more than {limit} in an hour from "
                                     f"{'this address' if kind == 'reset-ip' else 'this account'}",
                                     actor=email[:120], ip=ip)
                return
        row = self.user_row(email) if EMAIL_RE.match(email) else None
        if not row or not row.get("active", True):
            self.events.security("Password reset requested for an unknown or disabled account", actor=email[:120], ip=ip)
            return
        if row.get("role") == "admin" or row.get("local_only"):
            # A mailbox compromise must not become a GRC-pal admin compromise. Admins get a link from another
            # admin (Users and roles) or reset on the server (grcpal create-admin).
            self.events.security("Self-service password reset refused for an admin or break-glass account",
                                 actor=email, ip=ip)
            self.audit(email, "account.reset_refused", email, {"ip": ip})
            return
        url = self._issue_link(email, "reset", "self-service", SELF_RESET_HOURS)
        self._mail_link(email, url, "reset", SELF_RESET_HOURS)
        self.audit(email, "account.reset_requested", email, {"hours": SELF_RESET_HOURS, "ip": ip})

    def _live_link(self, token: str, stage: str) -> dict | None:
        """A link that is unexpired, at this stage ("email": the emailed token; "form": the opened form), and whose
        person is still active."""
        row = self.store.get("account_links", "l", _digest(token)) if token else None
        if not row or row.get("expires", "") < _now() or (row.get("stage") or "email") != stage:
            return None
        user = self.user_row(row["email"])
        return row if user and user.get("active", True) else None

    def open_link(self, token: str) -> str | None:
        """Exchange an emailed link token, once, for a password-form token that lasts FORM_LINK_MINUTES (kept in a
        cookie by the route). Returns None when the link is unknown, used, expired or its account is disabled."""
        row = self._live_link(token, "email")
        if not row:
            return None
        self.store.delete("account_links", "l", row["RowKey"])
        form = secrets.token_urlsafe(32)
        self.store.insert("account_links", {"PartitionKey": "l", "RowKey": _digest(form), "email": row["email"],
                                            "purpose": row["purpose"], "stage": "form",
                                            "expires": min(row["expires"], _later_min(FORM_LINK_MINUTES)),
                                            "created_by": row.get("created_by", ""), "created_at": _now()})
        return form

    def link_row(self, token: str) -> dict | None:
        """The open password form for this form token (see open_link)."""
        return self._live_link(token, "form")

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
                                                "password_set_at": _now(), "totp_secret": "", "totp_pending": "",
                                                "totp_last_step": 0})
        self.revoke_sessions(email)
        self._clear_limit("login-account", email)
        self.audit("cli", "account.break_glass_admin", email, {"existing": row is not None,
                                                               "previous_role": (row or {}).get("role", ""),
                                                               "two_step_cleared": bool((row or {}).get("totp_secret"))})

    def any_password_set(self) -> bool:
        return any(u.get("password_hash") and u.get("active", True) for u in self.users())

    # ================================================================ sessions
    def sign_in(self, email: str, password: str, ip: str = "", code: str = "") -> str:
        """Check the password (and the two-step code, when set up) and start a session. Returns the session token
        for the cookie. Locked accounts and addresses are refused before any hashing."""
        email = (email or "").strip().lower()[:254]
        wait = max(self._locked_minutes("login-account", email), self._locked_minutes("login-ip", ip))
        if wait:
            self.events.security("Sign-in refused: locked after repeated failures", actor=email[:120], ip=ip)
            raise AuthError(f"Too many failed sign-in attempts. Wait {wait} minute{'s' if wait != 1 else ''} and try "
                            "again, or ask a GRC-pal admin.", 429)
        row = self.user_row(email) if EMAIL_RE.match(email) else None
        stored = (row or {}).get("password_hash") or ""
        try:
            ok = verify_password(stored or _dummy_hash(), password or "") and bool(stored)
        except PasswordChecksBusy as exc:
            self.events.security("Sign-in refused: too many password checks at once", actor=email[:120], ip=ip)
            raise AuthError("GRC-pal is busy. Try again in a moment.", 503) from exc
        if not ok:
            self._sign_in_failed(email, ip, "wrong email or password")
            raise AuthError("Email or password is incorrect", 401)
        try:
            self._check_access(row)
        except AuthError as exc:
            self.events.security(f"Sign-in refused: {exc}", actor=email, ip=ip)
            raise
        if row.get("totp_secret"):
            code = "".join((code or "").split())
            if not code:
                raise AuthError("Enter the 6-digit code from your authenticator app", 401)
            if not self._totp_ok(row, code):
                self._sign_in_failed(email, ip, "wrong two-step code")
                raise AuthError("The code is not correct, or was already used. Wait for the next code and try again.", 401)
        self._clear_limit("login-account", email)
        token = secrets.token_urlsafe(32)
        now = _now()
        self.store.insert("sessions", {"PartitionKey": "s", "RowKey": _digest(token), "email": email,
                                       "created": now, "last_used": now, "expires": _later(SESSION_HOURS)})
        self.store.update("users", "u", email, {"last_seen": _now()})
        self.audit(email, "auth.signin", email, {"method": "password+code" if row.get("totp_secret") else "password",
                                                 "ip": ip})
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
        last_used = s.get("last_used") or s.get("created") or ""
        idle = _admin_idle_minutes()
        if row.get("role") == "admin" and last_used < (utcnow() - dt.timedelta(minutes=idle)).isoformat():
            # Admin sessions are worth the most to a thief and are most often left open on a desk: end them
            # after a short quiet period. The person signs in again; nothing they saved is lost.
            self.store.delete("sessions", "s", s["RowKey"])
            raise AuthError(f"you were signed out after {idle} minutes without activity; sign in again")
        if last_used < (utcnow() - dt.timedelta(seconds=TOUCH_SECONDS)).isoformat():
            self.store.update("sessions", "s", s["RowKey"], {"last_used": _now()})
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

    # ================================================================ two-step sign-in (authenticator app)
    def _totp_field(self, email: str) -> str:
        return f"totp|{email}"

    def _totp_secret(self, row: dict, field: str = "totp_secret") -> str:
        sealed = row.get(field) or ""
        try:
            return self.settings_store.open_secret(self._totp_field(row["RowKey"]), sealed) if sealed else ""
        except Exception:  # noqa: BLE001 - a key change makes it unreadable: fail closed (an admin can reset it)
            return ""

    def _totp_ok(self, row: dict, code: str, field: str = "totp_secret") -> bool:
        """Accept the current code or its neighbours (clock drift), each step once (no replay)."""
        secret = self._totp_secret(row, field)
        if not secret or not code.isdigit() or len(code) != 6:
            return False
        last, now = int(row.get("totp_last_step") or 0), _step()
        for step in (now - 1, now, now + 1):
            if step > last and hmac.compare_digest(code, totp_code(secret, step)):
                self.store.update("users", "u", row["RowKey"], {"totp_last_step": step})
                return True
        return False

    def _local_row(self, actor: User) -> dict:
        row = self.user_row(actor.email)
        if not row or not row.get("password_hash"):
            raise self._invalid("Two-step sign-in is for accounts that sign in with a GRC-pal password")
        return row

    def mfa_status(self, actor: User) -> dict:
        row = self.user_row(actor.email) or {}
        return {"on": bool(row.get("totp_secret")), "since": row.get("totp_since", "")}

    def mfa_start(self, actor: User) -> tuple[str, str]:
        """A new secret for the person's authenticator app. It takes effect only after mfa_confirm."""
        row = self._local_row(actor)
        secret = new_totp_secret()
        try:
            sealed = self.settings_store.seal_secret(self._totp_field(row["RowKey"]), secret)
        except NoKey as exc:
            raise self._invalid(str(exc)) from exc
        self.store.update("users", "u", row["RowKey"], {"totp_pending": sealed})
        label = quote(f"{TOTP_ISSUER}:{row['RowKey']}")
        return secret, f"otpauth://totp/{label}?secret={secret}&issuer={quote(TOTP_ISSUER)}&digits=6&period={TOTP_STEP}"

    def mfa_confirm(self, actor: User, code: str) -> None:
        row = self._local_row(actor)
        code = "".join((code or "").split())
        if not row.get("totp_pending") or not self._totp_ok(row, code, "totp_pending"):
            raise self._invalid("That code does not match. Check the time on your phone and enter the newest code.")
        self.store.update("users", "u", row["RowKey"], {"totp_secret": row["totp_pending"], "totp_pending": "",
                                                        "totp_since": _now()})
        self.audit(actor, "account.mfa_on", row["RowKey"], {})

    def mfa_off(self, actor: User, password: str) -> None:
        row = self._local_row(actor)
        try:
            ok = verify_password(row["password_hash"], password or "")
        except PasswordChecksBusy as exc:
            raise self._invalid("GRC-pal is busy. Try again in a moment.") from exc
        if not ok:
            raise self._invalid("The password is not correct")
        self.store.update("users", "u", row["RowKey"], {"totp_secret": "", "totp_pending": "", "totp_last_step": 0})
        self.audit(actor, "account.mfa_off", row["RowKey"], {})

    def reset_mfa(self, actor: User, email: str) -> None:
        """Admin: remove someone's two-step sign-in (lost phone). Their sessions end; they sign in with their
        password and can set it up again."""
        self._admin(actor)
        row = self.user_row(email)
        if not row:
            raise self._invalid("User not found")
        self.store.update("users", "u", row["RowKey"], {"totp_secret": "", "totp_pending": "", "totp_last_step": 0})
        self.revoke_sessions(row["RowKey"])
        self.audit(actor, "account.mfa_reset", row["RowKey"], {})

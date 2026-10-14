"""Local accounts (GRCPAL_AUTH_MODE=local): passwords, one-time links, sessions, auditor end dates,
break-glass admin from the CLI, and the Control owner label."""
import datetime as dt
import re

import pytest
from fastapi.testclient import TestClient

from grcpal import cli
from grcpal.portal import accounts, auth
from grcpal.portal.app import create_app
from grcpal.portal.service import Invalid
from test_portal import ADMIN, AUDITOR, CONTRIB, TODAY, make_portal

PW = "correct horse battery"
TOKEN_URL = re.compile(r"https://grc\.example\.com(/account/password/[A-Za-z0-9_-]+)")


@pytest.fixture(autouse=True)
def fast_hash(monkeypatch):
    # Real settings are deliberately slow; tests use cheap ones. The stored hash records its own settings.
    monkeypatch.setattr(accounts, "SCRYPT", {"n": 2 ** 10, "r": 8, "p": 1})


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "local")
    for var in ("GRCPAL_ENV", "GRCPAL_TENANT", "GRCPAL_BOOTSTRAP_ADMINS", "GRCPAL_PUBLIC_URL", "GRCPAL_DEV_PRINCIPAL"):
        monkeypatch.delenv(var, raising=False)
    portal = make_portal(tmp_path)
    client = TestClient(create_app(portal), base_url="https://grc.example.com")
    return portal, client


def form_csrf(html):
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    assert m, "no csrf field"
    return m.group(1)


def set_password(portal, who, password=PW):
    path = TOKEN_URL.search(portal.setup_link(ADMIN, who.email)).group(1)
    portal.set_password_with_link(path.rsplit("/", 1)[1], password)


def sign_in(client, email, password=PW, next="/"):
    client.cookies.clear()
    page = client.get(f"/login?next={next}")
    return client.post("/login", data={"email": email, "password": password, "next": next,
                                       "csrf": form_csrf(page.text)}, follow_redirects=False)


def audit_actions(portal):
    return [r["action"] for r in portal.log.recent(500)]


# ---------------------------------------------------------------- passwords
def test_password_hash_is_salted_and_verifies():
    h1, h2 = accounts.hash_password(PW), accounts.hash_password(PW)
    assert h1 != h2 and PW not in h1 and h1.startswith("scrypt$")
    assert accounts.verify_password(h1, PW) and not accounts.verify_password(h1, PW + "x")
    assert not accounts.verify_password("", PW) and not accounts.verify_password("garbage", PW)


def test_password_rules(env):
    portal, _ = env
    for bad in ("short", " " * 12, "pat@example.com!", "x" * 300):
        with pytest.raises(Invalid):
            portal.check_password(bad, "pat@example.com")
    portal.check_password("a long enough passphrase", "pat@example.com")


def test_default_auth_mode_is_local(monkeypatch):
    monkeypatch.delenv("GRCPAL_AUTH_MODE", raising=False)
    assert auth.auth_mode() == "local"


# ---------------------------------------------------------------- setup link and sign-in
def test_setup_link_sets_password_once_then_sign_in_works(env):
    portal, client = env
    url = portal.setup_link(ADMIN, CONTRIB.email)
    path = TOKEN_URL.search(url).group(1)
    assert any(path in m.text for m in portal.mailer.outbox if m.to == CONTRIB.email)  # emailed too
    page = client.get(path)
    assert page.status_code == 200 and "Choose a password" in page.text
    r = client.post(path, data={"password": PW, "confirm": PW, "csrf": form_csrf(page.text)}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    again = client.get(path)
    assert "expired or was already used" in again.text  # single use
    r = sign_in(client, CONTRIB.email)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert client.get("/work").status_code == 200
    acts = audit_actions(portal)
    assert {"account.link", "account.password_set", "auth.signin"} <= set(acts)


def test_setup_form_rejects_mismatch_and_weak_password(env):
    portal, client = env
    path = TOKEN_URL.search(portal.setup_link(ADMIN, CONTRIB.email)).group(1)
    page = client.get(path)
    r = client.post(path, data={"password": PW, "confirm": PW + "!", "csrf": form_csrf(page.text)})
    assert "do not match" in r.text
    r = client.post(path, data={"password": "short", "confirm": "short", "csrf": form_csrf(page.text)})
    assert "at least 12" in r.text
    assert not portal.user_row(CONTRIB.email).get("password_hash")


def test_expired_link_is_refused(env):
    portal, client = env
    path = TOKEN_URL.search(portal.setup_link(ADMIN, CONTRIB.email)).group(1)
    for row in portal.store.list("account_links", "l"):
        portal.store.update("account_links", "l", row["RowKey"], {"expires": "2000-01-01T00:00:00+00:00"})
    assert "expired or was already used" in client.get(path).text
    with pytest.raises(Invalid):
        portal.set_password_with_link(path.rsplit("/", 1)[1], PW)


def test_only_admins_create_links(env):
    portal, _ = env
    from grcpal.portal.service import Forbidden
    with pytest.raises(Forbidden):
        portal.setup_link(CONTRIB, AUDITOR.email)


def test_wrong_password_and_unknown_user_look_the_same(env):
    portal, client = env
    set_password(portal, CONTRIB)
    wrong = sign_in(client, CONTRIB.email, "not the password at all")
    unknown = sign_in(client, "nobody@example.com", "not the password at all")
    assert wrong.status_code == unknown.status_code == 401
    assert "Email or password is incorrect" in wrong.text and "Email or password is incorrect" in unknown.text
    assert "grcpal_session" not in wrong.headers.get("set-cookie", "")
    assert any(e["message"].startswith("Sign-in failed") for e in portal.events.search(level="security"))


def test_login_requires_csrf_and_blocks_open_redirect(env):
    portal, client = env
    set_password(portal, ADMIN)
    r = client.post("/login", data={"email": ADMIN.email, "password": PW, "next": "/", "csrf": "bad"})
    assert r.status_code == 403
    r = sign_in(client, ADMIN.email, next="//evil.example.com/x")
    assert r.headers["location"] == "/"


def test_anonymous_request_goes_to_login(env):
    _, client = env
    r = client.get("/controls", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login?next=/controls"


def test_session_cookie_flags_and_logout(env):
    portal, client = env
    set_password(portal, ADMIN)
    r = sign_in(client, ADMIN.email)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "secure" in cookie
    assert client.get("/").status_code == 200
    client.get("/logout")
    assert client.get("/", follow_redirects=False).status_code == 303
    assert "auth.signout" in audit_actions(portal)


def test_session_expires(env):
    portal, client = env
    set_password(portal, ADMIN)
    sign_in(client, ADMIN.email)
    for row in portal.store.list("sessions", "s"):
        portal.store.update("sessions", "s", row["RowKey"], {"expires": "2000-01-01T00:00:00+00:00"})
    assert client.get("/", follow_redirects=False).headers["location"].startswith("/login")


def test_disable_role_change_and_new_password_end_sessions(env):
    portal, client = env
    set_password(portal, CONTRIB)
    sign_in(client, CONTRIB.email)
    portal.set_role(ADMIN, CONTRIB.email, "admin")
    assert client.get("/work", follow_redirects=False).status_code == 303
    sign_in(client, CONTRIB.email)
    portal.set_active(ADMIN, CONTRIB.email, False)
    assert client.get("/work", follow_redirects=False).status_code == 303
    portal.set_active(ADMIN, CONTRIB.email, True)
    sign_in(client, CONTRIB.email)
    set_password(portal, CONTRIB, "another long passphrase")
    assert client.get("/work", follow_redirects=False).status_code == 303


def test_control_owner_still_sees_only_own_controls(env):
    portal, client = env
    set_password(portal, CONTRIB)
    sign_in(client, CONTRIB.email)
    assert client.get("/controls/IAM-04").status_code == 404
    assert client.get("/settings").status_code == 403


# ---------------------------------------------------------------- password reset
def test_self_service_reset_same_answer_for_unknown_email(env):
    portal, client = env
    set_password(portal, CONTRIB)
    portal.mailer.outbox.clear()
    page = client.get("/account/forgot")
    known = client.post("/account/forgot", data={"email": CONTRIB.email, "csrf": form_csrf(page.text)})
    unknown = client.post("/account/forgot", data={"email": "nobody@example.com", "csrf": form_csrf(page.text)})
    assert known.status_code == unknown.status_code == 200
    msg = "If that email belongs to an active account"
    assert msg in known.text and msg in unknown.text
    mails = list(portal.mailer.outbox)
    assert len(mails) == 1 and mails[0].to == CONTRIB.email
    path = TOKEN_URL.search(mails[0].text).group(1)
    page = client.get(path)
    client.post(path, data={"password": "brand new passphrase", "confirm": "brand new passphrase",
                            "csrf": form_csrf(page.text)})
    assert sign_in(client, CONTRIB.email, "brand new passphrase").status_code == 303
    assert not portal.store.list("account_links", "l")  # used link is gone


def test_self_service_reset_link_is_short_lived(env):
    portal, _ = env
    portal.request_reset(CONTRIB.email)
    row = portal.store.list("account_links", "l")[0]
    expires = dt.datetime.fromisoformat(row["expires"])
    assert expires - dt.datetime.now(dt.timezone.utc) <= dt.timedelta(hours=1, minutes=1)


def test_admin_break_glass_reset_shows_link(env):
    portal, client = env
    set_password(portal, ADMIN)
    set_password(portal, CONTRIB)
    sign_in(client, ADMIN.email)
    page = client.get("/users")
    r = client.post(f"/users/{CONTRIB.email}/link", data={"csrf": form_csrf(page.text)})
    assert r.status_code == 200 and TOKEN_URL.search(r.text)
    assert "account.link" in audit_actions(portal)


def test_adding_a_user_shows_their_setup_link(env):
    portal, client = env
    set_password(portal, ADMIN)
    sign_in(client, ADMIN.email)
    page = client.get("/users")
    assert "Control owner" in page.text
    r = client.post("/users", data={"email": "new@example.com", "name": "New", "role": "contributor",
                                    "csrf": form_csrf(page.text)})
    assert r.status_code == 200 and TOKEN_URL.search(r.text) and "new@example.com" in r.text


# ---------------------------------------------------------------- auditor end date
def test_auditor_gets_default_end_date_and_is_refused_after_it(env):
    portal, client = env
    row = portal.add_user(ADMIN, "cpa2@firm.example", "CPA", "auditor")
    assert row["access_until"] == (TODAY + dt.timedelta(days=90)).isoformat()
    with pytest.raises(Invalid):
        portal.add_user(ADMIN, "cpa3@firm.example", "CPA", "auditor", access_until="2001-01-01")
    portal.set_access_until(ADMIN, AUDITOR.email, TODAY.isoformat())
    set_password(portal, AUDITOR)
    assert sign_in(client, AUDITOR.email).status_code == 303
    assert client.get("/controls").status_code == 200  # last day still works
    portal._today = TODAY + dt.timedelta(days=1)
    r = client.get("/controls")
    assert r.status_code == 403 and "access ended" in r.text
    assert sign_in(client, AUDITOR.email).status_code == 403
    assert "user.access_until" in audit_actions(portal)


def test_end_date_only_for_auditors_and_cleared_on_role_change(env):
    portal, _ = env
    with pytest.raises(Invalid):
        portal.set_access_until(ADMIN, CONTRIB.email, TODAY.isoformat())
    portal.set_access_until(ADMIN, AUDITOR.email, TODAY.isoformat())
    portal.set_role(ADMIN, AUDITOR.email, "contributor")
    assert not portal.user_row(AUDITOR.email).get("access_until")
    portal.set_role(ADMIN, AUDITOR.email, "auditor")
    assert portal.user_row(AUDITOR.email)["access_until"] == (TODAY + dt.timedelta(days=90)).isoformat()


# ---------------------------------------------------------------- break-glass admin from the CLI
def test_cli_create_admin_is_local_only(env, tmp_path, monkeypatch):
    portal, client = env
    db = tmp_path / "cli.db"
    monkeypatch.setenv("GRCPAL_SQLITE", str(db))
    monkeypatch.setenv("GRCPAL_TENANT", "acme")
    answers = iter([PW, PW])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    assert cli.main(["--evidence", str(tmp_path / "ev"), "create-admin", "root@example.com", "--name", "Root"]) == 0
    from grcpal.portal.store import from_env
    row = from_env().get("users", "u", "root@example.com")
    assert row["role"] == "admin" and row["local_only"] and accounts.verify_password(row["password_hash"], PW)
    assert PW not in str(row)  # only the hash is stored


def test_cli_create_admin_refuses_mismatch(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_SQLITE", str(tmp_path / "cli.db"))
    answers = iter([PW, PW + "x"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    with pytest.raises(SystemExit):
        cli.main(["--evidence", str(tmp_path / "ev"), "create-admin", "root@example.com"])


# ---------------------------------------------------------------- pages
@pytest.mark.parametrize("path", ["/login", "/account/forgot", "/account/password/not-a-real-token"])
def test_public_account_pages_render_with_strict_csp(env, path):
    _, client = env
    r = client.get(path)
    assert r.status_code == 200 and "Content-Security-Policy" in r.headers
    assert 'style="' not in r.text and "<script>" not in r.text and "onclick" not in r.text


def test_login_page_explains_first_admin_when_nobody_can_sign_in(env):
    _, client = env
    assert "grcpal create-admin" in client.get("/login").text

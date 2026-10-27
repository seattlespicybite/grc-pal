"""Local accounts (GRCPAL_AUTH_MODE=local): passwords, one-time links, sessions, auditor end dates,
break-glass admin from the CLI, and the Control owner label."""
import base64
import datetime as dt
import json
import re

import pytest
from fastapi.testclient import TestClient

from grcpal import cli
from grcpal.portal import accounts, auth
from grcpal.portal.app import create_app
from grcpal.portal.service import Invalid
from test_portal import ADMIN, ADMIN2, AUDITOR, CONTRIB, HR, TODAY, make_portal

PW = "correct horse battery"
# Password links carry their token after "#", so it never reaches the server's request line or logs.
TOKEN_URL = re.compile(r"https://grc\.example\.com/account/password#([A-Za-z0-9_-]+)")


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
    token = TOKEN_URL.search(portal.setup_link(ADMIN, who.email)).group(1)
    portal.set_password_with_link(portal.open_link(token), password)


def open_link(client, token):
    """What the browser does with an emailed link: the page posts the token from the fragment once and gets the
    password form (bound to a short-lived cookie)."""
    page = client.get("/account/password")
    return client.post("/account/password/open", data={"token": token, "csrf": form_csrf(page.text)})


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
    token = TOKEN_URL.search(url).group(1)
    assert any(url in m.text for m in portal.mailer.outbox if m.to == CONTRIB.email)  # emailed too
    page = open_link(client, token)
    assert page.status_code == 200 and "Choose a password" in page.text
    r = client.post("/account/password", data={"password": PW, "confirm": PW, "csrf": form_csrf(page.text)},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    again = open_link(client, token)
    assert "expired or was already used" in again.text  # single use
    r = sign_in(client, CONTRIB.email)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert client.get("/work").status_code == 200
    acts = audit_actions(portal)
    assert {"account.link", "account.password_set", "auth.signin"} <= set(acts)


def test_setup_form_rejects_mismatch_and_weak_password(env):
    portal, client = env
    page = open_link(client, TOKEN_URL.search(portal.setup_link(ADMIN, CONTRIB.email)).group(1))
    r = client.post("/account/password", data={"password": PW, "confirm": PW + "!", "csrf": form_csrf(page.text)})
    assert "do not match" in r.text
    r = client.post("/account/password", data={"password": "short", "confirm": "short", "csrf": form_csrf(page.text)})
    assert "at least 12" in r.text
    assert not portal.user_row(CONTRIB.email).get("password_hash")


def test_expired_link_is_refused(env):
    portal, client = env
    token = TOKEN_URL.search(portal.setup_link(ADMIN, CONTRIB.email)).group(1)
    for row in portal.store.list("account_links", "l"):
        portal.store.update("account_links", "l", row["RowKey"], {"expires": "2000-01-01T00:00:00+00:00"})
    assert "expired or was already used" in open_link(client, token).text
    with pytest.raises(Invalid):
        portal.set_password_with_link(token, PW)


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
    home = client.get("/")
    assert home.status_code == 200
    client.post("/logout", data={"csrf": form_csrf(home.text)})
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
    page = open_link(client, TOKEN_URL.search(mails[0].text).group(1))
    client.post("/account/password", data={"password": "brand new passphrase", "confirm": "brand new passphrase",
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
@pytest.mark.parametrize("path", ["/login", "/account/forgot", "/account/password"])
def test_public_account_pages_render_with_strict_csp(env, path):
    _, client = env
    r = client.get(path)
    assert r.status_code == 200 and "Content-Security-Policy" in r.headers
    assert 'style="' not in r.text and "<script>" not in r.text and "onclick" not in r.text


def test_login_page_explains_first_admin_when_nobody_can_sign_in(env):
    _, client = env
    assert "grcpal create-admin" in client.get("/login").text


def test_sign_in_records_the_real_client_ip_not_a_forged_one(env, monkeypatch):
    portal, client = env
    set_password(portal, CONTRIB)
    monkeypatch.setenv("GRCPAL_TRUSTED_PROXY_HOPS", "1")
    client.cookies.clear()
    page = client.get("/login")
    r = client.post("/login", data={"email": CONTRIB.email, "password": PW, "next": "/", "csrf": form_csrf(page.text)},
                    headers={"X-Forwarded-For": "6.6.6.6, 203.0.113.9"}, follow_redirects=False)
    assert r.status_code == 303
    signin = [x for x in portal.log.recent(50) if x["action"] == "auth.signin"][0]
    assert signin["detail"]["ip"] == "203.0.113.9"


# ---------------------------------------------------------------- session hygiene (hardening batch B5)
SECRET = "test-secret-0123456789abcdef0123456789abcdef"


@pytest.fixture()
def prod(env, monkeypatch):
    """The same local-account portal, run as production (GRCPAL_ENV=production)."""
    portal, _ = env
    monkeypatch.setenv("GRCPAL_ENV", "production")
    monkeypatch.setenv("GRCPAL_SECRET", SECRET)
    return portal, TestClient(create_app(portal), base_url="https://grc.example.com")


def set_cookies(response):
    return [v for k, v in response.headers.multi_items() if k == "set-cookie"]


def test_production_cookies_are_secure_and_host_prefixed(prod):
    portal, client = prod
    set_password(portal, ADMIN)
    # even when the app sees plain http (a proxy that does not pass the scheme), production cookies are Secure
    plain = TestClient(client.app, base_url="http://grc.example.com")
    r = sign_in(plain, ADMIN.email)
    cookie = next(c for c in set_cookies(r) if "grcpal_session" in c)
    assert cookie.startswith("__Host-grcpal_session=")
    low = cookie.lower()
    assert "secure" in low and "httponly" in low and "path=/" in low and "domain" not in low
    sign_in(client, ADMIN.email)
    assert client.get("/").status_code == 200
    view = client.get("/view", params={"f": "all", "next": "/"}, follow_redirects=False)
    assert any(c.startswith("__Host-grcpal_view=all;") and "secure" in c.lower() for c in set_cookies(view))


def test_outside_production_cookie_names_do_not_change(env):
    portal, client = env
    set_password(portal, ADMIN)
    assert any(c.startswith("grcpal_session=") for c in set_cookies(sign_in(client, ADMIN.email)))


def test_old_cookie_names_are_accepted_once_and_reissued(prod):
    # Sessions started before the upgrade keep working: the old cookie is read once, then replaced.
    portal, client = prod
    set_password(portal, ADMIN)
    token = portal.sign_in(ADMIN.email, PW)
    client.cookies.clear()
    client.cookies.set("grcpal_session", token, domain="grc.example.com")
    client.cookies.set("grcpal_view", "all", domain="grc.example.com")
    r = client.get("/")
    assert r.status_code == 200
    cookies = set_cookies(r)
    assert any(c.startswith(f"__Host-grcpal_session={token};") and "secure" in c.lower() for c in cookies)
    assert any(c.startswith("__Host-grcpal_view=all;") for c in cookies)
    assert any(c.startswith("grcpal_session=") and "max-age=0" in c.lower() for c in cookies)
    assert any(c.startswith("grcpal_view=") and "max-age=0" in c.lower() for c in cookies)
    # a forged old-name cookie is no session at all
    client.cookies.clear()
    client.cookies.set("grcpal_session", "made-up", domain="grc.example.com")
    assert client.get("/", follow_redirects=False).headers["location"].startswith("/login")


def test_form_tokens_are_bound_to_the_session_and_rotate_at_sign_in(env):
    portal, client = env
    set_password(portal, ADMIN)
    sign_in(client, ADMIN.email)
    old = form_csrf(client.get("/users").text)
    sign_in(client, ADMIN.email)  # a new session: the old page's token must not work any more
    new = form_csrf(client.get("/users").text)
    assert new != old
    data = {"email": "new.person@example.com", "name": "New", "role": "contributor"}
    assert client.post("/users", data={**data, "csrf": old}, follow_redirects=False).status_code == 403
    assert client.post("/users", data={**data, "csrf": new}, follow_redirects=False).status_code == 200
    assert portal.user_row("new.person@example.com")


def test_sign_in_ends_the_session_the_browser_already_had(env):
    portal, client = env
    set_password(portal, ADMIN)
    sign_in(client, ADMIN.email)
    first = client.cookies.get("grcpal_session")
    page = client.get("/login")
    client.post("/login", data={"email": ADMIN.email, "password": PW, "next": "/", "csrf": form_csrf(page.text)},
                follow_redirects=False)
    assert client.cookies.get("grcpal_session") != first
    with pytest.raises(auth.AuthError):
        portal.session_user(first)


def _age_sessions(portal, minutes):
    when = (accounts.utcnow() - dt.timedelta(minutes=minutes)).isoformat()
    for row in portal.store.list("sessions", "s"):
        portal.store.update("sessions", "s", row["RowKey"], {"last_used": when})


def test_admin_sessions_end_after_30_idle_minutes(env):
    portal, client = env
    set_password(portal, ADMIN)
    sign_in(client, ADMIN.email)
    _age_sessions(portal, 29)
    assert client.get("/").status_code == 200       # still active, and the request counts as activity
    assert all(r["last_used"] > (accounts.utcnow() - dt.timedelta(minutes=1)).isoformat()
               for r in portal.store.list("sessions", "s"))
    _age_sessions(portal, 31)
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    assert not portal.store.list("sessions", "s")


def test_idle_limit_is_for_admins_only(env):
    portal, client = env
    set_password(portal, CONTRIB)
    sign_in(client, CONTRIB.email)
    _age_sessions(portal, 120)
    assert client.get("/").status_code == 200


def test_sign_out_is_a_post_with_a_form_token(env):
    portal, client = env
    set_password(portal, ADMIN)
    sign_in(client, ADMIN.email)
    home = client.get("/").text
    assert re.search(r'<form method="post" action="/logout"', home)
    # a link or an image on another site can no longer sign people out
    assert client.get("/logout", follow_redirects=False).status_code == 405
    assert client.post("/logout", data={"csrf": "bad"}, follow_redirects=False).status_code == 403
    assert client.get("/").status_code == 200
    r = client.post("/logout", data={"csrf": form_csrf(home)}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login?out=1"
    assert client.get("/", follow_redirects=False).status_code == 303
    assert "auth.signout" in audit_actions(portal)


# ================================================================ B6: local sign-in hardening
def _security(portal, text):
    return [e for e in portal.events.search(category="security") if text in e["message"]]


def _age_limits(portal, minutes):
    """Move every sign-in limit back in time, as if `minutes` had passed."""
    for row in portal.store.list("signinlimits", "k"):
        fields = {}
        for k in ("first", "locked_until"):
            if row.get(k):
                fields[k] = (dt.datetime.fromisoformat(row[k]) - dt.timedelta(minutes=minutes)).isoformat()
        portal.store.update("signinlimits", "k", row["RowKey"], fields)


# ---------------------------------------------------------------- reset links: token never in a URL path
def test_password_links_keep_the_token_out_of_the_url_path(env, caplog):
    import json
    import logging

    portal, client = env
    url = portal.setup_link(ADMIN, CONTRIB.email)
    token = TOKEN_URL.search(url).group(1)
    assert f"/account/password/{token}" not in url  # after "#": browsers never send it to the server
    with caplog.at_level(logging.INFO, logger="grcpal"):
        page = open_link(client, token)
        client.post("/account/password", data={"password": PW, "confirm": PW, "csrf": form_csrf(page.text)})
    assert not any(token in json.dumps(getattr(r, "fields", {})) + r.getMessage() for r in caplog.records)
    assert portal.user_row(CONTRIB.email).get("password_hash")


def test_old_style_links_still_work_without_reaching_the_form_by_path(env):
    portal, client = env
    token = TOKEN_URL.search(portal.setup_link(ADMIN, CONTRIB.email)).group(1)
    r = client.get(f"/account/password/{token}", follow_redirects=False)  # links mailed before the upgrade
    assert r.status_code == 303 and r.headers["location"] == f"/account/password#{token}"
    assert client.post(f"/account/password/{token}", data={"password": PW, "confirm": PW}).status_code in (404, 405)


def test_a_link_is_exchanged_once_for_a_short_lived_form(env):
    portal, client = env
    token = TOKEN_URL.search(portal.setup_link(ADMIN, CONTRIB.email)).group(1)
    page = open_link(client, token)
    assert "Choose a password" in page.text
    assert "expired or was already used" in open_link(client, token).text  # the emailed token is spent
    # the form it opened lasts minutes, not the link's 72 hours
    row = next(r for r in portal.store.list("account_links", "l") if r.get("stage") == "form")
    assert dt.datetime.fromisoformat(row["expires"]) - accounts.utcnow() <= dt.timedelta(minutes=16)
    portal.store.update("account_links", "l", row["RowKey"], {"expires": "2000-01-01T00:00:00+00:00"})
    r = client.post("/account/password", data={"password": PW, "confirm": PW, "csrf": form_csrf(page.text)})
    assert "expired or was already used" in r.text
    assert not portal.user_row(CONTRIB.email).get("password_hash")


def test_raw_link_tokens_cannot_set_a_password_directly(env):
    portal, _ = env
    token = TOKEN_URL.search(portal.setup_link(ADMIN, CONTRIB.email)).group(1)
    with pytest.raises(Invalid):
        portal.set_password_with_link(token, PW)  # only the form token from the exchange can


# ---------------------------------------------------------------- self-service reset
def test_admins_and_break_glass_cannot_reset_by_email(env):
    portal, client = env
    set_password(portal, ADMIN)
    portal.store.update("users", "u", HR.email, {"local_only": True})
    portal.mailer.outbox.clear()
    page = client.get("/account/forgot")
    for who in (ADMIN.email, HR.email):
        r = client.post("/account/forgot", data={"email": who, "csrf": form_csrf(page.text)})
        assert r.status_code == 200 and "If that email belongs to an active account" in r.text  # same answer
    assert not portal.mailer.outbox and not portal.store.list("account_links", "l")
    assert len(_security(portal, "Self-service password reset refused")) == 2
    assert audit_actions(portal).count("account.reset_refused") == 2


def test_reset_requests_are_limited_per_account(env):
    portal, _ = env
    portal.mailer.outbox.clear()
    for _ in range(6):
        portal.request_reset(CONTRIB.email, ip="203.0.113.5")
    assert len([m for m in portal.mailer.outbox if m.to == CONTRIB.email]) == accounts.RESET_PER_ACCOUNT
    assert _security(portal, "Password reset requests paused")
    _age_limits(portal, 61)
    portal.request_reset(CONTRIB.email, ip="203.0.113.5")
    assert len(portal.mailer.outbox) == accounts.RESET_PER_ACCOUNT + 1


def test_reset_requests_are_limited_per_address(env):
    portal, _ = env
    portal.mailer.outbox.clear()
    for i in range(accounts.RESET_PER_IP):
        portal.request_reset(f"nobody{i}@example.com", ip="203.0.113.5")
    portal.request_reset(CONTRIB.email, ip="203.0.113.5")
    assert not portal.mailer.outbox
    portal.request_reset(CONTRIB.email, ip="198.51.100.7")
    assert len(portal.mailer.outbox) == 1


def test_reset_work_runs_after_the_answer(env):
    """The page answers before the account is even looked up, so its timing says nothing about the account."""
    import threading

    portal, client = env
    portal.mailer.sync = False
    gate, done = threading.Event(), threading.Event()

    def slow(email, ip):
        gate.wait(5)
        done.set()

    portal._reset_work = slow
    page = client.get("/account/forgot")
    r = client.post("/account/forgot", data={"email": CONTRIB.email, "csrf": form_csrf(page.text)})
    assert r.status_code == 200 and not done.is_set()
    gate.set()
    assert done.wait(5)


# ---------------------------------------------------------------- sign-in limits
def test_sign_in_locks_after_repeated_failures_with_growing_waits(env, monkeypatch):
    portal, _ = env
    set_password(portal, CONTRIB)
    for _ in range(accounts.LOGIN_FREE_PER_ACCOUNT):
        with pytest.raises(auth.AuthError) as exc:
            portal.sign_in(CONTRIB.email, "wrong password here", ip="203.0.113.5")
        assert exc.value.status == 401
    with pytest.raises(auth.AuthError):
        portal.sign_in(CONTRIB.email, "wrong password here", ip="203.0.113.5")  # this one starts a 1-minute lock
    assert _security(portal, "Sign-in locked")
    checks = []
    monkeypatch.setattr(accounts, "verify_password", lambda *a: checks.append(1) or True)
    with pytest.raises(auth.AuthError) as exc:
        portal.sign_in(CONTRIB.email, PW, ip="198.51.100.7")  # the right password, even from elsewhere
    assert exc.value.status == 429 and "minute" in str(exc.value)
    assert not checks  # refused before any password hashing (no CPU spent)
    monkeypatch.undo()
    monkeypatch.setattr(accounts, "SCRYPT", {"n": 2 ** 10, "r": 8, "p": 1})
    _age_limits(portal, 2)
    with pytest.raises(auth.AuthError):
        portal.sign_in(CONTRIB.email, "wrong password here", ip="203.0.113.5")
    row = next(r for r in portal.store.list("signinlimits", "k") if r.get("kind") == "login-account")
    lock = dt.datetime.fromisoformat(row["locked_until"]) - accounts.utcnow()
    assert dt.timedelta(minutes=1, seconds=30) < lock <= dt.timedelta(minutes=2)  # the wait doubles
    _age_limits(portal, 3)
    assert portal.sign_in(CONTRIB.email, PW, ip="203.0.113.5")
    assert not any(r.get("kind") == "login-account" for r in portal.store.list("signinlimits", "k"))  # success clears


def test_lockout_looks_the_same_for_unknown_accounts(env):
    portal, client = env
    set_password(portal, CONTRIB)
    answers = []
    for email in (CONTRIB.email, "nobody@example.com"):
        for _ in range(accounts.LOGIN_FREE_PER_ACCOUNT + 1):
            sign_in(client, email, "wrong password here")
        r = sign_in(client, email, "wrong password here")
        answers.append((r.status_code, "Too many failed sign-in attempts" in r.text))
    assert answers[0] == answers[1] == (429, True)


def test_sign_in_is_limited_per_address(env):
    portal, _ = env
    set_password(portal, CONTRIB)
    for i in range(accounts.LOGIN_FREE_PER_IP + 1):
        with pytest.raises(auth.AuthError):
            portal.sign_in(f"spray{i}@example.com", "Winter2026!", ip="203.0.113.5")
    with pytest.raises(auth.AuthError) as exc:
        portal.sign_in(CONTRIB.email, PW, ip="203.0.113.5")
    assert exc.value.status == 429
    assert portal.sign_in(CONTRIB.email, PW, ip="198.51.100.7")  # other addresses are not affected


def test_password_checks_are_capped(env, monkeypatch):
    import threading

    portal, _ = env
    set_password(portal, CONTRIB)
    monkeypatch.setattr(accounts, "_CHECKS", threading.BoundedSemaphore(1))
    monkeypatch.setattr(accounts, "CHECK_WAIT_SECONDS", 0.05)
    accounts._CHECKS.acquire()  # another sign-in is hashing
    try:
        with pytest.raises(auth.AuthError) as exc:
            portal.sign_in(CONTRIB.email, PW, ip="203.0.113.5")
        assert exc.value.status == 503
    finally:
        accounts._CHECKS.release()
    assert portal.sign_in(CONTRIB.email, PW, ip="203.0.113.5")


# ---------------------------------------------------------------- two-step sign-in (TOTP)
def test_totp_matches_the_rfc_6238_test_vectors():
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert accounts.totp_code(secret, 59 // 30, digits=8) == "94287082"
    assert accounts.totp_code(secret, 1111111109 // 30, digits=8) == "07081804"
    assert accounts.totp_code(secret, 59 // 30) == "287082"


def _turn_on_mfa(client):
    page = client.get("/account/mfa")
    assert page.status_code == 200
    r = client.post("/account/mfa/start", data={"csrf": form_csrf(page.text)})
    secret = re.search(r'data-secret="([A-Z2-7]+)"', r.text).group(1)
    assert "otpauth://totp/" in r.text
    code = accounts.totp_code(secret, accounts._step())
    r = client.post("/account/mfa/confirm", data={"code": code, "csrf": form_csrf(r.text)}, follow_redirects=False)
    assert r.status_code == 303
    return secret


def test_admin_turns_on_two_step_sign_in(env):
    portal, client = env
    set_password(portal, ADMIN)
    sign_in(client, ADMIN.email)
    secret = _turn_on_mfa(client)
    row = portal.user_row(ADMIN.email)
    assert row.get("totp_secret") and secret not in json.dumps(row)  # stored encrypted
    assert "account.mfa_on" in audit_actions(portal)
    client.cookies.clear()
    page = client.get("/login")
    data = {"email": ADMIN.email, "password": PW, "next": "/", "csrf": form_csrf(page.text)}
    r = client.post("/login", data=data, follow_redirects=False)
    assert r.status_code == 401 and "6-digit code" in r.text
    r = client.post("/login", data={**data, "code": "000000" if accounts.totp_code(secret, accounts._step()) != "000000"
                                     else "111111"}, follow_redirects=False)
    assert r.status_code == 401
    code = accounts.totp_code(secret, accounts._step() + 1)  # the confirm used this step's code; the next one is new
    assert client.post("/login", data={**data, "code": code}, follow_redirects=False).status_code == 303
    client.cookies.clear()
    page = client.get("/login")
    r = client.post("/login", data={**data, "csrf": form_csrf(page.text), "code": code}, follow_redirects=False)
    assert r.status_code == 401  # a code works once


def test_wrong_codes_count_towards_the_lock(env):
    portal, client = env
    set_password(portal, ADMIN)
    sign_in(client, ADMIN.email)
    secret = _turn_on_mfa(client)
    good = accounts.totp_code(secret, accounts._step() + 1)
    bad = "123456" if good != "123456" else "654321"
    for _ in range(accounts.LOGIN_FREE_PER_ACCOUNT + 1):
        with pytest.raises(auth.AuthError):
            portal.sign_in(ADMIN.email, PW, ip="203.0.113.5", code=bad)
    with pytest.raises(auth.AuthError) as exc:
        portal.sign_in(ADMIN.email, PW, ip="203.0.113.5", code=good)
    assert exc.value.status == 429


def test_turning_two_step_off_needs_the_password(env):
    portal, client = env
    set_password(portal, ADMIN)
    sign_in(client, ADMIN.email)
    _turn_on_mfa(client)
    page = client.get("/account/mfa")
    r = client.post("/account/mfa/off", data={"password": "not my password", "csrf": form_csrf(page.text)})
    assert r.status_code == 400 and portal.user_row(ADMIN.email).get("totp_secret")
    r = client.post("/account/mfa/off", data={"password": PW, "csrf": form_csrf(page.text)}, follow_redirects=False)
    assert r.status_code == 303 and not portal.user_row(ADMIN.email).get("totp_secret")
    assert "account.mfa_off" in audit_actions(portal)


def test_admin_resets_a_lost_authenticator_and_others_cannot(env):
    from grcpal.portal.service import Forbidden

    portal, client = env
    set_password(portal, ADMIN2)
    sign_in(client, ADMIN2.email)
    _turn_on_mfa(client)
    with pytest.raises(Forbidden):
        portal.reset_mfa(CONTRIB, ADMIN2.email)
    set_password(portal, ADMIN)
    sign_in(client, ADMIN.email)
    page = client.get("/users")
    assert f"/users/{ADMIN2.email.replace('@', '%40')}/mfa" in page.text
    r = client.post(f"/users/{ADMIN2.email}/mfa", data={"csrf": form_csrf(page.text)}, follow_redirects=False)
    assert r.status_code == 303 and not portal.user_row(ADMIN2.email).get("totp_secret")
    assert "account.mfa_reset" in audit_actions(portal)


def test_break_glass_from_the_server_clears_two_step(env):
    portal, client = env
    set_password(portal, ADMIN)
    sign_in(client, ADMIN.email)
    _turn_on_mfa(client)
    portal.create_local_admin(ADMIN.email, "Admin", "a brand new break glass phrase")
    assert not portal.user_row(ADMIN.email).get("totp_secret")


# ---------------------------------------------------------------- request size (F-13)
def test_oversized_request_bodies_are_refused_before_parsing(env, monkeypatch):
    from grcpal.portal import security

    _, client = env
    monkeypatch.setattr(security, "MAX_BODY_BYTES", 2048)
    page = client.get("/account/forgot")
    big = {"email": "x" * 4096 + "@example.com", "csrf": form_csrf(page.text)}
    r = client.post("/account/forgot", data=big)
    assert r.status_code == 413 and "Content-Security-Policy" in r.headers

    def chunks():  # no Content-Length: counted while it streams
        for _ in range(8):
            yield b"email=" + b"x" * 1024

    r = client.post("/account/forgot", content=chunks(), headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413
    assert client.post("/account/forgot", data={"email": CONTRIB.email, "csrf": form_csrf(page.text)}).status_code == 200


# ================================================================ break-glass on Azure (deploy/azure/breakglass.sh)
GLASS = "breakglass@example.com"
GLASS_PW = "a long break glass sentence"
FIXED_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def _until(hours):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture()
def azure_glass(env, monkeypatch):
    """The armed break-glass revision: local sign-in on Azure Container Apps, window open for 2 hours, and a
    break-glass account with two-step sign-in (as breakglass.sh set-password leaves it)."""
    portal, client = env
    monkeypatch.setenv("CONTAINER_APP_NAME", "grcpal-acme")
    monkeypatch.setenv("GRCPAL_BREAK_GLASS_UNTIL", _until(2))
    monkeypatch.setattr(accounts, "new_totp_secret", lambda: FIXED_SECRET)
    portal.create_local_admin(GLASS, "Break glass", GLASS_PW)
    who = auth.User(email=GLASS, name="Break glass", role="admin")
    portal.mfa_start(who)
    portal.mfa_confirm(who, accounts.totp_code(FIXED_SECRET, accounts._step()))
    return portal, client


def _glass_code(offset=1):
    return accounts.totp_code(FIXED_SECRET, accounts._step() + offset)


@pytest.mark.parametrize("value,open_", [
    (None, False), ("", False), ("tomorrow", False), ("2026-01-01T00:00:00", False),  # no time zone
    ("past", False), ("too-far", False), ("ok", True)])
def test_break_glass_window_fails_closed(monkeypatch, value, open_):
    raw = {"past": _until(-1), "too-far": _until(auth.BREAK_GLASS_MAX_HOURS + 1), "ok": _until(2)}.get(value, value)
    if raw is None:
        monkeypatch.delenv("GRCPAL_BREAK_GLASS_UNTIL", raising=False)
    else:
        monkeypatch.setenv("GRCPAL_BREAK_GLASS_UNTIL", raw)
    assert auth.break_glass_open() is open_


def test_break_glass_mode_is_only_local_sign_in_on_azure(monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "local")
    for var in auth.EASYAUTH_PLATFORM_VARS:
        monkeypatch.delenv(var, raising=False)
    assert not auth.break_glass_mode()  # a VM: ordinary local accounts
    monkeypatch.setenv("CONTAINER_APP_NAME", "grcpal-acme")
    assert auth.break_glass_mode()
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "easyauth")
    assert not auth.break_glass_mode()


def test_break_glass_sign_in_works_and_is_loud(azure_glass):
    portal, client = azure_glass
    portal.mailer.outbox.clear()
    token = portal.sign_in(GLASS, GLASS_PW, ip="203.0.113.7", code=_glass_code())
    assert portal.session_user(token).email == GLASS
    signin = [x for x in portal.log.recent(50) if x["action"] == "auth.signin"][0]
    assert signin["detail"] == {"method": "password+code", "ip": "203.0.113.7", "break_glass": True}
    assert _security(portal, "Break-glass sign-in")
    alerted = {m.to for m in portal.mailer.outbox if "break-glass sign-in" in m.subject}
    assert {ADMIN.email, ADMIN2.email, GLASS} <= alerted  # every admin, the person signing in included


def test_break_glass_sign_in_through_the_login_page(azure_glass):
    portal, client = azure_glass
    page = client.get("/login")
    r = client.post("/login", data={"email": GLASS, "password": GLASS_PW, "code": _glass_code(), "next": "/",
                                    "csrf": form_csrf(page.text)}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/users").status_code == 200


def test_only_the_break_glass_account_signs_in_on_azure(azure_glass):
    portal, _ = azure_glass
    set_password(portal, ADMIN)  # an ordinary admin who also has a password
    with pytest.raises(auth.AuthError) as exc:
        portal.sign_in(ADMIN.email, PW, ip="203.0.113.7")
    assert exc.value.status == 401 and "incorrect" in str(exc.value)  # same answer as a wrong password
    assert _security(portal, "not the break-glass account")


def test_break_glass_needs_two_step_on_azure(azure_glass):
    portal, _ = azure_glass
    portal.create_local_admin(GLASS, "Break glass", GLASS_PW)  # a password reset on the server clears two-step
    with pytest.raises(auth.AuthError) as exc:
        portal.sign_in(GLASS, GLASS_PW, ip="203.0.113.7")
    assert exc.value.status == 403 and "two-step" in str(exc.value)


def test_closed_window_refuses_sign_in_and_ends_sessions(azure_glass, monkeypatch):
    portal, _ = azure_glass
    token = portal.sign_in(GLASS, GLASS_PW, ip="203.0.113.7", code=_glass_code())
    monkeypatch.setenv("GRCPAL_BREAK_GLASS_UNTIL", _until(-0.01))  # the closing time passed, nobody disarmed
    with pytest.raises(auth.AuthError):
        portal.session_user(token)
    with pytest.raises(auth.AuthError) as exc:
        portal.sign_in(GLASS, GLASS_PW, ip="203.0.113.7", code=_glass_code(2))
    assert exc.value.status == 403 and "closed" in str(exc.value)


def test_no_reset_emails_on_azure(azure_glass):
    portal, client = azure_glass
    portal.mailer.outbox.clear()
    page = client.get("/account/forgot")
    r = client.post("/account/forgot", data={"email": CONTRIB.email, "csrf": form_csrf(page.text)})
    assert r.status_code == 200 and not portal.mailer.outbox
    assert _security(portal, "break-glass sign-in only")


def test_cli_create_admin_on_azure_sets_up_two_step(env, tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_SQLITE", str(tmp_path / "cli.db"))
    monkeypatch.setenv("GRCPAL_TENANT", "acme")
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", base64.b64encode(b"k" * 32).decode())
    monkeypatch.setenv("CONTAINER_APP_NAME", "grcpal-acme")
    monkeypatch.setattr(accounts, "new_totp_secret", lambda: FIXED_SECRET)
    answers = iter([GLASS_PW, GLASS_PW])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    good = accounts.totp_code(FIXED_SECRET, accounts._step())
    codes = iter(["000001" if good != "000001" else "000002", good])  # one typo, then the right code
    monkeypatch.setattr("builtins.input", lambda prompt="": next(codes))
    assert cli.main(["--evidence", str(tmp_path / "ev"), "create-admin", GLASS]) == 0
    from grcpal.portal.store import from_env
    row = from_env().get("users", "u", GLASS)
    assert row["local_only"] and row["totp_secret"] and FIXED_SECRET not in json.dumps(row)


def test_forged_identity_header_is_ignored_while_armed(azure_glass):
    # Easy Auth is off while armed, so a caller can send X-MS-CLIENT-PRINCIPAL; local mode never reads it.
    _, client = azure_glass
    claims = {"claims": [{"typ": "preferred_username", "val": ADMIN.email}, {"typ": "tid", "val": "tenant-a"}]}
    client.cookies.clear()
    r = client.get("/users", headers={"X-MS-CLIENT-PRINCIPAL": base64.b64encode(json.dumps(claims).encode()).decode()},
                   follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")

"""Sign in with Microsoft in local mode (grcpal/portal/msauth.py, accounts.ms_begin/ms_finish, routes_accounts).

Microsoft is simulated: an RSA key plays Microsoft's token signing key (published as a JWKS), and the token
endpoint is replaced by a function that checks what GRC-pal sends and returns an ID token signed with that key."""
import base64
import hashlib
import json
import re
import time
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from grcpal import cli
from grcpal.portal import accounts, msauth
from grcpal.portal.app import create_app
from grcpal.portal.service import Invalid
from test_portal import ADMIN, CONTRIB, HR, make_portal

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID_PAT = "0f0f0f0f-0000-4000-8000-000000000001"
OID_OTHER = "0f0f0f0f-0000-4000-8000-000000000002"
PEM = cli._make_ms_certificate("GRC-pal sign-in test")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class FakeMicrosoft:
    """Microsoft's token endpoint and signing keys, as far as GRC-pal can see them."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "key-1"
        self.claims = {}            # claims for the next ID token (merged over the defaults)
        self.sign_with = None       # another private key to sign with (forged token)
        self.posts = []
        self.jwks_fetches = 0
        self.nonce = ""

    def jwks(self, tenant):
        self.jwks_fetches += 1
        nums = self.key.public_key().public_numbers()
        return {self.kid: {"kid": self.kid, "kty": "RSA", "n": _b64(nums.n.to_bytes(256, "big")),
                           "e": _b64(nums.e.to_bytes(3, "big"))}}

    def id_token(self, **over) -> str:
        now = int(time.time())
        claims = {"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "aud": CLIENT, "tid": TENANT,
                  "oid": OID_PAT, "preferred_username": CONTRIB.email, "name": "Pat Example", "nonce": self.nonce,
                  "iat": now, "nbf": now, "exp": now + 3600, "ver": "2.0"}
        claims.update(self.claims)
        claims.update(over)
        claims = {k: v for k, v in claims.items() if v is not None}
        header = {"alg": "RS256", "kid": self.kid, "typ": "JWT"}
        signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}"
        sig = (self.sign_with or self.key).sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input}.{_b64(sig)}"

    def post_token(self, url, form):
        self.posts.append((url, dict(form)))
        return {"id_token": self.id_token(), "token_type": "Bearer"}


@pytest.fixture(autouse=True)
def fast_hash(monkeypatch):
    monkeypatch.setattr(accounts, "SCRYPT", {"n": 2 ** 10, "r": 8, "p": 1})


@pytest.fixture()
def ms(monkeypatch):
    fake = FakeMicrosoft()
    monkeypatch.setattr(msauth, "_post_token", fake.post_token)
    monkeypatch.setattr(msauth, "_fetch_jwks", fake.jwks)
    monkeypatch.setattr(msauth, "_JWKS", {})
    return fake


def configure(monkeypatch, on=True):
    monkeypatch.setenv("GRCPAL_SSO_ENABLED", "true" if on else "false")
    monkeypatch.setenv("GRCPAL_SSO_TENANT_ID", TENANT)
    monkeypatch.setenv("GRCPAL_SSO_CLIENT_ID", CLIENT)
    monkeypatch.setenv("GRCPAL_SSO_CERTIFICATE", PEM)


@pytest.fixture()
def env(tmp_path, monkeypatch, ms):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "local")
    for var in ("GRCPAL_ENV", "GRCPAL_TENANT", "GRCPAL_BOOTSTRAP_ADMINS", "GRCPAL_PUBLIC_URL", "GRCPAL_DEV_PRINCIPAL",
                "CONTAINER_APP_NAME", "WEBSITE_SITE_NAME"):
        monkeypatch.delenv(var, raising=False)
    configure(monkeypatch)
    portal = make_portal(tmp_path)
    portal.store.update("users", "u", CONTRIB.email, {"signin": "microsoft"})
    client = TestClient(create_app(portal), base_url="https://grc.example.com")
    return portal, client, ms


def start(client, ms, next="/"):
    """Click Sign in with Microsoft; returns Microsoft's authorize URL query (and remembers the nonce)."""
    r = client.get(f"/auth/microsoft?next={next}", follow_redirects=False)
    assert r.status_code == 303, r.text
    url = urlparse(r.headers["location"])
    q = {k: v[0] for k, v in parse_qs(url.query).items()}
    ms.nonce = q["nonce"]
    return url, q


def finish(client, q, code="the-code", **over):
    params = {"code": code, "state": q["state"], **over}
    return client.get("/auth/microsoft/callback", params=params, follow_redirects=False)


def sign_in_with_microsoft(client, ms, next="/", **claims):
    ms.claims = claims
    _, q = start(client, ms, next)
    return finish(client, q)


def signed_in_as(client) -> str:
    r = client.get("/account/mfa", follow_redirects=False)
    return "" if r.status_code != 200 else r.text


# ---------------------------------------------------------------- the request to Microsoft
def test_authorize_request_uses_pkce_state_nonce_and_always_asks_for_the_account(env):
    portal, client, ms = env
    url, q = start(client, ms)
    assert url.netloc == "login.microsoftonline.com" and url.path == f"/{TENANT}/oauth2/v2.0/authorize"
    assert q["client_id"] == CLIENT and q["response_type"] == "code" and q["response_mode"] == "query"
    assert q["redirect_uri"] == "https://grc.example.com/auth/microsoft/callback"
    assert q["code_challenge_method"] == "S256" and len(q["code_challenge"]) == 43
    assert q["prompt"] == "select_account", "no silent sign-in: the person always picks the account"
    assert q["scope"] == "openid profile"
    assert len(q["state"]) >= 30 and len(q["nonce"]) >= 30 and q["state"] != q["nonce"]
    assert "client_secret" not in q
    # the flow is kept server-side under the hash of the browser cookie, never the cookie value itself
    rows = portal.store.list("signinflows", "f")
    assert len(rows) == 1 and rows[0]["state"] == q["state"]
    cookie = client.cookies.get("grcpal_msflow")
    assert cookie and rows[0]["RowKey"] != cookie


def test_code_exchange_sends_the_pkce_verifier_and_a_certificate_assertion(env):
    portal, client, ms = env
    _, q = start(client, ms)
    assert finish(client, q).status_code == 303
    url, form = ms.posts[-1]
    assert url == f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    assert form["grant_type"] == "authorization_code" and form["code"] == "the-code"
    challenge = _b64(hashlib.sha256(form["code_verifier"].encode()).digest())
    assert challenge == q["code_challenge"]
    assert form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    assert "client_secret" not in form
    # the assertion is signed by the certificate's key and addressed to this tenant's token endpoint
    from cryptography import x509
    h64, c64, s64 = form["client_assertion"].split(".")
    pad = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731
    header, claims = json.loads(pad(h64)), json.loads(pad(c64))
    cert = x509.load_pem_x509_certificate(PEM.encode())
    cert.public_key().verify(pad(s64), f"{h64}.{c64}".encode(), padding.PKCS1v15(), hashes.SHA256())
    assert header["alg"] == "RS256" and header["x5t#S256"] == _b64(cert.fingerprint(hashes.SHA256()))
    assert claims["aud"] == url and claims["iss"] == claims["sub"] == CLIENT and claims["exp"] - claims["iat"] <= 600


# ---------------------------------------------------------------- happy path
def test_invited_person_signs_in_and_is_linked_to_their_entra_account(env):
    portal, client, ms = env
    r = sign_in_with_microsoft(client, ms, next="/work")
    assert r.status_code == 303 and r.headers["location"] == "/work"
    assert "grcpal_session" in r.headers.get("set-cookie", "")
    assert CONTRIB.email in signed_in_as(client)
    row = portal.user_row(CONTRIB.email)
    assert (row["entra_oid"], row["entra_tid"]) == (OID_PAT, TENANT)
    signin = [x for x in portal.log.recent(50) if x["action"] == "auth.signin"][0]
    assert signin["detail"]["method"] == "microsoft" and signin["detail"]["entra_oid"] == OID_PAT
    assert any(x["action"] == "user.identity_bound" for x in portal.log.recent(50))
    assert portal.store.list("signinflows", "f") == [], "the flow row is used once and removed"


def test_next_destination_cannot_leave_the_portal(env):
    _, client, ms = env
    r = sign_in_with_microsoft(client, ms, next="//evil.example/x")
    assert r.headers["location"] == "/"


def test_renamed_account_is_found_by_its_object_id(env):
    portal, client, ms = env
    assert sign_in_with_microsoft(client, ms).status_code == 303
    client.cookies.clear()
    r = sign_in_with_microsoft(client, ms, preferred_username="pat.renamed@example.com")
    assert r.status_code == 303 and CONTRIB.email in signed_in_as(client)


# ---------------------------------------------------------------- refused: the sign-in response itself
def test_wrong_state_is_refused_and_the_flow_cannot_be_retried(env):
    portal, client, ms = env
    _, q = start(client, ms)
    r = finish(client, {**q, "state": "not-the-state"})
    assert r.status_code == 400 and "expired or was already used" in r.text
    assert finish(client, q).status_code == 400, "a refused attempt also used up the flow"
    assert not ms.posts, "no code is exchanged for a response that fails the state check"


def test_callback_without_the_browser_cookie_is_refused(env):
    """Login CSRF: an attacker's code and state pushed into someone else's browser have no matching flow."""
    _, client, ms = env
    _, q = start(client, ms)
    client.cookies.clear()
    assert finish(client, q).status_code == 400 and not ms.posts


def test_replayed_callback_is_refused(env):
    _, client, ms = env
    _, q = start(client, ms)
    flow = client.cookies.get("grcpal_msflow")
    assert finish(client, q).status_code == 303
    client.cookies.clear()
    client.cookies.set("grcpal_msflow", flow)
    assert finish(client, q).status_code == 400


def test_expired_flow_is_refused(env):
    portal, client, ms = env
    _, q = start(client, ms)
    row = portal.store.list("signinflows", "f")[0]
    portal.store.update("signinflows", "f", row["RowKey"], {"expires": "2000-01-01T00:00:00+00:00"})
    assert finish(client, q).status_code == 400


def test_cancelled_at_microsoft(env):
    _, client, ms = env
    _, q = start(client, ms)
    r = client.get("/auth/microsoft/callback", params={"state": q["state"], "error": "access_denied"})
    assert r.status_code == 401 and "cancelled" in r.text and not ms.posts


@pytest.mark.parametrize("claims, why", [
    ({"aud": "99999999-bbbb-cccc-dddd-eeeeeeeeeeee"}, "another application"),
    ({"iss": "https://login.microsoftonline.com/99999999-2222-3333-4444-555555555555/v2.0"}, "another directory"),
    ({"tid": "99999999-2222-3333-4444-555555555555"}, "not in the allowed directory"),
    ({"exp": int(time.time()) - 3600}, "expired"),
    ({"nbf": int(time.time()) + 3600}, "not valid yet"),
    ({"nonce": "someone-elses-nonce"}, "does not belong to this sign-in"),
    ({"oid": None}, "no Entra object ID"),
])
def test_id_token_claims_are_checked(env, claims, why):
    portal, client, ms = env
    r = sign_in_with_microsoft(client, ms, **claims)
    assert r.status_code == 401 and why in r.text
    assert not signed_in_as(client) and "entra_oid" not in portal.user_row(CONTRIB.email)


def test_forged_signature_is_refused(env):
    _, client, ms = env
    ms.sign_with = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    r = sign_in_with_microsoft(client, ms)
    assert r.status_code == 401 and "signature is not valid" in r.text


def test_unsigned_token_is_refused(env, monkeypatch):
    _, client, ms = env
    claims = {"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "aud": CLIENT, "tid": TENANT, "oid": OID_PAT}
    unsigned = f"{_b64(json.dumps({'alg': 'none'}).encode())}.{_b64(json.dumps(claims).encode())}."
    monkeypatch.setattr(msauth, "_post_token", lambda url, form: {"id_token": unsigned})
    _, q = start(client, ms)
    r = finish(client, q)
    assert r.status_code == 401 and "RS256" in r.text


def test_new_signing_key_is_fetched_once(ms):
    cfg = {"tenant": TENANT, "client": CLIENT}
    ms.nonce = "n"
    msauth.validate_id_token(ms.id_token(), cfg, "n")
    msauth.validate_id_token(ms.id_token(), cfg, "n")
    assert ms.jwks_fetches == 1, "keys are cached"
    ms.kid = "key-2"  # Microsoft rolled its key
    msauth.validate_id_token(ms.id_token(), cfg, "n")
    assert ms.jwks_fetches == 2
    ms.kid = "key-never-published"
    with pytest.raises(msauth.SignInFailed, match="does not publish"):
        msauth.validate_id_token(ms.id_token(), cfg, "n", fetch=lambda t: {})
    assert ms.jwks_fetches == 2, "an unknown key ID refetches once per attempt (here through the given fetch)"


# ---------------------------------------------------------------- refused: who it is
def test_person_not_added_to_grcpal_is_refused(env):
    portal, client, ms = env
    r = sign_in_with_microsoft(client, ms, preferred_username="stranger@example.com", oid=OID_OTHER)
    assert r.status_code == 403 and "has not been given access" in r.text
    assert portal.user_row("stranger@example.com") is None, "no account is created by a Microsoft sign-in"


def test_password_account_cannot_sign_in_with_microsoft(env):
    """One sign-in method per person: HR has no Microsoft sign-in, so a Microsoft account with HR's email is refused."""
    _, client, ms = env
    r = sign_in_with_microsoft(client, ms, preferred_username=HR.email, oid=OID_OTHER)
    assert r.status_code == 403 and "signs in with a password" in r.text


def test_break_glass_admin_never_signs_in_with_microsoft(env):
    portal, client, ms = env
    portal.create_local_admin("glass@example.com", "Glass", "a long enough passphrase")
    portal.store.update("users", "u", "glass@example.com", {"signin": "microsoft"})  # even if someone set it
    r = sign_in_with_microsoft(client, ms, preferred_username="glass@example.com", oid=OID_OTHER)
    assert r.status_code == 403


def test_another_entra_account_with_the_same_email_is_refused(env):
    portal, client, ms = env
    assert sign_in_with_microsoft(client, ms).status_code == 303
    client.cookies.clear()
    r = sign_in_with_microsoft(client, ms, oid=OID_OTHER)
    assert r.status_code == 403 and "different Microsoft Entra account" in r.text


def test_disabled_person_is_refused(env):
    portal, client, ms = env
    portal.set_active(ADMIN, CONTRIB.email, False)
    assert sign_in_with_microsoft(client, ms).status_code == 403


def test_microsoft_person_has_no_password_way_in(env):
    portal, client, ms = env
    with pytest.raises(Invalid, match="signs in with Microsoft"):
        portal.setup_link(ADMIN, CONTRIB.email)
    portal.request_reset(CONTRIB.email, ip="203.0.113.9")
    assert not portal.mailer.outbox, "no reset email for a Microsoft account"
    page = client.get("/login")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = client.post("/login", data={"email": CONTRIB.email, "password": "anything at all here", "csrf": csrf})
    assert r.status_code == 401 and "Sign in with Microsoft above" in r.text


def test_not_offered_in_break_glass_mode_on_azure(env, monkeypatch):
    portal, client, ms = env
    monkeypatch.setenv("CONTAINER_APP_NAME", "grc")
    assert portal.ms_signin_config() == {}
    assert "Sign in with Microsoft" not in client.get("/login").text
    assert client.get("/auth/microsoft", follow_redirects=False).status_code == 404


def test_not_offered_when_not_configured(env, monkeypatch):
    portal, client, ms = env
    configure(monkeypatch, on=False)
    page = client.get("/login").text
    assert "Sign in with Microsoft" not in page and 'name="password"' in page
    assert client.get("/auth/microsoft", follow_redirects=False).status_code == 404
    monkeypatch.setenv("GRCPAL_SSO_ENABLED", "true")
    monkeypatch.setenv("GRCPAL_SSO_TENANT_ID", "not-a-guid")
    assert not portal.ms_signin_ready()


def test_login_page_shows_the_button_and_keeps_password_sign_in_behind_it(env):
    _, client, _ = env
    page = client.get("/login?next=/work").text
    assert 'href="/auth/microsoft?next=/work"' in page or 'href="/auth/microsoft?next=%2Fwork"' in page
    assert "<details" in page and "Sign in with a password instead" in page
    assert 'http-equiv="refresh"' not in page, "no automatic redirect to Microsoft"


# ---------------------------------------------------------------- admins choose the method
def test_admin_adds_a_microsoft_person_without_a_password_link(env):
    portal, client, ms = env
    row = portal.add_user(ADMIN, "new.person@example.com", "New", "contributor", signin="microsoft")
    assert row["signin"] == "microsoft" and not row.get("password_hash")
    assert any(x["action"] == "user.signin_method" for x in portal.log.recent(20))


def test_microsoft_method_needs_sign_in_set_up(env, monkeypatch):
    portal, _, _ = env
    configure(monkeypatch, on=False)
    with pytest.raises(Invalid, match="Set up Sign in with Microsoft"):
        portal.add_user(ADMIN, "new.person@example.com", "New", "contributor", signin="microsoft")
    with pytest.raises(Invalid, match="Set up Sign in with Microsoft"):
        portal.set_signin_method(ADMIN, HR.email, "microsoft")


def test_switching_to_microsoft_removes_the_password_and_ends_sessions(env):
    portal, client, ms = env
    token = re.search(r"#([A-Za-z0-9_-]+)", portal.setup_link(ADMIN, HR.email)).group(1)
    portal.set_password_with_link(portal.open_link(token), "a long enough passphrase")
    session = portal.sign_in(HR.email, "a long enough passphrase")
    portal.set_signin_method(ADMIN, HR.email, "microsoft")
    row = portal.user_row(HR.email)
    assert row["signin"] == "microsoft" and not row["password_hash"]
    with pytest.raises(Exception):
        portal.session_user(session)
    audit = [x for x in portal.log.recent(20) if x["action"] == "user.signin_method"][0]
    assert audit["detail"] == {"from": "password", "to": "microsoft"} and audit["actor"] == ADMIN.email


def test_switching_back_to_password_removes_the_entra_link(env):
    portal, client, ms = env
    assert sign_in_with_microsoft(client, ms).status_code == 303
    portal.set_signin_method(ADMIN, CONTRIB.email, "password")
    row = portal.user_row(CONTRIB.email)
    assert not row["signin"] and not row["entra_oid"]
    assert not signed_in_as(client), "their Microsoft session ended"


def test_break_glass_admin_cannot_be_switched(env):
    portal, _, _ = env
    portal.create_local_admin("glass@example.com", "Glass", "a long enough passphrase")
    with pytest.raises(Invalid, match="break-glass"):
        portal.set_signin_method(ADMIN, "glass@example.com", "microsoft")


def test_only_admins_change_sign_in_methods(env):
    portal, _, _ = env
    with pytest.raises(Exception):
        portal.set_signin_method(CONTRIB, HR.email, "microsoft")


def test_users_page_offers_the_method(env):
    portal, client, ms = env
    token = re.search(r"#([A-Za-z0-9_-]+)", portal.setup_link(ADMIN, ADMIN.email)).group(1)
    portal.set_password_with_link(portal.open_link(token), "a long enough passphrase")
    page = client.get("/login")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    client.post("/login", data={"email": ADMIN.email, "password": "a long enough passphrase", "csrf": csrf})
    html = client.get("/users").text
    assert 'name="signin"' in html and "Signs in with Microsoft" in html and "Use a password instead" in html


# ---------------------------------------------------------------- configuration test
def test_connection_test_checks_settings_certificate_and_app(env, monkeypatch):
    portal, _, ms = env
    from grcpal.integrations import TestContext, validate
    result = validate("signin", portal.settings, TestContext(portal, ADMIN))
    names = {c["name"]: c["ok"] for c in result["checks"]}
    assert names == {"Settings": True, "Certificate and private key": True,
                     "Microsoft signing keys for this directory": True, "App registration and certificate": True}
    assert ms.posts[-1][1]["grant_type"] == "client_credentials"
    assert any("auth/microsoft/callback" in c["detail"] for c in result["checks"])


def test_problems_explain_what_is_missing(monkeypatch):
    from grcpal.settings import Settings
    monkeypatch.setenv("GRCPAL_SSO_ENABLED", "true")
    for k in ("GRCPAL_SSO_TENANT_ID", "GRCPAL_SSO_CLIENT_ID", "GRCPAL_SSO_CERTIFICATE"):
        monkeypatch.delenv(k, raising=False)
    out = msauth.problems(Settings(), "http://grc.example.com")
    assert len(out) == 4 and any("https://" in p for p in out)
    assert msauth.settings_of(Settings()) == {}

"""Sign in with Microsoft (Entra ID) for local mode: OpenID Connect authorization code flow with PKCE.

Used on a VM (GRCPAL_AUTH_MODE=local) when an admin turns on Configuration > Sign in with Microsoft. On Azure
Container Apps the platform's own sign-in (easyauth) does this job instead.

How it stays safe (each step names the attack it stops):
  * state (random, compared in constant time) and a one-time flow row tied to a browser cookie: a sign-in
    response cannot be replayed or pushed into someone else's browser (login CSRF, code injection);
  * PKCE (S256) and a client assertion signed with the app registration's certificate: a stolen authorization
    code is useless without the verifier and the private key;
  * nonce: an ID token from another sign-in cannot be swapped in;
  * the ID token is checked in full: RS256 signature against Microsoft's published keys for this tenant,
    issuer, audience (our client ID), tenant ID, expiry and not-before (5 minutes clock skew), nonce, object ID;
  * prompt=select_account: the person always picks the account; nobody is signed in silently;
  * only the token endpoint and key URL of login.microsoftonline.com are called, through checks.safe_request.

Who may sign in is decided by GRC-pal, not by Microsoft: the person must have been added on Users and roles with
"Sign in with Microsoft". The first sign-in links the account to the Entra object ID and tenant; later sign-ins
must come from the same Entra account (accounts.py, Portal.ms_finish).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import threading
import time
import uuid
from urllib.parse import urlencode

from grcpal import checks

AUTHORITY = "https://login.microsoftonline.com"
SCOPES = "openid profile"
CALLBACK_PATH = "/auth/microsoft/callback"
FLOW_COOKIE = "grcpal_msflow"
FLOW_MINUTES = 10
CLOCK_SKEW = 300
JWKS_SECONDS = 3600
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# Claims that name the account. Never the "email" claim: a user can set it in some directories (nOAuth).
_USERNAME_CLAIMS = ("preferred_username", "upn")


class SignInFailed(Exception):
    """A sign-in response that must be refused. The message is safe to show to the person."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ====================================================================== configuration
def settings_of(settings) -> dict:
    """The sign-in app registration from Configuration, or {} when sign-in with Microsoft is off or incomplete."""
    from grcpal.integrations.microsoft import normalize_pem

    if not settings.flag("GRCPAL_SSO_ENABLED"):
        return {}
    tenant = (settings.get("GRCPAL_SSO_TENANT_ID") or "").strip().lower()
    client = (settings.get("GRCPAL_SSO_CLIENT_ID") or "").strip().lower()
    pem = normalize_pem(settings.secret("GRCPAL_SSO_CERTIFICATE"))
    if not (GUID.match(tenant) and GUID.match(client) and "PRIVATE KEY" in pem and "CERTIFICATE" in pem):
        return {}
    return {"tenant": tenant, "client": client, "pem": pem}


def problems(settings, public_url: str) -> list[str]:
    """Why sign-in with Microsoft cannot work as configured (empty list: ready)."""
    from grcpal.integrations.microsoft import normalize_pem

    out = []
    if not settings.flag("GRCPAL_SSO_ENABLED"):
        return ["Sign in with Microsoft is turned off"]
    if not GUID.match((settings.get("GRCPAL_SSO_TENANT_ID") or "").strip().lower()):
        out.append("Directory (tenant) ID must be a GUID")
    if not GUID.match((settings.get("GRCPAL_SSO_CLIENT_ID") or "").strip().lower()):
        out.append("Application (client) ID must be a GUID")
    pem = normalize_pem(settings.secret("GRCPAL_SSO_CERTIFICATE"))
    if not ("PRIVATE KEY" in pem and "CERTIFICATE" in pem):
        out.append("Paste the certificate with its private key (the .pem file from grcpal ms-cert)")
    if not public_url.startswith("https://") and not re.match(r"^http://(localhost|127\.0\.0\.1)(:\d+)?$", public_url):
        out.append("GRCPAL_PUBLIC_URL must be the https:// address people use (Microsoft accepts http only for "
                   "localhost)")
    return out


def redirect_uri(public_url: str) -> str:
    return public_url.rstrip("/") + CALLBACK_PATH


# ====================================================================== step 1: send the browser to Microsoft
def new_flow() -> dict:
    verifier = secrets.token_urlsafe(48)
    return {"state": secrets.token_urlsafe(24), "nonce": secrets.token_urlsafe(24), "verifier": verifier}


def authorize_url(cfg: dict, flow: dict, redirect: str, login_hint: str = "") -> str:
    challenge = _b64url(hashlib.sha256(flow["verifier"].encode()).digest())
    query = {"client_id": cfg["client"], "response_type": "code", "redirect_uri": redirect, "response_mode": "query",
             "scope": SCOPES, "state": flow["state"], "nonce": flow["nonce"], "code_challenge": challenge,
             "code_challenge_method": "S256", "prompt": "select_account"}
    if login_hint:
        query["login_hint"] = login_hint
    return f"{AUTHORITY}/{cfg['tenant']}/oauth2/v2.0/authorize?{urlencode(query)}"


# ====================================================================== step 2: code -> ID token
def _load_cert(pem: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(pem.encode(), password=None)
    cert = x509.load_pem_x509_certificate(pem.encode())
    return key, cert


def client_assertion(cfg: dict, now: float | None = None) -> str:
    """A short-lived JWT signed with the certificate's private key: proves to Microsoft that this server holds the
    key whose public certificate is uploaded to the app registration (RFC 7523, Microsoft identity platform)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    key, cert = _load_cert(cfg["pem"])
    now = int(now or time.time())
    header = {"alg": "RS256", "typ": "JWT",
              "x5t#S256": _b64url(cert.fingerprint(hashes.SHA256())),
              # SHA-1 thumbprint: Microsoft's identifier for the certificate (a label, not a security check)
              "x5t": _b64url(hashlib.sha1(cert.public_bytes(_der()), usedforsecurity=False).digest())}
    claims = {"aud": f"{AUTHORITY}/{cfg['tenant']}/oauth2/v2.0/token", "iss": cfg["client"], "sub": cfg["client"],
              "jti": str(uuid.uuid4()), "nbf": now - 60, "iat": now, "exp": now + 300}
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}"
    sig = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(sig)}"


def _der():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def _post_token(url: str, form: dict) -> dict:
    """POST to Microsoft's token endpoint (fixed public host, no redirects followed)."""
    r = checks.safe_request("POST", url, headers={"Content-Type": "application/x-www-form-urlencoded",
                                                  "Accept": "application/json"},
                            body=urlencode(form), timeout=20, redirects=0, allow_private=False,
                            user_agent="GRC-pal/1")
    try:
        data = r.json() or {}
    except ValueError:
        data = {}
    if r.status_code != 200:
        code = str(data.get("error") or f"HTTP {r.status_code}")[:60]
        codes = data.get("error_codes") or []
        raise SignInFailed(f"Microsoft refused the sign-in ({code}{' ' + str(codes[0]) if codes else ''}). An admin "
                           "can check the app registration: redirect URI, certificate and tenant.")
    return data


def exchange_code(cfg: dict, code: str, verifier: str, redirect: str) -> str:
    data = _post_token(f"{AUTHORITY}/{cfg['tenant']}/oauth2/v2.0/token", {
        "client_id": cfg["client"], "grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
        "code_verifier": verifier, "scope": SCOPES,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion(cfg)})
    token = data.get("id_token")
    if not isinstance(token, str) or token.count(".") != 2:
        raise SignInFailed("Microsoft did not return an ID token")
    return token


# ====================================================================== step 3: check the ID token
_JWKS: dict[str, tuple[float, dict]] = {}
_JWKS_LOCK = threading.Lock()


def _fetch_jwks(tenant: str) -> dict:
    r = checks.safe_request("GET", f"{AUTHORITY}/{tenant}/discovery/v2.0/keys", timeout=20, redirects=0,
                            allow_private=False, user_agent="GRC-pal/1")
    if r.status_code != 200:
        raise SignInFailed(f"Could not read Microsoft's signing keys (HTTP {r.status_code})")
    return {k["kid"]: k for k in (r.json() or {}).get("keys", []) if k.get("kid") and k.get("kty") == "RSA"}


def signing_key(tenant: str, kid: str, fetch=None) -> dict:
    """Microsoft's public key `kid` for this tenant, cached for an hour; fetched again once for a new key ID
    (Microsoft rolls its keys)."""
    fetch = fetch or _fetch_jwks
    with _JWKS_LOCK:
        at, keys = _JWKS.get(tenant, (0.0, {}))
        if kid not in keys or time.time() - at > JWKS_SECONDS:
            keys = fetch(tenant)
            _JWKS[tenant] = (time.time(), keys)
    if kid not in keys:
        raise SignInFailed("The ID token was signed with a key Microsoft does not publish for this directory")
    return keys[kid]


def _verify_rs256(signing_input: bytes, sig: bytes, jwk: dict) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    n = int.from_bytes(_unb64url(jwk["n"]), "big")
    e = int.from_bytes(_unb64url(jwk["e"]), "big")
    try:
        rsa.RSAPublicNumbers(e, n).public_key().verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def validate_id_token(token: str, cfg: dict, nonce: str, now: float | None = None, fetch=None) -> dict:
    """Check everything that matters in the ID token; returns the claims. Raises SignInFailed."""
    try:
        h64, c64, s64 = token.split(".")
        header = json.loads(_unb64url(h64))
        claims = json.loads(_unb64url(c64))
        sig = _unb64url(s64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise SignInFailed("The ID token is malformed") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise SignInFailed("The ID token is malformed")
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise SignInFailed("The ID token is not signed the way Microsoft signs tokens (RS256)")
    if not _verify_rs256(f"{h64}.{c64}".encode(), sig, signing_key(cfg["tenant"], str(header["kid"]), fetch)):
        raise SignInFailed("The ID token signature is not valid")
    now = now or time.time()
    expected_iss = f"{AUTHORITY}/{cfg['tenant']}/v2.0"
    checks_ = (
        (claims.get("iss") == expected_iss, "The ID token comes from another directory or authority"),
        (claims.get("aud") == cfg["client"], "The ID token was issued for another application"),
        (str(claims.get("tid", "")).lower() == cfg["tenant"], "This Microsoft account is not in the allowed directory"),
        (isinstance(claims.get("exp"), (int, float)) and now <= claims["exp"] + CLOCK_SKEW, "The ID token has expired"),
        (not isinstance(claims.get("nbf"), (int, float)) or claims["nbf"] - CLOCK_SKEW <= now,
         "The ID token is not valid yet (check the server clock)"),
        (isinstance(claims.get("nonce"), str) and secrets.compare_digest(claims["nonce"], nonce),
         "The ID token does not belong to this sign-in"),
        (bool(GUID.match(str(claims.get("oid", "")).lower())), "The ID token has no Entra object ID"),
    )
    for ok, why in checks_:
        if not ok:
            raise SignInFailed(why)
    return claims


def username(claims: dict) -> str:
    return next((str(claims[k]).strip().lower() for k in _USERNAME_CLAIMS if claims.get(k)), "")

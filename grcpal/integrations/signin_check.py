"""Connection test for Sign in with Microsoft (Configuration > Sign in with Microsoft)."""
from __future__ import annotations

import datetime as dt


def validate(settings, ctx, result) -> None:
    from grcpal.portal import msauth

    if not settings.flag("GRCPAL_SSO_ENABLED"):
        result.add("Sign in with Microsoft is turned off", True)
        return
    public_url = getattr(ctx.portal, "public_url", "") if ctx and ctx.portal else ""
    for problem in msauth.problems(settings, public_url):
        result.add("Settings", False, problem)
    cfg = msauth.settings_of(settings)
    if not cfg:
        return
    result.add("Settings", True, f"Redirect URI to register: {msauth.redirect_uri(public_url)}")

    def certificate() -> str:
        _, cert = msauth._load_cert(cfg["pem"])
        left = cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)
        if left.total_seconds() <= 0:
            raise ValueError(f"the certificate expired on {cert.not_valid_after_utc:%Y-%m-%d}")
        return f"valid until {cert.not_valid_after_utc:%Y-%m-%d} ({left.days} days)"

    if result.run("Certificate and private key", certificate, hint="Run grcpal ms-cert again and paste the new .pem."):
        result.run("Microsoft signing keys for this directory",
                   lambda: f"{len(msauth._fetch_jwks(cfg['tenant']))} keys", hint="Check the tenant ID.")

        def app_registration() -> str:
            # A client-credentials request proves the client ID exists in this tenant and that the certificate's
            # public part is uploaded to it. The app has no API permissions, so the token grants nothing.
            msauth._post_token(f"{msauth.AUTHORITY}/{cfg['tenant']}/oauth2/v2.0/token", {
                "client_id": cfg["client"], "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": msauth.client_assertion(cfg)})
            return "Microsoft accepted the certificate for this app registration"

        result.run("App registration and certificate", app_registration,
                   hint="Upload the .cer file from grcpal ms-cert to the app registration (Certificates & secrets > "
                        "Certificates) and check the client ID.")

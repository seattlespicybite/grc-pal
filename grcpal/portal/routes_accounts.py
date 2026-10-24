"""Sign-in pages for local accounts (GRCPAL_AUTH_MODE=local): sign in, sign out, forgot password, the one-time
"choose a password" link and two-step sign-in. Business rules live in accounts.py (AccountsMixin on Portal).

Password links: the email carries /account/password#<token>. The part after "#" never leaves the browser, so the
token is in no request line or log. The page's script posts it once to /account/password/open, which swaps it for
a short-lived form token in the RESET_COOKIE cookie; /account/password then shows the password form."""
from __future__ import annotations

from fastapi import Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from grcpal.portal.accounts import FORM_LINK_MINUTES, PASSWORD_MIN, SESSION_COOKIE, SESSION_HOURS
from grcpal.portal.auth import AuthError, User
from grcpal.portal.observability import request_id
from grcpal.portal.security import clear_cookie, read_cookie, set_cookie
from grcpal.portal.service import Invalid

LOGIN_CSRF = "local-login"
FORGOT_CSRF = "local-forgot"
# CSRF scope label for the set-new-credential form (a fixed string, not a secret; named so code scanners
# do not mistake it for a password)
SETUP_FORM_CSRF = "local-setup-form"
RESET_COOKIE = "grcpal_reset"   # the opened link's form token (in production: __Host-grcpal_reset)


def register(app, h) -> None:
    def page(request: Request, name: str, status: int = 200, **ctx) -> HTMLResponse:
        ctx.update(request=request, user=None, org=h.p().org, request_id=request_id.get(),
                   password_min=PASSWORD_MIN)
        return h.templates.TemplateResponse(request, name, ctx, status_code=status)

    def login_page(request: Request, next: str = "/", error: str = "", status: int = 200, email: str = ""):
        return page(request, "login.html", status, next=h.safe_dest(next, "/"), error=error, email=email,
                    csrf=h.form_token(request, LOGIN_CSRF), first_admin=not h.p().any_password_set(),
                    signed_out=request.query_params.get("out") == "1",
                    done=request.query_params.get("done") == "1")

    @app.get("/login", response_class=HTMLResponse)
    def login(request: Request, next: str = "/"):
        return login_page(request, next)

    @app.post("/login")
    def login_post(request: Request, email: str = Form(""), password: str = Form(""), next: str = Form("/"),
                   code: str = Form(""), csrf: str = Form("")):
        h.check_csrf(request, LOGIN_CSRF, csrf)
        try:
            token = h.p().sign_in(email, password, ip=h.ip_of(request), code=code)
        except AuthError as exc:
            return login_page(request, next, str(exc), exc.status, email=email)
        # A new session at every sign-in: the one this browser had before (if any) ends, so a session ID planted
        # or seen before sign-in is worthless after it, and form tokens (bound to the session) rotate too.
        h.p().sign_out(read_cookie(request.cookies, SESSION_COOKIE))
        resp = RedirectResponse(h.safe_dest(next, "/"), status_code=303)
        clear_cookie(resp, request.url.scheme, SESSION_COOKIE)
        set_cookie(resp, request.url.scheme, SESSION_COOKIE, token, max_age=SESSION_HOURS * 3600)
        return resp

    @app.post("/logout")
    def logout(request: Request, csrf: str = Form("")):
        """Sign out is a form post with a token, so a link or image on another site cannot sign people out."""
        token = read_cookie(request.cookies, SESSION_COOKIE)
        try:
            user = h.p().session_user(token)
        except AuthError:
            user = None  # the session already ended: just clear the cookie
        if user:
            h.check_csrf(request, user.email, csrf)
            h.p().sign_out(token)
        resp = RedirectResponse("/login?out=1", status_code=303)
        clear_cookie(resp, request.url.scheme, SESSION_COOKIE)
        return resp

    @app.get("/account/forgot", response_class=HTMLResponse)
    def forgot(request: Request):
        return page(request, "forgot.html", csrf=h.form_token(request, FORGOT_CSRF), sent=False)

    @app.post("/account/forgot", response_class=HTMLResponse)
    def forgot_post(request: Request, email: str = Form(""), csrf: str = Form("")):
        h.check_csrf(request, FORGOT_CSRF, csrf)
        h.p().request_reset(email, ip=h.ip_of(request))
        # Same answer whether or not the account exists, so this page cannot be used to find accounts.
        return page(request, "forgot.html", csrf=h.form_token(request, FORGOT_CSRF), sent=True)

    def password_page(request: Request, stage: str, status: int = 200, row: dict | None = None, error: str = ""):
        """stage: "open" (the script reads the link from the address bar), "form" (choose a password) or "invalid"."""
        return page(request, "choose_password.html", status, csrf=h.form_token(request, SETUP_FORM_CSRF), stage=stage,
                    email=(row or {}).get("email", ""), new=(row or {}).get("purpose") == "setup", error=error,
                    minutes=FORM_LINK_MINUTES)

    def opened(request: Request) -> tuple[str, dict | None]:
        token = read_cookie(request.cookies, RESET_COOKIE)
        return token, (h.p().link_row(token) if token else None)

    @app.get("/account/password", response_class=HTMLResponse)
    def choose_password(request: Request):
        _, row = opened(request)
        return password_page(request, "form", row=row) if row else password_page(request, "open")

    @app.post("/account/password/open", response_class=HTMLResponse)
    def open_link(request: Request, token: str = Form(""), csrf: str = Form("")):
        h.check_csrf(request, SETUP_FORM_CSRF, csrf)
        token = token.strip().rsplit("#", 1)[-1].rsplit("/", 1)[-1]  # a pasted full link works too
        form = h.p().open_link(token[:200])
        if not form:
            return password_page(request, "invalid")
        resp = RedirectResponse("/account/password", status_code=303)
        set_cookie(resp, request.url.scheme, RESET_COOKIE, form, max_age=FORM_LINK_MINUTES * 60)
        return resp

    @app.post("/account/password", response_class=HTMLResponse)
    def choose_password_post(request: Request, password: str = Form(""), confirm: str = Form(""),
                             csrf: str = Form("")):
        h.check_csrf(request, SETUP_FORM_CSRF, csrf)
        token, row = opened(request)
        if not row:
            return password_page(request, "invalid")
        error = "The two passwords do not match" if password != confirm else ""
        if not error:
            try:
                h.p().set_password_with_link(token, password)
                resp = RedirectResponse("/login?done=1", status_code=303)
                clear_cookie(resp, request.url.scheme, RESET_COOKIE)
                return resp
            except Invalid as exc:
                error = str(exc)
        return password_page(request, "form", 400, row=row, error=error)

    @app.get("/account/password/{token}")
    def old_password_link(token: str):
        """Links emailed before the upgrade had the token in the path. Move it behind "#" straight away; the
        request log shows this path as /account/password/[redacted]."""
        return RedirectResponse(f"/account/password#{token[:200]}", status_code=303)

    # ------------------------------------------------------------------ two-step sign-in (authenticator app)
    def mfa_page(request: Request, user: User, status: int = 200, **ctx):
        resp = h.render(request, user, "account_mfa.html", nav_active="mfa", mfa=h.p().mfa_status(user),
                        secret=ctx.pop("secret", ""), uri=ctx.pop("uri", ""), **ctx)
        resp.status_code = status
        return resp

    @app.get("/account/mfa", response_class=HTMLResponse)
    def mfa(request: Request, user: User = Depends(h.current_user)):
        return mfa_page(request, user)

    @app.post("/account/mfa/start", response_class=HTMLResponse)
    def mfa_start(request: Request, csrf: str = Form(""), user: User = Depends(h.current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            secret, uri = h.p().mfa_start(user)
        except Invalid as exc:
            return mfa_page(request, user, 400, page_err=str(exc))
        return mfa_page(request, user, secret=secret, uri=uri)

    @app.post("/account/mfa/confirm", response_class=HTMLResponse)
    def mfa_confirm(request: Request, code: str = Form(""), csrf: str = Form(""), user: User = Depends(h.current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            h.p().mfa_confirm(user, code)
        except Invalid as exc:
            return mfa_page(request, user, 400, page_err=f"{exc} Start again to get a new key.")
        return RedirectResponse("/account/mfa?msg=Two-step+sign-in+is+on", status_code=303)

    @app.post("/account/mfa/off", response_class=HTMLResponse)
    def mfa_off(request: Request, password: str = Form(""), csrf: str = Form(""), user: User = Depends(h.current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            h.p().mfa_off(user, password)
        except Invalid as exc:
            return mfa_page(request, user, 400, page_err=str(exc))
        return RedirectResponse("/account/mfa?msg=Two-step+sign-in+is+off", status_code=303)

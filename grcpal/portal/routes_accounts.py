"""Sign-in pages for local accounts (GRCPAL_AUTH_MODE=local): sign in, sign out, forgot password and the
one-time "choose a password" link. Business rules live in accounts.py (AccountsMixin on Portal)."""
from __future__ import annotations

from fastapi import Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from grcpal.portal.accounts import PASSWORD_MIN, SESSION_COOKIE, SESSION_HOURS
from grcpal.portal.auth import AuthError
from grcpal.portal.observability import request_id
from grcpal.portal.security import csrf_token
from grcpal.portal.service import Invalid

LOGIN_CSRF = "local-login"
FORGOT_CSRF = "local-forgot"
PASSWORD_CSRF = "local-password"


def register(app, h) -> None:
    def page(request: Request, name: str, status: int = 200, **ctx) -> HTMLResponse:
        ctx.update(request=request, user=None, org=h.p().org, request_id=request_id.get(),
                   password_min=PASSWORD_MIN)
        return h.templates.TemplateResponse(request, name, ctx, status_code=status)

    def login_page(request: Request, next: str = "/", error: str = "", status: int = 200, email: str = ""):
        return page(request, "login.html", status, next=h.safe_dest(next, "/"), error=error, email=email,
                    csrf=csrf_token(LOGIN_CSRF), first_admin=not h.p().any_password_set(),
                    signed_out=request.query_params.get("out") == "1",
                    done=request.query_params.get("done") == "1")

    @app.get("/login", response_class=HTMLResponse)
    def login(request: Request, next: str = "/"):
        return login_page(request, next)

    @app.post("/login")
    def login_post(request: Request, email: str = Form(""), password: str = Form(""), next: str = Form("/"),
                   csrf: str = Form("")):
        h.check_csrf(request, LOGIN_CSRF, csrf)
        try:
            token = h.p().sign_in(email, password, ip=request.client.host if request.client else "")
        except AuthError as exc:
            return login_page(request, next, str(exc), exc.status, email=email)
        resp = RedirectResponse(h.safe_dest(next, "/"), status_code=303)
        resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_HOURS * 3600, path="/", httponly=True,
                        samesite="lax", secure=request.url.scheme == "https")
        return resp

    @app.get("/logout")
    def logout(request: Request):
        h.p().sign_out(request.cookies.get(SESSION_COOKIE))
        resp = RedirectResponse("/login?out=1", status_code=303)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.get("/account/forgot", response_class=HTMLResponse)
    def forgot(request: Request):
        return page(request, "forgot.html", csrf=csrf_token(FORGOT_CSRF), sent=False)

    @app.post("/account/forgot", response_class=HTMLResponse)
    def forgot_post(request: Request, email: str = Form(""), csrf: str = Form("")):
        h.check_csrf(request, FORGOT_CSRF, csrf)
        h.p().request_reset(email)
        # Same answer whether or not the account exists, so this page cannot be used to find accounts.
        return page(request, "forgot.html", csrf=csrf_token(FORGOT_CSRF), sent=True)

    @app.get("/account/password/{token}", response_class=HTMLResponse)
    def choose_password(request: Request, token: str):
        row = h.p().link_row(token)
        return page(request, "choose_password.html", csrf=csrf_token(PASSWORD_CSRF), valid=row is not None,
                    email=(row or {}).get("email", ""), new=(row or {}).get("purpose") == "setup", error="")

    @app.post("/account/password/{token}", response_class=HTMLResponse)
    def choose_password_post(request: Request, token: str, password: str = Form(""), confirm: str = Form(""),
                             csrf: str = Form("")):
        h.check_csrf(request, PASSWORD_CSRF, csrf)
        row = h.p().link_row(token)
        error = "The two passwords do not match" if password != confirm else ""
        if row and not error:
            try:
                h.p().set_password_with_link(token, password)
                return RedirectResponse("/login?done=1", status_code=303)
            except Invalid as exc:
                error = str(exc)
        return page(request, "choose_password.html", 400 if row else 200, csrf=csrf_token(PASSWORD_CSRF),
                    valid=row is not None, email=(row or {}).get("email", ""),
                    new=(row or {}).get("purpose") == "setup", error=error)

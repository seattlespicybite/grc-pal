"""Automation page (admins only): connections, collectors and custom checks, with Verify and Run once.
Rules, authorization and audit live in automationhub.py."""
from __future__ import annotations

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from grcpal.portal.auth import User
from grcpal.portal.automationhub import STATUS_LABELS
from grcpal.portal.service import Forbidden, Invalid


def register(app, h) -> None:
    p, current_user, render, back = h.p, h.current_user, h.render, h.back

    @app.get("/automation", response_class=HTMLResponse)
    def automation_page(request: Request, user: User = Depends(current_user)):
        h.need(user, "admin")
        return render(request, user, "automation.html", nav_active="automation", data=p().automation_overview(),
                      labels=STATUS_LABELS)

    @app.post("/automation/{name}/verify", response_class=HTMLResponse)
    async def automation_verify(request: Request, name: str, user: User = Depends(current_user)):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            result = p().verify_collector(user, name)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/automation", err=str(exc))
        return render(request, user, "automation_verify.html", nav_active="automation", r=result)

    @app.post("/automation/run")
    async def automation_run(request: Request, user: User = Depends(current_user)):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        names = [str(n) for n in form.getlist("name")][:50]
        if form.get("overdue"):
            names = p().automation_overview()["overdue"]
        try:
            job = p().run_collectors_once(user, names)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/automation", err=str(exc))
        h.invalidate()
        return RedirectResponse(f"/jobs/{job['RowKey']}", status_code=303)

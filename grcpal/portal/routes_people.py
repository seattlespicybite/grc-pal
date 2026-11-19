"""People view pages. Every rule and permission check lives in people.py; these routes only parse forms."""
from __future__ import annotations

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse

from grcpal.portal.auth import User
from grcpal.portal.service import Forbidden, Invalid


def register(app, h) -> None:
    p, current_user, render, back = h.p, h.current_user, h.render, h.back

    @app.get("/people", response_class=HTMLResponse)
    def people_page(request: Request, show: str = "", q: str = "", user: User = Depends(current_user)):
        try:
            view = p().people(user)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        show = show if show in ("problems", "joiners", "leavers") else ""
        needle = q.strip().lower()[:100]
        rows = [r for r in view["people"]
                if (show != "problems" or r["problems"]) and (show != "joiners" or r["new_joiner"])
                and (show != "leavers" or r["termination_date"])
                and (not needle or needle in r["email"] or needle in r["name"].lower())]
        return render(request, user, "people.html", nav_active="people", v=view, rows=rows, show=show, q=q[:100])

    @app.get("/people.csv")
    def people_csv(user: User = Depends(current_user)):
        try:
            data = p().people_csv(user)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        return h.attachment(f"people-{p().today.isoformat()}.csv", data)

    @app.post("/people/scope")
    async def people_scope(request: Request, user: User = Depends(current_user)):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        out = form.get("out") == "1"
        try:
            p().set_person_scope(user, form.get("email", ""), out, form.get("reason", ""))
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/people", err=str(exc))
        return back("/people", msg="Marked out of scope." if out else "Back in scope.")

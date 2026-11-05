"""Risk register pages. Every rule and permission check lives in risks.py; these routes only parse forms."""
from __future__ import annotations

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse

from grcpal.portal import risks as R
from grcpal.portal.auth import User
from grcpal.portal.service import Forbidden, Invalid

_FORM = ("title", "description", "category", "owner", "likelihood", "impact", "residual_likelihood",
         "residual_impact", "treatment", "controls", "status", "next_review", "acceptance_note", "acceptance_expires")


def register(app, h) -> None:
    p, current_user, render, back = h.p, h.current_user, h.render, h.back

    def fields(form) -> dict:
        out = {k: form.get(k, "") for k in _FORM}
        out["controls"] = form.getlist("controls") if len(form.getlist("controls")) > 1 else form.get("controls", "")
        return out

    def page_args() -> dict:
        return {"categories": R.CATEGORIES, "treatments": R.TREATMENTS, "statuses": R.STATUSES,
                "levels": R.LEVELS, "impacts": R.IMPACTS}

    @app.get("/risks", response_class=HTMLResponse)
    def risks_page(request: Request, user: User = Depends(current_user)):
        portal = p()
        try:
            rows = portal.risks(user)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        return render(request, user, "risks.html", nav_active="risks", rows=rows, summary=portal.risk_summary(user),
                      inherent=portal.risk_heatmap(rows), residual=portal.risk_heatmap(rows, residual=True),
                      to_import=portal.risk_import_preview() if user.is_admin else [], **page_args())

    @app.get("/risks.csv")
    def risks_csv(user: User = Depends(current_user)):
        try:
            data = p().export_risks(user)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        return h.attachment(f"risk-register-{p().today.isoformat()}.csv", data)

    @app.get("/risks/{rid}", response_class=HTMLResponse)
    def risk_page(request: Request, rid: str, user: User = Depends(current_user)):
        try:
            risk = p().risk(user, rid)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        return render(request, user, "risk.html", nav_active="risks", r=risk, **page_args())

    async def post(request: Request, user: User, action, ok: str, dest: str):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            result = action(form)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(dest, err=str(exc))
        return back(dest, msg=ok.format(**result) if result else ok)

    @app.post("/risks/new")
    async def risk_new(request: Request, user: User = Depends(current_user)):
        return await post(request, user, lambda f: p().create_risk(user, fields(f)),
                          "Risk {RowKey} added to the register.", "/risks")

    @app.post("/risks/import")
    async def risk_import(request: Request, user: User = Depends(current_user)):
        def run(_form):
            added = p().import_risks(user)
            return {"n": len(added)}
        return await post(request, user, run, "{n} risk(s) copied from registers/risks.yaml. Re-rate them with "
                                              "their owners, then approve the assessment.", "/risks")

    @app.post("/risks/approve")
    async def risk_approve(request: Request, user: User = Depends(current_user)):
        return await post(request, user, lambda f: p().approve_risk_assessment(user, f.get("note", "")),
                          "Risk assessment approved. The register is stored as RSK-01 evidence ({evidence_run}).",
                          "/risks")

    @app.post("/risks/{rid}")
    async def risk_update(request: Request, rid: str, user: User = Depends(current_user)):
        return await post(request, user, lambda f: p().update_risk(user, rid, fields(f), f.get("reason", "")),
                          "Risk saved. The previous version is kept in its history.", f"/risks/{rid}")

    @app.post("/risks/{rid}/review")
    async def risk_review(request: Request, rid: str, user: User = Depends(current_user)):
        return await post(request, user, lambda f: p().review_risk(user, rid, f.get("note", "")),
                          "Review recorded. Next review in 12 months.", f"/risks/{rid}")

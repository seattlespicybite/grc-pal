"""Audit request pages (/pbc: "provided by client", the auditor's request list). Every rule and permission check
lives in auditrequests.py; these routes only parse forms."""
from __future__ import annotations

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse

from grcpal.portal import auditrequests as AR
from grcpal.portal.auth import User
from grcpal.portal.service import Forbidden, Invalid


def register(app, h) -> None:
    p, current_user, render, back = h.p, h.current_user, h.render, h.back

    @app.get("/pbc", response_class=HTMLResponse)
    def pbc_page(request: Request, status: str = "", user: User = Depends(current_user)):
        portal = p()
        try:
            rows = portal.audit_requests(user, portal.active_cycle()["RowKey"])
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        status = status if status in AR.STATUSES else ""
        return render(request, user, "pbc.html", nav_active="pbc", summary=portal.audit_request_summary(rows),
                      rows=[r for r in rows if not status or r["status"] == status], f_status=status,
                      statuses=AR.STATUSES)

    @app.get("/pbc.csv")
    def pbc_csv(user: User = Depends(current_user)):
        portal = p()
        try:
            data = portal.audit_requests_csv(user, portal.active_cycle()["RowKey"])
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        return h.attachment(f"audit-requests-{portal.today.isoformat()}.csv", data)

    @app.get("/pbc/{rid}", response_class=HTMLResponse)
    def pbc_request(request: Request, rid: str, user: User = Depends(current_user)):
        try:
            r = p().audit_request(user, rid)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        return render(request, user, "pbc_request.html", nav_active="pbc", r=r, max_sample=AR.MAX_SAMPLE,
                      method=AR.SAMPLE_METHOD)

    async def post(request: Request, user: User, action, ok: str, dest: str):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            result = action(form)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(dest, err=str(exc))
        return back(f"/pbc/{result['id']}" if dest == "/pbc" and result else dest, msg=ok)

    @app.post("/pbc/new")
    async def pbc_new(request: Request, user: User = Depends(current_user)):
        return await post(request, user, lambda f: p().create_audit_request(
            user, f.get("title", ""), f.get("description", ""), f.get("controls", ""), f.get("due", "")),
            "Request added.", "/pbc")

    def dest(rid: str) -> str:
        return f"/pbc/{rid}" if AR._RID.match(rid) else "/pbc"

    @app.post("/pbc/{rid}/answer")
    async def pbc_answer(request: Request, rid: str, user: User = Depends(current_user)):
        return await post(request, user, lambda f: p().answer_audit_request(user, rid, f.get("note", ""), f.get("evidence", "")) and None,
                          "Answer recorded. The auditor can now accept or return it.", dest(rid))

    @app.post("/pbc/{rid}/decide")
    async def pbc_decide(request: Request, rid: str, user: User = Depends(current_user)):
        return await post(request, user, lambda f: p().decide_audit_request(user, rid, f.get("decision", ""), f.get("note", "")) and None,
                          "Decision recorded.", dest(rid))

    @app.post("/pbc/{rid}/comment")
    async def pbc_comment(request: Request, rid: str, user: User = Depends(current_user)):
        return await post(request, user, lambda f: p().comment_audit_request(user, rid, f.get("text", "")) and None,
                          "Comment added.", dest(rid))

    @app.post("/pbc/{rid}/sample")
    async def pbc_sample(request: Request, rid: str, user: User = Depends(current_user)):
        return await post(request, user, lambda f: p().sample_audit_request(
            user, rid, f.get("population", ""), f.get("file", ""), f.get("size", "")) and None,
            "Sample drawn and stored as evidence.", dest(rid))

"""Tests pages. Every rule and permission check lives in controltests.py; these routes only parse forms."""
from __future__ import annotations

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse

from grcpal.portal import controltests as T
from grcpal.portal.auth import User
from grcpal.portal.service import Forbidden, Invalid


def register(app, h) -> None:
    p, current_user, render, back = h.p, h.current_user, h.render, h.back

    @app.get("/tests", response_class=HTMLResponse)
    def tests_page(request: Request, status: str = "", kind: str = "", owner: str = "",
                   user: User = Depends(current_user)):
        try:
            rows = p().control_tests(user, h.health())
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        summary = p().test_summary(rows)
        shown = [t for t in rows if (not status or t["status"] == status or (status == "due_soon" and t.get("due_soon")))
                 and (not kind or t["kind"] == kind)
                 and (not owner or (t["owner"] == owner if owner != "none" else not t["owner"]))]
        return render(request, user, "tests.html", nav_active="tests", rows=shown, summary=summary,
                      f_status=status if status in T.STATUS_LABELS or status == "due_soon" else "", f_kind=kind if kind in T.KINDS else "",
                      f_owner=owner, statuses=T.STATUS_LABELS, kinds=T.KINDS,
                      owners=sorted({t["owner"] for t in rows if t["owner"]}))

    @app.get("/tests/exceptions", response_class=HTMLResponse)
    def test_exceptions_page(request: Request, user: User = Depends(current_user)):
        try:
            rows = p().list_test_exceptions(user)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        return render(request, user, "test_exceptions.html", nav_active="tests", rows=rows)

    @app.post("/tests/exceptions/{xid}/revoke")
    async def test_exception_revoke(request: Request, xid: str, user: User = Depends(current_user)):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            x = p().revoke_test_exception(user, xid, form.get("reason", ""))
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/tests/exceptions", err=str(exc))
        return back(f"/tests/{x['test']}", msg="Exception revoked. The finding counts against the test again.")

    @app.get("/tests/{tid}", response_class=HTMLResponse)
    def test_page(request: Request, tid: str, user: User = Depends(current_user)):
        try:
            test = p().control_test(user, h.health(), tid)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        people = [u for u in p().users() if u.get("active", True) and u["role"] != "auditor"] if user.is_admin else []
        return render(request, user, "test.html", nav_active="tests", t=test, people=people)

    @app.post("/tests/{tid}/owner")
    async def test_owner(request: Request, tid: str, user: User = Depends(current_user)):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            p().set_test_owner(user, h.health(), tid, form.get("owner", ""))
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(f"/tests/{tid}" if T.TEST_ID.match(tid) else "/tests", err=str(exc))
        return back(f"/tests/{tid}", msg="Owner saved.")

    @app.post("/tests/{tid}/exceptions")
    async def test_exception_new(request: Request, tid: str, user: User = Depends(current_user)):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            p().create_test_exception(user, h.health(), tid, form.get("key", ""), form.get("reason", ""),
                                      form.get("expires", ""))
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(f"/tests/{tid}" if T.TEST_ID.match(tid) else "/tests", err=str(exc))
        return back(f"/tests/{tid}", msg="Exception recorded. This finding no longer fails the test until it expires.")

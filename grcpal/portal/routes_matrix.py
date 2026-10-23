"""Control matrix pages: download the data file, import it back (preview, then apply), and the report.
Every rule and permission check lives in matrix.py; these routes only parse forms and pick the page."""
from __future__ import annotations

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse

from grcpal import xlsx
from grcpal.portal.auth import User
from grcpal.portal.service import Forbidden, Invalid


def register(app, h) -> None:
    p, current_user, render, back = h.p, h.current_user, h.render, h.back

    def readers_only(user: User) -> None:
        if not user.sees_everything:
            raise h.HTTPError(403, "Only admins and auditors can see the control matrix")

    @app.get("/matrix", response_class=HTMLResponse)
    def matrix_page(request: Request, user: User = Depends(current_user)):
        readers_only(user)
        portal = p()
        owner = portal.is_library_owner(user)
        return render(request, user, "matrix.html", nav_active="controls", is_owner=owner,
                      imports=portal.matrix_imports() if user.is_admin else [],
                      frameworks=portal.frameworks_in_use, count=len(portal.catalog.controls),
                      max_mb=xlsx.MAX_READ_BYTES // (1024 * 1024))

    @app.get("/matrix/data.xlsx")
    def matrix_data(user: User = Depends(current_user)):
        try:
            data = p().matrix_xlsx(user)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        return h.attachment(f"control-matrix-data-{p().today.isoformat()}.xlsx", data)

    @app.get("/matrix/report", response_class=HTMLResponse)
    def matrix_report(request: Request, user: User = Depends(current_user)):
        try:
            report = p().matrix_report(user, "html")
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        return render(request, user, "matrix_report.html", nav_active="controls", r=report)

    @app.get("/matrix/report.docx")
    def matrix_report_docx(user: User = Depends(current_user)):
        try:
            data = p().matrix_docx(user)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        return h.attachment(f"control-matrix-report-{p().today.isoformat()}.docx", data)

    @app.post("/matrix/import", response_class=HTMLResponse)
    async def matrix_import(request: Request, user: User = Depends(current_user)):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        upload = form.get("file")
        if upload is None or not hasattr(upload, "read"):
            return back("/matrix", err="Choose the control matrix file to upload")
        data = await upload.read(xlsx.MAX_READ_BYTES + 1)
        try:
            result = p().matrix_preview(user, upload.filename or "upload.xlsx", data)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/matrix", err=str(exc))
        return render(request, user, "matrix_preview.html", nav_active="controls", r=result)

    @app.post("/matrix/import/{import_id}/apply")
    async def matrix_apply(request: Request, import_id: str, user: User = Depends(current_user)):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            res = p().matrix_apply(user, import_id, form.get("plan", ""), form.get("reason", ""),
                                   accept_gaps=form.get("accept_gaps") == "yes")
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/matrix", err=str(exc))
        h.invalidate()
        if res["failed"]:
            return back("/matrix", err=f"Import stopped at {res['failed']['id']} after {len(res['applied'])} "
                                       f"change(s): {res['failed']['error']}. What was applied is recorded.")
        return back("/matrix", msg=f"Import applied: {len(res['applied'])} control(s) changed. "
                                   "Each change is in the control history and the audit log.")

    @app.post("/matrix/import/{import_id}/discard")
    async def matrix_discard(request: Request, import_id: str, user: User = Depends(current_user)):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            p().matrix_discard(user, import_id)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/matrix", err=str(exc))
        return back("/matrix", msg="Import discarded. Nothing was changed.")

"""Backups and Updates pages. Admins only (rules in backups.py and updates.py)."""
from __future__ import annotations

from fastapi import Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse

from grcpal.portal.auth import User
from grcpal.portal.service import Forbidden, Invalid

DOWNLOAD_HEADERS = {"Content-Security-Policy": "default-src 'none'; sandbox", "Cache-Control": "no-store"}


def register(app, h) -> None:
    p, current_user, render, back = h.p, h.current_user, h.render, h.back

    @app.get("/backups", response_class=HTMLResponse)
    def backups_page(request: Request, user: User = Depends(current_user)):
        h.need(user, "admin")
        return render(request, user, "backups.html", data=p().backups_overview(user))

    @app.post("/backups/now")
    def backups_now(request: Request, destination: str = Form(""), csrf: str = Form(""),
                    user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            out = p().backup_now(user, destination)
        except (Invalid, Forbidden) as exc:
            return back("/backups", err=str(exc))
        if out.get("queued"):
            return back("/backups", msg="Backup requested. The backup job starts it within about 15 minutes.")
        return RedirectResponse(f"/jobs/{out['RowKey']}", status_code=303)

    @app.post("/backups/schedule")
    async def backups_schedule(request: Request, user: User = Depends(current_user)):
        form = dict(await request.form())
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            p().save_backup_schedule(user, form)
        except (Invalid, Forbidden) as exc:
            return back("/backups", err=str(exc))
        return back("/backups", msg="Backup schedule saved.")

    @app.post("/backups/verify")
    def backups_verify(request: Request, destination: str = Form(""), name: str = Form(""), csrf: str = Form(""),
                       user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            job = p().verify_backup(user, destination, name)
        except (Invalid, Forbidden) as exc:
            return back("/backups", err=str(exc))
        return RedirectResponse(f"/jobs/{job['RowKey']}", status_code=303)

    @app.post("/backups/download")
    def backups_download(request: Request, destination: str = Form(""), name: str = Form(""), csrf: str = Form(""),
                         user: User = Depends(current_user)):
        # POST (with CSRF) rather than a link: a download of all data must be a deliberate action
        h.check_csrf(request, user.email, csrf)
        try:
            stream, fname = p().backup_download(user, destination, name)
        except (Invalid, Forbidden) as exc:
            return back("/backups", err=str(exc))

        def chunks():
            with stream:
                while block := stream.read(1 << 20):
                    yield block
        return StreamingResponse(chunks(), media_type="application/octet-stream",
                                 headers={"Content-Disposition": f'attachment; filename="{fname}"', **DOWNLOAD_HEADERS})

    @app.post("/backups/kit")
    def backups_kit(request: Request, csrf: str = Form(""), user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            text = p().recovery_kit(user)
        except (Invalid, Forbidden) as exc:
            return back("/backups", err=str(exc))
        return Response(text, media_type="application/json",
                        headers={"Content-Disposition": 'attachment; filename="grcpal-recovery-kit.json"',
                                 **DOWNLOAD_HEADERS})

    @app.post("/backups/restore")
    def backups_restore(request: Request, destination: str = Form(""), name: str = Form(""), confirm: str = Form(""),
                        csrf: str = Form(""), user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            p().request_restore(user, destination, name, confirm)
        except (Invalid, Forbidden) as exc:
            return back("/backups", err=str(exc))
        return back("/updates", msg=f"Restore of {name} requested. GRC-pal stops for a few minutes, takes a safety "
                                    "backup, restores, and starts again. Progress is shown here.")

    # ================================================================ updates
    @app.get("/updates", response_class=HTMLResponse)
    def updates_page(request: Request, user: User = Depends(current_user)):
        h.need(user, "admin")
        return render(request, user, "updates.html", data=p().updates_overview(user))

    @app.post("/updates/approve")
    def updates_approve(request: Request, version: str = Form(""), csrf: str = Form(""),
                        user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            p().approve_update(user, version)
        except (Invalid, Forbidden) as exc:
            return back("/updates", err=str(exc))
        return back("/updates", msg=f"Update to {version} approved. The updater starts within a minute; GRC-pal is "
                                    "unavailable for a few minutes while it switches.")

    @app.post("/updates/policy")
    def updates_policy(request: Request, auto_patch: str = Form(""), online: str = Form(""), csrf: str = Form(""),
                       user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            p().set_update_policy(user, auto_patch == "on", online == "on")
        except (Invalid, Forbidden) as exc:
            return back("/updates", err=str(exc))
        return back("/updates", msg="Update settings sent to the updater.")

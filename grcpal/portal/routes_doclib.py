"""Document library pages: the Explorer view (folders and files), one document with its template and official
versions. Every rule and permission check lives in doclib.py; these routes only parse forms and pick the page."""
from __future__ import annotations


from fastapi import Depends, Request
from fastapi.responses import HTMLResponse

from grcpal.portal import doclib
from grcpal.portal.auth import User
from grcpal.portal.security import MAX_UPLOAD_BYTES
from grcpal.portal.service import Forbidden, Invalid


def register(app, h) -> None:
    p, current_user, render, back = h.p, h.current_user, h.render, h.back

    def run(dest: str, msg: str, fn, *args):
        try:
            fn(*args)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(dest, err=str(exc))
        return back(dest, msg=msg)

    async def posted(request: Request, user: User) -> dict:
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        return form

    async def read_upload(raw) -> tuple[str, bytes] | None:
        upload = raw.get("file")
        if upload is None or not hasattr(upload, "read"):
            return None
        return upload.filename or "upload", await upload.read(MAX_UPLOAD_BYTES + 1)

    def options():
        return dict(statuses=doclib.STATUSES, changes=doclib.CHANGES, classifications=doclib.CLASSIFICATIONS,
                    kinds=doclib.KINDS, extensions=", ".join(sorted(doclib.DOC_EXTENSIONS)),
                    max_mb=MAX_UPLOAD_BYTES // (1024 * 1024))

    @app.get("/library", response_class=HTMLResponse)
    def library_page(request: Request, f: str = "", q: str = "", view: str = "docs", user: User = Depends(current_user)):
        portal = p()
        lib = portal.library(user, f, q)
        files = portal.library_files(user, f, q) if view == "files" else []
        return render(request, user, "doclib.html", nav_active="library", lib=lib, files=files, folder=f, q=q,
                      lview="files" if view == "files" else "docs", **options())

    @app.post("/library/add")
    async def library_add(request: Request, user: User = Depends(current_user)):
        raw = await posted(request, user)
        try:
            d = p().add_doc(user, str(raw.get("folder", "")), str(raw.get("number", "")), str(raw.get("title", "")),
                            str(raw.get("kind", "other")))
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/library", err=str(exc))
        return back(f"/library/{d['id']}", msg="Document added. Upload a template or the official version below.")

    @app.get("/library/{did}", response_class=HTMLResponse)
    def library_doc(request: Request, did: str, user: User = Depends(current_user)):
        portal = p()
        try:
            doc = portal.library_doc(user, did)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        folders = {f["id"]: f for f in portal.library(user)["folders"]}
        return render(request, user, "doclib_doc.html", nav_active="library", d=doc, folder=folders.get(doc["folder"]),
                      v=portal.doc_versions(user, did), **options())

    @app.post("/library/{did}/edit")
    async def library_edit(request: Request, did: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        fields = {k: str(raw.get(k, "")) for k in ("title", "owner", "approver", "classification", "next_review") if k in raw}
        return run(f"/library/{did}", "Document details saved", p().edit_doc, user, did, fields)

    @app.post("/library/{did}/official")
    async def library_official(request: Request, did: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        up = await read_upload(raw)
        if up is None:
            return back(f"/library/{did}", err="Choose a file to upload")
        return run(f"/library/{did}", "Uploaded as a draft. Move it to review and approve it when it is final.",
                   p().upload_official, user, did, up[0], up[1], str(raw.get("variant", "")),
                   str(raw.get("change", "")), str(raw.get("comment", "")))

    @app.post("/library/{did}/template")
    async def library_template(request: Request, did: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        if raw.get("action") == "restore":
            return run(f"/library/{did}", "Built-in template restored", p().restore_builtin_template, user, did)
        up = await read_upload(raw)
        if up is None:
            return back(f"/library/{did}", err="Choose a file to upload")
        return run(f"/library/{did}", "Template replaced. The previous template stays in the history.",
                   p().upload_template, user, did, up[0], up[1], str(raw.get("comment", "")))

    @app.post("/library/{did}/versions/{vid}/status")
    async def library_status(request: Request, did: str, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        return run(f"/library/{did}", "Status updated", p().set_version_status, user, did, vid,
                   str(raw.get("status", "")), str(raw.get("note", "")))

    @app.get("/library/{did}/files/{vid}")
    def library_file(did: str, vid: str, user: User = Depends(current_user)):
        try:
            name, data = p().doc_file(user, did, vid)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        return h.attachment(name, data)


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
    def library_page(request: Request, f: str = "", q: str = "", view: str = "docs", edit: int = 0,
                     user: User = Depends(current_user)):
        portal = p()
        lib = portal.library(user, f, q)
        lview = view if view in ("files", "register") and (view == "files" or user.sees_everything) else "docs"
        files = portal.library_files(user, f, q) if lview == "files" else []
        register = portal.document_register(user) if lview == "register" else []
        if register and (f or q):
            shown = {d["id"] for d in lib["docs"]}
            register = [d for d in register if d["id"] in shown]
        return render(request, user, "doclib.html", nav_active="library", lib=lib, files=files, folder=f, q=q,
                      register=register, lview=lview, editing=bool(edit and user.is_admin and lview == "docs"),
                      trash_count=sum(len(x) for x in portal.library_trash(user).values()) if user.sees_everything else 0,
                      **options())

    @app.get("/library/trash", response_class=HTMLResponse)
    def library_trash_page(request: Request, user: User = Depends(current_user)):
        try:
            trash = p().library_trash(user)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        return render(request, user, "doclib_trash.html", nav_active="library", trash=trash)

    @app.get("/library/register.xlsx")
    def library_register_xlsx(user: User = Depends(current_user)):
        try:
            data = p().register_xlsx(user)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        return h.attachment(f"document-register-{p().today.isoformat()}.xlsx", data)

    @app.post("/library/trash")
    async def library_trash_post(request: Request, user: User = Depends(current_user)):
        raw = await posted(request, user)
        ids = [str(i) for i in raw.getlist("ids")]
        try:
            done = p().trash_docs(user, ids, str(raw.get("reason", "")))
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/library?edit=1", err=str(exc))
        n = len(done)
        return back("/library", msg=f"Moved {n} document{'s' if n != 1 else ''} to the Trash. You can restore them from the Trash.")

    @app.post("/library/trash/restore")
    async def library_trash_restore(request: Request, user: User = Depends(current_user)):
        raw = await posted(request, user)
        did, vid = str(raw.get("doc", "")), str(raw.get("version", ""))
        if vid:
            own_page = raw.get("from_doc") == "1" and (doclib._ID.match(did) or did in doclib.builtin_catalog()["docs"])
            dest = f"/library/{did}#template" if own_page else "/library/trash"
            return run(dest, "Template restored", p().restore_template, user, did, vid)
        return run("/library/trash", "Document restored to the library", p().restore_doc, user, did)

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
    def library_doc(request: Request, did: str, edit: int = 0, user: User = Depends(current_user)):
        portal = p()
        try:
            doc = portal.library_doc(user, did)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        folders = {f["id"]: f for f in portal.library(user)["folders"]}
        editing = bool(edit and user.is_admin)
        people = sorted(portal.doc_people().values(), key=lambda u: ((u.get("name") or u["RowKey"]).lower())) if user.is_admin else []
        return render(request, user, "doclib_doc.html", nav_active="library", d=doc, folder=folders.get(doc["folder"]),
                      v=portal.doc_versions(user, did), editing=editing, people=people, **options())

    @app.post("/library/{did}/edit")
    async def library_edit(request: Request, did: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        fields = {k: str(raw.get(k, "")) for k in ("title", "number", "summary", "owner", "approver", "classification",
                                                   "next_review") if k in raw}
        dest = f"/library/{did}"
        if raw.get("back") == "list":  # saved from the pencil in the library list: stay in edit mode there
            folder = str(raw.get("f", ""))
            known = {fo["id"] for fo in doclib.builtin_catalog()["folders"]} | {"other"}
            dest = "/library?edit=1" + (f"&f={folder}" if folder in known else "")
        return run(dest, "Document details saved", p().edit_doc, user, did, fields)

    @app.post("/library/{did}/official")
    async def library_official(request: Request, did: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        up = await read_upload(raw)
        if up is None:
            return back(f"/library/{did}", err="Choose a file to upload")
        return run(f"/library/{did}", "Uploaded as a draft. Move it to review and approve it when it is final.",
                   p().upload_official, user, did, up[0], up[1], str(raw.get("variant", "")),
                   str(raw.get("change", "")), str(raw.get("comment", "")), str(raw.get("label", "")))

    @app.post("/library/{did}/template")
    async def library_template(request: Request, did: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        if raw.get("action") == "restore":
            return run(f"/library/{did}", "Built-in template restored", p().restore_builtin_template, user, did)
        if raw.get("action") == "rename":
            return run(f"/library/{did}#template", "Template renamed", p().rename_template, user, did,
                       str(raw.get("version", "")), str(raw.get("name", "")))
        if raw.get("action") == "remove":
            return run(f"/library/{did}#template", "Template moved to the Trash", p().remove_template, user, did,
                       str(raw.get("version", "")))
        up = await read_upload(raw)
        if up is None:
            return back(f"/library/{did}", err="Choose a file to upload")
        return run(f"/library/{did}#template", "Template uploaded and now in use. The previous one stays in the list.",
                   p().upload_template, user, did, up[0], up[1], str(raw.get("comment", "")))

    @app.post("/library/{did}/versions/{vid}/status")
    async def library_status(request: Request, did: str, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        return run(f"/library/{did}", "Status updated", p().set_version_status, user, did, vid,
                   str(raw.get("status", "")), str(raw.get("note", "")))

    @app.post("/library/{did}/versions/{vid}/label")
    async def library_label(request: Request, did: str, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        return run(f"/library/{did}", "Version number changed", p().set_version_label, user, did, vid,
                   str(raw.get("label", "")))

    @app.post("/library/{did}/versions/{vid}/approval")
    async def library_approval(request: Request, did: str, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        action, portal = str(raw.get("action", "")), p()
        if action == "send":
            return run(f"/library/{did}", "Sent for approval. The approver has an email and an item in My work.",
                       portal.request_approval, user, did, vid, str(raw.get("note", "")))
        if action == "withdraw":
            return run(f"/library/{did}", "Approval request withdrawn; the version is a draft again.",
                       portal.withdraw_approval, user, did, vid, str(raw.get("note", "")))
        if action == "reassign":
            return run(f"/library/{did}", "Approval request sent to the new approver.",
                       portal.reassign_approval, user, did, vid, str(raw.get("approver", "")))
        return back(f"/library/{did}", err="Choose an action")

    @app.get("/library/{did}/review/{vid}", response_class=HTMLResponse)
    def library_review(request: Request, did: str, vid: str, user: User = Depends(current_user)):
        try:
            view = p().approval_view(user, did, vid)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        return render(request, user, "doclib_review.html", nav_active="work", **view, **options())

    @app.post("/library/{did}/review/{vid}")
    async def library_decide(request: Request, did: str, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        decision = str(raw.get("decision", ""))
        msg = "Approved. It is now the published version." if decision == "approve" else "Sent back to the author with your reason."
        dest = "/work" if decision in ("approve", "deny") else f"/library/{did}/review/{vid}"
        try:
            p().decide_approval(user, did, vid, decision, str(raw.get("note", "")), raw.get("read") == "1")
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(f"/library/{did}/review/{vid}", err=str(exc))
        return back(dest, msg=msg)

    @app.get("/library/{did}/files/{vid}")
    def library_file(did: str, vid: str, user: User = Depends(current_user)):
        try:
            name, data = p().doc_file(user, did, vid)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        return h.attachment(name, data)


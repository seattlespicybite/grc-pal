"""Vendors pages: the register, one vendor (overview, contacts, annual review, CUECs, onboarding or
offboarding, history), the vendor form, and the security questionnaire. Every rule and permission check
lives in vendors.py; these routes only parse forms and choose the page to show."""
from __future__ import annotations

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse

from grcpal.portal import vendor_import as imod
from grcpal.portal import vendors as vmod
from grcpal.portal.auth import User
from grcpal.portal.security import MAX_UPLOAD_BYTES
from grcpal.portal.service import Forbidden, Invalid

TABS = {"overview": "Overview", "contacts": "Contacts and support", "review": "Review", "cuecs": "CUECs",
        "history": "History"}


def register(app, h) -> None:
    p, current_user, render, back = h.p, h.current_user, h.render, h.back

    def run(dest: str, msg: str, fn, *args):
        """Call a business rule; 403 when the role is wrong, otherwise back to the page with the result."""
        try:
            fn(*args)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(dest, err=str(exc))
        h.invalidate()
        return back(dest, msg=msg)

    async def posted(request: Request, user: User) -> dict:
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        return form

    def options():
        portal = p()
        return dict(tiers=vmod.TIERS, statuses=vmod.STATUSES, data_access=vmod.DATA_ACCESS, subservice=vmod.SUBSERVICE,
                    assurance=vmod.ASSURANCE, opinions=vmod.OPINIONS, contract=vmod.CONTRACT, file_kinds=vmod.FILE_KINDS,
                    cuec_status=vmod.CUEC_STATUS, review_kinds=vmod.REVIEW_KINDS, review_statuses=vmod.REVIEW_STATUSES,
                    questions=vmod.QUESTIONS, answer_labels=vmod.ANSWER_LABELS, q_types=vmod.Q_TYPES,
                    levels=vmod.ASSURANCE_LEVELS, baseline=vmod.BASELINE, baseline_status=vmod.BASELINE_STATUS,
                    questionnaires=vmod.QUESTIONNAIRES,
                    criteria=portal.catalog.criteria, max_mb=MAX_UPLOAD_BYTES // (1024 * 1024))

    # ---------------------------------------------------------------- register
    @app.get("/vendors", response_class=HTMLResponse)
    def vendors_page(request: Request, show: str = "", tier: str = "", q: str = "", user: User = Depends(current_user)):
        portal = p()
        rows = portal.vendors(user)
        live = [v for v in rows if v["status"] not in ("offboarded", "rejected")]
        counts = {"all": len(live), "overdue": sum(1 for v in live if v["health"][0] == "bad"),
                  "soon": sum(1 for v in live if v["health"][0] == "warn"),
                  "lifecycle": sum(1 for v in live if v["status"] in ("onboarding", "offboarding")),
                  "signoff": sum(1 for v in live if v["health"][1] == "Waiting for sign-off"),
                  "subservice": sum(1 for v in live if v.get("subservice") in ("carved_out", "inclusive")),
                  "closed": len(rows) - len(live)}
        shown = rows if show == "closed" else live
        shown = [v for v in shown if (show != "overdue" or v["health"][0] == "bad")
                 and (show != "soon" or v["health"][0] == "warn")
                 and (show != "lifecycle" or v["status"] in ("onboarding", "offboarding"))
                 and (show != "signoff" or v["health"][1] == "Waiting for sign-off")
                 and (show != "subservice" or v.get("subservice") in ("carved_out", "inclusive"))
                 and (show != "closed" or v["status"] in ("offboarded", "rejected"))
                 and (not tier or v.get("tier") == tier)
                 and (not q or q.lower()[:100] in f"{v['name']} {v.get('service', '')}".lower())]
        importable = portal.vendor_import_preview() if user.is_admin else []
        return render(request, user, "vendors.html", nav_active="vendors", rows=shown, counts=counts, show=show,
                      tier=tier, q=q[:100], importable=importable, **options())

    @app.post("/vendors/import")
    async def vendors_import(request: Request, user: User = Depends(current_user)):
        await posted(request, user)
        try:
            added = p().import_vendors(user)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        return back("/vendors", msg=f"Imported {len(added)} vendor{'s' if len(added) != 1 else ''} from vendors.yaml")

    # ---------------------------------------------------------------- bulk import from CSV (admins)
    @app.get("/vendors/import", response_class=HTMLResponse)
    def vendors_import_page(request: Request, user: User = Depends(current_user)):
        h.need(user, "admin")
        return render(request, user, "vendor_import.html", nav_active="vendors", columns=imod.COLUMNS,
                      imports=p().vendor_imports(), max_rows=imod.MAX_ROWS, rec=None, delta=None, **options())

    @app.get("/vendors/import/template.csv")
    def vendors_import_template(user: User = Depends(current_user)):
        h.need(user, "admin")
        return h.attachment("grcpal-vendor-import-template.csv", imod.template_csv())

    @app.post("/vendors/import/upload")
    async def vendors_import_upload(request: Request, user: User = Depends(current_user)):
        raw = await posted(request, user)
        upload = raw.get("file")
        if upload is None or not hasattr(upload, "read"):
            return back("/vendors/import", err="Choose a CSV file")
        data = await upload.read(imod.MAX_BYTES + 1)
        try:
            rec = p().vendor_import_upload(user, upload.filename or "vendors.csv", data)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/vendors/import", err=str(exc))
        return back(f"/vendors/import/{rec['RowKey']}")

    @app.get("/vendors/import/{token}", response_class=HTMLResponse)
    def vendors_import_preview(request: Request, token: str, user: User = Depends(current_user)):
        h.need(user, "admin")
        try:
            rec, delta = p().vendor_import(user, token)
        except Invalid as exc:
            return back("/vendors/import", err=str(exc))
        return render(request, user, "vendor_import.html", nav_active="vendors", columns=imod.COLUMNS, imports=[],
                      max_rows=imod.MAX_ROWS, rec=rec, delta=delta, **options())

    @app.post("/vendors/import/{token}/apply")
    async def vendors_import_apply(request: Request, token: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        rows = [int(x) for x in raw.getlist("row") if str(x).isdigit()][:imod.MAX_ROWS]
        try:
            added = p().vendor_import_apply(user, token, rows, str(raw.get("spread", "")) == "1")
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(f"/vendors/import/{token}" if len(token) == 32 else "/vendors/import", err=str(exc))
        h.invalidate()
        return back("/vendors", msg=f"Added {len(added)} vendor{'s' if len(added) != 1 else ''}. "
                    "Nothing already in the register was changed.")

    @app.post("/vendors/import/{token}/discard")
    async def vendors_import_discard(request: Request, token: str, user: User = Depends(current_user)):
        await posted(request, user)
        return run("/vendors/import", "Import discarded; nothing was added", p().vendor_import_discard, user, token)

    @app.get("/vendors/new", response_class=HTMLResponse)
    def vendor_new(request: Request, user: User = Depends(current_user)):
        h.need(user, "admin", "contributor")
        blank = {"RowKey": "new", "tier": "moderate", "subservice": "no", "data_access": [], "contract_terms": "unknown",
                 "dpa": "unknown", "assurance": "", "opinion": "", "status": "onboarding"}
        return render(request, user, "vendor_form.html", nav_active="vendors", v=blank, **options())

    @app.post("/vendors/new")
    async def vendor_create(request: Request, user: User = Depends(current_user)):
        raw = await posted(request, user)
        form = {k: str(raw.get(k, "")) for k in vmod.DETAIL_FIELDS + vmod.CONTACT_FIELDS if k in raw}
        form["data_access"] = [str(x) for x in raw.getlist("data_access")]
        try:
            row = p().create_vendor(user, form)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return render(request, user, "vendor_form.html", nav_active="vendors", page_err=str(exc),
                          v={"RowKey": "new", "status": "onboarding", **form}, **options())
        h.invalidate()
        return back(f"/vendors/{row['RowKey']}", msg="Vendor added. It stays in Onboarding until an admin approves it."
                    if user.is_admin else "Request sent. An admin reviews it before any data is shared.")

    # ---------------------------------------------------------------- questionnaire
    @app.get("/vendors/questionnaire", response_class=HTMLResponse)
    def questionnaire_page(request: Request, version: int = 0, q: str = "full", user: User = Depends(current_user)):
        portal = p()
        qid = q if q in vmod.QUESTIONNAIRES else "full"
        versions = portal.questionnaire_versions(qid)
        try:
            shown = portal.questionnaire_version(version, qid) if version else None
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        draft = portal.questionnaire_draft(user, qid) if user.is_admin and not shown else None
        q = shown or draft or versions[0]
        all_sections = [(s["id"], s["title"]) for s in q["sections"]]
        return render(request, user, "questionnaire.html", nav_active="vendors", q=q, draft=draft, versions=versions,
                      latest=versions[0], viewing=shown, all_sections=all_sections, qid=qid,
                      count=sum(len(s["questions"]) for s in q["sections"]), **options())

    @app.get("/vendors/questionnaire.xlsx")
    def questionnaire_xlsx(version: int = 0, q: str = "full", user: User = Depends(current_user)):
        portal = p()
        qid = q if q in vmod.QUESTIONNAIRES else "full"
        try:
            ver = portal.questionnaire_version(version, qid)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        name = "security-questionnaire" if qid == "full" else "security-essentials"
        return h.attachment(f"{name}-v{ver['version']}.xlsx", portal.questionnaire_xlsx(ver))

    @app.post("/vendors/questionnaire/edit")
    async def questionnaire_edit(request: Request, user: User = Depends(current_user)):
        raw = await posted(request, user)
        form = {k: str(raw.get(k, "")) for k in ("section", "question", "direction", "target", "title", "intro",
                                                  "text", "type", "guidance")}
        form["criteria"] = [str(c).strip() for c in str(raw.get("criteria", "")).replace(";", ",").split(",") if c.strip()]
        op = str(raw.get("op", ""))
        qid = str(raw.get("q", "full"))
        page = "/vendors/questionnaire" + ("" if qid == "full" else f"?q={qid}" if qid in vmod.QUESTIONNAIRES else "")
        anchor = f"#{form['question'] or form['section']}" if (form["question"] or form["section"]) else ""
        msgs = {"discard": "Draft discarded", "delete_question": "Question removed from the draft",
                "delete_section": "Section removed from the draft"}
        return run(page + anchor, msgs.get(op, "Saved in the draft"), p().edit_questionnaire, user, op, form, qid)

    @app.post("/vendors/questionnaire/publish")
    async def questionnaire_publish(request: Request, user: User = Depends(current_user)):
        raw = await posted(request, user)
        qid = str(raw.get("q", "full"))
        page = "/vendors/questionnaire" + ("" if qid == "full" else f"?q={qid}" if qid in vmod.QUESTIONNAIRES else "")
        return run(page, "Saved as a new version", p().publish_questionnaire, user, str(raw.get("reason", "")), qid)

    # ---------------------------------------------------------------- one vendor
    @app.get("/vendors/{vid}", response_class=HTMLResponse)
    def vendor_page(request: Request, vid: str, tab: str = "overview", user: User = Depends(current_user)):
        portal = p()
        try:
            v = portal.vendor(user, vid)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        tabs = {k: label for k, label in TABS.items() if not (k == "contacts" and user.is_auditor)}
        if v["status"] in ("onboarding", "offboarding"):
            tabs["review"] = vmod.REVIEW_KINDS[v["status"]]
        tab = tab if tab in tabs else "overview"
        files = portal.vendor_files(user, vid)
        reviews = portal.vendor_reviews(vid)
        r = v["open_review"]
        gaps = portal.review_gaps(portal._vendor_row(vid), r) if r and user.is_admin else []
        controls = sorted(portal.catalog.controls, key=lambda c: c["id"])
        return render(request, user, "vendor.html", nav_active="vendors", v=v, tab=tab, tabs=tabs, files=files,
                      files_by_id={f["RowKey"]: f for f in files}, reviews=reviews, r=r, gaps=gaps,
                      can_work=user.is_admin or portal._is_vendor_owner(user, v), controls=controls,
                      history=portal.vendor_history(user, vid) if tab == "history" else [],
                      versions=portal.vendor_versions(user, vid) if tab == "history" else [],
                      latest_q={qid: portal.questionnaire_version(0, qid) for qid in vmod.QUESTIONNAIRES},
                      needs_baseline=bool(r and portal.needs_baseline(v, r)),
                      needs_acceptance=bool(r and portal.needs_acceptance(v, r)), **options())

    @app.get("/vendors/{vid}/edit", response_class=HTMLResponse)
    def vendor_edit(request: Request, vid: str, user: User = Depends(current_user)):
        h.need(user, "admin")
        try:
            v = p().vendor(user, vid)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        return render(request, user, "vendor_form.html", nav_active="vendors", v=v, **options())

    @app.post("/vendors/{vid}/edit")
    async def vendor_save(request: Request, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        form = {k: str(raw.get(k, "")) for k in vmod.DETAIL_FIELDS + vmod.CONTACT_FIELDS if k in raw}
        form["data_access"] = [str(x) for x in raw.getlist("data_access")]
        try:
            p().update_vendor(user, vid, form, str(raw.get("reason", "")))
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            try:
                v = p().vendor(user, vid)
            except Invalid:
                raise h.HTTPError(404, "Vendor not found") from exc
            return render(request, user, "vendor_form.html", nav_active="vendors", page_err=str(exc),
                          v={**v, **form}, reason=str(raw.get("reason", "")), **options())
        h.invalidate()
        return back(f"/vendors/{vid}", msg="Vendor saved; the previous version is kept in the history")

    @app.post("/vendors/{vid}/contacts")
    async def vendor_contacts(request: Request, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        form = {k: str(raw.get(k, "")) for k in vmod.CONTACT_FIELDS if k in raw}
        return run(f"/vendors/{vid}?tab=contacts", "Contacts saved", p().update_vendor_contacts, user, vid, form)

    @app.post("/vendors/{vid}/review/start")
    async def vendor_review_start(request: Request, vid: str, user: User = Depends(current_user)):
        await posted(request, user)
        return run(f"/vendors/{vid}?tab=review", "Annual review started", p().start_annual_review, user, vid)

    @app.post("/vendors/{vid}/files")
    async def vendor_upload(request: Request, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        upload = raw.get("file")
        if upload is None or not hasattr(upload, "read"):
            return back(f"/vendors/{vid}?tab=review", err="Choose a file to upload")
        data = await upload.read(MAX_UPLOAD_BYTES + 1)
        return run(f"/vendors/{vid}?tab=review", "File stored write-once and attached to the review",
                   p().add_vendor_file, user, vid, upload.filename or "upload", data, str(raw.get("kind", "")),
                   str(raw.get("comment", "")))

    @app.get("/vendors/{vid}/files/{fid}")
    def vendor_file(vid: str, fid: str, user: User = Depends(current_user)):
        try:
            name, data = p().vendor_file(user, vid, fid)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        return h.attachment(name, data)

    @app.post("/vendors/{vid}/review/answers")
    async def vendor_answers(request: Request, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        answers = {key: str(raw.get(key, "")) for key, _label, _opts in vmod.QUESTIONS}
        submit = str(raw.get("action", "")) == "submit"
        return run(f"/vendors/{vid}?tab=review", "Your part is done. Security has been notified." if submit
                   else "Answers saved", p().save_review_answers, user, vid, answers, submit)

    @app.post("/vendors/{vid}/review/exception")
    async def vendor_exception(request: Request, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        if raw.get("remove"):
            return run(f"/vendors/{vid}?tab=review", "Exception removed", p().remove_review_exception, user, vid,
                       str(raw.get("remove")))
        return run(f"/vendors/{vid}?tab=review", "Exception recorded", p().add_review_exception, user, vid,
                   str(raw.get("text", "")), str(raw.get("impact", "")), str(raw.get("response", "")))

    @app.post("/vendors/{vid}/review/checklist")
    async def vendor_checklist(request: Request, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        return run(f"/vendors/{vid}?tab=review", "Checklist updated", p().update_checklist, user, vid,
                   str(raw.get("key", "")), str(raw.get("done", "")) == "1", str(raw.get("note", "")))

    @app.post("/vendors/{vid}/review/decide")
    async def vendor_decide(request: Request, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        decision = str(raw.get("decision", ""))
        msg = {"approve": "Signed off", "return": "Returned to the owner", "reject": "Vendor not approved"}.get(decision, "")
        return run(f"/vendors/{vid}?tab=review" if decision == "return" else f"/vendors/{vid}", msg,
                   p().decide_review, user, vid, decision, str(raw.get("note", "")))

    @app.post("/vendors/{vid}/cuecs")
    async def vendor_cuecs(request: Request, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        cid = str(raw.get("cuec", "new"))[:20]
        if str(raw.get("action", "")) == "remove":
            return run(f"/vendors/{vid}?tab=cuecs", "CUEC removed", p().remove_cuec, user, vid, cid)
        form = {"text": str(raw.get("text", "")), "how": str(raw.get("how", "")), "status": str(raw.get("status", "")),
                "controls": [str(c) for c in raw.getlist("controls")]}
        return run(f"/vendors/{vid}?tab=cuecs", "CUEC saved", p().save_cuec, user, vid, cid, form)

    @app.post("/vendors/{vid}/review/assurance")
    async def vendor_assurance(request: Request, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        items = {key: {"status": str(raw.get(f"b_{key}", "")), "note": str(raw.get(f"n_{key}", ""))}
                 for key in vmod.BASELINE_KEYS}
        return run(f"/vendors/{vid}?tab=review#assurance", "Assurance saved", p().save_assurance, user, vid,
                   str(raw.get("level", "")), items)

    @app.post("/vendors/{vid}/review/acceptance")
    async def vendor_acceptance(request: Request, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        form = {k: str(raw.get(k, "")) for k in ("owner_name", "owner_title", "reason", "expires")}
        return run(f"/vendors/{vid}?tab=review#acceptance", "Risk acceptance recorded", p().record_acceptance,
                   user, vid, form)

    @app.post("/vendors/{vid}/signin-check")
    async def vendor_signin_check(request: Request, vid: str, user: User = Depends(current_user)):
        await posted(request, user)
        try:
            result = p().vendor_signin_check(user, vid)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(f"/vendors/{vid}?tab=review", err=str(exc))
        h.invalidate()
        if result["ok"]:
            return back(f"/vendors/{vid}?tab=review", msg="No enabled app or account left in Entra ID. "
                        "'Sign-in removed' is ticked.")
        return back(f"/vendors/{vid}?tab=review#signin", err="Sign-in is not fully removed yet; see the check below.")

    @app.post("/vendors/{vid}/offboard")
    async def vendor_offboard(request: Request, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        return run(f"/vendors/{vid}?tab=review", "Offboarding started", p().start_offboarding, user, vid,
                   str(raw.get("reason", "")))

    @app.post("/vendors/{vid}/questionnaire")
    async def vendor_questionnaire(request: Request, vid: str, user: User = Depends(current_user)):
        raw = await posted(request, user)
        try:
            name, data = p().send_questionnaire(user, vid, str(raw.get("q", "full")))
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(f"/vendors/{vid}?tab=review", err=str(exc))
        return h.attachment(name, data)

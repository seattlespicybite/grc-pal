"""Access review pages: the list of reviews, one review (a manager's own accounts, or the admin overview), and the
actions. Every rule and permission check lives in accessreview.py; these routes only parse forms and choose the
page to show."""
from __future__ import annotations

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse

from grcpal.portal import accessreview as ar
from grcpal.portal.auth import User
from grcpal.portal.security import MAX_UPLOAD_BYTES
from grcpal.portal.service import Forbidden, Invalid


def register(app, h) -> None:
    p, current_user, render, back = h.p, h.current_user, h.render, h.back

    async def posted(request: Request, user: User):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        return form

    def run(dest: str, msg: str, fn, *args):
        """Call a business rule; 403 when the role is wrong, otherwise back to the page with the result."""
        try:
            fn(*args)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(dest, err=str(exc))
        return back(dest, msg=msg)

    async def read_file(form, field: str) -> bytes | None:
        upload = form.get(field)
        if upload is None or not hasattr(upload, "read"):
            return None
        return await upload.read(MAX_UPLOAD_BYTES + 1) or None

    @app.get("/access-reviews", response_class=HTMLResponse)
    def reviews_page(request: Request, user: User = Depends(current_user)):
        portal = p()
        return render(request, user, "access_reviews.html", nav_active="access", rows=portal.access_campaigns(user),
                      statuses=ar.STATUS, columns=ar.COLUMNS, max_accounts=ar.MAX_ACCOUNTS,
                      max_mb=MAX_UPLOAD_BYTES // (1024 * 1024))

    @app.get("/access-reviews/template.csv")
    def reviews_template(user: User = Depends(current_user)):
        return h.attachment("access-review-template.csv", ar.TEMPLATE_CSV.encode("utf-8"))

    @app.post("/access-reviews/new")
    async def review_create(request: Request, user: User = Depends(current_user)):
        form = await posted(request, user)
        accounts = await read_file(form, "accounts")
        if accounts is None:
            return back("/access-reviews", err="Choose the accounts CSV file")
        try:
            camp = p().create_access_campaign(user, str(form.get("name", "")), str(form.get("due", "")), accounts,
                                              await read_file(form, "people"))
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/access-reviews", err=str(exc))
        warn = camp["reviewers_without_account"]
        msg = f"Review started with {camp['records']} accounts."
        if warn:
            msg += (f" {len(warn)} manager{'s have' if len(warn) != 1 else ' has'} no portal account yet: "
                    "add them as Control owners so they can review.")
        return back(f"/access-reviews/{camp['RowKey']}", msg=msg)

    @app.get("/access-reviews/{cid}", response_class=HTMLResponse)
    def review_page(request: Request, cid: str, user: User = Depends(current_user)):
        portal = p()
        try:
            view = portal.access_campaign(user, cid)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        choices = portal.access_reviewer_choices(user) if user.is_admin else []
        return render(request, user, "access_review.html", nav_active="access", v=view, decisions=ar.DECISIONS,
                      flag_labels=ar.FLAGS, statuses=ar.STATUS, choices=choices)

    @app.post("/access-reviews/{cid}/decide")
    async def review_decide(request: Request, cid: str, user: User = Depends(current_user)):
        form = await posted(request, user)
        decisions: dict[str, dict] = {}
        for key, value in form.multi_items():
            if key.startswith("d_"):
                decisions.setdefault(key[2:], {})["decision"] = str(value)
            elif key.startswith("c_"):
                decisions.setdefault(key[2:], {})["comment"] = str(value)
        dest = f"/access-reviews/{cid}"
        try:
            changed = p().save_access_decisions(user, cid, decisions)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(dest, err=str(exc))
        return back(dest, msg=f"Saved {changed} decision{'s' if changed != 1 else ''}")

    @app.post("/access-reviews/{cid}/signoff")
    async def review_signoff(request: Request, cid: str, user: User = Depends(current_user)):
        await posted(request, user)
        return run(f"/access-reviews/{cid}", "Signed off. Your decisions are now locked", p().attest_access, user, cid)

    @app.post("/access-reviews/{cid}/reopen")
    async def review_reopen(request: Request, cid: str, user: User = Depends(current_user)):
        form = await posted(request, user)
        return run(f"/access-reviews/{cid}", "Sign-off reopened", p().reopen_access_signoff, user, cid,
                   str(form.get("reviewer", "")))

    @app.post("/access-reviews/{cid}/assign")
    async def review_assign(request: Request, cid: str, user: User = Depends(current_user)):
        form = await posted(request, user)
        return run(f"/access-reviews/{cid}", "Reviewer assigned", p().assign_access_reviewer, user, cid,
                   str(form.get("entry", "")), str(form.get("reviewer", "")))

    @app.post("/access-reviews/{cid}/confirm")
    async def review_confirm(request: Request, cid: str, user: User = Depends(current_user)):
        form = await posted(request, user)
        return run(f"/access-reviews/{cid}", "Change confirmed", p().confirm_access_change, user, cid,
                   str(form.get("entry", "")), str(form.get("note", "")))

    @app.post("/access-reviews/{cid}/close")
    async def review_close(request: Request, cid: str, user: User = Depends(current_user)):
        form = await posted(request, user)
        return run(f"/access-reviews/{cid}", "Review closed. The result is stored as evidence",
                   p().close_access_campaign, user, cid, str(form.get("note", "")))

    @app.get("/access-reviews/{cid}/export.csv")
    def review_export(cid: str, user: User = Depends(current_user)):
        try:
            name, data = p().access_export(user, cid)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        return h.attachment(name, data)

"""GRC-pal portal: FastAPI, server-rendered, no external scripts or fonts.

Run locally (demo data, pick a user on the sign-in page):
    grcpal serve --demo
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import mimetypes
import os
import time
import traceback
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from grcpal import report as report_mod
from grcpal.catalog import Catalog
from grcpal.evidence import EvidenceStore
from grcpal.portal import mailer as mailer_mod
from grcpal.portal import store as store_mod
from grcpal.portal.accounts import SESSION_COOKIE
from grcpal.portal.auth import (DEV_COOKIE, ROLE_HELP, ROLE_LABELS, ROLES, AuthError, User, auth_mode,
                                identity_from_request)
from grcpal.portal.observability import configure_logging, current_actor, event, new_request_id, request_id
from grcpal.portal.security import MAX_UPLOAD_BYTES, SECURITY_HEADERS, csrf_token, csrf_valid
from grcpal.portal.service import Forbidden, Invalid, Portal

HERE = Path(__file__).parent
STATUS_LABELS = report_mod._LABELS
VIEW_COOKIE = "grcpal_view"   # which framework the person is looking at; a display preference, not a permission
CATEGORY_NAMES = {"security": "Security", "availability": "Availability", "confidentiality": "Confidentiality",
                  "processing_integrity": "Processing Integrity", "privacy": "Privacy"}
ACCEPT = ".pdf,.png,.jpg,.jpeg,.csv,.xlsx,.docx,.pptx,.txt,.json,.md,.eml"


class _HTTPError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def portal_from_env() -> Portal:
    base = os.getenv("GRCPAL_BASE") or None
    if not base:
        from grcpal import configbundle

        fetched = configbundle.fetch()  # your catalog from the program repo, published by its workflow
        base = str(fetched) if fetched else None
    event("starting", catalog=base or "built-in starter", tenant=os.getenv("GRCPAL_TENANT", "default"))
    if os.getenv("GRCPAL_ENV", "").lower() == "production" and not os.getenv("GRCPAL_TABLES_URL"):
        event("GRCPAL_TABLES_URL is not set: portal data is in a local SQLite file and is lost when the "
              "container restarts", 30)
    portal = Portal(Catalog.load(base), store_mod.from_env(), EvidenceStore(os.getenv("GRCPAL_EVIDENCE_DIR", "evidence")),
                    mailer=mailer_mod.from_env())
    if os.getenv("GRCPAL_DEMO") == "1":
        from grcpal.portal.demo import seed

        seed(portal)
    return portal


def create_app(portal: Portal | None = None) -> FastAPI:
    configure_logging()
    mode = auth_mode()  # fail fast on an unsafe configuration
    app = FastAPI(title="GRC-pal", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.portal = portal or portal_from_env()
    app.state.report_cache = (0.0, None)
    app.state.portal.on_change(lambda: setattr(app.state, "report_cache", (0.0, None)))
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.globals.update(status_labels=STATUS_LABELS, category_names=CATEGORY_NAMES, role_help=ROLE_HELP, role_labels=ROLE_LABELS,
                                 roles=ROLES, auth_mode=mode, accept=ACCEPT)
    from grcpal.settings import OPTION_LABELS
    templates.env.globals["option_labels"] = OPTION_LABELS
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    logout_url = {"easyauth": "/.auth/logout", "dev": "/dev/logout", "local": "/logout"}.get(mode, os.getenv("GRCPAL_LOGOUT_URL", "/oauth2/sign_out"))
    templates.env.globals["logout_url"] = logout_url

    # ------------------------------------------------------------------ middleware
    @app.middleware("http")
    async def trace_and_secure(request: Request, call_next):
        rid = new_request_id(request.headers.get("x-request-id"))
        token = request_id.set(rid)
        actor_token = current_actor.set("-")
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:  # noqa: BLE001 - render a safe error page with the reference
            try:
                app.state.portal.events.error("system", f"Unexpected error on {request.method} {request.url.path}",
                                              reference=rid, trace=traceback.format_exc())
            except Exception:  # noqa: BLE001
                event("unhandled error", 40, path=request.url.path, exc=traceback.format_exc(limit=8))
            response = templates.TemplateResponse(request, "error.html", {"request": request, "status": 500,
                                                  "message": "Unexpected error.", "user": None, "request_id": rid},
                                                  status_code=500)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        response.headers["X-Request-ID"] = rid
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "public, max-age=3600"
        if request.url.path != "/healthz":
            event("request", method=request.method, path=request.url.path, status=response.status_code,
                  ms=round((time.perf_counter() - started) * 1000, 1))
        current_actor.reset(actor_token)
        request_id.reset(token)
        return response

    # ------------------------------------------------------------------ helpers
    def p() -> Portal:
        return app.state.portal

    def current_user(request: Request) -> User:
        if mode == "local":
            try:
                user = p().session_user(request.cookies.get(SESSION_COOKIE))
            except AuthError as exc:
                raise _HTTPError(exc.status, str(exc)) from exc
            current_actor.set(user.email)
            return user
        try:
            identity = identity_from_request(request.headers, request.cookies)
        except AuthError as exc:
            if exc.status == 403:
                p().events.security(f"Sign-in refused: {exc}", path=request.url.path)
            raise _HTTPError(exc.status, str(exc)) from exc
        try:
            user = p().resolve(identity)
        except AuthError as exc:
            p().events.security(f"Access refused for {identity.email}: {exc}", actor=identity.email, path=request.url.path)
            raise _HTTPError(exc.status, str(exc)) from exc
        current_actor.set(user.email)
        return user

    def need(user: User, *roles: str) -> None:
        if not user.has(*roles):
            raise _HTTPError(403, "Your role does not include this page")

    def check_csrf(request: Request, subject: str, token: str | None) -> None:
        origin = request.headers.get("origin")
        if origin:
            allowed = os.getenv("GRCPAL_PUBLIC_URL") or f"{request.url.scheme}://{request.headers.get('host')}"
            if urlparse(origin).netloc != urlparse(allowed).netloc:
                raise _HTTPError(403, "Cross-site request blocked")
        if not csrf_valid(subject, token):
            raise _HTTPError(403, "Your form expired. Go back, refresh the page and try again.")

    def health(force: bool = False) -> dict:
        ts, data = app.state.report_cache
        if force or data is None or time.time() - ts > 300:
            portal = p()
            data = report_mod.build(portal.catalog, portal.evidence, portal.today, portal=portal.report_inputs())
            app.state.report_cache = (time.time(), data)
        return data

    def invalidate() -> None:
        app.state.report_cache = (0.0, None)

    def status_of(control_id: str) -> dict:
        return next((c for c in health()["controls"] if c["id"] == control_id), {"status": "not_started", "evidence": []})

    def render(request: Request, user: User, name: str, **ctx) -> HTMLResponse:
        portal = p()
        in_use = portal.frameworks_in_use
        view = portal.program_view(request.cookies.get(VIEW_COOKIE, ""))
        ctx.setdefault("nav_active", "")
        ctx.update(fw_in_use=in_use, view=view, view_fw=in_use.get(view), library_owner=portal.library_owner(),request=request, user=user, csrf=csrf_token(user.email), today=portal.today.isoformat(),
                   cycle=portal.active_cycle(), org=portal.org, request_id=request_id.get(),
                   review_count=len(portal.reviewable(user)),
                   my_open=sum(1 for a in portal.assignments(user=user, mine=True) if a["status"] in ("open", "returned")),
                   flash=request.query_params.get("msg"), error=request.query_params.get("err"))
        return templates.TemplateResponse(request, name, ctx)

    def current_view(request: Request) -> str:
        return p().program_view(request.cookies.get(VIEW_COOKIE, ""))

    def safe_dest(url: str, default: str) -> str:
        return url if url.startswith("/") and not url.startswith("//") and "\\" not in url else default

    def back(url: str, msg: str | None = None, err: str | None = None) -> RedirectResponse:
        q = urlencode({k: v for k, v in (("msg", msg), ("err", err)) if v})
        url, _, frag = url.partition("#")
        return RedirectResponse(f"{url}{'&' if '?' in url else '?'}{q}{'#' + frag if frag else ''}" if q else url,
                                status_code=303)

    @app.exception_handler(_HTTPError)
    async def http_error(request: Request, exc: _HTTPError):
        if exc.status == 401 and mode in ("dev", "local") and request.method == "GET":
            login = "/dev/login" if mode == "dev" else "/login"
            return RedirectResponse(f"{login}?next={quote(request.url.path)}", status_code=303)
        return templates.TemplateResponse(request, "error.html", {"request": request, "status": exc.status,
                                          "message": exc.message, "user": None, "request_id": request_id.get()},
                                          status_code=exc.status)

    # ------------------------------------------------------------------ health and dev sign-in
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    if mode == "dev":
        @app.get("/dev/login", response_class=HTMLResponse)
        def dev_login(request: Request, next: str = "/"):
            users = [u for u in p().users() if u.get("active", True)]
            return templates.TemplateResponse(request, "dev_login.html", {
                "request": request, "user": None, "users": users, "next": safe_dest(next, "/"),
                "csrf": csrf_token("dev-login"), "request_id": request_id.get(), "org": p().org})

        @app.post("/dev/login")
        def dev_login_post(request: Request, email: str = Form(...), name: str = Form(""), next: str = Form("/"),
                           csrf: str = Form("")):
            check_csrf(request, "dev-login", csrf)
            email = email.strip().lower()
            portal = p()
            if not portal.users():  # empty instance in dev mode: the first person becomes admin
                portal._create_user(email, name or email, "admin", "dev-first-user", email)
            if not portal.user_row(email):
                return RedirectResponse("/dev/login?err=" + quote("Unknown user. Ask an admin to add you."), status_code=303)
            resp = RedirectResponse(safe_dest(next, "/"), status_code=303)
            resp.set_cookie(DEV_COOKIE, email, httponly=True, samesite="lax", secure=request.url.scheme == "https")
            return resp

        @app.get("/dev/logout")
        def dev_logout():
            resp = RedirectResponse("/dev/login", status_code=303)
            resp.delete_cookie(DEV_COOKIE)
            return resp

        @app.get("/dev/outbox", response_class=HTMLResponse)
        def dev_outbox(request: Request, user: User = Depends(current_user)):
            need(user, "admin")
            return render(request, user, "outbox.html", messages=list(getattr(p().mailer, "outbox", [])))

    # ------------------------------------------------------------------ dashboard and controls
    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, user: User = Depends(current_user)):
        if user.is_contributor:
            return RedirectResponse("/work", status_code=303)
        portal, data = p(), health()
        cats: dict = {}
        for c in data["controls"]:
            for crit in c["criteria"]:
                cat = portal.catalog.criteria[crit]["category"]
                cats.setdefault(cat, {}).setdefault(c["status"], set()).add(c["id"])
        by_cat = {k: {s: len(v) for s, v in d.items()} for k, d in cats.items()}
        attention = [c for c in data["controls"] if c["status"] in ("attention", "findings")][:8]
        work = portal.assignments()
        progress = {s: sum(1 for a in work if a["status"] == s) for s in ("open", "submitted", "returned", "approved")}
        policies = [(pol, portal.policy_status(pol)) for pol in portal.catalog.policies if pol.get("acknowledge", True)]
        return render(request, user, "dashboard.html", data=data, by_cat=by_cat, attention=attention, progress=progress,
                      overdue=[a for a in work if a["overdue"]][:8], policies=policies)

    @app.get("/controls", response_class=HTMLResponse)
    def controls(request: Request, q: str = "", status: str = "", category: str = "", owner: str = "",
                 sort: str = "id", framework: str = "", family: str = "", criterion: str = "", evidenced: str = "",
                 user: User = Depends(current_user)):
        from grcpal import frameworks as fw_mod
        from grcpal.collectors import disabled_sources
        from grcpal.portal import soc2

        portal = p()
        rows = health()["controls"]
        fws = portal.frameworks_in_use
        view = current_view(request)
        if view != "all":
            framework = view
        if framework in fws:
            mapped = {c["id"] for c in portal.catalog.controls if fw_mod.requirements_of(c, fws[framework])}
            rows = [c for c in rows if c["id"] in mapped]
        columns = [fws[view]] if view != "all" else list(fws.values())
        by_id = {c["id"]: c for c in portal.catalog.controls}
        refs = {c["id"]: {fw.id: fw_mod.requirements_of(by_id.get(c["id"], c), fw) for fw in columns} for c in rows}
        visible = portal.visible_controls(user)
        if visible is not None:
            rows = [c for c in rows if c["id"] in visible]
        if q:
            ql = q.lower()
            rows = [c for c in rows if ql in c["id"].lower() or ql in c["title"].lower()]
        if status:
            rows = [c for c in rows if c["status"] == status]
        if category:
            rows = [c for c in rows if any(portal.catalog.criteria[x]["category"] == category for x in c["criteria"])]
        if owner:
            rows = [c for c in rows if c["owner"] == owner]
        soc2_on = "soc2" in fws and view in ("soc2", "all")
        fam_ids = list(dict.fromkeys(soc2.family_of(x) for x in soc2.ordered_criteria(portal.catalog)))
        if family not in fam_ids:
            family = ""
        crit_options = [x for x in soc2.ordered_criteria(portal.catalog) if not family or soc2.family_of(x) == family]
        if criterion not in crit_options:
            criterion = ""
        if soc2_on and (family or criterion):
            rows = [c for c in rows if any((x == criterion) if criterion else (soc2.family_of(x) == family)
                                           for x in c["criteria"])]
        skip = disabled_sources(portal.catalog, portal.settings)
        how = {c["id"]: soc2.evidenced_by(by_id.get(c["id"], c), skip) for c in rows}
        if evidenced in soc2.TYPE_LABELS:
            rows = [c for c in rows if how[c["id"]]["type"] == evidenced]
        keys = {"id": lambda c: c["id"], "status": lambda c: c["status"], "owner": lambda c: c["owner"],
                "title": lambda c: c["title"].lower()}
        rows = sorted(rows, key=keys.get(sort, keys["id"]))
        return render(request, user, "controls.html", rows=rows, q=q, status=status, category=category,
                      owner=owner, sort=sort, owners=sorted(portal.catalog.roles), framework=framework,
                      frameworks=fws, columns=columns, refs=refs, how=how, soc2_on=soc2_on, family=family,
                      criterion=criterion, evidenced=evidenced, families=[(f, soc2.FAMILY_NAMES.get(f, f)) for f in fam_ids],
                      crit_options=crit_options, hits={criterion} if criterion else (set(crit_options) if family else set()),
                      list_qs=_list_query(str(request.url.query)))

    @app.get("/controls/{control_id}", response_class=HTMLResponse)
    def control_detail(request: Request, control_id: str, user: User = Depends(current_user)):
        from grcpal.collectors import disabled_sources
        from grcpal.portal import soc2

        portal = p()
        ctl = portal.catalog.control(control_id)
        if not ctl or not portal.can_see_control(user, control_id):
            raise _HTTPError(404, "Control not found, or it is not assigned to you")
        # Where the person came from. Only a known criterion id or a filtered list is accepted, never a URL.
        came_from = request.query_params.get("from", "")
        trail = None
        if came_from in portal.catalog.criteria and user.sees_everything:
            siblings = [c for c in portal.catalog.coverage().get(came_from, []) if portal.can_see_control(user, c)]
            prev_c, next_c, pos = soc2.neighbours(siblings, control_id)
            fam = soc2.family_of(came_from)
            trail = {"criterion": came_from, "family": fam, "family_name": soc2.FAMILY_NAMES.get(fam, fam),
                     "prev": prev_c, "next": next_c, "position": pos, "total": len(siblings)}
        list_qs = _list_query(request.query_params.get("list", ""))
        skip = disabled_sources(portal.catalog, portal.settings)
        how = soc2.evidenced_by(ctl, skip)
        wanted = [ev["artifact"] for ev in ctl.get("evidence", [])
                  if not (str(ev.get("via", "")).startswith("collector:") and str(ev["via"]).split(":", 1)[1] in skip)]
        prev = portal.previous_cycle()
        points = [(crit, pt) for crit, pts in portal.catalog.points_of_focus.items() for pt in pts
                  if control_id in pt.get("controls", [])]
        assignments = portal.assignments(control=control_id)
        if user.is_contributor:
            mine = [a for a in assignments if user.email in portal.participants(a)]
            assignments = mine or assignments
        return render(request, user, "control.html", ctl=ctl, status=status_of(control_id), points=points,
                      assignments=assignments, uploads=portal.uploads(control=control_id),
                      prev=prev, prev_uploads=portal.uploads(control=control_id, cycle=prev["RowKey"]) if prev else [],
                      prev_assignments=portal.assignments(control=control_id, cycle=prev["RowKey"]) if prev else [],
                      comments=portal.comments(control=control_id, cycle=portal.active_cycle()["RowKey"]),
                      overrides=[o for o in portal.overrides() if o["control"] == control_id],
                      history=portal.control_history(control_id, 50) if user.sees_everything else [],
                      can_upload=portal.can_upload_control(user, control_id),
                      can_comment=portal.can_comment(user, [control_id]),
                      wanted=wanted, how=how, trail=trail, list_qs=list_qs,
                      def_history=portal.control_definition_history(control_id) if user.sees_everything else [],
                      nav_active="framework" if trail else "",
                      owner_emails=portal.owner_emails(control_id), criteria=portal.catalog.criteria,
                      max_mb=MAX_UPLOAD_BYTES // (1024 * 1024),
                      mappings=_mappings(portal, ctl, current_view(request)),
                      checks=portal.checks_for(control_id) if user.sees_everything else [],
                      ai=portal.ai_status() if user.sees_everything else None,
                      ai_reviews=portal.ai_reviews(control_id)[:10] if user.sees_everything else [])

    @app.post("/controls/{control_id}/upload")
    async def control_upload(request: Request, control_id: str, file: UploadFile = File(...), comment: str = Form(""),
                             csrf: str = Form(""), user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        try:
            p().upload(user, file.filename or "upload", data, comment, control_id=control_id)
        except (Invalid, Forbidden) as exc:
            return back(f"/controls/{control_id}#upload", err=str(exc))
        invalidate()
        return back(f"/controls/{control_id}#submissions", msg="Evidence uploaded and sent for review")

    @app.post("/controls/{control_id}/remind")
    def control_remind(request: Request, control_id: str, note: str = Form(""), csrf: str = Form(""),
                       user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            r = p().remind(user, control_id, note, status=STATUS_LABELS.get(status_of(control_id)["status"]))
        except (Invalid, Forbidden) as exc:
            return back(f"/controls/{control_id}", err=str(exc))
        return back(f"/controls/{control_id}", msg=_remind_msg(r))

    @app.get("/view")
    def switch_view(request: Request, f: str = "all", next: str = "/", user: User = Depends(current_user)):
        """Remember which framework this person wants to look at. Only changes what is shown, never access."""
        portal = p()
        choice = f if f in portal.frameworks_in_use or f == "all" else "all"
        resp = RedirectResponse(safe_dest(next, "/"), status_code=303)
        resp.set_cookie(VIEW_COOKIE, choice, max_age=365 * 86400, path="/", httponly=True, samesite="lax",
                        secure=request.url.scheme == "https")
        return resp

    # ------------------------------------------------------------------ criteria (admins, auditors)
    @app.get("/criteria", response_class=HTMLResponse)
    def criteria(request: Request, open: str = "", user: User = Depends(current_user)):
        """SOC 2 overview: criteria grouped into families (CC1-CC9, then the additional categories)."""
        need(user, "admin", "auditor")
        from grcpal.portal import soc2

        portal = p()
        stat = {c["id"]: c["status"] for c in health()["controls"]}
        fams = soc2.families(portal.catalog, stat)
        in_scope = [f for f in fams if f["in_scope"]]
        scoped_controls = {c for f in in_scope for c in f["controls"]}
        totals = {s: 0 for s in soc2.STATUSES}
        for c in scoped_controls:
            s = stat.get(c, "not_started")
            totals[s if s in totals else "not_started"] += 1
        categories = [cat for cat in soc2.CATEGORY_ORDER if any(f["category"] == cat and f["in_scope"] for f in fams)]
        return render(request, user, "criteria.html", families=fams, totals=totals, open_family=open,
                      scoped_criteria=len(portal.catalog.in_scope_criteria), scoped_controls=len(scoped_controls),
                      scope_names=[CATEGORY_NAMES.get(c, c) for c in categories])

    @app.get("/criteria/{crit_id}", response_class=HTMLResponse)
    def criterion_detail(request: Request, crit_id: str, user: User = Depends(current_user)):
        need(user, "admin", "auditor")
        portal = p()
        crit = portal.catalog.criteria.get(crit_id)
        if not crit:
            raise _HTTPError(404, "Criterion not found")
        stat = {c["id"]: c["status"] for c in health()["controls"]}
        open_by_point: dict = {}
        for a in portal.assignments():
            if a["target_type"] == "point" and a["status"] not in ("approved", "cancelled"):
                open_by_point.setdefault(a["target_id"], []).append(a)
        from grcpal.collectors import disabled_sources
        from grcpal.portal import soc2

        order = soc2.ordered_criteria(portal.catalog, in_scope_only=crit_id in portal.catalog.in_scope_criteria)
        prev_id, next_id, position = soc2.neighbours(order, crit_id)
        skip = disabled_sources(portal.catalog, portal.settings)
        controls = [portal.catalog.control(c) for c in portal.catalog.coverage().get(crit_id, [])]
        how = {c["id"]: soc2.evidenced_by(c, skip) for c in controls}
        family = soc2.family_of(crit_id)
        return render(request, user, "criterion.html", crit_id=crit_id, crit=crit, stat=stat,
                      points=portal.catalog.points_of_focus.get(crit_id, []), open_by_point=open_by_point,
                      controls=controls, how=how, prev_id=prev_id, next_id=next_id, position=position,
                      order_total=len(order), family=family, family_name=soc2.FAMILY_NAMES.get(family, family),
                      in_scope=crit_id in portal.catalog.in_scope_criteria,
                      type_counts={k: sum(1 for h in how.values() if h["type"] == k) for k in soc2.TYPE_LABELS})

    # ------------------------------------------------------------------ work and assignments
    @app.get("/work", response_class=HTMLResponse)
    def my_work(request: Request, show: str = "open", user: User = Depends(current_user)):
        portal = p()
        rows = portal.assignments(user=user, mine=True)
        if show == "open":
            rows = [a for a in rows if a["status"] in ("open", "returned", "submitted")]
        managed = [a for a in portal.assignments() if a["status"] not in ("approved", "cancelled")] if user.is_admin else []
        owned = sorted(portal.owned_controls(user.email))
        return render(request, user, "work.html", rows=rows, show=show, managed=managed,
                      owned=[portal.catalog.control(c) for c in owned])

    @app.get("/assignments/{assignment_id}", response_class=HTMLResponse)
    def assignment_detail(request: Request, assignment_id: str, user: User = Depends(current_user)):
        portal = p()
        try:
            a = portal.assignment(assignment_id)
        except Invalid as exc:
            raise _HTTPError(404, str(exc)) from exc
        if not portal.can_see_assignment(user, a):
            raise _HTTPError(404, "Assignment not found, or it is not assigned to you")
        prev = None
        if a.get("previous"):
            try:
                prev = portal.assignment(a["previous"])
            except Invalid:
                prev = None
        uploads = portal.uploads(assignment=assignment_id, cycle=None)
        return render(request, user, "assignment.html", a=a, uploads=uploads,
                      comments=portal.comments(assignment=assignment_id),
                      prev=prev, prev_uploads=portal.uploads(assignment=prev["RowKey"], cycle=None) if prev else [],
                      prev_comments=portal.comments(assignment=prev["RowKey"]) if prev else [],
                      wanted=portal.evidence_wanted(a["controls"]), cycle_name=portal.cycle_name(a["cycle"]),
                      can_upload=portal.can_upload(user, a), can_comment=portal.can_comment(user, a["controls"]),
                      max_mb=MAX_UPLOAD_BYTES // (1024 * 1024))

    @app.post("/assignments")
    def create_assignment(request: Request, target_type: str = Form(...), target_id: str = Form(...),
                          assignee: str = Form(...), contributors: str = Form(""), due: str = Form(...),
                          instructions: str = Form(""), return_to: str = Form("/work"), csrf: str = Form(""),
                          user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        dest = safe_dest(return_to, "/work")
        try:
            a = p().create_assignment(user, target_type, target_id, assignee,
                                      contributors.replace(";", ",").split(","), due, instructions)
        except (Invalid, Forbidden) as exc:
            return back(dest, err=str(exc))
        invalidate()
        return back(f"/assignments/{a['RowKey']}", msg="Assignment created and the assignee was emailed")

    @app.post("/assignments/{assignment_id}/edit")
    def edit_assignment(request: Request, assignment_id: str, assignee: str = Form(...), contributors: str = Form(""),
                        due: str = Form(...), instructions: str = Form(""), csrf: str = Form(""),
                        user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            p().edit_assignment(user, assignment_id, assignee, contributors.replace(";", ",").split(","), due, instructions)
        except (Invalid, Forbidden) as exc:
            return back(f"/assignments/{assignment_id}", err=str(exc))
        invalidate()
        return back(f"/assignments/{assignment_id}", msg="Request updated; anyone newly added was emailed")

    @app.post("/assignments/{assignment_id}/cancel")
    def cancel_assignment(request: Request, assignment_id: str, reason: str = Form(""), csrf: str = Form(""),
                          user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            p().cancel_assignment(user, assignment_id, reason)
        except (Invalid, Forbidden) as exc:
            return back(f"/assignments/{assignment_id}", err=str(exc))
        return back(f"/assignments/{assignment_id}", msg="Assignment cancelled")

    @app.post("/assignments/{assignment_id}/upload")
    async def upload(request: Request, assignment_id: str, file: UploadFile = File(...), comment: str = Form(""),
                     csrf: str = Form(""), user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        try:
            p().upload(user, file.filename or "upload", data, comment, assignment_id=assignment_id)
        except (Invalid, Forbidden) as exc:
            return back(f"/assignments/{assignment_id}", err=str(exc))
        invalidate()
        return back(f"/assignments/{assignment_id}", msg="Evidence uploaded and sent for review")

    @app.post("/assignments/{assignment_id}/remind")
    def assignment_remind(request: Request, assignment_id: str, note: str = Form(""), csrf: str = Form(""),
                          user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            a = p().assignment(assignment_id)
            r = p().remind(user, a["controls"][0], note, assignment_id=assignment_id)
        except (Invalid, Forbidden) as exc:
            return back(f"/assignments/{assignment_id}", err=str(exc))
        return back(f"/assignments/{assignment_id}", msg=_remind_msg(r))

    # ------------------------------------------------------------------ comments
    @app.post("/comments")
    def add_comment(request: Request, body: str = Form(""), assignment_id: str = Form(""), upload_id: str = Form(""),
                    control_id: str = Form(""), return_to: str = Form("/work"), csrf: str = Form(""),
                    user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        dest = safe_dest(return_to, "/work")
        try:
            p().add_comment(user, body, assignment_id=assignment_id, upload_id=upload_id, control_id=control_id)
        except (Invalid, Forbidden) as exc:
            return back(dest, err=str(exc))
        return back(dest + "#comments", msg="Comment posted")

    # ------------------------------------------------------------------ reviews and downloads
    @app.get("/reviews", response_class=HTMLResponse)
    def reviews(request: Request, user: User = Depends(current_user)):
        need(user, "admin")
        portal = p()
        assignments = {a["RowKey"]: a for a in portal.assignments(cycle=None)}
        return render(request, user, "reviews.html", rows=portal.reviewable(user), assignments=assignments)

    @app.post("/uploads/{upload_id}/review")
    def review(request: Request, upload_id: str, decision: str = Form(...), note: str = Form(""),
               csrf: str = Form(""), return_to: str = Form("/reviews"), user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        dest = safe_dest(return_to, "/reviews")
        try:
            u = p().review(user, upload_id, decision, note)
        except (Invalid, Forbidden) as exc:
            return back(dest, err=str(exc))
        invalidate()
        return back(dest, msg=f"Evidence {u['status']}")

    @app.get("/uploads/{upload_id}/download")
    def upload_download(upload_id: str, user: User = Depends(current_user)):
        try:
            name, data = p().upload_file(user, upload_id)
        except (Invalid, Forbidden) as exc:
            raise _HTTPError(404, str(exc)) from exc
        return _attachment(name, data)

    # ------------------------------------------------------------------ evidence store (admins, auditors)
    @app.get("/evidence", response_class=HTMLResponse)
    def evidence(request: Request, source: str = "", user: User = Depends(current_user)):
        need(user, "admin", "auditor")
        portal = p()
        sources = []
        for s in portal.evidence_sources():
            runs = portal.evidence.list_runs(s)
            if runs:
                sources.append({"name": s, "runs": len(runs), "last": runs[-1]})
        runs = []
        if source:
            if source not in portal.evidence_sources():
                raise _HTTPError(404, "Unknown evidence source")
            runs = list(reversed(portal.evidence.list_runs(source)))[:200]
        return render(request, user, "evidence.html", sources=sources, source=source, runs=runs)

    @app.get("/evidence/{source}/{run}", response_class=HTMLResponse)
    def evidence_run(request: Request, source: str, run: str, user: User = Depends(current_user)):
        need(user, "admin", "auditor")
        try:
            manifest = p().manifest(source, run)
        except Invalid as exc:
            raise _HTTPError(404, str(exc)) from exc
        return render(request, user, "evidence_run.html", source=source, run=run, m=manifest)

    @app.get("/evidence/{source}/{run}/{filename}")
    def evidence_download(source: str, run: str, filename: str, user: User = Depends(current_user)):
        need(user, "admin", "auditor")
        try:
            data = p().evidence_file(source, run, filename)
        except Invalid as exc:
            raise _HTTPError(404, str(exc)) from exc
        return _attachment(filename, data)

    # ------------------------------------------------------------------ overrides
    @app.get("/overrides", response_class=HTMLResponse)
    def overrides(request: Request, user: User = Depends(current_user)):
        need(user, "admin", "auditor")
        portal = p()
        return render(request, user, "overrides.html", rows=portal.overrides(),
                      controls=[c["id"] for c in portal.catalog.controls],
                      max_expiry=(portal.today + dt.timedelta(days=365)).isoformat())

    @app.post("/overrides")
    def create_override(request: Request, control: str = Form(...), justification: str = Form(...),
                        expires: str = Form(...), evidence_ref: str = Form(""), csrf: str = Form(""),
                        user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            p().create_override(user, control, justification, expires, evidence_ref)
        except (Invalid, Forbidden) as exc:
            return back(f"/controls/{control}" if p().catalog.control(control) else "/overrides", err=str(exc))
        invalidate()
        return back(f"/controls/{control}", msg="Override recorded; the control now shows as accepted by admin")

    @app.post("/overrides/{override_id}/revoke")
    def revoke_override(request: Request, override_id: str, reason: str = Form(""), csrf: str = Form(""),
                        user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            p().revoke_override(user, override_id, reason)
        except (Invalid, Forbidden) as exc:
            return back("/overrides", err=str(exc))
        invalidate()
        return back("/overrides", msg="Override revoked")

    # ------------------------------------------------------------------ audit log
    @app.get("/audit", response_class=HTMLResponse)
    def audit(request: Request, actor: str = "", action: str = "", target: str = "", verify: str = "",
              user: User = Depends(current_user)):
        need(user, "admin", "auditor")
        portal = p()
        result = portal.log.verify() if verify else None
        return render(request, user, "audit.html", rows=portal.log.recent(500, actor, action, target), actor=actor,
                      action=action, target=target, verify=result)

    # ------------------------------------------------------------------ users
    @app.get("/users", response_class=HTMLResponse)
    def users(request: Request, user: User = Depends(current_user)):
        need(user, "admin")
        return render(request, user, "users.html", rows=p().users())

    def users_page_with_link(request: Request, user: User, email: str, url: str, msg: str) -> HTMLResponse:
        # The link is shown once on this page, never put in a redirect URL (it would land in logs and history).
        return render(request, user, "users.html", rows=p().users(), new_link={"email": email, "url": url},
                      page_msg=msg)

    @app.get("/users.csv")
    def users_csv(user: User = Depends(current_user)):
        need(user, "admin", "auditor")
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["email", "name", "role", "active", "source", "created_by", "created_at", "last_seen",
                    "access_until", "password_set"])
        for u in p().users():
            w.writerow([u["RowKey"], u.get("name", ""), ROLE_LABELS.get(u["role"], u["role"]), u.get("active", True),
                        u.get("source", ""), u.get("created_by", ""), u.get("created_at", ""), u.get("last_seen", ""),
                        u.get("access_until", ""), bool(u.get("password_hash"))])
        p().audit(user, "users.export", "users.csv", {"rows": len(p().users())})
        return _attachment(f"grcpal-users-{p().today}.csv", buf.getvalue().encode())

    @app.post("/users")
    def add_user(request: Request, email: str = Form(...), name: str = Form(""), role: str = Form(...),
                 access_until: str = Form(""), csrf: str = Form(""), user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            row = p().add_user(user, email, name, role, access_until)
            msg = f"{row['RowKey']} added as {ROLE_LABELS.get(role, role)}"
            if mode == "local":
                return users_page_with_link(request, user, row["RowKey"], p().setup_link(user, row["RowKey"]), msg)
        except (Invalid, Forbidden) as exc:
            return back("/users", err=str(exc))
        return back("/users", msg=msg)

    @app.post("/users/{email}/link")
    def user_link(request: Request, email: str, csrf: str = Form(""), user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            url = p().setup_link(user, email)
        except (Invalid, Forbidden) as exc:
            return back("/users", err=str(exc))
        return users_page_with_link(request, user, email.lower(), url, f"New password link for {email.lower()}")

    @app.post("/users/{email}/until")
    def user_until(request: Request, email: str, access_until: str = Form(""), csrf: str = Form(""),
                   user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            p().set_access_until(user, email, access_until)
        except (Invalid, Forbidden) as exc:
            return back("/users", err=str(exc))
        return back("/users", msg=f"Access end date saved for {email.lower()}")

    @app.post("/users/{email}/role")
    def set_role(request: Request, email: str, role: str = Form(...), csrf: str = Form(""),
                 user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            p().set_role(user, email, role)
        except (Invalid, Forbidden) as exc:
            return back("/users", err=str(exc))
        return back("/users", msg=f"{email} is now {ROLE_LABELS.get(role, role)}")

    @app.post("/users/{email}/library-owner")
    def set_library_owner(request: Request, email: str, csrf: str = Form(""), user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            p().set_library_owner(user, email)
        except (Invalid, Forbidden) as exc:
            return back("/users", err=str(exc))
        return back("/users", msg=f"{email} is now the control library owner")

    @app.post("/users/{email}/active")
    def set_active(request: Request, email: str, active: str = Form(...), csrf: str = Form(""),
                   user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            p().set_active(user, email, active == "1")
        except (Invalid, Forbidden) as exc:
            return back("/users", err=str(exc))
        return back("/users", msg=f"{email} {'enabled' if active == '1' else 'disabled'}")

    # ------------------------------------------------------------------ cycles and export
    @app.get("/cycles", response_class=HTMLResponse)
    def cycles(request: Request, user: User = Depends(current_user)):
        need(user, "admin", "auditor")
        portal = p()
        rows = []
        for c in portal.cycles():
            work = portal.assignments(cycle=c["RowKey"])
            rows.append({**c, "assignments": len(work), "approved": sum(1 for a in work if a["status"] == "approved"),
                         "uploads": len(portal.uploads(cycle=c["RowKey"]))})
        nxt = dt.date.fromisoformat(portal.active_cycle()["end"]) + dt.timedelta(days=1)
        return render(request, user, "cycles.html", rows=rows, next_start=nxt.isoformat(),
                      next_end=(nxt + dt.timedelta(days=364)).isoformat())

    @app.post("/cycles")
    def start_cycle(request: Request, name: str = Form(...), start: str = Form(...), end: str = Form(...),
                    carry_forward: str = Form(""), csrf: str = Form(""), user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            c = p().start_cycle(user, name, start, end, carry_forward == "1")
        except (Invalid, Forbidden) as exc:
            return back("/cycles", err=str(exc))
        invalidate()
        return back("/cycles", msg=f"Cycle {c['name']} started")

    @app.get("/cycles/{cycle_id}/export")
    def export_cycle(cycle_id: str, user: User = Depends(current_user)):
        try:
            blob = p().export_cycle(user, cycle_id, control_status=health()["controls"])
        except Forbidden as exc:
            raise _HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            raise _HTTPError(404, str(exc)) from exc
        return Response(blob, media_type="application/zip", headers={
            "Content-Disposition": f'attachment; filename="grcpal-{cycle_id}-export.zip"'})

    # ------------------------------------------------------------------ policies
    @app.get("/policies", response_class=HTMLResponse)
    def policies(request: Request, user: User = Depends(current_user)):
        portal = p()
        rows = [(pol, portal.policy_status(pol)) for pol in portal.catalog.policies]
        return render(request, user, "policies.html", rows=rows)

    @app.get("/policies/{policy_id}", response_class=HTMLResponse)
    def policy_detail(request: Request, policy_id: str, user: User = Depends(current_user)):
        portal = p()
        pol = portal.catalog.policy(policy_id)
        if not pol:
            raise _HTTPError(404, "Policy not found")
        st = portal.policy_status(pol)
        return render(request, user, "policy.html", pol=pol, st=st, acked=user.email in st["acked"])

    @app.post("/policies/{policy_id}/ack")
    def policy_ack(request: Request, policy_id: str, csrf: str = Form(""), user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            p().acknowledge(user, policy_id)
        except (Invalid, Forbidden) as exc:
            return back(f"/policies/{policy_id}", err=str(exc))
        return back(f"/policies/{policy_id}", msg="Thank you. Your acknowledgment is recorded.")

    @app.post("/policies/{policy_id}/remind")
    def policy_remind(request: Request, policy_id: str, csrf: str = Form(""), user: User = Depends(current_user)):
        check_csrf(request, user.email, csrf)
        try:
            r = p().remind_policy(user, policy_id)
        except (Invalid, Forbidden) as exc:
            return back(f"/policies/{policy_id}", err=str(exc))
        return back(f"/policies/{policy_id}", msg=_remind_msg(r))

    from types import SimpleNamespace

    from grcpal.portal import routes_accounts, routes_extra

    if mode == "local":
        routes_accounts.register(app, SimpleNamespace(p=p, templates=templates, HTTPError=_HTTPError,
                                                      check_csrf=check_csrf, safe_dest=safe_dest))

    routes_extra.register(app, SimpleNamespace(
        p=p, current_user=current_user, need=need, check_csrf=check_csrf, render=render, back=back,
        health=health, status_of=status_of, invalidate=invalidate, templates=templates, HTTPError=_HTTPError,
        safe_dest=safe_dest, attachment=_attachment))
    # Literal paths registered later (e.g. /controls/new) must win over parameter routes (/controls/{id}).
    literal = [r for r in app.router.routes if getattr(r, "path", "") in ("/controls/new", "/frameworks/new")]
    for r in literal:
        app.router.routes.remove(r)
        app.router.routes.insert(0, r)
    return app


LIST_FILTERS = ("q", "status", "category", "owner", "sort", "framework", "family", "criterion", "evidenced")


def _list_query(raw: str) -> str:
    """Rebuild a controls-list filter query from known keys only, so a crafted value cannot point elsewhere."""
    from urllib.parse import parse_qsl

    pairs = [(k, v[:100]) for k, v in parse_qsl(raw[:1000]) if k in LIST_FILTERS and v]
    return urlencode(pairs)


def _mappings(portal, ctl: dict, view: str = "all") -> list[tuple]:
    """Requirements a control meets, for the framework in view (or every framework in use)."""
    from grcpal import frameworks as fw_mod

    out = []
    in_use = portal.frameworks_in_use
    for fw in ([in_use[view]] if view in in_use else in_use.values()):
        ids = fw_mod.requirements_of(ctl, fw)
        if ids:
            out.append((fw, [(r, fw.requirements.get(r, {}).get("title", "")) for r in ids]))
    return out


def _remind_msg(r: dict) -> str:
    msg = f"Reminder sent to {', '.join(r['sent'])}" if r["sent"] else "No reminder sent"
    if r["skipped"]:
        msg += f" · skipped (already reminded in the last 12 hours): {', '.join(r['skipped'])}"
    return msg


def _attachment(filename: str, data: bytes) -> Response:
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    if ctype.startswith("text/html") or ctype == "image/svg+xml":
        ctype = "application/octet-stream"  # never render stored HTML or SVG in the portal origin
    safe = "".join(ch for ch in filename if ch.isalnum() or ch in "._-") or "download"
    return Response(data, media_type=ctype, headers={"Content-Disposition": f'attachment; filename="{safe}"',
                                                     "Content-Security-Policy": "default-src 'none'; sandbox"})


def __getattr__(name):  # lazy module-level app for `uvicorn grcpal.portal.app:app`
    if name == "app":
        globals()["app"] = create_app()
        return globals()["app"]
    raise AttributeError(name)

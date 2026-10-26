"""Routes for configuration, setup wizard, logs, jobs, frameworks, custom controls, checks and the AI assistant."""
from __future__ import annotations

import csv
import datetime as dt
import io
import json

from fastapi import Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from grcpal import frameworks as fw_mod
from grcpal.ai.review import VERDICT_LABELS
from grcpal.portal.auth import User
from grcpal.portal.eventlog import CATEGORIES, LEVELS
from grcpal.portal.service import Forbidden, Invalid
from grcpal.portal.setupguide import STEPS as GUIDE_STEPS
from grcpal.settings import SECTIONS

# Setup wizard steps. "section" steps reuse the Configuration forms; the others are special pages.
STEPS = (
    {"id": "welcome", "title": "Before you start", "kind": "info",
     "intro": "This guide walks through everything GRC-pal needs, one step at a time. Each step explains what the "
              "setting is for and where to find the value. You can save and test a step, skip it and come back, or "
              "close the guide at any time; nothing is lost. Everything here is also on the Configuration page.",
     "todo": ["About 1 to 2 hours, depending on how many systems you connect. You can stop and continue later.",
              "Have at hand: your Microsoft tenant ID, and admin access to the cloud accounts and GitHub organization "
              "you want to connect (or someone who has it).",
              "Also useful: the dates of your SOC 2 observation period, a list of control owners, your vendor list "
              "as a spreadsheet, and a password manager for the backup recovery kit.",
              "Credentials you enter are encrypted before they are stored and are never shown again.",
              "Only admins can see this guide."]},
    {"id": "deployment", "title": "Where GRC-pal runs", "kind": "deployment",
     "intro": "A quick health check of this installation: sign-in, storage, keys and email. Green items are done. "
              "For anything amber, the hint says what to change. If GRC-pal is not deployed for your team yet, the "
              "command builder below gives you the exact deployment command."},
    {"id": "organization", "kind": "section", "section": "organization"},
    {"id": "access", "title": "People and access", "kind": "access",
     "intro": "Admins manage everything, Control owners see only their own controls, auditors have read-only access "
              "until their access end date. "
              "Add at least one more admin so nobody reviews their own uploads. Everyone else can be added later, "
              "or gets access automatically when you assign them work."},
    {"id": "cycle", "kind": "readiness"},
    {"id": "owners", "kind": "readiness"},
    {"id": "backups", "kind": "readiness"},
    {"id": "updates", "kind": "readiness"},
    {"id": "microsoft", "kind": "section", "section": "microsoft"},
    {"id": "azure", "kind": "section", "section": "azure"},
    {"id": "aws", "kind": "section", "section": "aws"},
    {"id": "gcp", "kind": "section", "section": "gcp"},
    {"id": "github", "kind": "section", "section": "github"},
    {"id": "sources", "kind": "section", "section": "sources"},
    {"id": "email", "kind": "section", "section": "email"},
    {"id": "alerts", "kind": "readiness"},
    {"id": "access_reviews", "kind": "readiness"},
    {"id": "vendors", "kind": "readiness"},
    {"id": "calendar_library", "kind": "readiness"},
    {"id": "ai", "kind": "section", "section": "ai"},
    {"id": "collect", "title": "First evidence run", "kind": "collect",
     "intro": "Run every enabled collector now with the settings you saved. It takes a few minutes. Afterwards the "
              "dashboard shows real status, and the Logs page lists anything that failed."},
    {"id": "finish", "title": "Review and finish", "kind": "summary",
     "intro": "Here is where each step stands. Skipped steps can be finished any time on the Configuration page."},
)
STEP_IDS = [s["id"] for s in STEPS]


def _step(step_id: str) -> dict:
    step = next((s for s in STEPS if s["id"] == step_id), None)
    if step and step["kind"] == "section":
        sec = SECTIONS[step["section"]]
        step = {**step, "title": sec.title, "intro": sec.guide}
    elif step and step["kind"] == "readiness":
        title, why, _ = GUIDE_STEPS[step["id"]]
        step = {**step, "title": title, "intro": why}
    return step


def _form_dict(form) -> dict:
    """Form data -> plain dict; a 'remove saved value' box turns a secret into the clear marker."""
    out = {k: v for k, v in form.items() if isinstance(v, str)}
    for key in [k for k in out if k.endswith("__clear")]:
        out[key[:-7]] = "__clear__"
    return out


def register(app, h) -> None:
    p, current_user, render, back = h.p, h.current_user, h.render, h.back

    def admin(user: User) -> None:
        h.need(user, "admin")

    # ================================================================ configuration
    @app.get("/settings", response_class=HTMLResponse)
    def settings_home(request: Request, user: User = Depends(current_user)):
        admin(user)
        return render(request, user, "settings.html", overview=p().settings_overview(), section=None, result=None,
                      s=p().settings, last_collection=p().settings_store.state("last_collection", {}))

    @app.get("/settings/{section_id}", response_class=HTMLResponse)
    def settings_section(request: Request, section_id: str, user: User = Depends(current_user)):
        admin(user)
        if section_id not in SECTIONS:
            raise h.HTTPError(404, "Unknown configuration section")
        return render(request, user, "settings.html", overview=p().settings_overview(), section=SECTIONS[section_id],
                      result=None, s=p().settings, row=p().settings_store.row(section_id), last_collection={})

    @app.post("/settings/{section_id}", response_class=HTMLResponse)
    async def settings_post(request: Request, section_id: str, user: User = Depends(current_user)):
        admin(user)
        form = _form_dict(await request.form())
        h.check_csrf(request, user.email, form.get("csrf"))
        if section_id not in SECTIONS:
            raise h.HTTPError(404, "Unknown configuration section")
        action, result, error, msg = form.get("action", "save"), None, None, None
        try:
            if action == "test":
                result = p().test_settings(user, section_id, form)
            else:
                changed = p().save_settings(user, section_id, form)
                msg = f"Saved and applied ({len(changed)} change{'s' if len(changed) != 1 else ''})" if changed else "No changes"
                if action == "save_test" and SECTIONS[section_id].testable:
                    result = p().test_settings(user, section_id)
        except (Invalid, Forbidden) as exc:
            error = str(exc)
        h.invalidate()
        return render(request, user, "settings.html", overview=p().settings_overview(), section=SECTIONS[section_id],
                      result=result, s=p().settings, row=p().settings_store.row(section_id), last_collection={},
                      form=form if error else None, page_msg=msg, page_err=error)

    @app.post("/collect")
    def collect_now(request: Request, csrf: str = Form(""), return_to: str = Form("/settings"),
                    user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            job = p().run_collection(user)
        except (Invalid, Forbidden) as exc:
            return back(h.safe_dest(return_to, "/settings"), err=str(exc))
        return RedirectResponse(f"/jobs/{job['RowKey']}", status_code=303)

    # ================================================================ setup wizard
    def wizard_state() -> dict:
        return p().settings_store.state("wizard", {}) or {}

    def step_status(step: dict, state: dict, user: User | None = None) -> str:
        if step["kind"] == "section":
            st = next(o["status"] for o in p().settings_overview() if o["section"].id == step["section"])
            if st in ("ok", "failed", "disabled"):
                return {"ok": "done", "failed": "failed", "disabled": "skipped"}[st]
        saved = (state.get(step["id"]) or {}).get("status", "todo")
        if step["kind"] == "readiness" and user is not None:
            ready = p().setup_readiness(user, step["id"])
            if ready["has_required"]:  # the checklist decides; "Continue" never marks it done
                return "done" if ready["ready"] else ("skipped" if saved == "skipped" else "todo")
        return saved

    @app.get("/setup", response_class=HTMLResponse)
    def setup_home(request: Request, user: User = Depends(current_user)):
        admin(user)
        state = wizard_state()
        nxt = next((s["id"] for s in STEPS if step_status(s, state, user) in ("todo", "failed")), "finish")
        return RedirectResponse(f"/setup/{nxt}", status_code=303)

    def render_step(request, user, step_id, result=None, msg=None, err=None, form=None):
        step = _step(step_id)
        if not step:
            raise h.HTTPError(404, "Unknown step")
        state = wizard_state()
        portal = p()
        idx = STEP_IDS.index(step_id)
        ctx = {"step": step, "steps": [(s_, _step(s_["id"])["title"], step_status(s_, state, user)) for s_ in STEPS],
               "index": idx, "prev_id": STEP_IDS[idx - 1] if idx else None,
               "next_id": STEP_IDS[idx + 1] if idx + 1 < len(STEP_IDS) else None, "result": result,
               "page_msg": msg, "page_err": err, "s": portal.settings, "form": form}
        if step["kind"] == "section":
            ctx.update(section=SECTIONS[step["section"]], row=portal.settings_store.row(step["section"]))
        if step["kind"] == "deployment":
            ctx["checks"] = portal.deployment_checks(request.headers.get("host", ""))
        if step["kind"] == "access":
            ctx["people"] = [u for u in portal.users() if u.get("active", True)]
        if step["kind"] == "collect":
            ctx["last"] = portal.settings_store.state("last_collection", {}) or {}
            ctx["running"] = portal.jobs.running("collect")
        if step["kind"] == "readiness":
            ctx["ready"] = portal.setup_readiness(user, step_id)
        if step["kind"] == "summary":
            ctx["program"] = [(s_["id"], _step(s_["id"])["title"], step_status(s_, state, user))
                              for s_ in STEPS if s_["kind"] == "readiness"]
            ctx["overview"] = portal.settings_overview()
            ctx["checks"] = portal.deployment_checks(request.headers.get("host", ""))
        return render(request, user, "setup.html", **ctx)

    @app.get("/setup/{step_id}", response_class=HTMLResponse)
    def setup_step(request: Request, step_id: str, user: User = Depends(current_user)):
        admin(user)
        return render_step(request, user, step_id)

    @app.post("/setup/{step_id}", response_class=HTMLResponse)
    async def setup_post(request: Request, step_id: str, user: User = Depends(current_user)):
        admin(user)
        form = _form_dict(await request.form())
        h.check_csrf(request, user.email, form.get("csrf"))
        step = _step(step_id)
        if not step:
            raise h.HTTPError(404, "Unknown step")
        action = form.get("action", "next")
        state = wizard_state()
        idx = STEP_IDS.index(step_id)
        nxt = STEP_IDS[idx + 1] if idx + 1 < len(STEP_IDS) else "finish"
        if action == "back":
            return RedirectResponse(f"/setup/{STEP_IDS[max(idx - 1, 0)]}", status_code=303)
        if action == "skip":
            state[step_id] = {"status": "skipped", "by": user.email}
            p().settings_store.set_state("wizard", state)
            p().audit(user, "setup.skip", step_id, {})
            return RedirectResponse(f"/setup/{nxt}", status_code=303)
        if step["kind"] == "section":
            try:
                p().save_settings(user, step["section"], form)
                result = p().test_settings(user, step["section"]) if action == "validate" and SECTIONS[step["section"]].testable else None
            except (Invalid, Forbidden) as exc:
                return render_step(request, user, step_id, err=str(exc), form=form)
            state[step_id] = {"status": "done" if (result is None or result["ok"]) else "failed", "by": user.email}
            p().settings_store.set_state("wizard", state)
            if result is not None:
                return render_step(request, user, step_id, result=result,
                                   msg="Saved. " + ("All checks passed." if result["ok"] else "Some checks failed; see below."))
            return render_step(request, user, step_id, msg="Saved and applied.")
        if step["kind"] != "readiness" or not p().setup_readiness(user, step_id)["has_required"]:
            state[step_id] = {"status": "done", "by": user.email}
            p().settings_store.set_state("wizard", state)
        return RedirectResponse(f"/setup/{nxt}", status_code=303)

    # ================================================================ logs
    def log_rows(q, level, category, days, audit):
        portal = p()
        rows = [{"at": r["at"], "level": r["level"], "category": r["category"], "message": r["message"],
                 "actor": r["actor"], "request_id": r["request_id"], "detail": r.get("detail") or {}, "kind": "system"}
                for r in portal.events.search(q, level, category, days)]
        if audit and not level and category in ("", "audit"):
            cutoff = (portal.today - dt.timedelta(days=days - 1)).isoformat()
            for r in portal.log.recent(2000):
                if r["at"][:10] < cutoff:
                    continue
                row = {"at": r["at"], "level": "audit", "category": "audit", "message": f"{r['action']} {r['target']}",
                       "actor": r["actor"], "request_id": r.get("request_id", ""), "detail": r.get("detail") or {},
                       "kind": "audit"}
                if not q or q.lower() in json.dumps(row, default=str).lower():
                    rows.append(row)
        return sorted(rows, key=lambda r: r["at"], reverse=True)[:1500]

    @app.get("/logs", response_class=HTMLResponse)
    def logs(request: Request, q: str = "", level: str = "", category: str = "", days: int = 7, audit: str = "",
             user: User = Depends(current_user)):
        h.need(user, "admin", "auditor")
        days = days if days in (1, 7, 30, 90) else 7
        rows = log_rows(q, level, category, days, bool(audit))
        return render(request, user, "logs.html", rows=rows, q=q, level=level, category=category, days=days,
                      audit=bool(audit), levels=LEVELS, categories=CATEGORIES)

    @app.get("/logs.csv")
    def logs_csv(q: str = "", level: str = "", category: str = "", days: int = 7, audit: str = "",
                 user: User = Depends(current_user)):
        h.need(user, "admin", "auditor")
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["at", "level", "category", "message", "actor", "request_id", "detail"])
        for r in log_rows(q, level, category, days if days in (1, 7, 30, 90) else 7, bool(audit)):
            w.writerow([r["at"], r["level"], r["category"], r["message"], r["actor"], r["request_id"],
                        json.dumps(r["detail"], default=str)])
        p().events.info("export", "Logs exported", actor=user.email, query=q, days=days)
        return h.attachment(f"grcpal-logs-{p().today}.csv", buf.getvalue().encode())

    # ================================================================ jobs
    @app.get("/jobs", response_class=HTMLResponse)
    def jobs(request: Request, user: User = Depends(current_user)):
        h.need(user, "admin", "auditor")
        return render(request, user, "jobs.html", rows=p().jobs.recent(50), job=None)

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_detail(request: Request, job_id: str, user: User = Depends(current_user)):
        h.need(user, "admin", "auditor")
        job = p().jobs.get(job_id)
        if not job:
            raise h.HTTPError(404, "Job not found")
        return render(request, user, "jobs.html", rows=[], job=job, refresh=job["status"] in ("queued", "running"))

    # ================================================================ knowledge base
    @app.get("/kb", response_class=HTMLResponse)
    def kb_index(request: Request, user: User = Depends(current_user)):
        """Evidence guidance for every SOC 2 criterion, grouped by family. Open to every signed-in role."""
        from grcpal import kb as kb_mod
        from grcpal.portal import soc2

        portal = p()
        articles, cat = portal.kb, portal.catalog
        in_scope = set(cat.in_scope_criteria)
        groups: dict[str, dict] = {}
        for cid in soc2.ordered_criteria(cat, in_scope_only=False):
            fam = soc2.family_of(cid)
            a = articles.get(cid)
            pts = cat.points_of_focus.get(cid, [])
            g = groups.setdefault(fam, {"id": fam, "name": soc2.FAMILY_NAMES.get(fam, fam), "rows": [], "in_scope": False})
            g["in_scope"] = g["in_scope"] or cid in in_scope
            g["rows"].append({"id": cid, "title": (a.title if a else cat.criteria[cid]["title"]),
                              "status": a.status if a else "missing", "points": len(pts),
                              "written": len(pts) - len(kb_mod.missing_points(cat, articles, [cid]))})
        scoped = [r for g in groups.values() if g["in_scope"] for r in g["rows"]]
        counts = {s: sum(1 for r in scoped if r["status"] == s) for s in ("reviewed", "draft", "missing")}
        return render(request, user, "kb.html", groups=list(groups.values()), counts=counts)

    @app.get("/kb/{crit_id}", response_class=HTMLResponse)
    def kb_article(request: Request, crit_id: str, user: User = Depends(current_user)):
        from grcpal.portal import soc2

        portal = p()
        cat = portal.catalog
        if crit_id not in cat.criteria:  # only known ids; nothing from the path reaches the file system
            raise h.HTTPError(404, "No such criterion")
        article = portal.kb.get(crit_id)
        order = soc2.ordered_criteria(cat, in_scope_only=crit_id in cat.in_scope_criteria)
        prev_id, next_id, _ = soc2.neighbours(order, crit_id)
        controls = [cat.control(c) for c in cat.coverage().get(crit_id, []) if portal.can_see_control(user, c)]
        sections = [{"pf": pf, "guide": article.point(pf["id"]) if article else None}
                    for pf in cat.points_of_focus.get(crit_id, [])]
        return render(request, user, "kb_article.html", crit_id=crit_id, crit=cat.criteria[crit_id], article=article,
                      sections=sections, controls=controls, prev_id=prev_id, next_id=next_id,
                      in_scope=crit_id in cat.in_scope_criteria,
                      family_name=soc2.FAMILY_NAMES.get(soc2.family_of(crit_id), ""))

    # ================================================================ frameworks
    @app.get("/frameworks", response_class=HTMLResponse)
    def frameworks(request: Request, user: User = Depends(current_user)):
        h.need(user, "admin", "auditor")
        portal = p()
        rows = []
        in_use = portal.frameworks_in_use
        for fw in portal.frameworks.values():
            cov = fw_mod.coverage(portal.catalog.controls, fw)
            covered = sum(1 for v in cov.values() if v)
            rows.append({"fw": fw, "requirements": len(fw.requirements), "covered": covered, "in_use": fw.id in in_use,
                         "controls": len({c for v in cov.values() for c in v})})
        return render(request, user, "frameworks.html", rows=rows)

    @app.post("/frameworks/{fid}/use")
    def framework_use(request: Request, fid: str, on: str = Form(""), csrf: str = Form(""),
                      user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            p().set_framework_in_use(user, fid, on == "true")
        except (Invalid, Forbidden) as exc:
            return back("/frameworks", err=str(exc))
        h.invalidate()
        return back("/frameworks", msg="Frameworks in use updated")

    @app.get("/frameworks/new", response_class=HTMLResponse)
    def framework_new(request: Request, fid: str = "", user: User = Depends(current_user)):
        library(user)
        row = p().store.get("frameworks", "f", fid) if fid else None
        return render(request, user, "framework_form.html", row=row)

    @app.post("/frameworks/new")
    def framework_save(request: Request, fid: str = Form(...), name: str = Form(""), version: str = Form(""),
                       description: str = Form(""), requirements: str = Form(""), csrf: str = Form(""),
                       user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            row = p().save_framework(user, fid, name, version, description, requirements)
        except (Invalid, Forbidden) as exc:
            return back("/frameworks/new" + (f"?fid={fid}" if fid else ""), err=str(exc))
        h.invalidate()
        return back(f"/frameworks/{row['RowKey']}", msg="Framework saved")

    @app.get("/frameworks/{fid}", response_class=HTMLResponse)
    def framework_detail(request: Request, fid: str, user: User = Depends(current_user)):
        h.need(user, "admin", "auditor")
        if fid == "soc2":  # SOC 2 has its own view with families, points of focus and navigation
            return RedirectResponse("/criteria", status_code=303)
        portal = p()
        fw = portal.frameworks.get(fid)
        if not fw:
            raise h.HTTPError(404, "Framework not found")
        cov = fw_mod.coverage(portal.catalog.controls, fw)
        stat = {c["id"]: c["status"] for c in h.health()["controls"]}
        return render(request, user, "framework.html", fw=fw, cov=cov, stat=stat)

    # ================================================================ custom controls
    @app.get("/controls/new", response_class=HTMLResponse)
    def control_new(request: Request, user: User = Depends(current_user)):
        library(user)
        return render(request, user, "control_form.html", row=None, frameworks=p().frameworks_in_use,
                      roles_list=sorted(p().base_catalog.roles), frequencies=("continuous", "daily", "weekly", "monthly",
                                                                             "quarterly", "annual", "event"))

    @app.post("/controls/new")
    async def control_create(request: Request, user: User = Depends(current_user)):
        form = _form_dict(await request.form())
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            row = p().save_custom_control(user, form)
        except (Invalid, Forbidden) as exc:
            return render(request, user, "control_form.html", row=None, frameworks=p().frameworks_in_use, form=form,
                          roles_list=sorted(p().base_catalog.roles), page_err=str(exc),
                          frequencies=("continuous", "daily", "weekly", "monthly", "quarterly", "annual", "event"))
        return back(f"/controls/{row['RowKey']}", msg="Control created. Add checks or assign evidence collection below.")

    def library(user: User) -> None:
        if not p().is_library_owner(user):
            raise h.HTTPError(403, "Only the control library owner can change control definitions")

    @app.get("/controls/{cid}/definition", response_class=HTMLResponse)
    def control_definition(request: Request, cid: str, user: User = Depends(current_user)):
        library(user)
        portal = p()
        known = portal.catalog.control(cid)
        if not known:
            raise h.HTTPError(404, "Control not found")
        if known.get("custom"):
            return RedirectResponse(f"/controls/{known['id']}/edit", status_code=303)
        try:
            d = portal.control_definition(cid)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        ctl = portal.catalog.control(cid)
        return render(request, user, "control_definition.html", ctl=ctl, d=d, form={}, frameworks=portal.frameworks_in_use,
                      roles_list=sorted(portal.base_catalog.roles), roles=portal.base_catalog.roles,
                      automated=[e for e in ctl["evidence"] if e.get("via") != "upload"])

    @app.post("/controls/{cid}/definition")
    async def control_definition_save(request: Request, cid: str, user: User = Depends(current_user)):
        form = _form_dict(await request.form())
        h.check_csrf(request, user.email, form.get("csrf"))
        portal = p()
        try:
            portal.save_control_definition(user, cid, form)
        except (Invalid, Forbidden) as exc:
            if not portal.is_library_owner(user) or not portal.catalog.control(cid):
                return back(f"/controls/{cid}", err=str(exc))
            ctl = portal.catalog.control(cid)
            return render(request, user, "control_definition.html", ctl=ctl, d=portal.control_definition(cid), form=form,
                          frameworks=portal.frameworks_in_use, roles_list=sorted(portal.base_catalog.roles),
                          roles=portal.base_catalog.roles, page_err=str(exc),
                          automated=[e for e in ctl["evidence"] if e.get("via") != "upload"])
        h.invalidate()
        return back(f"/controls/{cid}#definition-history", msg="Control updated. The change and your reason are in its history.")

    @app.post("/controls/{cid}/definition/reset")
    def control_definition_reset(request: Request, cid: str, reason: str = Form(""), csrf: str = Form(""),
                                 user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            p().reset_control_definition(user, cid, reason)
        except (Invalid, Forbidden) as exc:
            return back(f"/controls/{cid}#definition-history", err=str(exc))
        h.invalidate()
        return back(f"/controls/{cid}#definition-history", msg="Control reset to the starter definition")

    @app.get("/controls/{cid}/edit", response_class=HTMLResponse)
    def control_edit(request: Request, cid: str, user: User = Depends(current_user)):
        library(user)
        row = p().custom_control(cid)
        if not row:
            ctl = p().catalog.control(cid)
            if not ctl:
                raise h.HTTPError(404, "Control not found")
            return RedirectResponse(f"/controls/{ctl['id']}/definition", status_code=303)
        return render(request, user, "control_form.html", row=row, frameworks=p().frameworks_in_use,
                      roles_list=sorted(p().base_catalog.roles),
                      frequencies=("continuous", "daily", "weekly", "monthly", "quarterly", "annual", "event"))

    @app.post("/controls/{cid}/edit")
    async def control_update(request: Request, cid: str, user: User = Depends(current_user)):
        form = _form_dict(await request.form())
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            p().save_custom_control(user, form, existing_id=cid)
        except (Invalid, Forbidden) as exc:
            return back(f"/controls/{cid}/edit", err=str(exc))
        return back(f"/controls/{cid}", msg="Control updated")

    @app.post("/controls/{cid}/retire")
    def control_retire(request: Request, cid: str, reason: str = Form(""), csrf: str = Form(""),
                       user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            p().retire_custom_control(user, cid, reason)
        except (Invalid, Forbidden) as exc:
            return back(f"/controls/{cid}", err=str(exc))
        return back("/controls", msg=f"{cid} retired")

    # ================================================================ checks
    @app.post("/controls/{cid}/checks")
    async def check_create(request: Request, cid: str, user: User = Depends(current_user)):
        form = _form_dict(await request.form())
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            row = p().save_check(user, cid, form)
            msg = f"Check {row['RowKey']} created"
            if form.get("run_now"):
                res = p().run_check(user, row["RowKey"])
                msg += f" and run: {res['summary']}"
        except ValueError as exc:
            return back(f"/controls/{cid}#checks", err=f"Assertions: {exc}")
        except (Invalid, Forbidden) as exc:
            return back(f"/controls/{cid}#checks", err=str(exc))
        return back(f"/controls/{cid}#checks", msg=msg)

    @app.post("/checks/{check_id}/run")
    def check_run(request: Request, check_id: str, return_to: str = Form("/controls"), csrf: str = Form(""),
                  user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        dest = h.safe_dest(return_to, "/controls")
        try:
            res = p().run_check(user, check_id)
        except (Invalid, Forbidden) as exc:
            return back(dest, err=str(exc))
        return back(dest, msg=f"{check_id}: {'passed' if res['ok'] else 'failed'} ({res['summary']})")

    @app.post("/checks/{check_id}/delete")
    def check_delete(request: Request, check_id: str, return_to: str = Form("/controls"), csrf: str = Form(""),
                     user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        dest = h.safe_dest(return_to, "/controls")
        try:
            p().delete_check(user, check_id)
        except (Invalid, Forbidden) as exc:
            return back(dest, err=str(exc))
        return back(dest, msg=f"Check {check_id} turned off; its past results stay in the evidence store")

    # ================================================================ AI assistant
    @app.post("/controls/{cid}/ai-review")
    def ai_review(request: Request, cid: str, csrf: str = Form(""), user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            row = p().ai_review(user, cid, h.status_of(cid))
        except (Invalid, Forbidden) as exc:
            return back(f"/controls/{cid}#ai", err=str(exc))
        if row["verdict"] == "error":
            return back(f"/controls/{cid}#ai", err=f"The AI review failed: {row['error']}")
        return back(f"/controls/{cid}#ai", msg=f"AI review ready: {VERDICT_LABELS.get(row['verdict'], row['verdict'])}. "
                                               "Accept or dismiss it below.")

    @app.post("/controls/{cid}/ai/{rid}/disposition")
    def ai_disposition(request: Request, cid: str, rid: str, decision: str = Form(...), note: str = Form(""),
                       csrf: str = Form(""), user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            row = p().ai_disposition(user, cid, rid, decision, note)
        except (Invalid, Forbidden) as exc:
            return back(f"/controls/{cid}#ai", err=str(exc))
        return back(f"/controls/{cid}#ai", msg=f"AI review {row['disposition']}")

    @app.get("/ai", response_class=HTMLResponse)
    def ai_home(request: Request, user: User = Depends(current_user)):
        h.need(user, "admin", "auditor")
        portal = p()
        scope_sizes = {}
        for fid in portal.frameworks:
            try:
                scope_sizes[fid] = len(portal.ai_audit_scope(fid))
            except Invalid:
                scope_sizes[fid] = 0
        return render(request, user, "ai.html", ai=portal.ai_status(), audits=portal.ai_audits(),
                      frameworks=portal.frameworks_in_use, scope_sizes=scope_sizes, running=portal.jobs.running("ai_audit"))

    @app.post("/ai/audits")
    def ai_audit_start(request: Request, framework: str = Form("soc2"), limit: int = Form(0), csrf: str = Form(""),
                       user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        try:
            started = p().start_ai_audit(user, framework, h.status_of, max(0, limit))
        except (Invalid, Forbidden) as exc:
            return back("/ai", err=str(exc))
        return RedirectResponse(f"/jobs/{started['job']}", status_code=303)

    @app.get("/ai/audits/{audit_id}", response_class=HTMLResponse)
    def ai_audit_view(request: Request, audit_id: str, user: User = Depends(current_user)):
        h.need(user, "admin", "auditor")
        try:
            row = p().ai_audit(audit_id)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        return render(request, user, "ai_audit.html", a=row, verdict_labels=VERDICT_LABELS)

    @app.get("/ai/audits/{audit_id}/report.html")
    def ai_audit_report(request: Request, audit_id: str, user: User = Depends(current_user)):
        h.need(user, "admin", "auditor")
        try:
            row = p().ai_audit(audit_id)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        html = h.templates.get_template("ai_report.html").render(a=row, org=p().org, verdict_labels=VERDICT_LABELS)
        return Response(html.encode(), media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="grcpal-mock-audit-{audit_id}.html"',
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox"})


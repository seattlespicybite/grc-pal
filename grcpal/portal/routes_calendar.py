"""Security calendar pages (admins only): the year view, one month of an activity, the activity editor,
the run history of an automated activity, and a CSV export. Rules and authorization live in calendar.py."""
from __future__ import annotations

import calendar as _cal
import csv
import io

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse

from grcpal.portal.auth import User
from grcpal.portal.security import csv_cell
from grcpal.portal.automation import DIGESTS
from grcpal.portal.calendar import AUTO_STATUSES, DUE_DAYS, KEY_RE, STATUSES
from grcpal.portal.service import Forbidden, Invalid

MONTHS = [_cal.month_abbr[m] for m in range(1, 13)]


_csv_cell = csv_cell  # kept for older imports


def register(app, h) -> None:
    p, current_user, render, back = h.p, h.current_user, h.render, h.back

    def admin(user: User) -> None:
        h.need(user, "admin")

    def clamp_year(year: int) -> int:
        return year if 2000 <= year <= 2100 else p().today.year

    @app.get("/calendar", response_class=HTMLResponse)
    def calendar_page(request: Request, year: int = 0, auto: str = "1", user: User = Depends(current_user)):
        admin(user)
        portal = p()
        year = clamp_year(year)
        show_auto = auto != "0"
        data = portal.calendar_year(year, show_automated=show_auto)
        cells = [c for a in data["manual"] for c in a["cells"] if c]
        counts = {"past_due": sum(1 for c in cells if c["past_due"]),
                  "performed": sum(1 for c in cells if c["status"] == "performed"),
                  "missed": sum(1 for c in cells if c["status"] == "missed"), "total": len(cells),
                  "activities": len(data["manual"]), "automated": len(data["automated"])}
        this_month = portal.today.month if year == portal.today.year else 0
        return render(request, user, "calendar.html", nav_active="calendar", year=year, show_auto=show_auto,
                      manual=data["manual"], automated=data["automated"], counts=counts,
                      months=MONTHS, this_month=this_month, labels=STATUSES, auto_labels=AUTO_STATUSES,
                      program_start=portal.calendar_program_start(), vendor_months=portal.vendor_calendar(year))

    @app.get("/calendar.csv")
    def calendar_csv(year: int = 0, user: User = Depends(current_user)):
        admin(user)
        year = clamp_year(year)
        rows = p().calendar_export_rows(f"{year}-01-01", f"{year}-12-31")
        cols = ["occurrence", "activity", "title", "month", "scheduled_due", "moved_to", "status", "past_due",
                "performed_on", "recorded_by", "recorded_at", "note", "controls"]
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        for r in rows:
            w.writerow([_csv_cell(r[c]) for c in cols])
        p().events.info("export", "Calendar exported", actor=user.email, year=year)
        return h.attachment(f"grcpal-calendar-{year}.csv", buf.getvalue().encode())

    # ---------------------------------------------------------------- one month of a manual activity
    @app.get("/calendar/o/{key}", response_class=HTMLResponse)
    def calendar_occurrence(request: Request, key: str, popup: int = 0, user: User = Depends(current_user)):
        admin(user)
        portal = p()
        if popup:
            return occurrence_popup(request, user, key)
        try:
            occ = portal.calendar_occurrence(key)
        except Invalid as exc:
            m = KEY_RE.match(key or "")
            act = None
            if m and 1 <= int(m.group(3)) <= 12:
                try:
                    act = portal.calendar_activity(m.group(1))
                except Invalid:
                    act = None
            if act and act["kind"] == "manual" and act["status"] == "active":
                return render(request, user, "calendar_add.html", nav_active="calendar", act=act, key=key,
                              year=int(m.group(2)), month_name=_cal.month_name[int(m.group(3))])
            raise h.HTTPError(404, str(exc)) from exc
        in_scope = set(portal.catalog.in_scope_criteria)
        window_start = f"{occ['year']}-{occ['month']:02d}-01"
        window_end = max(occ["due"], f"{occ['year']}-{occ['month']:02d}-31")
        controls = []
        for cid in occ["controls"]:
            ctl = portal.catalog.control(cid)
            if not ctl:
                continue
            uploads = [u for u in portal.uploads(control=cid, cycle=None)
                       if window_start <= u["uploaded_at"][:10] <= window_end]
            controls.append({"id": cid, "title": ctl["title"], "note": (portal.control_note(cid) or {}).get("text", ""),
                             "kb": [c for c in ctl.get("criteria", []) if c in in_scope and c in portal.kb],
                             "uploads": uploads})
        return render(request, user, "calendar_occurrence.html", nav_active="calendar", occ=occ,
                      act=occ["activity_info"], controls=controls, labels=STATUSES,
                      month_name=_cal.month_name[occ["month"]], window_end=window_end[:7])

    def occurrence_popup(request: Request, user: User, key: str):
        """The calendar's popup: the Record form, or the Add form for a month that is not scheduled.
        Saving comes back to the same row of the calendar, so the person never leaves the calendar."""
        portal = p()
        m = KEY_RE.match(key or "")
        if not m or not 1 <= int(m.group(3)) <= 12:
            raise h.HTTPError(404, "No such calendar entry")
        year, month = int(m.group(2)), int(m.group(3))
        try:
            act = portal.calendar_activity(m.group(1))
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        try:
            occ = portal.calendar_occurrence(key)
        except Invalid as exc:
            if act["kind"] != "manual" or act["status"] != "active":
                raise h.HTTPError(404, str(exc)) from exc
            occ = None
        return render(request, user, "calendar_popup.html", occ=occ, act=act, key=key, year=year, labels=STATUSES,
                      month_name=_cal.month_name[month], full_url=f"/calendar/o/{key}",
                      return_to=f"/calendar?year={year}#row-{act['id']}")

    @app.post("/calendar/o/{key}/add")
    async def calendar_occurrence_add(request: Request, key: str, user: User = Depends(current_user)):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            p().add_occurrence(user, key)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/calendar", err=str(exc))
        h.invalidate()
        return back(h.safe_dest(str(form.get("return_to", "")), f"/calendar/o/{key}"), msg="Added for this month")

    @app.post("/calendar/order")
    async def calendar_order(request: Request, user: User = Depends(current_user)):
        """Drag and drop: the new order of one group, as comma-separated ids."""
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        ids = [i.strip() for i in str(form.get("ids", "")).split(",") if i.strip()][:500]
        try:
            p().set_calendar_order(user, str(form.get("kind", "")), ids)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/calendar", err=str(exc))
        return back(h.safe_dest(str(form.get("return_to", "")), "/calendar"))

    @app.post("/calendar/a/{aid}/move")
    async def calendar_move(request: Request, aid: str, user: User = Depends(current_user)):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        try:
            p().move_activity(user, aid, str(form.get("direction", "")))
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back("/calendar", err=str(exc))
        return back(h.safe_dest(str(form.get("return_to", "")), "/calendar") + f"#row-{aid}")

    @app.post("/calendar/o/{key}")
    async def calendar_occurrence_save(request: Request, key: str, user: User = Depends(current_user)):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        dest = f"/calendar/o/{key}" if len(key) < 100 else "/calendar"
        try:
            occ = p().update_occurrence(user, key, str(form.get("status", "")), str(form.get("completed_on", "")),
                                        str(form.get("note", "")), str(form.get("move_to", "")))
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(dest, err=str(exc))
        h.invalidate()
        dest = h.safe_dest(str(form.get("return_to", "")), f"/calendar?year={occ['period'][:4]}")
        return back(dest, msg=f"Saved: {STATUSES[occ['decision']]}")

    # ---------------------------------------------------------------- email alerts and digests
    @app.get("/calendar/notifications", response_class=HTMLResponse)
    def calendar_notifications(request: Request, user: User = Depends(current_user)):
        admin(user)
        return render(request, user, "calendar_notifications.html", nav_active="calendar",
                      prefs=p().notify_prefs(user), digests=DIGESTS)

    @app.post("/calendar/notifications")
    async def calendar_notifications_save(request: Request, user: User = Depends(current_user)):
        raw = await request.form()
        h.check_csrf(request, user.email, raw.get("csrf"))
        try:
            p().set_notify_prefs(user, raw.get("alerts") == "1", [str(d) for d in raw.getlist("digests")])
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        return back("/calendar/notifications", msg="Email settings saved")

    # ---------------------------------------------------------------- activities
    def activity_page(request, user, act: dict, form: dict | None = None, error: str | None = None):
        portal = p()
        selected = set((form or {}).get("controls") or act.get("controls") or [])
        controls = sorted(portal.catalog.controls, key=lambda c: (c["id"] not in selected, c["id"]))
        sources = portal.automated_sources()
        return render(request, user, "calendar_activity.html", nav_active="calendar", act=act, form=form or act,
                      selected=selected, controls=controls, months=MONTHS, due_days=DUE_DAYS, sources=sources,
                      in_scope=portal.in_scope_controls(), page_err=error)

    @app.get("/calendar/a/new", response_class=HTMLResponse)
    def calendar_activity_new(request: Request, user: User = Depends(current_user)):
        admin(user)
        blank = {"id": "new", "title": "", "kind": "manual", "months": [], "due_day": "15", "controls": [],
                 "owner": "", "instructions": "", "source": "", "status": "active", "has_records": False}
        return activity_page(request, user, blank)

    @app.get("/calendar/a/{aid}", response_class=HTMLResponse)
    def calendar_activity(request: Request, aid: str, user: User = Depends(current_user)):
        admin(user)
        try:
            act = p().calendar_activity(aid)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        return activity_page(request, user, act)

    @app.post("/calendar/a/{aid}")
    async def calendar_activity_save(request: Request, aid: str, user: User = Depends(current_user)):
        raw = await request.form()
        h.check_csrf(request, user.email, raw.get("csrf"))
        form = {k: str(raw.get(k, "")) for k in ("title", "kind", "due_day", "owner", "instructions", "source")}
        form["months"] = [str(m) for m in raw.getlist("months")]
        form["controls"] = [str(c) for c in raw.getlist("controls")]
        form["clear_past"] = raw.get("clear_past") == "1"
        portal = p()
        try:
            row = portal.save_activity(user, aid, form)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            try:
                act = portal.calendar_activity(aid) if aid != "new" else {"id": "new", "has_records": False,
                                                                          "status": "active"}
            except Invalid:
                raise h.HTTPError(404, "No such activity") from exc
            merged = {**act, **form, "months": [int(m) for m in form["months"] if m.isdigit()]}
            return activity_page(request, user, {**act, "id": aid}, merged, str(exc))
        h.invalidate()
        return back("/calendar", msg=f"Saved activity: {row['title']}")

    @app.post("/calendar/a/{aid}/status")
    async def calendar_activity_status(request: Request, aid: str, user: User = Depends(current_user)):
        form = await request.form()
        h.check_csrf(request, user.email, form.get("csrf"))
        action = str(form.get("action", ""))
        try:
            if action == "delete":
                p().delete_activity(user, aid)
                msg = "Activity deleted"
            else:
                p().set_activity_status(user, aid, "retired" if action == "retire" else "active",
                                        str(form.get("reason", "")))
                msg = "Activity retired; its history is kept" if action == "retire" else "Activity reactivated"
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(f"/calendar/a/{aid}" if len(aid) < 100 else "/calendar", err=str(exc))
        h.invalidate()
        return back("/calendar", msg=msg)

    # ---------------------------------------------------------------- automated run history
    @app.get("/calendar/auto/{source}", response_class=HTMLResponse)
    def calendar_auto(request: Request, source: str, user: User = Depends(current_user)):
        admin(user)
        portal = p()
        info = portal.automated_sources().get(source)
        if not info:
            raise h.HTTPError(404, "Unknown automated activity")
        return render(request, user, "calendar_auto.html", nav_active="calendar", source=source, info=info,
                      runs=portal.automated_runs(source), auto_labels=AUTO_STATUSES)

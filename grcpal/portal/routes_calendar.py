"""Security calendar pages: year, month and list views, one occurrence, one automated activity, CSV.

Admins and auditors can read; only admins record decisions (checked again in calendar.py)."""
from __future__ import annotations

import calendar as _cal
import csv
import datetime as dt
import io

from fastapi import Depends, Form, Request
from fastapi.responses import HTMLResponse

from grcpal.portal.auth import User
from grcpal.portal.calendar import DECISIONS, STATUS_LABELS
from grcpal.portal.service import Forbidden, Invalid

VIEWS = ("year", "month", "list")
FILTERS = ("", "needs_decision", "open", "planned", "decided")


def _csv_cell(value) -> str:
    """Stop spreadsheet formula injection: text starting with = + - @ is prefixed with a quote."""
    text = ", ".join(value) if isinstance(value, list) else str(value if value is not None else "")
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def register(app, h) -> None:
    p, current_user, render, back = h.p, h.current_user, h.render, h.back

    def readers(user: User) -> None:
        h.need(user, "admin", "auditor")

    def clamp_year(year: int) -> int:
        today = p().today
        return year if 2000 <= year <= 2100 else today.year

    @app.get("/calendar", response_class=HTMLResponse)
    def calendar_page(request: Request, view: str = "year", year: int = 0, month: int = 0, status: str = "",
                      auto: str = "1", user: User = Depends(current_user)):
        readers(user)
        portal = p()
        today = portal.today
        view = view if view in VIEWS else "year"
        year = clamp_year(year)
        month = month if 1 <= month <= 12 else (today.month if year == today.year else 1)
        status = status if status in FILTERS else ""
        show_auto = auto != "0"
        occs = portal.calendar_occurrences(year)
        automated = portal.calendar_automated() if show_auto else []
        counts = {
            "needs_decision": sum(1 for o in occs if o["status"] == "needs_decision"),
            "open": sum(1 for o in occs if o["status"] == "open"),
            "soon": sum(1 for o in occs if o["status"] in ("open", "planned")
                        and today.isoformat() <= o["due_date"] <= (today + dt.timedelta(days=30)).isoformat()),
            "decided": sum(1 for o in occs if o["status"] in DECISIONS),
            "total": len(occs),
        }
        ctx = {"cal_view": view, "program_start": portal.calendar_program_start(), "year": year, "month": month, "status": status, "show_auto": show_auto,
               "counts": counts, "labels": STATUS_LABELS, "month_name": _cal.month_name[month],
               "month_abbr": [_cal.month_abbr[m] for m in range(1, 13)], "this_month": today.month if year == today.year else 0}
        if view == "year":
            rows: dict[str, dict] = {}
            for o in occs:
                row = rows.setdefault(o["activity"], {"id": o["activity"], "title": o["title"], "controls": o["controls"],
                                                      "cells": [[] for _ in range(12)]})
                row["cells"][o["due_month"] - 1].append(o)
            for act in portal.calendar_activities():  # activities with nothing due this year still get a row
                rows.setdefault(act["id"], {"id": act["id"], "title": act["title"], "controls": act["controls"],
                                            "cells": [[] for _ in range(12)]})
            ctx["rows"] = sorted(rows.values(), key=lambda r: r["title"])
            for a in automated:
                cells = [set() for _ in range(12)]
                for run in a["runs"]:
                    if run[:4] == str(year):
                        cells[int(run[5:7]) - 1].add(run[:10])
                a["month_days"] = [len(c) for c in cells]
            ctx["automated"] = automated
        elif view == "month":
            by_day: dict[str, list] = {}
            for o in occs:
                by_day.setdefault(o["due_date"], []).append(o)
            if month == 1 or month == 12:  # occurrences due in the edge weeks of the neighbouring years
                for o in portal.calendar_occurrences(year - 1 if month == 1 else year + 1):
                    by_day.setdefault(o["due_date"], []).append(o)
            auto_by_day: dict[str, list] = {}
            for a in automated:
                for day in sorted({r[:10] for r in a["runs"]}):
                    auto_by_day.setdefault(day, []).append(a["title"])
            weeks = []
            for week in _cal.Calendar(firstweekday=0).monthdatescalendar(year, month):
                weeks.append([{"date": d.isoformat(), "day": d.day, "in_month": d.month == month,
                               "today": d == today, "due": by_day.get(d.isoformat(), []),
                               "autos": auto_by_day.get(d.isoformat(), [])} for d in week])
            ctx["weeks"] = weeks
            prev_m = dt.date(year, month, 1) - dt.timedelta(days=1)
            next_m = dt.date(year, month, 28) + dt.timedelta(days=7)
            ctx["prev"] = {"year": prev_m.year, "month": prev_m.month, "name": _cal.month_abbr[prev_m.month]}
            ctx["next"] = {"year": next_m.year, "month": next_m.month, "name": _cal.month_abbr[next_m.month]}
            ctx["automated"] = automated
        else:
            if status == "decided":
                occs = [o for o in occs if o["status"] in DECISIONS]
            elif status:
                occs = [o for o in occs if o["status"] == status]
            ctx["occurrences"] = occs
            ctx["automated"] = automated
        return render(request, user, "calendar.html", nav_active="calendar", **ctx)

    @app.get("/calendar.csv")
    def calendar_csv(year: int = 0, user: User = Depends(current_user)):
        readers(user)
        year = clamp_year(year)
        rows = p().calendar_export_rows(f"{year}-01-01", f"{year}-12-31")
        buf = io.StringIO()
        cols = ["occurrence", "activity", "title", "period", "opens", "due", "controls", "status", "performed_on",
                "decided_by", "decided_at", "decision_version", "reason"]
        w = csv.writer(buf)
        w.writerow(cols)
        for r in rows:
            w.writerow([_csv_cell(r[c]) for c in cols])
        p().events.info("export", "Calendar exported", actor=user.email, year=year)
        return h.attachment(f"grcpal-calendar-{year}.csv", buf.getvalue().encode())

    @app.get("/calendar/o/{key}", response_class=HTMLResponse)
    def calendar_occurrence(request: Request, key: str, user: User = Depends(current_user)):
        readers(user)
        portal = p()
        try:
            occ = portal.calendar_occurrence(key)
        except Invalid as exc:
            raise h.HTTPError(404, str(exc)) from exc
        in_scope = set(portal.catalog.in_scope_criteria)
        controls = []
        for cid in occ["controls"]:
            ctl = portal.catalog.control(cid)
            if not ctl:
                continue
            note = portal.control_note(cid)
            uploads = [u for u in portal.uploads(control=cid, cycle=None)
                       if occ["opens"] <= u["uploaded_at"][:10] <= occ["window_end"]]
            controls.append({"id": cid, "title": ctl["title"], "note": (note or {}).get("text", ""),
                             "kb": [c for c in ctl.get("criteria", []) if c in in_scope and c in portal.kb],
                             "uploads": uploads})
        requests = [a for a in portal.assignments(cycle=None)
                    if a.get("task") == occ["activity"] and a.get("period") == occ["period"]]
        return render(request, user, "calendar_occurrence.html", nav_active="calendar", occ=occ,
                      act=occ["activity_info"], controls=controls, requests=requests, labels=STATUS_LABELS,
                      decisions=DECISIONS, can_decide=user.is_admin and occ["status"] != "planned")

    @app.post("/calendar/o/{key}/decide")
    def calendar_decide(request: Request, key: str, csrf: str = Form(""), decision: str = Form(""),
                        completed_on: str = Form(""), reason: str = Form(""), user: User = Depends(current_user)):
        h.check_csrf(request, user.email, csrf)
        dest = f"/calendar/o/{key}" if len(key) < 90 else "/calendar"
        try:
            p().decide_occurrence(user, key, decision, completed_on, reason)
        except Forbidden as exc:
            raise h.HTTPError(403, str(exc)) from exc
        except Invalid as exc:
            return back(dest, err=str(exc))
        h.invalidate()
        return back(dest, msg=f"Recorded: {DECISIONS[decision]}")

    @app.get("/calendar/auto/{source}", response_class=HTMLResponse)
    def calendar_auto(request: Request, source: str, user: User = Depends(current_user)):
        readers(user)
        portal = p()
        info = next((a for a in portal.calendar_automated() if a["id"] == source), None)
        if not info:
            raise h.HTTPError(404, "Unknown automated activity")
        return render(request, user, "calendar_auto.html", nav_active="calendar", info=info,
                      runs=portal.automated_runs(source))

"""Security calendar: one year view of every recurring compliance activity. Admins only.

Plain model:
- An activity is something that must happen on a schedule (access review, DR test, ...) or an automated
  evidence source (a collector or a check). Admins add, edit, retire or delete activities in the portal.
  The starter activities in `catalog/tasks.yaml` are copied in the first time the calendar opens.
- A manual activity's schedule is the months it is due and the due day (1st, 15th or last day). Every
  edit is a new version that applies from the month it was made, so months already past never change.
- An occurrence is one month of a manual activity. It stays Planned until an admin records Performed
  (with the date) or Missed (with a reason). GRC-pal never decides this. Every change, including moving
  the due date, is a new row (append-only) and is written to the hash-chained audit log.
- Automated activities take their monthly status from real runs: Passed, Findings, Failed or Not run.
"""
from __future__ import annotations

import calendar as _cal
import datetime as dt
import json
import re

from grcpal import frameworks as fw_mod

STATUSES = {"planned": "Planned", "performed": "Performed", "missed": "Missed"}
AUTO_STATUSES = {"passed": "Passed", "findings": "Findings", "failed": "Failed", "notrun": "Not run"}
LEGACY = {"performed_late": "performed", "not_performed": "missed", "not_applicable": "missed"}
DUE_DAYS = {"1": "1st", "15": "15th", "last": "Last day"}
KINDS = ("manual", "automated")
TITLE_MAX, OWNER_MAX, STEPS_MAX, NOTE_MAX = 120, 120, 4000, 2000
KEY_RE = re.compile(r"^([a-z0-9][a-z0-9_-]{0,79})~(\d{4})-(\d{2})$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,79}$")
SEED_EFFECTIVE = "2000-01-01"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def due_date(year: int, month: int, due_day: str) -> str:
    last = _cal.monthrange(year, month)[1]
    day = last if str(due_day) == "last" else min(int(due_day or 15), last)
    return dt.date(year, month, day).isoformat()


def month_end(year: int, month: int) -> str:
    return dt.date(year, month, _cal.monthrange(year, month)[1]).isoformat()


def cadence(months: list[int]) -> str:
    n = len(months)
    return {12: "Monthly", 4: "Quarterly", 2: "Twice a year", 1: "Annual", 0: "Not scheduled"}.get(n, f"{n} times a year")


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return (s or "activity")[:60].strip("-")


class CalendarMixin:
    """Calendar logic for the Portal. Every read and write is for admins; writes are audited."""

    # ================================================================ scope
    def _calendar_scope(self) -> tuple[list, set[str]]:
        return list(self.frameworks_in_use.values()), set(self.catalog.in_scope_criteria)

    def _in_use_framework(self, control_ids: list[str], scope: tuple | None = None) -> bool:
        """Shown when a linked control maps to a framework switched on (for SOC 2: an in-scope criterion),
        so ISO-only or Privacy-only activities stay hidden while those are off. No control: shown."""
        if not control_ids:
            return True
        frameworks, in_scope = scope or self._calendar_scope()
        for cid in control_ids:
            ctl = self.catalog.control(cid)
            if not ctl:
                continue
            for fw in frameworks:
                reqs = fw_mod.requirements_of(ctl, fw)
                if fw.id == "soc2":
                    reqs = [r for r in reqs if r in in_scope]
                if reqs:
                    return True
        return False

    def calendar_program_start(self) -> str:
        """Past-due warnings start with the first audit cycle (the observation period)."""
        self.ensure_cycle()
        return min(c["start"] for c in self.store.list("cycles", "c"))

    # ================================================================ activities
    def _seed_activities(self) -> None:
        """Copy the starter activities from tasks.yaml once. Deleted ones never come back."""
        if self.settings_store.state("calendar:seeded", False) or self.store.list("calendaractivities", "a"):
            return
        from grcpal.portal.auth import SYSTEM

        by_task = self.catalog.sources("task")
        now = _now()
        for name, task in self.catalog.tasks.items():
            if not ID_RE.match(name):
                continue
            controls = sorted(set(by_task.get(name, [])) | set(task.get("controls") or []))
            due = str(task.get("due_day") or ("15" if int(task.get("due_days", 30)) <= 21 else "last"))
            snap = {"title": str(task.get("title", name))[:TITLE_MAX], "kind": "manual",
                    "months": sorted({int(m) for m in task.get("months") or [] if 1 <= int(m) <= 12}),
                    "due_day": due if due in DUE_DAYS else "15", "controls": controls, "source": "",
                    "owner": (self.catalog.roles.get(task.get("owner")) or {}).get("title", ""),
                    "instructions": "\n".join(f"- {c}" for c in task.get("checklist") or [])[:STEPS_MAX], "status": "active"}
            self._write_activity(name, snap, 1, SEED_EFFECTIVE, SYSTEM.email, now, insert=True)
        self.settings_store.set_state("calendar:seeded", True)
        self.audit(SYSTEM, "calendar.seed", "calendar", {"activities": len(self.catalog.tasks)})

    def _write_activity(self, aid: str, snap: dict, version: int, effective: str, by: str, at: str,
                        insert: bool = False) -> dict:
        row = {"PartitionKey": "a", "RowKey": aid, "id": aid, **snap, "version": version, "updated_by": by,
               "updated_at": at}
        if insert or not self.store.get("calendaractivities", "a", aid):
            self.store.insert("calendaractivities", row)
        else:
            self.store.update("calendaractivities", "a", aid,
                              {k: v for k, v in row.items() if k not in ("PartitionKey", "RowKey")})
        self.store.insert("calendarversions", {"PartitionKey": "v", "RowKey": f"{aid}~{version:04d}", "activity": aid,
                                               "version": version, "effective": effective, **snap, "by": by, "at": at})
        return row

    def automated_sources(self) -> dict[str, dict]:
        """Collectors switched on and custom checks: source id -> default title and controls."""
        from grcpal.collectors import NAMES, disabled_sources

        skip = disabled_sources(self.catalog, self.settings)
        by_collector = self.catalog.sources("collector")
        out = {}
        for name in NAMES:
            if name not in skip and by_collector.get(name):
                out[name] = {"title": f"Collector: {name.replace('_', ' ')}", "controls": sorted(by_collector[name]),
                             "schedule": "Daily collection"}
        for chk in self.all_checks():
            cid = chk.get("id") or chk.get("RowKey")
            if cid:
                out[f"check-{cid}"] = {"title": f"Check: {chk.get('title') or cid}",
                                       "controls": [chk["control"]] if chk.get("control") else [],
                                       "schedule": {"daily": "Daily check", "weekly": "Weekly check"}.get(
                                           chk.get("schedule", "daily"), "Manual check")}
        return out

    def calendar_activities(self, include_retired: bool = False, include_hidden: bool = False) -> list[dict]:
        """Manual activities (stored) and automated ones (one per source; stored only once edited)."""
        self._seed_activities()
        stored = {r["RowKey"]: r for r in self.store.list("calendaractivities", "a")}
        sources = self.automated_sources()
        rows = [r for r in stored.values() if r.get("kind") == "manual"]
        for src, info in sources.items():
            aid = f"auto-{src}"
            rows.append(stored.get(aid) or {"id": aid, "RowKey": aid, "title": info["title"], "kind": "automated",
                                            "months": [], "due_day": "", "controls": info["controls"], "source": src,
                                            "owner": "", "instructions": "", "status": "active", "version": 0})
        scope = self._calendar_scope()
        out = []
        for r in rows:
            a = dict(r)
            a["id"] = a.get("id") or a["RowKey"]
            a["months"] = sorted(int(m) for m in a.get("months") or [])
            a["controls"] = list(a.get("controls") or [])
            # Hide out-of-scope starter and automated activities; never hide one an admin created.
            a["starter"] = a["kind"] == "automated" or a["id"] in self.catalog.tasks
            a["visible"] = not a["starter"] or self._in_use_framework(a["controls"], scope)
            a["schedule"] = (sources.get(a.get("source"), {}).get("schedule", "Automated") if a["kind"] == "automated"
                             else f"{cadence(a['months'])}, due {DUE_DAYS.get(str(a.get('due_day')), '15th').lower()}")
            if (a["status"] == "retired" and not include_retired) or (not a["visible"] and not include_hidden):
                continue
            out.append(a)
        order = self.calendar_order()
        default = sorted(out, key=lambda a: (a["kind"] != "manual", -len(a["months"]), a["title"].lower()))
        rank = {a["id"]: i for i, a in enumerate(default)}
        return sorted(default, key=lambda a: (a["kind"] != "manual", order.get(a["kind"], {}).get(a["id"], 10 ** 6),
                                              rank[a["id"]]))

    # ================================================================ order (admins arrange rows)
    def calendar_order(self) -> dict[str, dict[str, int]]:
        saved = self.settings_store.state("calendar:order", {}) or {}
        return {k: {aid: i for i, aid in enumerate(saved.get(k) or [])} for k in KINDS}

    def set_calendar_order(self, actor, kind: str, ids: list[str]) -> list[str]:
        """Save the order of one group (manual or automated). Unknown ids are ignored; activities left out keep
        their place after the ones given."""
        self._admin(actor)
        if kind not in KINDS:
            raise self._invalid("Unknown group")
        current = [a["id"] for a in self.calendar_activities(include_retired=True) if a["kind"] == kind]
        given = [i for i in dict.fromkeys(ids) if i in current]
        new = given + [i for i in current if i not in given]
        saved = self.settings_store.state("calendar:order", {}) or {}
        if saved.get(kind) == new:
            return new
        saved[kind] = new
        self.settings_store.set_state("calendar:order", saved)
        self.audit(actor, "calendar.order", kind, {"count": len(new), "first": new[:5]})
        return new

    def move_activity(self, actor, aid: str, direction: str) -> list[str]:
        """Move one row up or down within its group."""
        act = self.calendar_activity(aid)
        ids = [a["id"] for a in self.calendar_activities(include_retired=True) if a["kind"] == act["kind"]]
        if aid not in ids or direction not in ("up", "down"):
            raise self._invalid("Cannot move that activity")
        i = ids.index(aid)
        j = i - 1 if direction == "up" else i + 1
        if 0 <= j < len(ids):
            ids[i], ids[j] = ids[j], ids[i]
        return self.set_calendar_order(actor, act["kind"], ids)

    def in_scope_controls(self) -> set[str]:
        """Controls that map to a framework in use (for SOC 2: an in-scope criterion)."""
        scope = self._calendar_scope()
        return {c["id"] for c in self.catalog.controls if self._in_use_framework([c["id"]], scope)}

    def calendar_activity(self, aid: str) -> dict:
        a = next((x for x in self.calendar_activities(include_retired=True, include_hidden=True) if x["id"] == aid), None)
        if not a:
            raise self._invalid("No such activity")
        a["has_records"] = any(r["activity"] == aid for r in self.store.list("calendardecisions", "d"))
        return a

    def _activity_form(self, form: dict, current: dict | None) -> dict:
        kind = form.get("kind") or (current or {}).get("kind") or "manual"
        if kind not in KINDS:
            raise self._invalid("Type must be manual or automated")
        title = " ".join((form.get("title") or "").split())
        if not 3 <= len(title) <= TITLE_MAX:
            raise self._invalid(f"Give the activity a name (3 to {TITLE_MAX} characters)")
        controls = sorted({c.strip() for c in form.get("controls") or [] if c.strip()})
        for cid in controls:
            if not self.catalog.control(cid):
                raise self._invalid(f"Unknown control {cid}")
        owner = (form.get("owner") or "").strip()
        steps = (form.get("instructions") or "").replace("\r\n", "\n").strip()
        if len(owner) > OWNER_MAX or len(steps) > STEPS_MAX:
            raise self._invalid(f"Owner is limited to {OWNER_MAX} and steps to {STEPS_MAX} characters")
        snap = {"title": title, "kind": kind, "controls": controls, "owner": owner, "instructions": steps, "status": "active"}
        if kind == "manual":
            try:
                months = sorted({int(m) for m in form.get("months") or []})
            except ValueError as exc:
                raise self._invalid("Months must be 1 to 12") from exc
            if not months:
                raise self._invalid("Tick at least one month")
            if not set(months) <= set(range(1, 13)):
                raise self._invalid("Months must be 1 to 12")
            due = str(form.get("due_day") or "")
            if due not in DUE_DAYS:
                raise self._invalid("Due day must be the 1st, the 15th or the last day")
            snap.update(months=months, due_day=due, source="")
        else:
            source = (current or {}).get("source") or form.get("source") or ""
            if source not in self.automated_sources():
                raise self._invalid("Choose a collector or check that is switched on")
            snap.update(months=[], due_day="", source=source)
        return snap

    def save_activity(self, actor, aid: str, form: dict) -> dict:
        """Create (aid "new") or edit an activity. Edits apply from this month on."""
        self._admin(actor)
        self._seed_activities()
        current = None if aid == "new" else self.calendar_activity(aid)
        if current and current["status"] == "retired":
            raise self._invalid("This activity is retired; reactivate it first")
        snap = self._activity_form(form, current)
        if current is None:
            if snap["kind"] == "automated":
                aid = f"auto-{snap['source']}"
                if self.store.get("calendaractivities", "a", aid):
                    raise self._invalid("That collector or check already has an activity")
            else:
                base = aid = slug(snap["title"])
                n = 2
                while self.store.get("calendaractivities", "a", aid) or aid.startswith("auto-"):
                    aid, n = f"{base}-{n}", n + 1
            action, version, changes = "calendar.activity.create", 1, {"title": snap["title"]}
        else:
            if snap["kind"] != current["kind"]:
                raise self._invalid("The type of an existing activity cannot change; create a new one")
            changes = {k: {"from": current.get(k), "to": v} for k, v in snap.items()
                       if k != "instructions" and current.get(k) != v}
            if current.get("instructions", "") != snap["instructions"]:
                changes["instructions_changed"] = True
            if not changes:
                raise self._invalid("Nothing changed")
            action, version = "calendar.activity.edit", int(current.get("version") or 0) + 1
        row = self._write_activity(aid, snap, version, self.today.isoformat(), actor.email, _now())
        self.audit(actor, action, aid, {"controls": snap["controls"], "version": version, "changes": changes})
        return row

    def set_activity_status(self, actor, aid: str, status: str, reason: str = "") -> dict:
        """Retire (hide from now on, keep history) or reactivate."""
        self._admin(actor)
        current = self.calendar_activity(aid)
        if status not in ("active", "retired") or current["status"] == status:
            raise self._invalid("Nothing to change")
        snap = {k: current.get(k) for k in ("title", "kind", "months", "due_day", "controls", "source", "owner", "instructions")}
        snap["status"] = status
        version = int(current.get("version") or 0) + 1
        row = self._write_activity(aid, snap, version, self.today.isoformat(), actor.email, _now())
        self.audit(actor, f"calendar.activity.{'retire' if status == 'retired' else 'reactivate'}", aid,
                   {"controls": current["controls"], "version": version, "reason": (reason or "")[:300]})
        return row

    def delete_activity(self, actor, aid: str) -> None:
        """Delete a manual activity that has nothing recorded. Anything with records must be retired, so
        the evidence trail stays complete."""
        self._admin(actor)
        current = self.calendar_activity(aid)
        if current["kind"] != "manual":
            raise self._invalid("Automated activities follow a collector or check; retire them instead")
        if current["has_records"]:
            raise self._invalid("This activity has recorded months; retire it instead so its history stays")
        self.store.delete("calendaractivities", "a", aid)
        for v in self.store.list("calendarversions", "v"):
            if v["activity"] == aid:
                self.store.delete("calendarversions", "v", v["RowKey"])
        self.audit(actor, "calendar.activity.delete", aid, {"controls": current["controls"], "title": current["title"],
                                                            "months": current["months"]})

    # ================================================================ occurrences (manual)
    def _versions(self) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for v in self.store.list("calendarversions", "v"):
            out.setdefault(v["activity"], []).append(v)
        for vs in out.values():
            vs.sort(key=lambda v: v["version"])
        return out

    @staticmethod
    def _schedule_at(versions: list[dict], year: int, month: int) -> dict | None:
        """The version in force for a month: the latest one made on or before the month's last day."""
        end = month_end(year, month)
        valid = [v for v in versions if v["effective"] <= end]
        return valid[-1] if valid else None

    def calendar_records(self) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for r in self.store.list("calendardecisions", "d"):
            out.setdefault(r["occurrence"], []).append(r)
        for rows in out.values():
            rows.sort(key=lambda r: r["version"])
        return out

    def _occurrence(self, act: dict, year: int, month: int, versions: list[dict], records: list[dict] | None,
                    start: str) -> dict | None:
        # A month is on the calendar when the schedule in force that month had it (so unticking a month never
        # erases one already past), or when the current schedule has it and was made in or before this year (so
        # a month you tick shows up straight away, even earlier in the year).
        snap = self._schedule_at(versions, year, month)
        latest = versions[-1] if versions else None
        in_force = bool(snap and snap.get("status") == "active" and month in (snap.get("months") or []))
        added = bool(latest and latest.get("status") == "active" and month in (latest.get("months") or [])
                     and year >= int(str(latest.get("effective", "2000"))[:4]))
        if not in_force and not added and not records:
            return None
        source = snap if in_force else (latest if added else (snap or latest or act))
        planned_due = due_date(year, month, (source or act).get("due_day") or "15")
        last = records[-1] if records else {}
        status = LEGACY.get(last.get("decision"), last.get("decision") or "planned")
        status = status if status in STATUSES else "planned"
        due = last.get("moved_to") or planned_due
        today = self.today.isoformat()
        return {"key": f"{act['id']}~{year}-{month:02d}", "activity": act["id"], "title": act["title"],
                "year": year, "month": month, "planned_due": planned_due, "due": due, "moved": due != planned_due,
                "status": status, "past_due": status == "planned" and due < today and due >= start,
                "completed_on": last.get("completed_on", ""), "note": last.get("reason", ""),
                "by": last.get("by", ""), "at": last.get("at", ""), "controls": act["controls"]}

    def calendar_year(self, year: int, show_automated: bool = True) -> dict:
        """Everything the year page needs: one row per activity with twelve month cells."""
        acts = self.calendar_activities(include_retired=True)
        versions, records, start = self._versions(), self.calendar_records(), self.calendar_program_start()
        manual, automated = [], []
        for a in acts:
            if a["kind"] == "manual":
                cells = [self._occurrence(a, year, m, versions.get(a["id"], []),
                                          records.get(f"{a['id']}~{year}-{m:02d}"), start) for m in range(1, 13)]
                if a["status"] == "retired" and not any(cells):
                    continue
                manual.append({**a, "cells": cells})
            elif show_automated and a["status"] == "active":
                automated.append({**a, "cells": self._automated_cells(a["source"], year, start)})
        return {"manual": manual, "automated": automated}

    def calendar_occurrence(self, key: str) -> dict:
        m = KEY_RE.match(key or "")
        if not m:
            raise self._invalid("No such calendar entry")
        aid, year, month = m.group(1), int(m.group(2)), int(m.group(3))
        if not 1 <= month <= 12:
            raise self._invalid("No such calendar entry")
        act = self.calendar_activity(aid)
        if act["kind"] != "manual":
            raise self._invalid("No such calendar entry")
        history = self.calendar_records().get(key, [])
        occ = self._occurrence(act, year, month, self._versions().get(aid, []), history,
                               self.calendar_program_start())
        if not occ:
            raise self._invalid("That activity is not scheduled in that month")
        occ["history"] = [{**r, "decision": LEGACY.get(r["decision"], r["decision"])} for r in reversed(history)]
        occ["activity_info"] = act
        return occ

    def add_occurrence(self, actor, key: str) -> dict:
        """Add a one-off occurrence of a manual activity in a month it is not scheduled for."""
        self._admin(actor)
        m = KEY_RE.match(key or "")
        if not m or not 1 <= int(m.group(3)) <= 12:
            raise self._invalid("No such calendar entry")
        aid, year, month = m.group(1), int(m.group(2)), int(m.group(3))
        act = self.calendar_activity(aid)
        if act["kind"] != "manual" or act["status"] != "active":
            raise self._invalid("Only active manual activities can get an extra month")
        if abs(year - self.today.year) > 1:
            raise self._invalid("Add months within a year of today")
        if self._occurrence(act, year, month, self._versions().get(aid, []), self.calendar_records().get(key),
                            self.calendar_program_start()):
            raise self._invalid("That month is already on the calendar")
        planned = due_date(year, month, act.get("due_day") or "15")
        row = {"PartitionKey": "d", "RowKey": f"{key}~001", "occurrence": key, "activity": aid,
               "period": f"{year}-{month:02d}", "due_date": planned, "moved_to": "", "decision": "planned",
               "completed_on": "", "reason": "Added for this month only", "by": actor.email, "at": _now(),
               "version": 1, "supersedes": ""}
        self.store.insert("calendardecisions", row)
        self.audit(actor, "calendar.occurrence.add", key, {"controls": act["controls"], "due": planned})
        return row

    def update_occurrence(self, actor, key: str, status: str, completed_on: str = "", note: str = "",
                          move_to: str = "") -> dict:
        """Record Planned, Performed (date) or Missed (reason), and optionally move the due date."""
        self._admin(actor)
        occ = self.calendar_occurrence(key)
        if status not in STATUSES:
            raise self._invalid("Status must be planned, performed or missed")
        note = (note or "").replace("\r\n", "\n").strip()
        if len(note) > NOTE_MAX:
            raise self._invalid(f"Notes can be at most {NOTE_MAX} characters")
        done = ""
        if status == "performed":
            try:
                done = dt.date.fromisoformat((completed_on or "").strip()).isoformat()
            except ValueError as exc:
                raise self._invalid("Enter the date it was performed") from exc
            if done > self.today.isoformat():
                raise self._invalid("The performed date cannot be in the future")
        if status == "missed" and len(note) < 5:
            raise self._invalid("Explain why it was missed (at least 5 characters)")
        moved = occ["due"]
        if (move_to or "").strip():
            try:
                new_due = dt.date.fromisoformat(move_to.strip())
            except ValueError as exc:
                raise self._invalid("Move-to date must be a date") from exc
            if abs(new_due.year - occ["year"]) > 1:
                raise self._invalid("Move it within a year of the scheduled month")
            moved = new_due.isoformat()
        if (status == occ["status"] and done == occ["completed_on"] and moved == occ["due"]
                and (not note or note == occ["note"])):
            raise self._invalid("Nothing changed")
        version = len(occ["history"]) + 1
        row = {"PartitionKey": "d", "RowKey": f"{key}~{version:03d}", "occurrence": key, "activity": occ["activity"],
               "period": f"{occ['year']}-{occ['month']:02d}", "due_date": occ["planned_due"],
               "moved_to": moved if moved != occ["planned_due"] else "", "decision": status, "completed_on": done,
               "reason": note, "by": actor.email, "at": _now(), "version": version, "supersedes": occ["status"]}
        self.store.insert("calendardecisions", row)
        self.audit(actor, "calendar.occurrence", key, {"controls": occ["controls"], "status": status,
                                                     "previous": occ["status"], "performed_on": done or None,
                                                     "due": moved, "planned_due": occ["planned_due"],
                                                     "version": version, "note": note[:300]})
        return row

    def calendar_past_due_count(self) -> int:
        data = self.calendar_year(self.today.year, show_automated=False)
        return sum(1 for a in data["manual"] for c in a["cells"] if c and c["past_due"])

    # ================================================================ feeds into control status and exports
    def completed_tasks(self) -> dict[str, str]:
        """Activity -> latest performed date (the starter tasks referenced by controls.yaml)."""
        out: dict[str, str] = {}
        for rows in self.calendar_records().values():
            last = rows[-1]
            if LEGACY.get(last["decision"], last["decision"]) == "performed" and last["completed_on"] > out.get(last["activity"], ""):
                out[last["activity"]] = last["completed_on"]
        return out

    def performed_by_control(self) -> dict[str, str]:
        """Control -> latest date a linked calendar activity was performed."""
        acts = {a["id"]: a["controls"] for a in self.calendar_activities(include_retired=True, include_hidden=True)}
        out: dict[str, str] = {}
        for aid, done in self.completed_tasks().items():
            for cid in acts.get(aid, []):
                if done > out.get(cid, ""):
                    out[cid] = done
        return out

    def calendar_export_rows(self, start: str, end: str) -> list[dict]:
        """Population for the auditor: every manual occurrence due between start and end, recorded or not."""
        rows = []
        for year in range(int(start[:4]), int(end[:4]) + 1):
            for a in self.calendar_year(year, show_automated=False)["manual"]:
                for o in a["cells"]:
                    if not o or not start <= o["planned_due"] <= end:
                        continue
                    rows.append({"occurrence": o["key"], "activity": a["id"], "title": a["title"],
                                 "month": f"{o['year']}-{o['month']:02d}", "scheduled_due": o["planned_due"],
                                 "moved_to": o["due"] if o["moved"] else "", "status": STATUSES[o["status"]],
                                 "past_due": "yes" if o["past_due"] else "", "performed_on": o["completed_on"],
                                 "recorded_by": o["by"], "recorded_at": o["at"], "note": o["note"],
                                 "controls": a["controls"]})
        return rows

    def calendar_decisions(self, key: str | None = None) -> list[dict]:
        rows = self.store.list("calendardecisions", "d")
        if key:
            rows = [r for r in rows if r["occurrence"] == key]
        return sorted(rows, key=lambda r: (r["occurrence"], r["version"]))

    # ================================================================ automated evidence
    def _run_status(self, source: str, run: str) -> str:
        """Result of one run (manifests are write-once, so the answer is cached for good)."""
        cache = self.__dict__.setdefault("_run_status_cache", {})
        key = (source, run)
        if key not in cache:
            raw = self.evidence.read(source, run, "manifest.json")
            m = json.loads(raw) if raw else {}
            cache[key] = ("failed" if m.get("status") == "error" or not m else
                          "findings" if m.get("findings_count") else "passed")
        return cache[key]

    def _automated_cells(self, source: str, year: int, start: str) -> list[dict | None]:
        """Per month: the result of the latest run (a fixed failure followed by a passing re-run shows
        Passed; the failure stays in the run history). No run in a month of the observation period: Not run."""
        runs = [r for r in self.evidence.list_runs(source) if r[:4] == str(year)]
        by_month: dict[int, list[str]] = {}
        for r in runs:
            if len(r) >= 7 and r[5:7].isdigit():
                by_month.setdefault(int(r[5:7]), []).append(r)
        today = self.today.isoformat()
        cells: list[dict | None] = []
        for m in range(1, 13):
            first = f"{year}-{m:02d}-01"
            if first > today or month_end(year, m) < start:
                cells.append(None)
                continue
            month_runs = sorted(by_month.get(m, []))
            if not month_runs:
                cells.append({"status": "notrun", "runs": 0, "failed": 0, "source": source})
                continue
            results = [self._run_status(source, r) for r in month_runs]
            cells.append({"status": results[-1], "runs": len(results), "failed": results.count("failed"),
                          "source": source})
        return cells

    def automated_runs(self, source: str, limit: int = 60) -> list[dict]:
        if source not in self.automated_sources():
            raise self._invalid("Unknown automated activity")
        out = []
        for run in reversed(self.evidence.list_runs(source)[-limit:]):
            raw = self.evidence.read(source, run, "manifest.json")
            m = json.loads(raw) if raw else {}
            out.append({"run": run, "status": self._run_status(source, run), "findings": m.get("findings_count", 0),
                        "error": m.get("error") or ""})
        return out

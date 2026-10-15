"""Security calendar: every recurring compliance activity in the year, and what happened to each one.

Plain model:
- An activity is a recurring task from `catalog/tasks.yaml` (access review, DR test, ...).
- An occurrence is one instance of it (the October access review). Occurrences are computed from the
  schedule, never stored, so a missed scheduled job can never make one disappear.
- A decision is what an admin recorded about an occurrence: performed, performed late, not performed
  (an exception) or not applicable. GRC-pal never decides this itself. Decisions are append-only: a
  correction is a new decision and the earlier one stays visible (and in the hash-chained audit log).
- Automated evidence (collectors and custom checks) is shown next to the manual activities as the runs
  that actually happened.
"""
from __future__ import annotations

import calendar as _cal
import datetime as dt
import re

from grcpal import frameworks as fw_mod
from grcpal.tasks import period_label

DECISIONS = {
    "performed": "Performed",
    "performed_late": "Performed late",
    "not_performed": "Not performed (exception)",
    "not_applicable": "Not applicable",
}
STATUS_LABELS = {"planned": "Planned", "open": "Open", "needs_decision": "Needs decision", **DECISIONS}
NEED_REASON = {"performed_late", "not_performed", "not_applicable"}
NEED_DATE = {"performed", "performed_late"}
REASON_MAX = 2000
DEFAULT_DUE_TIME = "17:00"
KEY_RE = re.compile(r"^([a-z0-9][a-z0-9-]{0,63})~(\d{4})-(\d{2})$")
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
CADENCE_TEXT = {"monthly": "Monthly", "quarterly": "Quarterly", "annual": "Annually"}


def _month_names(months: list[int]) -> str:
    return ", ".join(_cal.month_abbr[m] for m in sorted(months))


def schedule_text(task: dict) -> str:
    """'Quarterly: opens 1 Jan, Apr, Jul, Oct; due 21 days later at 17:00'."""
    months = task.get("months") or []
    return (f"{CADENCE_TEXT.get(task.get('cadence'), 'Recurring')}: opens on the 1st of {_month_names(months)}; "
            f"due {task.get('due_days', 30)} days later at {task.get('due_time') or DEFAULT_DUE_TIME}")


def occurrence_status(occ: dict, today: dt.date, decision: dict | None) -> str:
    if decision:
        return decision["decision"]
    if occ["opens"] > today.isoformat():
        return "planned"
    if occ["due_date"] < today.isoformat():
        return "needs_decision"
    return "open"


class CalendarMixin:
    """Calendar logic for the Portal. Reads: admins and auditors. Decisions: admins only."""

    # ---------------------------------------------------------------- activities
    def _activity_controls(self, name: str) -> list[str]:
        return sorted(self.catalog.sources("task").get(name, []))

    def _calendar_scope(self) -> tuple[list, set[str]]:
        """Frameworks switched on, and the SOC 2 criteria in scope (Security plus the chosen categories)."""
        return list(self.frameworks_in_use.values()), set(self.catalog.in_scope_criteria)

    def _in_use_framework(self, control_ids: list[str], scope: tuple | None = None) -> bool:
        """An activity belongs on the calendar when one of its controls maps to a framework switched on for this
        organization (for SOC 2: to an in-scope criterion). So with ISO 27001 off, ISO-only activities are
        hidden, and with Privacy out of scope, privacy-only activities are hidden. No linked control: shown."""
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
        """Occurrences due before the first audit cycle started are not part of the program."""
        self.ensure_cycle()
        return min(c["start"] for c in self.store.list("cycles", "c"))

    def calendar_activities(self) -> list[dict]:
        out = []
        scope = self._calendar_scope()
        for name, task in self.catalog.tasks.items():
            controls = self._activity_controls(name)
            if not self._in_use_framework(controls, scope):
                continue
            owner = (self.catalog.roles.get(task.get("owner")) or {}).get("title", task.get("owner", ""))
            out.append({"id": name, "title": task["title"], "cadence": task.get("cadence", "annual"),
                        "months": sorted(task.get("months") or []), "due_days": int(task.get("due_days", 30)),
                        "due_time": task.get("due_time") if TIME_RE.match(str(task.get("due_time", ""))) else DEFAULT_DUE_TIME,
                        "controls": controls, "owner": owner, "checklist": list(task.get("checklist") or []),
                        "goal": task.get("goal", ""), "schedule": schedule_text(task)})
        return sorted(out, key=lambda a: a["title"])

    def calendar_activity(self, name: str) -> dict | None:
        return next((a for a in self.calendar_activities() if a["id"] == name), None)

    # ---------------------------------------------------------------- occurrences
    def _occurrence(self, act: dict, year: int, month: int) -> dict:
        opens = dt.date(year, month, 1)
        due = opens + dt.timedelta(days=act["due_days"])
        task = self.catalog.tasks[act["id"]]
        later = [m for m in act["months"] if m > month]
        next_open = dt.date(year, later[0], 1) if later else dt.date(year + 1, act["months"][0], 1)
        return {"window_end": (next_open - dt.timedelta(days=1)).isoformat(),"key": f"{act['id']}~{opens:%Y-%m}", "activity": act["id"], "title": act["title"],
                "period": period_label(task, opens), "opens": opens.isoformat(), "due_date": due.isoformat(),
                "due_time": act["due_time"], "due_month": due.month, "due_year": due.year,
                "controls": act["controls"]}

    def calendar_decisions(self, key: str | None = None) -> list[dict]:
        rows = self.store.list("calendardecisions", "d")
        if key:
            rows = [r for r in rows if r["occurrence"] == key]
        return sorted(rows, key=lambda r: (r["occurrence"], r["version"]))

    def _latest_decisions(self) -> dict[str, dict]:
        latest: dict[str, dict] = {}
        for r in self.calendar_decisions():
            latest[r["occurrence"]] = r  # sorted by version, so the last one wins
        return latest

    def calendar_occurrences(self, year: int, activity: str | None = None) -> list[dict]:
        """Every occurrence whose due date falls in `year` (an occurrence opening in December can be due in
        January), with its current status and latest decision."""
        latest = self._latest_decisions()
        start = self.calendar_program_start()
        out = []
        for act in self.calendar_activities():
            if activity and act["id"] != activity:
                continue
            for y in (year - 1, year):
                for m in act["months"]:
                    occ = self._occurrence(act, y, m)
                    if occ["due_year"] != year or occ["due_date"] < start:
                        continue
                    d = latest.get(occ["key"])
                    occ["decision"] = d
                    occ["status"] = occurrence_status(occ, self.today, d)
                    out.append(occ)
        return sorted(out, key=lambda o: (o["due_date"], o["title"]))

    def calendar_occurrence(self, key: str) -> dict:
        m = KEY_RE.match(key or "")
        act = self.calendar_activity(m.group(1)) if m else None
        year, month = (int(m.group(2)), int(m.group(3))) if m else (0, 0)
        if not act or month not in act["months"]:
            raise self._invalid("No such calendar occurrence")
        occ = self._occurrence(act, year, month)
        if occ["due_date"] < self.calendar_program_start():
            raise self._invalid("That occurrence was due before the first audit cycle started")
        history = self.calendar_decisions(occ["key"])
        occ["decision"] = history[-1] if history else None
        occ["history"] = list(reversed(history))
        occ["status"] = occurrence_status(occ, self.today, occ["decision"])
        occ["activity_info"] = act
        return occ

    def needs_decision_count(self) -> int:
        return sum(1 for o in self.calendar_occurrences(self.today.year) if o["status"] == "needs_decision")

    # ---------------------------------------------------------------- decisions
    def decide_occurrence(self, actor, key: str, decision: str, completed_on: str, reason: str) -> dict:
        """Record what happened. Admins only; nothing is ever decided automatically."""
        self._admin(actor)
        occ = self.calendar_occurrence(key)
        today = self.today
        if occ["opens"] > today.isoformat():
            raise self._invalid("This occurrence has not started yet")
        if decision not in DECISIONS:
            raise self._invalid("Choose performed, performed late, not performed or not applicable")
        reason = (reason or "").replace("\r\n", "\n").strip()
        if len(reason) > REASON_MAX:
            raise self._invalid(f"Notes can be at most {REASON_MAX} characters")
        if decision in NEED_REASON and len(reason) < 5:
            raise self._invalid("Explain the decision (at least 5 characters)")
        done = ""
        if decision in NEED_DATE:
            try:
                done = dt.date.fromisoformat((completed_on or "").strip()).isoformat()
            except ValueError as exc:
                raise self._invalid("Enter the date it was performed (YYYY-MM-DD)") from exc
            if done > today.isoformat():
                raise self._invalid("The performed date cannot be in the future")
            if decision == "performed" and done > occ["due_date"]:
                raise self._invalid(f"Performed after the due date ({occ['due_date']}): choose Performed late")
            if decision == "performed_late" and done <= occ["due_date"]:
                raise self._invalid(f"Performed on or before the due date ({occ['due_date']}): choose Performed")
        previous = occ["decision"]
        version = (previous["version"] if previous else 0) + 1
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        row = {"PartitionKey": "d", "RowKey": f"{occ['key']}~{version:03d}", "occurrence": occ["key"],
               "activity": occ["activity"], "period": occ["period"], "due_date": occ["due_date"],
               "decision": decision, "completed_on": done, "reason": reason, "by": actor.email, "at": now,
               "version": version, "supersedes": previous["decision"] if previous else ""}
        self.store.insert("calendardecisions", row)
        self.audit(actor, "calendar.decision", occ["key"], {"controls": occ["controls"], "decision": decision,
                                                          "completed_on": done or None, "version": version,
                                                          "supersedes": row["supersedes"] or None,
                                                          "reason": reason[:300]})
        return row

    def completed_tasks(self) -> dict[str, str]:
        """Activity -> latest date an admin recorded it as performed (feeds control status)."""
        out: dict[str, str] = {}
        for r in self._latest_decisions().values():
            if r["decision"] in NEED_DATE and r["completed_on"] > out.get(r["activity"], ""):
                out[r["activity"]] = r["completed_on"]
        return out

    def calendar_export_rows(self, start: str, end: str) -> list[dict]:
        """The population for an auditor: every occurrence due between start and end (inclusive), including
        the ones still waiting for a decision, with the latest decision."""
        rows = []
        for year in range(int(start[:4]), int(end[:4]) + 1):
            for o in self.calendar_occurrences(year):
                if not start <= o["due_date"] <= end:
                    continue
                d = o["decision"] or {}
                rows.append({"occurrence": o["key"], "activity": o["activity"], "title": o["title"],
                             "period": o["period"], "opens": o["opens"], "due": f"{o['due_date']} {o['due_time']}",
                             "controls": o["controls"], "status": STATUS_LABELS[o["status"]],
                             "performed_on": d.get("completed_on", ""), "decided_by": d.get("by", ""),
                             "decided_at": d.get("at", ""), "decision_version": d.get("version", ""),
                             "reason": d.get("reason", "")})
        return rows

    # ---------------------------------------------------------------- automated evidence
    def calendar_automated(self) -> list[dict]:
        """Collectors and custom checks that run on a schedule, with the dates they actually ran.
        Run ids are timestamps, so dates come from the run list without opening each manifest."""
        from grcpal.collectors import NAMES, disabled_sources

        skip = disabled_sources(self.catalog, self.settings)
        scope = self._calendar_scope()
        by_collector = self.catalog.sources("collector")
        rows = []
        for name in NAMES:
            controls = sorted(by_collector.get(name, []))
            if name in skip or not controls or not self._in_use_framework(controls, scope):
                continue
            rows.append({"id": name, "title": f"Collector: {name.replace('_', ' ')}", "kind": "collector",
                         "schedule": "Daily (grcpal collect --all)", "controls": controls,
                         "runs": self._run_dates(name)})
        for chk in self.all_checks():
            cid = chk.get("id") or chk.get("RowKey")
            controls = [chk["control"]] if chk.get("control") else []
            if not cid or not self._in_use_framework(controls, scope):
                continue
            sched = chk.get("schedule", "daily")
            rows.append({"id": f"check-{cid}", "title": f"Check: {chk.get('title') or cid}", "kind": "check",
                         "schedule": {"daily": "Daily", "weekly": "Weekly (Mondays)"}.get(sched, "Manual"),
                         "controls": controls, "runs": self._run_dates(f"check-{cid}")})
        return rows

    def _run_dates(self, source: str) -> list[str]:
        out = []
        for run in self.evidence.list_runs(source):
            if len(run) >= 10 and run[4] == "-" and run[7] == "-":
                out.append(run)
        return out

    def automated_runs(self, source: str, limit: int = 30) -> list[dict]:
        """Most recent runs of one automated source with their result (reads those manifests)."""
        known = {r["id"] for r in self.calendar_automated()}
        if source not in known:
            raise self._invalid("Unknown automated activity")
        import json

        out = []
        for run in reversed(self.evidence.list_runs(source)[-limit:]):
            raw = self.evidence.read(source, run, "manifest.json")
            m = json.loads(raw) if raw else {}
            status = "error" if m.get("status") == "error" else ("findings" if m.get("findings_count") else "ok")
            out.append({"run": run, "status": status, "findings": m.get("findings_count", 0),
                        "error": m.get("error") or "", "started": m.get("started", "")})
        return out

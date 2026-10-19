"""Automation alerts and digests: tell admins when collectors or checks fail, and send a regular summary.

Plain model:
- After each scheduled collection (`grcpal collect --all`), the job calls `send_automation_alerts` and
  `send_digests`. No extra scheduled job is needed, and on most installs that run is early in the morning.
- Failure alert: one email per new failed run (a source that is still failing alerts again on its next failed
  run, so a broken integration cannot go quiet). Which run was last alerted is kept in the `reminders` table.
- Digests: a daily, weekly (Mondays) and monthly (1st of the month) summary of every automated activity:
  runs passed, with findings, failed, and sources that did not run at all in the period.
- Who gets them: active admins. Failure alerts are on by default; digests are opt-in. Each admin chooses on
  Calendar > Email alerts. Preferences live on the user's own row.
- Emails carry only names, counts, dates and the error's first line; never evidence files or secrets.
"""
from __future__ import annotations

import calendar as _cal
import datetime as dt

DIGESTS = {"daily": "Every morning", "weekly": "Every Monday", "monthly": "On the 1st of each month"}
ERROR_MAX = 200


def _run_day(run: str) -> str:
    return run[:10] if len(run) >= 10 else ""


class AutomationMixin:
    # ------------------------------------------------------------------ preferences
    def notify_prefs(self, user) -> dict:
        row = self.user_row(user.email) or {}
        digests = [d for d in str(row.get("digests") or "").split(",") if d in DIGESTS]
        return {"alerts": not row.get("alerts_off", False), "digests": digests}

    def set_notify_prefs(self, actor, alerts: bool, digests: list[str]) -> dict:
        self._admin(actor)
        clean = [d for d in DIGESTS if d in set(digests or [])]
        before = self.notify_prefs(actor)
        after = {"alerts": bool(alerts), "digests": clean}
        if before == after:
            return after
        self.store.update("users", "u", actor.email, {"alerts_off": not alerts, "digests": ",".join(clean)})
        self.audit(actor, "notify.prefs", actor.email, {"before": before, "after": after})
        return after

    def _subscribers(self, want: str) -> list[str]:
        out = []
        for u in self.users():
            if u.get("role") != "admin" or not u.get("active", True):
                continue
            if want == "alerts" and not u.get("alerts_off", False):
                out.append(u["RowKey"])
            elif want in str(u.get("digests") or "").split(","):
                out.append(u["RowKey"])
        return out

    # ------------------------------------------------------------------ what happened
    def automation_summary(self, first_day: str, last_day: str) -> list[dict]:
        """Per automated source: the runs dated first_day..last_day (inclusive) and how they ended."""
        out = []
        for source, info in sorted(self.automated_sources().items(), key=lambda kv: kv[1]["title"].lower()):
            runs = [r for r in self.evidence.list_runs(source) if first_day <= _run_day(r) <= last_day]
            results = [self._run_status(source, r) for r in sorted(runs)]
            row = {"source": source, "title": info["title"], "runs": len(results),
                   "passed": results.count("passed"), "findings": results.count("findings"),
                   "failed": results.count("failed"), "last": results[-1] if results else "notrun",
                   "last_run": sorted(runs)[-1] if runs else "", "error": ""}
            if row["last"] == "failed":
                row["error"] = self._run_error(source, row["last_run"])
            out.append(row)
        return out

    def _run_error(self, source: str, run: str) -> str:
        import json

        raw = self.evidence.read(source, run, "manifest.json")
        m = json.loads(raw) if raw else {}
        return (str(m.get("error") or "The run did not finish").splitlines() or [""])[0][:ERROR_MAX]

    # ------------------------------------------------------------------ failure alerts
    def send_automation_alerts(self, actor) -> list[dict]:
        """Email admins about failed runs not alerted before. Returns the failures included."""
        failures = []
        for source, info in self.automated_sources().items():
            runs = sorted(self.evidence.list_runs(source))
            if not runs or self._run_status(source, runs[-1]) != "failed":
                continue
            key = f"automation-alert:{source}"
            seen = (self.store.get("reminders", "r", key) or {}).get("run", "")
            if runs[-1] <= seen:
                continue
            streak = 0
            for r in reversed(runs):
                if self._run_status(source, r) != "failed":
                    break
                streak += 1
            failures.append({"source": source, "title": info["title"], "run": runs[-1], "streak": streak,
                             "error": self._run_error(source, runs[-1])})
        if not failures:
            return []
        lines = [f"{f['title']}: {f['error']}" + (f" (failed {f['streak']} runs in a row)" if f["streak"] > 1 else "")
                 for f in failures]
        content = {"subject": f"GRC-pal: {len(failures)} automated check{'s' if len(failures) != 1 else ''} failed",
                   "title": "Automated evidence collection failed",
                   "intro": "These collectors or checks failed on their last run, so no evidence was collected for "
                            "them. Fix the cause (often an expired secret or a permission change) and run them again.",
                   "fields": [("Date", self.today.isoformat())],
                   "sections": [("Failed", lines)],
                   "button": ("Open the calendar", self.link("/calendar#automated"))}
        sent = self._notify("automation", self._subscribers("alerts"), actor, content)
        for f in failures:
            self.store.upsert("reminders", {"PartitionKey": "r", "RowKey": f"automation-alert:{f['source']}",
                                            "run": f["run"], "last_sent": self.today.isoformat(), "by": actor.email})
        self.audit(actor, "automation.alert", "automation", {"failed": [f["source"] for f in failures],
                                                             "recipients": len(sent)})
        return failures

    # ------------------------------------------------------------------ digests
    def _digest_window(self, kind: str) -> tuple[str, str, str] | None:
        """(first day, last day, label) for a digest due today, or None when that digest is not due."""
        today = self.today
        if kind == "daily":
            first = today - dt.timedelta(days=1)
            return first.isoformat(), today.isoformat(), f"{first.isoformat()} to {today.isoformat()}"
        if kind == "weekly" and today.weekday() == 0:
            first = today - dt.timedelta(days=7)
            return first.isoformat(), (today - dt.timedelta(days=1)).isoformat(), f"the week from {first.isoformat()}"
        if kind == "monthly" and today.day == 1:
            last = today - dt.timedelta(days=1)
            first = last.replace(day=1)
            return first.isoformat(), last.isoformat(), f"{_cal.month_name[first.month]} {first.year}"
        return None

    def send_digests(self, actor) -> list[dict]:
        """Send the digests due today (each at most once per day). Returns what was sent."""
        out = []
        for kind in DIGESTS:
            window = self._digest_window(kind)
            if not window:
                continue
            key = f"digest:{kind}"
            if (self.store.get("reminders", "r", key) or {}).get("last_sent") == self.today.isoformat():
                continue
            people = self._subscribers(kind)
            if not people:
                continue
            first, last, label = window
            rows = self.automation_summary(first, last)
            failed = [r for r in rows if r["last"] == "failed"]
            notrun = [r for r in rows if r["last"] == "notrun"]
            ok = [r for r in rows if r["last"] in ("passed", "findings")]
            sections = []
            if failed:
                sections.append(("Failing now", [f"{r['title']}: {r['error']}" for r in failed]))
            if notrun:
                sections.append(("Did not run in this period", [r["title"] for r in notrun]))
            if ok:
                sections.append(("Working", [f"{r['title']}: {r['runs']} run{'s' if r['runs'] != 1 else ''}"
                                             + (f", {r['failed']} failed" if r["failed"] else "")
                                             + (", findings to review" if r["last"] == "findings" else "")
                                             for r in ok]))
            if not rows:
                sections.append(("Automated activities", ["No collectors or checks are switched on."]))
            past_due = self.calendar_past_due_count()
            name = {"daily": "Morning", "weekly": "Weekly", "monthly": "Monthly"}[kind]
            content = {"subject": f"GRC-pal {name.lower()} digest: {len(failed)} failing, {len(notrun)} not run, "
                                  f"{len(ok)} working",
                       "title": f"{name} automation digest",
                       "intro": f"Automated evidence collection for {label}.",
                       "fields": [("Failing", str(len(failed))), ("Did not run", str(len(notrun))),
                                  ("Working", str(len(ok))), ("Calendar items past due", str(past_due))],
                       "sections": sections,
                       "button": ("Open the calendar", self.link("/calendar#automated"))}
            sent = self._notify("digest", people, actor, content)
            self.store.upsert("reminders", {"PartitionKey": "r", "RowKey": key, "last_sent": self.today.isoformat(),
                                            "by": actor.email})
            out.append({"kind": kind, "sent": sent, "failed": len(failed), "notrun": len(notrun), "ok": len(ok)})
        return out

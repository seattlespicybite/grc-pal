"""Access reviews, after the list is built: invitations and reminders to reviewers, remediation tickets, checking
removals against the nightly account pull, and the review schedule (SOC 2 CC6.2, CC6.3; control IAM-05).

Plain model:
- Invitations: an admin emails every reviewer who has not signed off (optionally giving managers without a portal
  account a Control owner account first). A scheduled review invites by itself. Emails carry counts and application
  names only; the accounts are shown in GRC-pal to the signed-in reviewer.
- Reminders (daily job after collection): from REMIND_BEFORE_DAYS before the due date, every REMIND_EVERY_DAYS days,
  to reviewers who have not signed off. On the first day past due, admins get one overdue notice.
- Tickets: one Jira or GitHub issue per application for the accounts to remove or change, opened by an admin or
  automatically when the last reviewer signs off. GRC-pal never disables accounts. Each ticket's key is stored
  on the accounts it covers and in the audit log.
- Checking: for applications with a nightly pull, a pull newer than the decision shows whether the account is gone,
  disabled or changed. An admin confirms (one by one, or all that the pull shows as done); the confirmation note
  names the stored pull, which is write-once evidence.
- Schedule: one recurring review (every 3, 6 or 12 months) from chosen applications. It starts on its day from the
  nightly job, only for periods that begin on or after the day it was saved, and never twice for one period.
"""
from __future__ import annotations

import datetime as dt
import json

from grcpal import tickets
from grcpal.portal.accessreview import CONTROLS, DECISIONS, DISABLED_WORDS, progress

REMIND_BEFORE_DAYS = 7
REMIND_EVERY_DAYS = 3
FREQUENCIES = {3: "Every 3 months", 6: "Every 6 months", 12: "Once a year"}
DONE_CHECKS = {"gone": "Account no longer in the application", "disabled": "Account is disabled",
               "changed": "Role changed"}
OTHER_CHECKS = {"still_there": "Still there in the latest pull", "no_newer_pull": "No pull since the decision",
                "no_pull": "Not pulled automatically"}
SCHEDULE_KEY = "default"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _add_months(day: dt.date, months: int) -> dt.date:
    m = day.month - 1 + months
    return dt.date(day.year + m // 12, m % 12 + 1, day.day)


class AccessFollowUpMixin:
    # ------------------------------------------------------------------ who still has work
    def _ar_mine(self, entries: list[dict], email: str) -> dict:
        mine = [e for e in entries if e.get("reviewer") == email]
        return {"total": len(mine), "left": sum(1 for e in mine if not e.get("decision")),
                "apps": sorted({e["app"] for e in mine})}

    def _ar_waiting(self, camp: dict) -> list[str]:
        att = camp.get("attestations") or {}
        return [r for r in camp.get("reviewers") or [] if r not in att]

    def _ar_mail(self, kind: str, camp: dict, entries: list[dict], email: str, actor) -> bool:
        from grcpal.portal import notify

        content = notify.access_review(self, kind, camp, self._ar_mine(entries, email))
        return bool(self._notify("access_review", [email], actor, content, CONTROLS))

    # ------------------------------------------------------------------ invitations
    def invite_access_reviewers(self, actor, cid: str, create_accounts: bool = False) -> dict:
        """Email every reviewer who has not signed off. With create_accounts, managers without a portal account get
        a Control owner account first (Microsoft sign-in when it is set up, otherwise a password link by email)."""
        from grcpal.portal.auth import auth_mode

        self._ar_admin(actor, "invite reviewers")
        camp = self._ar_campaign(cid)
        self._ar_open(camp)
        entries = self._ar_entries(cid)
        waiting = self._ar_waiting(camp)
        if not waiting:
            raise self._invalid("Every reviewer has signed off; nobody to invite")
        created, no_account, sent = [], [], []
        for email in waiting:
            if not self.user_row(email):
                if not create_accounts:
                    no_account.append(email)
                    continue
                self._create_user(email, email, "contributor", "access_review", actor.email)
                created.append(email)
                if auth_mode() == "local":
                    if self.ms_signin_ready():
                        self.store.update("users", "u", email, {"signin": "microsoft"})
                        self.audit(actor, "user.signin_method", email, {"from": "", "to": "microsoft"})
                    else:
                        self.setup_link(actor, email)  # emails the person a one-time password link
            if not self._ar_can_review(email):
                no_account.append(email)
                continue
            if self._ar_mail("invite", camp, entries, email, actor):
                sent.append(email)
        invited = dict(camp.get("invited") or {})
        invited.update({e: self.today.isoformat() for e in sent})
        self.store.update("arcampaigns", "c", cid, {"invited": invited})
        self.audit(actor, "access_review.invite", cid, {"invited": len(sent), "accounts_created": len(created),
                                                        "without_account": len(no_account)})
        return {"sent": sent, "created": created, "without_account": no_account}

    # ------------------------------------------------------------------ reminders (daily job)
    def send_access_review_reminders(self, actor) -> list[dict]:
        out = []
        for camp in self.store.list("arcampaigns", "c"):
            if camp["status"] != "open":
                continue
            days_left = (dt.date.fromisoformat(camp["due"]) - self.today).days
            if days_left > REMIND_BEFORE_DAYS:
                continue
            entries = self._ar_entries(camp["RowKey"])
            reminded = dict(camp.get("reminded") or {})
            invited = camp.get("invited") or {}
            waiting = self._ar_waiting(camp)
            sent = []
            for email in waiting:
                last = reminded.get(email) or invited.get(email) or ""
                if last and self._days_since(last) < REMIND_EVERY_DAYS:
                    continue
                if not self._ar_can_review(email):
                    continue
                if self._ar_mail("overdue" if days_left < 0 else "reminder", camp, entries, email, actor):
                    reminded[email] = self.today.isoformat()
                    sent.append(email)
            fields: dict = {"reminded": reminded} if sent else {}
            if days_left < 0 and waiting and not camp.get("overdue_notified"):
                from grcpal.portal import notify

                admins = self.active_emails("admin")
                self._notify("access_review", admins, actor, notify.access_review_overdue_admins(self, camp, waiting),
                             CONTROLS)
                fields["overdue_notified"] = self.today.isoformat()
            if fields:
                self.store.update("arcampaigns", "c", camp["RowKey"], fields)
                self.audit(actor, "access_review.remind", camp["RowKey"],
                           {"reminded": len(sent), "overdue": days_left < 0, "days_left": days_left})
                out.append({"campaign": camp["RowKey"], "reminded": len(sent), "overdue": days_left < 0})
        return out

    # ------------------------------------------------------------------ remediation tickets
    def access_tickets_ready(self) -> bool:
        return tickets.system(self.settings) != "off" and not tickets.problems(self.settings)

    def create_access_tickets(self, actor, cid: str, request_fn=None, clients=None) -> dict:
        """One ticket per application for the accounts to remove or change that have no ticket yet."""
        self._ar_admin(actor, "open remediation tickets")
        camp = self._ar_campaign(cid)
        if tickets.system(self.settings) == "off":
            raise self._invalid("Choose Jira or GitHub on Configuration > Remediation tickets first")
        by_app: dict[str, list[dict]] = {}
        for e in self._ar_entries(cid):
            if e.get("remediation") == "open" and not e.get("ticket_key"):
                by_app.setdefault(e["app"], []).append(e)
        if not by_app:
            raise self._invalid("No removals or changes are waiting for a ticket")
        created, failed = [], []
        log = list(camp.get("tickets") or [])
        for app, rows in sorted(by_app.items()):
            title, lines = self._ar_ticket_text(camp, app, rows)
            try:
                t = tickets.create(self.settings, title, lines, request_fn=request_fn, clients=clients)
            except (tickets.TicketError, OSError) as exc:
                failed.append({"app": app, "error": str(exc)[:300]})
                self.events.error("job", f"Remediation ticket for {app} failed: {str(exc)[:200]}",
                                  actor=actor.email)
                continue
            for e in rows:
                self.store.update("arentries", cid, e["RowKey"], {"ticket_key": t["key"], "ticket_url": t["url"]})
            entry = {"app": app, **t, "accounts": len(rows), "at": _now(), "by": actor.email}
            log.append(entry)
            created.append(entry)
            self.audit(actor, "access_review.ticket", cid, {"controls": CONTROLS, "application": app,
                                                           "system": t["system"], "ticket": t["key"],
                                                           "accounts": len(rows)})
        self.store.update("arcampaigns", "c", cid, {"tickets": log})
        return {"created": created, "failed": failed}

    def _ar_ticket_text(self, camp: dict, app: str, rows: list[dict]) -> tuple[str, list[str]]:
        removes = sum(1 for e in rows if e["decision"] == "revoke")
        changes = len(rows) - removes
        what = " and ".join(x for x in (f"remove {removes}" if removes else "", f"change {changes}" if changes else "") if x)
        title = f"Access review: {what} account{'s' if len(rows) != 1 else ''} in {app}"
        lines = [f"The access review \"{tickets.plain(camp['name'], 120)}\" (due {camp['due']}) decided that these "
                 f"accounts in {tickets.plain(app, 120)} must be removed or changed.",
                 "", "Please make the change in the application. GRC-pal never changes accounts itself: when it is "
                 "done, a GRC-pal admin confirms it in the review (the nightly account pull also shows it).", ""]
        for e in sorted(rows, key=lambda r: r["account_id"].lower()):
            who = " / ".join(tickets.plain(x, 120) for x in (e.get("name"), e.get("email")) if x)
            lines.append(f"- {tickets.plain(e['account_id'], 120)}{f' ({who})' if who else ''}: "
                         f"{DECISIONS[e['decision']]}"
                         + (f". Role: {tickets.plain(e['role'], 80)}" if e.get("role") else "")
                         + (f". Reviewer's note: {tickets.plain(e['comment'])}" if e.get("comment") else ""))
        lines += ["", f"Review in GRC-pal: {self.link('/access-reviews/' + camp['RowKey'])}",
                  f"Control: {', '.join(CONTROLS)} (SOC 2 CC6.2, CC6.3)"]
        return title, lines

    def _ar_after_signoff(self, cid: str) -> None:
        """When the last reviewer signs off, open tickets in the background (if tickets are set up)."""
        from grcpal.portal.auth import SYSTEM

        camp = self._ar_campaign(cid)
        if self._ar_waiting(camp) or not self.access_tickets_ready():
            return
        if not any(e.get("remediation") == "open" and not e.get("ticket_key") for e in self._ar_entries(cid)):
            return
        self.jobs.submit("access_tickets", f"Remediation tickets: {camp['name']}", SYSTEM.email,
                         lambda job: self.create_access_tickets(SYSTEM, cid))

    # ------------------------------------------------------------------ check removals against the account pulls
    def check_access_changes(self, actor, cid: str) -> dict:
        self._ar_admin(actor, "check removals")
        camp = self._ar_campaign(cid)
        self._ar_open(camp)
        apps = {a["name"]: a for a in self.store.list("arapps", "a") if a["kind"] != "csv"}
        counts = {k: 0 for k in (*DONE_CHECKS, *OTHER_CHECKS)}
        latest: dict[str, tuple] = {}
        for e in self._ar_entries(cid):
            if e.get("remediation") != "open":
                continue
            app = apps.get(e["app"])
            result, run_path, pulled_at = "no_pull", "", ""
            if app:
                if app["RowKey"] not in latest:
                    last = self._aa_last_ok(app["RowKey"])
                    rows = self._aa_snapshot_file(app["RowKey"], last[0], "accounts.json", []) if last else []
                    latest[app["RowKey"]] = (last, {str(r.get("account_id", "")).lower(): r for r in rows})
                last, by_id = latest[app["RowKey"]]
                # Decisions are stored to the second and pulls to the microsecond: compare whole seconds, and a pull in
                # the same second as the decision does not count as "after" it.
                if not last or last[1].get("started", "")[:19] <= (e.get("decided_at") or "")[:19]:
                    result = "no_newer_pull"
                else:
                    from grcpal.portal.accessapps import snapshot_source

                    run_path, pulled_at = f"{snapshot_source(app['RowKey'])}/{last[0]}", last[1]["started"]
                    now = by_id.get(e["account_id"].lower())
                    if now is None:
                        result = "gone"
                    elif str(now.get("status", "")).strip().lower() in DISABLED_WORDS:
                        result = "disabled"
                    elif e["decision"] == "modify" and str(now.get("role", "")) != str(e.get("role", "")):
                        result = "changed"
                    else:
                        result = "still_there"
            counts[result] += 1
            self.store.update("arentries", cid, e["RowKey"], {"pull_check": result, "pull_run": run_path,
                                                              "pull_at": pulled_at})
        self.audit(actor, "access_review.pull_check", cid, {"controls": CONTROLS, **{k: v for k, v in counts.items() if v}})
        return counts

    def confirm_checked_changes(self, actor, cid: str) -> int:
        """Confirm every open removal or change that the last check showed as done in the application's pull."""
        self._ar_admin(actor)
        self._ar_open(self._ar_campaign(cid))
        done = 0
        for e in self._ar_entries(cid):
            if e.get("remediation") == "open" and e.get("pull_check") in DONE_CHECKS:
                note = (f"{DONE_CHECKS[e['pull_check']]} in the account pull of {e['pull_at'][:10]} "
                        f"(evidence {e['pull_run']})")
                self.confirm_access_change(actor, cid, e["RowKey"], note)
                done += 1
        if not done:
            raise self._invalid("No removal or change is shown as done yet. Check with the latest pulls first")
        return done

    # ------------------------------------------------------------------ schedule
    def access_schedule(self, user) -> dict:
        self._ar_admin(user)
        row = self.store.get("arschedules", "s", SCHEDULE_KEY) or {}
        nxt = self._ar_next_start(row, self.today) if row.get("active") else None
        return {**row, "next_start": nxt.isoformat() if nxt else ""}

    def _ar_starts(self, row: dict, year: int):
        every, first, day = int(row["every"]), int(row["first_month"]), int(row["start_day"])
        start = dt.date(year - 1, first, day)
        while start.year <= year + 1:
            yield start
            start = _add_months(start, every)

    def _ar_next_start(self, row: dict, after: dt.date) -> dt.date | None:
        floor = max(after, dt.date.fromisoformat(row.get("created_from") or after.isoformat()))
        done = row.get("last_period") or ""
        return next((s for s in self._ar_starts(row, after.year) if s >= floor and s.isoformat() > done), None)

    def _ar_current_start(self, row: dict) -> dt.date | None:
        starts = [s for s in self._ar_starts(row, self.today.year) if s <= self.today]
        return starts[-1] if starts else None

    def save_access_schedule(self, actor, active: bool, name: str, every: str, first_month: str, start_day: str,
                             days: str, app_ids: list[str], entra_managers: bool, invite: bool) -> dict:
        self._ar_admin(actor, "schedule access reviews")
        name = (name or "").strip()
        if not name or len(name) > 80:
            raise self._invalid("Give the scheduled review a name (up to 80 characters)")
        try:
            every_n, first_n, day_n, days_n = int(every), int(first_month), int(start_day), int(days)
        except ValueError as exc:
            raise self._invalid("Choose how often, the first month, the start day and the days to finish") from exc
        if every_n not in FREQUENCIES or not 1 <= first_n <= 12 or not 1 <= day_n <= 28 or not 3 <= days_n <= 60:
            raise self._invalid("How often: every 3, 6 or 12 months; start day 1 to 28; 3 to 60 days to finish")
        apps = []
        for aid in dict.fromkeys(app_ids or []):
            app = self._aa_get(aid)
            if app["kind"] == "csv" or not app.get("active", True):
                raise self._invalid(f"{app['name']} cannot be pulled automatically, so it cannot be scheduled")
            apps.append(app["RowKey"])
        if active and not apps:
            raise self._invalid("Choose at least one application that GRC-pal reads automatically")
        old = self.store.get("arschedules", "s", SCHEDULE_KEY) or {}
        row = {"PartitionKey": "s", "RowKey": SCHEDULE_KEY, "active": bool(active), "name": name, "every": every_n,
               "first_month": first_n, "start_day": day_n, "days": days_n, "app_ids": apps,
               "entra_managers": bool(entra_managers), "invite": bool(invite),
               "created_from": old.get("created_from") if old.get("active") and active else self.today.isoformat(),
               "last_period": old.get("last_period", ""), "last_campaign": old.get("last_campaign", ""),
               "last_error": old.get("last_error", ""), "updated_by": actor.email, "updated_at": _now()}
        self.store.upsert("arschedules", row)
        self.audit(actor, "access_review.schedule", SCHEDULE_KEY, {"controls": CONTROLS, "active": row["active"],
                                                                   "every_months": every_n, "applications": len(apps),
                                                                   "days": days_n, "invite": row["invite"]})
        return self.access_schedule(actor)

    def run_access_review_schedules(self, actor, clients=None, request_fn=None) -> list[dict]:
        """Daily job: start this period's review when its day has come (once per period)."""
        row = self.store.get("arschedules", "s", SCHEDULE_KEY)
        if not row or not row.get("active"):
            return []
        start = self._ar_current_start(row)
        if (not start or start.isoformat() < (row.get("created_from") or "")
                or start.isoformat() <= (row.get("last_period") or "")):
            return []
        due = start + dt.timedelta(days=int(row["days"]))
        if due < self.today + dt.timedelta(days=3):  # the job did not run for a while: still give people time
            due = self.today + dt.timedelta(days=int(row["days"]))
        name = f"{row['name']} {start:%Y-%m}"
        # Mark the period first: a crash or a failed pull must not start a second review tomorrow.
        self.store.update("arschedules", "s", SCHEDULE_KEY, {"last_period": start.isoformat(), "last_error": ""})
        from grcpal.portal.jobs import JobRunner

        runner = JobRunner(self.store, self.events, sync=True)
        job = self.start_access_review(actor, name, due.isoformat(), list(row.get("app_ids") or []),
                                       entra_managers=bool(row.get("entra_managers")), clients=clients,
                                       request_fn=request_fn, invite=bool(row.get("invite")), runner=runner)
        admins = self.active_emails("admin")
        if job.get("status") != "done":
            error = str(job.get("message") or "unknown error")[:300]
            self.store.update("arschedules", "s", SCHEDULE_KEY, {"last_error": error})
            self._notify("access_review", admins, actor, {
                "subject": f"Scheduled access review did not start: {name}",
                "title": "The scheduled access review could not start",
                "intro": "GRC-pal could not read the applications for this period's review. Fix the application "
                         "settings, then start the review by hand on the Access reviews page.",
                "fields": [("Review", name), ("Problem", error)],
                "button": ("Open access reviews", self.link("/access-reviews"))}, CONTROLS)
            return [{"period": start.isoformat(), "error": error}]
        result = json.loads(job["result"]) if isinstance(job.get("result"), str) else job.get("result") or {}
        cid = result.get("campaign", "")
        self.store.update("arschedules", "s", SCHEDULE_KEY, {"last_campaign": cid})
        camp = self._ar_campaign(cid)
        content = {"subject": f"Access review started: {name}", "title": "The scheduled access review has started",
                   "intro": f"{camp['records']} accounts, due {camp['due']}."
                            + (" Reviewers were emailed." if row.get("invite") else
                               " Reviewers were not emailed yet: open the review and press Email reviewers."),
                   "fields": [("Review", name), ("Accounts", str(camp["records"])),
                              ("Without a reviewer", str(sum(1 for e in self._ar_entries(cid) if not e.get("reviewer"))))],
                   "button": ("Open the review", self.link(f"/access-reviews/{cid}"))}
        self._notify("access_review", admins, actor, content, CONTROLS)
        return [{"period": start.isoformat(), "campaign": cid}]

    def access_review_extras(self, camp: dict, entries: list[dict]) -> dict:
        """What the review page shows about invitations, tickets and pull checks."""
        return {"invited": camp.get("invited") or {}, "reminded": camp.get("reminded") or {},
                "tickets": camp.get("tickets") or [], "tickets_on": tickets.system(self.settings) != "off",
                "ticket_system": tickets.system(self.settings), "done_checks": DONE_CHECKS,
                "other_checks": OTHER_CHECKS, "waiting": self._ar_waiting(camp),
                "checked_done": sum(1 for e in entries if e.get("remediation") == "open"
                                    and e.get("pull_check") in DONE_CHECKS),
                "untracked": sum(1 for e in entries if e.get("remediation") == "open" and not e.get("ticket_key")),
                "stats": progress(entries)}

"""Setup guide readiness: for each program-setup step, a short checklist of what is done and what is missing.

Read-only: nothing here changes data, so nothing is audited. Each step links to the page where the work is done;
the guide never duplicates those pages. Mixed into Portal (service.py); admins only.

A check is {"name", "ok", "detail", "hint", "optional"}. A step is ready when every required (not optional) item
is ok. A step with only optional items is a recommendation: it is ready once an admin has looked at it.
"""
from __future__ import annotations

import datetime as dt

from grcpal import update
from grcpal.evidence import utcnow

# id -> title, why it matters, links (label, path). The order here is the order in the guide.
STEPS = {
    "cycle": ("Audit period",
              "A SOC 2 Type 2 report covers an observation period (often 3, 6 or 12 months). GRC-pal groups requests, "
              "evidence and exports by cycle, so set the first cycle to your real period before evidence piles up. "
              "The first cycle was created automatically on the day GRC-pal started.",
              [("Set the audit period", "/cycles")]),
    "owners": ("Control owners",
               "Every control needs a named person: they get the evidence requests, reminders and calendar tasks, and "
               "they see only their own controls. One admin is the control library owner: the only person who may "
               "change control text, owners and mappings (an auditor will ask who can).",
               [("Controls", "/controls"), ("Users and roles", "/users")]),
    "backups": ("Backups",
                "Backups are encrypted. Without the recovery kit (backup key and app key), a backup cannot be opened: "
                "keep it offline, for example in your password manager, never on the same server.",
                [("Backups", "/backups")]),
    "updates": ("Updates",
                "Choose how new versions arrive. Patch releases contain security and bug fixes only; minor releases "
                "add features. Every update is backed up first and rolled back automatically if checks fail.",
                [("Updates", "/updates")]),
    "alerts": ("Email alerts",
               "GRC-pal emails admins when a collector or check fails, so a broken connection does not silently "
               "leave a gap in your evidence for the audit period. Each admin can also choose summary emails.",
               [("Email alerts", "/calendar/notifications"), ("Email settings", "/settings/email")]),
    "access_reviews": ("Access reviews",
                       "Quarterly user access reviews (CC6.2, CC6.3) read the accounts from each application. Add "
                       "the applications in scope and test each one before the first review.",
                       [("Applications", "/access-reviews/apps")]),
    "vendors": ("Vendors",
                "The vendor register is the population for vendor risk reviews (CC9.2). Import your existing list "
                "from a spreadsheet (CSV), then set owners and review dates.",
                [("Import vendors", "/vendors/import"), ("Vendors", "/vendors")]),
    "calendar_library": ("Calendar and policies",
                         "The security calendar holds the recurring manual activities (reviews, drills, trainings). "
                         "The document library holds your policies; each one needs a named approver before it can "
                         "be sent for approval. Review both once; you can change them any time.",
                         [("Security calendar", "/calendar"), ("Document library", "/library")]),
}
SYSTEM_ACTORS = {"system@grc-pal.local", "cli", "test", ""}


def _item(name: str, ok: bool, detail: str = "", hint: str = "", optional: bool = False) -> dict:
    return {"name": name, "ok": bool(ok), "detail": detail, "hint": "" if ok else hint, "optional": optional}


class SetupGuideMixin:
    def setup_readiness(self, actor, step_id: str) -> dict:
        self._admin(actor)
        if step_id not in STEPS:
            raise self._invalid("Unknown setup step")
        title, why, links = STEPS[step_id]
        items = getattr(self, f"_ready_{step_id}")(actor)
        required = [i for i in items if not i["optional"]]
        return {"id": step_id, "title": title, "why": why, "links": links, "checks": items,
                "has_required": bool(required), "ready": bool(required) and all(i["ok"] for i in required)}

    def _acted(self, action: str) -> list[dict]:
        """Audit records for an action prefix made by a person (not the scheduler or the installer)."""
        return [r for r in self.log.recent(5000, "", action, "") if r.get("actor", "") not in SYSTEM_ACTORS]

    # ---------------------------------------------------------------- steps
    def _ready_cycle(self, actor) -> list[dict]:
        cur = self.active_cycle()
        set_by_person = cur.get("created_by") not in SYSTEM_ACTORS or any(
            r["target"] == cur["RowKey"] for r in self._acted("cycle.edit"))
        return [_item("Audit period confirmed", set_by_person, f"{cur['name']}: {cur['start']} to {cur['end']}",
                      "Open Cycles and export and set the name and dates of your observation period.")]

    def _ready_owners(self, actor) -> list[dict]:
        scope = self.in_scope_controls()  # out-of-scope categories (for example Privacy) need no owner yet
        controls = [c for c in self.catalog.controls if c["id"] in scope and c.get("status", "active") != "retired"]
        missing = [c["id"] for c in controls if not self.owner_emails(c["id"])]
        detail = (f"{len(controls) - len(missing)} of {len(controls)} in-scope controls have an owner; "
                  f"{len(missing)} without: {', '.join(missing[:8])}{'...' if len(missing) > 8 else ''}"
                  if missing else f"all {len(controls)} in-scope controls have an owner")
        lib = self.library_owner()
        return [_item("Every in-scope control has an owner", not missing, detail,
                      "Open a control and set its owner, or have the library owner set owners from the control "
                      "matrix import. Owners who are new get Control owner access."),
                _item("Control library owner", bool(lib), lib or "nobody",
                      "Users and roles: give the library owner role to one admin.")]

    def _ready_backups(self, actor) -> list[dict]:
        blocker = self.backups_blocker()
        items = [_item("Backup location", not blocker, "configured" if not blocker else blocker,
                       "On the server, set GRCPAL_BACKUP_DIR (the VM installer does this) and restart GRC-pal.")]
        sched = self.backup_schedule()
        items.append(_item("Backup schedule", sched["frequency"] != "off",
                           f"{sched['frequency']} at {sched['hour']:02d}:00 UTC" if sched["frequency"] != "off" else "off",
                           "Backups page: choose daily (recommended) or weekly."))
        latest = None
        if not blocker:
            for d in self._backup_dests():
                try:
                    found = d.list()
                except Exception:  # noqa: BLE001 - an unreadable location simply has no recent backup
                    found = []
                if found and (latest is None or found[0]["created"] > latest):
                    latest = found[0]["created"]
        window = dt.timedelta(days=8 if sched["frequency"] == "weekly" else 2)
        items.append(_item("A recent backup", bool(latest) and utcnow() - latest <= window,
                           f"latest {latest:%Y-%m-%d %H:%M} UTC" if latest else "none yet",
                           "Backups page: click Back up now and check that it verifies."))
        kit = self._acted("backup.kit_export")
        items.append(_item("Recovery kit saved offline", bool(kit),
                           f"exported {kit[0]['at'][:10]} by {kit[0]['actor']}" if kit else "never exported",
                           "On the server run grcpal backup kit --out recovery-kit.json (or use the Backups page when "
                           "it allows downloads), then store it in your password manager and delete the file."))
        return items

    def _ready_updates(self, actor) -> list[dict]:
        where = self.deployment
        if where == "azure":
            return [_item("Update method", True, "Azure: updates run from your program repository's workflow "
                          "(grcpal-update.yml), with a health check and automatic rollback.")]
        if where != "vm":
            return [_item("Update method", False, "manual installation",
                          "Install with the VM installer (deploy/vm/install.sh) or the Azure template so updates are "
                          "backed up, checked and rolled back automatically. A hand-run container has no updater.")]
        policy = update.read_state("policy.json", None)
        if policy is None:
            return [_item("Update policy chosen", False, "not chosen yet",
                          "Updates page: choose whether security patches install automatically and whether GRC-pal "
                          "checks online for new versions (or you bring update files).")]
        detail = (f"security patches {'automatic' if policy.get('auto_patch') else 'installed by an admin'}; "
                  f"{'checks online' if policy.get('online') else 'update files brought in by an admin'}")
        return [_item("Update policy chosen", True, detail)]

    def _ready_alerts(self, actor) -> list[dict]:
        email = next((o["status"] for o in self.settings_overview() if o["section"].id == "email"), "not_configured")
        admins = [u for u in self.users() if u.get("active", True) and u["role"] == "admin"]
        alerted = [u for u in admins if not u.get("alerts_off")]
        digests = [u for u in admins if u.get("digests")]
        return [_item("Email works", email == "ok", {"ok": "tested", "failed": "test failed"}.get(email, "not tested"),
                      "Email step: choose SMTP or Microsoft Graph, save and test. Without it nobody hears about "
                      "failures, reminders or approvals."),
                _item("Admins receiving failure alerts", bool(alerted), f"{len(alerted)} of {len(admins)} admins",
                      "Email alerts page: turn failure alerts on for at least one admin."),
                _item("Summary emails", bool(digests), f"{len(digests)} admin(s) chose a daily, weekly or monthly summary",
                      "Optional: a weekly summary is a good habit for the security lead.", optional=True)]

    def _ready_access_reviews(self, actor) -> list[dict]:
        apps = [a for a in self.store.list("arapps", "a") if a.get("active", True)]
        untested = [a["name"] for a in apps if not (a.get("last_test") or {}).get("ok")]
        return [_item("Applications in scope", bool(apps), f"{len(apps)} added",
                      "Applications page: add Microsoft Entra users, your SSO applications, Azure roles and GRC-pal "
                      "itself, plus any other system in scope."),
                _item("Each application tested", bool(apps) and not untested,
                      f"not tested or failing: {', '.join(untested[:6])}" if untested else
                      ("all tested" if apps else "nothing to test yet"),
                      "Open each application and click Test; fix what the test reports.")]

    def _ready_vendors(self, actor) -> list[dict]:
        rows = self.store.list("vendors", "v")
        return [_item("Vendor register", bool(rows), f"{len(rows)} vendor(s)",
                      "Import vendors: download the template, fill it in and upload it. Include cloud providers and "
                      "every service that stores or processes your data.")]

    def _ready_calendar_library(self, actor) -> list[dict]:
        acts = [a for a in self.calendar_activities() if a.get("status", "active") == "active"]
        reviewed = [r for r in self._acted("calendar.") if r["action"] != "calendar.seed"]
        docs = self.library(actor)["docs"]
        named = [d for d in docs if d.get("approver_is_person")]
        return [_item("Calendar reviewed", bool(reviewed), f"{len(acts)} active activities",
                      "Security calendar: check the months, owners and steps of each activity.", optional=True),
                _item("Documents with a named approver", bool(docs) and len(named) == len(docs),
                      f"{len(named)} of {len(docs)}",
                      "Document library: open each policy you will use and set the person who approves it.",
                      optional=True)]

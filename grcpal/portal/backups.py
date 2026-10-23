"""Backups page rules: who may back up, download, verify and export the recovery kit; every action audited.

Safety rules
  * Admins only, checked here (not just in the template).
  * Whole-instance backups contain every organization's data, so the page works only when this instance
    holds one organization (GRC-pal's model: one instance per customer). Otherwise it says so and backups
    stay with the operator's command line.
  * Backups are written only to locations the operator configured (backup_store.destinations()); names are
    checked against a strict pattern before any file is opened, so a request cannot reach other files.
  * On Azure the portal scales to zero, so "Back up now" is queued for the scheduled backup job instead of
    running inside a web request.
  * With GRCPAL_ENV=production, backup files and the recovery kit cannot be downloaded through the web page:
    one stolen admin session would otherwise take every record plus the keys that open them (and the saved
    integration credentials). Operators get them from the command line (`grcpal backup kit`, `deploy.sh
    --kit-out`). GRCPAL_WEB_BACKUP_DOWNLOAD=on brings the downloads back; each one is then emailed to every admin.
"""
from __future__ import annotations

import datetime as dt
import os

from grcpal import backup, backup_store
from grcpal.portal.auth import SYSTEM


def web_backup_download_allowed() -> bool:
    """Backup files and the recovery kit leave through the web page only outside production, or when the
    operator turned it on (GRCPAL_WEB_BACKUP_DOWNLOAD=on)."""
    if os.getenv("GRCPAL_ENV", "").lower() != "production":
        return True
    return os.getenv("GRCPAL_WEB_BACKUP_DOWNLOAD", "").strip().lower() in ("on", "1", "true", "yes")


WEB_DOWNLOAD_OFF = ("Backup files and the recovery kit are not downloadable from the web page in production. "
                    "Use the command line on the server (grcpal backup kit, or deploy.sh --kit-out on Azure).")


class BackupsMixin:
    # ================================================================ setup
    @property
    def backup_queue_mode(self) -> bool:
        return bool(os.getenv("GRCPAL_TABLES_URL"))

    def _backup_dests(self) -> list:
        return backup_store.destinations(self.evidence.root)

    def _backup_dest(self, dest_id: str):
        dest = next((d for d in self._backup_dests() if d.id == dest_id), None)
        if dest is None:
            raise self._invalid("Unknown backup location")
        return dest

    def backups_blocker(self) -> str:
        """'' when the Backups page can run, else why not (shown instead of the buttons)."""
        others = backup.tenants_in(self.store.backend) - {self.store.tenant}
        if others:
            return ("This instance holds more than one organization, so whole-instance backups are run by the "
                    "operator from the server's command line (grcpal backup create), not from this page.")
        if not self._backup_dests():
            return "No backup location is configured. Set GRCPAL_BACKUP_DIR on the server."
        return ""

    def _backup_ready(self, actor) -> None:
        self._admin(actor)
        if (why := self.backups_blocker()):
            raise self._invalid(why)

    def _backup_instance(self) -> backup.Instance:
        return backup.instance_for(self.store.backend, self.evidence)

    def _backup_key(self) -> bytes:
        try:
            return backup_store.backup_key(self.evidence.root)
        except backup.BackupError as exc:
            raise self._invalid(str(exc)) from None

    def backup_schedule(self) -> dict:
        return backup_store.schedule(self.settings_store.state(backup_store.STATE_KEY, {}))

    # ================================================================ page
    def backups_overview(self, actor) -> dict:
        self._admin(actor)
        state = self.settings_store.state(backup_store.STATE_KEY, {}) or {}
        sched = backup_store.schedule(state)
        dests = self._backup_dests()
        if not sched["destination"] and dests:
            sched["destination"] = dests[0].id
        places = []
        for d in dests:
            try:
                items, problem = d.list(), d.ready()
            except Exception as exc:  # noqa: BLE001 - show the problem, keep the page usable
                items, problem = [], f"Cannot read {d.where()}: {type(exc).__name__}"
            places.append({"id": d.id, "label": d.label, "where": d.where(), "kind": d.kind, "problem": problem,
                           "backups": items, "can_delete": d.can_delete})
        return {"blocker": self.backups_blocker(), "schedule": sched, "places": places,
                "queue_mode": self.backup_queue_mode, "can_restore": self.deployment == "vm",
                "request": self.settings_store.state(backup_store.REQUEST_KEY, None),
                "running": self.jobs.running("backup"), "kit": state.get("kit") or {},
                "web_download": web_backup_download_allowed(),
                "key_file": str(backup_store.key_file(self.evidence.root) or ""),
                "frequencies": backup_store.FREQUENCIES}

    def save_backup_schedule(self, actor, form: dict) -> dict:
        self._backup_ready(actor)
        try:
            sched = backup_store.validate_schedule(form, [d.id for d in self._backup_dests()])
        except ValueError as exc:
            raise self._invalid(str(exc)) from None
        state = self.settings_store.state(backup_store.STATE_KEY, {}) or {}
        before = backup_store.schedule(state)
        state.update(sched)
        self.settings_store.set_state(backup_store.STATE_KEY, state)
        self.audit(actor, "backup.schedule", "backups", {"before": before, "after": sched})
        return sched

    # ================================================================ actions
    def backup_now(self, actor, dest_id: str) -> dict:
        """VM: a background job right away. Azure: a request the backup job picks up within minutes."""
        self._backup_ready(actor)
        dest = self._backup_dest(dest_id)
        if self.backup_queue_mode:
            req = {"destination": dest.id, "by": actor.email, "at": backup_store._now().isoformat()}
            self.settings_store.set_state(backup_store.REQUEST_KEY, req)
            self.audit(actor, "backup.requested", dest.id, {"where": dest.where()})
            return {"queued": True, **req}
        if self.jobs.running("backup"):
            raise self._invalid("A backup is already running")
        key = self._backup_key()
        self.audit(actor, "backup.requested", dest.id, {"where": dest.where()})
        return self.jobs.submit("backup", f"Backup to {dest.label}", actor.email,
                                lambda job: self._run_backup(dest, key, "manual", job.log))

    def _run_backup(self, dest, key: bytes, kind: str, say=None) -> dict:
        result = backup_store.run(self._backup_instance(), dest, key, self.store.tenant, kind,
                                  sched=self.backup_schedule(), progress=say)
        for name in result.pruned:
            self.audit(SYSTEM, "backup.retention_delete", name, {"where": dest.where()})
        return {"file": result.name, "where": result.where, "verified": result.summary.get("verified_ok"),
                "sha256": result.summary.get("file_sha256"), "removed_by_retention": result.pruned}

    def verify_backup(self, actor, dest_id: str, name: str) -> dict:
        self._backup_ready(actor)
        dest = self._backup_dest(dest_id)
        if not backup_store.parse_name(name):
            raise self._invalid("Unknown backup")
        key = self._backup_key()

        def work(job):
            job.log(f"Checking {name}")
            report = backup_store.verify_existing(dest, name, key)
            self.audit(actor, "backup.verify", name, {"ok": report["ok"], "problems": report["problems"][:5]})
            return {"file": name, "ok": report["ok"], "problems": report["problems"]}
        return self.jobs.submit("backup_verify", f"Check backup {name}", actor.email, work)

    def backup_download(self, actor, dest_id: str, name: str):
        """(stream, filename). Admin only, audit-logged, and in production only when turned on (see the top)."""
        self._backup_ready(actor)
        if not web_backup_download_allowed():
            raise self._forbidden(WEB_DOWNLOAD_OFF)
        dest = self._backup_dest(dest_id)
        info = backup_store.parse_name(name)
        if not info or info["tenant"] != self.store.tenant or name not in {b["name"] for b in dest.list()}:
            raise self._invalid("Unknown backup")
        self.audit(actor, "backup.download", name, {"where": dest.where(name)})
        self._alert_admins_about_download(actor, "security.backup_download", "A backup file was downloaded",
                                          [("Backup", name)])
        return dest.open(name), name

    def recovery_kit(self, actor) -> str:
        """Backup key + app key. Admin only; recorded in the audit log and shown on the page. In production only
        when turned on (see the top)."""
        self._backup_ready(actor)
        if not web_backup_download_allowed():
            raise self._forbidden(WEB_DOWNLOAD_OFF)
        text = backup.make_kit(self._backup_key(), backup._settings_key(), self.public_url or "")
        state = self.settings_store.state(backup_store.STATE_KEY, {}) or {}
        state["kit"] = {"at": backup_store._now().isoformat(), "by": actor.email}
        self.settings_store.set_state(backup_store.STATE_KEY, state)
        self.audit(actor, "backup.kit_export", "backups", {"settings_key_included": bool(backup._settings_key())})
        self._alert_admins_about_download(actor, "security.backup_kit", "The recovery kit was downloaded",
                                          [("Holds", "the backup key and the key for saved integration credentials")])
        return text

    def _alert_admins_about_download(self, actor, kind: str, title: str, fields: list) -> None:
        """Every other active admin hears about it at once, so a download nobody expected is noticed."""
        if os.getenv("GRCPAL_ENV", "").lower() != "production":
            return
        admins = [u["RowKey"] for u in self.users() if u.get("role") == "admin" and u.get("active", True)]
        self._notify(kind, admins, actor, {
            "subject": f"GRC-pal security alert: {title.lower()}", "title": title,
            "intro": f"{actor.email} downloaded this from the Backups page. If nobody expected it, treat it as a "
                     "security incident: disable that account, rotate the backup key and the integration "
                     "credentials, and check the audit log.",
            "fields": [("By", actor.email), *fields], "button": ("Open the audit log", self.link("/audit"))})

    def run_pre_update_backup(self) -> dict:
        """The updater's mandatory backup before switching versions (operator path, so it also works when the
        instance holds several organizations; the file is then named after the instance)."""
        dests = self._backup_dests()
        if not dests:
            raise self._invalid("No backup location is configured")
        label = self.store.tenant if not (backup.tenants_in(self.store.backend) - {self.store.tenant}) else "instance"
        result = backup_store.run(self._backup_instance(), dests[0], self._backup_key(), label, "pre-update",
                                  sched=self.backup_schedule())
        if not result.summary.get("verified_ok"):
            raise self._invalid(f"The pre-update backup {result.name} did not pass its check")
        return {"file": result.name, "path": str(dests[0].local_path(result.name) or ""), "where": result.where,
                "sha256": result.summary.get("file_sha256"), "verified": True}

    # ================================================================ scheduled runner (CLI / job)
    def run_due_backups(self, now=None) -> list[dict]:
        """Called hourly by the VM timer or every 15 minutes by the Azure backup job: a queued "Back up now",
        then the schedule. Skips while another run is still working, so a long backup is never made twice."""
        if self.backups_blocker():
            return []
        now_ = now or backup_store._now()
        running = self.settings_store.state(backup_store.RUNNING_KEY, None)
        if running:
            try:
                started = dt.datetime.fromisoformat(running["at"])
            except (KeyError, TypeError, ValueError):
                started = None
            if started and now_ - started < backup_store.RUNNING_STALE:
                return []
        self.settings_store.set_state(backup_store.RUNNING_KEY, {"at": now_.isoformat()})
        try:
            return self._run_due_backups(now)
        finally:
            self.settings_store.set_state(backup_store.RUNNING_KEY, None)

    def _run_due_backups(self, now) -> list[dict]:
        done = []
        key = None
        req = self.settings_store.state(backup_store.REQUEST_KEY, None)
        if req:
            self.settings_store.set_state(backup_store.REQUEST_KEY, None)
            key = key or self._backup_key()
            dest = next((d for d in self._backup_dests() if d.id == req.get("destination")), self._backup_dests()[0])
            done.append({"kind": "manual", "requested_by": req.get("by"), **self._run_backup(dest, key, "manual")})
        sched = self.backup_schedule()
        dests = self._backup_dests()
        dest = next((d for d in dests if d.id == sched["destination"]), dests[0])
        if backup_store.due(sched, dest.list(), now):
            key = key or self._backup_key()
            done.append({"kind": "scheduled", **self._run_backup(dest, key, "scheduled")})
        return done

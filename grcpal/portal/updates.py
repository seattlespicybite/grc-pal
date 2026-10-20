"""Updates page and in-app restore (VM installs). The portal only leaves requests for the host updater
(deploy/vm/grcpal-update), which checks them again on its own; nothing here runs anything on the host.

Admins only, every request audited: update.approved, update.policy_requested, restore.requested.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import time

from grcpal import __version__, backup_store, update
from grcpal.checks import Blocked

log = logging.getLogger("grcpal.updates")

# Steps of an update as the host updater reports them in status.json (deploy/vm/grcpal-update, PROGRESS).
UPDATE_STEPS = (("checking", "Check the update file"), ("backing_up", "Backup"), ("trial", "Trial on a copy"),
                ("switching", "Switch"), ("health", "Health check"), ("done", "Done"))
ACTIVE_STATES = ("checking", "backing_up", "trial", "switching", "health", "restoring", "rolling_back")

# Release list from GitHub, kept in memory: one small request per 12 hours (15 minutes after a failure).
_FEED: dict = {}
FEED_TTL, FEED_RETRY = 12 * 3600, 15 * 60
CHECK_COOLDOWN = 60  # seconds between manual GitHub queries to avoid rate limits


class UpdatesMixin:
    @property
    def deployment(self) -> str:
        """vm (host updater present) | azure | manual"""
        if update.requests_dir() is not None:
            return "vm"
        return "azure" if os.getenv("GRCPAL_TABLES_URL") else "manual"

    def release_feed(self, online: bool, force: bool = False) -> dict:
        """Releases newer than this one, with a "do I need it?" answer each. Read from GitHub's public release
        list (nothing about this instance is sent). Off with GRCPAL_UPDATE_CHECK=off; on VMs only when the admin
        allowed the server to download releases (`online`)."""
        if os.getenv("GRCPAL_UPDATE_CHECK", "on").strip().lower() == "off" or (self.deployment == "vm" and not online):
            return {"enabled": False, "releases": []}
        repo = os.getenv("GRCPAL_UPDATE_REPO", "seattlespicybite/grc-pal")
        now = time.time()
        hit = _FEED.get(repo)
        should_fetch = not hit or now - hit["at"] > (FEED_RETRY if hit["error"] else FEED_TTL)
        if force and hit and (now - hit["at"] >= CHECK_COOLDOWN):
            should_fetch = True
        if should_fetch:
            try:
                hit = {"at": now, "rows": update.fetch_releases(repo), "error": ""}
            except (update.UpdateError, Blocked, OSError, ValueError) as exc:
                log.warning("update check failed: %s", exc)
                hit = {"at": now, "rows": (hit or {}).get("rows", []), "error": "Could not reach GitHub to check for "
                                                                                  "new releases; trying again later."}
            _FEED[repo] = hit
        releases = update.newer_releases(hit["rows"], __version__)
        return {"enabled": True, "releases": releases, "error": hit["error"],
                "checked": dt.datetime.fromtimestamp(hit["at"], dt.timezone.utc).isoformat(timespec="seconds"),
                "security": any(r["advice"]["level"] == "security" for r in releases)}

    def updates_overview(self, actor) -> dict:
        from grcpal import migrations

        self._admin(actor)
        try:
            model = migrations.check(self.store.backend)
        except migrations.SchemaError as exc:
            model = {"error": str(exc)}
        policy = {"auto_patch": False, "online": False, **(update.read_state("policy.json", {}) or {})}
        hist = update.history()
        if not hist and hasattr(self, "log") and hasattr(self.log, "recent"):
            for r in self.log.recent(limit=30):
                act = str(r.get("action") or "")
                if act.startswith("update.") or act.startswith("restore."):
                    detail = r.get("detail") or {}
                    hist.append({
                        "at": r.get("at", ""),
                        "event": act,
                        "by": r.get("actor", ""),
                        "from": detail.get("from", ""),
                        "to": detail.get("to", "") or r.get("target", ""),
                        "backup": detail.get("backup", ""),
                        "reason": detail.get("reason", "") or detail.get("error", "")
                    })
        return {"deployment": self.deployment, "version": __version__, "data_model": model,
                "status": update.read_state("status.json", {}) or {},
                "available": update.read_state("available.json", {}) or {},
                "policy": policy, "feed": self.release_feed(bool(policy.get("online"))),
                "history": hist, "pending": update.pending_requests(), "steps": UPDATE_STEPS,
                "progress": self.update_progress(actor)}

    def check_for_updates(self, actor) -> dict:
        """Trigger a manual check for updates: refresh GitHub release feed (cooldown guarded) and request host check."""
        self._admin(actor)
        policy = {"auto_patch": False, "online": False, **(update.read_state("policy.json", {}) or {})}
        req = None
        if self.deployment == "vm":
            try:
                req = update.write_request("check", {}, actor.email)
            except update.UpdateError as exc:
                log.warning("could not write check request: %s", exc)
        repo = os.getenv("GRCPAL_UPDATE_REPO", "seattlespicybite/grc-pal")
        hit_before = _FEED.get(repo)
        was_recent = bool(hit_before and (time.time() - hit_before["at"] < CHECK_COOLDOWN))
        feed = self.release_feed(bool(policy.get("online")), force=True)
        count = len(feed.get("releases", []))
        newest = feed["releases"][0]["version"] if count else None
        detail = {"releases_found": count, "newest": newest, "error": feed.get("error", ""), "cached": was_recent}
        if req:
            detail["request"] = req["id"]
        self.audit(actor, "update.checked", "updates", detail)
        return {"feed": feed, "count": count, "newest": newest, "error": feed.get("error", ""), "recent": was_recent}

    def verify_installation(self, actor) -> dict:
        """Submit a background job to verify data model, audit log, and evidence for this tenant only."""
        self._admin(actor)

        def work(job):
            from grcpal import migrations

            job.log("Checking data model...")
            problems, checked = [], {}
            try:
                checked["data_model"] = migrations.check(self.store.backend)
            except migrations.SchemaError as exc:
                problems.append(str(exc))

            job.log("Checking audit log hash chain...")
            audit_res = self.log.verify()
            checked["audit"] = {"ok": audit_res["ok"], "records": audit_res["records"]}
            if not audit_res["ok"]:
                problems.extend(audit_res["problems"][:3])

            job.log("Checking evidence files...")
            files_checked, runs_checked = 0, 0
            if hasattr(self, "evidence") and hasattr(self.evidence, "root"):
                tenant_dir = (self.evidence.root / self.evidence.namespace
                              if getattr(self.evidence, "namespace", "") and (self.evidence.root / self.evidence.namespace).is_dir()
                              else self.evidence.root)
                if tenant_dir.is_dir():
                    runs = sorted(p.parent for p in tenant_dir.rglob("manifest.json"))
                    runs_checked = len(runs)
                    for run in runs:
                        try:
                            man = json.loads((run / "manifest.json").read_text())
                        except (OSError, ValueError):
                            problems.append(f"evidence run {run.name}: manifest unreadable")
                            continue
                        for f in man.get("files", []):
                            p = run / f.get("name", "")
                            try:
                                digest = hashlib.file_digest(p.open("rb"), "sha256").hexdigest()
                            except OSError:
                                problems.append(f"evidence file {f.get('name')}: missing")
                                continue
                            files_checked += 1
                            if digest != f.get("sha256"):
                                problems.append(f"evidence file {f.get('name')}: changed")
            checked["evidence"] = {"runs_checked": runs_checked, "files_checked": files_checked}

            ok = not problems
            job.log(f"Verification {'passed' if ok else 'failed'}")
            self.audit(actor, "update.verified", "updates", {"ok": ok, "problems": problems[:5]})
            return {"ok": ok, "problems": problems, "checked": checked}

        return self.jobs.submit("update_verify", "Verify installation", actor.email, work)

    def update_progress(self, actor) -> dict:
        """What the updater is doing now, for the live progress bar (polled by the Updates page)."""
        self._admin(actor)
        st = update.read_state("status.json", {}) or {}
        pending = bool(update.pending_requests())
        state = str(st.get("state") or "")
        percent = st.get("percent")
        return {"state": state, "message": str(st.get("message") or ""), "at": str(st.get("at") or ""),
                "percent": percent if isinstance(percent, int) and 0 <= percent <= 100 else None,
                "active": pending or state in ACTIVE_STATES, "pending": pending}

    def approve_update(self, actor, version: str) -> dict:
        self._admin(actor)
        available = update.read_state("available.json", {}) or {}
        if not version or available.get("version") != version:
            raise self._invalid("That update is not waiting for approval (refresh the page)")
        try:
            req = update.write_request("apply", {"version": version}, actor.email)
        except update.UpdateError as exc:
            raise self._invalid(str(exc)) from None
        self.audit(actor, "update.approved", version, {"kind": available.get("kind"), "from": __version__,
                                                       "request": req["id"]})
        return req

    def set_update_policy(self, actor, auto_patch: bool, online: bool) -> dict:
        self._admin(actor)
        try:
            req = update.write_request("policy", {"auto_patch": bool(auto_patch), "online": bool(online)}, actor.email)
        except update.UpdateError as exc:
            raise self._invalid(str(exc)) from None
        self.audit(actor, "update.policy_requested", "updates", {"auto_patch": bool(auto_patch), "online": bool(online)})
        return req

    def request_restore(self, actor, dest_id: str, name: str, confirm: str) -> dict:
        """Replace this instance's data with a backup (VM). Typed confirmation; the current data is kept aside."""
        self._backup_ready(actor)
        if self.deployment != "vm":
            raise self._invalid("In-app restore needs the VM updater; on Azure restore into a new instance "
                                "(docs/deploy-azure.md)")
        if (confirm or "").strip() != "RESTORE":
            raise self._invalid("Type RESTORE to confirm")
        dest = self._backup_dest(dest_id)
        if dest.kind != "folder" or dest.id != "local":
            raise self._invalid("Restore from the backups on this server (copy others there first)")
        info = backup_store.parse_name(name)
        listed = {b["name"]: b for b in dest.list()}
        if not info or name not in listed:
            raise self._invalid("Unknown backup")
        if not (listed[name].get("summary") or {}).get("verified_ok"):
            raise self._invalid("Check this backup first (it has not passed its check)")
        try:
            req = update.write_request("restore", {"backup": name}, actor.email)
        except update.UpdateError as exc:
            raise self._invalid(str(exc)) from None
        self.audit(actor, "restore.requested", name, {"request": req["id"], "created": info["created"].isoformat()})
        return req

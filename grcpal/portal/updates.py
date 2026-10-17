"""Updates page and in-app restore (VM installs). The portal only leaves requests for the host updater
(deploy/vm/grcpal-update), which checks them again on its own; nothing here runs anything on the host.

Admins only, every request audited: update.approved, update.policy_requested, restore.requested.
"""
from __future__ import annotations

import os

from grcpal import __version__, backup_store, update


class UpdatesMixin:
    @property
    def deployment(self) -> str:
        """vm (host updater present) | azure | manual"""
        if update.requests_dir() is not None:
            return "vm"
        return "azure" if os.getenv("GRCPAL_TABLES_URL") else "manual"

    def updates_overview(self, actor) -> dict:
        from grcpal import migrations

        self._admin(actor)
        try:
            model = migrations.check(self.store.backend)
        except migrations.SchemaError as exc:
            model = {"error": str(exc)}
        return {"deployment": self.deployment, "version": __version__, "data_model": model,
                "status": update.read_state("status.json", {}) or {},
                "available": update.read_state("available.json", {}) or {},
                "policy": {"auto_patch": True, "online": False, **(update.read_state("policy.json", {}) or {})},
                "history": update.history(), "pending": update.pending_requests()}

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

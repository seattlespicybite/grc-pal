"""Portal business logic.

Every read and write is authorized here, not only in the UI, and every write is recorded in
the tamper-evident audit log. The service only ever receives a TenantStore, so it cannot reach
another organization's data.

Roles (exactly one per user):
  admin       everything
  contributor only controls they own (catalog/roles.yaml) or are assigned to; upload, comment
  auditor     read-only: controls, evidence, comments, overrides, audit log, exports
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import uuid
import zipfile

from grcpal.evidence import INTEGRITY_FILES, EvidenceStore, public_key_pem, utcnow, verify_source
from grcpal.portal import notify
from grcpal.portal.auditlog import AuditLog
from grcpal.portal.accounts import AccountsMixin
from grcpal.portal.backups import BackupsMixin
from grcpal.portal.updates import UpdatesMixin
from grcpal.portal.calendar import CalendarMixin
from grcpal.portal.automation import AutomationMixin
from grcpal.portal.features import FeaturesMixin
from grcpal.portal.accessapps import AccessAppsMixin
from grcpal.portal.accessreview import AccessReviewMixin
from grcpal.portal.doclib import DocLibMixin
from grcpal.portal.vendor_import import VendorImportMixin
from grcpal.portal.matrix import MatrixMixin
from grcpal.portal.vendors import VendorsMixin
from grcpal.portal.auth import ROLES, SYSTEM, AuthError, Identity, User, bootstrap_admins, group_role
from grcpal.portal.mailer import ConsoleMailer, Mailer, Message
from grcpal.portal.security import csv_cell, safe_filename, validate_upload
from grcpal.tasks import period_label

EMAIL = re.compile(r"^[^@\s]{1,64}@(?=[^@\s]{1,253}\Z)[^@\s.]+(?:\.[^@\s.]+)+\Z")  # linear time: labels cannot overlap
RUN_ID = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{6}Z$")
SLUG = re.compile(r"[^a-z0-9]+")
MIN_JUSTIFICATION = 30
MAX_OVERRIDE_DAYS = 365
REMINDER_COOLDOWN_HOURS = 12
OPEN_STATES = ("open", "returned", "submitted")
APPROVAL_NOTE_ERROR = ("Add an approval note: who approved this evidence and when, for example "
                       "'Approved by the CEO on 2026-09-30' (at least 10 characters)")
CLOSED_STATES = ("approved", "cancelled")


class Forbidden(Exception):
    pass


class Invalid(Exception):
    pass


def _now() -> str:
    return utcnow().isoformat()


def _rk() -> str:
    return f"{utcnow():%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:10]}"


class Portal(FeaturesMixin, MatrixMixin, CalendarMixin, AutomationMixin, VendorsMixin, VendorImportMixin, DocLibMixin,
             AccessReviewMixin, AccessAppsMixin, AccountsMixin, BackupsMixin, UpdatesMixin):
    def __init__(self, catalog, store, evidence: EvidenceStore, mailer: Mailer | None = None,
                 today: dt.date | None = None, public_url: str | None = None, jobs_sync: bool | None = None) -> None:
        self.base_catalog, self.store, self.evidence = catalog, store, evidence
        self.log = AuditLog(store)
        evidence.on_seal = self._seal_evidence  # one portal per evidence store and tenant
        self._today = today
        self._init_features(os.getenv("GRCPAL_JOBS_SYNC") == "1" if jobs_sync is None else jobs_sync)
        self._explicit_mailer = mailer is not None
        if mailer is not None:
            self.mailer = mailer
            self.mailer.on_result = self._mail_result
        else:
            self.mailer = ConsoleMailer("grc-pal@localhost", sync=True)
            self.apply_settings()
        self.public_url = (public_url or os.getenv("GRCPAL_PUBLIC_URL") or "http://localhost:8000").rstrip("/")
        self.ensure_cycle()

    @staticmethod
    def _invalid(message: str) -> "Invalid":
        return Invalid(message)

    @staticmethod
    def _forbidden(message: str) -> "Forbidden":
        return Forbidden(message)

    @staticmethod
    def _email_ok(email: str) -> bool:
        return bool(EMAIL.match(email))

    @property
    def today(self) -> dt.date:
        return self._today or dt.datetime.now(dt.timezone.utc).date()

    @property
    def org(self) -> str:
        return self.settings.get("GRCPAL_ORG_NAME") or self.base_catalog.scope.get("organization") or "your organization"

    def link(self, path: str) -> str:
        return f"{self.public_url}{path}"

    def audit(self, actor: User | str, action: str, target: str, detail: dict | None = None) -> dict:
        return self.log.append(actor if isinstance(actor, str) else actor.email, action, target, detail)

    # ================================================================ users
    def user_row(self, email: str) -> dict | None:
        return self.store.get("users", "u", (email or "").lower())

    def users(self) -> list[dict]:
        return sorted(self.store.list("users", "u"), key=lambda u: (not u.get("active", True), u["role"], u["RowKey"]))

    def active_emails(self, *roles: str) -> list[str]:
        return [u["RowKey"] for u in self.users() if u.get("active", True) and (not roles or u["role"] in roles)]

    def resolve(self, identity: Identity) -> User:
        """Map a signed-in identity to a portal user, creating the row on first sign-in when allowed."""
        row = self.user_row(identity.email)
        if row:
            self._check_access(row)
            row = self._check_identity_binding(row, identity)
            if (row.get("last_seen") or "") < (utcnow() - dt.timedelta(hours=1)).isoformat():
                fields = {"last_seen": _now()}
                if identity.name and identity.name != identity.email:
                    fields["name"] = identity.name[:120]
                row = self.store.update("users", "u", row["RowKey"], fields)
            return User(email=row["RowKey"], name=row.get("name") or identity.name, role=row["role"])
        role, source = None, ""
        if identity.email in bootstrap_admins():
            role, source = "admin", "bootstrap"
        elif group_role(identity.groups):
            role, source = group_role(identity.groups), "group"
        elif identity.email in self.all_owner_emails():
            role, source = "contributor", "roles.yaml"
        if not role:
            raise AuthError("you have not been given access to GRC-pal yet; ask an admin to add you", 403)
        self._create_user(identity.email, identity.name, role, source, SYSTEM.email)
        self._check_identity_binding(self.user_row(identity.email), identity)
        return User(email=identity.email, name=identity.name, role=role)

    def _check_identity_binding(self, row: dict, identity: Identity) -> dict:
        """Tie a person to their Microsoft Entra object ID (and tenant) at their first sign-in that carries one.
        An email address can be given to someone else or renamed; the object ID never changes. A later sign-in
        with the same email but another object ID is refused until an admin clears the binding."""
        if not identity.object_id:
            return row  # this sign-in layer (proxy, dev) has no object IDs
        bound_oid, bound_tid = row.get("entra_oid") or "", row.get("entra_tid") or ""
        if not bound_oid:
            row = self.store.update("users", "u", row["RowKey"],
                                    {"entra_oid": identity.object_id, "entra_tid": identity.tenant_id})
            self.audit(SYSTEM, "user.identity_bound", row["RowKey"],
                       {"entra_oid": identity.object_id, "entra_tid": identity.tenant_id})
            return row
        if (bound_oid, bound_tid) != (identity.object_id, identity.tenant_id):
            self.events.security(f"Sign-in refused for {row['RowKey']}: a different Microsoft Entra account "
                                 "used this email address", actor=row["RowKey"], bound_oid=bound_oid,
                                 bound_tid=bound_tid, oid=identity.object_id, tid=identity.tenant_id)
            raise AuthError("this email address belongs to a different Microsoft Entra account in GRC-pal; ask an "
                            "admin to check it and clear the old link on Users and roles", 403)
        return row

    def reset_identity_binding(self, actor: User, email: str) -> None:
        """Admin: forget the Entra object ID linked to this person, so their next sign-in links a new one (for
        example after their Entra account was deleted and created again)."""
        self._admin(actor)
        row = self.user_row(email)
        if not row:
            raise Invalid("User not found")
        old = {"entra_oid": row.get("entra_oid") or "", "entra_tid": row.get("entra_tid") or ""}
        self.store.update("users", "u", row["RowKey"], {"entra_oid": "", "entra_tid": ""})
        self.audit(actor, "user.identity_reset", row["RowKey"], old)

    def _create_user(self, email: str, name: str, role: str, source: str, by: str) -> dict:
        row = {"PartitionKey": "u", "RowKey": email, "name": name or email, "role": role, "active": True,
               "source": source, "created_by": by, "created_at": _now(), "last_seen": ""}
        self.store.insert("users", row)
        self.audit(by, "user.create", email, {"role": role, "source": source})
        return row

    def add_user(self, actor: User, email: str, name: str, role: str, access_until: str = "") -> dict:
        self._admin(actor)
        email = (email or "").strip().lower()
        if not EMAIL.match(email):
            raise Invalid(f"'{email}' is not a valid email address")
        if role not in ROLES:
            raise Invalid("Role must be Admin, Control owner or Auditor")
        if self.user_row(email):
            raise Invalid(f"{email} already has access; change their role instead")
        until = self._auditor_until(access_until) if role == "auditor" else ""
        row = self._create_user(email, (name or "").strip()[:120], role, "admin", actor.email)
        if until:
            row = self.store.update("users", "u", email, {"access_until": until})
            self.audit(actor, "user.access_until", email, {"from": "", "to": until})
        return row

    # ---------------------------------------------------------------- control library owner
    def library_owner(self) -> str:
        """Email of the one admin who may change control definitions (owners, text, mappings), or "" if nobody."""
        for u in self.store.list("users", "u"):
            if u.get("library_owner") and u.get("active", True) and u["role"] == "admin":
                return u["RowKey"]
        return ""

    def is_library_owner(self, user: User) -> bool:
        # read live from the users table, so a change applies at once, not at the next sign-in
        return bool(user.is_admin and self.library_owner() == user.email)

    def _library(self, actor: User) -> None:
        if not self.is_library_owner(actor):
            raise Forbidden("Only the control library owner can change control definitions"
                            + ("" if self.library_owner() else "; an admin must take on that role first (Users and roles)"))

    def set_library_owner(self, actor: User, email: str) -> None:
        """Hand the control library owner role to an active admin. Only the current holder can hand it over;
        when nobody holds it (for example the holder left), any admin can take it on or give it."""
        self._admin(actor)
        current = self.library_owner()
        if current and current != actor.email:
            raise Forbidden(f"Only the current control library owner ({current}) can hand this role over")
        row = self.user_row(email)
        if not row or row["role"] != "admin" or not row.get("active", True):
            raise Invalid("The control library owner must be an active admin")
        if current == row["RowKey"]:
            return
        if current:
            self.store.update("users", "u", current, {"library_owner": False})
        self.store.update("users", "u", row["RowKey"], {"library_owner": True})
        self.audit(actor, "library_owner.set", row["RowKey"], {"from": current or None, "to": row["RowKey"]})

    def _drop_library_owner(self, actor: User, row: dict, why: str) -> None:
        if row.get("library_owner"):
            self.store.update("users", "u", row["RowKey"], {"library_owner": False})
            self.audit(actor, "library_owner.cleared", row["RowKey"], {"reason": why})

    def _last_admin_guard(self, email: str) -> None:
        if self.active_emails("admin") == [email]:
            raise Invalid("This is the last active admin. Add another admin first.")

    def set_role(self, actor: User, email: str, role: str) -> None:
        self._admin(actor)
        row = self.user_row(email)
        if not row:
            raise Invalid("User not found")
        if role not in ROLES:
            raise Invalid("Role must be Admin, Control owner or Auditor")
        if row["role"] == role:
            return
        if row["role"] == "admin":
            self._last_admin_guard(row["RowKey"])
        # auditors always have an access end date; other roles never do
        until = self._auditor_until("") if role == "auditor" else ""
        if row["role"] == "admin":
            self._drop_library_owner(actor, row, f"role changed to {role}")
        self.store.update("users", "u", row["RowKey"], {"role": role, "access_until": until})
        self.revoke_sessions(row["RowKey"])  # new permissions take effect at the next sign-in
        self.audit(actor, "user.role", row["RowKey"], {"from": row["role"], "to": role, "access_until": until})

    def set_active(self, actor: User, email: str, active: bool) -> None:
        self._admin(actor)
        row = self.user_row(email)
        if not row:
            raise Invalid("User not found")
        if not active and row["role"] == "admin":
            self._last_admin_guard(row["RowKey"])
        if not active:
            self._drop_library_owner(actor, row, "account disabled")
        self.store.update("users", "u", row["RowKey"], {"active": bool(active)})
        if not active:
            self.revoke_sessions(row["RowKey"])
        self.audit(actor, "user.enable" if active else "user.disable", row["RowKey"], {})

    def _ensure_contributor(self, actor: User, email: str) -> None:
        row = self.user_row(email)
        if row is None:
            self._create_user(email, email, "contributor", "assignment", actor.email)
        elif not row.get("active", True):
            raise Invalid(f"{email} is disabled; enable the account before assigning work")
        elif row["role"] == "auditor":
            raise Invalid(f"{email} is an auditor (read-only) and cannot be assigned work")

    @staticmethod
    def _admin(actor: User) -> None:
        if not actor.is_admin:
            raise Forbidden("Only admins can do this")

    # ================================================================ catalog helpers
    def role_emails(self, role: str) -> list[str]:
        value = (self.catalog.roles.get(role) or {}).get("email") or []
        values = value if isinstance(value, list) else [value]
        return [v.lower() for v in values if v and v != "TBD"]

    def all_owner_emails(self) -> set[str]:
        return {e for r in self.catalog.roles for e in self.role_emails(r)}

    def owner_emails(self, control_id: str) -> list[str]:
        ctl = self.catalog.control(control_id)
        if not ctl:
            return []
        return sorted(set(self.role_emails(ctl["owner"])) | set(ctl.get("owner_emails") or []))

    def owned_controls(self, email: str) -> set[str]:
        return {c["id"] for c in self.catalog.controls
                if email in self.role_emails(c["owner"]) or email in (c.get("owner_emails") or [])}

    def evidence_wanted(self, control_ids: list[str]) -> list[str]:
        out = []
        for cid in control_ids:
            ctl = self.catalog.control(cid)
            for ev in (ctl or {}).get("evidence", []):
                out.append(f"{ev['artifact']}" + (f" ({cid})" if len(control_ids) > 1 else ""))
        return out

    # ================================================================ cycles
    def cycles(self) -> list[dict]:
        return sorted(self.store.list("cycles", "c"), key=lambda c: c["start"], reverse=True)

    def cycle(self, cycle_id: str) -> dict | None:
        return self.store.get("cycles", "c", cycle_id) if cycle_id else None

    def cycle_name(self, cycle_id: str) -> str:
        c = self.cycle(cycle_id)
        return c["name"] if c else cycle_id

    def active_cycle(self) -> dict:
        active = [c for c in self.cycles() if c["status"] == "active"]
        return active[0] if active else self.ensure_cycle()

    def previous_cycle(self, cycle: dict | None = None) -> dict | None:
        cycle = cycle or self.active_cycle()
        return self.cycle(cycle.get("previous", ""))

    def ensure_cycle(self) -> dict:
        existing = [c for c in self.store.list("cycles", "c") if c["status"] == "active"]
        if existing:
            return existing[0]
        start = self.today
        row = {"PartitionKey": "c", "RowKey": f"{start.year}", "name": f"{start.year} cycle", "start": start.isoformat(),
               "end": (start + dt.timedelta(days=364)).isoformat(), "status": "active", "previous": "",
               "created_by": SYSTEM.email, "created_at": _now(), "closed_at": "", "closed_by": ""}
        if self.cycle(row["RowKey"]):
            row["RowKey"] = f"{start.year}-{uuid.uuid4().hex[:4]}"
        self.store.insert("cycles", row)
        self.audit(SYSTEM, "cycle.start", row["RowKey"], {"name": row["name"], "carried": 0})
        return row

    def edit_cycle(self, actor: User, name: str, start: str, end: str) -> dict:
        """Change the name and dates of the active cycle (the audit period). The first cycle is created
        automatically on the first day the portal runs, so this is how an admin sets the real observation
        window. Closed cycles never change."""
        self._admin(actor)
        cur = self.active_cycle()
        name = " ".join((name or "").split())[:80]
        if not name:
            raise Invalid("Give the cycle a name, for example FY2027 or 2027 Type 2 window")
        try:
            s, e = dt.date.fromisoformat((start or "").strip()), dt.date.fromisoformat((end or "").strip())
        except ValueError as exc:
            raise Invalid("Dates must be YYYY-MM-DD") from exc
        if e <= s or (e - s).days > 731:
            raise Invalid("The end date must be after the start date and within two years of it")
        prev = self.previous_cycle(cur)
        if prev and s.isoformat() <= prev["start"]:
            raise Invalid(f"The start must be after the previous cycle started ({prev['start']})")
        after = {"name": name, "start": s.isoformat(), "end": e.isoformat()}
        before = {k: cur.get(k) for k in after}
        if before == after:
            raise Invalid("Nothing changed")
        self.store.update("cycles", "c", cur["RowKey"], after)
        self.audit(actor, "cycle.edit", cur["RowKey"], {"before": before, "after": after})
        return {**cur, **after}

    def start_cycle(self, actor: User, name: str, start: str, end: str, carry_forward: bool = True) -> dict:
        """Close the active cycle and open a new one. Carry-forward copies every assignment that was
        not cancelled, with the same owner, contributors and instructions, linked to last cycle's work."""
        self._admin(actor)
        name = (name or "").strip()[:80]
        if not name:
            raise Invalid("Give the cycle a name, for example FY2027 or 2027 Type 2 window")
        try:
            s, e = dt.date.fromisoformat(start), dt.date.fromisoformat(end)
        except ValueError as exc:
            raise Invalid("Dates must be YYYY-MM-DD") from exc
        if e <= s or (e - s).days > 731:
            raise Invalid("The end date must be after the start date and within two years of it")
        cid = SLUG.sub("-", name.lower()).strip("-")[:40] or uuid.uuid4().hex[:8]
        if self.cycle(cid):
            raise Invalid("A cycle with that name already exists")
        old = self.active_cycle()
        now = _now()
        self.store.update("cycles", "c", old["RowKey"], {"status": "closed", "closed_at": now, "closed_by": actor.email})
        new = {"PartitionKey": "c", "RowKey": cid, "name": name, "start": s.isoformat(), "end": e.isoformat(),
               "status": "active", "previous": old["RowKey"], "created_by": actor.email, "created_at": now,
               "closed_at": "", "closed_by": ""}
        self.store.insert("cycles", new)
        carried = 0
        if carry_forward:
            old_start = dt.date.fromisoformat(old["start"])
            for a in self.assignments(cycle=old["RowKey"]):
                if a["status"] == "cancelled":
                    continue
                offset = (dt.date.fromisoformat(a["due"]) - old_start).days
                due = min(max(s + dt.timedelta(days=max(offset, 0)), self.today, s), e)
                self._insert_assignment(actor, new["RowKey"], a["target_type"], a["target_id"], a["label"], a["controls"],
                                        a["assignee"], a.get("contributors", []), due.isoformat(), a["instructions"],
                                        a.get("task", ""), "", previous=a["RowKey"], notify_people=False)
                carried += 1
        self.audit(actor, "cycle.close", old["RowKey"], {"name": old["name"]})
        self.audit(actor, "cycle.start", cid, {"name": name, "start": new["start"], "end": new["end"], "carried": carried,
                                               "previous": old["RowKey"]})
        return new

    def _writable_cycle(self, cycle_id: str) -> None:
        if cycle_id != self.active_cycle()["RowKey"]:
            raise Invalid("That cycle is closed; work happens in the active cycle")

    # ================================================================ visibility
    @staticmethod
    def participants(a: dict) -> set[str]:
        return {a["assignee"], *a.get("contributors", [])}

    def visible_controls(self, user: User) -> set[str] | None:
        """None means every control (admins and auditors)."""
        if user.sees_everything:
            return None
        ids = self.owned_controls(user.email)
        for a in self.store.list("assignments", "a"):
            if user.email in self.participants(a) and a["status"] != "cancelled":
                ids.update(a["controls"])
        return ids

    def can_see_control(self, user: User, control_id: str) -> bool:
        vis = self.visible_controls(user)
        return vis is None or control_id in vis

    def can_see_assignment(self, user: User, a: dict) -> bool:
        return user.sees_everything or user.email in self.participants(a)

    def can_upload(self, user: User, a: dict) -> bool:
        if a["status"] in CLOSED_STATES or a["cycle"] != self.active_cycle()["RowKey"]:
            return False
        return user.is_admin or (user.is_contributor and user.email in self.participants(a))

    def can_upload_control(self, user: User, control_id: str) -> bool:
        if user.is_admin:
            return True
        if not user.is_contributor:
            return False
        return control_id in self.owned_controls(user.email) or any(
            self.can_upload(user, a) for a in self.assignments(control=control_id))

    def can_comment(self, user: User, control_ids: list[str]) -> bool:
        return user.is_admin or (user.is_contributor and any(self.can_see_control(user, c) for c in control_ids))

    # ================================================================ targets and assignments
    def resolve_target(self, target_type: str, target_id: str) -> tuple[str, list[str]]:
        if target_type == "control":
            ctl = self.catalog.control(target_id)
            if not ctl:
                raise Invalid(f"Unknown control {target_id}")
            return f"{ctl['id']} {ctl['title']}", [ctl["id"]]
        if target_type == "point":
            for points in self.catalog.points_of_focus.values():
                for p in points:
                    if p["id"] == target_id:
                        if not p.get("controls"):
                            raise Invalid(f"{target_id} has no mapped control yet; assign a control first")
                        return f"{p['id']} {p['point']}", list(p["controls"])
            raise Invalid(f"Unknown point of focus {target_id}")
        if target_type == "task":
            task = self.catalog.tasks.get(target_id)
            if not task:
                raise Invalid(f"Unknown task {target_id}")
            return task["title"], sorted(set(self.catalog.sources("task").get(target_id, [])) | set(task.get("controls") or []))
        raise Invalid("Target must be a control, point of focus or task")

    def create_assignment(self, actor: User, target_type: str, target_id: str, assignee: str, contributors: list[str],
                          due: str, instructions: str, task: str | None = None, period: str | None = None) -> dict:
        self._admin(actor)
        label, controls = self.resolve_target(target_type, target_id)
        if not controls:
            raise Invalid("The target is not linked to any control")
        assignee = (assignee or "").strip().lower()
        contributors = sorted({c.strip().lower() for c in contributors if c.strip()} - {assignee})
        for email in [assignee, *contributors]:
            if not EMAIL.match(email):
                raise Invalid(f"'{email}' is not a valid email address")
        try:
            due_date = dt.date.fromisoformat(due)
        except ValueError as exc:
            raise Invalid("Due date must be YYYY-MM-DD") from exc
        if due_date < self.today:
            raise Invalid("Due date cannot be in the past")
        for email in [assignee, *contributors]:
            self._ensure_contributor(actor, email)
        return self._insert_assignment(actor, self.active_cycle()["RowKey"], target_type, target_id, label, controls,
                                       assignee, contributors, due_date.isoformat(), instructions, task or "", period or "")

    def _insert_assignment(self, actor: User, cycle: str, target_type: str, target_id: str, label: str, controls: list,
                           assignee: str, contributors: list, due: str, instructions: str, task: str, period: str,
                           previous: str = "", notify_people: bool = True) -> dict:
        now = _now()
        a = {"PartitionKey": "a", "RowKey": uuid.uuid4().hex, "cycle": cycle, "target_type": target_type,
             "target_id": target_id, "label": label, "controls": controls, "assignee": assignee,
             "contributors": contributors, "due": due, "instructions": (instructions or "").strip()[:4000],
             "status": "open", "task": task, "period": period, "previous": previous,
             "created_by": actor.email, "created_at": now, "updated_at": now, "approved_at": ""}
        self.store.insert("assignments", a)
        self.audit(actor, "assignment.create", a["RowKey"], {"controls": controls, "target": target_id,
                                                            "assignee": assignee, "due": due, "cycle": cycle,
                                                            "previous": previous or None})
        if notify_people:
            self._notify("assigned", [assignee, *contributors], actor, notify.assigned(self, a, actor), controls)
        return a

    def assignment(self, assignment_id: str) -> dict:
        a = self.store.get("assignments", "a", assignment_id or "-")
        if not a:
            raise Invalid("Assignment not found")
        a["overdue"] = a["status"] in ("open", "returned") and a["due"] < self.today.isoformat()
        return a

    def assignments(self, *, user: User | None = None, mine: bool = False, status: str | None = None,
                    control: str | None = None, cycle: str | None = "active") -> list[dict]:
        rows = self.store.list("assignments", "a")
        if cycle == "active":
            cycle = self.active_cycle()["RowKey"]
        if cycle:
            rows = [a for a in rows if a["cycle"] == cycle]
        if mine and user:
            rows = [a for a in rows if user.email in self.participants(a)]
        if status:
            rows = [a for a in rows if a["status"] == status]
        if control:
            rows = [a for a in rows if control in a["controls"]]
        today = self.today.isoformat()
        for a in rows:
            a["overdue"] = a["status"] in ("open", "returned") and a["due"] < today
        return sorted(rows, key=lambda a: (a["status"] in CLOSED_STATES, a["due"]))

    def edit_assignment(self, actor: User, assignment_id: str, assignee: str, contributors: list[str], due: str,
                        instructions: str) -> dict:
        """Change who works on an open request, the helpers, due date or instructions. Uploads keep their
        original uploader; people who are removed lose access to the request; people who are added are emailed."""
        self._admin(actor)
        a = self.assignment(assignment_id)
        if a["status"] in CLOSED_STATES or a["cycle"] != self.active_cycle()["RowKey"]:
            raise Invalid("Only open requests in the current cycle can be changed")
        assignee = (assignee or "").strip().lower()
        contributors = sorted({c.strip().lower() for c in contributors if c.strip()} - {assignee})
        for email in [assignee, *contributors]:
            if not EMAIL.match(email):
                raise Invalid(f"'{email}' is not a valid email address")
        try:
            due_date = dt.date.fromisoformat(due)
        except ValueError as exc:
            raise Invalid("Due date must be YYYY-MM-DD") from exc
        if due_date < self.today and due_date.isoformat() != a["due"]:
            raise Invalid("Due date cannot be in the past")
        for email in [assignee, *contributors]:
            self._ensure_contributor(actor, email)
        new = {"assignee": assignee, "contributors": contributors, "due": due_date.isoformat(),
               "instructions": (instructions or "").strip()[:4000]}
        changes = {k: {"from": a.get(k), "to": v} for k, v in new.items() if a.get(k) != v}
        if not changes:
            return a
        row = self.store.update("assignments", "a", assignment_id, {**new, "updated_at": _now()})
        detail = {k: v for k, v in changes.items() if k != "instructions"}
        if "instructions" in changes:
            detail["instructions_changed"] = True
        self.audit(actor, "assignment.edit", assignment_id, {"controls": a["controls"], **detail})
        added = ({assignee, *contributors}) - self.participants(a)
        if added:
            self._notify("assigned", sorted(added), actor, notify.assigned(self, row, actor), a["controls"])
        return row

    def cancel_assignment(self, actor: User, assignment_id: str, reason: str) -> None:
        self._admin(actor)
        a = self.assignment(assignment_id)
        if len((reason or "").strip()) < 5:
            raise Invalid("Give a reason for cancelling (at least 5 characters)")
        self.store.update("assignments", "a", assignment_id, {"status": "cancelled", "updated_at": _now()})
        self.audit(actor, "assignment.cancel", assignment_id, {"controls": a["controls"], "reason": reason[:500]})

    # ================================================================ uploads and review
    def upload(self, actor: User, filename: str, data: bytes, note: str, *, assignment_id: str | None = None,
               control_id: str | None = None, approval_note: str = "") -> dict:
        """Store evidence write-once. Admins own the program and upload evidence that is already approved, so
        their upload is approved on upload and must say who approved it and when; uploads from control owners
        wait for any admin to review them."""
        a = None
        approval_note = (approval_note or "").strip()
        if actor.is_admin and len(approval_note) < 10:
            raise Invalid(APPROVAL_NOTE_ERROR)
        if assignment_id:
            a = self.assignment(assignment_id)
            if not self.can_upload(actor, a):
                if a["status"] in CLOSED_STATES or a["cycle"] != self.active_cycle()["RowKey"]:
                    raise Invalid(f"This request is {a['status'] if a['status'] in CLOSED_STATES else 'in a closed cycle'}; "
                                  "ask an admin to open a new one")
                raise Forbidden("You are not assigned to this work")
            controls = a["controls"]
        else:
            if not self.catalog.control(control_id or ""):
                raise Invalid("Unknown control")
            if not self.can_upload_control(actor, control_id):
                raise Forbidden("You can only upload evidence for controls you own or are assigned to")
            controls = [control_id]
            mine = [x for x in self.assignments(control=control_id) if self.can_upload(actor, x)
                    and actor.email in self.participants(x)]
            a = mine[0] if mine else None
        name = safe_filename(filename)
        error = validate_upload(name, data)
        if error:
            raise Invalid(error)
        cycle = self.active_cycle()["RowKey"]
        run = self.evidence.new_run("portal_upload", controls, {
            "uploaded_by": actor.email, "assignment": a["RowKey"] if a else None, "cycle": cycle,
            "target": a["target_id"] if a else control_id, "comment": (note or "")[:2000]})
        run.add_bytes(name, data)
        manifest = run.finish([])
        u = {"PartitionKey": "u", "RowKey": uuid.uuid4().hex, "cycle": cycle, "assignment": a["RowKey"] if a else "",
             "controls": controls, "target_id": a["target_id"] if a else control_id, "filename": name,
             "evidence_run": run.prefix, "sha256": manifest["files"][0]["sha256"], "size": len(data),
             "comment": (note or "").strip()[:2000], "uploaded_by": actor.email, "uploaded_at": _now(),
             "status": "pending", "reviewed_by": "", "reviewed_at": "", "review_note": "",
             "approved_on_upload": False}
        self.store.insert("uploads", u)
        if a:
            self.store.update("assignments", "a", a["RowKey"], {"status": "submitted", "updated_at": _now()})
        self.audit(actor, "evidence.upload", u["RowKey"], {"controls": controls, "assignment": u["assignment"] or None,
                                                           "file": name, "sha256": u["sha256"], "run": run.prefix,
                                                           "cycle": cycle, "approved_on_upload": actor.is_admin})
        if actor.is_admin:
            return self._record_decision(actor, u, "approved", approval_note, on_upload=True)
        people = set(self.active_emails("admin")) | (self.participants(a) if a else set())
        self._notify("uploaded", people, actor, notify.uploaded(self, u, a, actor), controls)
        return u

    def upload_row(self, upload_id: str) -> dict:
        u = self.store.get("uploads", "u", upload_id or "-")
        if not u:
            raise Invalid("Upload not found")
        return u

    def uploads(self, *, assignment: str | None = None, status: str | None = None, control: str | None = None,
                cycle: str | None = "active") -> list[dict]:
        rows = self.store.list("uploads", "u")
        if cycle == "active":
            cycle = self.active_cycle()["RowKey"]
        if cycle:
            rows = [u for u in rows if u["cycle"] == cycle]
        if assignment:
            rows = [u for u in rows if u["assignment"] == assignment]
        if status:
            rows = [u for u in rows if u["status"] == status]
        if control:
            rows = [u for u in rows if control in u["controls"]]
        return sorted(rows, key=lambda u: u["uploaded_at"], reverse=True)

    def reviewable(self, user: User) -> list[dict]:
        """Pending uploads for admins. An admin's own pending upload (made before uploads by admins were approved
        on upload) is listed too, so it can be approved with an approval note instead of staying stuck."""
        if not user.is_admin:
            return []
        return self.uploads(status="pending", cycle=None)

    def review(self, actor: User, upload_id: str, decision: str, note: str) -> dict:
        u = self.upload_row(upload_id)
        if decision not in ("approve", "return"):
            raise Invalid("Decision must be approve or return")
        if not actor.is_admin:
            raise Forbidden("Only admins can review evidence")
        if u["status"] != "pending":
            raise Invalid(f"This upload was already {u['status']}")
        own = u["uploaded_by"] == actor.email
        if own and decision == "return":
            raise Forbidden("You uploaded this evidence; upload a corrected file instead of returning it")
        if own and len((note or "").strip()) < 10:
            raise Invalid(APPROVAL_NOTE_ERROR)
        if decision == "return" and len((note or "").strip()) < 10:
            raise Invalid("Explain what is missing when returning evidence (at least 10 characters)")
        status = "approved" if decision == "approve" else "returned"
        return self._record_decision(actor, u, status, (note or "").strip(), on_upload=own)

    def _record_decision(self, actor: User, u: dict, status: str, note: str, *, on_upload: bool) -> dict:
        """Write the review decision as write-once evidence, update the upload and its request, audit and email.
        on_upload marks an admin attesting to their own evidence (approved on upload) instead of a second review."""
        upload_id = u["RowKey"]
        now = _now()
        a = self.assignment(u["assignment"]) if u["assignment"] else None
        run = self.evidence.new_run("portal_review", u["controls"], {"reviewer": actor.email, "upload": upload_id,
                                                                     "cycle": u["cycle"]})
        run.add("decision", {"upload": upload_id, "evidence_run": u["evidence_run"], "sha256": u["sha256"],
                             "decision": status, "note": note, "reviewer": actor.email, "at": now,
                             "uploaded_by": u["uploaded_by"], "assignment": u["assignment"] or None,
                             "task": (a or {}).get("task") or None, "cycle": u["cycle"],
                             "approved_on_upload": on_upload})
        run.finish([])
        u = self.store.update("uploads", "u", upload_id, {"status": status, "reviewed_by": actor.email,
                                                         "reviewed_at": now, "review_note": (note or "")[:2000],
                                                         "approved_on_upload": on_upload})
        if a and a["status"] not in CLOSED_STATES:
            fields = {"status": status, "updated_at": now}
            if status == "approved":
                fields["approved_at"] = now
            self.store.update("assignments", "a", a["RowKey"], fields)
        self.audit(actor, f"evidence.{status}", upload_id, {"controls": u["controls"], "note": (note or "")[:500],
                                                           "file": u["filename"], "approved_on_upload": on_upload})
        people = {u["uploaded_by"]} | (self.participants(a) if a else set())
        self._notify("reviewed", people, actor, notify.reviewed(self, u, actor), u["controls"])
        return u

    def upload_file(self, user: User, upload_id: str) -> tuple[str, bytes]:
        u = self.upload_row(upload_id)
        if not any(self.can_see_control(user, c) for c in u["controls"]):
            raise Forbidden("You cannot see this evidence")
        source, run = u["evidence_run"].split("/", 1)
        data = self.evidence.read(source, run, u["filename"])
        if data is None:
            raise Invalid("File not found in evidence storage")
        if user.is_auditor:
            self.audit(user, "evidence.download", upload_id, {"controls": u["controls"], "file": u["filename"]})
        return u["filename"], data

    # ================================================================ comments
    def add_comment(self, actor: User, body: str, *, assignment_id: str = "", upload_id: str = "",
                    control_id: str = "") -> dict:
        body = (body or "").strip()
        if not body:
            raise Invalid("Write a comment first")
        if len(body) > 4000:
            raise Invalid("Comments are limited to 4,000 characters")
        u = self.upload_row(upload_id) if upload_id else None
        a = self.assignment(assignment_id or (u or {}).get("assignment", "")) if (assignment_id or (u and u["assignment"])) else None
        if u:
            controls = u["controls"]
        elif a:
            controls = a["controls"]
        elif self.catalog.control(control_id):
            controls = [control_id]
        else:
            raise Invalid("Comment on an assignment, an upload or a control")
        if not self.can_comment(actor, controls):
            raise Forbidden("Auditors and people outside this work cannot comment here")
        if a and actor.is_contributor and actor.email not in self.participants(a) and not any(
                c in self.owned_controls(actor.email) for c in controls):
            raise Forbidden("You are not part of this request")
        c = {"PartitionKey": "m", "RowKey": _rk(), "cycle": (u or a or {}).get("cycle") or self.active_cycle()["RowKey"],
             "assignment": a["RowKey"] if a else "", "upload": u["RowKey"] if u else "",
             "upload_name": u["filename"] if u else "", "controls": controls, "author": actor.email,
             "author_name": actor.name, "body": body, "at": _now()}
        self.store.insert("comments", c)
        self.audit(actor, "comment.add", c["RowKey"], {"controls": controls, "assignment": c["assignment"] or None,
                                                       "upload": c["upload"] or None, "chars": len(body)})
        people = {x["author"] for x in self.comments(assignment=c["assignment"] or None, upload=c["upload"] or None,
                                                       control=None if (a or u) else controls[0], cycle=None)}
        if a:
            people |= self.participants(a) | {a["created_by"]}
        if u:
            people.add(u["uploaded_by"])
        if not a and actor.is_contributor:
            people |= set(self.active_emails("admin"))
        self._notify("commented", people, actor, notify.commented(self, c, actor), controls)
        return c

    def comments(self, *, assignment: str | None = None, upload: str | None = None, control: str | None = None,
                 cycle: str | None = None) -> list[dict]:
        rows = self.store.list("comments", "m")
        if assignment:
            rows = [c for c in rows if c["assignment"] == assignment]
        if upload:
            rows = [c for c in rows if c["upload"] == upload]
        if control:
            rows = [c for c in rows if control in c["controls"]]
        if cycle:
            rows = [c for c in rows if c["cycle"] == cycle]
        return sorted(rows, key=lambda c: c["RowKey"])

    # ================================================================ overrides
    def create_override(self, actor: User, control_id: str, justification: str, expires: str, evidence_ref: str) -> dict:
        if not actor.is_admin:
            raise Forbidden("Only admins can override a control's status")
        if not self.catalog.control(control_id):
            raise Invalid(f"Unknown control {control_id}")
        justification = (justification or "").strip()
        if len(justification) < MIN_JUSTIFICATION:
            raise Invalid(f"Justification must be at least {MIN_JUSTIFICATION} characters")
        try:
            exp = dt.date.fromisoformat(expires)
        except ValueError as exc:
            raise Invalid("Expiry must be YYYY-MM-DD") from exc
        if not self.today < exp <= self.today + dt.timedelta(days=MAX_OVERRIDE_DAYS):
            raise Invalid(f"Expiry must be in the future and within {MAX_OVERRIDE_DAYS} days")
        if control_id in self.active_overrides():
            raise Invalid("This control already has an active override; revoke it first")
        now = _now()
        o = {"PartitionKey": "o", "RowKey": uuid.uuid4().hex, "cycle": self.active_cycle()["RowKey"], "control": control_id,
             "justification": justification[:4000], "evidence_ref": (evidence_ref or "").strip()[:500],
             "expires": exp.isoformat(), "created_by": actor.email, "created_at": now,
             "revoked": False, "revoked_by": "", "revoked_at": ""}
        run = self.evidence.new_run("portal_override", [control_id], {"admin": actor.email})
        run.add("override", {k: v for k, v in o.items() if k != "PartitionKey"})
        run.finish([])
        o["evidence_run"] = run.prefix
        self.store.insert("overrides", o)
        self.audit(actor, "override.create", control_id, {"controls": [control_id], "expires": o["expires"],
                                                          "justification": justification[:500]})
        return o

    def revoke_override(self, actor: User, override_id: str, reason: str) -> None:
        if not actor.is_admin:
            raise Forbidden("Only admins can revoke an override")
        o = self.store.get("overrides", "o", override_id)
        if not o or o.get("revoked"):
            raise Invalid("Override not found or already revoked")
        now = _now()
        self.store.update("overrides", "o", override_id, {"revoked": True, "revoked_by": actor.email, "revoked_at": now})
        run = self.evidence.new_run("portal_override", [o["control"]], {"admin": actor.email})
        run.add("revocation", {"override": override_id, "reason": reason, "at": now})
        run.finish([])
        self.audit(actor, "override.revoke", o["control"], {"controls": [o["control"]], "reason": (reason or "")[:500]})

    def overrides(self) -> list[dict]:
        today, active_cycle = self.today.isoformat(), self.active_cycle()["RowKey"]
        rows = self.store.list("overrides", "o")
        for o in rows:
            o["active"] = not o.get("revoked") and o["expires"] > today and o.get("cycle", active_cycle) == active_cycle
        return sorted(rows, key=lambda o: o["created_at"], reverse=True)

    def active_overrides(self) -> dict[str, dict]:
        return {o["control"]: o for o in self.overrides() if o["active"]}

    # ================================================================ email
    def _notify(self, kind: str, recipients, actor: User, content: dict, controls: list[str] | None = None,
                include_actor: bool = False) -> list[str]:
        """Queue one email per recipient. Skips the actor (unless include_actor), disabled accounts and invalid
        addresses."""
        sent = []
        for email in sorted({(r or "").lower() for r in recipients}):
            if not EMAIL.match(email) or (email == actor.email and not include_actor):
                continue
            row = self.user_row(email)
            if row and not row.get("active", True):
                continue
            self.mailer.send(notify.render(content, email, self.org, kind))
            sent.append(email)
        if sent:
            # Vendor emails can go to people outside GRC-pal (a vendor's internal owner); auditors read the audit log
            # and must not see contact details, so only the number of recipients is kept for those.
            who = {"recipients": len(sent)} if kind == "vendor" else {"to": sent}
            self.audit(actor, "mail.queued", kind, {"controls": controls or [], **who, "subject": content["subject"][:200]})
        return sent

    def _mail_result(self, msg: Message, error: Exception | None) -> None:
        if error is not None:
            self.audit(SYSTEM, "mail.failed", msg.kind, {"to": msg.to, "error": f"{type(error).__name__}: {error}"[:300]})

    def _cooldown_ok(self, key: str) -> bool:
        row = self.store.get("reminders", "r", key)
        cutoff = (utcnow() - dt.timedelta(hours=REMINDER_COOLDOWN_HOURS)).isoformat()
        return not row or row["last_sent"] < cutoff

    def _mark_sent(self, key: str, actor: User) -> None:
        self.store.upsert("reminders", {"PartitionKey": "r", "RowKey": key, "last_sent": _now(), "by": actor.email})

    def remind(self, actor: User, control_id: str, note: str = "", assignment_id: str | None = None,
               status: str | None = None) -> dict:
        """Email the people responsible for a control: participants of its open assignments in the active
        cycle (or one assignment), otherwise the control owner from roles.yaml. One reminder per person per
        control every 12 hours."""
        self._admin(actor)
        ctl = self.catalog.control(control_id)
        if not ctl:
            raise Invalid("Unknown control")
        if assignment_id:
            a = self.assignment(assignment_id)
            open_work = [a] if a["status"] in OPEN_STATES else []
        else:
            open_work = [a for a in self.assignments(control=control_id) if a["status"] in OPEN_STATES]
        people = set().union(*(self.participants(a) for a in open_work)) if open_work else set(self.owner_emails(control_id))
        if not people:
            raise Invalid("Nobody to remind: there is no open request and the owner role has no email in roles.yaml")
        content = notify.reminder(self, ctl, open_work, (note or "")[:1000], actor, status)
        due, skipped = [], []
        for email in sorted(people):
            (due if self._cooldown_ok(f"{control_id}|{email}") else skipped).append(email)
        sent = self._notify("reminder", due, actor, content, [control_id])
        for email in sent:
            self._mark_sent(f"{control_id}|{email}", actor)
        self.audit(actor, "reminder.send", control_id, {"controls": [control_id], "to": sent, "skipped": skipped,
                                                         "note": (note or "")[:300]})
        return {"sent": sent, "skipped": skipped}

    def remind_overdue(self, actor: User) -> list[dict]:
        out = []
        for a in self.assignments():
            if a["overdue"]:
                try:
                    r = self.remind(actor, a["controls"][0], "This request is past its due date.", assignment_id=a["RowKey"])
                except Invalid:
                    continue
                out.append({"assignment": a["RowKey"], "label": a["label"], **r})
        return out

    # ================================================================ policies
    def policy_status(self, policy: dict) -> dict:
        acks = {r["RowKey"].split("|", 1)[1]: r for r in self.store.list("acks", policy["id"])
                if r["RowKey"].startswith(f"{policy['version']}|")}
        people = self.active_emails("admin", "contributor")
        return {"acked": sorted(acks), "missing": [e for e in people if e not in acks], "rows": acks}

    def acknowledge(self, user: User, policy_id: str) -> dict:
        policy = self.catalog.policy(policy_id)
        if not policy or not policy.get("acknowledge", True):
            raise Invalid("Policy not found")
        if user.is_auditor:
            raise Forbidden("Auditors do not acknowledge policies")
        key = f"{policy['version']}|{user.email}"
        existing = self.store.get("acks", policy_id, key)
        if existing:
            return existing
        row = {"PartitionKey": policy_id, "RowKey": key, "email": user.email, "version": policy["version"],
               "sha256": policy["sha256"], "at": _now()}
        self.store.insert("acks", row)
        self.audit(user, "policy.ack", policy_id, {"controls": policy["controls"], "version": policy["version"],
                                                   "sha256": policy["sha256"]})
        return row

    def remind_policy(self, actor: User, policy_id: str) -> dict:
        self._admin(actor)
        policy = self.catalog.policy(policy_id)
        if not policy:
            raise Invalid("Policy not found")
        missing = self.policy_status(policy)["missing"]
        due = [e for e in missing if self._cooldown_ok(f"policy:{policy_id}|{e}")]
        sent = self._notify("policy", due, actor, notify.policy_reminder(self, policy, actor), policy["controls"])
        for e in sent:
            self._mark_sent(f"policy:{policy_id}|{e}", actor)
        return {"sent": sent, "skipped": [e for e in missing if e not in sent]}

    # ================================================================ history, tasks, reports
    def control_history(self, control_id: str, limit: int = 200) -> list[dict]:
        return self.log.recent(limit=limit, target=control_id)

    def open_due_tasks(self, actor: User) -> list[dict]:
        """One assignment per task due this month (idempotent per task and period)."""
        created = []
        existing = {(a.get("task"), a.get("period")) for a in self.store.list("assignments", "a")}
        for name, task in self.catalog.tasks.items():
            if self.today.month not in task.get("months", []):
                continue
            period = period_label(task, self.today)
            if (name, period) in existing:
                continue
            owners = self.role_emails(task["owner"])
            if not owners:
                continue
            due = (self.today + dt.timedelta(days=task.get("due_days", 30))).isoformat()
            checklist = "\n".join(f"- {item}" for item in task.get("checklist", []))
            created.append(self.create_assignment(actor, "task", name, owners[0], owners[1:], due,
                                                  f"{task['title']} ({period})\n{checklist}", task=name, period=period))
        return created

    def report_inputs(self) -> dict:
        tasks: dict[str, str] = {}
        for a in self.store.list("assignments", "a"):
            if a.get("task") and a["status"] == "approved" and a.get("approved_at") > tasks.get(a["task"], ""):
                tasks[a["task"]] = a["approved_at"]
        for name, done in self.completed_tasks().items():  # recorded on the security calendar
            if done > tasks.get(name, ""):
                tasks[name] = done
        uploads: dict[str, str] = {}
        for u in self.store.list("uploads", "u"):
            if u["status"] == "approved":
                for c in u["controls"]:
                    if u["reviewed_at"] > uploads.get(c, ""):
                        uploads[c] = u["reviewed_at"]
        from grcpal.collectors import disabled_sources

        return {"overrides": self.active_overrides(), "tasks": tasks, "uploads": uploads,
                "activities": self.performed_by_control(),
                "skip_sources": disabled_sources(self.catalog, self.settings)}

    # ================================================================ evidence browsing (admins, auditors)
    def evidence_sources(self) -> list[str]:
        from grcpal.collectors import NAMES

        checks = {f"check-{c['id']}" for c in self.all_checks()}
        return sorted(set(NAMES) | checks | {"prowler", "maester", "testssl", "control_report", "portal_upload",
                                             "portal_review", "portal_override", "portal_audit", "ai_review", "ai_audit"})

    def manifest(self, source: str, run: str) -> dict:
        if source not in self.evidence_sources() or not RUN_ID.match(run):
            raise Invalid("Unknown evidence run")
        raw = self.evidence.read(source, run, "manifest.json")
        if not raw:
            raise Invalid("Evidence run not found")
        return json.loads(raw)

    # ---- evidence integrity: audit-log anchor and verification ----
    def _seal_evidence(self, prefix: str, digest: str, manifest: dict) -> None:
        """Record each finished run's manifest hash in the hash-chained audit log, so a manifest rewritten
        later no longer matches (even by someone holding the signing key)."""
        self.audit(SYSTEM, "evidence.sealed", prefix, {
            "sha256": digest, "controls": manifest.get("controls") or [], "status": manifest.get("status"),
            "key_id": (manifest.get("integrity") or {}).get("key_id")})

    def evidence_anchor(self, source: str, run: str) -> dict | None:
        prefix = f"{source}/{run}"
        return next((r for r in self.log.recent(limit=20, action="evidence.sealed", target=prefix)
                     if r["target"] == prefix), None)

    def verify_evidence(self, actor: User, source: str, run: str, check_files: bool = True) -> dict:
        """Hashes, signature and audit-log anchor of one run. Status: verified, warning (good but not
        recorded in the audit log, e.g. collected without the portal), legacy (before signing), failed."""
        if not actor.sees_everything:
            raise Forbidden("Only admins and auditors can verify evidence")
        if not RUN_ID.match(run or "") or "/" in source or ".." in source:
            raise Invalid("Unknown evidence run")
        result = self.evidence.verify_run(source, run, check_files=check_files)
        anchor = self.evidence_anchor(source, run)
        result["anchor"] = {"seq": anchor["seq"], "at": anchor["at"]} if anchor else None
        if anchor and result["manifest_sha256"] and anchor["detail"].get("sha256") != result["manifest_sha256"]:
            result["problems"].append(f"manifest.json does not match audit log record {anchor['seq']} (changed)")
            result["status"] = "failed"
        elif not anchor and result["status"] == "verified":
            result["status"] = "warning"
            result["problems"].append("not recorded in the audit log (collected while the portal was not connected)")
        return result

    def evidence_file(self, source: str, run: str, filename: str) -> bytes:
        manifest = self.manifest(source, run)
        if filename not in ("manifest.json", *INTEGRITY_FILES) and filename not in {f["name"] for f in manifest["files"]}:
            raise Invalid("File is not part of this evidence run")
        data = self.evidence.read(source, run, filename)
        if data is None:
            raise Invalid("File not found")
        return data

    # ================================================================ auditor export
    def export_cycle(self, actor: User, cycle_id: str, control_status: list[dict] | None = None) -> bytes:
        """Zip for the auditor: populations as CSV (assignments, uploads with review decisions, comments,
        overrides, users, policy acknowledgments, audit log for the period), the audit-chain check, control
        status, every uploaded file, and a manifest with the SHA-256 of each file in the zip."""
        if not actor.sees_everything:
            raise Forbidden("Only admins and auditors can export")
        cycle = self.cycle(cycle_id)
        if not cycle:
            raise Invalid("Cycle not found")
        files: dict[str, bytes] = {}

        def table(name: str, rows: list[dict]) -> None:
            cols: list[str] = []
            for r in rows:
                cols += [k for k in r if k not in cols and k != "PartitionKey"]
            buf = io.StringIO()
            w = csv.DictWriter(buf, fieldnames=cols or ["empty"], extrasaction="ignore")
            w.writeheader()
            for r in rows:  # csv_cell: text starting with = + - @ cannot run as a spreadsheet formula
                w.writerow({k: csv_cell(json.dumps(v) if isinstance(v, (list, dict)) else v) for k, v in r.items()})
            files[f"{name}.csv"] = buf.getvalue().encode()

        end = cycle.get("closed_at") or "9999"
        uploads = self.uploads(cycle=cycle_id)
        table("assignments", self.assignments(cycle=cycle_id))
        table("uploads_and_reviews", uploads)
        table("comments", self.comments(cycle=cycle_id))
        table("overrides", [o for o in self.overrides() if o.get("cycle") == cycle_id])
        table("users", self.users())
        table("policy_acknowledgments", [r for p in self.catalog.policies for r in self.store.list("acks", p["id"])])
        table("audit_log", [r for r in self.log.records() if cycle["start"] <= r["at"][:10] and r["at"] <= end])
        table("calendar_occurrences", self.calendar_export_rows(cycle["start"], cycle["end"]))
        table("calendar_decisions", [{k: v for k, v in r.items() if k != "PartitionKey"} for r in self.calendar_decisions()
                                     if cycle["start"] <= r["due_date"] <= cycle["end"]])
        table("control_definition_changes", [{k: v for k, v in r.items() if k not in ("PartitionKey", "RowKey")}
                                             for r in self.control_definition_history()])
        table("implementation_notes", sorted(({k: v for k, v in r.items() if k not in ("PartitionKey", "RowKey")}
                                              for r in self.store.list("controlnotes", "n")),
                                             key=lambda r: (r["control"], r["version"])))
        vendor_tables, vendor_files = self.vendor_export(cycle["start"], cycle["end"])
        for name, rows in vendor_tables.items():
            table(name, rows)
        files.update(vendor_files)
        files["audit_chain_verification.json"] = json.dumps(self.log.verify(), indent=2).encode()
        runs = []
        for source in self.evidence.list_sources():
            for r in verify_source(self.evidence, source,
                                   lambda src, run: self.verify_evidence(actor, src, run, check_files=False)):
                run = r["run"]
                if cycle["start"] <= run[:10] <= cycle["end"]:
                    runs.append({"source": source, "run": run, "status": r["status"], "signed": r["signed"],
                                 "key_id": r["key_id"] or "", "manifest_sha256": r["manifest_sha256"] or "",
                                 "audit_record": (r["anchor"] or {}).get("seq", ""), "problems": "; ".join(r["problems"])})
        table("evidence_run_verification", runs)
        pem = public_key_pem()
        if pem:
            files["evidence_signing_key.pem"] = pem.encode()
        files["cycle.json"] = json.dumps({k: v for k, v in cycle.items() if k != "PartitionKey"}, indent=2).encode()
        if control_status is not None:
            files["control_status.json"] = json.dumps(control_status, indent=2, default=str).encode()
        for u in uploads:
            source, run = u["evidence_run"].split("/", 1)
            data = self.evidence.read(source, run, u["filename"])
            if data is not None:
                files[f"evidence/{u['RowKey'][:8]}_{u['filename']}"] = data
        files["README.txt"] = (
            f"GRC-pal export for {self.org}\nCycle: {cycle['name']} ({cycle['start']} to {cycle['end']}, {cycle['status']})\n"
            f"Exported by {actor.email} at {_now()}\n\n"
            "uploads_and_reviews.csv is the full population of portal evidence for the cycle with reviewer decisions;\n"
            "approved_on_upload=True means an admin (program owner) attested to the file on upload, with the approval\n"
            "note in review_note, instead of a second person reviewing it.\n"
            "Each upload's sha256 matches the file under evidence/ and the write-once evidence store.\n"
            "calendar_occurrences.csv lists every scheduled activity due in the cycle and what an admin recorded for it;\n"
            "calendar_decisions.csv keeps every decision, including ones later corrected.\n"
            "audit_chain_verification.json shows whether the tamper-evident audit log verified at export time.\n"
            "evidence_run_verification.csv lists every evidence run in the cycle: signature status, the manifest's\n"
            "SHA-256 and the audit_log.csv record (action evidence.sealed) that holds the same hash. To re-test a run,\n"
            "download its folder, run `sha256sum -c SHA256SUMS`, and check manifest.sig against manifest.json with\n"
            "evidence_signing_key.pem (Ed25519), or run `grcpal evidence verify --public-key evidence_signing_key.pem`.\n"
            "implementation_notes.csv holds every version of each control's 'How we meet this control' notes.\n"
            "vendors.csv is the vendor population (all statuses) with tier, data access, status and review dates;\n"
            "vendor_reviews.csv, vendor_exceptions.csv and vendor_cuecs.csv hold each onboarding check, annual review and\n"
            "offboarding in the cycle, the exceptions in vendors' reports and the CUEC mapping; vendor_files.csv lists\n"
            "the files under vendor_files/ with their sha256; subservice_organizations.csv supports the system description;\n"
            "questionnaire_versions.csv holds every version of the vendor security questionnaire. Vendor contact\n"
            "details are left out on purpose.\n"
            "MANIFEST.csv lists the SHA-256 of every file in this archive.\n").encode()
        manifest = io.StringIO()
        mw = csv.writer(manifest)
        mw.writerow(["file", "bytes", "sha256"])
        for name, data in sorted(files.items()):
            mw.writerow([name, len(data), hashlib.sha256(data).hexdigest()])
        files["MANIFEST.csv"] = manifest.getvalue().encode()
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in sorted(files.items()):
                z.writestr(name, data)
        blob = out.getvalue()
        self.audit(actor, "export.cycle", cycle_id, {"files": len(files), "sha256": hashlib.sha256(blob).hexdigest()})
        return blob

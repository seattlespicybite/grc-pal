"""People: one row per person, joining what the collectors and the portal already know about them.

Auditors sample people: "show me this joiner's account, MFA, device and policy acknowledgment", "show me this
leaver's account was disabled". Those facts sit in four evidence sources and two portal tables. This page joins
them by sign-in name (lower-cased), reads only the latest run of each source, and stores nothing new except the
out-of-scope list.

Sources (latest run of each; a source with no run is shown as "no data", never as a pass):
  * entra_users/users.json                 account, enabled, type, created, last sign-in, department, job title
  * entra_mfa/mfa_registration.json        MFA registered
  * intune_devices/managed_devices.json    devices, compliance, encryption
  * leaver_reconcile/reconciliation.json   termination date, account still enabled
  * portal users and policy acknowledgments

Checks per person: account (enabled; a terminated person's account must be disabled), MFA, devices, policies.
A person can be marked out of scope with a reason (a shared mailbox, a break-glass account); that only moves them
to a separate list on this page. It does not change any collector finding or control status.

Admins and auditors read; admins mark scope. This page shows names and work email addresses, as the evidence store
already does; it adds no other personal data.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import json

from grcpal.portal.auth import EMAIL_RE, User
from grcpal.portal.security import csv_cell

SOURCES = {"entra_users": "users.json", "entra_mfa": "mfa_registration.json",
           "intune_devices": "managed_devices.json", "leaver_reconcile": "reconciliation.json"}
NEW_JOINER_DAYS = 90
MIN_SCOPE_REASON = 10
CSV_COLUMNS = ("email", "name", "type", "department", "job_title", "account", "created", "new_joiner", "last_sign_in",
               "mfa", "devices", "devices_not_compliant", "devices_not_encrypted", "policies_required",
               "policies_missing", "termination_date", "portal_role", "problems", "in_scope", "scope_reason")


class PeopleMixin:
    def _people_reader(self, actor: User) -> None:
        if not actor.sees_everything:
            raise self._forbidden("Only admins and auditors can see the people view")

    def _latest_rows(self, source: str) -> tuple[list[dict], str]:
        """Rows of the latest run of a source and that run's ID ("" when there is no run or the file is unreadable)."""
        runs = self.evidence.list_runs(source)
        raw = self.evidence.read(source, runs[-1], SOURCES[source]) if runs else None
        try:
            rows = json.loads(raw) if raw else []
        except ValueError:
            rows = []
        return [r for r in rows if isinstance(r, dict)], (runs[-1] if runs and raw else "")

    def people(self, actor: User) -> dict:
        self._people_reader(actor)
        data = {s: self._latest_rows(s) for s in SOURCES}
        have = {s: bool(run) for s, (_, run) in data.items()}
        key = lambda v: (v or "").strip().lower()  # noqa: E731
        mfa = {key(r.get("upn")): r for r in data["entra_mfa"][0]}
        devices: dict[str, list[dict]] = {}
        for d in data["intune_devices"][0]:
            devices.setdefault(key(d.get("user")), []).append(d)
        leavers = {key(r.get("email")): r for r in data["leaver_reconcile"][0]}
        portal_users = {u["RowKey"]: u for u in self.users()}
        required: dict[str, int] = {}
        missing: dict[str, int] = {}
        for doc in self.published_documents(actor):
            for email in doc["status"]["audience"]:
                required[email] = required.get(email, 0) + 1
            for email in doc["status"]["missing"]:
                missing[email] = missing.get(email, 0) + 1
        scope = {r["RowKey"]: r for r in self.store.list("peoplescope", "p") if r.get("out")}
        cutoff = (self.today - dt.timedelta(days=NEW_JOINER_DAYS)).isoformat()

        people: dict[str, dict] = {}
        for u in data["entra_users"][0]:
            email = key(u.get("upn"))
            if email:
                people[email] = {"email": email, "name": u.get("name") or email, "type": u.get("type") or "",
                                 "department": u.get("department") or "", "job_title": u.get("job_title") or "",
                                 "enabled": u.get("enabled"), "created": (u.get("created") or "")[:10],
                                 "last_sign_in": (u.get("last_sign_in") or "")[:10], "in_directory": True}
        for email in list(leavers) + list(portal_users):   # leavers already deleted, portal-only accounts
            if email and email not in people:
                pu = portal_users.get(email, {})
                people[email] = {"email": email, "name": pu.get("name") or email, "type": "", "department": "",
                                 "job_title": "", "enabled": None, "created": "", "last_sign_in": "",
                                 "in_directory": False}

        for email, p in people.items():
            own, leaver, pu = devices.get(email, []), leavers.get(email), portal_users.get(email)
            p["new_joiner"] = bool(p["created"]) and p["created"] >= cutoff
            p["termination_date"] = (leaver or {}).get("termination_date", "")
            p["portal_role"] = pu["role"] if pu and pu.get("active", True) else ""
            p["devices"] = len(own)
            p["devices_not_compliant"] = sum(1 for d in own if d.get("compliance") != "compliant")
            p["devices_not_encrypted"] = sum(1 for d in own if not d.get("encrypted"))
            p["policies_required"], p["policies_missing"] = required.get(email, 0), missing.get(email, 0)
            p["account"] = ("not in directory" if not p["in_directory"] else
                            "enabled" if p["enabled"] else "disabled")
            reg = (mfa.get(email) or {}).get("mfa_registered")
            p["mfa"] = "no data" if not have["entra_mfa"] or email not in mfa else ("registered" if reg else "not registered")
            checks = []
            if leaver:
                gone = not p["in_directory"] or not p["enabled"]
                checks.append(("Leaver", "ok" if gone else "problem",
                               f"left {p['termination_date']}, account {'disabled or removed' if gone else 'STILL ENABLED'}"))
            active = p["in_directory"] and p["enabled"] and not leaver and p["type"] != "guest"
            if active:
                checks.append(("MFA", {"registered": "ok", "not registered": "problem"}.get(p["mfa"], "unknown"), p["mfa"]))
                if have["intune_devices"]:
                    bad = p["devices_not_compliant"] + p["devices_not_encrypted"]
                    checks.append(("Devices", "problem" if bad else "ok" if own else "unknown",
                                   f"{len(own)} managed" + (f", {p['devices_not_compliant']} not compliant, "
                                                            f"{p['devices_not_encrypted']} not encrypted" if bad else "")
                                   if own else "no managed device"))
                else:
                    checks.append(("Devices", "unknown", "no data"))
            if p["policies_required"]:
                checks.append(("Policies", "problem" if p["policies_missing"] else "ok",
                               f"{p['policies_required'] - p['policies_missing']} of {p['policies_required']} acknowledged"))
            p["checks"] = [{"name": n, "state": s, "detail": d} for n, s, d in checks]
            p["problems"] = sum(1 for c in p["checks"] if c["state"] == "problem")
            out = scope.get(email)
            p["in_scope"], p["scope_reason"] = not out, (out or {}).get("reason", "")
            p["scope_by"], p["scope_at"] = (out or {}).get("by", ""), (out or {}).get("at", "")

        rows = sorted(people.values(), key=lambda p: (-p["problems"], p["email"]))
        inside = [p for p in rows if p["in_scope"]]
        return {"people": inside, "out_of_scope": [p for p in rows if not p["in_scope"]],
                "sources": [{"source": s, "run": run, "rows": len(r)} for s, (r, run) in data.items()],
                "summary": {"people": len(inside), "with_problems": sum(1 for p in inside if p["problems"]),
                            "new_joiners": sum(1 for p in inside if p["new_joiner"]),
                            "leavers": sum(1 for p in inside if p["termination_date"]),
                            "no_mfa": sum(1 for p in inside if any(c["name"] == "MFA" and c["state"] == "problem"
                                                                   for c in p["checks"]))}}

    def people_csv(self, actor: User) -> bytes:
        """The whole population, in and out of scope, for auditors to sample from."""
        view = self.people(actor)
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for p in view["people"] + view["out_of_scope"]:
            w.writerow({k: csv_cell(p.get(k, "")) for k in CSV_COLUMNS})
        self.audit(actor, "people.export", "people.csv", {"rows": len(view["people"]) + len(view["out_of_scope"]),
                                                          "runs": {s["source"]: s["run"] for s in view["sources"]}})
        return buf.getvalue().encode()

    def set_person_scope(self, actor: User, email: str, out: bool, reason: str) -> None:
        """Mark a person out of scope of the people view (or back in). Admins only; reason required."""
        if not actor.is_admin:
            raise self._forbidden("Only admins can change who is in scope")
        email, reason = (email or "").strip().lower(), (reason or "").strip()
        if not EMAIL_RE.match(email):
            raise self._invalid("Unknown person")
        if len(reason) < MIN_SCOPE_REASON:
            raise self._invalid(f"Give a reason of at least {MIN_SCOPE_REASON} characters; auditors will read it")
        view = self.people(actor)
        current = next((p for p in view["people"] + view["out_of_scope"] if p["email"] == email), None)
        if not current:
            raise self._invalid("Unknown person")
        if current["in_scope"] != out:
            raise self._invalid("This person is already " + ("out of scope" if out else "in scope"))
        from grcpal.portal.service import _now

        self.store.upsert("peoplescope", {"PartitionKey": "p", "RowKey": email, "out": out, "reason": reason[:500],
                                           "by": actor.email, "at": _now()})
        self.audit(actor, "person.scope", email, {"in_scope": not out, "reason": reason[:500]})

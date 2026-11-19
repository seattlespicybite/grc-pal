"""Tests: each automated or recurring check shown once, with its own status, owner and run history.

A control lists its evidence items (`via: collector:entra_mfa`, `task:policy-review`, ...). The same item often
supports several controls. A test is one such item, whichever controls use it: it has an ID, a kind, a status, the
controls it supports, a named owner and (for collectors, tools and custom checks) the history of its runs.

Nothing is stored twice: tests are read from the control health report (grcpal/report.py), which already decides
each item's status. Only the owner is saved here (table `testmeta`). A control's status still comes from its items,
so the Tests page and the Controls page can never disagree.

Failing resources and scoped exceptions: a collector, tool or check reports each problem as a finding with a
stable key (for example `no-mfa:pat@example.com`). A test's page lists the findings of its latest run. An admin can
accept one finding for a limited time (reason and expiry required): the finding then no longer fails the test or
its controls, the rest still do, and the exception ends by itself on its expiry date. Each exception and each
revocation is stored as write-once evidence (`portal_test_exception/`) and in the audit log, and is listed in the
auditor export. This replaces overriding a whole control because of one known item.

Admins and auditors read tests; only admins change them. Every change is recorded in the audit log.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import uuid

from grcpal.portal.auth import User

KINDS = {"collector": "Automated collector", "tool": "External tool", "check": "Custom check",
         "task": "Recurring task", "git": "Document history"}
RUN_KINDS = ("collector", "tool", "check")   # kinds that write evidence runs, so they have a run history
# Report item status -> test status. A test's status is the worst one among the controls that use it.
STATUS = {"error": "error", "findings": "failing", "stale": "stale", "not_started": "not_run", "ok": "passing",
          "n/a": "not_applicable"}
STATUS_ORDER = ("error", "failing", "stale", "not_run", "passing", "not_applicable")
STATUS_LABELS = {"error": "Error", "failing": "Failing", "stale": "Stale", "not_run": "Not run", "passing": "Passing",
                 "not_applicable": "Not applicable"}
STATUS_CSS = {"error": "error", "failing": "findings", "stale": "stale", "not_run": "not_started", "passing": "ok",
              "not_applicable": "na"}
STATUS_HELP = {"error": "The last run stopped with an error", "failing": "The last run found problems",
               "stale": "No run or completion recent enough for the control's frequency",
               "not_run": "No run or completion recorded yet", "passing": "The last run found no problems",
               "not_applicable": "The platform this test reads is not in use"}
HISTORY_RUNS = 20
MAX_FINDINGS_SHOWN = 500
MIN_EXCEPTION_REASON = 30
MAX_EXCEPTION_DAYS = 365
MAX_KEY = 300
TEST_ID = re.compile(r"^(collector|tool|check|task|git)-[A-Za-z0-9_.-]{1,80}$")
_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def test_id(via: str) -> str | None:
    """`collector:entra_mfa` -> `collector-entra_mfa`. None for items that are not tests (`event`, portal uploads)."""
    kind, _, name = str(via).partition(":")
    name = _UNSAFE.sub("-", name).strip("-")[:80]
    return f"{kind}-{name}" if kind in KINDS and name else None


test_id.__test__ = False  # not a pytest test, whatever its name


def source_of(test: dict) -> str | None:
    """The evidence source a test's runs are stored under, or None for kinds without runs."""
    if test["kind"] not in RUN_KINDS:
        return None
    return f"check-{test['name']}" if test["kind"] == "check" else test["name"]


class ControlTestsMixin:
    """Mixed into Portal. `health` is the control health report (report.build), passed in by the routes."""

    def _tests_reader(self, actor: User) -> None:
        if not actor.sees_everything:
            raise self._forbidden("Only admins and auditors can see tests")

    def control_tests(self, actor: User, health: dict) -> list[dict]:
        self._tests_reader(actor)
        owners = {r["RowKey"]: r for r in self.store.list("testmeta", "t")}
        tests: dict[str, dict] = {}
        for ctl in health["controls"]:
            for item in ctl["evidence"]:
                tid = test_id(item["via"])
                if not tid:
                    continue
                kind, _, name = str(item["via"]).partition(":")
                t = tests.setdefault(tid, {
                    "id": tid, "kind": kind, "kind_label": KINDS[kind], "name": name, "via": item["via"],
                    "title": item["artifact"], "controls": [], "status": "not_applicable", "last": None,
                    "findings": 0, "excepted": 0, "note": item.get("note", ""), "owner": (owners.get(tid) or {}).get("owner", "")})
                if not any(c["id"] == ctl["id"] for c in t["controls"]):
                    t["controls"].append({"id": ctl["id"], "title": ctl["title"], "frequency": ctl["frequency"],
                                          "in_scope": ctl["in_scope"]})
                status = STATUS.get(item["status"], "not_run")
                if STATUS_ORDER.index(status) < STATUS_ORDER.index(t["status"]):
                    t["status"] = status
                t["last"] = max(filter(None, (t["last"], item.get("last"))), default=None)
                t["findings"] = max(t["findings"], int(item.get("findings") or 0))
                t["excepted"] = max(t.get("excepted", 0), int(item.get("excepted") or 0))
                if item.get("due"):  # manual work: the earliest date any control needs it done again
                    t["due"] = min(filter(None, (t.get("due"), item["due"])))
                    t["due_soon"] = t.get("due_soon", False) or bool(item.get("due_soon"))
        for t in tests.values():
            t["status_label"], t["status_css"] = STATUS_LABELS[t["status"]], STATUS_CSS[t["status"]]
            t["status_help"] = STATUS_HELP[t["status"]]
            t["in_scope"] = any(c["in_scope"] for c in t["controls"])
        return sorted(tests.values(), key=lambda t: (STATUS_ORDER.index(t["status"]), t["kind"], t["name"]))

    def control_test(self, actor: User, health: dict, tid: str) -> dict:
        """One test with its run history. Raises Invalid for an unknown ID."""
        self._tests_reader(actor)
        test = next((t for t in self.control_tests(actor, health) if t["id"] == tid), None) \
            if TEST_ID.match(tid or "") else None
        if not test:
            raise self._invalid("Test not found")
        source = source_of(test)
        test["source"], test["history"] = source, self._test_history(source) if source else []
        resources = self._failing_resources(test)
        test["resources"], test["resources_total"] = resources[:MAX_FINDINGS_SHOWN], len(resources)
        test["exceptions"] = [x for x in self.test_exceptions() if x["test"] == tid]
        meta = self.store.get("testmeta", "t", tid) or {}
        test["owner_set_by"], test["owner_set_at"] = meta.get("updated_by", ""), meta.get("updated_at", "")
        return test

    def _test_history(self, source: str) -> list[dict]:
        """The latest runs of an evidence source, newest first, read from each run's manifest."""
        out = []
        for run in reversed(self.evidence.list_runs(source)[-HISTORY_RUNS:]):
            raw = self.evidence.read(source, run, "manifest.json")
            try:
                m = json.loads(raw) if raw else {}
            except ValueError:
                m = {}
            count = int(m.get("findings_count") or 0)
            status = "error" if m.get("status") == "error" or not m else ("failing" if count else "passing")
            out.append({"run": run, "finished": m.get("finished", ""), "findings": count, "status": status,
                        "status_label": STATUS_LABELS[status], "status_css": STATUS_CSS[status],
                        "error": (m.get("error") or "")[:300]})
        return out

    def test_summary(self, tests: list[dict]) -> dict:
        counts = {s: 0 for s in STATUS_ORDER}
        for t in tests:
            counts[t["status"]] += 1
        return {"counts": counts, "total": len(tests), "unowned": sum(1 for t in tests if not t["owner"]),
                "due_soon": sum(1 for t in tests if t.get("due_soon"))}

    def set_test_owner(self, actor: User, health: dict, tid: str, email: str) -> dict:
        """Name the person answerable for a test's status (empty to clear). Admins only."""
        if not actor.is_admin:
            raise self._forbidden("Only admins can change a test's owner")
        test = self.control_test(actor, health, tid)
        email = (email or "").strip().lower()
        if email:
            row = self.user_row(email)
            if not row or not row.get("active", True) or row["role"] == "auditor":
                raise self._invalid("The owner must be an active admin or control owner in GRC-pal")
        if email == test["owner"]:
            return test
        from grcpal.portal.service import _now

        self.store.upsert("testmeta", {"PartitionKey": "t", "RowKey": tid, "owner": email,
                                        "updated_by": actor.email, "updated_at": _now()})
        self.audit(actor, "test.owner", tid, {"owner": email, "previous": test["owner"],
                                              "controls": [c["id"] for c in test["controls"]]})
        return dict(test, owner=email)

    # ------------------------------------------------------------------ failing resources and scoped exceptions
    def _latest_findings(self, source: str | None) -> list[dict]:
        m = self.evidence.latest_manifest(source) if source else None
        return [f for f in (m or {}).get("findings") or [] if isinstance(f, dict) and f.get("key")]

    def _failing_resources(self, test: dict) -> list[dict]:
        """The findings of the test's latest run, each with the exception that covers it, if one is active."""
        active = {x["key"]: x for x in self.test_exceptions() if x["test"] == test["id"] and x["active"]}
        rows = [{"key": str(f["key"]), "title": str(f.get("title") or f["key"]), "severity": str(f.get("severity") or ""),
                 "exception": active.get(str(f["key"]))} for f in self._latest_findings(source_of(test))]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(rows, key=lambda r: (r["exception"] is not None, order.get(r["severity"], 4), r["key"]))

    def test_exceptions(self) -> list[dict]:
        """Every exception, newest first. `active` = not revoked and not past its expiry date."""
        today = self.today.isoformat()
        rows = self.store.list("testexceptions", "x")
        for x in rows:
            x["active"] = not x.get("revoked") and x["expires"] > today
            x["state"] = "revoked" if x.get("revoked") else ("active" if x["active"] else "expired")
        return sorted(rows, key=lambda x: x["created_at"], reverse=True)

    def list_test_exceptions(self, actor: User) -> list[dict]:
        self._tests_reader(actor)
        return self.test_exceptions()

    def active_test_exception_keys(self) -> dict[str, set]:
        """{evidence source: {finding key}} for the control health report (report.build)."""
        out: dict[str, set] = {}
        for x in self.test_exceptions():
            if x["active"]:
                out.setdefault(x["source"], set()).add(x["key"])
        return out

    def create_test_exception(self, actor: User, health: dict, tid: str, key: str, reason: str, expires: str) -> dict:
        """Accept one finding of a test until a date. Admins only. The finding must be in the test's latest run, so
        an exception can never be granted ahead of time for something not yet seen."""
        if not actor.is_admin:
            raise self._forbidden("Only admins can accept a finding")
        test = self.control_test(actor, health, tid)
        key, reason = (key or "").strip(), (reason or "").strip()
        finding = next((r for r in self._failing_resources(test) if r["key"] == key), None) if len(key) <= MAX_KEY else None
        if not finding:
            raise self._invalid("That finding is not in this test's latest run")
        if finding["exception"]:
            raise self._invalid("This finding already has an active exception; revoke it first")
        if len(reason) < MIN_EXCEPTION_REASON:
            raise self._invalid(f"The reason must be at least {MIN_EXCEPTION_REASON} characters; auditors will read it")
        try:
            exp = dt.date.fromisoformat(expires or "")
        except ValueError as exc:
            raise self._invalid("Expiry must be YYYY-MM-DD") from exc
        if not self.today < exp <= self.today + dt.timedelta(days=MAX_EXCEPTION_DAYS):
            raise self._invalid(f"Expiry must be in the future and within {MAX_EXCEPTION_DAYS} days")
        from grcpal.portal.service import _now

        controls = [c["id"] for c in test["controls"]]
        x = {"PartitionKey": "x", "RowKey": uuid.uuid4().hex, "test": tid, "source": test["source"], "key": key,
             "title": finding["title"][:300], "severity": finding["severity"], "reason": reason[:4000],
             "expires": exp.isoformat(), "controls": controls, "created_by": actor.email, "created_at": _now(),
             "revoked": False, "revoked_by": "", "revoked_at": "", "revoke_reason": ""}
        run = self.evidence.new_run("portal_test_exception", controls, {"admin": actor.email})
        run.add("exception", {k: v for k, v in x.items() if k != "PartitionKey"})
        run.finish([])
        x["evidence_run"] = run.prefix
        self.store.insert("testexceptions", x)
        self.audit(actor, "test.exception.create", tid, {"controls": controls, "key": key, "expires": x["expires"],
                                                         "reason": reason[:500], "exception": x["RowKey"]})
        self._changed()
        return x

    def revoke_test_exception(self, actor: User, xid: str, reason: str) -> dict:
        if not actor.is_admin:
            raise self._forbidden("Only admins can revoke an exception")
        x = self.store.get("testexceptions", "x", xid) if re.fullmatch(r"[0-9a-f]{32}", xid or "") else None
        if not x or x.get("revoked"):
            raise self._invalid("Exception not found or already revoked")
        reason = (reason or "").strip()
        if len(reason) < 5:
            raise self._invalid("Say why the exception is revoked (at least 5 characters)")
        from grcpal.portal.service import _now

        now = _now()
        x = self.store.update("testexceptions", "x", xid, {"revoked": True, "revoked_by": actor.email,
                                                            "revoked_at": now, "revoke_reason": reason[:1000]})
        run = self.evidence.new_run("portal_test_exception", x.get("controls") or [], {"admin": actor.email})
        run.add("revocation", {"exception": xid, "test": x["test"], "key": x["key"], "reason": reason[:1000], "at": now})
        run.finish([])
        self.audit(actor, "test.exception.revoke", x["test"], {"controls": x.get("controls") or [], "key": x["key"],
                                                               "reason": reason[:500], "exception": xid})
        self._changed()
        return x

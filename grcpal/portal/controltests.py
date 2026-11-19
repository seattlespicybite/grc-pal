"""Tests: each automated or recurring check shown once, with its own status, owner and run history.

A control lists its evidence items (`via: collector:entra_mfa`, `task:policy-review`, ...). The same item often
supports several controls. A test is one such item, whichever controls use it: it has an ID, a kind, a status, the
controls it supports, a named owner and (for collectors, tools and custom checks) the history of its runs.

Nothing is stored twice: tests are read from the control health report (grcpal/report.py), which already decides
each item's status. Only the owner is saved here (table `testmeta`). A control's status still comes from its items,
so the Tests page and the Controls page can never disagree.

Admins and auditors read tests; only admins change them. Every change is recorded in the audit log.
"""
from __future__ import annotations

import json
import re

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
                    "findings": 0, "note": item.get("note", ""), "owner": (owners.get(tid) or {}).get("owner", "")})
                if not any(c["id"] == ctl["id"] for c in t["controls"]):
                    t["controls"].append({"id": ctl["id"], "title": ctl["title"], "frequency": ctl["frequency"],
                                          "in_scope": ctl["in_scope"]})
                status = STATUS.get(item["status"], "not_run")
                if STATUS_ORDER.index(status) < STATUS_ORDER.index(t["status"]):
                    t["status"] = status
                t["last"] = max(filter(None, (t["last"], item.get("last"))), default=None)
                t["findings"] = max(t["findings"], int(item.get("findings") or 0))
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
        return {"counts": counts, "total": len(tests), "unowned": sum(1 for t in tests if not t["owner"])}

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

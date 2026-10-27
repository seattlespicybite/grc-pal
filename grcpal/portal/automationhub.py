"""Automation page (admins only): every connection, collector and custom check in one place.

What it adds on top of the Configuration page and the calendar:
- Connections: one card per platform with its status, what it needs, and a link to its settings form.
- Collectors: status (Passed, Findings, Failed, Overdue, Never run, Not set up, Off), last run, controls fed.
- Verify: runs one collector against an in-memory store and shows what it would collect (files, record counts,
  column names, findings, API calls). Nothing is saved as evidence; the audit log records that it ran.
- Run once: a real, write-once run of one collector (or every overdue collector), marked as manual in the
  manifest, so evidence is available now or a missed scheduled run is caught up.

Overdue means the last run is older than OVERDUE_HOURS: the daily schedule did not run. A manual run fills the gap
but does not fix the schedule, so the page keeps saying when the last scheduled-or-manual run happened.
"""
from __future__ import annotations

import datetime as dt
import json

from grcpal.evidence import EvidenceStore

OVERDUE_HOURS = 36          # daily schedule plus a 12-hour grace period
PREVIEW_COLUMNS = 15        # column names shown per file in Verify
PREVIEW_FINDINGS = 25
PREVIEW_QUERIES = 25

# Settings section -> collector PLATFORM values it switches on, and the plain "what you need" list.
CONNECTIONS = (
    ("microsoft", ("identity", "productivity", "endpoints"),
     ["A Microsoft Entra app registration (or the portal's managed identity in Azure) for GRC-pal only.",
      "Microsoft Graph application permissions, read only: User.Read.All, AuditLog.Read.All, "
      "RoleManagement.Read.Directory, Application.Read.All, Policy.Read.All, "
      "DeviceManagementManagedDevices.Read.All. The script deploy/azure/grant-permissions.ps1 grants them.",
      "Your tenant ID: Entra admin center > Overview. Sign-in data needs Entra ID P1 or P2."]),
    ("azure", ("cloud",),
     ["The same identity as Microsoft, with the Reader role on each subscription or the management group.",
      "Subscription IDs: Azure portal > Subscriptions."]),
    ("aws", ("aws",),
     ["An IAM role for GRC-pal with the SecurityAudit and ViewOnlyAccess managed policies.",
      "Best: let the Azure managed identity or GitHub OIDC assume the role (no stored key)."]),
    ("gcp", ("gcp",),
     ["A service account with Security Reviewer, Logs Viewer and Browser on the projects or organization.",
      "Project or organization ID: Google Cloud console > project picker."]),
    ("github", ("source_control",),
     ["A fine-grained token with read access to Contents, Pull requests and Administration on the repositories "
      "in scope, and Issues write on the program repository."]),
)
STATUS_LABELS = {"passed": "Passed", "findings": "Findings", "failed": "Failed", "overdue": "Overdue",
                 "never": "Never run", "unconfigured": "Not set up", "off": "Off"}


class _PreviewStore(EvidenceStore):
    """Evidence store that keeps files in memory: Verify uses it so a test pull is never saved."""

    def __init__(self) -> None:
        super().__init__(root="/nonexistent-preview", account_url="", namespace="")
        self.account_url = None
        self.files: dict[str, bytes] = {}

    def _put(self, name: str, data: bytes) -> None:
        self.files[name] = data


def _parse(value: str | None) -> dt.datetime | None:
    try:
        t = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def _file_summary(name: str, data: bytes) -> dict:
    out = {"name": name, "bytes": len(data), "records": None, "columns": []}
    if name.endswith(".json"):
        try:
            value = json.loads(data)
        except ValueError:
            return out
        if isinstance(value, list):
            out["records"] = len(value)
            if value and isinstance(value[0], dict):
                out["columns"] = sorted(value[0])[:PREVIEW_COLUMNS]
        elif isinstance(value, dict):
            out["columns"] = sorted(value)[:PREVIEW_COLUMNS]
    return out


class AutomationHubMixin:
    # ------------------------------------------------------------------ overview
    def automation_overview(self) -> dict:
        from grcpal import collectors

        self_now = dt.datetime.now(dt.timezone.utc)
        sections = {o["section"].id: o for o in self.settings_overview()}
        controls = self.catalog.sources("collector")
        rows = []
        for name in collectors.NAMES:
            mod = collectors.get(name)
            rows.append(self._collector_row(name, mod, controls.get(name, set()), self_now))
        groups = []
        for section_id, platforms, needs in CONNECTIONS:
            o = sections.get(section_id)
            if not o:
                continue
            groups.append({"section": o["section"], "status": o["status"], "needs": needs,
                           "collectors": [r for r in rows if r["platform"] in platforms]})
        groups.append({"section": None, "status": "ok", "needs": [],
                       "collectors": [r for r in rows if r["platform"] is None]})
        checks = []
        for k in self.all_checks():
            last = k.get("last_result") or {}
            checks.append({"id": k.get("id"), "title": k.get("title") or k.get("id"), "type": k.get("type"),
                           "control": k.get("control"), "source": k.get("source"), "ok": last.get("ok"),
                           "at": last.get("at"), "summary": last.get("summary")})
        counts: dict[str, int] = {}
        for r in rows:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        return {"groups": groups, "checks": checks, "counts": counts, "overdue_hours": OVERDUE_HOURS,
                "overdue": [r["name"] for r in rows if r["status"] in ("overdue", "never") and r["runnable"]],
                "running": bool(self.jobs.running("collect"))}

    def _collector_row(self, name: str, mod, controls, now: dt.datetime) -> dict:
        from grcpal import collectors

        row = {"name": name, "description": mod.DESCRIPTION, "platform": mod.PLATFORM,
               "controls": sorted(controls), "last_run": None, "last_at": None, "findings": None, "error": None,
               "runnable": False}
        if not collectors.platform_enabled(mod, self.catalog, self.settings):
            row["status"] = "off"
            return row
        if hasattr(mod, "enabled") and not mod.enabled():
            row["status"] = "unconfigured"
            return row
        row["runnable"] = True
        runs = self.evidence.list_runs(name)
        if not runs:
            row["status"] = "never"
            return row
        raw = self.evidence.read(name, runs[-1], "manifest.json")
        m = json.loads(raw) if raw else {}
        finished = _parse(m.get("finished") or m.get("started"))
        row.update(last_run=runs[-1], last_at=finished.isoformat(timespec="minutes") if finished else None,
                   findings=m.get("findings_count", 0), error=(m.get("error") or "")[:300] or None)
        if m.get("status") == "error" or not m:
            row["status"] = "failed"
        elif finished is None or now - finished > dt.timedelta(hours=OVERDUE_HOURS):
            row["status"] = "overdue"
        else:
            row["status"] = "findings" if m.get("findings_count") else "passed"
        return row

    # ------------------------------------------------------------------ verify (nothing saved)
    def verify_collector(self, actor, name: str, clients=None, sessions: dict | None = None) -> dict:
        """Run one collector against an in-memory store and summarize what it would collect."""
        from grcpal import collectors
        from grcpal.clients import Clients

        self._admin(actor)
        if name not in collectors.NAMES:
            raise self._invalid("Unknown collector")
        mod = collectors.get(name)
        if not collectors.platform_enabled(mod, self.catalog, self.settings):
            raise self._invalid("This collector's platform is turned off. Turn it on in its settings first.")
        if hasattr(mod, "enabled") and not mod.enabled():
            raise self._invalid("This collector is not set up on this installation")
        ctx = collectors.Context(clients=clients or Clients(self.settings), catalog=self.catalog, today=self.today,
                                 settings=self.settings, inbox=self.inbox_read)
        ctx._sessions.update(sessions or {})
        ctx.clients.queries = []
        if name == "portal_audit":
            ctx.portal_store = self.store
        store = _PreviewStore()
        run = store.new_run(name, [], {"description": mod.DESCRIPTION})
        started = dt.datetime.now(dt.timezone.utc)
        result = {"name": name, "description": mod.DESCRIPTION, "ok": True, "error": None, "files": [],
                  "findings": [], "findings_count": 0, "queries": [], "seconds": 0.0}
        try:
            findings = mod.run(ctx, run) or []
            result["findings_count"] = len(findings)
            result["findings"] = [{"title": str(f.get("title", ""))[:300], "severity": f.get("severity", "")}
                                  for f in findings[:PREVIEW_FINDINGS]]
        except Exception as exc:  # noqa: BLE001 - shown to the admin, like a failed run
            result.update(ok=False, error=f"{type(exc).__name__}: {str(exc)[:500]}")
        result["seconds"] = round((dt.datetime.now(dt.timezone.utc) - started).total_seconds(), 1)
        result["files"] = [_file_summary(f["name"], store.files.get(f"{run.prefix}/{f['name']}", b""))
                           for f in run.files if f["name"].endswith(".json")]
        result["queries"] = [{"api": q.get("api"), "request": q.get("request"), "records": q.get("records"),
                              "pages": q.get("pages")} for q in (getattr(ctx.clients, "queries", None) or [])
                             ][:PREVIEW_QUERIES]
        self.audit(actor, "automation.verify", name, {"ok": result["ok"], "findings": result["findings_count"],
                                                     "records": {f["name"]: f["records"] for f in result["files"]}})
        self.events.info("collector", f"Collector {name} verified ({'ok' if result['ok'] else 'failed'})",
                         actor=actor.email, collector=name)
        return result

    # ------------------------------------------------------------------ run once (saved as evidence)
    def run_collectors_once(self, actor, names: list[str], **kwargs) -> dict:
        from grcpal import collectors

        self._admin(actor)
        names = [n for n in dict.fromkeys(names or []) if n in collectors.NAMES]
        if not names:
            raise self._invalid("Choose a collector to run")
        self.audit(actor, "automation.run", ",".join(names)[:200], {"collectors": names, "trigger": "manual"})
        return self.run_collection(actor, names=names, trigger="manual", **kwargs)

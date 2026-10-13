"""Control health report: the dashboard view a GRC platform would provide.

For each control, every evidence source is checked for freshness against the control's
frequency and for open findings. Output: a self-contained HTML page and a JSON summary.
"""
from __future__ import annotations

import datetime as dt
import html
import json

MAX_AGE_DAYS = {"continuous": 2, "daily": 2, "weekly": 8, "monthly": 35,
                "quarterly": 100, "annual": 380, "event": 35}
CADENCE_AGE = {"monthly": 35, "quarterly": 100, "annual": 380}


def _age(ts: str | None, today: dt.date) -> int | None:
    if not ts:
        return None
    return (today - dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).date()).days


def _task_index(store) -> dict[str, dict]:
    """Last approved completion per task, from the latest issues export."""
    runs = store.list_runs("issues_export")
    raw = store.read("issues_export", runs[-1], "grc_issues.json") if runs else None
    out: dict[str, dict] = {}
    for issue in json.loads(raw) if raw else []:
        task = issue.get("task")
        if not task or issue.get("state") != "closed" or not issue.get("approved"):
            continue
        if task not in out or issue["closed"] > out[task]["closed"]:
            out[task] = issue
    return out


def build(catalog, store, today: dt.date | None = None, portal: dict | None = None) -> dict:
    """portal: optional {"overrides": {control: override}, "tasks": {task: iso}, "uploads": {control: iso},
    "skip_sources": {collector names whose platform is turned off}}."""
    today = today or dt.datetime.now(dt.timezone.utc).date()
    portal = portal or {}
    overrides, portal_tasks, portal_uploads = portal.get("overrides", {}), portal.get("tasks", {}), portal.get("uploads", {})
    skip = set(portal.get("skip_sources") or ())
    manifests: dict[str, dict | None] = {}
    tasks_done = _task_index(store)
    controls = []
    for ctl in catalog.controls:
        in_scope = any(c in catalog.in_scope_criteria for c in ctl.get("criteria", []))
        items = []
        for ev in ctl["evidence"]:
            via = str(ev["via"])
            kind, _, name = via.partition(":")
            item = {"artifact": ev["artifact"], "via": via, "status": "n/a", "last": None, "findings": 0}
            if kind == "collector" and name in skip:
                item["status"], item["note"] = "n/a", "platform not in use"
                items.append(item)
                continue
            if kind == "check":
                kind, name = "collector", f"check-{name}"
            if kind in ("collector", "tool"):
                if name not in manifests:
                    manifests[name] = store.latest_manifest(name)
                m = manifests[name]
                if not m:
                    item["status"] = "not_started"
                else:
                    age = _age(m["finished"], today)
                    item["last"] = m["finished"][:10]
                    item["findings"] = m.get("findings_count", 0)
                    if m.get("status") == "error":
                        item["status"] = "error"
                    elif age is not None and age > MAX_AGE_DAYS[ctl["frequency"]]:
                        item["status"] = "stale"
                    else:
                        item["status"] = "findings" if item["findings"] else "ok"
            elif kind == "task":
                cadence = catalog.tasks.get(name, {}).get("cadence", "annual")
                dates = [d for d in ((tasks_done.get(name) or {}).get("closed"), portal_tasks.get(name)) if d]
                if not dates:
                    item["status"] = "not_started"
                else:
                    last = max(dates)
                    item["last"] = last[:10]
                    item["status"] = "ok" if _age(last, today) <= CADENCE_AGE[cadence] else "stale"
            elif kind == "git":
                item["status"] = "ok" if (catalog.base / name).exists() else "not_started"
            items.append(item)
        if ctl["id"] in portal_uploads:
            items.append({"artifact": "Evidence uploaded in the portal and approved", "via": "portal",
                          "status": "ok", "last": portal_uploads[ctl["id"]][:10], "findings": 0})
        statuses = {i["status"] for i in items}
        if statuses <= {"not_started", "n/a"}:
            overall = "not_started"
        elif statuses & {"stale", "error", "not_started"}:
            overall = "attention"
        elif "findings" in statuses:
            overall = "findings"
        else:
            overall = "ok"
        override = overrides.get(ctl["id"])
        controls.append({"id": ctl["id"], "title": ctl["title"], "owner": ctl["owner"],
                         "frequency": ctl["frequency"], "criteria": ctl.get("criteria", []),
                         "custom": bool(ctl.get("custom")), "mappings": ctl.get("mappings") or {},
                         "iso27001": ctl.get("iso27001") or [],
                         "in_scope": in_scope, "status": "accepted" if override else overall,
                         "computed_status": overall, "override": override, "evidence": items})

    counts: dict[str, int] = {}
    for c in controls:
        if c["in_scope"]:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
    coverage = catalog.coverage()
    return {
        "generated": today.isoformat(),
        "in_scope_categories": catalog.scope.get("in_scope_categories", []),
        "counts": counts,
        "criteria": [{"id": k, "title": catalog.criteria[k]["title"], "controls": coverage.get(k, []),
                      "statuses": sorted({c["status"] for c in controls if c["id"] in coverage.get(k, [])})}
                     for k in catalog.in_scope_criteria],
        "controls": controls,
        "open_exceptions": [e for e in catalog.exceptions if e.get("status") not in ("remediated",)],
    }


_COLORS = {"ok": "#1b7f5b", "findings": "#b7791f", "attention": "#c8553d", "not_started": "#6b7b83",
           "stale": "#c8553d", "error": "#c8553d", "n/a": "#6b7b83", "accepted": "#2f6f9f"}
_LABELS = {"ok": "Operating", "findings": "Findings", "attention": "Needs attention",
           "not_started": "Not started", "stale": "Stale", "error": "Error", "n/a": "Per event",
           "accepted": "Accepted by admin"}


def _pill(status: str) -> str:
    return (f'<span class="pill" style="background:{_COLORS.get(status, "#6b7b83")}">'
            f'{_LABELS.get(status, status)}</span>')


def to_html(data: dict) -> str:
    e = html.escape
    cards = "".join(
        f'<div class="card"><div class="num" style="color:{_COLORS[s]}">{data["counts"].get(s, 0)}</div>'
        f'<div>{_LABELS[s]}</div></div>' for s in ("ok", "accepted", "findings", "attention", "not_started"))
    crit_rows = "".join(
        f"<tr><td>{e(c['id'])}</td><td>{e(c['title'])}</td><td>{e(', '.join(c['controls']))}</td>"
        f"<td>{' '.join(_pill(s) for s in c['statuses'])}</td></tr>" for c in data["criteria"])
    ctl_rows = []
    for c in data["controls"]:
        ev = "<br>".join(
            f"{_pill(i['status'])} {e(i['artifact'])} <span class=q>{e(i['via'])}"
            f"{' · ' + i['last'] if i['last'] else ''}{' · ' + str(i['findings']) + ' findings' if i['findings'] else ''}</span>"
            for i in c["evidence"])
        scope = "" if c["in_scope"] else " <span class=q>(deferred)</span>"
        ctl_rows.append(f"<tr><td><b>{e(c['id'])}</b></td><td>{e(c['title'])}{scope}<br>"
                        f"<span class=q>{e(', '.join(c['criteria']))} · {e(c['owner'])} · {e(c['frequency'])}</span></td>"
                        f"<td>{_pill(c['status'])}</td><td>{ev}</td></tr>")
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>GRC-pal control health</title>
<style>
body{{font-family:Segoe UI,Calibri,Arial,sans-serif;margin:0;padding:24px;color:#1a1f24;background:#fff}}
h1{{margin:0 0 4px;color:#0e2a35}} .q{{color:#5c7a86;font-size:12px}}
.cards{{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0 24px}}
.card{{background:#eef3f4;border-radius:8px;padding:16px 20px;min-width:140px}}
.num{{font-size:36px;font-weight:700}}
table{{border-collapse:collapse;width:100%;margin-bottom:28px;font-size:14px}}
th,td{{text-align:left;padding:8px;border-bottom:1px solid #dde6e8;vertical-align:top}}
th{{background:#0e2a35;color:#fff}}
.pill{{color:#fff;border-radius:10px;padding:1px 8px;font-size:12px;white-space:nowrap}}
</style></head><body>
<h1>GRC-pal control health</h1>
<div class=q>Generated {e(data['generated'])} · In scope: {e(', '.join(data['in_scope_categories']))} ·
{len(data['open_exceptions'])} open exceptions</div>
<div class=cards>{cards}</div>
<h2>In-scope criteria coverage</h2>
<table><tr><th>Criterion</th><th>Title</th><th>Controls</th><th>Status</th></tr>{crit_rows}</table>
<h2>Controls</h2>
<table><tr><th>ID</th><th>Control</th><th>Status</th><th>Evidence</th></tr>{''.join(ctl_rows)}</table>
</body></html>"""

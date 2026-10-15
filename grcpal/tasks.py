"""Recurring control tasks as GitHub issues (replaces the task engine of a GRC platform)."""
from __future__ import annotations

import datetime as dt


def period_label(task: dict, today: dt.date) -> str:
    if task["cadence"] == "annual":
        return f"{today.year}"
    if task["cadence"] == "quarterly":
        return f"{today.year}-Q{(today.month - 1) // 3 + 1}"
    return f"{today:%Y-%m}"


def due_this_month(catalog, today: dt.date) -> list[tuple[str, dict]]:
    return [(name, t) for name, t in catalog.tasks.items() if today.month in t.get("months", [])]


def issue_body(name: str, task: dict, controls: list[str], due: dt.date, catalog) -> str:
    owner = catalog.roles[task["owner"]]
    approver = catalog.roles[task["approver"]]
    lines = [
        f"**Control task:** `{name}`  ",
        f"**Controls:** {', '.join(controls) or '(none)'}  ",
        f"**Owner:** {owner['title']} ({owner.get('person')})  ",
        f"**Approver:** {approver['title']} ({approver.get('person')})  ",
        f"**Due:** {due.isoformat()}",
        "",
        "### Checklist",
        *[f"- [ ] {item}" for item in task.get("checklist", [])],
        "",
        "### How to complete",
        "1. Attach evidence files to this issue (drag and drop) or link them.",
        "2. The approver reviews and comments a line starting with **Approved**.",
        "3. Close the issue. The nightly export stores this issue, its comments and approval as evidence.",
    ]
    return "\n".join(lines)


def open_due(ctx, dry_run: bool = False) -> list[str]:
    catalog, gh = ctx.catalog, ctx.clients
    repo = None if dry_run else ctx.grc_repo
    by_task = catalog.sources("task")
    created = []
    for name, task in due_this_month(catalog, ctx.today):
        period = period_label(task, ctx.today)
        title = f"[GRC] {task['title']} ({period})"
        due = ctx.today + dt.timedelta(days=task.get("due_days", 30))
        controls = sorted(set(by_task.get(name, [])) | set(task.get("controls") or []))
        labels = ["grc", f"task:{name}", f"due:{due.isoformat()}", f"owner:{task['owner']}",
                  *[f"control:{c}" for c in controls]]
        if dry_run:
            created.append(f"(dry run) {title}")
            continue
        existing = gh.gh_list(f"/repos/{repo}/issues", {"labels": f"task:{name}", "state": "all"})
        if any(i["title"] == title for i in existing):
            continue
        for label in labels:
            gh.gh_post(f"/repos/{repo}/labels", {"name": label, "color": "0f8b8d"}, ok_statuses=(422,))
        assignee = (catalog.roles[task["owner"]].get("github") or "TBD")
        body = {"title": title, "body": issue_body(name, task, controls, due, catalog), "labels": labels}
        if assignee != "TBD":
            body["assignees"] = [assignee]
        issue = gh.gh_post(f"/repos/{repo}/issues", body)
        created.append(issue["html_url"])
    return created


def sync_deficiencies(ctx, source: str, findings: list[dict]) -> str | None:
    """One open deficiency issue per collector; updated with the current finding list."""
    gh, repo = ctx.clients, ctx.grc_repo
    label = f"source:{source}"
    open_issues = gh.gh_list(f"/repos/{repo}/issues", {"labels": f"deficiency,{label}", "state": "open"})
    listing = "\n".join(f"- **{f['severity']}** {f['title']}" for f in findings[:100])
    if findings and not open_issues:
        for lbl in ("grc", "deficiency", label):
            gh.gh_post(f"/repos/{repo}/labels", {"name": lbl, "color": "c8553d"}, ok_statuses=(422,))
        issue = gh.gh_post(f"/repos/{repo}/issues", {
            "title": f"[Deficiency] {source}: {len(findings)} finding(s)",
            "labels": ["grc", "deficiency", label],
            "body": f"Automated control test `{source}` found issues on {ctx.today}.\n\n{listing}\n\n"
                    "Fix the items or record an approved exception in registers/exceptions.yaml, "
                    "then close this issue with a comment describing the remediation."})
        return issue["html_url"]
    if open_issues:
        number = open_issues[0]["number"]
        text = (f"Run {ctx.today}: {len(findings)} finding(s) remain.\n\n{listing}" if findings
                else f"Run {ctx.today}: no findings. Close this issue with a remediation note.")
        gh.gh_post(f"/repos/{repo}/issues/{number}/comments", {"body": text})
        return open_issues[0]["html_url"]
    return None

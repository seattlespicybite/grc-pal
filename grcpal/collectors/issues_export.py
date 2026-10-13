"""Evidence for task-based and event controls: export GRC issues (tasks, access requests,
incidents, deficiencies, architecture reviews) from the GRC repository, with comments,
assignees, close date and whether the designated approver approved.
"""
import datetime as dt

PLATFORM = "source_control"
DESCRIPTION = "Export GRC issues with comments, approvals and close dates"


def run(ctx, run):
    # All GRC issues are exported every run (volume is small) so that the report can see the
    # last completion of annual tasks without reading older runs.
    repo = ctx.grc_repo
    approvers = {role: (info.get("github") or "").lower() for role, info in ctx.catalog.roles.items()}
    issues = ctx.clients.gh_list(f"/repos/{repo}/issues", {"labels": "grc", "state": "all"})
    rows, findings = [], []
    for issue in issues:
        if "pull_request" in issue:
            continue
        labels = [lbl["name"] for lbl in issue.get("labels", [])]
        comments = ctx.clients.gh_list(issue["comments_url"]) if issue.get("comments") else []
        task = next((lbl.split(":", 1)[1] for lbl in labels if lbl.startswith("task:")), None)
        approver_role = (ctx.catalog.tasks.get(task) or {}).get("approver") if task else None
        approver_login = approvers.get(approver_role, "")
        approved_by = [c["user"]["login"] for c in comments
                       if c.get("body", "").strip().lower().startswith("approved")
                       and (not approver_login or approver_login == "tbd" or c["user"]["login"].lower() == approver_login)]
        row = {
            "number": issue["number"], "title": issue["title"], "url": issue["html_url"],
            "state": issue["state"], "labels": ",".join(labels), "task": task,
            "controls": ",".join(lbl.split(":", 1)[1] for lbl in labels if lbl.startswith("control:")),
            "created": issue["created_at"], "closed": issue.get("closed_at"),
            "closed_by": (issue.get("closed_by") or {}).get("login"),
            "approved_by": ",".join(approved_by), "approved": bool(approved_by),
            "body": issue.get("body"),
            "comments": [{"user": c["user"]["login"], "at": c["created_at"], "body": c.get("body")} for c in comments],
        }
        rows.append(row)
        if task and issue["state"] == "closed" and not approved_by:
            findings.append({"key": f"unapproved:{issue['number']}", "severity": "medium",
                             "title": f"Task issue #{issue['number']} closed without approver sign-off", "detail": {"url": issue["html_url"]}})
        due = next((lbl.split(":", 1)[1] for lbl in labels if lbl.startswith("due:")), None)
        if task and issue["state"] == "open" and due and dt.date.fromisoformat(due) < ctx.today:
            findings.append({"key": f"overdue:{issue['number']}", "severity": "medium",
                             "title": f"Task issue #{issue['number']} overdue since {due}", "detail": {"url": issue["html_url"]}})
    run.add("grc_issues", rows)
    return findings

"""CHG-01, CHG-02, CHG-03, PI-02: population of merged pull requests with approvals and checks.

Covers repos in GRCPAL_REPOS for the last GRCPAL_WINDOW_DAYS (default 31). Run monthly at
minimum; the auditor samples from this population.
Token scope: repository metadata, pull requests and checks (read).
"""
import datetime as dt

from grcpal.collectors import parse_time

PLATFORM = "source_control"
DESCRIPTION = "Export merged PRs with author, approvers, check results and emergency labels"
EMERGENCY_LABEL = "emergency-change"
RETRO_LABEL = "retro-reviewed"


def _repo_changes(ctx, repo, since):
    gh = ctx.clients
    default = gh.gh_get(f"/repos/{repo}")["default_branch"]
    pulls = []
    for pr in gh.gh_list(f"/repos/{repo}/pulls", {"state": "closed", "base": default,
                                                  "sort": "updated", "direction": "desc"}, max_pages=20):
        if parse_time(pr["updated_at"]) < since:
            break
        if pr.get("merged_at") and parse_time(pr["merged_at"]) >= since:
            pulls.append(pr)
    rows = []
    for pr in pulls:
        author = pr["user"]["login"]
        reviews = gh.gh_list(f"/repos/{repo}/pulls/{pr['number']}/reviews")
        approvers = sorted({r["user"]["login"] for r in reviews
                            if r.get("state") == "APPROVED" and r.get("user") and r["user"]["login"] != author})
        checks = gh.gh_get(f"/repos/{repo}/commits/{pr['merge_commit_sha']}/check-runs") or {}
        conclusions = [c.get("conclusion") for c in checks.get("check_runs", [])]
        labels = [lbl["name"] for lbl in pr.get("labels", [])]
        rows.append({
            "repo": repo, "number": pr["number"], "title": pr["title"], "url": pr["html_url"],
            "author": author, "approvers": ",".join(approvers), "independent_approval": bool(approvers),
            "merged_by": (pr.get("merged_by") or {}).get("login"), "merged_at": pr["merged_at"],
            "checks_total": len(conclusions),
            "checks_failed": sum(1 for c in conclusions if c not in ("success", "skipped", "neutral")),
            "emergency": EMERGENCY_LABEL in labels, "retro_reviewed": RETRO_LABEL in labels,
            "labels": ",".join(labels), "merge_commit": pr["merge_commit_sha"],
        })
    return rows


def run(ctx, run):
    since = dt.datetime.combine(ctx.today - dt.timedelta(days=ctx.window_days), dt.time(), dt.timezone.utc)
    rows = []
    for repo in ctx.repos:
        rows.extend(_repo_changes(ctx, repo, since))
    run.add("merged_changes", rows)
    run.meta["window_start"] = since.isoformat()
    findings = []
    for r in rows:
        if not r["independent_approval"] and not r["emergency"]:
            findings.append({"key": f"no-approval:{r['repo']}#{r['number']}", "severity": "high",
                             "title": f"{r['repo']}#{r['number']} merged without independent approval", "detail": {"url": r["url"]}})
        if r["emergency"] and not r["retro_reviewed"]:
            findings.append({"key": f"no-retro:{r['repo']}#{r['number']}", "severity": "medium",
                             "title": f"Emergency change {r['repo']}#{r['number']} awaiting retro review", "detail": {"url": r["url"]}})
        if r["checks_failed"]:
            findings.append({"key": f"failed-checks:{r['repo']}#{r['number']}", "severity": "medium",
                             "title": f"{r['repo']}#{r['number']} merged with {r['checks_failed']} failed checks", "detail": {"url": r["url"]}})
    return findings

"""VUL-01: open Dependabot alerts with age against remediation SLAs.

Dependabot alerts are free on GitHub. Token needs Dependabot alerts read permission.
"""
from grcpal.collectors import days_since

PLATFORM = "source_control"
DESCRIPTION = "Export open Dependabot alerts and flag those past SLA"
SLA_DAYS = {"critical": 15, "high": 30, "medium": 90, "low": 180}


def run(ctx, run):
    rows, findings = [], []
    for repo in ctx.repos:
        for a in ctx.clients.gh_list(f"/repos/{repo}/dependabot/alerts", {"state": "open"}):
            sev = ((a.get("security_advisory") or {}).get("severity") or "low").lower()
            age = days_since(a.get("created_at"), ctx.today)
            sla = SLA_DAYS.get(sev, 180)
            row = {"repo": repo, "number": a.get("number"), "severity": sev,
                   "package": ((a.get("dependency") or {}).get("package") or {}).get("name"),
                   "advisory": (a.get("security_advisory") or {}).get("ghsa_id"),
                   "created": a.get("created_at"), "age_days": age, "sla_days": sla,
                   "past_sla": age is not None and age > sla, "url": a.get("html_url")}
            rows.append(row)
            if row["past_sla"] and sev in ("critical", "high"):
                findings.append({"key": f"vuln:{repo}:{row['number']}", "severity": "high",
                                 "title": f"{repo} {sev} {row['package']} open {age} days (SLA {sla})",
                                 "detail": {"url": row["url"]}})
    run.add("dependabot_open_alerts", rows)
    return findings

"""AST-01, DAT-01, CHG-04, LOG-01: Azure inventory via Azure Resource Graph.

Azure RBAC: Reader on in-scope subscriptions (or the management group).
"""
PLATFORM = "cloud"
DESCRIPTION = "Export Azure subscriptions, resources, tags and Log Analytics retention"
REQUIRED_TAGS = ("owner", "environment", "data-class")
MIN_RETENTION_DAYS = 90  # interactive retention; total retention (with archive) must reach 365

RESOURCES = """
resources
| project id, name, type, location, resourceGroup, subscriptionId, tags
"""
SUBSCRIPTIONS = """
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| project subscriptionId, name, state = properties.state, tags
"""
WORKSPACES = """
resources
| where type =~ 'microsoft.operationalinsights/workspaces'
| project id, name, subscriptionId, retentionInDays = toint(properties.retentionInDays),
          dailyQuotaGb = properties.workspaceCapping.dailyQuotaGb
"""


def run(ctx, run):
    q = ctx.clients.arg_query
    subs, resources, workspaces = q(SUBSCRIPTIONS), q(RESOURCES), q(WORKSPACES)
    run.add("subscriptions", subs)
    run.add("resources", resources)
    run.add("log_analytics_workspaces", workspaces)

    missing = {t: 0 for t in REQUIRED_TAGS}
    for r in resources:
        tags = {k.lower() for k in (r.get("tags") or {})}
        for t in REQUIRED_TAGS:
            if t not in tags:
                missing[t] += 1
    run.add("tag_coverage", {"resources": len(resources), "missing_by_tag": missing})

    findings = []
    for ws in workspaces:
        if (ws.get("retentionInDays") or 0) < MIN_RETENTION_DAYS:
            findings.append({"key": f"retention:{ws['id']}", "severity": "medium",
                             "title": f"Log Analytics workspace {ws['name']} retention "
                                      f"{ws.get('retentionInDays')} days (check archive reaches 365)",
                             "detail": {}})
    if resources and missing["data-class"]:
        findings.append({"key": "tag:data-class", "severity": "low",
                         "title": f"{missing['data-class']} resources missing data-class tag", "detail": {}})
    return findings

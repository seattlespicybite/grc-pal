"""MON-01, NET-01, CRY-01: Azure Policy compliance, including the built-in
"SOC 2 Type 2" regulatory compliance initiative. Assign that initiative to the in-scope
subscriptions or management group (Azure Policy evaluation of Azure resources is free).

Optional: GRCPAL_POLICY_ASSIGNMENT = assignment name of the SOC 2 initiative, to filter.
"""
from collections import Counter

PLATFORM = "cloud"
DESCRIPTION = "Export Azure Policy compliance states and per-control summary"

STATES = """
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| extend p = properties
| project resourceId = tostring(p.resourceId), complianceState = tostring(p.complianceState),
          assignment = tostring(p.policyAssignmentName), initiative = tostring(p.policySetDefinitionName),
          policy = tostring(p.policyDefinitionName), groups = p.policyDefinitionGroupNames,
          subscriptionId, timestamp = tostring(p.timestamp)
"""


def run(ctx, run):
    rows = ctx.clients.arg_query(STATES)
    assignment = ctx.setting("GRCPAL_POLICY_ASSIGNMENT")
    if assignment:
        rows = [r for r in rows if r.get("assignment") == assignment]
    run.add("policy_states", rows)
    by_group = Counter()
    noncompliant = [r for r in rows if r.get("complianceState", "").lower() == "noncompliant"]
    for r in noncompliant:
        for g in r.get("groups") or ["(ungrouped)"]:
            by_group[g] += 1
    run.add("noncompliant_by_control_group",
            [{"group": g, "noncompliant_resources": n} for g, n in by_group.most_common()])
    run.add("summary", {"states": len(rows), "noncompliant": len(noncompliant)})
    return [{"key": f"policy-group:{g}", "severity": "medium",
             "title": f"Azure Policy group {g}: {n} noncompliant resources", "detail": {}}
            for g, n in by_group.most_common(25)]

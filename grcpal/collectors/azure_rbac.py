"""IAM-09: Azure role assignments (production access population for access reviews)."""
PLATFORM = "cloud"
DESCRIPTION = "Export Azure RBAC role assignments with role names"
PRIVILEGED = {"Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator"}

ASSIGNMENTS = """
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| project id, subscriptionId,
          principalId = tostring(properties.principalId),
          principalType = tostring(properties.principalType),
          roleDefinitionId = tolower(tostring(properties.roleDefinitionId)),
          scope = tostring(properties.scope),
          createdOn = tostring(properties.createdOn)
"""
DEFINITIONS = """
authorizationresources
| where type =~ 'microsoft.authorization/roledefinitions'
| project id = tolower(id), roleName = tostring(properties.roleName)
"""


def run(ctx, run):
    defs = {}
    for d in ctx.clients.arg_query(DEFINITIONS):
        # role definition ids appear at several scopes; key on the trailing GUID
        defs[d["id"].rsplit("/", 1)[-1]] = d["roleName"]
    rows = []
    for a in ctx.clients.arg_query(ASSIGNMENTS):
        a["roleName"] = defs.get(a["roleDefinitionId"].rsplit("/", 1)[-1], a["roleDefinitionId"])
        rows.append(a)
    run.add("role_assignments", rows)
    findings = []
    for a in rows:
        if a["roleName"] in PRIVILEGED and a["principalType"] == "User" and a["scope"].count("/") <= 2:
            findings.append({"key": f"standing-priv:{a['id']}", "severity": "medium",
                             "title": f"Standing {a['roleName']} for a user at subscription scope {a['scope']}",
                             "detail": {"principalId": a["principalId"]}})
    return findings

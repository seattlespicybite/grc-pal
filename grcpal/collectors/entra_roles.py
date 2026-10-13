"""IAM-06: directory role assignments (privileged access).

Graph permission: RoleManagement.Read.Directory.
"""
PLATFORM = "identity"
DESCRIPTION = "Export Entra ID directory role assignments"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"  # built-in Global Administrator template id
MAX_GLOBAL_ADMINS = 4


def run(ctx, run):
    defs = {d["id"]: d.get("displayName") for d in ctx.clients.graph_list(
        "/roleManagement/directory/roleDefinitions", {"$select": "id,displayName"})}
    assignments = ctx.clients.graph_list("/roleManagement/directory/roleAssignments", {"$expand": "principal"})
    rows = []
    for a in assignments:
        p = a.get("principal") or {}
        rows.append({
            "role": defs.get(a.get("roleDefinitionId"), a.get("roleDefinitionId")),
            "role_id": a.get("roleDefinitionId"), "scope": a.get("directoryScopeId"),
            "principal": p.get("userPrincipalName") or p.get("displayName"),
            "principal_type": (p.get("@odata.type") or "").replace("#microsoft.graph.", ""),
        })
    run.add("role_assignments", rows)
    findings = []
    gas = [r for r in rows if r["role_id"] == GLOBAL_ADMIN]
    if len(gas) > MAX_GLOBAL_ADMINS:
        findings.append({"key": "global-admin-count", "severity": "high",
                         "title": f"{len(gas)} Global Administrator assignments (target {MAX_GLOBAL_ADMINS} or fewer)",
                         "detail": {"principals": [r["principal"] for r in gas]}})
    if len(gas) < 2:
        findings.append({"key": "global-admin-min", "severity": "medium",
                         "title": "Fewer than 2 Global Administrators (break-glass coverage)", "detail": {}})
    return findings

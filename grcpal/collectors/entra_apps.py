"""AST-03, IAM-01, IAM-07: applications, SSO mode and credential hygiene.

Graph permission: Application.Read.All.
"""
from grcpal.collectors import parse_time

PLATFORM = "identity"
DESCRIPTION = "Export enterprise apps (SSO mode) and app registration credentials"
MAX_SECRET_DAYS = 365


def run(ctx, run):
    sps = ctx.clients.graph_list("/servicePrincipals", {
        "$select": "id,appId,displayName,servicePrincipalType,preferredSingleSignOnMode,accountEnabled,"
                   "appOwnerOrganizationId,tags", "$top": 999})
    run.add("enterprise_apps", [{
        "name": s.get("displayName"), "app_id": s.get("appId"), "type": s.get("servicePrincipalType"),
        "sso_mode": s.get("preferredSingleSignOnMode"), "enabled": s.get("accountEnabled"),
        "owner_tenant": s.get("appOwnerOrganizationId"),
    } for s in sps])

    apps = ctx.clients.graph_list("/applications", {
        "$select": "id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials", "$top": 999})
    creds, findings = [], []
    for app in apps:
        for kind, items in (("secret", app.get("passwordCredentials") or []),
                            ("certificate", app.get("keyCredentials") or [])):
            for c in items:
                start, end = parse_time(c.get("startDateTime")), parse_time(c.get("endDateTime"))
                lifetime = (end - start).days if start and end else None
                expired = bool(end and end.date() < ctx.today)
                creds.append({"app": app.get("displayName"), "app_id": app.get("appId"), "kind": kind,
                              "name": c.get("displayName"), "start": c.get("startDateTime"),
                              "end": c.get("endDateTime"), "lifetime_days": lifetime, "expired": expired})
                if kind == "secret" and lifetime and lifetime > MAX_SECRET_DAYS and not expired:
                    findings.append({"key": f"long-secret:{app.get('appId')}:{c.get('keyId')}", "severity": "medium",
                                     "title": f"Client secret valid {lifetime} days on {app.get('displayName')}",
                                     "detail": {"end": c.get("endDateTime")}})
    run.add("app_credentials", creds)
    return findings

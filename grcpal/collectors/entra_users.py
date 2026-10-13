"""IAM-03, IAM-05, IAM-08, GOV-02: user population from Entra ID.

Graph permissions (application): User.Read.All, AuditLog.Read.All (for signInActivity,
which requires Entra ID P1 or P2).
"""
from grcpal.collectors import days_since

PLATFORM = "identity"
DESCRIPTION = "Export all Entra ID users with status, type and last sign-in"
GUEST_INACTIVE_DAYS = 90

SELECT = ("id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime,"
          "employeeId,department,jobTitle,signInActivity")


def run(ctx, run):
    users = ctx.clients.graph_list("/users", {"$select": SELECT, "$top": 999})
    rows = []
    for u in users:
        sign_in = (u.get("signInActivity") or {})
        last = sign_in.get("lastSuccessfulSignInDateTime") or sign_in.get("lastSignInDateTime")
        rows.append({
            "id": u.get("id"), "upn": u.get("userPrincipalName"), "name": u.get("displayName"),
            "enabled": u.get("accountEnabled"), "type": u.get("userType"),
            "created": u.get("createdDateTime"), "employee_id": u.get("employeeId"),
            "department": u.get("department"), "job_title": u.get("jobTitle"),
            "last_sign_in": last, "days_since_sign_in": days_since(last, ctx.today),
        })
    run.add("users", rows)

    findings = []
    for r in rows:
        stale = r["days_since_sign_in"]
        if r["type"] == "Guest" and r["enabled"] and (stale is None or stale > GUEST_INACTIVE_DAYS):
            findings.append({"key": f"guest-inactive:{r['id']}", "severity": "medium",
                             "title": f"Enabled guest inactive over {GUEST_INACTIVE_DAYS} days: {r['upn']}",
                             "detail": {"last_sign_in": r["last_sign_in"]}})
    return findings

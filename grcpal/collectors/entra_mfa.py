"""IAM-02: MFA registration for every user.

Graph permission: AuditLog.Read.All (userRegistrationDetails report).
"""
PLATFORM = "identity"
DESCRIPTION = "Export MFA registration details and flag members without MFA"


def run(ctx, run):
    rows = ctx.clients.graph_list("/reports/authenticationMethods/userRegistrationDetails")
    slim = [{
        "upn": r.get("userPrincipalName"), "user_type": r.get("userType"), "is_admin": r.get("isAdmin"),
        "mfa_registered": r.get("isMfaRegistered"), "mfa_capable": r.get("isMfaCapable"),
        "passwordless_capable": r.get("isPasswordlessCapable"),
        "methods": ",".join(r.get("methodsRegistered") or []),
    } for r in rows]
    run.add("mfa_registration", slim)
    members = [r for r in slim if r["user_type"] == "member"]
    run.add("summary", {
        "members": len(members),
        "members_mfa_registered": sum(1 for r in members if r["mfa_registered"]),
        "admins_without_phishing_resistant": sum(
            1 for r in members if r["is_admin"] and not any(
                m in (r["methods"] or "") for m in ("fido2", "windowsHelloForBusiness", "passKeyDeviceBound"))),
    })
    findings = []
    for r in members:
        if not r["mfa_registered"]:
            findings.append({"key": f"no-mfa:{r['upn']}", "severity": "high" if r["is_admin"] else "medium",
                             "title": f"Member without MFA registered: {r['upn']}", "detail": {}})
    return findings

"""IAM-02: Conditional Access policies (MFA enforcement, legacy auth block).

Graph permission: Policy.Read.All.
"""
PLATFORM = "identity"
DESCRIPTION = "Export Conditional Access policies and test MFA and legacy-auth coverage"


def _requires_mfa(p: dict) -> bool:
    grant = p.get("grantControls") or {}
    return "mfa" in (grant.get("builtInControls") or []) or bool(grant.get("authenticationStrength"))


def _all_users(p: dict) -> bool:
    return "All" in (((p.get("conditions") or {}).get("users") or {}).get("includeUsers") or [])


def _blocks_legacy(p: dict) -> bool:
    apps = (p.get("conditions") or {}).get("clientAppTypes") or []
    grant = p.get("grantControls") or {}
    return {"exchangeActiveSync", "other"} <= set(apps) and "block" in (grant.get("builtInControls") or [])


def run(ctx, run):
    policies = ctx.clients.graph_list("/identity/conditionalAccess/policies")
    run.add("policies_full", policies)
    enabled = [p for p in policies if p.get("state") == "enabled"]
    summary = [{
        "name": p.get("displayName"), "state": p.get("state"), "all_users": _all_users(p),
        "requires_mfa": _requires_mfa(p), "blocks_legacy_auth": _blocks_legacy(p),
        "excluded_users": len((((p.get("conditions") or {}).get("users") or {}).get("excludeUsers") or [])),
        "modified": p.get("modifiedDateTime"),
    } for p in policies]
    run.add("policies_summary", summary)

    findings = []
    if not any(_all_users(p) and _requires_mfa(p) for p in enabled):
        findings.append({"key": "no-mfa-all-users", "severity": "high",
                         "title": "No enabled Conditional Access policy requires MFA for all users", "detail": {}})
    if not any(_blocks_legacy(p) for p in enabled):
        findings.append({"key": "legacy-auth-open", "severity": "high",
                         "title": "No enabled Conditional Access policy blocks legacy authentication", "detail": {}})
    return findings

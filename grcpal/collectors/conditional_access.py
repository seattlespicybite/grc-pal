"""IAM-02 and AST-02: Conditional Access policies (MFA enforcement, legacy auth block, compliant device).

Graph permission: Policy.Read.All.
"""
PLATFORM = "identity"
DESCRIPTION = "Export Conditional Access policies and test MFA, legacy-auth and device-compliance coverage"


def _requires_mfa(p: dict) -> bool:
    grant = p.get("grantControls") or {}
    return "mfa" in (grant.get("builtInControls") or []) or bool(grant.get("authenticationStrength"))


def _all_users(p: dict) -> bool:
    return "All" in (((p.get("conditions") or {}).get("users") or {}).get("includeUsers") or [])


def _blocks_legacy(p: dict) -> bool:
    apps = (p.get("conditions") or {}).get("clientAppTypes") or []
    grant = p.get("grantControls") or {}
    return {"exchangeActiveSync", "other"} <= set(apps) and "block" in (grant.get("builtInControls") or [])


_DEVICE_CONTROLS = {"compliantDevice", "domainJoinedDevice"}  # Intune compliant, or Microsoft Entra hybrid joined


def _requires_device(p: dict) -> bool:
    """The policy only lets in managed devices. With "Require one of the selected controls" (OR), MFA alone would
    also pass, so that only counts when every listed control is a device control."""
    grant = p.get("grantControls") or {}
    controls = set(grant.get("builtInControls") or [])
    if not controls & _DEVICE_CONTROLS:
        return False
    return (grant.get("operator") or "OR").upper() == "AND" or controls <= _DEVICE_CONTROLS


def run(ctx, run):
    policies = ctx.clients.graph_list("/identity/conditionalAccess/policies")
    run.add("policies_full", policies)
    enabled = [p for p in policies if p.get("state") == "enabled"]
    summary = [{
        "name": p.get("displayName"), "state": p.get("state"), "all_users": _all_users(p),
        "requires_mfa": _requires_mfa(p), "blocks_legacy_auth": _blocks_legacy(p),
        "requires_compliant_device": _requires_device(p),
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
    if not any(_requires_device(p) for p in enabled):
        findings.append({"key": "no-device-compliance", "severity": "medium",
                         "title": "No enabled Conditional Access policy requires a compliant or hybrid-joined device "
                                  "(unmanaged devices can sign in)", "detail": {}})
    return findings

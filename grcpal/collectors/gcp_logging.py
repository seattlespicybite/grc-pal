"""LOG-01 (Google Cloud): Data Access audit logs and log sinks.

Permissions: resourcemanager.projects.getIamPolicy, logging.sinks.list (roles/iam.securityReviewer, roles/logging.viewer).
"""
PLATFORM = "gcp"
DESCRIPTION = "Google Cloud audit logging configuration and log export sinks"
CRM = "https://cloudresourcemanager.googleapis.com/v1"
LOGGING = "https://logging.googleapis.com/v2"


def run(ctx, run):
    s = ctx.gcp()
    rows, sinks, findings = [], [], []
    for pid in ctx.setting_list("GRCPAL_GCP_PROJECTS"):
        r = s.post(f"{CRM}/projects/{pid}:getIamPolicy", json={"options": {"requestedPolicyVersion": 3}}, timeout=30)
        r.raise_for_status()
        configs = r.json().get("auditConfigs", [])
        all_services = next((c for c in configs if c.get("service") == "allServices"), None)
        types = sorted({t.get("logType") for t in (all_services or {}).get("auditLogConfigs", [])})
        rows.append({"project": pid, "all_services_log_types": ",".join(types)})
        if not {"DATA_READ", "DATA_WRITE"} <= set(types):
            findings.append({"key": f"data-access:{pid}", "severity": "medium",
                             "title": f"{pid}: Data Access audit logs are not on for all services", "detail": {}})
        sr = s.get(f"{LOGGING}/projects/{pid}/sinks", timeout=30)
        sr.raise_for_status()
        for k in sr.json().get("sinks", []):
            sinks.append({"project": pid, "name": k["name"], "destination": k.get("destination"),
                          "filter": k.get("filter", ""), "disabled": k.get("disabled", False)})
        if not any(x["project"] == pid and not x["disabled"] for x in sinks):
            findings.append({"key": f"no-sink:{pid}", "severity": "low",
                             "title": f"{pid}: no log sink exports logs for retention", "detail": {}})
    run.add("audit_configs", rows)
    run.add("log_sinks", sinks)
    return findings

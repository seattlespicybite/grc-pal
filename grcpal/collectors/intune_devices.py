"""AST-02, END-01, VUL-03: managed device inventory and compliance from Intune.

Graph permission: DeviceManagementManagedDevices.Read.All.
"""
from grcpal.collectors import days_since

PLATFORM = "endpoints"
DESCRIPTION = "Export Intune managed devices with compliance, encryption and last sync"
STALE_SYNC_DAYS = 30


def run(ctx, run):
    devices = ctx.clients.graph_list("/deviceManagement/managedDevices", {
        "$select": "id,deviceName,operatingSystem,osVersion,complianceState,isEncrypted,lastSyncDateTime,"
                   "userPrincipalName,managedDeviceOwnerType,enrolledDateTime,serialNumber"})
    rows = [{
        "device": d.get("deviceName"), "user": d.get("userPrincipalName"), "os": d.get("operatingSystem"),
        "os_version": d.get("osVersion"), "compliance": d.get("complianceState"),
        "encrypted": d.get("isEncrypted"), "ownership": d.get("managedDeviceOwnerType"),
        "last_sync": d.get("lastSyncDateTime"), "days_since_sync": days_since(d.get("lastSyncDateTime"), ctx.today),
        "serial": d.get("serialNumber"),
    } for d in devices]
    run.add("managed_devices", rows)
    run.add("summary", {
        "devices": len(rows),
        "compliant": sum(1 for r in rows if r["compliance"] == "compliant"),
        "encrypted": sum(1 for r in rows if r["encrypted"]),
    })
    findings = []
    for r in rows:
        if r["ownership"] != "company":
            continue
        problems = []
        if r["compliance"] != "compliant":
            problems.append(f"compliance={r['compliance']}")
        if not r["encrypted"] and r["os"] in ("Windows", "macOS"):
            problems.append("not encrypted")
        if (r["days_since_sync"] or 0) > STALE_SYNC_DAYS:
            problems.append(f"no sync for {r['days_since_sync']} days")
        if problems:
            findings.append({"key": f"device:{r['serial'] or r['device']}", "severity": "medium",
                             "title": f"Device {r['device']} ({r['user']}): {', '.join(problems)}", "detail": {}})
    return findings

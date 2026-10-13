"""BCP-02, PI-05: Azure Backup vault settings and protected item health."""
from grcpal.collectors import days_since

PLATFORM = "cloud"
DESCRIPTION = "Export Recovery Services vaults and protected items with last backup status"
MAX_BACKUP_AGE_DAYS = 2

VAULTS = """
resources
| where type =~ 'microsoft.recoveryservices/vaults'
| project id, name, subscriptionId, location,
          redundancy = tostring(properties.redundancySettings.standardTierStorageRedundancy),
          softDelete = tostring(properties.securitySettings.softDeleteSettings.softDeleteState),
          immutability = tostring(properties.securitySettings.immutabilitySettings.state)
"""
ITEMS = """
recoveryservicesresources
| where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems'
| extend p = properties
| project id, item = tostring(p.friendlyName), workload = tostring(p.workloadType),
          policy = tostring(p.policyName), lastBackupStatus = tostring(p.lastBackupStatus),
          lastBackupTime = tostring(p.lastBackupTime), protectionState = tostring(p.protectionState)
"""


def run(ctx, run):
    vaults, items = ctx.clients.arg_query(VAULTS), ctx.clients.arg_query(ITEMS)
    run.add("vaults", vaults)
    run.add("protected_items", items)
    findings = []
    for v in vaults:
        if v.get("softDelete", "").lower() not in ("enabled", "alwayson"):
            findings.append({"key": f"softdelete:{v['id']}", "severity": "medium",
                             "title": f"Vault {v['name']} soft delete is {v.get('softDelete') or 'unknown'}", "detail": {}})
    for i in items:
        age = days_since(i.get("lastBackupTime"), ctx.today)
        if i.get("lastBackupStatus", "").lower() not in ("healthy", "completed") or age is None or age > MAX_BACKUP_AGE_DAYS:
            findings.append({"key": f"backup:{i['id']}", "severity": "high",
                             "title": f"Backup of {i['item']} status {i.get('lastBackupStatus')}, last {i.get('lastBackupTime')}",
                             "detail": {}})
    return findings

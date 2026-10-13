# Detection and alert rules (LOG-02, BCP-04)

Azure Monitor alert rules live here as Bicep or ARM, so every rule change is reviewed in a PR.
Scheduled log alerts and activity log alerts cost a few dollars per month at most, and are the
only paid component besides storage and Log Analytics ingestion. Microsoft Sentinel is optional
and not required for SOC 2.

Minimum rule set before the observation window:

| Rule | Source | Response |
| --- | --- | --- |
| Global Administrator or Privileged Role Administrator assigned | Entra audit log | Issue + page security lead |
| Conditional Access policy changed or disabled | Entra audit log | Issue |
| MFA method removed for an admin | Entra audit log | Issue |
| Break-glass account sign-in | Entra sign-in log | Page security lead |
| Mass deletion or resource lock removed in production | Azure Activity log | Issue |
| Key Vault purge or access policy change | Azure Activity log | Issue |
| Risky sign-in (if Entra ID P2) | Identity Protection | Issue |
| Backup job failure | Azure Backup | Issue (also caught daily by azure_backup) |
| Capacity thresholds (CPU, storage, DB DTU) | Azure Monitor metrics | Engineering on-call |

Route alerts to an action group that calls a small Logic App or webhook to open a GitHub issue
labeled `grc,incident-candidate`, so triage is evidenced (CC7.3).

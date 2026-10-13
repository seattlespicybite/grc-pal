# Policy set

Policies are Markdown files in this folder. A change is made by pull request; the executive
sponsor's approval on the PR is the approval record (GOV-01). Every policy carries the header
from `TEMPLATE.md`. Staff read the published copy and acknowledge it yearly (GOV-04).

| File | Policy | Owner | Main controls | Status |
| --- | --- | --- | --- | --- |
| information-security-policy.md | Information Security Policy (objectives, roles) | security-lead | GOV-01, GOV-06 | to draft |
| acceptable-use.md | Code of Conduct and Acceptable Use (incl. AI tools) | hr-lead | GOV-04 | to draft |
| access-control.md | Access Control | security-lead | IAM-01 to IAM-09 | to draft |
| data-classification.md | Asset Management and Data Classification | it-lead | AST-01 to AST-03, DAT-01 | to draft |
| encryption.md | Encryption and Key Management | engineering-lead | CRY-01 to CRY-03 | to draft |
| change-management.md | Change Management and SDLC | engineering-lead | CHG-01 to CHG-05 | to draft |
| vulnerability-management.md | Vulnerability Management | security-lead | VUL-01 to VUL-03 | to draft |
| logging-monitoring.md | Logging and Monitoring | security-lead | LOG-01, LOG-02 | to draft |
| incident-response.md | Incident Response Plan and notification | security-lead | IR-01 to IR-04 | to draft |
| business-continuity.md | Business Continuity and Disaster Recovery | engineering-lead | BCP-01 to BCP-04 | to draft |
| risk-management.md | Risk Management | security-lead | RSK-01, RSK-02 | to draft |
| vendor-management.md | Vendor Management | security-lead | VEN-01 to VEN-03 | to draft |
| hr-security.md | Human Resources Security | hr-lead | HR-01 to HR-04, GOV-05 | to draft |
| physical-security.md | Physical Security | it-lead | VEN-04 | to draft |
| data-retention.md | Data Retention and Disposal | legal-lead | DAT-02, DAT-03 | to draft |
| endpoint.md | Endpoint and Mobile Device | it-lead | END-01, END-02 | to draft |
| privacy.md | Privacy | legal-lead | PRV-01 to PRV-06 | to draft |

Write each policy from what the organization actually does (discovery interviews). Every "must" is a
test the auditor will run, so check each one against a control in `catalog/controls.yaml`.

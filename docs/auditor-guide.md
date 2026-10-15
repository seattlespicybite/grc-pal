# Auditor guide: testing controls from GRC-pal evidence

## Access
The auditor gets the **Auditor** role in the GRC-pal portal (an Entra B2B guest account). The role is
read-only: controls, evidence, comments, overrides, the audit log and exports. Optionally the
auditor also gets **Storage Blob Data Reader** on the `evidence` container and read access to the
program repository for the audit period.

## Starting fieldwork: the cycle export
**Cycles and export > Export (.zip)** produces, for one audit period:

| File | Use |
| --- | --- |
| `uploads_and_reviews.csv` | Full population of evidence submitted in the portal, with uploader, time, SHA-256, reviewer, decision and note |
| `assignments.csv` | Every evidence request: control, assignee, due date, status, link to the previous cycle's request |
| `comments.csv` | Discussion on each request and file (comments cannot be edited or deleted) |
| `overrides.csv` | Admin acceptances with justification, expiry, author and revocation |
| `users.csv` | Who had which role, how they got it, when they were last seen |
| `policy_acknowledgments.csv` | Who acknowledged which policy version and when (with the policy hash) |
| `audit_log.csv` | Every change in the period, hash-chained |
| `control_definition_changes.csv` | Every version of a changed control definition, with author, reason and before/after |
| `calendar_occurrences.csv` | Every recurring activity due in the cycle (from the schedule, not from what was done), with the latest admin decision, performed date, who recorded it, when and why. Rows still marked "Needs decision" are activities nobody has recorded |
| `calendar_decisions.csv` | Every calendar decision, including ones later corrected (version and what it replaced) |
| `implementation_notes.csv` | Every version of each control's "How we meet this control" notes, with author and time; each save is also in the audit log with the SHA-256 of the text |
| `audit_chain_verification.json` | Result of recomputing the chain at export time |
| `control_status.json` | Control health at export time, including the computed status behind any override |
| `evidence/` | Every uploaded file |
| `MANIFEST.csv` | SHA-256 of every file in the zip |

## Where evidence lives
- `catalog/controls.yaml` lists each control, the criteria it supports, its owner and frequency,
  and the exact evidence source (`collector:`, `tool:`, `task:`, `git:`).
- Evidence container layout: `<source>/<UTC timestamp>/` with the artifacts (JSON and CSV) and a
  `manifest.json` listing every file's SHA-256, the control IDs, the collector code version
  (Git commit) and the workflow run URL.

## Integrity
- Portal uploads are stored in the same write-once container (`portal_upload/<run>/`), with the
  SHA-256 recorded on the upload row. Review decisions are stored as their own evidence runs
  (`portal_review/`), and so are overrides (`portal_override/`).
- The portal audit log is hash-chained: each record contains the hash of the previous one. The
  daily `portal_audit/` export contains the full log and a verification result, so any later
  alteration is detectable by comparing against the locked copy.
- The container has a locked time-based immutability policy: blobs cannot be modified or deleted
  during retention, including by administrators.
- Each manifest hash can be recomputed to confirm completeness and accuracy of the artifact.
- Collector code is version-controlled; the `collector_version` in each manifest identifies the
  exact code that produced the evidence.

## Populations and samples
| Control | Population source | Typical test |
| --- | --- | --- |
| CHG-01 changes | `github_changes/*/merged_changes.csv` (monthly runs cover the period) | Sample PRs; confirm independent approval and passing checks |
| IAM-03 new users | `entra_users/*/users.csv` (`created` within period) + access request issues | Sample joiners; match to approved request |
| IAM-04 leavers | HR leaver list + `leaver_reconcile/*/reconciliation.csv` | Sample leavers; confirm disabled within 24 hours |
| IAM-05 access reviews | `issues_export` task issues labeled `task:access-review` | Inspect each quarter's review, removals and approval |
| VUL-01 vulnerabilities | `github_vulns`, `prowler` runs | Sample findings; confirm remediation within SLA or exception |
| IR-02 incidents | `issues_export` issues labeled `incident` | Inspect handling records |
| Recurring tasks | `issues_export/*/grc_issues.json` | Confirm completion each period and approver sign-off |

## Daily evidence for continuous controls
Daily runs exist for each day of the period. Gaps (failed runs) are visible as manifests with
`status: error` and are tracked as deficiencies.

## Testing the portal's own controls
| Assertion | How to test |
| --- | --- |
| Only authorized people can access GRC-pal | `users.csv` against HR's active staff list; sample sign-ins in the audit log |
| Reviewers are independent of submitters | In `uploads_and_reviews.csv`, `uploaded_by` never equals `reviewed_by` (enforced by the application) |
| Exceptions are approved and time-limited | Every row in `overrides.csv` has a justification, an admin author and an expiry within 365 days |
| Records are complete and unaltered | `audit_chain_verification.json` is ok; spot-check daily `portal_audit` copies against the export |

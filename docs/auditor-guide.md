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
| `calendar_occurrences.csv` | Every scheduled month of every recurring activity in the cycle (from the schedule, not from what was done): scheduled and moved due date, status (Planned, Performed, Missed), past-due flag, performed date, who recorded it, when and the note |
| `calendar_decisions.csv` | Every change recorded on the calendar, including ones later corrected (version and the status it replaced) |
| `vendors.csv` | Vendor population (every status, including offboarded and not approved): tier, data access, internal owner's title, status, subservice flag, contract and report details, last and next review, onboarding approval date and a `data_shared_before_approval` flag |
| `vendor_reviews.csv` | Every onboarding check, annual review and offboarding in the cycle: who started, submitted and signed off, the owner's answers, checklist items with notes, open items accepted at sign-off with the reason, self-approval flag, questionnaire version sent, and the tier, report and report result at sign-off (column `opinion_at_signoff`, in the formal terms: unqualified, qualified, adverse, disclaimer) |
| `vendor_exceptions.csv`, `vendor_cuecs.csv` | Exceptions noted in vendors' reports with our response; CUECs mapped to our controls, both current and as frozen at each sign-off |
| `vendor_files.csv`, `vendor_files/` | Vendor reports, returned questionnaires and offboarding evidence uploaded in the cycle, with SHA-256 (these may be under NDA with the vendor) |
| `vendor_register_history.csv` | Every version of every vendor record with author and reason |
| `subservice_organizations.csv` | Vendors flagged as subservice organizations (carved out or inclusive), for the system description |
| `questionnaire_versions.csv` | Every version of the vendor security questionnaire, one row per question, with the SOC 2 criteria each question supports |
| `implementation_notes.csv` | Every version of each control's "Control Implementation" notes, with author and time; each save is also in the audit log with the SHA-256 of the text |
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
| GOV-01 policy approval | Document library **Register** (Excel export) + `doclib_approval/*/decision.json` + audit log `doclib.status.approved` | Sample policies; confirm the approved file's SHA-256 matches the decision record, the approver is not the uploader, `method` is `workflow` (named approver) or `direct` (admin backup, look for the note), and the approval falls before the policy took effect |
| VEN-01 new vendors | `vendors.csv` (onboarding approved in the period) + `vendor_reviews.csv` (kind onboarding) | Sample new vendors; confirm the onboarding check was approved before `start_date` (`data_shared_before_approval` is false) |
| VEN-02 vendor reviews | `vendors.csv` (critical and high, active) + `vendor_reviews.csv` (kind annual) + `vendor_files/` | Sample vendors; inspect the report (period within 12 months), our questionnaire, exceptions with responses and the CUEC mapping; confirm sign-off by someone other than the submitter |
| VEN-05 vendor offboarding | `vendors.csv` (status offboarded, `end_date` in the period) + `vendor_reviews.csv` (kind offboarding) | Confirm each checklist item has a note and evidence under `vendor_files/` |

Vendor contact details (names, emails, phone numbers, support links) are deliberately left out of the
export and of the auditor's view of the portal; the internal owner is shown by title only.

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

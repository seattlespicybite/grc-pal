# GRC-pal compared with commercial platforms, and the roadmap

Vanta and Drata are mature commercial compliance platforms with hundreds of integrations. GRC-pal
is a small open-source alternative for teams that want to own their program, their data and their
costs. This page is an honest map of what GRC-pal covers today. Commercial feature lists change
often; check the vendors' current sites before comparing.

## Feature map

| Capability (as commercial platforms describe it) | GRC-pal today | Notes |
| --- | --- | --- |
| Control library mapped to frameworks | ✓ SOC 2 and ISO/IEC 27001:2022 built in; custom frameworks; custom controls | Add frameworks as files or in the portal; controls are reused |
| Automated tests / integrations | ✓ Entra ID, Intune, Azure, AWS, Google Cloud, GitHub; Prowler, Maester, testssl; custom HTTP/TLS checks | Far fewer integrations; Google Workspace, Okta, Jira are roadmap items |
| Continuous monitoring dashboard | ✓ Daily control health, by category | |
| Evidence library | ✓ Write-once storage with hashes and full populations | Stronger tamper evidence than many hosted tools; you hold the data |
| Tasks and owners for manual controls | ✓ Requests with due dates, assignees, contributors | |
| Reminders and notifications | ✓ Email on assignment, upload, comment, review; reminder button; weekly overdue job | No Slack or Teams yet |
| Comments and collaboration on evidence | ✓ Threads on requests and files | |
| Audit periods | ✓ Cycles with carry-forward and last-cycle evidence | |
| Auditor access | ✓ Read-only role and one-click export with manifest | No dedicated auditor portal or request-list workflow yet |
| Policy management and acknowledgments | ✓ Policies as code (PR approval), versioned acknowledgments, reminders | No policy template library beyond samples |
| Access reviews | Partial: quarterly task with user populations from collectors | Campaign UI (reviewer per system, keep/remove decisions) is roadmap |
| Risk register | Partial: `registers/risks.yaml`, validated, linked to controls | Risk scoring UI and heat map are roadmap |
| Vendor risk management | Partial: `registers/vendors.yaml`, review tasks, subservice and CUEC fields | Vendor questionnaires and portal page are roadmap |
| Personnel / HR onboarding and offboarding | Partial: leaver reconciliation from HR export, Entra users | HRIS API connectors are roadmap |
| Device monitoring | ✓ via Intune collector | No own endpoint agent (by design) |
| Trust center for customers | Not yet | Roadmap: static public page generated from control status and approved documents |
| Security questionnaire automation | Not yet | Roadmap: answer library from controls and policies, AI-drafted with human approval |
| AI assistance | ✓ Per-control review and full mock audit ([ai-assistant.md](ai-assistant.md)) | Questionnaire answering is roadmap |
| Roles and permissions | ✓ Admin, contributor, auditor; enforced server-side | Custom roles and SCIM are roadmap |
| Audit trail of the platform itself | ✓ Hash-chained, verifiable, exported daily | |
| Multi-entity / multi-tenant | ✓ One instance per organization with strict isolation | Pooled tier is optional future work |
| Cost and lock-in | Free software (AGPL); you pay your own cloud usage; data in your storage account | Commercial tools are subscriptions; exports vary |

## Roadmap

Ordered by value to a team preparing for its first SOC 2 Type 2. Each item is designed so it
produces evidence an auditor can test.

**Next (0.2)**
1. **Access review campaigns**: per-system reviewer, populations from collectors, keep or remove
   decisions, completion tracking, export. (CC6.2, CC6.3)
2. **Slack and Microsoft Teams notifications** alongside email, with per-user preferences and a
   weekly digest.
3. **Restore command** for portal data from the daily export.
4. **Risk register UI** with likelihood and impact scoring, treatment owners and review cycle. (CC3)
5. **Vendor page** with review status, SOC 2 report expiry reminders and CUEC tracking. (CC9.2)

**Later**
6. **Trust center**: a static, public page of selected controls and documents, published from the
   portal with approval.
7. **Questionnaire assistant**: a library of approved answers linked to controls and policies; AI
   drafts answers for new questionnaires, a person approves each one, and approvals are logged.
8. **More collectors**: Google Workspace, Okta, Jira, Azure DevOps, multi-account AWS role chaining.
9. **Framework packs**: NIST CSF 2.0 and HIPAA Security Rule requirement files with mappings.
10. **SCIM provisioning and custom roles** for larger organizations.
11. **Malware scanning hook** for uploads (Defender for Storage or ClamAV sidecar).
12. **Control plane** for hosted use: signup, provisioning, billing (see [saas-architecture.md](saas-architecture.md)).

**AI features (all with human approval and an audit record)**
- Summarize the week's control health and deficiencies for leadership.
- Pre-check an upload against the evidence wanted ("is this the full period? is the approver visible?")
  and suggest a review note; the admin still decides.
- Draft policy updates from catalog changes.
- Map new framework requirements to existing controls.

Each AI feature will document the data it sends, where it is processed, the risk (data exposure,
wrong answers, prompt injection from uploaded files) and the review step, and will be off by default.

Want to help? Pick an item and open an issue to agree the design first.

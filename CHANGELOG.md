# Changelog

All notable changes are listed here. The project follows [semantic versioning](https://semver.org/).

## [Unreleased]

### Added
- **Security calendar** (`/calendar`, admins and auditors): every recurring activity from
  `catalog/tasks.yaml` with its due dates, in Year, Month and List views, plus the dates collectors and
  checks actually ran (hide them with one click). Only activities whose controls map to a framework in
  use (for SOC 2, an in-scope criterion) are shown, so Privacy or ISO-only activities stay hidden while
  they are off. Occurrences are computed from the schedule, so a missed scheduled job cannot lose one;
  occurrences due before the first audit cycle started are not shown.
- **Decisions, never automatic**: a past-due occurrence shows **Needs decision** until an admin records
  Performed (with the date), Performed late, Not performed (exception) or Not applicable (reason
  required for the last three). Decisions are append-only: a correction is a new version and the earlier
  one stays visible. Each is in the audit log (`calendar.decision`). Performed decisions count as task
  evidence for control status. New `calendardecisions` table, included in backups.
- Occurrence page: steps and expected evidence, linked controls with their implementation notes,
  evidence-guide links and the evidence uploaded during the occurrence's window, related requests and
  the decision history. Automated activity page: recent runs with Passed, Findings or Failed.
- Calendar CSV (`/calendar.csv`) and, in the cycle export, `calendar_occurrences.csv` (the population of
  scheduled activities in the cycle) and `calendar_decisions.csv` (every decision, including corrected
  ones). CSV cells starting with `= + - @` are prefixed with a quote.

## [0.2.0] - 2026-10-14 - SOC 2 focus

This release makes GRC-pal a SOC 2 Type 2 tool first. Other frameworks stay available but out of
the way until an admin turns them on.

### Added
- **Knowledge base** tab (`/kb`): one article per SOC 2 criterion with a section per point of focus:
  what the auditor tests, evidence standard, good examples, common mistakes, frequency and sampling.
  38 articles cover every Security, Availability and Confidentiality criterion and all 214 of their
  points of focus. Articles are YAML in `starter/kb/` (a program repository's `kb/` folder can replace
  one), plain text, shown escaped, and marked **Draft** until a reviewer is recorded.
  Linked from control pages (per point of focus), criterion pages and evidence requests.
  `grcpal validate` checks articles and warns about in-scope points of focus without guidance.
- **How we meet this control**: implementation notes on every control. Admins and the control's
  owner can edit; every save is a new version (earlier ones stay visible) and is recorded in the audit
  log (`control.note`, with version, length and SHA-256). New `controlnotes` table, included in
  backups. The cycle export adds `implementation_notes.csv`. Demo data includes sample notes.
- `grcpal backup keygen | create | verify`: one encrypted file (AES-256-GCM, authenticated chunks) with every
  table for every tenant, all evidence, the HR inbox and the published configuration. A manifest holds the
  SHA-256 of every file, row counts, app and schema versions, and the audit-chain check of each tenant.
  The backup key is separate from `GRCPAL_ENCRYPTION_KEY`, which is never written into a backup. Backups are
  recorded in each tenant's audit log (`backup.create`, `backup.complete`).
- `SCHEMA_VERSION` for the stored data model (recorded in backups; migrations follow).
- **Frameworks in use.** Admins turn frameworks on or off per organization (Frameworks page or
  `GRCPAL_FRAMEWORKS`; audited, at least one stays on). With one framework the portal shows only that
  framework; with several, a **Showing** switcher picks one or **All**. The switch is a display
  preference and never changes access. Mappings to frameworks that are off are kept.
- **SOC 2 view.** Criteria grouped into families (CC1-CC9, then the additional categories) with
  status bars and report scope; criterion pages with previous/next and how each control is evidenced
  from connected sources only.
- **Control navigation.** Control pages remember whether you came from a criterion or a filtered
  list: trail, **Back to** buttons, previous/next within the criterion, and the menu stays in place.
  Only known criterion IDs and list filter keys are accepted, so the links cannot point outside the portal.
- Controls list: SOC 2 family, criterion and evidence-type filters; one requirements column per
  framework shown.
- **Change people on a request.** Admins change the assignee, helpers, due date and instructions of
  open requests. Newly added people are emailed; removed people lose access; earlier uploads keep
  their uploader. Audited (`assignment.edit`).
- **Control library owner.** One admin alone can change control definitions, custom controls and
  custom frameworks. Handed over by the holder; any admin can assign it when nobody holds it;
  cleared when the holder stops being an admin. Audited.
- **Edit controls in the portal.** Owners (role and several named people), title, description,
  evidence wanted and framework mappings. Reason required, every version kept with before and after,
  reset to starter, coverage warning, flag when a release changes the starter text. History is in
  the auditor export and in backups (new tables `controledits`, `controlhistory`).

### Documentation
- README rewritten for what GRC-pal does today: SOC 2 view, frameworks in use, control library owner,
  request editing, backups, and three ways to deploy (VM with Python, Docker, Azure).
- Quickstart section 4 is now a full production VM guide: settings file, systemd service, Docker
  option, HTTPS, first sign-in, cron jobs for collection, recurring activities, reminders and backups.

### Changed
- **SOC 2 only by default.** An empty `GRCPAL_FRAMEWORKS` setting now means SOC 2 only (was: every
  framework). ISO/IEC 27001 keeps its data and mappings; turn it on from the Frameworks page.
  *Upgrade note:* an existing installation that left the setting empty and uses ISO 27001 should turn
  ISO 27001 back on (Frameworks page) or set `GRCPAL_FRAMEWORKS` to `soc2` and `iso27001`.
- **Starter scope** is Security, Availability and Confidentiality. Processing Integrity and Privacy
  move to `deferred_categories`; their controls stay in the catalog.
- Controls list hides controls that serve only deferred categories (count and **show** link
  displayed; choosing a deferred category shows them). Dashboard category tiles show in-scope
  categories only.
- DAT-03 (device and media disposal) now also maps to C1.2 (disposal of confidential information).
- Creating or changing custom controls and custom frameworks now needs the control library owner
  (was: any admin).

### Fixed
- Scheduled command-line jobs (`grcpal remind`, `grcpal tasks`) now send email with the settings saved
  on the Configuration page, like the portal does. Before, they used environment variables only, so
  reminders from cron could silently go to the console.
- The Docker image creates `/data` owned by the app user, so a volume mounted there (as in
  `docker-compose.yml` and the VM guide) is writable.
- `owner_emails` and `links` on custom controls are stored as JSON, so they also work with Azure
  Table storage.
- Email address check rewritten to run in linear time (a crafted value could make the old pattern slow;
  found by CodeQL). It now also rejects addresses such as `pat@.example.com` and local parts over 64 characters.
- Redirect targets are checked in one place: only paths inside the portal, never another host or
  scheme, backslashes or control characters.
- Signing in at `http://localhost:8000` was blocked as a cross-site request because `grcpal serve` records
  its address as `127.0.0.1`. `localhost`, `127.0.0.1` and `[::1]` now count as the same computer when the
  portal runs on a loopback address (same port and scheme); real host names must still match exactly.

## [0.1.0] - unreleased

First public release.

### Program engine
- 77 controls covering all 61 SOC 2 Trust Services Criteria and 285 points of focus, tagged to ISO 27001:2022
- 16 collectors (Entra ID, Intune, Azure, GitHub) plus Prowler, Maester and testssl.sh ingestion
- Write-once evidence store with SHA-256 manifests; control health report
- `grcpal init` starter kit with GitHub Actions workflows; `grcpal publish-config`

### Portal
- Three roles: admin, contributor (assigned or owned controls only), auditor (read-only)
- Users table with bootstrap admins, optional group mapping, automatic access for assignees and roles.yaml owners
- Cycles with carry-forward and last-cycle evidence on requests and controls
- Evidence requests, uploads (validated), review with segregation of duties, comments
- Email via SMTP, Microsoft Graph or console outbox: assignment, upload, comment, review, reminders
- Reminder button with deep links; weekly overdue reminders; monthly recurring tasks
- Policies with versioned acknowledgments
- Admin overrides with justification and expiry, scoped to the cycle
- Auditor export zip per cycle with SHA-256 manifest
- Hash-chained audit log with verification; JSON logs with request IDs
- Tenant isolation for records and evidence; demo mode

### Configuration, multi-cloud, frameworks, AI
- Configuration page with per-section help, Test without saving, Save and apply; secrets encrypted (AES-256-GCM)
- Opt-in Setup guide: deployment health, command builder, every integration with save, validate or skip
- Logs page: persisted system events with keyword, level, category and date filters, CSV export, retention
- AWS collectors (IAM, CloudTrail, S3, GuardDuty/Config/Security Hub/EBS) and Google Cloud collectors (IAM, logging, storage, firewall)
- Framework registry: SOC 2 and ISO/IEC 27001:2022 built in, file and portal-defined frameworks, coverage pages
- Custom controls for any framework with owners, expected evidence and reference links
- HTTP and TLS checks with assertions, encrypted secret headers and protection against internal-network requests; command checks from the reviewed repository only
- AI assistant: per-control review and full mock audit with Claude, OpenAI-compatible endpoints (Ollama, vLLM, Azure OpenAI) or an offline demo reviewer; results kept as evidence and accepted or dismissed by an admin
- Background jobs page; collection runs from the portal and a daily scheduled job

### Deployment
- Single Bicep template and `deploy.sh` for Azure Container Apps (scale to zero), scheduled jobs
- Docker image, Docker Compose quickstart, CI, CodeQL, Dependabot, release workflow for GHCR

### Local accounts (for a VM on an internal network)
- New default sign-in `GRCPAL_AUTH_MODE=local`: GRC-pal's own accounts with passwords stored as scrypt hashes
- Admins add people and get a one-time link (72 hours, also emailed) for the person to choose a password
- Forgot password by email (1-hour single-use link) and admin "Reset password" link as break-glass
- `grcpal create-admin` creates the first admin or restores access (local sign-in only), from the server
- Server-side sessions (8 hours), ended on sign-out, disable, role change and new password
- Auditor accounts have an access end date (default 90 days); access is refused after it in every sign-in mode
- "Contributor" is now shown as "Control owner" (stored value unchanged, no migration)
- Users CSV adds access end date and whether a password is set; Setup guide flags missing HTTPS
- Accepted for the internal proof of concept: no MFA or lockout yet (see docs/security.md)

### Development
- Catalog and framework YAML is parsed with libyaml's C safe loader when available (about 9x faster load,
  test suite ~40 s to ~16 s); still the safe subset, a test proves Python object tags are rejected
- pytest defaults to short tracebacks; CLAUDE.md maps each area to its test file

### CI and supply chain
- Actions pinned to commit hashes; per-job least-privilege permissions; checkout does not persist the token
- New checks on pull requests: dependency review, zizmor workflow security scan; CodeQL uses security-extended rules
- Release job runs in the `release` environment (maintainer approval) and uses the built-in `gh` CLI
  instead of a third-party release action
- Dependabot 7-day cooldown; CODEOWNERS for `.github/`, Dockerfile, `deploy/`, SECURITY.md

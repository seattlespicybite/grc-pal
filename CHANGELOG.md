# Changelog

All notable changes are listed here. The project follows [semantic versioning](https://semver.org/).

## [Unreleased]

No data model change.

### Added
- Document library, one document: a single **Details** card with an **✏ Edit** button that turns it into a
  form. The **document number** is now editable (it must stay unique; versions and history stay attached), and
  **owner and approver** are picked from active admins and control owners instead of typed text.
- Document library: type the **version number** written inside the file when uploading (or leave it empty for
  automatic numbering), and correct it with the pencil while the version is a draft or in review. Approved
  version numbers are locked. Changes are in the audit log (`doclib.version.label`).
- Document library: the **Template** section is a compact table (file name, uploaded, uploaded by) with an
  upload button, a pencil to rename a template (`doclib.template.rename`; the file and hash never change) and a
  bin to remove it, plus a **Removed templates** table with who removed each one, when, and a Restore button.
- Document library list: in **Edit list**, a pencil on each row changes the document's number and title in
  place. A new **Register** tab (admins and auditors) shows the master document list (owner, approver, current
  version, status, next review) with **Export to Excel**; exports are in the audit log.
- **Back button** at the top of every page. It works like the browser's Back button, so the previous page
  opens at the same scroll position. It appears only when the previous page was a page of this portal.
- Calendar: clicking a month or the **+** of an empty month opens a **small window on the calendar** to
  record it or add it; saving returns to the same row. The full page is still one click away.
- Calendar: when you untick a month, you can also **remove it from earlier months and years** where nothing
  was recorded. Recorded months always stay (they are evidence), and the change is in the audit log.
- Document library: **Edit list** lets admins tick documents and delete them (with an "Are you sure?" step).
  Deleted documents go to a new **Trash** page where they can be restored; their files are never destroyed.
- Document library: old templates can be **removed** from a document (to the Trash), so you can keep just one.
- Document library: the **description** of a document can now be edited, next to the title.
- Cycles: admins can **change the current cycle's name, start and end date** (Cycles and export > Change
  the current cycle; the dashboard links there). Before, the first cycle started on the day GRC-pal was
  first opened and could not be adjusted. Every change is in the audit log.
- **Automation alerts.** Admins are emailed when a collector or check fails (one email per new failed run, so a
  broken integration cannot go quiet). Optional **morning, weekly and monthly digests** summarize what worked,
  what failed and what did not run. Each admin chooses on Calendar > Email alerts. Sent after the daily
  collection; no new scheduled job.
- Vendors: **Not applicable** is now a choice for contract security terms and the data processing agreement.

### Changed
- Document numbers of documents in the Trash stay reserved, so restoring a document never creates two
  documents with the same number.
- Vendors: contract and DPA answers nobody has checked yet show as an empty choice instead of "Not checked".
- Vendors: "Auditor's opinion" is now **Report result** with plain choices (Clean, With exceptions,
  Unfavorable, No conclusion, Not applicable). Stored values and the auditor export keep the formal terms.
- Vendors: the "Date we started sharing data" field is no longer shown. Dates already saved are kept.

## [0.4.0] - 2026-10-19 - Refreshed look, grouped menu

No data model change (data model 1, as in 0.3.0).

### Changed
- **New look.** Icons in the menu, softer cards and status labels with a colored dot, light and dark themes
  that follow the computer's setting, and a readiness ring on the dashboard ("3 of 79 controls operating":
  operating plus accepted by admin, out of all controls in scope). Still no inline styles or scripts (strict
  CSP), and no new JavaScript.
- **Shorter, grouped menu.** Dashboard, My work and Reviews stay at the top; everything else sits in three
  groups that open with a click: **Compliance** (criteria, controls, calendar, vendors, access reviews,
  overrides, cycles and export, AI assistant), **Evidence & docs** (evidence store, policies, document
  library, knowledge base) and **Configuration** (frameworks in use, settings, setup guide, backups,
  updates, logs, audit log, users and roles, email outbox in development). The group holding the current
  page opens by itself; a closed group shows its count (past-due calendar items, open access reviews). Who
  sees which page did not change, and the server still checks every page and action. The Configuration
  page is now listed as **Settings** in the Configuration group. Built with the browser's own `<details>`
  element, so it works with the keyboard and without JavaScript.
- `AGENTS.md` (Jules and other agents) and `GEMINI.md` (Gemini CLI) point to `CLAUDE.md`, which stays the
  single source of the repository rules, plus rules for working with several AI tools (one branch and pull
  request per task, no pushes to `main`, no weakened tests).

## [0.3.0] - 2026-10-17

### Added
- **Access review campaigns** (menu: Access reviews; control IAM-05, SOC 2 CC6.2 and CC6.3). Managers review the accounts of their own people across every application on one screen. An admin uploads a CSV of accounts exported from any system, including accounts that are not in Entra ID, plus an optional people file (email, manager_email). The import is refused as a whole if any row is wrong. Each account goes to its manager; accounts with no manager, service accounts and accounts whose manager is the account holder wait for an admin to assign a reviewer, and nobody can review their own account. Managers choose keep, remove or change per account, see risky accounts first (admin-type role, no MFA, no sign-in for 90+ days, disabled but listed, service account), and sign off, which locks their decisions until an admin reopens it. Admins confirm each removal with how it was done, then close the review; closing stores the decisions file write-once with a SHA-256, next to the stored copy of the uploaded list. Admins and auditors can download the decisions as a formula-safe CSV. Every step is in the audit log without names or addresses. New tables `arcampaigns` and `arentries` (no migration needed). See [docs/access-reviews.md](docs/access-reviews.md).
- **Document library** (menu: Document library). An Explorer-style repository for the whole policy hierarchy:
  53 built-in Word templates (the umbrella policy and 13 topic policies as full templates with a "How it is
  tested" column; 13 standards, 20 procedures and 6 SOC 2 documents as skeletons), written without any
  organization name. Admins download a template, adapt it and upload it as the **official version**
  (major/minor numbering, an optional product/variant label, draft, in review, approved, superseded, archived);
  approval needs a second admin; every old version is kept and downloadable. A template can be **replaced**
  by uploading your own (history kept, built-in restorable), titles and owners can be changed (the document
  number stays), and admins can add their own documents. Staff see only approved versions; auditors see
  everything read-only. Files are write-once with SHA-256 and every action is in the audit log. New tables
  `docs` and `docversions` (no migration needed); `python-docx` joins the `dev` extra to rebuild templates
  with `python tools/build_doc_templates.py`.

### Security
- **Vendor contact details are never shown to auditors**: removed on the server, left out of the export, and
  contact changes and vendor emails are written to the audit log without names or addresses. Vendor files can
  only be downloaded by admins, auditors and that vendor's owners, are not in the evidence review queue and
  are never sent to AI. Control owners cannot change who owns a vendor. Links must start with https://.
- **Spreadsheet formula injection blocked in the cycle export.** Every CSV cell that starts with = + - @ is
  now written as text (this was only done for the calendar CSV before).
- **Azure backup check every 15 minutes** (was hourly; `backupCheckCron`): still one scheduled backup a day,
  and "Back up now" starts within about 15 minutes. A check that finds a backup still running skips, so a
  long backup is never made twice.
- **Old Azure backups are removed** by a storage lifecycle rule after `backupRetentionDays` (35); before,
  write-once backups were never deleted and storage grew forever. The Backups page keep settings apply to
  folder locations (VMs) only; docs corrected.
- **Delete lock** on the storage account (`lockStorage`, on by default).
- **Sign-in session lasts 8 hours** (`sessionHours`), after which Entra ID and Conditional Access check the
  user and device again.
- **Alerts** with `deploy.sh --alert-email`: no successful backup in 2 days, and changes to locks, role
  assignments, write-once policies or sign-in settings.
- `grcpal backup run-due` prints one JSON line (`"event": "backup.run_due"`) so logs and alerts can read it.

### Added
- **Vendors page (SOC 2 CC9.2).** A vendor register in the portal, imported once from `registers/vendors.yaml`
  (every original field kept). Each vendor has a tier, data access, status, subservice flag, contract and
  report details, an internal owner and backup (name, title, email, phone), the vendor's contract contact,
  and how to open a support ticket or request their SOC 2 report or questionnaire. One review a year; the tier
  decides what it needs. The owner uploads the report or returned questionnaire and answers four questions; an
  admin records exceptions, maps CUECs to our controls and signs off (never a review they submitted while
  another admin is active; open items need a written reason). Onboarding and offboarding checklists (new
  control **VEN-05 Vendor offboarding**). Reminders 30 days before a review and while overdue, through the
  existing weekly `grcpal remind --overdue` job. A row on the security calendar. Demo data included.
- **Security questionnaire.** An editable vendor questionnaire (47 starter questions in 10 sections, mapped to
  SOC 2 criteria) with drafts, numbered versions, moving questions across sections, and an Excel download
  (locked questions, answer and comment columns, Yes/No/N/A lists) written with the standard library.
- **Auditor export:** `vendors.csv`, `vendor_reviews.csv`, `vendor_exceptions.csv`, `vendor_cuecs.csv`,
  `vendor_files.csv` with the files, `vendor_register_history.csv`, `subservice_organizations.csv` and
  `questionnaire_versions.csv`.
- **Updates page: newer releases with "Do I need it?"** Lists every release newer than yours from GitHub's
  public release list (checked at most every 12 hours, nothing about the instance is sent, SSRF-guarded,
  links limited to github.com; off with `GRCPAL_UPDATE_CHECK=off`, and on VMs only when downloads are allowed).
  Each release shows security, fixed, added and changed counts from its notes and a plain advice line; a
  banner appears when a newer release has security fixes. `update.sh --status` prints the same list.
- **Live update progress.** The VM updater reports a percentage and step; the Updates page shows a progress
  bar and the step list, polling `/updates/progress` (admins only) and reconnecting while the portal
  restarts. The Azure updater prints `[NN%]` before each step in the workflow log.
- **Calendar: one-off months.** Click **+** in an empty month of a manual activity to add it for that month
  only (audited as `calendar.occurrence.add`); the regular schedule does not change.
- **Calendar: arrange rows.** Drag and drop rows within Manual or Automated, or use the ↑ ↓ buttons; the order
  is saved for everyone and audited (`calendar.order`). New activities go to the bottom.
- **VM installs (Debian 13 minimal + Docker)**: `deploy/vm/install.sh` installs only docker.io, Caddy
  (HTTPS), nftables (firewall: SSH, HTTP, HTTPS), unattended-upgrades and Python's cryptography from Debian,
  keeps all data in `/var/lib/grcpal`, runs the portal as a non-root, read-only container on 127.0.0.1, and
  sets up systemd timers for the jobs, the hourly backup runner and the monthly update check. It installs from
  a version, from an offline update file, or rebuilds from a backup and recovery kit. Guide:
  `docs/deploy-vm.md`. The Python and plain Docker setups are now for trying GRC-pal and development only.
- **Signed update files** (`.grcupdate`): the image plus an Ed25519-signed manifest, built by the release
  workflow when the `GRCPAL_UPDATE_SIGNING_KEY` secret is set; the release also carries the VM installer kit.
- **VM updater** (`grcpal-update`, runs on the host, never inside the app): the running version checks the
  signature and checksum; mandatory checked backup; trial of the new version on a copy of the data; switch;
  health gate (portal answers; data model, audit chains, evidence hashes, no table lost rows); automatic
  rollback of image and data; the last two versions are kept. Patch releases install during the monthly
  check, feature and major releases after **Approve**. An optional second backup location (for example a
  network share) is mounted when `GRCPAL_BACKUP_DIR_2_HOST` points to a folder outside `/var/lib/grcpal`.
- **Updates page** (Administration → Updates, admins): installed version, data model, waiting update with
  release notes, Approve, automatic patches and downloads on or off, history. On VMs, **Restore this
  backup** on the Backups page (typed confirmation; a safety backup first, today's data kept aside). The portal
  only leaves requests; the updater checks them again. Audited: `update.approved`, `update.policy_requested`,
  `restore.requested`, plus the updater's `update.applied`, `update.trial_failed`, `update.rolled_back`,
  `restore.completed`.
- **Azure updates** (`deploy/azure/update.sh` and the program repository's monthly `grcpal-update.yml`
  workflow): image pinned by digest with a build provenance check, backup with the current version, trial of
  the new version on a copy of the tables (`grcpal update trial`), new revision with no traffic, health gate
  (`/healthz` and `grcpal update selftest-saved`), then traffic moves; `--rollback` returns to the revision
  labelled `previous`. Patch releases only on the schedule; feature and major releases need a person to run
  the workflow with the version. The updater identity is usable only from the repository's `grcpal-update`
  environment and may change only the container app and its jobs.
- **Azure backups**: a `backups` container with time-based write protection (35 days by default), a backup
  key secret kept across re-deployments, and an hourly backup job. `deploy.sh --restore-from FILE --kit KIT`
  builds a new instance from a backup. `grcpal backup restore NAME` also finds a backup by name in the
  instance's backup locations.
- **Edit the calendar in the portal**: add, edit, retire and delete activities; tick the months they are
  due, the due day (1st, 15th or last day) and any number of linked controls at once. Schedule edits apply
  from the current month on (versioned in the new `calendarversions` table); past months never change.
  Delete only works while nothing is recorded. All changes are in the audit log.
- **Move a due date** for one month; the original date stays on record.
- **22 new starter activities** in `catalog/tasks.yaml` (40 in total): monthly security meeting minutes,
  vulnerability scan review, joiner/leaver and change ticket samples, alert and incident log review,
  deficiency register review and newsletter; quarterly privileged access, guest user, roles, asset,
  credentials, phishing, firewall and new-vendor reviews; annual objectives, system description, data
  inventory, incident plan, retention, configuration baseline and continuity plan reviews. Tasks can now
  list `controls` and a `due_day` directly.
- Performed calendar activities count as evidence for their linked controls' status.
- **Restore**: `grcpal backup restore FILE` checks the whole backup first and writes nothing unless it is
  intact, then fills an empty instance or a new folder (`--into`); it never overwrites data. Files are
  re-hashed as they are written. A backup from a newer data model is refused. Each tenant's audit chain
  continues with a `backup.restore` record.
- **Recovery kit**: `grcpal backup kit --out FILE` writes the backup key and the app key
  (`GRCPAL_ENCRYPTION_KEY`) to one owner-only file for a password manager; `restore --kit FILE` uses it.
  `grcpal backup keygen` now creates `keys/backup.key` next to the database by default.
- Backups of SQLite installs are read from a point-in-time copy, so rows written during a backup never
  mix in.
- The first-run sign-in page shows the restore command next to `create-admin`.
- **Backups page** (Administration → Backups, admins only): back up now, daily or weekly schedule,
  retention (7 daily, 4 weekly, 12 monthly, 3 before updates; never the newest verified one), every
  backup checked right after it is written, Check and Download per backup, recovery kit download with a
  reminder banner. Locations come from server settings (`GRCPAL_BACKUP_DIR`, optional second location,
  Azure container), never from the browser. Works only when the instance holds one organization.
  Every action is audited (`backup.requested`, `backup.schedule`, `backup.download`, `backup.verify`,
  `backup.kit_export`, `backup.retention_delete`).
- `grcpal backup run-due`: the hourly runner for the schedule and queued requests (VM timer, Azure job).
- **Safe data model upgrades**: numbered, additive migrations (`grcpal/migrations.py`) run once each when
  the portal starts or with `grcpal migrate`, recorded in every audit log (`system.migration`). Migrations
  never get access to evidence. An older version refuses to start only on data it can no longer read.
  Restoring an older backup upgrades it right away.
- **Upgrade test in CI**: installs the previous release, loads demo data and a backup made with it, upgrades
  to the new code and checks every row, evidence file and audit chain is unchanged, the portal starts and the
  old backup restores. The release workflow checks the version rules (data model changes only in minor or
  major releases).
- **Security calendar** (`/calendar`, admins; auditors get it in the cycle export): every recurring activity from
  `catalog/tasks.yaml` with its due dates on one year page, plus the dates collectors and
  checks actually ran (hide them with one click). Only activities whose controls map to a framework in
  use (for SOC 2, an in-scope criterion) are shown, so Privacy or ISO-only activities stay hidden while
  they are off. Occurrences are computed from the schedule, so a missed scheduled job cannot lose one;
  occurrences due before the first audit cycle started are not shown.
- **Decisions, never automatic**: a past-due occurrence stays **Past due** until an admin records
  Performed (with the date) or Missed (note required); nothing is marked automatically. Decisions are append-only: a correction is a new version and the earlier
  one stays visible. Each is in the audit log (`calendar.decision`). Performed decisions count as task
  evidence for control status. New `calendardecisions` table, included in backups.
- Occurrence page: steps and expected evidence, linked controls with their implementation notes,
  evidence-guide links and the evidence uploaded during the occurrence's window, related requests and
  the decision history. Automated activity page: recent runs with Passed, Findings or Failed.
- Calendar CSV (`/calendar.csv`) and, in the cycle export, `calendar_occurrences.csv` (the population of
  scheduled activities in the cycle) and `calendar_decisions.csv` (every decision, including corrected
  ones). CSV cells starting with `= + - @` are prefixed with a quote.

### Changed
- **Every update is manual by default.** VM: automatic patch installs are off unless an admin turns them on.
  Azure: the scheduled workflow run (now weekly, Mondays) only lists newer releases in its summary; an update
  installs only when someone runs the workflow with a version.
- **30-day rollback window.** Pre-update backups (Backups page retention) and the VM's pre-update data copies
  are kept for at least 30 days, in addition to the newest ones.
- Calendar rows are grouped only into **Manual** and **Automated**.
- **Security calendar redesigned** as one year page for admins (activities on the left, months on the
  right). Month and List views are gone; auditors get the calendar through the cycle export.
- Statuses are now **Planned** (amber **Past due** after the due date), **Performed** (with the date) and
  **Missed** (note required) for manual activities, and **Passed**, **Findings**, **Failed**, **Not run**
  for automated ones (latest run of the month). Earlier "performed late" records show as Performed and
  "not performed" or "not applicable" as Missed.
- Azure Container Apps now runs in multiple-revision mode (needed for checked updates).
- `deploy.sh` never changes the running version: without `--image` it keeps the image that is running, or
  uses this checkout's version for a new instance (instead of `:latest`).

### Fixed
- **Calendar: months you tick now show up straight away**, including months earlier in the year (a new
  activity for March, or extra months added to the vendor review in October, appeared only next year).
  Unticking a month still never removes one that has already passed, so a missed activity cannot vanish.
- **Calendar: activities you create are never hidden** by the scope filter (one linked only to an
  out-of-scope control disappeared). Starter and automated activities for out-of-scope areas stay hidden.
  The control picker marks out-of-scope controls.
- A backup made by an older version (without tables added since, such as the calendar) failed `verify` and
  could not be restored. Found by the new upgrade test.
- `sessions` and `account_links` (local sign-in sessions and one-time setup/reset links) were missing from
  the table registry, so Azure Table Storage never created them, and `account_links` was not a valid Azure
  table name. Both are now registered (Azure names drop underscores) and are deliberately never backed up:
  restoring them would revive old sign-ins and used links. A test now fails if code uses an unregistered table.

### Docs
- README: quick guide for deploying, backing up and updating (VM and Azure), the security calendar and
  safe updates in the feature list, current counts (40 recurring activities), all backup, migrate and
  updater commands, and the VM guide in the documentation table. Unreleased changelog regrouped.
- Conditional Access runbook (phishing-resistant MFA, compliant device, group assignment, guests):
  `docs/deploy-azure.md`, Step 3b. Lock both write-once containers in Step 6. Why private endpoints and
  Key Vault are not in the template yet: `docs/security.md`.

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

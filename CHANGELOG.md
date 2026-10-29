# Changelog

All notable changes are listed here. The project follows [semantic versioning](https://semver.org/).

## [Unreleased]

## [0.6.0] - 2026-10-29 - Automation page, access review pulls, calendar links, security hardening
Security hardening release from the internal assessment of the Azure deployment (batches B1, B2, B3 and the CI
security scan; findings F-01, F-02, F-04, F-05, F-10, F-11 and B-3). This was an internal assessment with
automated scanning, not an independent penetration test.

No data model change.

**Before you upgrade (action may be needed):**
- **Azure:** nothing to do if you deployed with the template (it sets `GRCPAL_ENV=production`, your tenant in
  `GRCPAL_ALLOWED_TENANT_IDS` and `GRCPAL_TRUSTED_PROXY_HOPS=1`). Custom deployments in easyauth mode must set
  `GRCPAL_ALLOWED_TENANT_IDS`, or the portal refuses to start. After the upgrade run checks V-1 and V-2 in
  [docs/deploy-azure.md](docs/deploy-azure.md).
- **Proxy mode (VM with oauth2-proxy or Caddy):** set `GRCPAL_PROXY_SECRET` and have the proxy send it as
  `X-GRCPAL-Proxy-Secret`, or the portal refuses to start.
- **Self-hosted AI models or GitHub Enterprise Server on a private network:** set `GRCPAL_AI_ALLOW_PRIVATE=1` /
  `GRCPAL_GITHUB_ALLOW_PRIVATE=1`, or those calls are refused.
- **Backups:** in production the web page no longer downloads backup files or the recovery kit; use
  `grcpal backup ...` or the backup job (`GRCPAL_WEB_BACKUP_DOWNLOAD=on` brings the buttons back).
- **Anything that used `GRCPAL_AUTH_MODE=dev`** (demo containers, test setups) must also set `GRCPAL_ENV=dev`.

### Security
- **Authorization test suite** (`tests/test_authz.py`, table in `tests/authz_matrix.py`): every route of the app, in
  both sign-in modes, is called as each kind of caller (not signed in, admin, Control owner, other Control owner,
  auditor, expired auditor, disabled admin). Allowed roles must get through and change data; refused roles must be
  refused and change nothing (no table row, evidence file or email). It also checks object-level access (IDs of
  other people's controls, vendors, reviews, documents), a second admin who is not the library owner, two
  organizations in one store, CSRF on every POST, and download headers. A route that is not in the table fails
  the suite.
- `GET /cycles/{id}/export` now sends the same sandbox CSP and sanitized file name as every other download.
- `POST /vendors/new` without a name returns a message instead of a server error.
- Editing a custom control that does not exist is refused instead of creating it (the "already exists" check
  was skipped on that path).
- **Break-glass sign-in on Azure.** `deploy/azure/breakglass.sh` (`set-password`, `arm`, `disarm`, `status`)
  opens password sign-in for the break-glass account when Microsoft sign-in to GRC-pal is broken. `arm` starts a
  revision with local sign-in and a closing time, moves traffic there and only then turns Easy Auth off; `disarm`
  turns Easy Auth on first, so a forged identity header is never believed. On Azure, local sign-in accepts only
  the break-glass account, requires its two-step code, refuses "Forgot password", closes by itself at
  `GRCPAL_BREAK_GLASS_UNTIL` (at most 24 hours; a missing or bad value means closed) and ends its sessions then.
  Each break-glass sign-in is a security event, is marked in the audit log and is emailed to every admin.
  `update.sh` refuses to run while break-glass is open.
- `grcpal create-admin --two-step` sets up two-step sign-in on the server (always on Azure).
- **Easy Auth only on Azure.** In `easyauth` mode the portal now refuses to start unless it runs on Azure
  Container Apps or App Service (`CONTAINER_APP_NAME` or `WEBSITE_SITE_NAME` is set by the platform). Anywhere else
  nothing removes a caller's `X-MS-CLIENT-PRINCIPAL` header, so anyone could forge one and sign in as anyone.
  Docker or VM installs use `local` or `proxy`.
- **Entra sign-ins in the audit log.** Each new Easy Auth or proxy sign-in session is recorded once as
  `auth.signin` (method, client address and, for Entra, the object and tenant ID), so GRC-pal keeps its own
  sign-in evidence beyond Entra's log retention (7 days on Entra ID Free). Only a hash of the session cookie is
  stored. Refused sign-ins stay security events on the Logs page.
- `Cross-Origin-Resource-Policy: same-origin` on every response: other sites cannot embed portal responses.
- **Conditional Access collector checks device compliance** (AST-02, also IAM-02): a finding when no enabled
  policy requires a compliant or hybrid-joined device. A policy that accepts MFA *or* a compliant device does
  not count, because MFA alone would let an unmanaged laptop in.
- **Local sign-in hardening (hardening batch B6; findings F-03, F-06, F-07, F-08, F-13, F-16).** These apply to
  local accounts (VM installs and the break-glass admin); Azure Easy Auth sign-in is governed by Entra.
  - **Lockout with growing waits.** After 5 failed sign-ins for one account, or 20 from one address, within
    15 minutes, sign-in is locked for 1 minute, then 2, 4, 8 and at most 15 for each further failure. A locked
    sign-in is refused before the password is checked, the answer is the same for real and unknown accounts,
    and each lock is a security event on the Logs page. A successful sign-in clears the account's count.
  - **Password checks are capped.** At most 4 password hashes run at once (`GRCPAL_MAX_PASSWORD_CHECKS`); others
    wait up to 5 seconds and then get "busy, try again", so a flood of sign-ins cannot exhaust memory or CPU.
  - **Optional two-step sign-in** with an authenticator app (6-digit codes, RFC 6238), set up from the new
    **Two-step sign-in** link in the sidebar. Recommended for admins. Codes work once; wrong codes count towards
    the lockout. An admin can remove it for someone who lost their phone (Users and roles), and
    `grcpal create-admin` on the server clears it. The key is stored encrypted. No new dependency.
  - **Password links keep their token out of the address path.** Emailed links now look like
    `/account/password#...`: the part after `#` never reaches the server, a proxy or a log. The page swaps it,
    once, for a password form that works for 15 minutes. Links emailed before the upgrade still work.
  - **"Forgot password" is limited and refused for admins.** At most 3 emails per account and 10 requests per
    address per hour. Admins and the break-glass account can no longer reset by email (ask another admin for a
    link, or use `grcpal create-admin` on the server); the attempt is a security event. The page answers before
    any lookup or email is done, so neither its text nor its timing shows whether an account exists.
  - **Request size limit.** Bodies larger than the upload limit plus 5 MB (30 MB by default,
    `GRCPAL_MAX_BODY_MB`) are refused with 413 before they are read.
  - New table `signinlimits` (not backed up, like sessions). No migration.
- **Outbound endpoint controls (hardening B3, F-11).** AI provider, GitHub (connection test and collector client)
  and Microsoft Graph connection-test calls now go through the same guard as custom checks: public addresses
  only, every redirect re-checked, cloud metadata and private ranges blocked. Credential headers are dropped when a
  redirect leaves the original host (this also applies to custom checks). Self-hosted models and GitHub Enterprise
  Server on a private network need `GRCPAL_AI_ALLOW_PRIVATE=1` / `GRCPAL_GITHUB_ALLOW_PRIVATE=1` in the
  environment. **Upgrade note:** an existing `http://ollama:11434/v1` setup needs `GRCPAL_AI_ALLOW_PRIVATE=1`.
- **Secrets follow their server.** Changing the AI endpoint, the GitHub API URL or the SMTP server on the
  Configuration page clears that section's secret unless a new one is entered in the same save, and blocks a
  deployment-provided secret (such as the Azure SMTP password) for the new server. "Test without saving" does not
  send the saved secret to a changed address.
- **Configuration changes are emailed to every admin**, the person who saved included, and the audit entry lists
  cleared secrets and new endpoints (names and addresses only, never secret values).
- **Entra accounts are linked at first sign-in.** On Azure (easyauth) each person's Entra object ID and tenant
  are stored the first time they sign in; the same email from another Entra account is refused and logged as a
  security event until an admin clicks **Unlink Entra account** on Users and roles. In production the tenant
  allow-list (`GRCPAL_ALLOWED_TENANT_IDS`) is now required; the Azure template already sets it.
- **Proxy mode needs a shared secret.** `GRCPAL_AUTH_MODE=proxy` now requires `GRCPAL_PROXY_SECRET` (32+
  characters), which the proxy sends as `X-GRCPAL-Proxy-Secret`; a request that reaches the app without it is
  refused, so nobody can claim to be someone by sending `X-Forwarded-Email` directly. **Action for proxy users:**
  set the secret on both sides before upgrading (examples in docs/configuration.md).
- **Request logs name the person and hide password-link tokens.** Every request line now carries the signed-in
  `actor` (it was always "-"), and `/account/password/<token>` is logged as `/account/password/[redacted]`.
- **Backup files and the recovery kit are no longer downloadable from the web page in production.** One stolen
  admin session could take every record plus the keys that open them and the saved integration credentials.
  Operators get the kit on the command line: `grcpal backup kit` (VM) or the new `deploy.sh --kit-out FILE`
  (Azure; `deploy.sh` no longer prints the encryption key). `GRCPAL_WEB_BACKUP_DOWNLOAD=on` brings the
  downloads back, and each one is then emailed to every admin. Backing up, checking and restoring are unchanged.
- **Caller addresses can no longer be forged.** The container trusted every `X-Forwarded-For` header, so the
  address a client typed in was recorded in sign-in events and the audit log. Now only the address added by
  our own proxy counts (`GRCPAL_TRUSTED_PROXY_HOPS`, set to 1 by the Azure template and the VM installer), and
  request log lines carry it as `ip`.
- **Development sign-in fails closed.** `GRCPAL_AUTH_MODE=dev` now needs `GRCPAL_ENV=dev` (or `development`) set
  explicitly; before, only `GRCPAL_ENV=production` refused it, so a missing variable left a password-free
  sign-in open. `grcpal serve --demo` sets it and refuses a non-local `--host` unless `--insecure-demo` is given.
  **Action:** if you run dev mode outside `grcpal serve --demo` or Docker Compose, set `GRCPAL_ENV=dev`.
- Custom application tokens are encrypted per organization and application, never shown, logged or audited, and only sent
  to that application's host: no redirects, next-page links must stay on the same host, internal and metadata addresses
  are blocked. `Clients.gh_list(..., complete=True)` raises instead of silently returning a partial list.
- GRC-pal now reads one kind of uploaded spreadsheet (the control matrix). The reader in `grcpal/xlsx.py` is
  standard library only and refuses large or zip-bomb files, DOCTYPE and entities, formulas and password-protected
  files; it opens only the workbook, shared text and worksheet parts.

New tables `arapps`, `matriximports` and `vendorimports` (no migration needed). No other data model change.
- **Session hygiene (hardening batch B5).**
  - In production every GRC-pal cookie is `Secure` and uses the `__Host-` prefix (`__Host-grcpal_session`,
    `__Host-grcpal_view`), so only this exact HTTPS host can set or read it. Cookies from before the upgrade are
    accepted once and replaced, so nobody is signed out by the change.
  - Form tokens are tied to the sign-in session as well as the person (the local session, the Azure Easy Auth
    session cookie, or the proxy's session cookie). A token copied from another session is refused, and every
    sign-in starts a new session and new tokens. Signing in also ends the session the browser had before.
  - Local accounts: admin sessions end after 30 minutes without activity (`GRCPAL_ADMIN_IDLE_MINUTES`).
    Admins signed in before the upgrade for more than 30 minutes sign in once more.
  - Local accounts: **Sign out** is a form post with a token (`POST /logout`); `GET /logout` no longer signs
    anyone out, so a link or image on another site cannot.
- **Entra accounts are linked at first sign-in.** On Azure (easyauth) each person's Entra object ID and tenant
  are stored the first time they sign in; the same email from another Entra account is refused and logged as a
  security event until an admin clicks **Unlink Entra account** on Users and roles. In production the tenant
  allow-list (`GRCPAL_ALLOWED_TENANT_IDS`) is now required; the Azure template already sets it.
- **Proxy mode needs a shared secret.** `GRCPAL_AUTH_MODE=proxy` now requires `GRCPAL_PROXY_SECRET` (32+
  characters), which the proxy sends as `X-GRCPAL-Proxy-Secret`; a request that reaches the app without it is
  refused, so nobody can claim to be someone by sending `X-Forwarded-Email` directly. **Action for proxy users:**
  set the secret on both sides before upgrading (examples in docs/configuration.md).
- **Request logs name the person and hide password-link tokens.** Every request line now carries the signed-in
  `actor` (it was always "-"), and `/account/password/<token>` is logged as `/account/password/[redacted]`.
- **Backup files and the recovery kit are no longer downloadable from the web page in production.** One stolen
  admin session could take every record plus the keys that open them and the saved integration credentials.
  Operators get the kit on the command line: `grcpal backup kit` (VM) or the new `deploy.sh --kit-out FILE`
  (Azure; `deploy.sh` no longer prints the encryption key). `GRCPAL_WEB_BACKUP_DOWNLOAD=on` brings the
  downloads back, and each one is then emailed to every admin. Backing up, checking and restoring are unchanged.
- **Caller addresses can no longer be forged.** The container trusted every `X-Forwarded-For` header, so the
  address a client typed in was recorded in sign-in events and the audit log. Now only the address added by
  our own proxy counts (`GRCPAL_TRUSTED_PROXY_HOPS`, set to 1 by the Azure template and the VM installer), and
  request log lines carry it as `ip`.
- **Development sign-in fails closed.** `GRCPAL_AUTH_MODE=dev` now needs `GRCPAL_ENV=dev` (or `development`) set
  explicitly; before, only `GRCPAL_ENV=production` refused it, so a missing variable left a password-free
  sign-in open. `grcpal serve --demo` sets it and refuses a non-local `--host` unless `--insecure-demo` is given.
  **Action:** if you run dev mode outside `grcpal serve --demo` or Docker Compose, set `GRCPAL_ENV=dev`.
- Custom application tokens are encrypted per organization and application, never shown, logged or audited, and only sent
  to that application's host: no redirects, next-page links must stay on the same host, internal and metadata addresses
  are blocked. `Clients.gh_list(..., complete=True)` raises instead of silently returning a partial list.
- GRC-pal now reads one kind of uploaded spreadsheet (the control matrix). The reader in `grcpal/xlsx.py` is
  standard library only and refuses large or zip-bomb files, DOCTYPE and entities, formulas and password-protected
  files; it opens only the workbook, shared text and worksheet parts.

New tables `arapps`, `matriximports` and `vendorimports` (no migration needed). No other data model change.

### Added
- **Automation page** (admins, Compliance > Automation): every connection, collector and custom check in one place.
  Each platform card shows its connection status, what you need to connect it and a link to its settings form; each
  collector shows Passed, Findings, Failed, Overdue (no run in 36 hours), Never run, Not set up or Off, its last run
  and the controls it feeds. **Verify** runs one collector without saving anything and shows the files, record
  counts, field names, API calls and findings it would produce, to check the connection and the data before
  relying on it. **Run once** saves a real write-once run now; **Run them once now** catches up every overdue
  collector. Both are recorded in the audit log, and portal runs now record `trigger`, `triggered_by` and the API
  call provenance in the manifest, like scheduled runs.
- **Calendar and controls link both ways.** Each control page has a **Schedule** card (admins only) with the
  linked calendar activities: cadence and months, last recorded month and result, next due date, months past due,
  and links to the exact calendar month or run history. The calendar's popup lists the controls an activity covers.
  Clicking anywhere in a date field opens the date picker, and the picker icon is now visible in dark mode.
  **Last cycle** on the control page is folded by default.
- **Daily account pulls for access reviews.** Every night after `collect --all` (or `grcpal access-pull`, or **Pull now**),
  each access review application with an API source is read and stored write-once as `access-<application>` evidence:
  the full account list, what changed since the last good pull, and the request addresses. A failed pull is stored as a
  failure and alerted like a collector. New **Accounts** page (admins, auditors read-only) with flags, including accounts
  not found in Entra ID, and the pull history. A review started within 24 hours of a pull uses that stored list.
- **Setup guide covers the whole program setup.** Eight new steps, each a checklist of what is done and what
  is missing with links to the page where the work is done: **audit period** (cycle dates set by an admin),
  **control owners** (controls without an owner, control library owner), **backups** (location, schedule, a
  recent backup, recovery kit exported), **updates** (policy chosen on a VM; how updates arrive elsewhere),
  **email alerts** (email tested, admins receiving failure alerts), **access reviews** (applications added and
  tested), **vendors** (register not empty) and **calendar and policies** (recommendations). These steps turn
  Done by themselves when their checks pass; **Continue** no longer marks an unfinished step done. The finish
  page lists them under **Program setup**. The welcome step lists what to have at hand.
- **Certificate sign-in to Microsoft** (`GRCPAL_MS_AUTH=certificate`, recommended on a VM) and
  `grcpal ms-cert`, which creates the certificate (private `.pem` readable by you only, public `.cer` for the app
  registration, thumbprint and expiry printed). A certificate pasted on one line is rebuilt.
- The Microsoft connection test also checks **GroupMember.Read.All** (access reviews).
- **Security scanning in CI** (`.github/workflows/security-scan.yml`, on every pull request, nightly and on demand):
  bandit (medium and high, with a reviewed baseline of false positives), pip-audit on everything the image ships,
  a Trivy scan of the built image that fails on high or critical vulnerabilities with a fix, a CycloneDX SBOM kept
  as a build artifact, and nightly a ZAP baseline scan of a demo container signed in as the demo admin (fails on
  any High alert). Scanners are pinned by version and SHA-256 and run with read-only permissions. See
  [docs/security.md](docs/security.md#security-scanning-in-ci).
- **Vendors: import from CSV, add only.** Upload a CSV (template on the page); GRC-pal shows every row compared
  with the register (new, already there with the differences, similar name, problem) and adds only the rows
  you tick. Nothing in the register is changed or deleted. Imported vendors are Active and never reviewed;
  their first reviews can be spread over 12 months, critical first. The file is kept write-once as evidence;
  the import, the rows picked and every vendor added are audited.
- **Vendors without SOC 2 or ISO 27001.** Each onboarding check and annual review records an assurance level
  (independent audit, evidence reviewed, self-attested, none). Critical and high vendors without an audit get
  13 baseline controls to assess with proof, a written risk acceptance by the business owner (with an end date,
  at most 12 months) when self-attested or a control is not met, and a 6-month review interval. A second
  questionnaire, **Small vendor essentials** (18 questions asking for proof), sits next to the full one.
- **Offboarding: Entra ID sign-in check.** Vendors can list their Entra ID apps and email domains. During
  offboarding, **Check now** reads the latest `entra_apps` and `entra_users` runs for apps still enabled and
  enabled accounts (guests included) from those domains, and ticks "Sign-in removed" when nothing is left.
- Auditor export: `vendor_baseline.csv`, `vendor_risk_acceptances.csv`, `vendor_imports.csv`, and assurance,
  questionnaire and sign-in check columns in `vendor_reviews.csv`.
- **Access reviews read the accounts themselves** (Access reviews > Applications). Admins list each in-scope application
  once and choose its source: Microsoft Entra ID / Microsoft 365 (users, guests, last sign-in, MFA, admin roles, license),
  an Entra enterprise (SSO) application (assigned users, groups expanded; refused when “assignment required” is off), Azure
  role assignments (groups expanded, service principals and deleted identities listed), a GitHub organization (owners,
  members, outside collaborators, two-factor status), a **custom application's REST API** (URL, token, paging, field map;
  ready-made settings for monday.com and WorkOS), GRC-pal itself, or a CSV. Starting a review reads the chosen
  applications in the background and takes managers from Entra ID direct reports; if one application cannot be read
  completely, nothing is created. Accounts without a manager go to the application owner, never to the account holder.
  An identity map per application links accounts without a work email (GitHub logins) to people. A Test button shows
  counts only. The reviewed list is stored write-once as `population.csv` (its SHA-256 is the review's), next to each
  source's accounts. New table `arapps` (no migration needed). Microsoft Graph permission **GroupMember.Read.All** is
  added to `deploy/azure/grant-permissions.ps1`; run it again before reviewing applications or Azure access granted to groups.
- **Control matrix: export, bulk edit and import back.** **Controls > Control matrix** downloads a data file
  (.xlsx, one row per control, a column per framework switched on). The control library owner edits it and
  uploads it: a **preview** shows every change (old and new) and every problem before anything is saved, then
  **Apply** (with a reason) or **Discard**. Rows go through the same rules as **Edit control** and **New
  control**, so each change has its own history version and audit entry. New IDs create custom controls,
  Status `retired` retires a custom control, and rows left out of the file are never deleted. Files from
  another organization, rows changed in GRC-pal after the download (conflicts) and changes made between the
  preview and the apply are refused. The uploaded file and the result are kept as write-once evidence
  (`control_matrix_import/`, `control_matrix_apply/`). Admins and auditors can download; only the library
  owner imports.
- **Control matrix report** for leadership and auditors: every control with description, owners, mappings,
  points of focus and evidence, plus a cross-reference per framework. Print or save as PDF from the browser,
  or download Word (.docx). Written with the standard library, no new dependency.
- **Updates page manual check**: Admins can manually trigger an update check with the **Check for updates** button, receiving immediate confirmation of whether newer releases are available or the instance is up to date, protected by a request cooldown.
- **Tenant installation verification**: Added **Verify installation** on the Updates page to validate the signed-in tenant's data model version, audit log hash chain, and evidence digests via a background job.
- **Activity log table**: Enhanced the Updates page history table with status indicators and audit log fallback.

### Changed
- **Clear result when a backup finishes.** The job page now shows a green "Backup completed" or red "Backup failed"
  banner, and pops up the result once when the job has just ended. A backup that was written but failed its
  verification is shown as a problem, not a success. The same applies to backup checks and other jobs.
- **Vendor edits: the reason for the change is optional.** Every change is still saved as a new version and
  written to the audit log with who, when and which fields changed. Offboarding still needs a reason.
- **Vendor page: "Who to call" is now "Internal contact".**
- **Document library register fits wide screens better:** smaller text, tighter cells, and folder and people
  names wrap instead of widening the table. Other tables are unchanged.
- The deployment step points to the VM installer instead of a sign-in proxy for running outside Azure.
- **Evidence integrity.** Every evidence run now also gets `SHA256SUMS` (check with `sha256sum -c`) and
  `manifest.sig`, an Ed25519 signature of `manifest.json` with a key derived from the instance's encryption key
  (or `GRCPAL_EVIDENCE_SIGNING_KEY`). The manifest's SHA-256 is recorded in the hash-chained audit log
  (`evidence.sealed`), so a rewritten run is caught even by someone holding the signing key.
- `grcpal evidence verify` (hashes, signature, audit-log record; exit code 1 on failure) and
  `grcpal evidence public-key`. Each evidence run page shows an **Integrity** card; admins and auditors can
  download the public key.
- Collector runs record provenance: each API call with its request or query, record count, pages, request ID
  and the app registration used.
- The auditor export adds `evidence_run_verification.csv` and `evidence_signing_key.pem`.
- Uploads named `manifest.json`, `manifest.sig` or `SHA256SUMS` are refused (reserved names in the evidence store).

No data model change. Runs collected before this release show as **Legacy** (file hashes still checked).
- **Evidence uploaded by an admin is approved on upload.** Admins own the program and upload evidence that
  is already approved, so a second review made no sense, and with a single admin the upload stayed
  "pending" forever with nobody able to approve it. Admin uploads now require an approval note (who
  approved it and when) and are recorded as approved on upload: the decision is write-once evidence, the
  audit log and the auditor export (`uploads_and_reviews.csv`) carry `approved_on_upload`, and no review
  emails are sent. Evidence from Control owners still waits for review by any admin. Admin uploads left
  pending from before can be approved on **Reviews** or the control page with an approval note.
  No data model change (the new field is read with a default).

### Fixed
- **Evidence names in the built-in catalog are no longer cut short.** Four entries had an unquoted comma that YAML
  treats as the end of the name (GOV-01 "Policy approval history (PR", GOV-05 "Case log (sampled", GOV-07 and the AWS
  security services control), so the control page, control matrix report and data file showed a truncated name.
- **ISO 27001 clause references in the catalog match the ISO framework file** (`Clause9.3`, not `Clause 9.3`; six
  controls). With ISO switched on, saving one of those controls or importing the control matrix failed with
  "unknown requirement".
- New tests: every catalog evidence entry has a whole name and only `artifact`/`via`; every `iso27001:` reference
  exists in the framework file.
- **SQLite reads take the store lock.** On VM installs (SQLite) every request shares one database connection;
  reads ran without the lock that writes use, so pages loaded at the same moment as a save could fail. Azure Table
  Storage was not affected.
- **No false "data is lost on restart" warning on VM installs.** The startup warning and the Setup guide's
  "Portal data storage" item now flag SQLite only when the file really is temporary (in memory, under `/tmp`, or a
  relative path inside the container), not the VM installer's persistent `/data/grcpal.db`.
- **Program repository knowledge articles and frameworks now reach Azure portals.** `grcpal publish-config`
  sent only `catalog/`, `registers/` and `policies/`, so your own `kb/` articles and `frameworks/` files worked
  on a VM (local folder) but were silently ignored on Azure. The bundle now carries `kb/` and `frameworks/` too.
  No data model change.

## [0.5.0] - 2026-10-20 - Document approvals, signed VM updates

First release whose VM installer carries the update-signing key and ships a signed `.grcupdate` file.
VM installs should start from 0.5.0 (0.4.0's installer has no signing key).

No data model change.

### Fixed
- After an update, some browsers (seen in Brave) kept an old copy of the stylesheet and showed the new pages with
  icons as huge black shapes. Stylesheet and script links now carry a version tag taken from the file's
  contents (`/static/app.css?v=...`), so browsers fetch the new file as soon as it changes.

### Added
- **Document approval workflow.** **Send for approval** emails the document's named approver with a link and puts
  an item in their **My work**. On the review page they confirm they read the version and **Approve**, or **Send
  back** with a reason. The approver can never be the uploader or sender; control owners who approve see only the
  version waiting for them. Admins can **Reassign** or **Withdraw** a request; reminders go out every 7 days with
  the daily scheduled run. **Approve directly** stays as the admin backup and is recorded as a direct approval.
  Every decision is in the audit log (`doclib.approval.*`, `doclib.status.approved` with `method`) and kept as
  write-once evidence (`doclib_approval`, GOV-01).
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
- Document versions: "In review" is now **Waiting for approval** and is reached only through Send for approval.
  The old "Send to review" button is gone. A version left in review from before can be withdrawn and sent again.
- Document page: the versions table is narrower (product and size are shown under the version and file name).
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

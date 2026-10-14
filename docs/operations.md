# Operating GRC-pal

What the security admin does each day, month and year, and how to keep the instance healthy.

## Routine

| When | What happens automatically | What you do |
| --- | --- | --- |
| Daily | Collectors run, evidence is stored, deficiency issues open or update, the portal records and the verified audit log are exported to write-once storage | Glance at the dashboard; fix or assign red controls |
| On upload | Admins and the request's people are emailed | Review under **Reviews** (approve, or return with a note) |
| On comment | Everyone on the request is emailed | Reply in the thread |
| Weekly (Monday) | Overdue requests get a reminder (job `remind`) | Escalate anything overdue twice |
| Monthly (1st) | Recurring control tasks open as requests (job `tasks`) | Check they reached the right people |
| Monthly | | Show the dashboard to the executive sponsor (management review evidence) |
| Quarterly | | Access review of GRC-pal itself: download **Users and roles > CSV**, confirm each person, disable leavers |
| Yearly | | Start the next cycle; re-justify overrides; publish policy updates and ask for acknowledgments |

## Requests, reminders and comments

- **Assign** from a control page (or a point of focus) with a due date and clear instructions:
  which system, which period, what format. The instructions appear in the email and on the request.
- **Remind** with the button on a control or request. The email links straight to the control and
  includes the description, the evidence wanted, what was submitted this cycle and last cycle's
  evidence. Each person gets at most one reminder per control every 12 hours; the result says who
  was skipped.
- **Comments** are permanent (no editing or deleting), which is what makes them usable as
  evidence of review. Keep personal or sensitive data out of them.

## Cycles

A cycle is one audit period. Start a new one under **Cycles and export**:

1. Download the export of the cycle you are closing and hand it to the auditor, or keep it.
2. Start the new cycle with **carry-forward** on. Every request that was not cancelled is copied
   with the same people and instructions and a due date at the same point in the new period.
3. Each carried request links to last cycle's request, files and comments, so people can repeat
   what worked.
4. Overrides do not carry over. Re-justify any that still apply.

Closed cycles are read-only.

## Overrides

Use an override when good evidence exists but the automated check cannot see it (for example a
manual process documented in a ticket). It needs a justification of at least 30 characters and an
expiry within a year, applies to the current cycle only, and is stored as locked evidence. The
dashboard shows the control as *Accepted by admin* and keeps the computed status visible.

## Policies

Policies are Markdown files in your program repository's `policies/` folder (see
`policies/TEMPLATE.md`). Changing one is a pull request; the approval is the approval record.
After merge, the portal shows the new version and acknowledgments start again for that version.
Use **Email a reminder** on the policy page to chase people who have not acknowledged.

## Audit log integrity

Every change is a record chained to the previous one by SHA-256. Check it any time with
**Audit log > Verify integrity** or `grcpal audit verify`. The daily export puts a verified copy in
write-once storage; a later edit or deletion in the database is then provable. A failed check is a
security incident: preserve the evidence and investigate who had storage access.

## Logs page

**Administration > Logs** lists the events that matter for troubleshooting and audits: sign-in
refusals, first sign-ins, configuration saves and connection tests, collector and check runs, email
failures, AI requests (never their content), jobs, exports and unexpected errors with their
reference. Filter by keyword, level, category and period; tick *Include audit trail* to merge in the
hash-chained audit records; download as CSV. Secrets are scrubbed before anything is stored.

## Logs and tracing

The portal writes one JSON object per line (timestamp, level, request ID, user, tenant, path,
status, duration). Every error page shows a reference; search it in Log Analytics:

```kusto
ContainerAppConsoleLogs_CL
| where Log_s has "<reference>"
| project TimeGenerated, Log_s
```

The same request ID is stored on audit records, so you can go from a log line to the exact change.

## Backups and recovery

| Data | Protection |
| --- | --- |
| Evidence | Write-once container with locked retention, soft delete, geo-redundant storage by default |
| Portal data (tables) | Daily JSON and CSV export to the write-once evidence container by the `portal_audit` collector, plus the full backup file below |
| Catalog, registers, policies | Git history of your program repository |
| Configuration | `deploy/azure/main.bicep` and the deployment parameters; re-run `deploy.sh` |

### Full backup file

`grcpal backup` writes one encrypted file (`.grcbak`) with everything needed to rebuild the
instance: every portal table for every tenant (users, settings, control monitoring, checks,
frameworks, audit log), all evidence, the HR inbox and the published configuration. Docker and VM
installs have no other copy of their data, so take one regularly.

```bash
grcpal backup keygen --key-file backup.key          # once; store the key outside the instance
grcpal backup create acme-2026-10.grcbak --key-file backup.key
grcpal backup verify acme-2026-10.grcbak --key-file backup.key
```

- **Two keys, kept apart.** The backup key encrypts the file. `GRCPAL_ENCRYPTION_KEY` (which protects
  saved integration secrets) is never put in a backup; keep it too. Losing the backup key makes the
  backup unreadable. Losing the app key only means re-entering integration secrets after a restore.
  The key can also come from the `GRCPAL_BACKUP_KEY` environment variable; it is never accepted on
  the command line, so it stays out of shell history.
- **Tamper-evident.** The file is AES-256-GCM in authenticated chunks. Any changed, reordered or
  missing byte makes `verify` fail. Its manifest holds the SHA-256 of every file and the
  audit-chain check of each tenant.
- **Recorded.** Each tenant's audit log gets `backup.create` (inside the backup) and
  `backup.complete` (with the file's SHA-256), so you can match a file to its audit record.
- **Private by default.** The file is created with owner-only permissions and an existing file is
  never overwritten.
- **Consistency.** Take backups at a quiet time (for example right after the nightly collection).
  Rows written during a backup may be in the file or not; evidence is write-once, so nothing
  already stored can change.

Restoring into a clean instance (`grcpal backup restore`) is the next step on the roadmap. Until
then, `verify` proves the file is complete.

Once a year, check recoverability: run `grcpal backup verify` on a recent backup, open the latest
`portal_audit` export and confirm it has every table and that `audit_chain_verification.json` says `"ok": true`; redeploy a test instance with
`--name acme-restore` to confirm the template still deploys.

## Upgrades

Pin a version: set the image tag (`--image ghcr.io/seattlespicybite/grc-pal:0.2.0`) and the
`GRCPAL_VERSION` repository variable to the same release. Read the CHANGELOG first. Upgrades never
rewrite stored evidence; data model changes are additive.

## Local administration

With `GRCPAL_TABLES_URL` (and `az login` as someone with *Storage Table Data Contributor*):

```bash
grcpal users list
grcpal users add new.admin@acme.com --role admin
grcpal remind --overdue --dry-run
grcpal audit verify
grcpal export --cycle fy2026 --out fy2026.zip
```

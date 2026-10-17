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
grcpal backup keygen                          # once: creates keys/backup.key next to the database
grcpal backup kit --out recovery-kit.json     # once: put this file in a password manager, then delete it here
grcpal backup create acme-2026-10.grcbak
grcpal backup verify acme-2026-10.grcbak
```

- **Recovery kit.** One small file with the backup key and `GRCPAL_ENCRYPTION_KEY` (the app key that
  protects integration credentials saved in the portal). With a backup file and the kit, a clean machine
  can be rebuilt. Keep it in a password manager or safe, never next to the backups. Making a kit is
  recorded in the audit log (`backup.kit_export`).
- **Where the key comes from.** `--key-file`, `--kit`, the `GRCPAL_BACKUP_KEY` environment variable
  (Azure: a Container Apps secret), or `keys/backup.key` next to the database. A key is never accepted
  on the command line, so it stays out of shell history. The app key is never put in a backup.
- **Tamper-evident.** The file is AES-256-GCM in authenticated chunks. Any changed, reordered or
  missing byte makes `verify` fail. Its manifest holds the SHA-256 of every file and the
  audit-chain check of each tenant.
- **Recorded.** Each tenant's audit log gets `backup.create` (inside the backup) and
  `backup.complete` (with the file's SHA-256), so you can match a file to its audit record.
- **Private by default.** The file is created with owner-only permissions and an existing file is
  never overwritten.
- **Consistent.** On VMs the database is read from a point-in-time copy (SQLite online backup), so
  rows written during a backup never mix in. Evidence is write-once, so nothing already stored changes.
- **Not included on purpose:** sign-in sessions and one-time setup/reset links. After a restore,
  everyone signs in again with their existing accounts.

### Backups page (admins)

**Administration → Backups** does the same without a command line:

- **Back up now** to any configured location. On a VM it runs at once (see Background jobs); on Azure
  it is queued for the backup job and starts within about 15 minutes, because the portal scales to zero.
- **Schedule**: every day (default 02:00 UTC), every Sunday or off. Keeps 7 daily, 4 weekly and
  12 monthly backups plus the last 3 made before updates; older ones are removed after each new
  backup, but never the newest one that passed its check. On Azure these keep settings do not
  apply: backups are write-once, so each is kept `backupRetentionDays` (default 35) and then removed by
  the storage lifecycle rule.
- Each backup shows where it is (the path on the server), its size and whether it passed its check.
  **Check** re-verifies it; **Download** saves a copy (recorded in the audit log).
- **Recovery kit**: a banner asks for it until an admin has downloaded it once.
- The page works only when the instance holds one organization (one instance per customer). With more,
  whole-instance backups stay on the command line, so no admin can download another organization's data.

Locations are set on the server, never typed in the browser:

| Setting | Meaning |
| --- | --- |
| `GRCPAL_BACKUP_DIR` | Folder for backups (default: `backups/` next to the database) |
| `GRCPAL_BACKUP_DIR_HOST` | What that folder is called on the host, shown on the page (Docker) |
| `GRCPAL_BACKUP_DIR_2`, `_LABEL`, `_HOST` | Optional second location, e.g. a mounted network share |
| `GRCPAL_BACKUP_CONTAINER` | Azure: blob container for backups (default `backups`) |
| `GRCPAL_BACKUP_KEY` / `GRCPAL_BACKUP_KEY_FILE` | The backup key (Azure secret) or its file; on a VM it is created on first use |

The schedule runs from `grcpal backup run-due`, called every hour by the VM timer or every 15 minutes
by the Azure backup job. Each call only checks: it makes at most one scheduled backup per day (or week)
and starts any queued "Back up now". If a backup is still running, the next check skips, so a long
backup is never made twice. It prints one JSON line (`"event": "backup.run_due"`), which the Azure
backup alert looks for.

### Restore

Restore checks the whole file first and writes nothing unless it is intact. It only fills an
**empty** instance or a **new folder**, so it can never overwrite live data.

```bash
# rebuild a clean machine (fresh install, before anyone signs in)
grcpal backup restore acme-2026-10.grcbak --kit recovery-kit.json
# or restore into a separate folder, e.g. to inspect a recovery point
grcpal backup restore acme-2026-10.grcbak --kit recovery-kit.json --into /var/lib/grcpal/restore-test
```

- Before starting GRC-pal on the new machine, set `GRCPAL_ENCRYPTION_KEY` to the kit's `settings_key`.
  If you don't, restore warns you and integration credentials must be entered again.
- A backup made by a newer GRC-pal is refused; install that version (or newer) first.
- Each tenant's audit log continues the restored chain with a `backup.restore` record (backup ID, file
  SHA-256, version it came from). `grcpal audit verify` shows one unbroken chain.
- If an audit log inside the backup does not verify, restore stops. `--accept-audit-problems`
  restores anyway and records that you chose to.

### Yearly restore test

Once a year (and after a major update), prove that a backup restores. Keep the output as SOC 2 A1.3 evidence.

1. Pick a recent scheduled backup on the Backups page and click **Check** (it must pass).
2. Restore it somewhere that is not production:
   - VM: `sudo grcpal backup restore /backups/<file>.grcbak --into /data/restore-test` and save the JSON it
     prints (row counts, files, audit chains), then delete `/var/lib/grcpal/data/restore-test`;
   - Azure: `./deploy/azure/deploy.sh --name acme-restoretest --admins you@acme.com --restore-from <file> --kit
     recovery-kit.json`, sign in, spot-check a few controls and evidence files, then delete the resource group
     `rg-grcpal-acme-restoretest`.
3. Write down the time it took (your recovery time) and the backup's age (your recovery point), and add
   both with the JSON to the evidence for your continuity control.

### Disaster recovery runbook

| Event | Recovery | Expected loss |
| --- | --- | --- |
| A bad update | Nothing to do: it rolls back by itself. To go back later: VM `sudo grcpal-update rollback`; Azure: the update workflow with **rollback** | None |
| Data deleted or changed by mistake | VM: Backups page → **Restore this backup** (today's data is kept aside). Azure: rebuild a new instance from the backup | Changes since that backup |
| VM lost or its disk damaged | New Debian 13 VM, then `install.sh ... --restore <file> --kit recovery-kit.json` ([deploy-vm.md](deploy-vm.md#rebuild-on-a-new-vm)) | Since the last off-VM copy |
| Azure resource group or region lost | `deploy.sh --name <new> --restore-from <file> --kit recovery-kit.json` ([deploy-azure.md](deploy-azure.md#rebuild-from-a-backup)) | Since the last backup copied outside that storage account |
| Recovery kit lost | Download a new one from the Backups page while the instance still runs. Backups made with the old key still need the old kit | None while the instance runs |

What to keep where: backups on a second location (network share, other storage); the recovery kit in a
password manager; the installer kit or this repository at the version you run.

## Upgrades

Updates are applied by the updater of each deployment, never by hand: on a VM from the Updates page or a
signed update file ([deploy-vm.md](deploy-vm.md#updates)), on Azure by the update workflow (run with a version) in your program
repository ([deploy-azure.md](deploy-azure.md#updates)). Both back up first, try the new version on a copy of
the data, check it before users get it, and roll back by themselves. Read the CHANGELOG before approving a
feature or major release, and keep the repository variable `GRCPAL_VERSION` (used by your program
repository's collector workflows) on the version you run.

### What an update may change

| Release | Example | Data model | Going back to the previous version |
| --- | --- | --- | --- |
| Patch (0.2.1) | Bug and security fixes | Never changes | Start the previous image |
| Minor (0.3.0) | Features, design changes | Only adds (new fields, rows, tables) | Start the previous image: it still reads the data |
| Major (1.0, 2.0) | Larger changes | May clean up what an earlier release announced | Restore the backup taken before the update |

- **Evidence is never changed by an update.** Migrations only get the table store.
- **Migrations run when the portal starts** (and on `grcpal migrate`), in order, once each. Each one is
  recorded in every organization's audit log (`system.migration`) and in the instance's data model
  history. `grcpal migrate --check` shows the version and anything pending.
- **An older version refuses to start only when it can no longer read the data** (after a major
  update), with a message saying to start the newer version again or restore the pre-update backup.
- **CI proves it on every change:** it installs the previous release, loads demo data, takes a backup
  with it, upgrades to the new code and checks that every row, every evidence file and every audit
  chain is unchanged, that the portal starts, and that the old backup restores
  (`deploy/ci/upgrade_check.py`). The release workflow refuses a tag that breaks the version rules.

## Local administration

With `GRCPAL_TABLES_URL` (and `az login` as someone with *Storage Table Data Contributor*):

```bash
grcpal users list
grcpal users add new.admin@acme.com --role admin
grcpal remind --overdue --dry-run
grcpal audit verify
grcpal export --cycle fy2026 --out fy2026.zip
```

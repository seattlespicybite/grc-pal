# Deploy GRC-pal to Azure

About an hour end to end, most of it waiting. The result is one GRC-pal instance for one
organization, in its own resource group.

| Created | Purpose | Typical cost |
| --- | --- | --- |
| Storage account (delete lock) | Evidence and backups (both write-once), portal data (tables), your published catalog | Cents per GB per month |
| Container App + 4 scheduled jobs | Portal (scales to zero), daily collection, weekly reminders, monthly tasks, backup check every 15 minutes (one backup a day) | Usually within the Container Apps monthly free grant |
| Log Analytics workspace | App logs, 30 days, capped at 0.5 GB per day | A few dollars at most |
| Alerts (with `--alert-email`) | Missed backups; changes to locks, roles, write-once policies, sign-in settings | Cents per month |
| Managed identities | Portal and (optional) GitHub collectors; no stored keys | Free |
| Entra app registration | Sign-in | Free |

Check current Azure pricing for your region before committing; the free grants change.

## Before you start

- An Azure subscription where you are **Owner** (or Contributor plus User Access Administrator).
- An Entra ID role that can create app registrations (**Application Administrator** or higher).
- Azure CLI 2.60 or later, signed in: `az login`.
- Optional: GitHub CLI (`gh auth login`) so the script can set repository variables for you.

## Step 1. Create your program repository

```bash
pip install "grc-pal @ git+https://github.com/seattlespicybite/grc-pal"
grcpal init acme-grc --org "Acme Inc"
cd acme-grc
```

Edit two files:

- `catalog/scope.yaml`: organization name, in-scope categories, platforms.
- `catalog/roles.yaml`: for each role, the person's name and **work email** (the email they sign
  in with). These people get contributor access to the controls their role owns.

Then `grcpal validate`, commit, and push to a **private** GitHub repository.

## Step 2. Run the deployment script

From a clone of the GRC-pal repository:

```bash
./deploy/azure/deploy.sh \
  --name acme \
  --admins you@acme.com \
  --require-assignment \
  --alert-email security@acme.com \
  --github-repo acme/acme-grc \
  --location eastus2
```

Add `--what-if` first if you want to preview the changes. The script:

1. creates the resource group `rg-grcpal-acme`;
2. creates the Entra app registration **GRC-pal (acme)** and a sign-in secret (valid one year);
3. deploys `deploy/azure/main.bicep`: storage, identities, logs, the portal, the jobs and (with
   `--alert-email`) the alerts;
4. sets the sign-in redirect URL;
5. sets the GitHub repository variables your workflows need (or prints them).

It prints the portal URL at the end.

> Prefer clicking? `deploy/azure/azuredeploy.json` is the same template for the Azure portal's
> *Deploy a custom template* page. You then create the app registration yourself and pass its
> client ID and secret as parameters.

## Step 3. Sign in

With `--require-assignment`, first do items 1 and 2 of Step 3b (group and assignment, with yourself in
the group), or Entra ID will refuse your own sign-in. Then open the portal URL and sign in with the email
you passed to `--admins`. You are an admin.

- Add people under **Users and roles**, or simply assign work: assignees get contributor access
  automatically. Auditors are added with the **Auditor** role (as Entra B2B guests).
- Only accounts from your Entra directory can sign in (`GRCPAL_ALLOWED_TENANT_IDS`). With
  `--require-assignment`, only people or groups assigned to the enterprise app can even get a token.
  Add Conditional Access next.

## Step 3b. Allow only your staff, on managed devices (Conditional Access)

Sign-in happens in Entra ID before any request reaches GRC-pal, so Conditional Access (CA) decides
who gets in. This needs Entra ID P1 (included in Microsoft 365 E3/E5 and Business Premium) and Intune
for device compliance.

1. **One group.** Create a security group, e.g. `GRC-pal users`, and add the people who use the
   portal, yourself included.
2. **Assign it.** Entra admin center → Enterprise applications → **GRC-pal (acme)** → Users and
   groups → Add assignment → the group. With `--require-assignment`, anyone not assigned is refused
   by Entra ID itself (AADSTS50105) and never reaches the portal.
3. **Create the policy.** Entra admin center → Protection → Conditional Access → New policy:

   | Setting | Value |
   | --- | --- |
   | Name | `GRC-pal: phishing-resistant MFA + compliant device` |
   | Users | Include: `GRC-pal users`. Exclude: *Guest or external users*, and your two emergency (break-glass) accounts |
   | Target resources | Select resources → **GRC-pal (acme)** |
   | Grant | Grant access, **Require authentication strength: Phishing-resistant MFA** and **Require device to be marked as compliant**, with **Require all the selected controls** |
   | Session | Sign-in frequency: 8 hours (match `sessionHours`) |
   | Enable policy | **Report-only** first |

   Guests (auditors) use their own laptops, which cannot pass "compliant device", so they are
   excluded above and get a second policy: same target app, Users = *Guest or external users*, grant
   **Require multifactor authentication** (phishing-resistant if their home directory supports it),
   sign-in frequency 8 hours. Keep them on the Auditor role (read-only, with an end date).
4. **Test in report-only for a few days.** Entra → Sign-in logs → filter Application = GRC-pal (acme)
   → Conditional Access tab; "Report-only: Failure" shows who would be blocked and why.
5. **Turn it on.** Switch the policy to **On**.

Browsers: device compliance only reaches Entra ID from a supported browser. Edge signed in with the
work profile works everywhere. Chrome on Windows needs the Intune policy `CloudAPAuthEnabled`; Chrome on
macOS needs the Microsoft Single Sign On extension. Private/incognito windows always fail the device check.

How long a check lasts: GRC-pal's sign-in cookie expires after `sessionHours` (default 8). Then the
browser goes back to Entra ID and the CA policy is evaluated again, so a device that fell out of
compliance or a disabled account loses access within that time. To cut someone off at once: disable
the account in Entra ID and remove the user under **Users and roles**.

Evidence for your own audit (CC6.1, CC6.2): the CA policy JSON (Graph Explorer:
`GET /identity/conditionalAccess/policies`), the assignment list of the enterprise app, and a monthly
sign-in log export filtered to GRC-pal.

## Step 4. Connect your systems in the portal

Open **Configuration > Settings** (or the **Setup guide**, which walks through the same steps).
For each system: read the guidance, enter the values, press **Test without saving**, fix anything
red, then **Save and apply**. Credentials are encrypted with the instance's `GRCPAL_ENCRYPTION_KEY`.
`deploy.sh` printed that key the first time; keep it in a password manager. Press **Run collection
now** at the end; afterwards the daily `collect` job runs at 06:17 UTC with the saved settings.
See [clouds.md](clouds.md) for AWS and Google Cloud.

## Step 4b. Connect your program repository (optional)

In the program repository, the workflows from the starter kit are already in `.github/workflows`:

| Workflow | When | What |
| --- | --- | --- |
| `validate.yml` | Every pull request | Catalog checks; the PR approval is your change record |
| `publish-config.yml` | Merge to main | Sends catalog, registers, policies, knowledge articles (`kb/`) and frameworks to the portal |
| `collect-daily.yml` | Daily | Runs collectors, stores evidence, opens deficiency issues, builds the health report |
| `scanners.yml` | Weekly | Prowler (Azure) and Maester (Entra) |
| `tls-weekly.yml` | Weekly | testssl.sh against your public endpoints |
| `tasks-monthly.yml` | Monthly | Recurring control tasks |

Grant the collector identity read access to Microsoft Graph and Azure (one time, needs a Global
Administrator for the Graph part). The script prints the exact command:

```powershell
./deploy/azure/grant-permissions.ps1 -PrincipalId <collectorPrincipalId> -Scope /subscriptions/<id>
```

Run **Publish program configuration** and **Collect evidence** once from the Actions tab, then
reload the portal (it picks up the catalog at its next start; `az containerapp revision restart`
applies it immediately).

## Step 5. Turn on email (optional, recommended)

Reminders and notifications need a sender mailbox. Two options:

**Microsoft 365 (no secrets).** Create a shared mailbox such as `grc@acme.com`, re-run the script
with `--mail-from grc@acme.com`, and run the three Exchange Online PowerShell commands it prints.
They use *RBAC for Applications* so the portal can send only as that one mailbox. Do not grant
the tenant-wide Graph `Mail.Send` permission in Entra ID; that would allow sending as anyone.

**Any SMTP server.** Set `mailBackend=smtp`, `smtpHost`, `smtpPort`, `smtpUser` and
`smtpPassword` in the deployment parameters. TLS (STARTTLS) is required by default.

Check it: assign yourself a test request; the email should arrive within a minute. Failures are
written to the audit log (`mail.failed`) and to the app logs.

## Step 6. Lock evidence and backup retention (after a clean week)

The `evidence` and `backups` containers have time-based retention policies that are not locked yet, so
you can fix mistakes in the first days. Once runs are stable, lock both. **This cannot be undone**:
nobody, including you or someone with your Owner role, can delete or change evidence or backups until
they age out.

```bash
for c in evidence backups; do
  ETAG=$(az storage container immutability-policy show -g rg-grcpal-acme --account-name <storage> -c $c --query etag -o tsv)
  az storage container immutability-policy lock -g rg-grcpal-acme --account-name <storage> -c $c --if-match "$ETAG"
done
```

The storage account also carries a delete lock (`grcpal-no-delete`), so the account and the resource
group cannot be deleted by accident or by a stolen admin session without first removing the lock,
which raises an alert when `--alert-email` is set.

## Backups

`deploy.sh` sets up everything: a `backups` container whose files are write-protected for 35 days
(`backupRetentionDays`), a backup key stored as a Container Apps secret, and a backup job that checks every
15 minutes (`backupCheckCron`). It makes the scheduled backup once a day at the hour set on
**Administration → Backups** (UTC), and starts any **Back up now** within about 15 minutes. A check that finds
a backup still running skips it, so a long backup is never made twice. A backup cannot be changed or deleted
before its protection ends, even by an admin, which also protects against ransomware.

On Azure every backup is kept for `backupRetentionDays` (default 35) and then removed by a storage lifecycle
rule; the 7-day/4-week/12-month settings on the Backups page apply to folder locations (VMs) only, because
the app cannot delete write-once files. For longer history, raise `backupRetentionDays` (storage cost grows
with each daily copy) or rely on the auditor exports and write-once evidence for the audit period.

With `--alert-email`, you get an email when no verified scheduled backup was logged for 2 days
(`backupAlertWindow`; set `P8D` for a weekly schedule).

Save the **recovery kit** once: re-run `deploy.sh` with the same options plus `--kit-out recovery-kit.json`
(or add it to the first run). Move the file into your password manager and delete the local copy. It holds the
backup key and the app key; with a backup file it rebuilds the instance anywhere. In production the Backups page
does not offer the kit or backup downloads, so a stolen admin session cannot take them
(`GRCPAL_WEB_BACKUP_DOWNLOAD=on` brings them back, with an email to every admin on each download).

Evidence itself is also in write-once storage (step 6) and geo-redundant by default, so the backup file is
your second, portable copy.

## Updates

Updates run from the **GRC-pal update** workflow in your program repository (`grcpal init` adds it as
`.github/workflows/grcpal-update.yml`; for an existing repository copy it from
`grcpal/starter/github/workflows/`. `deploy.sh --github-repo` sets its variables). The portal never
updates itself. One-time setup: in GitHub → your program repository → Settings → Environments, create
**`grcpal-update`**. Add yourself as a required reviewer if every update should wait for your approval.
The updater identity can only be used by workflow runs in that environment, and may change only this
container app and its jobs (plus using its Container Apps environment).

| Release | Installs |
| --- | --- |
| Patch (0.3.0 → 0.3.1) | When someone runs the workflow with the version number. The weekly run (Mondays) installs nothing: it lists newer releases, security fixes first, in the run summary |
| Feature (0.3 → 0.4) | When someone runs the workflow with the version number (Actions → GRC-pal update → Run workflow) |
| Major (0.x → 1.0) | Same, with **major** ticked, after reading the release notes |

What every update does (users stay on the current version until the last step):

1. Pins the new image by its digest and checks its build provenance (built by GRC-pal's release workflow).
2. Takes a backup with the current version and checks it.
3. **Trial:** the new version copies every table into a scratch database, runs its data upgrades there and
   checks the copy. A failure stops the update with nothing changed.
4. Starts the new version as a new revision **with no traffic**. It applies its data upgrades, which only add,
   so the current version keeps working on the same data.
5. **Health check:** the new revision must answer, and its self-test on the live data must pass (data model,
   every audit chain, no table with fewer rows than before).
6. Moves all traffic to the new revision and switches the jobs to it. The previous revision stays ready
   (label `previous`).

If step 4 or 5 fails, traffic never moves and the new revision is switched off. Each result is in the audit
log: `update.applied`, `update.trial_failed`, `update.rolled_back`.

The workflow log shows each step with its percentage (`[45%] Trial ...`). The **Administration → Updates**
page lists newer releases with *Do I need it?*. The previous revision stays ready until the next update, and
the backup taken before each update is kept for at least 30 days.

**Roll back:** run the workflow with **rollback** ticked, or `./deploy/azure/update.sh --name acme --rollback`.
Traffic and jobs go back to the previous revision; the data needs nothing because updates only add.

From your own computer (Azure CLI and GitHub CLI signed in):

```bash
./deploy/azure/update.sh --name acme --status            # running, previous and latest versions
./deploy/azure/update.sh --name acme --version 0.3.1     # install a release (asks first)
./deploy/azure/update.sh --name acme --rollback
```

`deploy.sh` never changes the version: re-running it (for example to rotate the sign-in secret) keeps the
version that is running.

**Instances on 0.2.0** (before the updater existed): move to 0.3.0 once with
`./deploy/azure/deploy.sh --name acme --admins you@acme.com --image ghcr.io/seattlespicybite/grc-pal:0.3.0`
after a backup; from then on the workflow does it.

## Rebuild from a backup

To recover from a lost resource group or subscription, or to move to another region, build a **new** instance
from a backup file and its recovery kit:

```bash
./deploy/azure/deploy.sh --name acme2 --admins you@acme.com \
    --restore-from grcpal-acme-20261001T020000Z-scheduled.grcbak --kit recovery-kit.json
```

It deploys a new, empty instance with the kit's keys, uploads the backup to its `backups` container (giving
you temporary permission there), and runs the restore as a job. The restore checks the whole file and
writes nothing unless it is intact. Point your users to the new address afterwards. If the old instance is
still running, retire it only after you have checked the new one.

## Other changes

- **Catalog or policy change:** pull request in your program repository; merging publishes it.
- **Rotate the sign-in secret:** re-run `deploy.sh` once a year (it rotates automatically).

## Removing an instance

Take a final backup and an auditor export first. Remove the delete lock
(`az lock delete -g rg-grcpal-acme -n grcpal-no-delete --resource <storage> --resource-type Microsoft.Storage/storageAccounts`),
then `az group delete -n rg-grcpal-acme` removes everything except locked evidence and backups, which
Azure keeps until retention ends. Delete the app registration separately (`az ad app delete --id <appId>`).

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| "You have not been given access" after sign-in | Add the person under Users and roles, or list them in roles.yaml, or assign them work |
| AADSTS50105 after sign-in | The person is not assigned to the enterprise app: add them to the `GRC-pal users` group |
| "You can't get there from here" / device not compliant | Use Edge with the work profile (or Chrome with the settings in Step 3b), not a private window; check the device in Intune |
| Backup alert email | Administration → Backups; Log Analytics: `ContainerAppConsoleLogs_CL \| where Log_s has "backup.run_due"` |
| Sign-in loops or AADSTS50011 | The redirect URL is missing: re-run deploy.sh, or `az ad app update --id <appId> --web-redirect-uris <redirectUri>` |
| Portal shows the starter catalog | Run *Publish program configuration*, then restart the revision |
| Error page with a reference | Search the reference in Log Analytics: `ContainerAppConsoleLogs_CL | where Log_s has "<reference>"` |
| Emails not arriving | Audit log, filter `mail.`; check the Exchange RBAC commands ran and the sender address matches |

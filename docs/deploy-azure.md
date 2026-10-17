# Deploy GRC-pal to Azure

About an hour end to end, most of it waiting. The result is one GRC-pal instance for one
organization, in its own resource group.

| Created | Purpose | Typical cost |
| --- | --- | --- |
| Storage account | Evidence (write-once), portal data (tables), your published catalog | Cents per GB per month |
| Container App + 2 scheduled jobs | Portal (scales to zero), weekly reminders, monthly tasks | Usually within the Container Apps monthly free grant |
| Log Analytics workspace | App logs, 30 days, capped at 0.5 GB per day | A few dollars at most |
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
  --github-repo acme/acme-grc \
  --location eastus2
```

Add `--what-if` first if you want to preview the changes. The script:

1. creates the resource group `rg-grcpal-acme`;
2. creates the Entra app registration **GRC-pal (acme)** and a sign-in secret (valid one year);
3. deploys `deploy/azure/main.bicep`: storage, identities, logs, the portal and the jobs;
4. sets the sign-in redirect URL;
5. sets the GitHub repository variables your workflows need (or prints them).

It prints the portal URL at the end.

> Prefer clicking? `deploy/azure/azuredeploy.json` is the same template for the Azure portal's
> *Deploy a custom template* page. You then create the app registration yourself and pass its
> client ID and secret as parameters.

## Step 3. Sign in

Open the portal URL and sign in with the email you passed to `--admins`. You are an admin.

- Add people under **Users and roles**, or simply assign work: assignees get contributor access
  automatically. Auditors are added with the **Auditor** role (as Entra B2B guests).
- Only accounts from your Entra directory can sign in (`GRCPAL_ALLOWED_TENANT_IDS`). For an
  extra gate, re-run the script with `--require-assignment` and assign users to the enterprise app.

## Step 4. Connect your systems in the portal

Open **Administration > Configuration** (or the **Setup guide**, which walks through the same steps).
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
| `publish-config.yml` | Merge to main | Sends catalog, registers and policies to the portal |
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

## Step 6. Lock evidence retention (after a clean week)

The `evidence` container has a time-based retention policy that is not locked yet, so you can fix
mistakes in the first days. Once runs are stable, lock it. **This cannot be undone**: nobody,
including you, can delete or change evidence until it ages out.

```bash
az storage container immutability-policy show -g rg-grcpal-acme --account-name <storage> -c evidence
az storage container immutability-policy lock -g rg-grcpal-acme --account-name <storage> -c evidence --if-match <etag>
```

## Backups

`deploy.sh` sets up everything: a `backups` container whose files are write-protected for 35 days
(`backupRetentionDays`), a backup key stored as a Container Apps secret, and an hourly backup job that runs
the schedule and any **Back up now** from **Administration → Backups**. The default is a nightly backup,
kept 7 days, 4 weeks and 12 months. A backup cannot be changed or deleted before its protection ends, even by
an admin, which also protects against ransomware.

Download the **recovery kit** from the Backups page after the first sign-in and keep it in your password
manager. It holds the backup key and the app key; with a backup file it rebuilds the instance anywhere.

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
| Patch (0.3.0 → 0.3.1) | Automatically on the 8th of each month |
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

`az group delete -n rg-grcpal-acme` removes everything except locked evidence, which Azure keeps
until retention ends, and the app registration (`az ad app delete --id <appId>`).

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| "You have not been given access" after sign-in | Add the person under Users and roles, or list them in roles.yaml, or assign them work |
| Sign-in loops or AADSTS50011 | The redirect URL is missing: re-run deploy.sh, or `az ad app update --id <appId> --web-redirect-uris <redirectUri>` |
| Portal shows the starter catalog | Run *Publish program configuration*, then restart the revision |
| Error page with a reference | Search the reference in Log Analytics: `ContainerAppConsoleLogs_CL | where Log_s has "<reference>"` |
| Emails not arriving | Audit log, filter `mail.`; check the Exchange RBAC commands ran and the sender address matches |

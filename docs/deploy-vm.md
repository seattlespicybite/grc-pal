# Deploy GRC-pal on a VM in your network

This is the production setup for one organization on a private network: one small Linux VM, GRC-pal in a
container, HTTPS in front, and all data in one folder. People sign in with GRC-pal's own accounts.
Updates come as signed files, are tried on a copy of the data first, and roll back by themselves if a
check fails. Backups run every night and are managed on the **Backups** page.

For staff who work remotely over the internet, use [Azure](deploy-azure.md) instead (Entra ID sign-in with MFA
and Conditional Access). Local accounts have no MFA yet, so keep this VM reachable only from your network or VPN.

## What you need

| | |
| --- | --- |
| Operating system | **Debian 13 (trixie), minimal**: the "netinst" ISO; in the installer pick only **SSH server** and **standard system utilities** (no desktop). Security support until August 2028, long-term support until June 2030, and a CIS benchmark exists (CIS Debian Linux 13) for your hardening evidence. |
| Size | 2 vCPU, 4 GB RAM, 40 GB disk (more disk if you keep large evidence files). Hyper-V, VMware, Proxmox or any cloud VM. |
| Network | A DNS name such as `grc.internal.example.com`. Internet access is optional: without it, install and update from files. |
| Certificate | Your internal CA's certificate and key for that name, **or** let Caddy create its own (then distribute its root certificate to staff devices with Intune or Group Policy). |

## Install

Copy the installer kit from the release page (`grcpal-vm-installer-<version>.tar.gz`) to the VM, then
(the installer kit and signed update files are published from release 0.4.0 on):

```bash
tar -xzf grcpal-vm-installer-0.4.0.tar.gz && cd vm
# with internet access:
sudo ./install.sh --hostname grc.internal.example.com --version 0.4.0
# without internet access: also copy grcpal-0.4.0.grcupdate from the release page
sudo ./install.sh --hostname grc.internal.example.com --bundle grcpal-0.4.0.grcupdate
# your own certificate instead of Caddy's:
sudo ./install.sh --hostname grc.internal.example.com --version 0.4.0 --tls files --cert grc.crt --key grc.key
```

The installer is safe to run again and never deletes data. It:

- installs only `docker.io`, `caddy`, `nftables`, `unattended-upgrades`, `python3-cryptography`, `curl` and
  `ca-certificates` from Debian. Security updates for the operating system install by themselves;
- turns on a firewall that lets in only SSH, HTTP (redirects to HTTPS) and HTTPS. GRC-pal itself listens on
  127.0.0.1 only, behind Caddy;
- turns off SSH log-in as root;
- runs GRC-pal as a non-root, read-only container with no extra privileges;
- creates systemd services and timers for the portal, daily evidence collection, monthly tasks, weekly
  reminders, the hourly backup check, the monthly update check, and the updater that acts on approvals
  from the Updates page.

Then create the first admin and sign in:

```bash
sudo grcpal create-admin you@example.com --name "Your Name"
```

**Right after the first sign-in, open Administration → Backups and download the recovery kit.** Keep it in
your password manager, separate from the backups. Without it a backup cannot be read.

## Where everything is

| Path | What |
| --- | --- |
| `/var/lib/grcpal/data` | Database, evidence, HR inbox, keys (the backup key is in `data/keys`) |
| `/var/lib/grcpal/backups` | Backup files (`.grcbak`), checked right after they are written |
| `/var/lib/grcpal/updates` | Update files waiting to be installed |
| `/var/lib/grcpal/state` | Updater status, history and log (`update.log`) |
| `/var/lib/grcpal/rollback` | The data copies from before each update of the last 30 days (at least the last two) |
| `/etc/grcpal` | Settings (`grcpal.env`), secrets (`secrets.env`, owner-only), the update signing public key |

Updating the operating system (`apt upgrade`, a reboot, or a hypervisor host patch) does not touch any of
these folders, and GRC-pal starts again by itself after a reboot.

## Backups

Backups are set up for you: every night, kept for 7 days, 4 weeks and 12 months, plus the last 3 taken before
updates. Manage them on **Administration → Backups**: **Back up now**, the schedule, **Check** and
**Download** for each backup, and the recovery kit. Every action is in the audit log.

A backup on the same VM does not protect you if the VM is lost. Copy `/var/lib/grcpal/backups` somewhere
else every night. Pick one:

- **A network share** mounted on the VM and set as the second location (it then appears on the Backups page):
  ```bash
  # /etc/fstab, e.g.  //nas.example.com/grcpal  /mnt/grcpal-backups  cifs  credentials=/etc/grcpal/nas.cred,uid=10001,gid=10001  0 0
  sudo mkdir -p /mnt/grcpal-backups && sudo mount /mnt/grcpal-backups
  echo 'GRCPAL_BACKUP_DIR_2_HOST=/mnt/grcpal-backups' | sudo tee -a /etc/grcpal/grcpal.env
  echo 'GRCPAL_BACKUP_DIR_2_LABEL=NAS' | sudo tee -a /etc/grcpal/grcpal.env
  sudo systemctl restart grcpal
  ```
  Then choose the NAS as the schedule's location on the Backups page. The folder must exist and be outside
  `/var/lib/grcpal`; otherwise it is ignored (and the update log says so).
- **Your existing backup tool** (Veeam, Azure Backup agent, rsync to a NAS with snapshots): include
  `/var/lib/grcpal/backups`.
- Best protection against ransomware: a target that cannot be changed for a while, such as storage with
  object lock or immutable snapshots.

Backup files are encrypted (AES-256-GCM). Whoever holds a backup **and** the recovery kit can read everything
in it, so store them apart.

## Updates

Open **Administration → Updates** to see the installed version, newer releases with a plain answer to
*Do I need it?* (security fixes, bug fixes, new features, major), anything waiting, and the history.
Nothing installs on its own: every update waits for an admin.

| Release | Example | Installs |
| --- | --- | --- |
| Patch | 0.4.0 → 0.4.1 (fixes) | After an admin clicks **Approve** (you can turn on automatic patches if you prefer) |
| Feature | 0.4 → 0.5 | After an admin clicks **Approve** on the Updates page |
| Major | 0.x → 1.0 | After **Approve**; read the release notes first and take a VM snapshot |

**Getting the update file.** With internet access, turn on *Download updates* on the Updates page; the
update check fetches signed update files from the release page. Without internet access, copy
`grcpal-<version>.grcupdate` from the release page to `/var/lib/grcpal/updates/` (or run
`sudo grcpal-update apply grcpal-<version>.grcupdate` to install it at once).

**What happens during an update** (users can keep working until step 5, which takes a few minutes):

1. The version that is already running checks the file's signature and the image checksum. A file that
   was not signed by the GRC-pal release key is refused before it is even loaded.
2. A backup is taken and checked, and the row count of every table is saved.
3. **Trial:** the new version restores that backup's tables into a scratch folder, runs its data upgrades
   there and checks the result. If anything fails, the update stops and nothing has changed.
4. The portal stops. The database, settings and keys are copied aside. Evidence is write-once and never
   changed by an update, so it is not copied.
5. The new version starts and upgrades the data.
6. **Health check:** the portal must answer and pass its self-test: data model, every audit chain, evidence
   files against their SHA-256, and no table with fewer rows than before. If any check fails, the copies are
   put back and the previous version starts again, automatically.

While an update runs, the Updates page shows a progress bar with the percentage and the current step
(check, backup, trial, switch, health check). The page reconnects by itself while the portal restarts.

The previous version stays on the VM, so going back needs no internet: `sudo grcpal-update rollback`. The data
copy and the backup taken before each update are kept for at least 30 days.

### Release signing key (maintainers of the GRC-pal repository)

Update files are signed in the release workflow with an Ed25519 key held only as the
`GRCPAL_UPDATE_SIGNING_KEY` secret of the `release` environment. VMs check them against
`deploy/vm/update-signing.pub`, which the installer copies to `/etc/grcpal/update-signing.pub`. To create the
key once, on your own computer (Linux, macOS with OpenSSL 3, or WSL):

```bash
openssl genpkey -algorithm ed25519 -out grcpal-signing.pem
openssl pkey -in grcpal-signing.pem -pubout -out update-signing.pub
```

1. GitHub → Settings → Environments → `release` → **Add environment secret**: name
   `GRCPAL_UPDATE_SIGNING_KEY`, value: the whole content of `grcpal-signing.pem`.
2. Commit `update-signing.pub` as `deploy/vm/update-signing.pub`.
3. Delete `grcpal-signing.pem` from your computer (the secret is the only copy; a lost key is replaced by
   a new one, see below).

To rotate the key, add the new public key to `update-signing.pub` (the file may hold several keys), release
once, then replace the secret and remove the old key in the next release. Until the secret is set, releases
publish the image but no update file (the workflow says so).

## If something goes wrong

| Situation | What to do |
| --- | --- |
| An update failed | Nothing to do: it rolled back by itself. The Updates page and `/var/lib/grcpal/state/update.log` say why. |
| The new version runs but behaves badly | `sudo grcpal-update rollback` (the data copy from before the update comes back too). |
| Data was deleted or damaged by mistake | Backups page → **Restore this backup** under a backup from before the problem. Type RESTORE. A safety backup is taken first and today's data is kept aside in `/var/lib/grcpal`. |
| The VM is lost | Rebuild: see below. |

### Rebuild on a new VM

You need a backup file (from your off-VM copy) and the recovery kit.

```bash
sudo ./install.sh --hostname grc.internal.example.com --version 0.4.0 \
     --restore grcpal-acme-20261001T020000Z-scheduled.grcbak --kit recovery-kit.json
```

Use the same version as the backup or newer. The restore checks the whole file first, writes nothing unless
it is intact, and puts the app key from the kit in place so saved integration credentials keep working.
Everyone signs in with their existing accounts. Each organization's audit log continues with a
`backup.restore` record.

## Snapshots before major updates

A hypervisor snapshot is a quick extra safety net before a **major** release (not needed for patches or
feature releases: the updater's own copy covers those). Take it with the portal stopped, so the database file
is consistent:

```bash
sudo systemctl stop grcpal
# Hyper-V: Checkpoint-VM -Name grcpal -SnapshotName before-1.0   (PowerShell on the host)
# VMware:  take a snapshot without memory in vSphere
# Proxmox: qm snapshot <vmid> before-1.0
sudo systemctl start grcpal
```

Delete the snapshot after a week of normal use: snapshots slow the disk down and are not backups.

## Commands

```bash
sudo grcpal-update status              # installed version, anything waiting, last result
sudo grcpal-update apply FILE          # install a signed update file now (same checks as an approval)
sudo grcpal-update rollback            # previous version and its data copy
sudo grcpal <command>                  # any grcpal command inside the running portal, e.g.
sudo grcpal users list
sudo grcpal backup verify /backups/<file>.grcbak
journalctl -u grcpal -n 100            # portal logs
```

## Audit evidence this setup produces

- **A1.2 (backups):** the Backups page list (created, checked, kept), `backup.*` audit records.
- **A1.3 (recovery testing):** once a year, restore a recent backup into a test folder or test VM and keep
  the JSON result (see [operations.md](operations.md#yearly-restore-test)).
- **CC8.1 (changes):** `update.approved`, `update.applied`, `update.trial_failed` and `update.rolled_back`
  records with versions, approver and the pre-update backup.
- **CC7.1 (patching and configuration):** `unattended-upgrades` logs, and the CIS Debian 13 benchmark if you
  scan the VM (for example with Tenable).

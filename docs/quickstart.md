# Quickstart

Three ways to run GRC-pal on your own computer. None of them needs an Azure account.

## 1. Python (one minute)

Requires Python 3.11 or later.

```bash
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install "grc-pal[portal] @ git+https://github.com/seattlespicybite/grc-pal"
grcpal serve --demo
```

Open http://localhost:8000. You see a sign-in page with sample people:

| Pick | To see |
| --- | --- |
| Alex Admin | Dashboard, reviews, users, cycles, reminders, overrides, audit log |
| Harper HR (Control owner) | Only HR controls; upload evidence, comment, last cycle's evidence |
| Casey (external auditor) | Read-only views and the export zip |

Things to try:

1. As **Alex**, open control **HR-01**, then **Send a reminder**. Open **Email outbox** to read
   the email Harper would get, with the link back to the control.
2. As **Harper**, open **My work**, open the HR-01 request, upload any PDF or PNG and leave a comment.
3. As **Sam Security** (second admin), approve it under **Reviews**. You cannot approve your own upload.
4. As **Alex**, open **Cycles and export** and download the export zip.
5. Open **Audit log** and click **Verify integrity**.

`--demo` keeps data in memory, so every restart starts fresh. Use `--db grcpal.db` to keep it.

## 2. Docker Compose

```bash
git clone https://github.com/seattlespicybite/grc-pal && cd grc-pal
docker compose up --build
```

Open http://localhost:8000. Data is kept in a Docker volume. To read the notification emails in
a real web inbox, run `docker compose --profile mail up --build`, set the SMTP lines in `.env`
(see `.env.example`) and open http://localhost:8025.

## 3. With your own catalog

```bash
grcpal init my-grc --org "My Company"
cd my-grc
# edit catalog/roles.yaml: put your own email on a role, e.g. security-lead
grcpal validate
grcpal serve --base . --db portal.db
```

`--demo` aside, `grcpal serve` uses local accounts: run `grcpal create-admin` first (section 4).
People listed in `catalog/roles.yaml` get Control owner access automatically for the controls
their role owns.

## 4. On a VM for your team (production, local accounts)

This is the setup for running GRC-pal for one organization on a Linux VM inside your network
(on-premises, Azure VM, or any cloud VM). People sign in with GRC-pal's own accounts (email and
password, stored only as hashes). Pick Python or Docker; both keep all data in one folder.

### Before you start

- A Linux VM with 2 GB RAM, Python 3.11+ **or** Docker, reachable only from your internal network or VPN.
- A DNS name for it (for example `grc.internal.example.com`) and a TLS certificate. **Do not run
  it without HTTPS**: passwords would cross the network in clear text.
- Three secrets, generated once and kept in your password manager:
  ```bash
  openssl rand -hex 32   # GRCPAL_SECRET: signs form tokens
  openssl rand -hex 32   # GRCPAL_ENCRYPTION_KEY: encrypts integration credentials saved in the portal
  ```
  Losing `GRCPAL_ENCRYPTION_KEY` means re-entering integration credentials. The backup key is
  created after installing (see Scheduled jobs).

### Option A: Python

```bash
sudo useradd --system --create-home --home-dir /var/lib/grcpal grcpal
sudo -u grcpal python3 -m venv /var/lib/grcpal/venv
sudo -u grcpal /var/lib/grcpal/venv/bin/pip install "grc-pal[portal] @ git+https://github.com/seattlespicybite/grc-pal@main"
```

Create `/etc/grcpal.env` and let only root and the `grcpal` user read it
(`sudo chown root:grcpal /etc/grcpal.env && sudo chmod 640 /etc/grcpal.env`):

```bash
GRCPAL_ENV=production
GRCPAL_AUTH_MODE=local
GRCPAL_PUBLIC_URL=https://grc.internal.example.com
GRCPAL_SECRET=<first value from openssl>
GRCPAL_ENCRYPTION_KEY=<second value from openssl>
GRCPAL_SQLITE=/var/lib/grcpal/grcpal.db
GRCPAL_EVIDENCE_DIR=/var/lib/grcpal/evidence
```

Run it as a service, `/etc/systemd/system/grcpal.service`:

```ini
[Unit]
Description=GRC-pal
After=network.target

[Service]
User=grcpal
EnvironmentFile=/etc/grcpal.env
ExecStart=/var/lib/grcpal/venv/bin/uvicorn grcpal.portal.app:app --host 127.0.0.1 --port 8000 --proxy-headers --no-server-header
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/grcpal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now grcpal
sudo -u grcpal bash -c 'set -a; . /etc/grcpal.env; /var/lib/grcpal/venv/bin/grcpal create-admin you@example.com --name "Your Name"'
```

### Option B: Docker

```bash
git clone https://github.com/seattlespicybite/grc-pal && cd grc-pal
docker build -t grc-pal .
docker volume create grcpal-data
docker run -d --name grcpal --restart unless-stopped -p 127.0.0.1:8000:8000 \
  -v grcpal-data:/data --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -e GRCPAL_PUBLIC_URL=https://grc.internal.example.com \
  -e GRCPAL_SQLITE=/data/grcpal.db -e GRCPAL_EVIDENCE_DIR=/data/evidence \
  --env-file /etc/grcpal.secrets grc-pal
docker exec -it grcpal grcpal create-admin you@example.com --name "Your Name"
```

`/etc/grcpal.secrets` (mode 600) holds `GRCPAL_SECRET=...` and `GRCPAL_ENCRYPTION_KEY=...`. The
image already sets `GRCPAL_ENV=production` and `GRCPAL_AUTH_MODE=local`, runs as a non-root user
and keeps everything it writes in the `grcpal-data` volume. To use a host folder instead of a
volume, create it and `chown 10001:10001` it first.

### HTTPS in front

The app listens on `127.0.0.1:8000` only. Put a reverse proxy with your certificate in front, for
example [Caddy](https://caddyserver.com/) (`caddy reverse-proxy --from grc.internal.example.com --to 127.0.0.1:8000`),
nginx or IIS. Keep `GRCPAL_PUBLIC_URL` equal to the address people type; it is used for email links
and the cross-site request check.

### First sign-in

1. Sign in at `https://grc.internal.example.com/login` with the admin you created.
2. **Users and roles**: add people. Each gets a one-time link (also emailed if email is set up)
   to choose a password. Make one admin the **control library owner** (it can be you).
3. **Frameworks**: turn off any framework the organization is not working on (for example keep
   only SOC 2).
4. **Setup guide**: connect Microsoft Entra ID / Microsoft 365, Azure, GitHub and email. Each
   connection is tested before it is saved; credentials are encrypted.

Forgot a password? **Forgot password?** on the sign-in page, or an admin's **Reset password** on
the Users page. Locked out completely? Run `grcpal create-admin` on the server again (break-glass).

### Scheduled jobs

Create the backup key once, then add the jobs to the `grcpal` user's crontab
(`sudo crontab -u grcpal -e`). Each line loads the same settings as the service, including the
email settings saved on the Configuration page. With Docker, run the same commands through
`docker exec grcpal ...` from the host's crontab.

```bash
sudo -u grcpal mkdir -p /var/lib/grcpal/backups
sudo -u grcpal /var/lib/grcpal/venv/bin/grcpal backup keygen --key-file /var/lib/grcpal/backup.key
```

Copy the key into your password manager now. Backups are only useful off the VM: copy
`/var/lib/grcpal/backups` to other storage every night, and keep the key separate from those copies.

```cron
SHELL=/bin/bash
# daily evidence collection and custom checks
30 2 * * *  set -a; . /etc/grcpal.env; /var/lib/grcpal/venv/bin/grcpal collect --all --checks
# open this month's recurring tasks (access reviews, DR test, ...)
0 6 1 * *   set -a; . /etc/grcpal.env; /var/lib/grcpal/venv/bin/grcpal tasks
# weekly overdue reminders
0 8 * * 1   set -a; . /etc/grcpal.env; /var/lib/grcpal/venv/bin/grcpal remind --overdue
# nightly encrypted backup (copy the files off the VM)
0 3 * * *   set -a; . /etc/grcpal.env; /var/lib/grcpal/venv/bin/grcpal backup create /var/lib/grcpal/backups/grcpal-$(date +\%F).grcbak --key-file /var/lib/grcpal/backup.key
```

Until Microsoft and Azure are connected in the Setup guide (or switched off on the Configuration
page), the daily collection reports those collectors as failed; that is expected on day one.

Check a backup with `grcpal backup verify FILE --key-file /var/lib/grcpal/backup.key`. Details:
[operations.md](operations.md#backups-and-recovery).

### Accepted risk for an internal VM

Local accounts have no MFA or lockout yet. That is acceptable only while the portal is reachable
from the internal network alone. Before it is reachable from outside, use Entra ID single sign-on
with Conditional Access (Azure deployment or `GRCPAL_AUTH_MODE=proxy` behind an identity-aware
proxy). See [security.md](security.md).

### Upgrades

Back up first (`grcpal backup create ...`). Python: reinstall with `pip install --upgrade` and
restart the service. Docker: rebuild the image and re-run the container with the same volume.
Upgrades never rewrite stored evidence; read the [CHANGELOG](../CHANGELOG.md) first.

## Development mode is for your computer only

`grcpal serve --demo` and Docker Compose use simulated sign-in: anyone who can reach the page can act as
any user. The app refuses to start in that mode when `GRCPAL_ENV=production`. For a shared
instance, follow section 4 above (VM) or [deploy-azure.md](deploy-azure.md).

## Next

- [Deploy to Azure](deploy-azure.md)
- [Configuration reference](configuration.md)

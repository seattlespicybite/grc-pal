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

## 4. On a VM for your team (production)

Production on your own network runs on **Debian 13 minimal with Docker**, installed by one script that also
sets up HTTPS, the firewall, scheduled jobs, nightly backups and signed updates with automatic rollback:

```bash
sudo ./install.sh --hostname grc.internal.example.com --version 0.3.0
sudo grcpal create-admin you@example.com --name "Your Name"
```

Everything, including offline installs, backups, updates and rebuilding from a backup:
[deploy-vm.md](deploy-vm.md). Local accounts have no MFA yet, so keep the VM reachable only from your
network or VPN; for remote staff use [Azure](deploy-azure.md) with Entra ID and Conditional Access.

The Python install from sections 1 and 3 is for trying GRC-pal and for development. It has no automatic
backups, signed updates or rollback, so do not use it for production.

## Development mode is for your computer only

`grcpal serve --demo` and Docker Compose use simulated sign-in: anyone who can reach the page can act as
any user. The app refuses to start in that mode when `GRCPAL_ENV=production`. For a shared
instance, follow [deploy-vm.md](deploy-vm.md) or [deploy-azure.md](deploy-azure.md).

## Next

- [Deploy to Azure](deploy-azure.md)
- [Configuration reference](configuration.md)

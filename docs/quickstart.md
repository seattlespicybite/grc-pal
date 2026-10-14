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

## 4. On a VM for your team (local accounts)

Without `--demo`, GRC-pal uses its own accounts: people sign in with an email and password.

```bash
export GRCPAL_SQLITE=/var/lib/grcpal/grcpal.db GRCPAL_EVIDENCE_DIR=/var/lib/grcpal/evidence
export GRCPAL_PUBLIC_URL=https://grc.internal.example.com
grcpal create-admin you@example.com --name "Your Name"     # asks for the password twice
grcpal serve --host 0.0.0.0
```

With Docker: `docker compose exec grcpal grcpal create-admin you@example.com`.

1. Sign in at `/login` with the admin you just created.
2. Open **Users and roles** and add people. After each one you get a one-time link (also emailed
   if email is set up). They open it and choose their own password; you never see it.
3. Forgot a password? People use **Forgot password?** on the sign-in page, or an admin clicks
   **Reset password** on the Users page for a new link. Locked out completely? Run
   `grcpal create-admin` again on the server (break-glass).

Put GRC-pal behind HTTPS before other people use it, so passwords do not cross the network in
clear text. A step-by-step VM guide with HTTPS and scheduled collection is coming next.

## Development mode is for your computer only

`grcpal serve --demo` and Docker Compose use simulated sign-in: anyone who can reach the page can act as
any user. The app refuses to start in that mode when `GRCPAL_ENV=production`. For a shared or
internet-facing instance, follow [deploy-azure.md](deploy-azure.md).

## Next

- [Deploy to Azure](deploy-azure.md)
- [Configuration reference](configuration.md)

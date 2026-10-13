# Configuration reference

There are two layers:

1. **The Configuration page** (admins, **Administration > Configuration**) holds everything about what
   GRC-pal connects to: organization name, Microsoft Entra ID and Azure, AWS, Google Cloud, GitHub,
   HR feed and documentation links, email and the AI assistant. Each section explains every field,
   has **Test without saving**, **Save and apply** and **Save and test**, and shows the result of the
   last test. Changes take effect immediately and are recorded in the audit log (field names only).
   Secrets are encrypted with AES-256-GCM using `GRCPAL_ENCRYPTION_KEY`, bound to the tenant and
   field, and never shown again. The **Setup guide** walks through the same sections in order.
2. **Environment variables** for how the instance itself runs (sign-in mode, storage, keys). The
   deployment sets them. Any Configuration-page field can also be given as an environment variable
   of the same name; a value saved on the page takes precedence.

## Instance keys

| Variable | Meaning |
| --- | --- |
| `GRCPAL_ENCRYPTION_KEY` | Encrypts credentials saved on the Configuration page. Required in production. `deploy.sh` generates it once and reuses it; keep a copy in a password manager. Without it, saved credentials must be re-entered |
| `GRCPAL_KEY_FILE` | Development only: where the generated local key is kept (default `.grcpal.key`) |
| `GRCPAL_LOG_RETENTION_DAYS` | Days of system events kept for the Logs page (default 90) |
| `GRCPAL_JOBS_SYNC` | `1` runs background jobs inline (tests, scripts) |
| `GRCPAL_CHECKS_ALLOW_PRIVATE` | `1` lets checks reach private addresses. Only for internal-only, self-hosted deployments |

## Core

| Variable | Default | Meaning |
| --- | --- | --- |
| `GRCPAL_ENV` | (empty) | `production` refuses development sign-in and requires `GRCPAL_SECRET` |
| `GRCPAL_TENANT` | `default` | Instance ID. Prefixes every portal record and evidence path. 1-40 lowercase letters, digits, hyphens |
| `GRCPAL_SECRET` | random per process | Signs form tokens. Required in production (`openssl rand -hex 32`) |
| `GRCPAL_PUBLIC_URL` | `http://localhost:8000` | Base for links in emails and for the cross-site request check |
| `GRCPAL_BASE` | (empty) | Folder with `catalog/`, `registers/`, `policies/`. Empty: published bundle, else the starter kit |
| `GRCPAL_CONFIG` | `blob` | `off` disables loading the published configuration bundle |
| `GRCPAL_CONFIG_DIR` | `/tmp/grcpal-config` | Where the bundle is extracted |
| `GRCPAL_DEMO` | (empty) | `1` loads sample data into an empty store. Never in production |

## Sign-in and access

| Variable | Default | Meaning |
| --- | --- | --- |
| `GRCPAL_AUTH_MODE` | `easyauth` | `easyauth` (Azure Container Apps / App Service), `proxy` (trusted reverse proxy) or `dev` |
| `GRCPAL_BOOTSTRAP_ADMINS` | (empty) | Comma-separated emails created as admins at first sign-in |
| `GRCPAL_ALLOWED_TENANT_IDS` | (empty = any) | Entra directory IDs allowed to sign in (easyauth) |
| `GRCPAL_GROUP_ADMIN` / `_CONTRIBUTOR` / `_AUDITOR` | (empty) | Optional group object IDs that create a user with that role at first sign-in |
| `GRCPAL_PROXY_EMAIL_HEADER` | `x-forwarded-email` | proxy mode: header carrying the signed-in email |
| `GRCPAL_PROXY_NAME_HEADER` | `x-forwarded-preferred-username` | proxy mode: display name header |
| `GRCPAL_LOGOUT_URL` | `/oauth2/sign_out` | proxy mode: sign-out link |
| `GRCPAL_DEV_PRINCIPAL` | (empty) | dev mode: default user as JSON, e.g. `{"email":"me@example.com"}` |

`proxy` mode trusts a header, so the app must be reachable only through the proxy (for example
oauth2-proxy or Pomerium in front, the app on a private network).

## Storage

| Variable | Default | Meaning |
| --- | --- | --- |
| `GRCPAL_TABLES_URL` | (empty) | Azure Table Storage endpoint for portal data (managed identity). Empty: SQLite |
| `GRCPAL_SQLITE` | `grcpal.db` | SQLite file when no tables URL. `:memory:` for throwaway runs |
| `GRCPAL_EVIDENCE_ACCOUNT_URL` | (empty) | Blob endpoint; evidence goes to the `evidence` container (write-once) |
| `GRCPAL_EVIDENCE_CONTAINER` | `evidence` | Container name |
| `GRCPAL_EVIDENCE_DIR` | `evidence` | Local evidence folder (also a cache in production) |
| `GRCPAL_MAX_UPLOAD_MB` | `25` | Upload size limit |

## Email

| Variable | Default | Meaning |
| --- | --- | --- |
| `GRCPAL_MAIL_BACKEND` | `console` | `console` (outbox page, dev), `smtp`, `graph` (Microsoft 365), `off` |
| `GRCPAL_MAIL_FROM` | `grc-pal@localhost` | Sender address; for `graph`, the mailbox the identity may send as |
| `GRCPAL_SMTP_HOST` / `_PORT` | / `587` | SMTP server |
| `GRCPAL_SMTP_USER` / `_PASSWORD` | (empty) | SMTP login (store the password as a secret) |
| `GRCPAL_SMTP_TLS` | `starttls` | `starttls`, `ssl` (port 465) or `none` (local test servers only) |
| `GRCPAL_MAIL_SYNC` | (empty) | `1` sends inline instead of in the background (scripts, tests) |

## Logging

| Variable | Default | Meaning |
| --- | --- | --- |
| `GRCPAL_LOG_FORMAT` | `json` | `json` (one object per line) or `text` |
| `GRCPAL_LOG_LEVEL` | `INFO` | Standard levels |

## Collectors (program repository workflows)

| Variable | Meaning |
| --- | --- |
| `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` | Collector identity for keyless GitHub OIDC login |
| `GRCPAL_REPOS` | Repositories in scope for change and vulnerability collectors, `org/app,org/infra` |
| `GRCPAL_SUBSCRIPTIONS` | Optional subscription filter |
| `GRCPAL_POLICY_ASSIGNMENT` | Azure Policy SOC 2 initiative assignment name |
| `GRCPAL_HR_LEAVERS_CSV` | Path of the HR leavers export (`email,termination_date`) |
| `GRCPAL_GRC_REPO` | Repository for deficiency issues (defaults to the current one) |
| `GRCPAL_WINDOW_DAYS` | Look-back window for change collectors (default 31) |
| `GRCPAL_TLS_TARGETS` | Hostnames checked weekly by testssl.sh |
| `GRCPAL_GITHUB_TOKEN` | Repository secret: fine-grained token, read-only on `GRCPAL_REPOS`, issues write on the program repo |
| `GRCPAL_VERSION` | Repository variable: GRC-pal version (Git tag) the workflows install |

# Configuration reference

There are two layers:

1. **The Configuration page** (admins, **Configuration > Settings**) holds everything about what
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
| `GRCPAL_AI_ALLOW_PRIVATE` | `1` lets the AI assistant reach a model on a private address (Ollama, vLLM, LM Studio on your network). Without it, AI calls go to public addresses only |
| `GRCPAL_GITHUB_ALLOW_PRIVATE` | `1` lets GitHub calls reach GitHub Enterprise Server on a private address |

Each switch opens only its own kind of call and can only be set in the deployment environment, not on the
Configuration page. The AI and GitHub switches never open link-local addresses (cloud metadata such as
169.254.169.254). Leave all three off on Azure.

### Secrets follow their server

Changing **Endpoint URL** (AI assistant), **API URL** (GitHub) or **SMTP server** (Email) clears that section's
saved secret (API key, token, SMTP password) unless you type a new one in the same save. A secret set by the
deployment, such as the SMTP password from `deploy.sh`, is blocked the same way until you enter a password or
switch back to the original server. "Test without saving" with a changed address does not use the saved secret.
Every Configuration save is in the audit log and is emailed to all admins (the person who saved included).

## Core

| Variable | Default | Meaning |
| --- | --- | --- |
| `GRCPAL_ENV` | (empty) | `production` requires `GRCPAL_SECRET` and keeps backup files and the recovery kit off the web page. `dev` (or `development`) is the only value that allows `GRCPAL_AUTH_MODE=dev`; `grcpal serve --demo` sets it |
| `GRCPAL_TRUSTED_PROXY_HOPS` | `0` | How many proxies in front of GRC-pal add to `X-Forwarded-For` (Azure Container Apps ingress: `1`, set by the template; VM with Caddy: `1`, set by `install.sh`). Only the address those proxies added is recorded as the caller's in sign-in events, the audit log and request logs; anything the caller sent is ignored. `0` uses the connection's address |
| `GRCPAL_WEB_BACKUP_DOWNLOAD` | (off) | `on` brings back **Download** for backup files and the recovery kit on the Backups page in production. Each download is audited and emailed to every admin. Leave it off and use `grcpal backup kit` or `deploy.sh --kit-out` |
| `GRCPAL_TENANT` | `default` | Instance ID. Prefixes every portal record and evidence path. 1-40 lowercase letters, digits, hyphens |
| `GRCPAL_SECRET` | random per process | Signs form tokens, which are tied to the person and their sign-in session. Required in production (`openssl rand -hex 32`) |
| `GRCPAL_PUBLIC_URL` | `http://localhost:8000` | Base for links in emails and for the cross-site request check |
| `GRCPAL_BASE` | (empty) | Folder with `catalog/`, `registers/`, `policies/`. Empty: published bundle, else the starter kit |
| `GRCPAL_CONFIG` | `blob` | `off` disables loading the published configuration bundle |
| `GRCPAL_CONFIG_DIR` | `/tmp/grcpal-config` | Where the bundle is extracted |
| `GRCPAL_DEMO` | (empty) | `1` loads sample data into an empty store. Never in production |

## Sign-in and access

| Variable | Default | Meaning |
| --- | --- | --- |
| `GRCPAL_AUTH_MODE` | `local` | `local` (GRC-pal accounts with passwords, for a VM), `easyauth` (Azure Container Apps / App Service), `proxy` (trusted reverse proxy) or `dev` |
| `GRCPAL_BOOTSTRAP_ADMINS` | (empty) | Comma-separated emails created as admins at first sign-in |
| `GRCPAL_ALLOWED_TENANT_IDS` | (empty) | Entra directory IDs allowed to sign in (easyauth). **Required** when `GRCPAL_ENV=production`: the portal refuses to start without it (the Azure template sets your tenant). Outside production, empty allows any directory |
| `GRCPAL_GROUP_ADMIN` / `_CONTRIBUTOR` / `_AUDITOR` | (empty) | Optional group object IDs that create a user with that role at first sign-in |
| `GRCPAL_PROXY_SECRET` | (none) | proxy mode, required: a random value of at least 32 characters (`openssl rand -hex 32`) that the proxy sends as `X-GRCPAL-Proxy-Secret` on every request. Requests without it are refused |
| `GRCPAL_PROXY_EMAIL_HEADER` | `x-forwarded-email` | proxy mode: header carrying the signed-in email |
| `GRCPAL_PROXY_NAME_HEADER` | `x-forwarded-preferred-username` | proxy mode: display name header |
| `GRCPAL_LOGOUT_URL` | `/oauth2/sign_out` | proxy mode: sign-out link |
| `GRCPAL_PROXY_SESSION_COOKIE` | `_oauth2_proxy` | proxy mode: name (or name prefix) of the proxy's session cookie; form tokens are tied to it so they change at every sign-in |
| `GRCPAL_ADMIN_IDLE_MINUTES` | `30` | local mode: an admin session unused for this many minutes ends. Other roles keep the 8-hour session limit |
| `GRCPAL_DEV_PRINCIPAL` | (empty) | dev mode: default user as JSON, e.g. `{"email":"me@example.com"}` |

`proxy` mode reads the signed-in email from a header, which anyone who reaches the app directly could also
send. So the proxy must add a shared secret to every request, and the app should still listen only where the
proxy can reach it (for example on 127.0.0.1 or a private network):

- Caddy (`forward_auth` to oauth2-proxy, then): `reverse_proxy 127.0.0.1:8000 { header_up X-GRCPAL-Proxy-Secret {env.GRCPAL_PROXY_SECRET} }`
- nginx: `proxy_set_header X-GRCPAL-Proxy-Secret "<the secret>";`
- oauth2-proxy (alpha config): an `injectRequestHeaders` entry named `X-GRCPAL-Proxy-Secret` whose value comes from the secret.

The proxy must also remove any `X-Forwarded-Email` the browser sent (Caddy's `forward_auth` with `copy_headers`,
and oauth2-proxy, both overwrite it).

**Microsoft Entra accounts are linked at first sign-in (easyauth).** Each person's row records their Entra
object ID and tenant the first time they sign in. Later, the same email from a different Entra account (an
address given to a new employee, a deleted and recreated account) is refused and logged as a security event.
After checking who now holds the address, an admin clicks **Unlink Entra account** on Users and roles; the next
sign-in links the new account. Both steps are in the audit log (`user.identity_bound`, `user.identity_reset`).

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

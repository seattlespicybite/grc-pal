# Security design

GRC-pal holds sensitive material: evidence about how an organization is protected, staff names,
and sometimes screenshots of production systems. This page describes how it is protected and what
remains your responsibility. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Threats considered

| Threat | Protection |
| --- | --- |
| Someone outside the organization opens the portal | Local accounts (VM): only people an admin added can set a password, one-time links, sessions on the server. On Azure: sign-in at the platform edge (Easy Auth); only listed directories (`GRCPAL_ALLOWED_TENANT_IDS`); only people in the users table; optional enterprise-app assignment |
| A contributor reads other teams' evidence | Visibility is computed in the service for every request: only assigned or owned controls; raw evidence store hidden; 404 rather than 403 for hidden objects |
| An auditor changes something | Auditor role has no write paths; every write checks the role in the service layer |
| One customer sees another's data (hosted use) | Separate deployment and storage account per customer; in addition every record key and evidence path carries the tenant prefix and reads outside it are refused (see [saas-architecture.md](saas-architecture.md)) |
| Evidence altered or deleted after the fact | Write-once container with locked retention; SHA-256 manifest per run; uploads stored with their hash |
| Portal history rewritten | Hash-chained audit log, verified on demand and exported daily to write-once storage |
| Approving your own work | Uploader can never review their upload |
| Malicious upload (script, malware disguised as PDF) | Extension allow-list, magic-byte check, UTF-8 check for text, size limit, files served only as downloads with `Content-Disposition: attachment`, a sandbox CSP and HTML/SVG forced to `octet-stream` |
| Cross-site scripting | Server-rendered templates with auto-escaping; strict CSP with no inline script or style; no third-party scripts or fonts |
| Password guessing and spraying against local accounts | Lockout per account (5 failures in 15 minutes) and per address (20), with waits that double up to 15 minutes, refused before any password hashing and identical for unknown accounts; every failure and lock is a security event; optional two-step sign-in (authenticator app) for local accounts |
| Flooding sign-in to exhaust the server | At most `GRCPAL_MAX_PASSWORD_CHECKS` password hashes at once; locked sign-ins cost no hashing; request bodies above `GRCPAL_MAX_BODY_MB` refused before they are read |
| Password reset abused (mailbox takeover, flooding, finding accounts) | No self-service reset for admins or the break-glass account; at most 3 reset emails per account and 10 requests per address per hour; same answer and timing for every address (the work runs after the reply); link tokens sit after `#` so they never reach logs, and are swapped once for a 15-minute form |
| Cross-site request forgery | HMAC token on every form, tied to the person and their sign-in session (local session, Easy Auth or proxy session cookie) and renewed at every sign-in, valid 12 to 24 hours, plus an Origin check |
| Open redirect | Return URLs limited to same-site paths |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` |
| Email abuse | One message per recipient, no recipient lists exposed, subject sanitized, reminder rate limit, sender restricted to one mailbox (Exchange RBAC for Applications) |
| Stolen credentials in config | No storage keys (shared-key auth disabled); managed identities and GitHub OIDC; secrets only as Container Apps secrets |
| Leaked integration credentials | Saved credentials encrypted with AES-256-GCM, bound to tenant and field, write-only in the UI, scrubbed from logs and audit records |
| Server-side request forgery through checks (for example reading cloud metadata to steal the portal's identity) | Checks resolve and pin the address, refuse loopback, private, link-local, multicast and reserved ranges, re-check every redirect, limit time and size |
| Server-side request forgery or token theft through integration endpoints (AI endpoint, GitHub API URL, Microsoft Graph) | The same guard as checks (`checks.safe_request`) carries these calls; credential headers are dropped when a redirect leaves the original host; private addresses only with an operator opt-in in the environment (`GRCPAL_AI_ALLOW_PRIVATE`, `GRCPAL_GITHUB_ALLOW_PRIVATE`), never from the portal |
| An admin session (or a stolen one) redirects a saved secret to another server | Changing the AI endpoint, GitHub API URL or SMTP server clears that section's secret unless a new one is typed in the same save, and also blocks a secret set by the deployment (for example the Azure SMTP password); "Test without saving" never sends the saved secret to a changed address; every Configuration save is audit-logged and emailed to all admins |
| Running code through the web portal | The portal never executes commands; command checks live only in the reviewed repository |
| AI data exposure or manipulation | See [ai-assistant.md](ai-assistant.md): off by default, confirmation, masking, injection fencing, human disposition, full record |
| Stolen password database | Passwords stored only as scrypt hashes with a random salt; setup links and session cookies stored only as SHA-256 hashes, so a database copy cannot sign anyone in |
| Finding which accounts exist | Same answer on sign-in and Forgot password whether or not the account exists |
| Session theft | HttpOnly, SameSite=Lax cookie; in production always Secure with the `__Host-` prefix (only this HTTPS host can set it). Every sign-in starts a new session; sessions end after 8 hours (admins: 30 minutes without activity), on sign-out (a form post with a token), and when the person is disabled, changes role or sets a new password |
| Auditor keeps access after fieldwork | Every auditor account has an access end date (default 90 days); after it, sign-in and existing sessions are refused |
| Losing the last admin | `grcpal create-admin` on the server creates or restores a local admin (break-glass); it needs shell access to the VM and is in the audit log |
| Development shortcuts reaching production | `dev` sign-in runs only with `GRCPAL_ENV=dev` set explicitly (a missing or mistyped value refuses it); `grcpal serve --demo` listens on 127.0.0.1 only; production requires `GRCPAL_SECRET` |
| One stolen admin session taking everything | In production the Backups page offers neither backup files nor the recovery kit (the keys that open backups and saved credentials); operators get them on the command line. `GRCPAL_WEB_BACKUP_DOWNLOAD=on` brings them back, and every download is then emailed to all admins |
| Someone else signing in with a reused or renamed email address | On Azure each person is linked to their Entra object ID and tenant at first sign-in; another Entra account with the same email is refused and logged until an admin unlinks it. The tenant allow-list is required in production |
| Requests that bypass the sign-in proxy (proxy mode) | The identity header is believed only with the proxy's shared secret (`GRCPAL_PROXY_SECRET`, compared in constant time); without it the request is refused |
| Forged caller address in logs | Only the address added by our own proxy (`GRCPAL_TRUSTED_PROXY_HOPS`) is recorded in sign-in events, the audit log and request logs; a client-sent `X-Forwarded-For` is ignored. Request log lines name the signed-in person, and one-time password-link tokens are replaced by `[redacted]` |

## Data handled

| Data | Where | Retention |
| --- | --- | --- |
| Evidence files and collector output | Blob `evidence` (write-once) | Retention period you set (default 730 days) |
| Users (email, name, role, last seen, password hash, auditor end date) | Table storage or SQLite | Until deleted by an operator; accounts are disabled, not deleted |
| Requests, uploads metadata, comments, overrides, acknowledgments | Table storage | Same |
| Audit log | Table storage, exported daily to blob | Same, plus write-once copies |
| Application logs | Log Analytics | 30 days |

Emails contain control descriptions, request instructions, file names and comment text; never
file contents.

## How the code and image are built (supply chain)

- Every change reaches `main` through a pull request that must pass tests, CodeQL (security-extended
  rules), dependency review and a workflow security check (zizmor). CODEOWNERS requires the
  maintainer's review for CI, Docker and deployment files.
- Pull requests and a nightly run also scan the code, the installed packages and the built image, and
  nightly a ZAP baseline crawls a demo container ([Security scanning in CI](#security-scanning-in-ci)).
- GitHub Actions are pinned to exact commit hashes and get the least permissions they need; checkouts do
  not keep the token on disk. Dependabot proposes updates after a 7-day cooldown.
- Releases need a maintainer approval, are built in CI with an SBOM and signed build provenance.
  Verify an image before you run it: `gh attestation verify oci://ghcr.io/seattlespicybite/grc-pal:<version> --owner seattlespicybite`

## Security scanning in CI

The workflow `.github/workflows/security-scan.yml` runs on every pull request, every night (06:17 UTC) and
on demand (Actions > Security scan > Run workflow). It only reads the repository (`permissions: contents:
read`), its actions are pinned to commit hashes, and the scanners it downloads are pinned to a version
and checked against a SHA-256 before they run. Its configuration lives in `.github/security/`. This is
automated scanning, not a penetration test.

| Check | What it looks at | Fails the run when | Results |
| --- | --- | --- | --- |
| bandit | Python code in `grcpal/` | a medium or high finding that is not in the baseline | job log |
| pip-audit | every package installed with `grc-pal[all]` (what the image ships) | any package has a known vulnerability | job log |
| Trivy | the image built from `Dockerfile` (OS and Python packages) | a high or critical vulnerability that has a fixed version | job log; full JSON report in the `image-scan-and-sbom` artifact |
| SBOM | the same image, CycloneDX format | never | `grc-pal-sbom.cdx.json` in the `image-scan-and-sbom` artifact |
| ZAP baseline (nightly and manual only) | a demo container on the runner (`GRCPAL_ENV=dev`, dev sign-in, sample data), crawled as the demo admin through the `X-Dev-Principal` header; passive rules only, no attacks, no form posts | any High alert | HTML and JSON reports plus the portal log in the `zap-baseline` artifact |

Artifacts are kept 30 days (Actions > the run > Artifacts). Release images also carry their own SBOM and
signed provenance (see above).

Run the same checks on your computer:

```
python -m venv /tmp/tools && /tmp/tools/bin/pip install --require-hashes -r .github/security/requirements.txt
/tmp/tools/bin/bandit -r grcpal --severity-level medium -b .github/security/bandit-baseline.json
PIPAPI_PYTHON_LOCATION=$(which python) /tmp/tools/bin/pip-audit --skip-editable   # in your dev environment
grcpal serve --demo   # then, in another terminal, with ZAP installed:
TARGET_URL=http://127.0.0.1:8000 REPORT_DIR=$PWD/reports ZAP_AUTH_HEADER=X-Dev-Principal \
  ZAP_AUTH_HEADER_VALUE='{"email":"alex.admin@example.com"}' ZAP_AUTH_HEADER_SITE=127.0.0.1 \
  zap.sh -cmd -autorun .github/security/zap-baseline.yaml
```

### Suppressing a finding

Fix the finding when you can. When it does not apply, suppress it in the file below with a reason
(why it does not apply, or why it can wait) and a review date, in the same pull request, so the owner
reviews it like any other change.

| Scanner | Where | Reason and review date |
| --- | --- | --- |
| bandit | Regenerate `.github/security/bandit-baseline.json` (`bandit -r grcpal --severity-level medium -f json -o ...`) and add a row to the table below. Prefer this to `# nosec` in the code. | in the table below |
| pip-audit | `--ignore-vuln <ID>` on the pip-audit step | comment on the same line |
| Trivy | `.github/security/trivyignore.yaml` | `statement` and `expired_at` (Trivy reports the finding again after that date) |
| ZAP | `rules:` in `.github/security/zap-baseline.yaml` (`threshold: "off"` for one rule) | comment on the same line |

Current bandit baseline (review by 2027-04-23):

| File | Rule | Why it is accepted |
| --- | --- | --- |
| `grcpal/catalog.py` | B506 yaml_load | False positive: the loader is `CSafeLoader`/`SafeLoader`, never the full loader. |
| `grcpal/xlsx.py` | B314 xml fromstring | Uploaded workbooks are untrusted, so the reader refuses any DOCTYPE or entity declaration before parsing and caps part size, total unpacked size and entry count (zip bombs). The parser is the standard library's expat, which does not fetch external entities. |
| `grcpal/configbundle.py` | B108 /tmp path | Default extract folder for a published catalog when `GRCPAL_CONFIG_DIR` is not set. Inside the container `/tmp` belongs to the app user alone. On a shared host, set `GRCPAL_CONFIG_DIR`. |

Updating the scanners: Dependabot proposes new bandit and pip-audit versions (`.github/security/requirements.txt`).
Trivy and ZAP are updated by hand: change `TRIVY_VERSION`/`ZAP_VERSION` in the workflow and the matching
SHA-256 from the Trivy release's checksums file or ZAP's `ZapVersions.xml`, after checking it matches the
file you downloaded. Do not use `aquasecurity/trivy-action` or `setup-trivy`: their tags were hijacked in
March 2026 (GHSA-69fq-xp46-6x23).

## How authorization is tested

`tests/test_authz.py` is the evidence that "who can do what" holds. For an auditor: pick any route in
`tests/authz_matrix.py`; the table says which roles may call it, and the suite proves it.

- **Completeness.** Every route of the app (dev and local sign-in modes) must be in the table, and every table
  entry must be a real route. A new route without an entry fails the suite.
- **Route by role.** Each route is called as: not signed in, admin, Control owner, a Control owner with nothing
  assigned, auditor, expired auditor and disabled admin. Allowed roles get through and a POST changes data.
  Refused roles are refused and a refused POST changes nothing: no table row (except events and sessions), no
  evidence file, no email. The data is reset to the same starting point after every change.
- **Object level.** A Control owner asks by ID for controls, requests, uploads, vendors, library versions and
  access reviews that are not theirs: refused. A second admin (not the library owner) cannot change control
  definitions or apply a matrix import.
- **Organizations.** Two organizations share one store. An admin of one asks for every ID-bearing route with the
  other's IDs, then every page is searched for the other's IDs and names. Nothing is shown or changed.
- **CSRF.** Every POST refuses a missing token, another person's token and a cross-site Origin.
- **Downloads.** Every file download is an attachment with a sandbox CSP, `nosniff` and a safe file name.
- **Empty forms.** Every POST with an empty form answers cleanly, never with a server error.

Limits: the suite uses demo-sized data and a stubbed network; it does not test the identity provider itself or
the infrastructure around the app.

## Your responsibilities (complementary controls)

- Keep evidence free of secrets and unnecessary personal data; redact screenshots.
- Review GRC-pal users quarterly (`/users.csv`) and disable leavers.
- Lock the evidence and backup retention policies after the first stable week.
- On Azure, require phishing-resistant MFA and a compliant device for the GRC-pal app with
  Conditional Access, and assignment to a group ([deploy-azure.md, Step 3b](deploy-azure.md)).
- Save the backup recovery kit in a password manager, apart from the backups; restore-test once a year.
- Deploy with `--alert-email` and act on its alerts (missed backup, lock or role changes).
- Restrict who holds Owner or Storage roles on the resource group; those people could remove the
  delete lock and delete the instance (but not locked evidence or backups).
- Rotate the sign-in secret yearly (`deploy.sh` does it) and keep `GRCPAL_SECRET` secret.
- Keep the image updated; watch the repository's security advisories.

## Accepted risks for the internal VM proof of concept

Local accounts lock after repeated failed sign-ins and offer optional two-step sign-in with an
authenticator app, but two-step sign-in is not enforced, and an address-based limit can be spread
over many addresses. Failed sign-ins and locks are recorded on the Logs page (category security).
Turn on two-step sign-in for every admin. For a portal reachable from outside the internal network,
use Entra sign-in (Azure Easy Auth or a proxy) with Conditional Access MFA, and keep local sign-in
for the break-glass admin only. Also:

- Use HTTPS; without it passwords cross the network in clear text. The Setup guide flags it.
- Whoever administers the VM can read the database and evidence folder. Limit VM admin access and
  include it in your own access reviews.

## Not included yet

Malware scanning of uploads (use Microsoft Defender for Storage malware scanning if licensed),
customer-managed keys, and private networking. See the roadmap in
[compare-and-roadmap.md](compare-and-roadmap.md).

**Why the Azure template has no private network or Key Vault (yet).**

- *Private endpoints for storage.* Storage already refuses keys and anonymous access; every request
  needs an Entra token for an identity with a storage role. A private endpoint would also block a
  stolen token used from the internet, which is real defense in depth. But it breaks three things the
  product relies on: collectors running in GitHub Actions (`--github-repo`) write to storage from the
  internet, admins run `grcpal users`, `audit verify` and restores from their own machine, and moving an
  existing Container Apps environment into a network means recreating it with a new URL. It adds
  roughly $15-25 a month in endpoints and DNS (check current pricing). Add it when collectors run inside Azure and admin work moves to
  a jump host or Azure Cloud Shell in the same network.
- *Key Vault for secrets.* The three app secrets live as Container Apps secrets: encrypted at rest,
  never shown in the portal or logs, readable only by people with write access to the app (the same
  people who could change the image anyway). Key Vault would add per-read access logs and rotation
  workflows, at the cost of another resource, more role assignments and a harder key-reuse step in
  `deploy.sh`. Worth it when several people administer Azure or your auditor asks for secret-access
  logs.

# Security design

GRC-pal holds sensitive material: evidence about how an organization is protected, staff names,
and sometimes screenshots of production systems. This page describes how it is protected and what
remains your responsibility. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Threats considered

| Threat | Protection |
| --- | --- |
| Someone outside the organization opens the portal | Sign-in at the platform edge (Easy Auth); only listed directories (`GRCPAL_ALLOWED_TENANT_IDS`); only people in the users table; optional enterprise-app assignment |
| A contributor reads other teams' evidence | Visibility is computed in the service for every request: only assigned or owned controls; raw evidence store hidden; 404 rather than 403 for hidden objects |
| An auditor changes something | Auditor role has no write paths; every write checks the role in the service layer |
| One customer sees another's data (hosted use) | Separate deployment and storage account per customer; in addition every record key and evidence path carries the tenant prefix and reads outside it are refused (see [saas-architecture.md](saas-architecture.md)) |
| Evidence altered or deleted after the fact | Write-once container with locked retention; SHA-256 manifest per run; uploads stored with their hash |
| Portal history rewritten | Hash-chained audit log, verified on demand and exported daily to write-once storage |
| Approving your own work | Uploader can never review their upload |
| Malicious upload (script, malware disguised as PDF) | Extension allow-list, magic-byte check, UTF-8 check for text, size limit, files served only as downloads with `Content-Disposition: attachment`, a sandbox CSP and HTML/SVG forced to `octet-stream` |
| Cross-site scripting | Server-rendered templates with auto-escaping; strict CSP with no inline script or style; no third-party scripts or fonts |
| Cross-site request forgery | Per-user HMAC token on every form (12-hour window) plus Origin check |
| Open redirect | Return URLs limited to same-site paths |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` |
| Email abuse | One message per recipient, no recipient lists exposed, subject sanitized, reminder rate limit, sender restricted to one mailbox (Exchange RBAC for Applications) |
| Stolen credentials in config | No storage keys (shared-key auth disabled); managed identities and GitHub OIDC; secrets only as Container Apps secrets |
| Leaked integration credentials | Saved credentials encrypted with AES-256-GCM, bound to tenant and field, write-only in the UI, scrubbed from logs and audit records |
| Server-side request forgery through checks (for example reading cloud metadata to steal the portal's identity) | Checks resolve and pin the address, refuse loopback, private, link-local, multicast and reserved ranges, re-check every redirect, limit time and size |
| Running code through the web portal | The portal never executes commands; command checks live only in the reviewed repository |
| AI data exposure or manipulation | See [ai-assistant.md](ai-assistant.md): off by default, confirmation, masking, injection fencing, human disposition, full record |
| Development shortcuts reaching production | `dev` sign-in refused when `GRCPAL_ENV=production`; production requires `GRCPAL_SECRET` |

## Data handled

| Data | Where | Retention |
| --- | --- | --- |
| Evidence files and collector output | Blob `evidence` (write-once) | Retention period you set (default 730 days) |
| Users (email, name, role, last seen) | Table storage | Until deleted by an operator; accounts are disabled, not deleted |
| Requests, uploads metadata, comments, overrides, acknowledgments | Table storage | Same |
| Audit log | Table storage, exported daily to blob | Same, plus write-once copies |
| Application logs | Log Analytics | 30 days |

Emails contain control descriptions, request instructions, file names and comment text; never
file contents.

## How the code and image are built (supply chain)

- Every change reaches `main` through a pull request that must pass tests, CodeQL (security-extended
  rules), dependency review and a workflow security check (zizmor). CODEOWNERS requires the
  maintainer's review for CI, Docker and deployment files.
- GitHub Actions are pinned to exact commit hashes and get the least permissions they need; checkouts do
  not keep the token on disk. Dependabot proposes updates after a 7-day cooldown.
- Releases need a maintainer approval, are built in CI with an SBOM and signed build provenance.
  Verify an image before you run it: `gh attestation verify oci://ghcr.io/seattlespicybite/grc-pal:<version> --owner seattlespicybite`

## Your responsibilities (complementary controls)

- Keep evidence free of secrets and unnecessary personal data; redact screenshots.
- Review GRC-pal users quarterly (`/users.csv`) and disable leavers.
- Lock the evidence retention policy after the first stable week.
- Restrict who holds Owner or Storage roles on the resource group; those people could delete
  the instance (but not locked evidence).
- Rotate the sign-in secret yearly (`deploy.sh` does it) and keep `GRCPAL_SECRET` secret.
- Keep the image updated; watch the repository's security advisories.

## Not included yet

Malware scanning of uploads (use Microsoft Defender for Storage malware scanning if licensed),
customer-managed keys, and private networking. See the roadmap in
[compare-and-roadmap.md](compare-and-roadmap.md).

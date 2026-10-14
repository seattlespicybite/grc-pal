# Changelog

All notable changes are listed here. The project follows [semantic versioning](https://semver.org/).

## [0.1.0] - unreleased

First public release.

### Program engine
- 77 controls covering all 61 SOC 2 Trust Services Criteria and 285 points of focus, tagged to ISO 27001:2022
- 16 collectors (Entra ID, Intune, Azure, GitHub) plus Prowler, Maester and testssl.sh ingestion
- Write-once evidence store with SHA-256 manifests; control health report
- `grcpal init` starter kit with GitHub Actions workflows; `grcpal publish-config`

### Portal
- Three roles: admin, contributor (assigned or owned controls only), auditor (read-only)
- Users table with bootstrap admins, optional group mapping, automatic access for assignees and roles.yaml owners
- Cycles with carry-forward and last-cycle evidence on requests and controls
- Evidence requests, uploads (validated), review with segregation of duties, comments
- Email via SMTP, Microsoft Graph or console outbox: assignment, upload, comment, review, reminders
- Reminder button with deep links; weekly overdue reminders; monthly recurring tasks
- Policies with versioned acknowledgments
- Admin overrides with justification and expiry, scoped to the cycle
- Auditor export zip per cycle with SHA-256 manifest
- Hash-chained audit log with verification; JSON logs with request IDs
- Tenant isolation for records and evidence; demo mode

### Configuration, multi-cloud, frameworks, AI
- Configuration page with per-section help, Test without saving, Save and apply; secrets encrypted (AES-256-GCM)
- Opt-in Setup guide: deployment health, command builder, every integration with save, validate or skip
- Logs page: persisted system events with keyword, level, category and date filters, CSV export, retention
- AWS collectors (IAM, CloudTrail, S3, GuardDuty/Config/Security Hub/EBS) and Google Cloud collectors (IAM, logging, storage, firewall)
- Framework registry: SOC 2 and ISO/IEC 27001:2022 built in, file and portal-defined frameworks, coverage pages
- Custom controls for any framework with owners, expected evidence and reference links
- HTTP and TLS checks with assertions, encrypted secret headers and protection against internal-network requests; command checks from the reviewed repository only
- AI assistant: per-control review and full mock audit with Claude, OpenAI-compatible endpoints (Ollama, vLLM, Azure OpenAI) or an offline demo reviewer; results kept as evidence and accepted or dismissed by an admin
- Background jobs page; collection runs from the portal and a daily scheduled job

### Deployment
- Single Bicep template and `deploy.sh` for Azure Container Apps (scale to zero), scheduled jobs
- Docker image, Docker Compose quickstart, CI, CodeQL, Dependabot, release workflow for GHCR

### Development
- Catalog and framework YAML is parsed with libyaml's C safe loader when available (about 9x faster load,
  test suite ~40 s to ~16 s); still the safe subset, a test proves Python object tags are rejected
- pytest defaults to short tracebacks; CLAUDE.md maps each area to its test file

# GRC-pal: notes for Claude

Open-source SOC 2 Type 2 compliance automation and evidence portal (SOC 2 first; ISO 27001 and other
frameworks are available but off by default). Python 3.11+, FastAPI,
server-rendered Jinja2, vanilla JS. AGPL-3.0. Owner: seattlespicybite (not a professional developer:
explain choices in plain words, keep changes small, never leave the test suite red).

## How to work in this repo (keep it cheap)
- Read only the files the task needs. Start from the map below instead of exploring the whole tree.
- Before changing code, say in 2-3 lines what you will change and which tests prove it.
- Write or update the test first when fixing a bug; make it fail, then fix.
- Large files (`service.py`, `features.py`, `app.py`, `routes_extra.py`, `settings.py`, `test_portal.py`):
  find the function with grep, then read only that line range. Never print a whole large file.
- Run the narrowest tests while working, the full suite once at the end:
  - one test: `python -m pytest -q tests/test_portal.py -k reminder`
  - after a failure, rerun only what failed: `python -m pytest -q --lf`
  - everything: `python -m pytest -q` (about 20 s) and `python -m pyflakes grcpal tests`
- Which tests to run for a change:

  | Changed | Run |
  | --- | --- |
  | catalog, frameworks, collectors, evidence, report, tasks, checks | `tests/test_framework.py` |
  | service, auth, store, audit log, uploads, users, routes in `app.py` | `tests/test_portal.py` |
  | settings, integrations, AI, logs, frameworks page, `routes_extra.py` | `tests/test_features.py` |
  | backup, restore, `store.TABLES` | `tests/test_backup.py tests/test_restore.py` |
  | Backups page, locations, retention | `tests/test_backups_page.py` |
  | migrations, `SCHEMA_VERSION`, `RELEASES` | `tests/test_migrations.py` |
  | templates, `app.js`, `app.css` | `tests/test_portal.py -k render` (also checks strict CSP), then the full suite |
- Show diffs or changed parts only; do not paste whole files or full test output back.
- Done means: full suite green, pyflakes clean, docs/CHANGELOG updated if behavior changed.
- Do not reformat or rename unrelated code. Do not add dependencies without asking.
- Commit only when asked. Use a branch and a pull request for anything non-trivial.
- Report at the end: what changed (files), test result line, anything left undone.

## Commands
- Install for development: `pip install -e ".[dev]"`
- Run locally with sample data: `grcpal serve --demo` (http://127.0.0.1:8000, dev sign-in)
- Real-browser test (optional, needs Playwright + Chromium): `python -m pytest -q tests/test_browser.py`
- Rebuild the Azure template after editing Bicep: `az bicep build --file deploy/azure/main.bicep --outfile deploy/azure/azuredeploy.json` (CI fails if it is stale)

## Map
| Area | Files |
| --- | --- |
| CLI | `grcpal/cli.py` |
| Catalog (controls, criteria, roles, tasks, policies) | `grcpal/catalog.py`, `grcpal/starter/catalog/*.yaml`, `grcpal/starter/policies/` |
| Frameworks (SOC 2 built in, ISO 27001 file, custom; SOC 2 only by default) | `grcpal/frameworks.py`, `grcpal/starter/frameworks/` |
| Knowledge base (evidence guidance per criterion and point of focus) | `grcpal/kb.py`, `grcpal/starter/kb/*.yaml`, routes `/kb` in `routes_extra.py`, tests `tests/test_kb.py` |
| Security calendar (admins only; activities seeded once from tasks.yaml, then edited in the portal; versioned schedules; append-only month records) | `grcpal/portal/calendar.py` (`CalendarMixin`), routes `routes_calendar.py`, templates `calendar*.html`, tables `calendaractivities`, `calendarversions`, `calendardecisions`, tests `tests/test_calendar.py` |
| Implementation notes per control | `features.py` (`save_control_note`), table `controlnotes`, `control.html` `#notes` |
| Collectors (Entra, Intune, Azure, AWS, GCP, GitHub) | `grcpal/collectors/*.py` (register in `NAMES` and `PLATFORMS`), clients in `grcpal/clients.py`, `grcpal/integrations/` |
| Evidence store (write-once, SHA-256 manifests, tenant namespace) | `grcpal/evidence.py` |
| Health report | `grcpal/report.py` |
| Backup file (.grcbak: encrypt, create, verify, restore, recovery kit) | `grcpal/backup.py` |
| Backup locations, retention, schedule; Backups page rules | `grcpal/backup_store.py`, `grcpal/portal/backups.py`, `routes_backups.py` |
| Data model versions, migrations, release rules, upgrade test | `grcpal/migrations.py`, `deploy/ci/upgrade_check.py` |
| Settings registry (Configuration page, Setup guide, encryption) | `grcpal/settings.py` (`SCHEMA`), validators in `grcpal/integrations/` |
| Custom checks (HTTP, TLS, command) and SSRF guard | `grcpal/checks.py` |
| AI review and mock audit | `grcpal/ai/providers.py`, `grcpal/ai/review.py` |
| Portal app and routes | `grcpal/portal/app.py`, `grcpal/portal/routes_extra.py` |
| Business rules (authorize + audit every write) | `grcpal/portal/service.py`, `grcpal/portal/features.py` |
| Storage (tenant isolation) | `grcpal/portal/store.py` (`TenantStore`, `SqliteStore`, `TableStore`) |
| Sign-in and roles | `grcpal/portal/auth.py` (local, easyauth, proxy, dev; roles admin/contributor/auditor, shown as Admin/Control owner/Auditor), local accounts and sessions in `accounts.py` + `routes_accounts.py` (tests: `tests/test_accounts.py`) |
| Audit log (hash chain), event log, jobs | `grcpal/portal/auditlog.py`, `eventlog.py`, `jobs.py` |
| Email | `grcpal/portal/mailer.py`, `notify.py`, `templates/email/` |
| Security headers, CSRF, upload validation | `grcpal/portal/security.py` |
| Templates and static | `grcpal/portal/templates/`, `grcpal/portal/static/app.css`, `app.js` |
| Demo data | `grcpal/portal/demo.py` |
| Deployment | `Dockerfile`, `docker-compose.yml`, `deploy/azure/main.bicep`, `deploy/azure/deploy.sh` |
| Tests | `tests/test_framework.py` (engine), `test_portal.py` (portal core), `test_features.py` (config, logs, frameworks, checks, AI), `test_backup.py`, `test_browser.py` |
| Docs | `README.md`, `docs/*.md`, `CHANGELOG.md` |

## Rules that must not be broken
1. Every write goes through `service.py`/`features.py`, checks the role there (not only in the template)
   and calls `self.audit(...)`. Hidden buttons are not authorization.
2. Application code uses `TenantStore` only, never a backend store directly. Evidence paths stay
   `<source>/<run>`; the namespace is added inside `EvidenceStore`.
   Only exception: `backup.py` reads every tenant through the raw backend. It is an operator tool
   (CLI and jobs), must never be called from portal routes, and records its runs in each tenant's audit log.
3. Strict CSP: no inline `<script>`, no `style="..."`, no `onclick` in portal templates (a test checks).
   Behavior goes in `static/app.js`, styles in `static/app.css`. Email templates may use inline styles.
4. Secrets: saved via `SettingsStore` (AES-GCM, bound to tenant and field), never echoed to the browser,
   logs, events or audit details. New secret fields use `kind="secret"`.
5. The portal never executes shell commands. Command checks only come from `catalog/checks.yaml` and run
   from the CLI/job. Outbound requests from checks use `checks.safe_request` (blocks private, link-local,
   metadata addresses; re-checks redirects).
6. AI output is advisory: stored as evidence (`ai_review/`), shown escaped, accepted or dismissed by an
   admin. Evidence sent to models stays inside `<evidence>` tags (`_fence`), emails masked by default.
7. Contributors (Control owners) see only assigned or owned controls (404 for others); auditors are read-only
   and refused after their `access_until` date. Passwords and tokens are stored only as hashes (`accounts.py`).
8. Keep `Referrer-Policy: same-origin` (no-referrer makes browsers send `Origin: null` and breaks forms).
9. No real organization names, emails or secrets in code, tests or fixtures. Use `example.com`.
10. Data model changes go through `grcpal/migrations.py`: additive only, numbered, `SCHEMA_VERSION` = 1 +
    number of migrations, never in a patch release, `breaking=True` only in a major release. Migrations get
    the table store only (never evidence). Add `"X.Y.Z": SCHEMA_VERSION` to `RELEASES` in every release.
    New tables need no migration but must be in `store.TABLES` (a test scans for them).

## Patterns to copy
- New integration: section in `settings.SCHEMA` with help text -> validator in `grcpal/integrations/` ->
  register in `integrations.validators()` -> collectors with `PLATFORM` -> tests with fake sessions.
- New collector: module with `PLATFORM`, `DESCRIPTION`, `run(ctx, run)` returning findings
  `{"key","title","severity","detail"}`; add to `collectors.NAMES`; test with canned data.
- New portal page: route in `routes_extra.register` (use `h.need`, `h.check_csrf`, `h.render`), logic in
  `features.py`, template extends `base.html`, add the path to the admin-pages render test.
- New framework: YAML file in `starter/frameworks/` (`id`, `name`, `requirements: [{id,title,group}]`).
- Knowledge base article: `starter/kb/<criterion>.yaml` (format in `grcpal/kb.py`), plain text, our own
  words (never AICPA text), `status: draft` until a person reviews it; `tests/test_kb.py` must stay green.
- Product focus: SOC 2 Type 2 (Security, Availability, Confidentiality). Do not add ISO or other
  framework features unless asked.

## Test fixtures
- `tests/test_portal.py::make_portal(tmp_path, tenant="acme", people=(...))` builds a portal with users
  ADMIN, ADMIN2, HR (owner of hr-lead), CONTRIB, AUDITOR and a console mailer (`portal.mailer.outbox`).
- `env` fixtures set `GRCPAL_AUTH_MODE=dev`; log in with the `X-Dev-Principal` header.
- Set `GRCPAL_JOBS_SYNC=1` so background jobs run inline in tests.

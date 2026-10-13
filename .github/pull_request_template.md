## What and why

## How it was tested
- [ ] `python -m pytest -q` passes
- [ ] New behavior has a test (permissions and tenant isolation included where relevant)
- [ ] Docs updated (README, docs/, CHANGELOG)

## Security and audit checklist
- [ ] Every new write is authorized in `service.py` (not only hidden in the UI) and recorded in the audit log
- [ ] Data stays inside the tenant store; no direct backend access
- [ ] No inline scripts or styles (strict CSP); user input is escaped
- [ ] No secrets, customer data or real organization names in code, tests or fixtures

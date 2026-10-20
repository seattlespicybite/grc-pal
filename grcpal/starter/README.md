# Our compliance program (GRC-pal)

This repository is our SOC 2 program as code, run with [GRC-pal](https://github.com/seattlespicybite/grc-pal).
Changes are made by pull request; the approval is the change record.

| Folder | What it holds | Who edits |
| --- | --- | --- |
| `catalog/controls.yaml` | Our controls, mapped to SOC 2 criteria, with owner, frequency and evidence source | Security lead |
| `catalog/roles.yaml` | Who holds each role (name, work email, GitHub user) | Security lead |
| `catalog/scope.yaml` | Audit scope, categories, platforms | Security lead, approved by the executive sponsor |
| `catalog/tasks.yaml` | Recurring manual control tasks | Security lead |
| `registers/` | Risks, vendors, exceptions | Owners named in each file |
| `policies/` | Policies in Markdown; staff acknowledge them in the portal | Policy owners, approved by the executive sponsor |
| `.github/workflows/` | Daily evidence collection, scanners, monthly tasks, publishing to the portal | Security lead |

## Everyday commands

```bash
pip install "grc-pal[portal] @ git+https://github.com/seattlespicybite/grc-pal"
grcpal validate                 # before every pull request
grcpal serve --base . --db portal.db   # try the portal locally on this catalog
```

Merging to `main` publishes the catalog, registers, policies, knowledge articles (`kb/`) and frameworks to the portal automatically.

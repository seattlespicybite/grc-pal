# Frameworks, custom controls and checks

## Frameworks

A framework is a list of requirements (ID, title, group). Controls map to requirements of any
number of frameworks, so one control can satisfy SOC 2 CC6.1, ISO 27001 A.5.15 and a customer's
security schedule at the same time.

| Source | How to add |
| --- | --- |
| Built in | SOC 2 (from `catalog/criteria.yaml`) |
| Files | `frameworks/*.yaml` in the starter kit (ISO/IEC 27001:2022 ships) and in your program repository |
| Portal | **Frameworks > New framework**: paste lines of `ID | title | group` |

File format:

```yaml
id: hipaa-security           # lowercase, used in mappings
name: HIPAA Security Rule
version: "2013"
requirements:
  - {id: "164.308(a)(1)", title: Security management process, group: Administrative safeguards}
  - {id: "164.312(a)(1)", title: Access control, group: Technical safeguards}
```

Map controls in `catalog/controls.yaml` with `mappings: {hipaa-security: ["164.312(a)(1)"]}`
(SOC 2 also reads `criteria:`, ISO 27001 also reads `iso27001:`). The **Frameworks** page shows
coverage per requirement, and the AI mock audit can run against any framework.

## Custom (manual) controls

**Controls > New control** creates a control without editing YAML:

- ID, title, description, frequency;
- mappings to one or more frameworks (requirement IDs are checked);
- owner role or owner emails (owners get contributor access and see the control);
- the evidence you expect (shown to contributors and in reminder emails);
- reference links to documents kept elsewhere (SharePoint, Confluence, a vendor portal).

Custom controls behave like catalog controls: requests, uploads, reviews, comments, reminders,
overrides, AI review, export. Retire one instead of deleting it; history stays. To version-control
them, copy them into `catalog/controls.yaml` when the program matures.

## Checks: pull data from a URL and test it

A check runs on a schedule (daily, weekly or manual), stores the request and response as write-once
evidence, and turns failed assertions into findings on the control.

| Type | Created in | What it does |
| --- | --- | --- |
| `http` | Portal or `catalog/checks.yaml` | GET, HEAD, POST or OPTIONS to a URL with optional headers (secret header values are encrypted and redacted in evidence), then assertions |
| `tls` | Portal or `catalog/checks.yaml` | Certificate expiry and TLS version of a host |
| `command` | `catalog/checks.yaml` only | Runs a program in the collection job or `grcpal checks run` and tests its exit code and output |

Assertions (one per line in the portal form, `kind | path | op | value`):

```
status | 200
contains | "indicator": "none"
json_path | status.indicator | equals | none
json_path | open_alerts | le | 0
header | strict-transport-security | contains | max-age
regex | Last backup: 2026-
max_ms | 2000
```

Operators: `exists`, `equals`, `not_equals`, `contains`, `matches` (regex), `lt`, `le`, `gt`, `ge`.

### Why the portal cannot run commands or reach internal addresses

- **No commands from the web page.** A command typed in a browser would run with the portal's
  identity, which can read every secret and all evidence. Commands are allowed only in
  `catalog/checks.yaml`, where every change is a reviewed pull request, and they run in the
  collection job with a minimal environment.
- **No requests to internal networks.** URLs are resolved first; loopback, private, link-local
  (including the cloud metadata address 169.254.169.254, which would hand out the portal's cloud
  credentials), multicast and reserved addresses are refused. The connection is pinned to the
  checked address (no DNS rebinding) and every redirect is checked again. On an internal-only
  self-hosted deployment, `GRCPAL_CHECKS_ALLOW_PRIVATE=1` lifts this rule.

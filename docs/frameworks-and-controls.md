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

### Frameworks in use: one at a time when that is all you need

Most organizations start with one framework. An admin chooses which frameworks are **in use** on
the **Frameworks** page (**Turn on** / **Turn off**), or with the `GRCPAL_FRAMEWORKS` setting
(Configuration > Organization, one ID per line; empty means all). Each change is in the audit log
(`framework.on`, `framework.off`), and at least one framework stays on.

- **One framework in use** (for example only SOC 2): the portal is a single-framework tool. The
  menu shows **SOC 2 criteria** instead of Frameworks, lists and control pages show only SOC 2
  references, and there is no switcher. Frameworks that are off keep their mappings and evidence;
  turning one back on brings everything back.
- **Several in use**: a **Showing** switcher appears at the top of the menu: one framework at a
  time, or **All** to see shared controls with a column per framework. The choice is a display
  preference saved in the browser. It never changes what a person may see: control owners still
  see only their own controls.

### SOC 2 view

**SOC 2 criteria** groups the criteria into families (CC1 Control environment ... CC9 Risk
mitigation, then Availability, Confidentiality, Processing Integrity and Privacy). Each family shows
how many controls it has and their status; open it to see its criteria. Categories that are not in
the report scope (`catalog/scope.yaml`) are shown as *Not in scope*.

A criterion page lists its controls with **how each is evidenced** (automatic, hybrid or manual,
and from which connected source). Sources that are switched off for this organization, such as AWS
when only Azure is used, are not shown. Use **‹ ›** to move to the previous or next criterion.

Open a control from a criterion and the page remembers it: the trail shows
*SOC 2 / CC6 / CC6.1*, **Back to CC6.1** and **All SOC 2 criteria** take you back, **‹ ›** moves
through that criterion's controls, and the criterion you came from is highlighted. Open a control
from the **Controls** list and **Back to controls list** keeps your filters. The list can be
filtered by SOC 2 family, criterion and evidence type.

Criterion titles are short paraphrases for navigation; the AICPA publication is authoritative.

## Changing a control (control library owner)

The control library owner (see [roles.md](roles.md)) can change any control from its page with
**Edit control**: title, description, owner role, **named owners** (one or more people, each of
whom can see the control and upload evidence), framework mappings (move a control between SOC 2
criteria by removing one ID and adding another), and additional evidence people upload. Evidence
collected automatically is listed but changed in the catalog or Configuration.

- **A reason is required** for every save. It is shown to auditors.
- **Every version is kept** with who, when, why, and the before and after values (**Definition
  history** on the control page, `control_definition_changes` in the auditor export).
  **Reset to the starter definition** is recorded the same way.
- **Coverage check**: if the change would leave an in-scope criterion with no control, GRC-pal names
  the criterion and asks you to confirm. The accepted gap is in the audit log.
- **Upgrades keep your edits.** Edits are stored as a layer over the starter catalog. If a GRC-pal
  release later changes the starter text of a control you edited, your version stays in use and
  the control page says the starter changed, so you can compare and decide.

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

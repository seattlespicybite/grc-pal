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
(Configuration > Settings > Organization, one ID per line; empty means SOC 2 only, the default for a new
installation). Each change is in the audit log
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

### Report scope and deferred categories

`catalog/scope.yaml` lists the categories tested in the next report. The starter scope is
**Security, Availability and Confidentiality**; Processing Integrity and Privacy are listed under
`deferred_categories`. Controls that serve only deferred categories are hidden from the
**Controls** list (the count of hidden controls is shown with a **show** link), and the dashboard
shows only in-scope categories. Choosing a deferred category in the list filter shows its controls.
To add a category to the report, move it to `in_scope_categories` through a pull request; that
history is scope-change evidence.

## Implementation notes: "How we meet this control"

Every control page has a **How we meet this control** box for the organization's own explanation:
which policy section covers it, which system or procedure operates it, when it happens. For
example: *"Covered by Information Security Policy section 6. Access reviews run in January, April,
July and October."* It is written for the next person who runs the program and for the auditor.

- **Who can edit:** admins, and the control's owner for their own controls. Auditors and other
  control owners can read but not edit. The rule is checked on the server, not only hidden in the page.
- **History:** every save is a new version; earlier versions stay visible under **Earlier versions**.
- **Audit:** each save writes `control.note` to the audit log with the version, length and SHA-256
  of the text (not the text itself).
- **Export:** the cycle export includes `implementation_notes.csv` with every version.
- Notes are plain text (up to 5,000 characters). Do not put passwords or other secrets in them.

## Vendors

**Vendors** is the vendor register for SOC 2 CC9.2: every vendor that stores, processes or can reach
company or customer data. It replaces editing `registers/vendors.yaml` by hand: when the page opens for the
first time, an admin clicks **Import from vendors.yaml** to copy those vendors in (every original field is
kept; nothing already in the register is overwritten).

**Each vendor** has a tier (critical, high, moderate, low), the data or systems it can reach, a status
(Onboarding, Active, Offboarding, Offboarded, Not approved), whether it is a subservice organization for
our SOC 2 system description, contract and report details, and its contacts:

- **Internal owner** (name, title, email, phone): who maintains the contract and who to call when the vendor
  does not answer. A **backup** covers when the owner is away. If the owner's or backup's email belongs to a
  GRC-pal user, that person sees this vendor (and only their vendors) and can work on it.
- **Vendor contract contact**, **how to open a support ticket** and **how to request their SOC 2 report,
  ISO certificate or a questionnaire**, with links (https only).

Auditors never see contact details: they are removed on the server, left out of the export, and contact
changes are written to the audit log without the values.

**One review a year.** Every active vendor is reviewed 12 months after its last review. The tier decides what
the review needs: critical and high need a SOC 2 report or ISO certificate and our returned questionnaire,
plus the CUECs mapped for SOC 2 reports; moderate needs one of them; low needs only an NDA or standard terms.
The owner uploads the files and answers four plain questions, then clicks **Mark my part done**. An admin
records the report details and any exceptions in the vendor's report, maps the CUECs (complementary user
entity controls: things the vendor's auditor assumes we do) to our controls, and signs off. GRC-pal lists
anything the tier still needs; signing off anyway requires a note saying why, and both go to the auditor.
An admin cannot sign off a review they submitted while another admin is active. Signed-off reviews never
change. If the attached report's period ended more than 12 months ago, it shows as an open item.

**Onboarding and offboarding.** New vendors (added by an admin or requested by a Control owner) start in
Onboarding with a checklist: tier, data and owner set; report or questionnaire attached; contract terms
checked. An admin approves the vendor before data is shared. **Start offboarding** opens a checklist (sign-in
removed, keys revoked, data returned or deleted, contract ended); each item needs a note and the offboarding
needs at least one evidence file (for example the vendor's deletion letter) before it can be closed (VEN-05).

**Security questionnaire.** **Vendors > Security questionnaire** holds our own questionnaire (47 starter
questions in 10 sections, written in plain language and linked to the SOC 2 criteria they help assess).
Admins edit a draft: add, edit or remove questions and sections, move questions up and down, across
sections or with **Move to section**. Nothing changes for anyone else until **Save as version N** (a reason
is required). Every version is kept and visible to auditors. Each question keeps a permanent ID (`Q-017`)
when it moves, and the display number (2.3) is recalculated. **Download (.xlsx)** gives a blank file; on a
vendor's Review tab, **Download our questionnaire** puts the vendor's name and a return date on the cover
sheet and records which version was sent. The Excel file has a locked Questions sheet with Answer and
Comments columns to fill in and Yes/No/N/A lists. Upload the returned file to the vendor's review.

**Reminders.** The weekly `grcpal remind --overdue` job also emails the internal owner, backup and admins 30
days before a vendor's review is due (once) and on every run while it is overdue. The security calendar
shows a row with each month's vendor reviews.

**Importing many vendors (CSV).** **Vendors > Import from CSV** adds vendors from a spreadsheet saved as CSV
UTF-8 (download the template on that page; only `name` and `tier` are required). Import only ever **adds**:
GRC-pal compares each row with the register and shows the difference before anything happens:

| Row | Shown as | What happens |
| --- | --- | --- |
| Not in the register | New | Added if you tick it ("Select all new vendors" helps with long lists) |
| Same name (ignoring Inc, LLC, Ltd...) or a shared domain | Already in the register, with the differences | Nothing. Edit the vendor by hand if the file is right |
| A name close to one in the register ("Githab" and "GitHub") | Similar | Added only if you tick it as a different vendor |
| No name, no or unknown tier, bad email, listed twice | Problem, with the reason | Skipped; fix the file and upload it again |
| In the register but not in the file | Listed for information | Nothing. Use offboarding to end a relationship |

Imported vendors are **Active, never reviewed**: they are already in use, so they skip onboarding. Tick
**Spread their first reviews over the next 12 months** so 80 reviews do not all fall due at once (critical
vendors come first, the first one 30 days out). The uploaded file is stored write-once as evidence of where
the population came from, and the import, the rows picked and each vendor added are in the audit log.
Applying reads the stored file again and checks the register again, so a vendor added by someone else in the
meantime is never duplicated. A preview can be applied once, within 7 days.

**Small vendors without SOC 2 or ISO 27001.** SOC 2 does not require every vendor to have an audit report; it
requires that we assess the risk in proportion to it, act on it, and that someone accountable accepts what is
left. On each onboarding check and annual review of a vendor that is not low tier, record the **assurance
level**: Independent audit, Evidence reviewed (our questionnaire with proof, and a call), Self-attested, or None.

- **Two questionnaires.** **Vendors > Security questionnaire** now has the full questionnaire and a short
  **Small vendor essentials** one (18 questions; most ask for proof such as a screenshot of the MFA setting).
  Both are edited and versioned the same way; each review records which one and which version was sent.
- **Baseline controls.** A critical or high vendor without an independent audit gets 13 baseline controls to
  mark Met, Met another way, Not met or Not applicable (a note is required for anything but Met): MFA, own
  accounts, encrypted devices, our data kept in our systems, least data, no copies on personal devices,
  backups, breach notice, no unapproved subcontractors, deletion at the end, data location, sanctions
  screening, and continuity if the vendor stops working. The strongest control for payroll and HR data is
  having them work inside accounts we own, so our data never sits in their systems.
- **Risk acceptance.** If such a vendor is self-attested (or None), or a baseline control is Not met, the
  business owner accepts the remaining risk in writing: upload their email or signed note as "Risk acceptance",
  then record who accepted, what and why, and until when (at most 12 months).
- **Review interval.** Critical and high vendors without an independent audit are reviewed every **6 months**
  instead of 12, and never later than their risk acceptance's end date.

**Offboarding: sign-in removed.** Add the vendor's Entra ID apps and its email domains on the vendor (Edit
vendor). During offboarding, **Check now** looks in the latest `entra_apps` and `entra_users` collector runs
for those apps still enabled and for enabled accounts (guests included) from those domains. GRC-pal does not
call Entra ID for this; it reads the collected evidence, so run the collectors first (runs older than 7 days are
flagged). If nothing is left, the checklist item "Sign-in removed" is ticked with the runs named as evidence.
Accounts in systems outside Entra ID are still checked by hand with a note and a screenshot.

## Security calendar

**Calendar** (admins only) is one page for the year: activities on the left, January to December on the
right. It lists every recurring manual activity and, below them, every collector and check that is
switched on. **Hide automated** removes the automated rows. Only activities linked to a control that maps
to a framework in use appear (for SOC 2, an in-scope criterion), so Privacy activities stay hidden while
Privacy is out of scope.

**Starter activities.** The first time the calendar opens it copies the activities in
`catalog/tasks.yaml` (40, including monthly ticket samples, quarterly access reviews and annual plan
reviews). From then on they live in GRC-pal: edit, retire or delete them, and add your own with
**+ New activity**.

**Editing an activity** (click its name): name, owner (for information), steps and expected evidence,
the months it is due (tick any months), the due day (1st, 15th or last day) and the linked controls
(tick as many as apply; type in the filter box to find them; out-of-scope controls are marked). Months you
tick show up straight away, including earlier in the year. Unticking a month removes it only from months
still ahead: a month already past stays, so a missed activity cannot disappear. If those past months were
never really planned (for example, an old schedule you no longer use), tick **Also remove unticked months
from earlier months and years where nothing was recorded** when you save. Months with a recorded status
always stay, because they are evidence, and the change is kept in the audit log. To add an activity for one
month only, click **+** in that month's empty cell. Rows are grouped into Manual and Automated; drag them (or
use ↑ ↓) to arrange them. Activities you create are always shown, even when linked only to out-of-scope
controls.
**Retire** hides an activity from now on and keeps everything recorded. **Delete** is only possible while
nothing has been recorded for it.

**Recording a month** (click the cell): a small window opens on top of the calendar. Pick the status and
save; the calendar reloads at the same row. **Open the full page** in that window shows the linked
controls, evidence uploaded that month and the full history. Clicking **+** opens the same window to add a
one-off month.

| Status | Meaning |
| --- | --- |
| Planned | Not done yet. Shown as **Past due** (amber) once the due date has passed inside the observation period |
| Performed | Done, with the date it was performed |
| Missed | Did not happen; a note explaining why is required. The auditor will treat it as an exception |

GRC-pal never marks anything Missed by itself. The same page can move the due date to any day; the
original date stays on record (a moved cell shows `*`). Every save is a new entry in the history and in
the audit log, nothing is overwritten. The page also links each control's "How we meet this control"
notes, its evidence guide and the evidence uploaded that month.

**Automated activities** take their monthly status from real runs:

| Status | Meaning |
| --- | --- |
| Passed | The latest run that month worked and found nothing to fix |
| Findings | The run worked and found items to follow up; the control is doing its job |
| Failed | The run itself broke (for example an expired secret). Fix it and run again: the month shows the latest run, and the failure stays in the run history |
| Not run | No run that month, inside the observation period |

Past-due warnings start on the first audit cycle's start date: set it on **Cycles and export > Change the
current cycle** to the first day of your observation period.

## Knowledge base

The **Knowledge base** tab has one article per SOC 2 criterion with a section per point of focus:
**what the auditor tests**, the **evidence standard**, **good examples**, **common mistakes**, and
**how often and sampling**. Every Security, Availability and Confidentiality criterion is covered.
Each point of focus on a control page, each criterion page and each evidence request links to the
matching section, so a control owner can see what good evidence looks like before uploading.

- Articles are guidance only; the auditor decides what is sufficient. Each article shows
  **Draft** until a person has reviewed it (`status: reviewed`, `reviewed_by`, `last_reviewed`).
- Articles are YAML files in `starter/kb/<criterion>.yaml`. To adapt one, put a file with the same
  name in your program repository's `kb/` folder; it replaces the starter article. Text is plain
  (no HTML or Markdown) and shown escaped.
- `grcpal validate` checks every article (known criterion and point-of-focus IDs, required fields,
  reviewer details on reviewed articles) and warns about in-scope points of focus without guidance.
- Articles are written in GRC-pal's own words and do not reproduce the AICPA text.

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

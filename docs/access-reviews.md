# Access reviews

Every quarter, the people who manage others confirm that each of their people still needs the access they have, in
every application. GRC-pal runs that review (SOC 2 CC6.2 and CC6.3, control IAM-05) and keeps the proof.

GRC-pal reads the accounts itself from Microsoft Entra ID / Microsoft 365, Entra enterprise (SSO) applications, Azure,
GitHub, your own applications through their REST API, and GRC-pal itself. Anything else (a database, an internal tool
reachable only inside your network) comes in as a CSV export. Every source is read-only.

## How it works

1. **An admin lists the applications in scope once** (*Access reviews > Applications*, see below) and tests each one.
2. **The admin starts a review** on *Access reviews*: a name, a due date, the applications to read, and optionally a CSV
   for anything else. GRC-pal reads every application in the background and takes managers from Entra ID. If one
   application cannot be read completely, or any CSV row is wrong, nothing is created and the reason is shown, so a
   review never starts from a partial list.
3. **Each account goes to one reviewer: the account holder's manager.** Accounts with no manager, service accounts and
   accounts whose manager is the account holder go to the **application owner**, or wait for an admin to assign a
   reviewer when the application has no owner. Nobody can review their own account, owners included.
4. **Managers review on one screen.** A manager signs in, opens the review and sees only their own people's accounts across
   all applications. For each account they choose *Keep*, *Remove access* or *Change access* (with a comment saying what
   should change). Accounts with a flag come first and are always decided one by one:
   *admin-type role*, *no MFA*, *no sign-in for 90+ days*, *disabled but still listed*, *service account*.
   One button keeps every account without a flag.
5. **Managers sign off.** When all their accounts are decided, the manager signs off. That locks their decisions.
   An admin can reopen a sign-off if a manager made a mistake. Every change is in the audit log.
6. **An admin carries out and confirms the removals.** Do the removal in the application, then confirm it in GRC-pal and
   say how it was done. A decision without follow-through is a finding in most audits.
7. **The admin closes the review.** It needs a reviewer and a decision for every account, a sign-off from every manager, and
   confirmed removals (or a written reason). Closing stores the decisions file write-once in the evidence store.

## Applications

Add each in-scope application once and choose where its accounts come from. Use **Test** after saving: it reads the
application and shows counts only (accounts read, how many carry an email, which fields were filled), never the accounts.

| Source | What is read | What it needs |
| --- | --- | --- |
| Microsoft Entra ID / Microsoft 365 | Every user and guest: enabled, last sign-in, MFA registered, directory admin roles, Microsoft 365 license yes/no | The Microsoft connection (Configuration). Last sign-in and MFA need AuditLog.Read.All and Entra ID P1/P2; without them the review still starts and says what is missing |
| Entra enterprise application | Everyone assigned to an app people sign in to with Microsoft (for example monday.com or the WorkOS dashboard when they use Entra single sign-on), groups expanded to people, the app role of each | Its Application (client) ID. **“Assignment required” must be on** in Entra, otherwise everyone can sign in and the list is refused. GroupMember.Read.All |
| Azure | Every role assignment on the subscriptions in scope, groups expanded to people, service principals as service accounts, deleted identities still holding a role | Reader (Configuration), GroupMember.Read.All |
| GitHub organization | Owners, members, outside collaborators, bots as service accounts, two-factor status | The GitHub token with the organization permission **Members: read**. Two-factor status shows only when the token's owner is an organization owner |
| Custom application (REST API) | Any application with a JSON user list over HTTPS: your own product's admin API, monday.com, WorkOS and similar | URL, authentication, paging and a field map (below). Ready-made settings for monday.com and WorkOS |
| This GRC-pal portal | Its own users and roles. GRC-pal holds your evidence, so its access is in scope | Nothing |
| Other application (CSV) | Whatever you upload when you start the review | A CSV export |

**Managers** come from Entra ID direct reports. Microsoft does not let an application identity read a user's manager
directly, but it can list each person's direct reports with User.Read.All, which gives the same answer. A people file
uploaded with the review wins over Entra ID.

**Identity map.** Some applications have no work email on their accounts (GitHub logins, user names). Upload a CSV with
the columns `account_id,email` on the application's page once; it links those accounts to people every quarter. Accounts
that stay unmatched go to the application owner.

### Custom applications

For an application you built, or a SaaS without a ready-made connection, describe its user-list API:

- **Request:** the HTTPS URL, GET or POST (POST for GraphQL APIs such as monday.com, with a fixed JSON body; `{page}` and
  `{cursor}` are replaced), and how the token is sent: `Authorization: Bearer`, or a header you name such as `X-API-Key`.
- **Paging:** none, page numbers (until a page is empty), a cursor from the response, a next-page link in the response, or
  a `Link` header. Every page is read; more than 200 pages or 2,000 accounts stops the pull.
- **Field map:** dotted paths into one user, for example `profile.email`. Status accepts true/false (start with `!` to
  invert, e.g. `!disabled`). Role can be a path or flags such as `is_admin:Admin, is_guest:Guest`.

**WorkOS** is a service your product may use so that *your customers* can sign in with their own single sign-on. Two
different groups of people can be involved. Your staff who can sign in to the WorkOS dashboard are in scope for your own
review: read them as an Entra enterprise application if the dashboard uses Microsoft sign-in, or use a CSV. Your
customers' users who sign in to your product through WorkOS are usually managed by your customers; review them only if
your system description says you manage them (the WorkOS ready-made settings read them).

## Who needs a portal account

Managers must be able to sign in. Add them as **Control owners** (`grcpal users add manager@example.com --role contributor`,
or the Users page). A Control owner sees only the accounts assigned to them in a review; nothing else changes for them.
When you start a review, GRC-pal tells you which managers in the file have no portal account yet.

## The accounts file

One row per account. Only `app` and `account_id` are required; the rest improves the review. Download a template from the
*Access reviews* page. Column names are not case sensitive.

| Column | Meaning |
| --- | --- |
| `app` | Application name, for example `GitHub` |
| `account_id` | The account's user name or ID in that application |
| `email` | The person it belongs to. Leave empty for service accounts |
| `name` | Display name |
| `status` | `active`, or `disabled`, `suspended`, ... for accounts that are still listed but switched off |
| `role` | The role or permission level in the application. Roles containing admin, owner, root, maintain or global are flagged |
| `last_login` | A date such as `2026-09-30`. Accounts idle for 90 days or more are flagged |
| `mfa` | `yes` or `no` |
| `is_service_account` | `yes` for non-person accounts |
| `manager_email` | The person's manager, who will review the account |

If you do not have manager data in each export, upload a second **people file** with the columns `email` and `manager_email`
(for example exported from Entra ID). It fills in the managers for every account that has an `email`.

Limits: 2,000 accounts per review (split larger exports by application), 25 MB per file, UTF-8 text. Accounts are never
sent anywhere else: no AI is involved in access reviews.

## What an auditor tests

- **Completeness of the list.** The exact list reviewed (`population.csv`, every source together) is stored write-once with
  its SHA-256, shown on the closed review, next to each source's accounts and record count (`source_<application>.json`),
  the managers used and any uploaded file as received. Compare a source with a fresh export from the application.
- **Who reviewed what.** The decisions file (*Download decisions*) lists every account, its reviewer, the decision, the
  comment, who decided and when, and whether the removal was confirmed.
- **Independence.** No reviewer reviewed their own account. The audit log shows each decision, sign-off, reassignment and
  confirmation with the application and entry number, but never names or email addresses.
- **Follow-through.** Each removal or change has a confirmation with how it was done, or the review records why it closed
  with open items.
- **Tamper evidence.** The audit log is hash-chained (*Audit log > Verify integrity*), and a closed review returns the stored
  file, not a rebuilt one.

## Security notes

- Tenant separation: reviews live in the tenant's own tables and evidence namespace. A review of another organization is
  never visible and looks like it does not exist.
- Managers see only their own accounts; a review they have no accounts in returns *not found*. Auditors read everything and
  change nothing. Admins cannot decide for a manager.
- Exports neutralize spreadsheet formulas (cells starting with `=`, `+`, `-` or `@`).
- Account lists are personal data about employees. They sit in the same storage as the rest of the portal and are included in
  its encrypted backups.
- Connections are read-only. GRC-pal never removes access itself; removals stay with the application's admins.
- A custom application's token is encrypted (AES-GCM, bound to the organization and that application), never shown again,
  never written to logs or the audit log, and sent only to that application's host. Redirects are not followed, next-page
  links must stay on the same host, and requests to internal networks and cloud metadata addresses are blocked. An
  operator who must reach internal applications can set `GRCPAL_CHECKS_ALLOW_PRIVATE=1`; otherwise use a CSV export.
- An application test stores counts only. The evidence keeps each source's normalized accounts and the request addresses
  without query strings, so a token placed in a URL never reaches the evidence.

## Not in this version yet

- Email to managers when a review starts. For now, tell them or use the *Access reviews* menu entry, which shows a count.
- Sending privileged accounts to the application owner instead of the manager (today only accounts without a manager go to the owner).
- Scheduling a review every quarter.
- Reading GitHub SAML identities to match logins to people without an identity map.

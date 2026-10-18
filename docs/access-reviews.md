# Access reviews

Every quarter, the people who manage others confirm that each of their people still needs the access they have, in
every application. GRC-pal runs that review (SOC 2 CC6.2 and CC6.3, control IAM-05) and keeps the proof.

It works for any application you can export a user list from: GitHub, Slack, a database, a SaaS admin console, and
also accounts that are not in Entra ID. Automatic collection for specific applications is planned; the CSV import
works today for all of them.

## How it works

1. **An admin exports the user list** from each application and puts them in one CSV (see below).
2. **The admin starts a review** on *Access reviews*: a name, a due date and the CSV. If any row is wrong, nothing is
   imported and the message says which rows to fix, so a review never starts from a partial list.
3. **Each account goes to one reviewer: the account holder's manager.** Accounts with no manager, service accounts and
   accounts whose manager is the account holder have no reviewer. An admin assigns one. Nobody can review their own account.
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

- **Completeness of the list.** The accounts file as received is stored write-once with its SHA-256, shown on the closed
  review. Compare it with a fresh export from the application, and check the record count.
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

## Not in this version yet

- Automatic collection of accounts for Entra ID, GitHub and others (the collectors already run; feeding a review from them is next).
- Email to managers when a review starts. For now, tell them or use the *Access reviews* menu entry, which shows a count.
- Sending privileged accounts to the application owner instead of the manager.
- Scheduling a review every quarter.

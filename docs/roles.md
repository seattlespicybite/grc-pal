# Roles and permissions

Each person has exactly one role in an instance. Roles live in GRC-pal's own users table, not in
the identity provider, so an admin can change them on the **Users and roles** page and every
change is in the audit log. Every rule below is enforced in the service layer (`service.py`),
not only by hiding buttons.

The three roles are **Admin**, **Control owner** and **Auditor**. (Control owner is stored as
`contributor` in data, exports and the CLI, so older data needs no change.)

**Control library owner** is an extra responsibility held by exactly one admin (it can be the same
person who runs everything else). Only the library owner can change what a control *is*: its owners,
title, description, evidence wanted and framework mappings, plus custom controls and custom
frameworks. Other admins operate the program: requests, reviews, reminders, users. This separates
the person who defines controls from the people who operate them, which auditors look for.

- The holder hands the role over on **Users and roles** (**Hand over control library**).
- If nobody holds it (for example the holder left), any admin can give it to an active admin.
- It is cleared automatically when the holder stops being an admin or is disabled.
- Every change is in the audit log (`library_owner.set`, `library_owner.cleared`).

## Permission matrix

| Action | Admin | Control owner | Auditor |
| --- | :-: | :-: | :-: |
| Dashboard and control health | ✓ | own controls via My work | ✓ |
| See a control | all | only assigned or owned | all |
| Criteria and points of focus pages | ✓ |  | ✓ |
| Browse the raw evidence store | ✓ |  | ✓ |
| Download portal uploads | ✓ | for controls they can see | ✓ (logged) |
| Assign work; change people, due date or instructions on open requests; cancel requests | ✓ |  |  |
| Upload evidence | ✓ | own requests and owned controls |  |
| Comment | ✓ | own requests and owned controls |  |
| Review (approve or return) | ✓, never own upload |  |  |
| Send reminders | ✓ |  |  |
| Override control status | ✓ (justification, expiry, current cycle) |  |  |
| Acknowledge policies | ✓ | ✓ |  |
| Document library: upload versions and templates, edit details and numbers, delete and restore | ✓ |  |  |
| Document library: send for approval, reassign or withdraw a request | ✓ |  |  |
| Document library: approve or send back a version | named approver only, never one they uploaded or sent; **Approve directly** as backup (never own upload while another admin is active) | named approver only, sees just that version while it waits | |
| Document library: download | everything | approved versions (and the version waiting for their approval) | everything (logged) |
| Document library: register and Excel export | ✓ |  | ✓ (logged) |
| Users and roles | ✓ |  | user list CSV |
| Start a cycle | ✓ |  |  |
| Security calendar: view, edit activities, record Performed or Missed, CSV | ✓ |  | (cycle export only) |
| Vendors: see the register and vendor pages | all | only vendors where they are the internal owner or backup | all, without contact details |
| Vendors: add a vendor | ✓ | request one (starts in Onboarding) |  |
| Vendors: edit tier, status, contract and report details, CUECs, exceptions; start offboarding | ✓ (reason required) |  |  |
| Vendors: edit contacts and support notes | ✓ | own vendors, except who the owner and backup are |  |
| Vendors: upload files, answer review questions, checklist notes, download the questionnaire for a vendor | ✓ | own vendors |  |
| Vendors: sign off a review, approve or reject a new vendor, close offboarding | ✓, never a review they submitted while another admin is active |  |  |
| Security questionnaire: view and download | ✓ | ✓ | ✓ (every version) |
| Security questionnaire: edit and save a new version | ✓ |  |  |
| Audit log and integrity check | ✓ |  | ✓ |
| Export zip per cycle | ✓ |  | ✓ |
| Configuration page and Setup guide | ✓ |  |  |
| Logs page and background jobs | ✓ |  | ✓ |
| Frameworks and coverage; turn frameworks on or off | ✓ |  | ✓ (read) |
| Change control definitions (owners, wording, evidence wanted, mappings); create, edit, retire custom controls and custom frameworks | library owner only |  | history (read) |
| Control matrix: download the data file and the report (PDF, Word) | ✓ |  | ✓ |
| Control matrix: import changes from the data file | library owner only |  |  |
| Add and run checks | ✓ |  |  |
| AI review and mock audit | ✓ (run, accept, dismiss) |  | ✓ (read) |

"Owned" means the person's email is on the control's owner role in `catalog/roles.yaml`, or the
library owner named them as an owner of the control (a control can have several named owners).
"Assigned" means they are the assignee or a contributor on a request in any cycle (so they can
look back at last year's evidence for their controls).

## How people get access

### Local accounts (default on a VM)

1. The first admin is created on the server: `grcpal create-admin you@example.com`. This account
   signs in with a password only and is your break-glass admin: run the command again to restore
   access if every other admin is locked out.
2. An admin adds a person on **Users and roles** and gets a one-time link (valid 72 hours, also
   emailed if email is set up). The person opens it and chooses a password of at least 12
   characters. Admins never see passwords.
3. **Forgot password?** on the sign-in page emails a link valid for 1 hour. If email is not set up,
   an admin clicks **Reset password** for a new link. Requesting a new link cancels the old one.
4. Sessions last 8 hours and end at once when the person is disabled, changes role or sets a new
   password.

### Auditor access end date

Every auditor account has an end date (default 90 days from when it is added or switched to
auditor; change it on the Users page). From the day after, the auditor cannot sign in and open
sessions stop working. The change is in the audit log.

### First sign-in with Easy Auth or a proxy

In order of precedence at first sign-in:

1. **Already in the users table**: their stored role applies; disabled accounts are refused.
2. **`GRCPAL_BOOTSTRAP_ADMINS`**: listed emails become admins. Use it for the first admin only.
3. **Group mapping (optional)**: `GRCPAL_GROUP_ADMIN`, `GRCPAL_GROUP_CONTRIBUTOR`,
   `GRCPAL_GROUP_AUDITOR` map Entra group object IDs to a role. Requires group claims in the token.
4. **Named in `catalog/roles.yaml`**: becomes a Control owner.
5. Anyone else sees "You have not been given access" and nothing else.

Assigning work to a new email also creates a Control owner account for that person (with local
accounts, use **Password link** on the Users page so they can sign in).

## Safeguards

- The last active admin cannot be demoted or disabled.
- Evidence from Control owners waits for review by any admin (every admin sees it on **Reviews** and
  is emailed). Control owners can never approve evidence.
- Admins own the program and upload evidence that is already approved (a signed policy, approved
  minutes), so an admin's upload is **approved on upload**. The admin must add an approval note saying
  who approved it and when; the note, the admin's name, the time and the file's checksum are stored as
  write-once evidence, recorded in the audit log and marked `approved_on_upload` in the auditor export.
- Auditors cannot be assigned work.
- Accounts are disabled, never deleted, so the audit trail keeps a name for every action.
- `/users.csv` gives the full user list with role, source, created and last seen dates, access end
  date and whether a password is set, for your
  quarterly access review of GRC-pal itself.

# Roles and permissions

Each person has exactly one role in an instance. Roles live in GRC-pal's own users table, not in
the identity provider, so an admin can change them on the **Users and roles** page and every
change is in the audit log. Every rule below is enforced in the service layer (`service.py`),
not only by hiding buttons.

## Permission matrix

| Action | Admin | Contributor | Auditor |
| --- | :-: | :-: | :-: |
| Dashboard and control health | ✓ | own controls via My work | ✓ |
| See a control | all | only assigned or owned | all |
| Criteria and points of focus pages | ✓ |  | ✓ |
| Browse the raw evidence store | ✓ |  | ✓ |
| Download portal uploads | ✓ | for controls they can see | ✓ (logged) |
| Assign work, cancel requests | ✓ |  |  |
| Upload evidence | ✓ | own requests and owned controls |  |
| Comment | ✓ | own requests and owned controls |  |
| Review (approve or return) | ✓, never own upload |  |  |
| Send reminders | ✓ |  |  |
| Override control status | ✓ (justification, expiry, current cycle) |  |  |
| Acknowledge policies | ✓ | ✓ |  |
| Users and roles | ✓ |  | user list CSV |
| Start a cycle | ✓ |  |  |
| Audit log and integrity check | ✓ |  | ✓ |
| Export zip per cycle | ✓ |  | ✓ |
| Configuration page and Setup guide | ✓ |  |  |
| Logs page and background jobs | ✓ |  | ✓ |
| Frameworks and coverage | ✓ (create custom) |  | ✓ |
| Create, edit, retire custom controls; add and run checks | ✓ |  |  |
| AI review and mock audit | ✓ (run, accept, dismiss) |  | ✓ (read) |

"Owned" means the person's email is on the control's owner role in `catalog/roles.yaml`.
"Assigned" means they are the assignee or a contributor on a request in any cycle (so they can
look back at last year's evidence for their controls).

## How people get access

In order of precedence at first sign-in:

1. **Already in the users table**: their stored role applies; disabled accounts are refused.
2. **`GRCPAL_BOOTSTRAP_ADMINS`**: listed emails become admins. Use it for the first admin only.
3. **Group mapping (optional)**: `GRCPAL_GROUP_ADMIN`, `GRCPAL_GROUP_CONTRIBUTOR`,
   `GRCPAL_GROUP_AUDITOR` map Entra group object IDs to a role. Requires group claims in the token.
4. **Named in `catalog/roles.yaml`**: becomes a contributor.
5. Anyone else sees "You have not been given access" and nothing else.

Assigning work to a new email also creates a contributor account for that person.

## Safeguards

- The last active admin cannot be demoted or disabled.
- Nobody can review evidence they uploaded (segregation of duties).
- Auditors cannot be assigned work.
- Accounts are disabled, never deleted, so the audit trail keeps a name for every action.
- `/users.csv` gives the full user list with role, source, created and last seen dates for your
  quarterly access review of GRC-pal itself.

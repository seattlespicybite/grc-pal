"""IAM-04: daily reconciliation of HR terminations against Entra ID.

Input: CSV with columns `email,termination_date` (YYYY-MM-DD) at GRCPAL_HR_LEAVERS_CSV
(default evidence-inbox/hr_leavers.csv). Replace with an HR system API when one is chosen.
Graph permission: User.Read.All.
"""
import csv
import datetime as dt
import io

PLATFORM = "identity"
DESCRIPTION = "Flag enabled Entra ID accounts belonging to terminated staff"
GRACE_DAYS = 1  # policy: access removed within 24 hours


def run(ctx, run):
    data = ctx.read_input(ctx.setting("GRCPAL_HR_LEAVERS_CSV", "inbox/hr_leavers.csv"))
    leavers = list(csv.DictReader(io.StringIO(data.decode("utf-8-sig"))))
    run.add_bytes("hr_leavers_input.csv", data)

    users = ctx.clients.graph_list("/users", {"$select": "userPrincipalName,mail,accountEnabled", "$top": 999})
    by_email = {}
    for u in users:
        for key in (u.get("userPrincipalName"), u.get("mail")):
            if key:
                by_email[key.lower()] = u

    rows, findings = [], []
    for lv in leavers:
        email = (lv.get("email") or "").strip().lower()
        term = dt.date.fromisoformat(lv["termination_date"].strip())
        user = by_email.get(email)
        enabled = bool(user and user.get("accountEnabled"))
        overdue = enabled and (ctx.today - term).days >= GRACE_DAYS
        rows.append({"email": email, "termination_date": term.isoformat(), "found_in_entra": bool(user),
                     "account_enabled": enabled, "overdue": overdue})
        if overdue:
            findings.append({"key": f"leaver-enabled:{email}", "severity": "high",
                             "title": f"Terminated user still enabled: {email} (terminated {term})", "detail": {}})
    run.add("reconciliation", rows)
    return findings

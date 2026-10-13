"""IAM-05, IAM-06 (Google Cloud): basic roles (owner, editor) on people, and user-managed service account keys.

Permissions: resourcemanager.projects.getIamPolicy, iam.serviceAccounts.list, iam.serviceAccountKeys.list
(roles/iam.securityReviewer).
"""
import datetime as dt

PLATFORM = "gcp"
DESCRIPTION = "Google Cloud IAM: basic roles granted to users, user-managed service account keys and their age"
CRM = "https://cloudresourcemanager.googleapis.com/v1"
IAM = "https://iam.googleapis.com/v1"
KEY_MAX_AGE = 90


def run(ctx, run):
    s = ctx.gcp()
    bindings, keys, findings = [], [], []
    for pid in ctx.setting_list("GRCPAL_GCP_PROJECTS"):
        policy = s.post(f"{CRM}/projects/{pid}:getIamPolicy", json={}, timeout=30)
        policy.raise_for_status()
        for b in policy.json().get("bindings", []):
            for m in b.get("members", []):
                bindings.append({"project": pid, "role": b["role"], "member": m})
                if b["role"] in ("roles/owner", "roles/editor") and m.startswith(("user:", "group:")):
                    findings.append({"key": f"basic-role:{pid}:{b['role']}:{m}", "severity": "medium",
                                     "title": f"{pid}: basic role {b['role']} granted to {m}", "detail": {}})
                if m in ("allUsers", "allAuthenticatedUsers"):
                    findings.append({"key": f"public-iam:{pid}:{b['role']}", "severity": "high",
                                     "title": f"{pid}: {b['role']} granted to {m}", "detail": {}})
        r = s.get(f"{IAM}/projects/{pid}/serviceAccounts", timeout=30)
        r.raise_for_status()
        for sa in r.json().get("accounts", []):
            kr = s.get(f"{IAM}/{sa['name']}/keys?keyTypes=USER_MANAGED", timeout=30)
            kr.raise_for_status()
            for k in kr.json().get("keys", []):
                created = dt.datetime.fromisoformat(k["validAfterTime"].replace("Z", "+00:00")).date()
                age = (ctx.today - created).days
                keys.append({"project": pid, "service_account": sa["email"], "key": k["name"].rsplit("/", 1)[-1],
                             "created": created.isoformat(), "age_days": age})
                if age > KEY_MAX_AGE:
                    findings.append({"key": f"sa-key:{k['name']}", "severity": "medium",
                                     "title": f"{pid}: key for {sa['email']} is {age} days old", "detail": {}})
    run.add("iam_bindings", bindings)
    run.add("service_account_keys", keys)
    return findings

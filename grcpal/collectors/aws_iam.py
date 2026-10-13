"""IAM-02, IAM-05, IAM-06 (AWS): root account, MFA and access key hygiene from the IAM credential report.

Permissions: iam:GenerateCredentialReport, iam:GetCredentialReport, iam:GetAccountSummary (SecurityAudit policy).
"""
import csv
import datetime as dt
import io
import time

PLATFORM = "aws"
DESCRIPTION = "AWS IAM credential report: root MFA, users without MFA, old and unused access keys"
KEY_MAX_AGE = 90


def _age(value, today):
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    return (today - dt.datetime.fromisoformat(value.replace("Z", "+00:00")).date()).days


def run(ctx, run):
    iam = ctx.aws().client("iam")
    for _ in range(20):
        if iam.generate_credential_report()["State"] == "COMPLETE":
            break
        time.sleep(2)
    report = iam.get_credential_report()["Content"]
    rows = list(csv.DictReader(io.StringIO(report.decode() if isinstance(report, bytes) else report)))
    summary = iam.get_account_summary()["SummaryMap"]
    run.add("credential_report", rows)
    run.add("account_summary", summary)
    findings = []
    for r in rows:
        user = r["user"]
        if user == "<root_account>":
            if r.get("mfa_active") != "true":
                findings.append({"key": "root-no-mfa", "severity": "high", "title": "AWS root account has no MFA", "detail": {}})
            if r.get("access_key_1_active") == "true" or r.get("access_key_2_active") == "true":
                findings.append({"key": "root-keys", "severity": "high", "title": "AWS root account has access keys", "detail": {}})
            continue
        if r.get("password_enabled") == "true" and r.get("mfa_active") != "true":
            findings.append({"key": f"no-mfa:{user}", "severity": "high",
                             "title": f"AWS console user without MFA: {user}", "detail": {}})
        for n in ("1", "2"):
            if r.get(f"access_key_{n}_active") != "true":
                continue
            age = _age(r.get(f"access_key_{n}_last_rotated"), ctx.today)
            used = _age(r.get(f"access_key_{n}_last_used_date"), ctx.today)
            if age is not None and age > KEY_MAX_AGE:
                findings.append({"key": f"key-age:{user}:{n}", "severity": "medium",
                                 "title": f"AWS access key {n} of {user} is {age} days old", "detail": {}})
            if used is None or used > KEY_MAX_AGE:
                findings.append({"key": f"key-unused:{user}:{n}", "severity": "low",
                                 "title": f"AWS access key {n} of {user} unused for over {KEY_MAX_AGE} days", "detail": {}})
    return findings

"""LOG-01 (AWS): an active multi-region CloudTrail trail with log file validation.

Permissions: cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus (SecurityAudit policy).
"""
PLATFORM = "aws"
DESCRIPTION = "AWS CloudTrail: multi-region logging, log file validation, trail status"


def run(ctx, run):
    ct = ctx.aws().client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
    rows = []
    for t in trails:
        status = ct.get_trail_status(Name=t["TrailARN"])
        rows.append({"name": t["Name"], "multi_region": t.get("IsMultiRegionTrail", False),
                     "organization_trail": t.get("IsOrganizationTrail", False),
                     "log_validation": t.get("LogFileValidationEnabled", False), "kms_encrypted": bool(t.get("KmsKeyId")),
                     "bucket": t.get("S3BucketName"), "logging": status.get("IsLogging", False),
                     "latest_delivery": str(status.get("LatestDeliveryTime", ""))})
    run.add("trails", rows)
    good = [r for r in rows if r["multi_region"] and r["logging"]]
    findings = []
    if not good:
        findings.append({"key": "no-multiregion-trail", "severity": "high",
                         "title": "No active multi-region CloudTrail trail", "detail": {}})
    for r in good:
        if not r["log_validation"]:
            findings.append({"key": f"validation:{r['name']}", "severity": "medium",
                             "title": f"CloudTrail {r['name']}: log file validation is off", "detail": {}})
    return findings

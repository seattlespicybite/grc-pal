"""MON-01, VUL-02, CRY-01 (AWS): GuardDuty, AWS Config recorder, Security Hub and EBS default encryption per region.

Permissions: guardduty:ListDetectors, config:DescribeConfigurationRecorderStatus, securityhub:DescribeHub,
ec2:GetEbsEncryptionByDefault (SecurityAudit policy).
"""
PLATFORM = "aws"
DESCRIPTION = "AWS detective services and EBS encryption by default, per region"


def run(ctx, run):
    regions = ctx.setting_list("GRCPAL_AWS_REGIONS") or ["us-east-1"]
    rows, findings = [], []
    for region in regions:
        sess = ctx.aws(region)
        row = {"region": region}
        row["guardduty"] = bool(sess.client("guardduty", region_name=region).list_detectors().get("DetectorIds"))
        statuses = sess.client("config", region_name=region).describe_configuration_recorder_status().get(
            "ConfigurationRecordersStatus", [])
        row["config_recording"] = any(s.get("recording") for s in statuses)
        try:
            sess.client("securityhub", region_name=region).describe_hub()
            row["security_hub"] = True
        except Exception:  # noqa: BLE001 - not subscribed
            row["security_hub"] = False
        row["ebs_default_encryption"] = sess.client("ec2", region_name=region).get_ebs_encryption_by_default().get(
            "EbsEncryptionByDefault", False)
        rows.append(row)
        for key, label, sev in (("guardduty", "GuardDuty is not enabled", "high"),
                                ("config_recording", "AWS Config is not recording", "medium"),
                                ("ebs_default_encryption", "EBS encryption by default is off", "medium")):
            if not row[key]:
                findings.append({"key": f"{key}:{region}", "severity": sev, "title": f"{region}: {label}", "detail": {}})
    run.add("regions", rows)
    return findings

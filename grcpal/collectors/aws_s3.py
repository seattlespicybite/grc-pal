"""CRY-01, DAT-01 (AWS): S3 account-level public access block and bucket encryption and public access.

Permissions: s3:GetAccountPublicAccessBlock, s3:ListAllMyBuckets, s3:GetEncryptionConfiguration,
s3:GetBucketPublicAccessBlock, s3:GetBucketPolicyStatus (SecurityAudit policy).
"""
PLATFORM = "aws"
DESCRIPTION = "AWS S3: account public access block, bucket encryption, public buckets"
_PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _err(exc) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "") or type(exc).__name__


def run(ctx, run):
    sess = ctx.aws()
    account = sess.client("sts").get_caller_identity()["Account"]
    findings = []
    try:
        pab = sess.client("s3control").get_public_access_block(AccountId=account)["PublicAccessBlockConfiguration"]
    except Exception as exc:  # noqa: BLE001
        if _err(exc) != "NoSuchPublicAccessBlockConfiguration":
            raise
        pab = {}
    run.add("account_public_access_block", pab)
    if not all(pab.get(k) for k in _PAB_KEYS):
        findings.append({"key": "account-pab", "severity": "high",
                         "title": "S3 Block Public Access is not fully on at the account level", "detail": pab})
    s3 = sess.client("s3")
    rows = []
    for b in s3.list_buckets().get("Buckets", []):
        name, row = b["Name"], {"bucket": b["Name"]}
        try:
            rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
            row["encryption"] = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        except Exception as exc:  # noqa: BLE001
            row["encryption"] = "none" if _err(exc) == "ServerSideEncryptionConfigurationNotFoundError" else f"unknown ({_err(exc)})"
        try:
            row["public"] = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]
        except Exception:  # noqa: BLE001 - no bucket policy
            row["public"] = False
        rows.append(row)
        if row["public"]:
            findings.append({"key": f"public:{name}", "severity": "high", "title": f"S3 bucket {name} is public", "detail": {}})
        if row["encryption"] == "none":
            findings.append({"key": f"unencrypted:{name}", "severity": "medium",
                             "title": f"S3 bucket {name} has no default encryption", "detail": {}})
    run.add("buckets", rows)
    return findings

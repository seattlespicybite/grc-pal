"""Amazon Web Services: sessions and connection test. Needs the optional extra: pip install "grc-pal[aws]"."""
from __future__ import annotations


def _boto3():
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError('AWS support is not installed. Run: pip install "grc-pal[aws]" (the container image '
                           "includes it).") from exc
    return boto3


def session(settings, region: str | None = None):
    """A boto3 session for the configured sign-in method. Credentials stay in this object only."""
    boto3 = _boto3()
    auth = settings.get("GRCPAL_AWS_AUTH")
    region = region or (settings.list("GRCPAL_AWS_REGIONS") or ["us-east-1"])[0]
    if auth == "access_key":
        return boto3.Session(aws_access_key_id=settings.get("GRCPAL_AWS_ACCESS_KEY_ID"),
                             aws_secret_access_key=settings.secret("GRCPAL_AWS_SECRET_ACCESS_KEY"), region_name=region)
    base = boto3.Session(region_name=region)
    role = settings.get("GRCPAL_AWS_ROLE_ARN")
    if auth == "assume_role" and role:
        kwargs = {"RoleArn": role, "RoleSessionName": "grc-pal"}
        if settings.get("GRCPAL_AWS_EXTERNAL_ID"):
            kwargs["ExternalId"] = settings.get("GRCPAL_AWS_EXTERNAL_ID")
        creds = base.client("sts").assume_role(**kwargs)["Credentials"]
        return _from_creds(boto3, creds, region)
    if auth == "azure_web_identity":
        from grcpal.integrations.microsoft import credential

        audience = settings.get("GRCPAL_AWS_WEB_IDENTITY_AUDIENCE").rstrip("/")
        jwt = credential(settings).get_token(f"{audience}/.default").token
        creds = base.client("sts").assume_role_with_web_identity(RoleArn=role, RoleSessionName="grc-pal",
                                                                 WebIdentityToken=jwt)["Credentials"]
        return _from_creds(boto3, creds, region)
    return base


def _from_creds(boto3, creds: dict, region: str):
    return boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                         aws_session_token=creds["SessionToken"], region_name=region)


def validate(settings, ctx, result) -> None:
    if not settings.flag("GRCPAL_AWS_ENABLED"):
        result.add("AWS collection is turned off", True)
        return
    sess = result.run("Load AWS support", lambda: session(settings))
    if sess is None:
        return
    ident = result.run("Sign in (sts:GetCallerIdentity)", lambda: sess.client("sts").get_caller_identity(),
                       "Check the keys or role trust policy.")
    if not ident:
        return
    account = ident["Account"]
    result.add("Signed in as", True, f"{ident['Arn']} in account {account}")
    probes = (
        ("IAM read (SecurityAudit)", lambda: sess.client("iam").get_account_summary() and "ok"),
        ("CloudTrail read", lambda: f"{len(sess.client('cloudtrail').describe_trails()['trailList'])} trails"),
        ("S3 account public access block read", lambda: _pab(sess, account)),
        ("GuardDuty read", lambda: f"{len(sess.client('guardduty').list_detectors()['DetectorIds'])} detectors"),
    )
    for name, fn in probes:
        result.run(name, fn, "Attach the AWS managed policies SecurityAudit and ViewOnlyAccess to the identity.")


def _pab(sess, account: str) -> str:
    try:
        sess.client("s3control").get_public_access_block(AccountId=account)
        return "configured"
    except Exception as exc:  # noqa: BLE001
        if "NoSuchPublicAccessBlockConfiguration" in str(exc):
            return "readable (not configured: this will be a finding)"
        raise

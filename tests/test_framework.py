"""Offline tests: every collector runs against canned API responses; evidence, tasks and
report work end to end without network access."""
import datetime as dt
import json
from pathlib import Path

import pytest
import yaml

from grcpal import collectors, report, tasks
from grcpal.catalog import Catalog, validate
from grcpal.evidence import EvidenceStore

ROOT = Path(__file__).resolve().parents[1] / "grcpal" / "starter"
TODAY = dt.date(2026, 10, 12)


class FakeClients:
    def graph_list(self, path, params=None, headers=None):
        data = {
            "/users": [
                {"id": "1", "userPrincipalName": "ana@example.com", "accountEnabled": True, "userType": "Member",
                 "signInActivity": {"lastSuccessfulSignInDateTime": "2026-10-10T00:00:00Z"}},
                {"id": "2", "userPrincipalName": "old@example.com", "accountEnabled": True, "userType": "Member"},
                {"id": "3", "userPrincipalName": "guest_x#EXT#@example.com", "accountEnabled": True, "userType": "Guest",
                 "signInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z"}},
            ],
            "/reports/authenticationMethods/userRegistrationDetails": [
                {"userPrincipalName": "ana@example.com", "userType": "member", "isAdmin": True,
                 "isMfaRegistered": True, "methodsRegistered": ["fido2"]},
                {"userPrincipalName": "old@example.com", "userType": "member", "isAdmin": False,
                 "isMfaRegistered": False, "methodsRegistered": []},
            ],
            "/roleManagement/directory/roleDefinitions": [
                {"id": "62e90394-69f5-4237-9190-012177145e10", "displayName": "Global Administrator"}],
            "/roleManagement/directory/roleAssignments": [
                {"roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "directoryScopeId": "/",
                 "principal": {"@odata.type": "#microsoft.graph.user", "userPrincipalName": "ana@example.com"}}],
            "/servicePrincipals": [{"displayName": "Payroll", "appId": "a1", "preferredSingleSignOnMode": "saml"}],
            "/applications": [{"displayName": "API", "appId": "a2", "passwordCredentials": [
                {"keyId": "k", "startDateTime": "2026-01-01T00:00:00Z", "endDateTime": "2028-01-01T00:00:00Z"}]}],
            "/identity/conditionalAccess/policies": [
                {"displayName": "MFA all", "state": "enabled",
                 "conditions": {"users": {"includeUsers": ["All"]}, "clientAppTypes": ["all"]},
                 "grantControls": {"builtInControls": ["mfa"]}}],
            "/deviceManagement/managedDevices": [
                {"deviceName": "LT-1", "operatingSystem": "Windows", "complianceState": "noncompliant",
                 "isEncrypted": False, "lastSyncDateTime": "2026-10-11T00:00:00Z",
                 "managedDeviceOwnerType": "company", "serialNumber": "S1"}],
        }
        return data[path]

    def arg_query(self, query, subscriptions=None):
        if "resourcecontainers" in query:
            return [{"subscriptionId": "s1", "name": "prod"}]
        if "operationalinsights" in query:
            return [{"id": "w1", "name": "law-prod", "retentionInDays": 30}]
        if "roledefinitions" in query:
            return [{"id": "/providers/microsoft.authorization/roledefinitions/r-owner", "roleName": "Owner"}]
        if "roleassignments" in query:
            return [{"id": "ra1", "principalId": "p", "principalType": "User",
                     "roleDefinitionId": "/subscriptions/s1/providers/microsoft.authorization/roledefinitions/r-owner",
                     "scope": "/subscriptions/s1"}]
        if "policystates" in query:
            return [{"complianceState": "NonCompliant", "groups": ["SOC_2_CC6.1"], "assignment": "soc2"}]
        if "recoveryservices/vaults'" in query:
            return [{"id": "v1", "name": "rsv", "softDelete": "Disabled"}]
        if "protecteditems" in query:
            return [{"id": "i1", "item": "sql-prod", "lastBackupStatus": "Healthy",
                     "lastBackupTime": "2026-10-11T02:00:00Z"}]
        return [{"id": "r1", "name": "st1", "type": "storage", "tags": {"owner": "x"}}]

    def gh_get(self, path, allow_404=False):
        if path.endswith("/check-runs"):
            return {"check_runs": [{"conclusion": "success"}]}
        return {"default_branch": "main"}

    def gh_list(self, path, params=None, max_pages=50):
        if path.endswith("/pulls"):
            return [{"number": 7, "title": "Fix", "html_url": "u", "user": {"login": "dev"},
                     "updated_at": "2026-10-10T00:00:00Z", "merged_at": "2026-10-10T00:00:00Z",
                     "merge_commit_sha": "abc", "merged_by": {"login": "dev"}, "labels": []}]
        if path.endswith("/reviews"):
            return [{"state": "APPROVED", "user": {"login": "dev"}}]  # self-approval only
        if "/rules/branches/" in path:
            return [{"type": "pull_request", "parameters": {"required_approving_review_count": 1}}]
        if path.endswith("/dependabot/alerts"):
            return [{"number": 1, "security_advisory": {"severity": "critical"},
                     "created_at": "2026-08-01T00:00:00Z", "dependency": {"package": {"name": "lodash"}}}]
        if path.endswith("/issues"):
            return [{"number": 3, "title": "[GRC] Quarterly user access review (2026-Q3)", "html_url": "u",
                     "state": "closed", "labels": [{"name": "grc"}, {"name": "task:access-review"},
                                                   {"name": "control:IAM-05"}],
                     "created_at": "2026-07-01T00:00:00Z", "closed_at": "2026-07-15T00:00:00Z",
                     "comments": 1, "comments_url": "c", "body": "x"}]
        if path == "c":
            return [{"user": {"login": "sec"}, "created_at": "2026-07-15T00:00:00Z", "body": "Approved, removals done"}]
        return []


class _AwsClient:
    def __init__(self, name):
        self.name = name

    def __getattr__(self, op):
        responses = {
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {"Content": (
                "user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
                "access_key_1_last_used_date,access_key_2_active\n"
                "<root_account>,arn:root,not_supported,false,false,N/A,N/A,false\n"
                "dev,arn:dev,true,false,true,2026-01-01T00:00:00+00:00,2026-01-02T00:00:00+00:00,false\n").encode()},
            "get_account_summary": {"SummaryMap": {"Users": 1}},
            "describe_trails": {"trailList": [{"Name": "main", "TrailARN": "arn:t", "IsMultiRegionTrail": True,
                                               "LogFileValidationEnabled": False}]},
            "get_trail_status": {"IsLogging": True},
            "get_caller_identity": {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/r"},
            "list_buckets": {"Buckets": [{"Name": "logs"}]},
            "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {"Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}},
            "get_bucket_policy_status": {"PolicyStatus": {"IsPublic": True}},
            "list_detectors": {"DetectorIds": []},
            "describe_configuration_recorder_status": {"ConfigurationRecordersStatus": [{"recording": True}]},
            "describe_hub": {},
            "get_ebs_encryption_by_default": {"EbsEncryptionByDefault": True},
        }
        if op == "get_public_access_block":
            def missing(**kw):
                err = Exception("NoSuchPublicAccessBlockConfiguration")
                err.response = {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}
                raise err
            return missing
        return lambda *a, **kw: responses[op]


class FakeAws:
    def client(self, name, region_name=None):
        return _AwsClient(name)


class _Resp:
    def __init__(self, data, status=200):
        self._data, self.status_code, self.ok = data, status, status < 400

    def json(self):
        return self._data

    def raise_for_status(self):
        if not self.ok:
            raise RuntimeError(self.status_code)


class FakeGcp:
    def post(self, url, json=None, timeout=None):
        return _Resp({"bindings": [{"role": "roles/owner", "members": ["user:ana@example.com"]}],
                      "auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "ADMIN_READ"}]}]})

    def get(self, url, timeout=None):
        if url.endswith("/serviceAccounts"):
            return _Resp({"accounts": [{"name": "projects/p1/serviceAccounts/sa@p1", "email": "sa@p1"}]})
        if "/keys" in url:
            return _Resp({"keys": [{"name": "projects/p1/serviceAccounts/sa@p1/keys/k1", "validAfterTime": "2025-01-01T00:00:00Z"}]})
        if url.endswith("/sinks"):
            return _Resp({"sinks": []})
        if "/storage/v1/b?" in url:
            return _Resp({"items": [{"name": "b1", "iamConfiguration": {"publicAccessPrevention": "inherited"}}]})
        if url.endswith("/iam"):
            return _Resp({"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]})
        if url.endswith("/firewalls"):
            return _Resp({"items": [{"name": "allow-ssh", "sourceRanges": ["0.0.0.0/0"],
                                     "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}]})
        return _Resp({})


@pytest.fixture()
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_REPOS", "acme/app")
    monkeypatch.setenv("GRCPAL_GRC_REPO", "acme/compliance")
    leavers = tmp_path / "leavers.csv"
    leavers.write_text("email,termination_date\nold@example.com,2026-10-01\n")
    monkeypatch.setenv("GRCPAL_HR_LEAVERS_CSV", str(leavers))
    monkeypatch.delenv("GRCPAL_EVIDENCE_ACCOUNT_URL", raising=False)
    monkeypatch.setenv("GRCPAL_GCP_PROJECTS", "p1")
    monkeypatch.setenv("GRCPAL_AWS_REGIONS", "us-east-1")
    c = collectors.Context(clients=FakeClients(), catalog=Catalog.load(ROOT), today=TODAY)
    c.aws = lambda region=None: FakeAws()
    c.gcp = lambda: FakeGcp()
    return c


def test_catalog_valid():
    cat = Catalog.load(ROOT)
    errors, _ = validate(cat, set(collectors.NAMES))
    assert errors == []
    assert all(cat.coverage()[c] for c in cat.criteria), "every TSC criterion has a control"


@pytest.mark.parametrize("name", collectors.NAMES)
def test_collector_runs(name, ctx, tmp_path):
    store = EvidenceStore(tmp_path / "ev")
    run = store.new_run(name, [], {})
    findings = collectors.get(name).run(ctx, run)
    manifest = run.finish(findings)
    assert manifest["files"], f"{name} wrote no evidence"
    saved = json.loads((tmp_path / "ev" / run.prefix / "manifest.json").read_text())
    assert saved["findings_count"] == len(findings)


def test_expected_findings(ctx, tmp_path):
    store = EvidenceStore(tmp_path / "ev")

    def findings(name):
        return collectors.get(name).run(ctx, store.new_run(name, [], {}))

    assert any("old@example.com" in f["title"] for f in findings("leaver_reconcile"))
    assert any("without independent approval" in f["title"] for f in findings("github_changes"))
    assert any(f["key"] == "legacy-auth-open" for f in findings("conditional_access"))
    assert any(f["key"] == "no-device-compliance" for f in findings("conditional_access"))
    assert any("Owner" in f["title"] for f in findings("azure_rbac"))
    assert any("lodash" in f["title"] for f in findings("github_vulns"))


def _ca_policy(controls, operator="AND", state="enabled"):
    return {"displayName": "p", "state": state, "conditions": {"users": {"includeUsers": ["All"]}},
            "grantControls": {"operator": operator, "builtInControls": controls}}


@pytest.mark.parametrize("policy,ok", [
    (_ca_policy(["mfa", "compliantDevice"], "AND"), True),       # MFA and a managed device
    (_ca_policy(["compliantDevice"], "OR"), True),               # only one control: it is required
    (_ca_policy(["compliantDevice", "domainJoinedDevice"], "OR"), True),  # either kind of managed device
    (_ca_policy(["mfa", "compliantDevice"], "OR"), False),       # MFA alone also lets an unmanaged laptop in
    (_ca_policy(["mfa"], "AND"), False),
    (_ca_policy(["compliantDevice"], "AND", state="enabledForReportingButNotEnforced"), False),  # report-only
])
def test_conditional_access_device_compliance(policy, ok, tmp_path):
    from types import SimpleNamespace
    ca = collectors.get("conditional_access")
    fake = SimpleNamespace(clients=SimpleNamespace(graph_list=lambda path: [policy]))
    findings = ca.run(fake, EvidenceStore(tmp_path / "ev").new_run("conditional_access", [], {}))
    assert any(f["key"] == "no-device-compliance" for f in findings) is not ok


def test_tasks_due_dry_run(ctx):
    created = tasks.open_due(ctx, dry_run=True)
    assert any("access review" in t.lower() for t in created)  # October is a review month


def test_report_end_to_end(ctx, tmp_path):
    store = EvidenceStore(tmp_path / "ev")
    for name in collectors.NAMES:
        run = store.new_run(name, [], {})
        run.finish(collectors.get(name).run(ctx, run))
    data = report.build(ctx.catalog, store, today=TODAY)
    iam05 = next(c for c in data["controls"] if c["id"] == "IAM-05")
    task_item = next(i for i in iam05["evidence"] if i["via"] == "task:access-review")
    assert task_item["status"] == "ok" and task_item["last"] == "2026-07-15"
    html = report.to_html(data)
    assert "GRC-pal control health" in html and "CC6.1" in html


def test_criteria_titles_not_truncated():
    cat = Catalog.load(ROOT)
    assert len(cat.criteria) == 61
    assert cat.criteria["CC1.3"]["title"].startswith("Structures, reporting lines")
    assert all(isinstance(c["title"], str) and len(c["title"]) > 12 for c in cat.criteria.values())


def test_points_of_focus_consistent():
    cat = Catalog.load(ROOT)
    assert cat.points_of_focus, "points_of_focus.yaml loaded"
    errors, warnings = validate(cat, set(collectors.NAMES))
    assert errors == []
    assert set(cat.in_scope_criteria) <= set(cat.points_of_focus)
    assert any(" gap:" in w for w in warnings)


def test_cloud_collector_findings(ctx, tmp_path):
    store = EvidenceStore(tmp_path / "ev")
    expected = {
        "aws_iam": ("root-no-mfa", "no-mfa:dev", "key-age:dev:1"),
        "aws_cloudtrail": ("validation:main",),
        "aws_s3": ("account-pab", "public:logs"),
        "aws_security_services": ("guardduty:us-east-1",),
        "gcp_iam": ("basic-role:p1:roles/owner:user:ana@example.com", "sa-key:projects/p1/serviceAccounts/sa@p1/keys/k1"),
        "gcp_logging": ("data-access:p1", "no-sink:p1"),
        "gcp_storage": ("public:b1",),
        "gcp_firewall": ("open-admin:p1:allow-ssh",),
    }
    for name, keys in expected.items():
        findings = collectors.get(name).run(ctx, store.new_run(name, [], {}))
        got = {f["key"] for f in findings}
        assert set(keys) <= got, (name, got)


def test_platform_gating_and_report_skip(ctx, tmp_path, monkeypatch):
    from grcpal.settings import Settings

    monkeypatch.delenv("GRCPAL_AWS_ENABLED", raising=False)
    s = Settings({"GRCPAL_AWS_ENABLED": "false", "GRCPAL_AZURE_ENABLED": "false"}, env=False)
    off = collectors.disabled_sources(ctx.catalog, s)
    assert {"aws_iam", "gcp_iam", "azure_rbac"} <= off and "entra_mfa" not in off
    data = report.build(ctx.catalog, EvidenceStore(tmp_path / "e"), TODAY, portal={"skip_sources": off})
    iam02 = next(c for c in data["controls"] if c["id"] == "IAM-02")
    aws_item = next(i for i in iam02["evidence"] if i["via"] == "collector:aws_iam")
    assert aws_item["status"] == "n/a" and aws_item["note"] == "platform not in use"


def test_load_yaml_is_safe_and_handles_empty():
    from grcpal.catalog import load_yaml
    assert load_yaml("") == {}
    assert load_yaml("a: 1") == {"a": 1}
    with pytest.raises(yaml.YAMLError):  # no Python objects, even with the fast C loader
        load_yaml("!!python/object/apply:os.system ['echo pwned']")

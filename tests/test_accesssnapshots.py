"""Daily account snapshots for access reviews: every application's full list stored write-once with a hash, what changed
since the last good pull, failed pulls stored as failures (never partial) and alerted like a collector, no tokens or
people in the audit log, reviews reuse a fresh snapshot, the Accounts page and its roles, and tenant separation."""
import json

import pytest
from fastapi.testclient import TestClient

from grcpal import cli
from grcpal.portal import accessapps as aa
from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from grcpal.portal.store import SqliteStore
from test_accesssources import CRM, FakeApi, FakeClients, setup_apps
from test_portal import ADMIN, AUDITOR, CONTRIB, HR, as_, csrf, make_portal


@pytest.fixture()
def portal(tmp_path, monkeypatch):
    for key in ("GRCPAL_MS_ENABLED", "GRCPAL_AZURE_ENABLED", "GRCPAL_GITHUB_ENABLED"):
        monkeypatch.setenv(key, "true")
    monkeypatch.setenv("GRCPAL_JOBS_SYNC", "1")
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", "test-only-key-0123456789abcdef")
    return make_portal(tmp_path)


def crm_api(users):
    return FakeApi({"https://api.example.com/v1/users": {"users": users}})


def runs(portal, aid):
    return portal.evidence.list_runs(aa.snapshot_source(aid))


def test_a_pull_stores_every_application_write_once_with_a_hash(portal):
    entra, gh, crm = setup_apps(portal)
    results = portal.pull_access_snapshots(ADMIN, clients=FakeClients(), request_fn=CRM)
    assert {r["app"]: r["records"] for r in results} == {"Microsoft 365": 5, "GitHub": 4, "Customer portal": 2}
    run = runs(portal, crm["RowKey"])[-1]
    source = aa.snapshot_source(crm["RowKey"])
    rows = json.loads(portal.evidence.read(source, run, "accounts.json"))
    assert [r["account_id"] for r in rows] == ["alice", "carol"]
    assert json.loads(portal.evidence.read(source, run, "requests.json")) == ["https://api.example.com/v1/users"]
    assert b"alice@example.com" in portal.evidence.read(source, run, "accounts.csv")
    assert portal.evidence.verify_run(source, run)["status"] in ("verified", "unsigned")
    manifest = json.loads(portal.evidence.read(source, run, "manifest.json"))
    assert manifest["status"] == "ok" and manifest["records"] == 2 and manifest["controls"] == ["IAM-05"]
    assert manifest["findings"] == []                                  # alice is an owner, but MFA is unknown
    last = portal.store.get("arapps", "a", crm["RowKey"])["last_pull"]
    assert last["ok"] and last["records"] == 2 and last["added"] == 2 and last["run"] == f"{source}/{run}"
    log = json.dumps([r["detail"] for r in portal.log.records() if r["action"] == "access_review.pull"])
    assert "example.com" not in log and "crm-secret" not in log and '"records": 2' in log


def test_the_next_pull_says_what_changed(portal):
    _, _, crm = setup_apps(portal)
    portal.pull_access_snapshots(ADMIN, [crm["RowKey"]], request_fn=CRM)
    portal.pull_access_snapshots(ADMIN, [crm["RowKey"]], request_fn=crm_api([
        {"login": "alice", "mail": "alice@example.com", "role": "agent"},
        {"login": "dave", "mail": "dave@example.com", "role": "agent"}]))
    first, second = runs(portal, crm["RowKey"])
    changes = json.loads(portal.evidence.read(aa.snapshot_source(crm["RowKey"]), second, "changes.json"))
    assert changes["added"] == ["dave"] and changes["removed"] == ["carol"]
    assert changes["changed"] == [{"account_id": "alice", "field": "role", "before": "owner", "after": "agent"}]
    assert changes["previous"] == f"{aa.snapshot_source(crm['RowKey'])}/{first}"


def test_a_failed_pull_is_stored_as_a_failure_never_partial_and_alerts(portal):
    entra, _, crm = setup_apps(portal)
    results = portal.pull_access_snapshots(ADMIN, [entra["RowKey"], crm["RowKey"]], clients=FakeClients(),
                                           request_fn=FakeApi({}, status=500))
    assert {r["app"]: r["ok"] for r in results} == {"Microsoft 365": True, "Customer portal": False}  # others still run
    source = aa.snapshot_source(crm["RowKey"])
    run = runs(portal, crm["RowKey"])[-1]
    assert portal.evidence.read(source, run, "accounts.json") is None
    assert json.loads(portal.evidence.read(source, run, "manifest.json"))["status"] == "error"
    assert portal.store.get("arapps", "a", crm["RowKey"])["last_pull"]["ok"] is False
    assert portal.automated_sources()[source]["title"] == "Account pull: Customer portal"
    assert portal._run_status(source, run) == "failed"


def test_admin_accounts_without_mfa_are_a_finding_without_names(portal):
    _, gh, _ = setup_apps(portal)
    portal.pull_access_snapshots(ADMIN, [gh["RowKey"]], clients=FakeClients())
    manifest = json.loads(portal.evidence.read(aa.snapshot_source(gh["RowKey"]), runs(portal, gh["RowKey"])[-1],
                                               "manifest.json"))
    assert manifest["findings_count"] == 0                             # the GitHub owner has two-factor on
    findings = aa.snapshot_findings([{"role": "Owner", "mfa": "no", "status": "active", "email": "x@example.com"}])
    assert findings[0]["severity"] == "high" and "example.com" not in json.dumps(findings)


def test_tokens_never_reach_evidence(portal, tmp_path):
    setup_apps(portal)
    portal.pull_access_snapshots(ADMIN, clients=FakeClients(), request_fn=CRM)
    for path in (tmp_path / "evidence").rglob("*"):
        if path.is_file():
            assert b"crm-secret-token-123" not in path.read_bytes(), path


def test_a_review_uses_a_fresh_snapshot_and_pulls_again_when_it_is_old(portal, monkeypatch):
    _, _, crm = setup_apps(portal)
    portal.pull_access_snapshots(ADMIN, [crm["RowKey"]], request_fn=CRM)
    stored = f"{aa.snapshot_source(crm['RowKey'])}/{runs(portal, crm['RowKey'])[-1]}"
    broken = FakeApi({}, status=500)
    job = portal.start_access_review(ADMIN, "Q4", "2026-11-30", [crm["RowKey"]], request_fn=broken)
    assert job["status"] == "done" and broken.sent == []                # nothing pulled: the stored list was used
    camp = portal.access_campaign(ADMIN, job["result"]["campaign"])["campaign"]
    assert camp["pulled"]["Customer portal"]["snapshot"] == stored and camp["records"] == 2
    monkeypatch.setattr(aa, "FRESH_HOURS", -1)
    job = portal.start_access_review(ADMIN, "Q4 again", "2026-11-30", [crm["RowKey"]], request_fn=broken)
    assert job["status"] == "failed" and broken.sent and "Nothing was created" in job["message"]


def test_only_admins_pull_and_only_admins_and_auditors_see_accounts(portal):
    _, _, crm = setup_apps(portal)
    for who in (HR, CONTRIB, AUDITOR):
        with pytest.raises(Forbidden):
            portal.pull_access_snapshots(who, request_fn=CRM)
        with pytest.raises(Forbidden):
            portal.request_access_pull(who, crm["RowKey"])
    for who in (HR, CONTRIB):
        with pytest.raises(Forbidden):
            portal.access_accounts(who)
    assert portal.access_accounts(AUDITOR)["jobs"] == []
    with pytest.raises(Invalid):
        portal.request_access_pull(ADMIN, "no-such-app")


def test_accounts_are_flagged_including_people_missing_from_entra(portal):
    entra, _, crm = setup_apps(portal)
    portal.pull_access_snapshots(ADMIN, [entra["RowKey"], crm["RowKey"]], clients=FakeClients(), request_fn=CRM)
    selected = portal.access_accounts(AUDITOR, crm["RowKey"])["selected"]
    flags = {r["account_id"]: r["flags"] for r in selected["accounts"]}
    assert flags["alice"] == ["privileged"] and flags["carol"] == ["not_in_directory"]
    assert selected["directory"] and selected["history"][0]["status"] == "ok"
    users = {r["account_id"]: r["flags"] for r in portal.access_accounts(ADMIN, entra["RowKey"])["selected"]["accounts"]}
    assert "not_in_directory" not in users["bob@example.com"] and "disabled" in users["bob@example.com"]


def test_tenants_never_see_each_others_snapshots(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", "test-only-key-0123456789abcdef")
    shared = SqliteStore()
    acme, beta = make_portal(tmp_path, "acme", shared), make_portal(tmp_path, "beta", shared)
    _, _, crm = setup_apps(acme)
    acme.pull_access_snapshots(ADMIN, [crm["RowKey"]], request_fn=CRM)
    assert beta.access_accounts(ADMIN)["apps"] == []
    assert beta.evidence.list_runs(aa.snapshot_source(crm["RowKey"])) == []
    with pytest.raises(Invalid):
        beta.access_accounts(ADMIN, crm["RowKey"])


def test_the_nightly_job_pulls_and_reports(portal, monkeypatch, capsys):
    portal.add_access_app(ADMIN, "GRC-pal", "grcpal")
    monkeypatch.setattr(cli, "_admin_portal", lambda args: portal)
    assert cli._access_pull(None) == 0
    assert "ok    accounts GRC-pal: 5 accounts" in capsys.readouterr().out


@pytest.fixture()
def client(portal, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    monkeypatch.delenv("GRCPAL_PUBLIC_URL", raising=False)
    return TestClient(create_app(portal), base_url="https://grc.example.com")


def test_accounts_page_and_pull_now(portal, client):
    me = portal.add_access_app(ADMIN, "GRC-pal", "grcpal")
    as_(client, ADMIN)
    token = csrf(client, "/access-reviews/accounts")
    assert "Not pulled yet" in client.get("/access-reviews/accounts").text
    assert client.post("/access-reviews/accounts/pull", data={"app_id": me["RowKey"]}).status_code == 403  # no CSRF
    r = client.post("/access-reviews/accounts/pull", data={"csrf": token, "app_id": me["RowKey"]}, follow_redirects=False)
    assert r.status_code == 303 and "msg=" in r.headers["location"]
    page = client.get(f"/access-reviews/accounts?app_id={me['RowKey']}")
    assert page.status_code == 200 and "Pull history" in page.text and ADMIN.email in page.text
    assert client.get("/access-reviews/accounts?app_id=no-such-app").status_code == 404
    assert 'href="/access-reviews/accounts"' in client.get("/access-reviews").text
    as_(client, AUDITOR)
    page = client.get(f"/access-reviews/accounts?app_id={me['RowKey']}")
    assert page.status_code == 200 and "Pull now" not in page.text
    assert client.post("/access-reviews/accounts/pull", data={"csrf": csrf(client, "/access-reviews")}).status_code == 403
    as_(client, HR)
    assert client.get("/access-reviews/accounts").status_code == 403

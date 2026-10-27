"""Automation page: overview statuses, Verify (nothing saved), Run once (saved, manual, audited), roles, tenants."""
import datetime as dt
import json
import re

import pytest
from fastapi.testclient import TestClient

from grcpal.evidence import Run
from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from test_portal import ADMIN, AUDITOR, CONTRIB, make_portal


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    monkeypatch.setenv("GRCPAL_KEY_FILE", str(tmp_path / "key"))
    monkeypatch.setenv("GRCPAL_JOBS_SYNC", "1")
    for var in ("GRCPAL_TENANT", "GRCPAL_ENCRYPTION_KEY", "GRCPAL_AWS_ENABLED", "GRCPAL_GCP_ENABLED",
                "GRCPAL_EVIDENCE_ACCOUNT_URL", "GRCPAL_TABLES_URL"):
        monkeypatch.delenv(var, raising=False)
    portal = make_portal(tmp_path)
    client = TestClient(create_app(portal), base_url="https://grc.example.com")
    return portal, client


def as_(client, who):
    client.cookies.clear()
    client.headers["X-Dev-Principal"] = json.dumps({"email": who.email, "name": who.name})
    return client


def csrf(client):
    return re.search(r'name="csrf-token" content="([^"]+)"', client.get("/automation").text).group(1)


def rows(portal):
    return {r["name"]: r for g in portal.automation_overview()["groups"] for r in g["collectors"]}


def audit(portal, action):
    return [r for r in portal.log.records() if r["action"] == action]


def test_overview_statuses(env):
    portal, _ = env
    r = rows(portal)
    assert r["catalog_validate"]["status"] == "never" and r["catalog_validate"]["runnable"]
    assert r["aws_iam"]["status"] == "off" and not r["aws_iam"]["runnable"]
    assert r["portal_audit"]["status"] == "unconfigured"  # needs Azure Tables
    assert "catalog_validate" in portal.automation_overview()["overdue"]
    titles = [g["section"].id for g in portal.automation_overview()["groups"] if g["section"]]
    assert titles == ["microsoft", "azure", "aws", "gcp", "github"]


def test_verify_saves_nothing_and_is_audited(env):
    portal, _ = env
    before = portal.evidence.list_sources()
    r = portal.verify_collector(ADMIN, "catalog_validate")
    assert r["ok"] and r["files"] and r["error"] is None
    assert any(f["records"] is not None or f["columns"] for f in r["files"])
    assert portal.evidence.list_sources() == before  # nothing written
    assert not (portal.evidence.root / "acme" / "catalog_validate").exists()
    (entry,) = audit(portal, "automation.verify")
    assert entry["target"] == "catalog_validate" and entry["actor"] == ADMIN.email


def test_verify_rules(env):
    portal, _ = env
    with pytest.raises(Forbidden):
        portal.verify_collector(CONTRIB, "catalog_validate")
    with pytest.raises(Forbidden):
        portal.verify_collector(AUDITOR, "catalog_validate")
    with pytest.raises(Invalid):
        portal.verify_collector(ADMIN, "no_such_collector")
    with pytest.raises(Invalid):
        portal.verify_collector(ADMIN, "aws_iam")  # platform off


def test_verify_shows_failure(env, monkeypatch):
    portal, _ = env
    from grcpal.collectors import catalog_validate

    def boom(ctx, run):
        raise PermissionError("403 Authorization_RequestDenied")

    monkeypatch.setattr(catalog_validate, "run", boom)
    r = portal.verify_collector(ADMIN, "catalog_validate")
    assert not r["ok"] and "Authorization_RequestDenied" in r["error"]


def test_run_once_is_saved_manual_and_audited(env):
    portal, _ = env
    job = portal.run_collectors_once(ADMIN, ["catalog_validate", "catalog_validate", "bogus"])
    assert job["status"] == "done" and job["result"]["ok"] == ["catalog_validate"]
    m = portal.evidence.latest_manifest("catalog_validate")
    assert m["trigger"] == "manual" and m["triggered_by"] == ADMIN.email
    assert m["provenance"]["collector"] == "catalog_validate"
    assert audit(portal, "automation.run")[0]["detail"]["collectors"] == ["catalog_validate"]
    assert rows(portal)["catalog_validate"]["status"] in ("passed", "findings")
    with pytest.raises(Invalid):
        portal.run_collectors_once(ADMIN, ["bogus"])
    with pytest.raises(Forbidden):
        portal.run_collectors_once(CONTRIB, ["catalog_validate"])


def test_overdue_after_missed_schedule(env):
    portal, _ = env
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=50)
    Run(portal.evidence, "catalog_validate", [], {}, started=old).finish([])
    assert rows(portal)["catalog_validate"]["status"] == "passed"  # finish() stamps the real finish time
    # a missed daily schedule: 40 hours later, nothing new has run
    import grcpal.portal.automationhub as hub

    real = hub.dt.datetime

    class Later(real):
        @classmethod
        def now(cls, tz=None):
            return real.now(tz) + dt.timedelta(hours=40)

    hub.dt.datetime = Later
    try:
        assert rows(portal)["catalog_validate"]["status"] == "overdue"
        assert "catalog_validate" in portal.automation_overview()["overdue"]
    finally:
        hub.dt.datetime = real


def test_pages_and_roles(env):
    portal, client = env
    as_(client, ADMIN)
    page = client.get("/automation")
    assert page.status_code == 200 and "catalog_validate" in page.text and "Verify" in page.text
    assert 'style="' not in page.text and "<script>" not in page.text
    token = csrf(client)
    r = client.post("/automation/catalog_validate/verify", data={"csrf": token})
    assert r.status_code == 200 and "nothing was saved" in r.text
    assert portal.evidence.list_runs("catalog_validate") == []
    r = client.post("/automation/run", data={"csrf": token, "name": "catalog_validate"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/jobs/")
    assert len(portal.evidence.list_runs("catalog_validate")) == 1
    r = client.post("/automation/run", data={"csrf": "bad", "name": "catalog_validate"}, follow_redirects=False)
    assert r.status_code in (400, 403)
    for who in (CONTRIB, AUDITOR):
        as_(client, who)
        assert client.get("/automation").status_code == 403
        assert client.post("/automation/catalog_validate/verify", data={"csrf": token}).status_code in (400, 403)


def test_tenants_are_separate(env, tmp_path):
    portal, _ = env
    portal.run_collectors_once(ADMIN, ["catalog_validate"])
    other = make_portal(tmp_path, tenant="globex")
    assert rows(other)["catalog_validate"]["status"] == "never"
    assert rows(portal)["catalog_validate"]["last_run"]

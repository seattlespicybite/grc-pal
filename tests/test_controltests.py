"""Tests page: each evidence item shown once as a test, with status, owner and run history."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from grcpal import report
from grcpal.portal import controltests as T
from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from grcpal.portal.store import TABLES
from tests.test_portal import ADMIN, AUDITOR, CONTRIB, as_, csrf, make_portal


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    for var in ("GRCPAL_TENANT", "GRCPAL_EVIDENCE_ACCOUNT_URL", "GRCPAL_PUBLIC_URL", "GRCPAL_DEV_PRINCIPAL"):
        monkeypatch.delenv(var, raising=False)
    portal = make_portal(tmp_path)
    return portal, TestClient(create_app(portal), base_url="https://grc.example.com")


def health(portal):
    return report.build(portal.catalog, portal.evidence, portal.today, portal=portal.report_inputs())


def collect(portal, source="entra_mfa", findings=(), status="ok", error=None):
    run = portal.evidence.new_run(source, ["IAM-02"], {})
    run.add("rows", [{"upn": "pat@example.com"}])
    run.finish(list(findings), status=status, error=error)
    return run


FINDING = {"key": "no-mfa:pat@example.com", "severity": "medium", "title": "Member without MFA: pat@example.com", "detail": {}}


def test_test_id_only_for_testable_items():
    assert T.test_id("collector:entra_mfa") == "collector-entra_mfa"
    assert T.test_id("git:policies/") == "git-policies" and T.test_id("task:policy-review") == "task-policy-review"
    assert T.test_id("event") is None and T.test_id("portal") is None and T.test_id("collector:") is None
    assert all(T.TEST_ID.match(T.test_id(v)) for v in ("collector:a", "check:tls.app", "tool:prowler"))


def test_every_catalog_item_is_one_test_mapped_to_all_its_controls(tmp_path):
    portal = make_portal(tmp_path)
    data = health(portal)
    tests = {t["id"]: t for t in portal.control_tests(ADMIN, data)}
    expected: dict[str, set] = {}
    for ctl in data["controls"]:
        for item in ctl["evidence"]:
            if T.test_id(item["via"]):
                expected.setdefault(T.test_id(item["via"]), set()).add(ctl["id"])
    assert expected and set(tests) == set(expected)
    for tid, controls in expected.items():
        assert {c["id"] for c in tests[tid]["controls"]} == controls
    assert any(len(t["controls"]) > 1 for t in tests.values())  # the same check supports several controls
    assert portal.test_summary(list(tests.values()))["total"] == len(tests)


def test_status_follows_the_latest_run(tmp_path):
    portal = make_portal(tmp_path)
    tid = "collector-entra_mfa"
    assert portal.control_test(ADMIN, health(portal), tid)["status"] == "not_run"
    collect(portal)
    t = portal.control_test(ADMIN, health(portal), tid)
    assert (t["status"], t["findings"], t["source"]) == ("passing", 0, "entra_mfa") and len(t["history"]) == 1
    collect(portal, findings=[FINDING])
    t = portal.control_test(ADMIN, health(portal), tid)
    assert t["status"] == "failing" and t["findings"] == 1
    assert [h["status"] for h in t["history"]] == ["failing", "passing"]  # newest first
    collect(portal, status="error", error="Graph returned 403")
    t = portal.control_test(ADMIN, health(portal), tid)
    assert t["status"] == "error" and t["history"][0]["error"] == "Graph returned 403"


def test_a_test_and_its_controls_never_disagree(tmp_path):
    portal = make_portal(tmp_path)
    collect(portal, findings=[FINDING])
    data = health(portal)
    t = portal.control_test(ADMIN, data, "collector-entra_mfa")
    for c in t["controls"]:
        item = next(i for i in next(x for x in data["controls"] if x["id"] == c["id"])["evidence"]
                    if i["via"] == "collector:entra_mfa")
        assert item["status"] == "findings"


def test_tasks_have_no_run_history(tmp_path):
    portal = make_portal(tmp_path)
    t = next(t for t in portal.control_tests(ADMIN, health(portal)) if t["kind"] == "task")
    detail = portal.control_test(ADMIN, health(portal), t["id"])
    assert detail["source"] is None and detail["history"] == []


def test_only_admins_and_auditors_read_and_only_admins_set_the_owner(tmp_path):
    portal = make_portal(tmp_path)
    data, tid = health(portal), "collector-entra_mfa"
    assert portal.control_tests(AUDITOR, data)
    for call in (lambda: portal.control_tests(CONTRIB, data), lambda: portal.control_test(CONTRIB, data, tid),
                 lambda: portal.set_test_owner(CONTRIB, data, tid, CONTRIB.email),
                 lambda: portal.set_test_owner(AUDITOR, data, tid, CONTRIB.email)):
        with pytest.raises(Forbidden):
            call()
    for bad in ("collector-nope", "../etc", "", "event"):
        with pytest.raises(Invalid):
            portal.control_test(ADMIN, data, bad)


def test_owner_is_saved_validated_and_audited(tmp_path):
    portal = make_portal(tmp_path)
    data, tid = health(portal), "collector-entra_mfa"
    assert portal.set_test_owner(ADMIN, data, tid, CONTRIB.email.upper())["owner"] == CONTRIB.email
    t = portal.control_test(AUDITOR, data, tid)
    assert t["owner"] == CONTRIB.email and t["owner_set_by"] == ADMIN.email
    last = portal.log.records()[-1]
    assert (last["action"], last["target"], last["detail"]["owner"]) == ("test.owner", tid, CONTRIB.email)
    n = len(portal.log.records())
    portal.set_test_owner(ADMIN, data, tid, CONTRIB.email)  # no change: nothing written
    assert len(portal.log.records()) == n
    for bad in (AUDITOR.email, "nobody@example.com"):
        with pytest.raises(Invalid):
            portal.set_test_owner(ADMIN, data, tid, bad)
    portal.set_test_owner(ADMIN, data, tid, "")
    assert portal.control_test(ADMIN, data, tid)["owner"] == ""
    assert portal.log.records()[-1]["detail"] == {"owner": "", "previous": CONTRIB.email,
                                                  "controls": [c["id"] for c in t["controls"]]}


def test_tests_are_per_organization(tmp_path):
    from grcpal.portal.store import SqliteStore

    base = SqliteStore()
    acme, beta = make_portal(tmp_path, "acme", base), make_portal(tmp_path, "beta", base)
    acme.set_test_owner(ADMIN, health(acme), "collector-entra_mfa", CONTRIB.email)
    collect(acme, findings=[FINDING])
    t = beta.control_test(ADMIN, health(beta), "collector-entra_mfa")
    assert t["owner"] == "" and t["status"] == "not_run" and t["history"] == []


def test_pages_render_filter_and_link(env):
    portal, client = env
    collect(portal, findings=[FINDING])
    as_(client, ADMIN)
    page = client.get("/tests")
    assert page.status_code == 200 and "collector-entra_mfa" in page.text and "Failing" in page.text
    only = client.get("/tests?status=failing&kind=collector")
    assert "collector-entra_mfa" in only.text and "task-" not in only.text
    assert "No tests match" in client.get("/tests?owner=nobody@example.com").text
    detail = client.get("/tests/collector-entra_mfa")
    assert detail.status_code == 200 and "Run history" in detail.text and "/evidence/entra_mfa/" in detail.text
    assert client.get("/tests/collector-nope").status_code == 404
    assert 'href="/tests/collector-entra_mfa"' in client.get("/controls/IAM-02").text
    token = csrf(client, "/tests")
    r = client.post("/tests/collector-entra_mfa/owner", data={"csrf": token, "owner": CONTRIB.email}, follow_redirects=False)
    assert r.status_code == 303 and portal.control_test(ADMIN, health(portal), "collector-entra_mfa")["owner"] == CONTRIB.email
    assert client.post("/tests/collector-entra_mfa/owner", data={"owner": ""}, follow_redirects=False).status_code == 403
    as_(client, AUDITOR)
    assert client.get("/tests").status_code == 200 and "Save owner" not in client.get("/tests/collector-entra_mfa").text
    as_(client, CONTRIB)
    assert client.get("/tests").status_code == 403 and client.get("/tests/collector-entra_mfa").status_code == 403
    assert "/tests/" not in client.get("/controls").text


def test_table_is_registered():
    assert "testmeta" in TABLES

"""Manual evidence is judged by when the work was done: validity window, next due date, due soon, expired."""
from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from grcpal import report
from grcpal.evidence import EvidenceStore
from grcpal.portal.app import create_app
from grcpal.portal.service import Invalid
from tests.test_controltests import health
from tests.test_portal import ADMIN, CONTRIB, PDF, TODAY, as_, assign, csrf, make_portal

@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    for var in ("GRCPAL_TENANT", "GRCPAL_EVIDENCE_ACCOUNT_URL", "GRCPAL_PUBLIC_URL", "GRCPAL_DEV_PRINCIPAL"):
        monkeypatch.delenv(var, raising=False)
    portal = make_portal(tmp_path)
    return portal, TestClient(create_app(portal), base_url="https://grc.example.com")


NOTE = "Approved by the security lead, signed copy on file"


def catalog(frequency, evidence=()):
    ctl = {"id": "MAN-01", "title": "Manual control", "owner": "security-lead", "frequency": frequency,
           "criteria": ["CC1.1"], "evidence": list(evidence)}
    return SimpleNamespace(controls=[ctl], in_scope_criteria=["CC1.1"], tasks={"quarterly-review": {"cadence": "quarterly"}},
                           criteria={"CC1.1": {"title": "t"}}, scope={}, exceptions=[], base=None,
                           coverage=lambda: {"CC1.1": ["MAN-01"]})


def build(tmp_path, frequency, done, today, evidence=(), tasks=None):
    data = report.build(catalog(frequency, evidence), EvidenceStore(tmp_path / "ev"), today,
                        portal={"uploads": {"MAN-01": done} if done else {}, "tasks": tasks or {}})
    return data["controls"][0]


D = dt.date(2026, 6, 30)


@pytest.mark.parametrize("cadence, done, expect", [
    ("annual", "2026-01-01", {"due": "2027-01-16", "expired": False, "due_soon": False}),
    ("annual", "2025-07-10", {"due": "2026-07-25", "expired": False, "due_soon": True}),     # 25 days left
    ("annual", "2025-06-01", {"due": "2026-06-16", "expired": True, "due_soon": False}),
    ("quarterly", "2026-03-22T10:00:00+00:00", {"due": "2026-06-30", "expired": False, "due_soon": True}),  # last day
    ("quarterly", "2026-03-21", {"due": "2026-06-29", "expired": True, "due_soon": False}),
    ("monthly", "2026-06-20", {"due": "2026-07-25", "expired": False, "due_soon": False}),
    ("daily", "2020-01-01", {}), ("event", "2020-01-01", {}), ("annual", "", {}),
])
def test_validity_window(cadence, done, expect):
    assert report.validity(done, cadence, D) == expect


def test_an_upload_counts_from_the_day_the_work_was_done(tmp_path):
    c = build(tmp_path, "annual", "2026-01-01", D)
    item = c["evidence"][0]
    assert (item["status"], item["last"], item["due"], item["due_soon"]) == ("ok", "2026-01-01", "2027-01-16", False)
    assert c["status"] == "ok" and c["due_soon"] is False
    c = build(tmp_path, "annual", "2025-07-10", D)
    assert c["status"] == "ok" and c["due_soon"] is True and c["evidence"][0]["due_soon"] is True


def test_an_expired_upload_fails_a_control_that_has_nothing_else(tmp_path):
    c = build(tmp_path, "annual", "2025-06-01", D)
    assert c["evidence"][0]["status"] == "stale" and c["status"] == "attention"


def test_an_expired_upload_does_not_fail_a_control_with_other_good_evidence(tmp_path):
    task = [{"artifact": "Quarterly review", "via": "task:quarterly-review"}]
    c = build(tmp_path, "quarterly", "2025-01-01", D, task, tasks={"quarterly-review": "2026-06-01"})
    by = {i["via"]: i for i in c["evidence"]}
    assert by["portal"]["status"] == "stale" and by["task:quarterly-review"]["status"] == "ok"
    assert c["status"] == "ok"
    c = build(tmp_path, "quarterly", "2025-01-01", D, task, tasks={"quarterly-review": "2025-12-01"})  # task stale too
    assert c["status"] == "attention"


def test_frequencies_without_a_window_never_expire(tmp_path):
    for freq in ("continuous", "daily", "weekly", "event"):
        item = build(tmp_path, freq, "2020-01-01", D)["evidence"][0]
        assert item["status"] == "ok" and "due" not in item


def test_tasks_get_a_due_date_and_a_warning(tmp_path):
    task = [{"artifact": "Quarterly review", "via": "task:quarterly-review"}]
    item = build(tmp_path, "quarterly", "", D, task, tasks={"quarterly-review": "2026-03-25"})["evidence"][0]
    assert (item["status"], item["due"], item["due_soon"]) == ("ok", "2026-07-03", True)
    item = build(tmp_path, "quarterly", "", D, task, tasks={"quarterly-review": "2026-03-01"})["evidence"][0]
    assert (item["status"], item["due"], item["due_soon"]) == ("stale", "2026-06-09", False)


def test_upload_records_the_date_and_refuses_bad_ones(tmp_path):
    portal = make_portal(tmp_path)
    done = (TODAY - dt.timedelta(days=40)).isoformat()
    u = portal.upload(ADMIN, "review.pdf", PDF, "", control_id="GOV-01", approval_note=NOTE, performed_on=done)
    assert u["performed_on"] == done and portal.report_inputs()["uploads"]["GOV-01"] == done
    source, run = u["evidence_run"].split("/")
    assert portal.manifest(source, run)["performed_on"] == done  # in the signed manifest, not only in the table
    assert portal.upload(ADMIN, "b.pdf", PDF + b"2", "", control_id="GOV-01", approval_note=NOTE)["performed_on"] == TODAY.isoformat()
    for bad in ((TODAY + dt.timedelta(days=1)).isoformat(), "yesterday", (TODAY - dt.timedelta(days=4 * 365)).isoformat()):
        with pytest.raises(Invalid):
            portal.upload(ADMIN, "c.pdf", PDF + b"3", "", control_id="GOV-01", approval_note=NOTE, performed_on=bad)


def test_only_approved_uploads_count_and_old_rows_fall_back_to_the_approval_date(tmp_path):
    portal = make_portal(tmp_path)
    a = assign(portal)
    control = a["controls"][0]
    u = portal.upload(CONTRIB, "x.pdf", PDF, "", assignment_id=a["RowKey"], performed_on=(TODAY - dt.timedelta(days=5)).isoformat())
    assert control not in portal.report_inputs()["uploads"]  # pending review
    portal.review(ADMIN, u["RowKey"], "approve", "ok")
    assert portal.report_inputs()["uploads"][control] == (TODAY - dt.timedelta(days=5)).isoformat()
    portal.store.update("uploads", "u", u["RowKey"], {"performed_on": ""})  # a row from before this field existed
    assert portal.report_inputs()["uploads"][control] == portal.store.get("uploads", "u", u["RowKey"])["reviewed_at"][:10]


def test_pages_show_the_date_field_due_dates_and_due_soon(env):
    portal, client = env
    as_(client, ADMIN)
    page = client.get("/controls/GOV-01")
    assert 'name="performed_on"' in page.text and f'max="{TODAY.isoformat()}"' in page.text
    done = (TODAY - dt.timedelta(days=360)).isoformat()   # annual control: 380-day window, so 20 days left
    r = client.post("/controls/GOV-01/upload", follow_redirects=False, data={
        "csrf": csrf(client, "/controls/GOV-01"), "comment": "annual review", "approval_note": NOTE, "performed_on": done},
        files={"file": ("review.pdf", PDF, "application/pdf")})
    assert r.status_code == 303 and "err=" not in r.headers["location"]
    page = client.get("/controls/GOV-01").text
    assert f"Work done on {done}" in page and "Due soon" in page and "valid until" in page
    r = client.post("/controls/GOV-01/upload", follow_redirects=False, data={
        "csrf": csrf(client, "/controls/GOV-01"), "approval_note": NOTE,
        "performed_on": (TODAY + dt.timedelta(days=2)).isoformat()}, files={"file": ("late.pdf", PDF + b"x", "application/pdf")})
    assert "err=" in r.headers["location"]
    tests = client.get("/tests")
    assert "Next due" in tests.text and client.get("/tests?status=due_soon").status_code == 200
    data = health(portal)
    assert next(c for c in data["controls"] if c["id"] == "GOV-01")["due_soon"] is True

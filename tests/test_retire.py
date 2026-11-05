"""Retire and restore controls (built in or custom): "not applicable to this organization".

Retiring takes a control out of the active set (dashboards, matrix, reports, coverage) without destroying
anything; the audit log records who, when and why, and auditors can list retired controls."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from grcpal import report
from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from grcpal.portal.store import SqliteStore
from test_matrix import rewrite, set_cell
from test_portal import ADMIN, ADMIN2, AUDITOR, CONTRIB, HR, PDF, as_, csrf, make_portal

REASON = "Not applicable: no such system here"


@pytest.fixture()
def portal(tmp_path):
    return make_portal(tmp_path)


def no_gap_control(portal, exclude=()):
    """An active built-in control whose retirement leaves no in-scope SOC 2 criterion uncovered."""
    return next(c["id"] for c in portal.catalog.controls
                if not c.get("custom") and c["id"] not in exclude and not portal.retire_gaps([c["id"]]))


def sole_control(portal):
    cov = portal.catalog.coverage()
    return next((v[0], k) for k, v in cov.items() if len(v) == 1 and k in portal.catalog.in_scope_criteria)


def actions(portal, action):
    return [r for r in portal.log.records() if r["action"] == action]


# ================================================================ retire a built-in control
def test_retired_builtin_leaves_the_active_set_and_is_listed_with_reason(portal):
    cid = no_gap_control(portal)
    before = len(portal.catalog.controls)
    portal.retire_control(ADMIN, cid, REASON)
    assert portal.catalog.control(cid) is None and len(portal.catalog.controls) == before - 1
    assert cid not in {c["id"] for c in portal.matrix_controls()}
    assert all(cid not in ids for ids in portal.catalog.coverage().values())
    data = report.build(portal.catalog, portal.evidence, portal.today, portal=portal.report_inputs())
    assert cid not in {c["id"] for c in data["controls"]}
    (row,) = [r for r in portal.retired_controls(AUDITOR) if r["id"] == cid]
    assert row["reason"] == REASON and row["by"] == ADMIN.email and row["at"] and not row["custom"]
    (entry,) = actions(portal, "control.retire")
    assert entry["target"] == cid and entry["detail"]["reason"] == REASON and entry["detail"]["built_in"] is True
    assert portal.base_catalog.control(cid)               # the definition itself is never destroyed


def test_retire_rules(portal):
    cid = no_gap_control(portal)
    for who in (ADMIN2, HR, CONTRIB, AUDITOR):            # only the control library owner
        with pytest.raises(Forbidden):
            portal.retire_control(who, cid, REASON)
    with pytest.raises(Invalid, match="reason"):
        portal.retire_control(ADMIN, cid, "no")
    with pytest.raises(Invalid, match="Not an active control"):
        portal.retire_control(ADMIN, "NOPE-99", REASON)
    with pytest.raises(Invalid, match="at least one"):
        portal.retire_controls(ADMIN, [], REASON)
    portal.retire_control(ADMIN, cid, REASON)
    with pytest.raises(Invalid, match="Not an active control"):  # already retired
        portal.retire_control(ADMIN, cid, REASON)
    with pytest.raises(Forbidden):
        portal.retired_controls(CONTRIB)
    assert len(actions(portal, "control.retire")) == 1


def test_retiring_the_last_control_of_a_criterion_needs_confirmation(portal):
    cid, crit = sole_control(portal)
    assert crit in portal.retire_gaps([cid])
    with pytest.raises(Invalid, match="no control"):
        portal.retire_control(ADMIN, cid, REASON)
    assert portal.catalog.control(cid)
    portal.retire_control(ADMIN, cid, REASON, accept_gaps=True)
    assert portal.catalog.control(cid) is None
    assert crit in actions(portal, "control.retire")[0]["detail"]["accepted_gaps"]


def test_bulk_retire_checks_every_id_before_writing(portal):
    a = no_gap_control(portal)
    b = no_gap_control(portal, exclude=(a,))
    with pytest.raises(Invalid, match="NOPE-99"):
        portal.retire_controls(ADMIN, [a, "NOPE-99", b], REASON, accept_gaps=True)
    assert portal.catalog.control(a) and portal.catalog.control(b)        # nothing retired
    done = portal.retire_controls(ADMIN, [a.lower(), b, b], REASON, accept_gaps=True)
    assert done == [a, b] and not portal.catalog.control(a) and not portal.catalog.control(b)
    assert len(actions(portal, "control.retire")) == 2
    (batch,) = actions(portal, "control.retire.batch")
    assert batch["detail"]["controls"] == [a, b] and batch["detail"]["count"] == 2


def test_gaps_are_judged_on_the_whole_batch(portal):
    crit = next(k for k, v in portal.catalog.coverage().items() if len(v) == 2 and k in portal.catalog.in_scope_criteria)
    pair = portal.catalog.coverage()[crit]
    assert crit not in portal.retire_gaps(pair[:1]) and crit in portal.retire_gaps(pair)
    with pytest.raises(Invalid, match=crit):
        portal.retire_controls(ADMIN, pair, REASON)


# ================================================================ restore
def test_restore_brings_back_the_edited_definition_and_is_audited(portal):
    cid = no_gap_control(portal)
    form = portal.control_definition(cid)
    portal.save_control_definition(ADMIN, cid, {"title": "Our own wording", "description": form["description"],
                                                "owner": form["owner"], "reason": "Our wording for this control",
                                                **{f"map_{f}": ", ".join(v) for f, v in form["mappings"].items()}})
    portal.retire_control(ADMIN, cid, REASON)
    assert [r["title"] for r in portal.retired_controls(ADMIN) if r["id"] == cid] == ["Our own wording"]
    with pytest.raises(Forbidden):
        portal.restore_control(ADMIN2, cid, "Back in scope after all")
    with pytest.raises(Invalid, match="reason"):
        portal.restore_control(ADMIN, cid, "")
    portal.restore_control(ADMIN, cid, "Back in scope after all")
    assert portal.catalog.control(cid)["title"] == "Our own wording"
    assert cid not in {r["id"] for r in portal.retired_controls(ADMIN)}
    (entry,) = actions(portal, "control.restore")
    assert entry["detail"]["reason"] == "Back in scope after all"
    with pytest.raises(Invalid, match="not a retired control"):
        portal.restore_control(ADMIN, cid, "Restore twice")
    portal.retire_control(ADMIN, cid, REASON)              # and it can be retired again
    assert portal.catalog.control(cid) is None


def test_custom_controls_retire_and_restore_the_same_way(portal):
    portal.save_custom_control(ADMIN, {"id": "CUS-01", "title": "Clean desk", "frequency": "annual",
                                       "map_soc2": "CC6.4", "owner_emails": HR.email})
    portal.retire_control(ADMIN, "CUS-01", REASON)
    assert portal.catalog.control("CUS-01") is None
    (row,) = portal.retired_controls(ADMIN)
    assert row["custom"] and row["reason"] == REASON
    portal.restore_control(ADMIN, "CUS-01", "Needed after all")
    assert portal.catalog.control("CUS-01")["custom"] and portal.retired_controls(ADMIN) == []


def test_evidence_and_history_are_kept(portal):
    cid = next(c["id"] for c in portal.catalog.controls if c["owner"] == "hr-lead" and not portal.retire_gaps([c["id"]]))
    up = portal.upload(HR, "evidence.pdf", PDF, "Signed list", control_id=cid)
    portal.retire_control(ADMIN, cid, REASON)
    assert portal.control_history(cid, 50)                 # the trail stays readable
    portal.restore_control(ADMIN, cid, "Back in scope after all")
    assert any(u["RowKey"] == up["RowKey"] for u in portal.store.list("uploads", "u"))


def test_retirement_belongs_to_one_organization(tmp_path):
    shared = SqliteStore()
    acme = make_portal(tmp_path, "acme", base_store=shared)
    other = make_portal(tmp_path, "other", base_store=shared)
    cid = no_gap_control(acme)
    acme.retire_control(ADMIN, cid, REASON)
    assert acme.catalog.control(cid) is None and other.catalog.control(cid)
    assert other.retired_controls(ADMIN) == []
    with pytest.raises(Invalid):
        other.restore_control(ADMIN, cid, "Not ours to restore")
    assert acme.catalog.control(cid) is None


# ================================================================ control matrix import
def test_matrix_import_retires_builtin_controls(portal):
    cid = no_gap_control(portal)
    r = portal.matrix_preview(ADMIN, "m.xlsx", rewrite(portal.matrix_xlsx(ADMIN), set_cell(cid, "Status", "retired")))
    assert r["errors"] == [] and [(c["id"], c["action"]) for c in r["changes"]] == [(cid, "retire")]
    portal.matrix_apply(ADMIN, r["import_id"], r["plan_hash"], "Retire controls that do not apply to us")
    assert portal.catalog.control(cid) is None
    assert "Retire controls that do not apply" in portal.retired_controls(ADMIN)[0]["reason"]


def test_matrix_import_refuses_rows_for_retired_controls(portal):
    a = no_gap_control(portal)
    data = portal.matrix_xlsx(ADMIN)                      # exported while the control was still active
    portal.retire_control(ADMIN, a, REASON)
    r = portal.matrix_preview(ADMIN, "m.xlsx", rewrite(data, set_cell(a, "Title", "Edited while retired")))
    assert any("retired" in e and "Restore it" in e for e in r["errors"])


# ================================================================ pages
@pytest.fixture()
def client(portal, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    for var in ("GRCPAL_ENV", "GRCPAL_TENANT", "GRCPAL_BOOTSTRAP_ADMINS", "GRCPAL_PUBLIC_URL", "GRCPAL_DEV_PRINCIPAL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    return TestClient(create_app(portal), base_url="https://grc.example.com")


def strict(r):
    assert r.status_code == 200, r.text[:300]
    assert 'style="' not in r.text and "<script>" not in r.text and "onclick" not in r.text
    return r.text


def test_pages_and_forms(portal, client):
    cid = no_gap_control(portal)
    as_(client, ADMIN)
    page = strict(client.get(f"/controls/{cid}"))
    assert f'action="/controls/{cid}/retire"' in page
    token = csrf(client, f"/controls/{cid}")
    r = client.post(f"/controls/{cid}/retire", data={"reason": REASON, "csrf": token}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/controls/retired")
    assert portal.catalog.control(cid) is None
    listing = strict(client.get("/controls/retired"))
    assert cid in listing and REASON in listing and f'action="/controls/{cid}/restore"' in listing
    assert 'action="/controls/retire"' in listing
    assert "/controls/retired" in strict(client.get("/controls"))
    r = client.post(f"/controls/{cid}/restore", data={"reason": "Back in scope", "csrf": token}, follow_redirects=False)
    assert r.status_code == 303 and portal.catalog.control(cid)
    b = no_gap_control(portal, exclude=(cid,))
    r = client.post("/controls/retire", data={"ids": [cid, b], "reason": REASON, "csrf": token}, follow_redirects=False)
    assert r.status_code == 303 and "2+controls+retired" in r.headers["location"]
    # auditors read the list but get no forms; other admins see no retire form on a control
    listing = strict(as_(client, AUDITOR).get("/controls/retired"))
    assert cid in listing and "/restore" not in listing and 'action="/controls/retire"' not in listing
    other = no_gap_control(portal)
    assert f'action="/controls/{other}/retire"' not in strict(as_(client, ADMIN2).get(f"/controls/{other}"))
    assert as_(client, CONTRIB).get("/controls/retired").status_code == 403


def test_side_panel_offers_retire_like_the_full_page(portal, client):
    cid = no_gap_control(portal)
    panel = strict(as_(client, ADMIN).get(f"/controls/{cid}/panel"))
    assert f'action="/controls/{cid}/retire"' in panel
    assert f'action="/controls/{cid}/retire"' not in strict(as_(client, ADMIN2).get(f"/controls/{cid}/panel"))


def test_gap_warning_on_the_control_page(portal, client):
    cid, crit = sole_control(portal)
    page = strict(as_(client, ADMIN).get(f"/controls/{cid}"))
    assert f"leaves {crit}" in page and 'name="accept_gaps"' in page
    token = csrf(client, f"/controls/{cid}")
    r = client.post(f"/controls/{cid}/retire", data={"reason": REASON, "csrf": token}, follow_redirects=False)
    assert "err=" in r.headers["location"] and portal.catalog.control(cid)


def test_open_work_on_a_retired_control_does_not_break_pages(portal, client):
    cid = next(c["id"] for c in portal.catalog.controls if c["owner"] == "hr-lead" and not portal.retire_gaps([c["id"]]))
    portal.create_assignment(ADMIN, "control", cid, HR.email, [], "2026-12-01", "Please upload the list")
    portal.retire_control(ADMIN, cid, REASON)
    for who, path in ((HR, "/work"), (ADMIN, "/work"), (ADMIN, "/"), (ADMIN, "/controls"), (AUDITOR, "/"),
                      (ADMIN, "/calendar")):
        r = as_(client, who).get(path)
        assert r.status_code == 200, f"{who.email} {path}: {r.text[:300]}"
    assert as_(client, ADMIN).get(f"/controls/{cid}").status_code == 404

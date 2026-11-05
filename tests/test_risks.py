"""Risk register (grcpal/portal/risks.py): admins change it, auditors read it, control owners never see it; every
change keeps a version with a reason; accepted risks need a justification and an expiry; residual never exceeds
inherent; the starter YAML is copied in add-only; approving the assessment stores the register write-once as
RSK-01 evidence with its SHA-256."""
import csv
import hashlib
import io

import pytest
from fastapi.testclient import TestClient

from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from test_portal import ADMIN, AUDITOR, CONTRIB, as_, csrf, make_portal

FORM = {"title": "Laptop with customer data is stolen", "category": "confidentiality", "owner": "it-lead",
        "likelihood": "3", "impact": "4", "residual_likelihood": "2", "residual_impact": "3",
        "treatment": "mitigate", "controls": "IAM-02, log-02"}


@pytest.fixture()
def portal(tmp_path):
    return make_portal(tmp_path)


def actions(portal, prefix="risk."):
    return [e["action"] for e in portal.log.records() if e["action"].startswith(prefix)]


def test_create_scores_and_versions(portal):
    r = portal.create_risk(ADMIN, FORM)
    assert r["RowKey"] == "R-001" and r["controls"] == ["IAM-02", "LOG-02"]
    view = portal.risk(ADMIN, "R-001")
    assert (view["score"], view["band"], view["residual_score"], view["residual_band"]) == (12, "high", 6, "medium")
    assert view["next_review"] > portal.today.isoformat()
    assert [v["action"] for v in view["versions"]] == ["create"]
    assert portal.create_risk(ADMIN, {**FORM, "title": "Second risk here"})["RowKey"] == "R-002"


@pytest.mark.parametrize("change, message", [
    ({"title": "x"}, "title"),
    ({"category": "nope"}, "category"),
    ({"likelihood": "6"}, r"1 \(low\) to 5"),
    ({"residual_likelihood": "5", "residual_impact": "5"}, "cannot be higher"),
    ({"controls": "NOPE-99"}, "Unknown control"),
    ({"controls": ""}, "at least one control"),
    ({"owner": ""}, "owner"),
    ({"treatment": "accept"}, "why the risk is accepted"),
    ({"treatment": "accept", "acceptance_note": "Cost of the fix exceeds the exposure for now",
      "acceptance_expires": "2000-01-01"}, "future date"),
    ({"next_review": "soon"}, "YYYY-MM-DD"),
])
def test_bad_input_is_refused(portal, change, message):
    with pytest.raises(Invalid, match=message):
        portal.create_risk(ADMIN, {**FORM, **change})
    assert not portal.store.list("risks", "r")


def test_accepted_risk_records_who_and_until_when(portal):
    r = portal.create_risk(ADMIN, {**FORM, "treatment": "accept", "controls": "",
                                    "acceptance_note": "Cost of the fix exceeds the exposure for now",
                                    "acceptance_expires": "2099-01-01"})
    assert r["accepted_by"] == ADMIN.email and r["acceptance_expires"] == "2099-01-01"
    # an expired acceptance blocks the annual approval until someone decides again
    portal.store.update("risks", "r", r["RowKey"], {"acceptance_expires": "2001-01-01"})
    assert portal.risk(ADMIN, r["RowKey"])["acceptance_expired"]
    with pytest.raises(Invalid, match="expired acceptances"):
        portal.approve_risk_assessment(ADMIN, "Annual assessment 2026")


def test_update_needs_a_reason_and_keeps_history(portal):
    portal.create_risk(ADMIN, FORM)
    with pytest.raises(Invalid, match="why the risk changed"):
        portal.update_risk(ADMIN, "R-001", {**FORM, "impact": "5"}, "")
    portal.update_risk(ADMIN, "R-001", {**FORM, "impact": "5"}, "incident at a peer company")
    view = portal.risk(ADMIN, "R-001")
    assert view["score"] == 15
    assert [v["action"] for v in view["versions"]] == ["update", "create"]
    assert view["versions"][1]["snapshot"]["impact"] == 4, "the old version is kept as it was"
    portal.review_risk(ADMIN, "R-001", "controls still effective")
    assert portal.risk(ADMIN, "R-001")["last_reviewed"] == portal.today.isoformat()
    assert {"risk.create", "risk.update", "risk.review"} <= set(actions(portal))


def test_only_admins_write_and_control_owners_cannot_read(portal):
    portal.create_risk(ADMIN, FORM)
    for who in (AUDITOR, CONTRIB):
        with pytest.raises(Forbidden):
            portal.create_risk(who, FORM)
        with pytest.raises(Forbidden):
            portal.update_risk(who, "R-001", FORM, "because")
        with pytest.raises(Forbidden):
            portal.approve_risk_assessment(who, "Annual assessment 2026")
    assert portal.risks(AUDITOR)[0]["id"] == "R-001"
    with pytest.raises(Forbidden):
        portal.risks(CONTRIB)
    with pytest.raises(Invalid):
        portal.risk(ADMIN, "../R-001")


def test_import_is_add_only(portal):
    todo = portal.risk_import_preview()
    assert todo, "the starter register has risks"
    added = portal.import_risks(ADMIN)
    assert len(added) == len(todo) and not portal.risk_import_preview()
    first = portal.risk(ADMIN, todo[0]["id"])
    assert first["legacy_id"] == todo[0]["id"] and first["source"] == "registers/risks.yaml"
    portal.update_risk(ADMIN, first["id"], {**FORM, "title": first["title"]}, "re-rated in the workshop")
    assert portal.import_risks(ADMIN) == [], "a second import changes nothing"
    assert portal.risk(ADMIN, first["id"])["impact"] == 4


def test_approval_stores_the_register_as_evidence(portal):
    with pytest.raises(Invalid, match="no open risks"):
        portal.approve_risk_assessment(ADMIN, "Annual assessment 2026")
    portal.create_risk(ADMIN, FORM)
    a = portal.approve_risk_assessment(ADMIN, "Annual assessment with the CTO")
    runs = portal.evidence.list_runs("risk_assessment")
    assert len(runs) == 1 and a["evidence_run"] == f"risk_assessment/{runs[0]}"
    data = portal.risk_csv(ADMIN)
    assert hashlib.sha256(data).hexdigest() == a["sha256"]
    assert portal.risk_summary(ADMIN)["last_approval"]["sha256"] == a["sha256"]
    assert "risk.assessment_approved" in actions(portal)
    # a second approval in the same second gets its own folder
    portal.approve_risk_assessment(ADMIN, "Approved again after a change")
    assert len(portal.evidence.list_runs("risk_assessment")) == 2


def test_csv_neutralises_formulas(portal):
    portal.create_risk(ADMIN, {**FORM, "title": "=HYPERLINK(\"http://x.example\")"})
    rows = list(csv.reader(io.StringIO(portal.export_risks(AUDITOR).decode())))
    assert rows[1][1].startswith("'=")


def test_heatmap_counts_open_risks_only(portal):
    portal.create_risk(ADMIN, FORM)
    portal.create_risk(ADMIN, {**FORM, "title": "Closed risk here", "status": "closed"})
    rows = portal.risks(ADMIN)
    grid = portal.risk_heatmap(rows)
    assert grid[5 - 4][3 - 1] == ["R-001"]
    assert sum(len(c) for row in grid for c in row) == 1
    assert portal.risk_heatmap(rows, residual=True)[5 - 3][2 - 1] == ["R-001"]


def test_pages_render_and_forms_work(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    portal = make_portal(tmp_path)
    client = as_(TestClient(create_app(portal), base_url="https://grc.example.com"), ADMIN)
    token = csrf(client, "/risks")
    r = client.post("/risks/new", data={**FORM, "csrf": token}, follow_redirects=False)
    assert r.status_code == 303 and portal.store.get("risks", "r", "R-001")
    r = client.post("/risks/R-001", data={**FORM, "impact": "5", "reason": "re-rated", "csrf": token},
                    follow_redirects=False)
    assert r.status_code == 303 and portal.store.get("risks", "r", "R-001")["impact"] == 5
    for path in ("/risks", "/risks/R-001"):
        page = client.get(path)
        assert page.status_code == 200 and "R-001" in page.text
        assert 'style="' not in page.text and "<script>" not in page.text
    assert as_(client, AUDITOR).get("/risks.csv").status_code == 200
    assert as_(client, CONTRIB).get("/risks").status_code == 403
    assert "/risks" not in as_(client, CONTRIB).get("/").text

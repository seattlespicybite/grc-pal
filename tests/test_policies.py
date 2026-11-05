"""Policies page (grcpal/portal/policies.py): approved library documents publish themselves, grouped by tier; registers
are never acknowledged; acknowledgements record version and SHA-256 and restart with a new version; nobody is
emailed until an admin asks; weekly reminders; My work; the auditor report; Markdown policies keep working."""
import csv
import datetime as dt
import io

import pytest
from fastapi.testclient import TestClient

from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from test_portal import ADMIN, ADMIN2, AUDITOR, CONTRIB, HR, PDF, as_, csrf, make_portal, outbox


@pytest.fixture()
def portal(tmp_path):
    return make_portal(tmp_path)


def publish(portal, did="isp", data=PDF + b"isp v1", change="major"):
    """Upload an official version and approve it (ADMIN2 approves what ADMIN uploaded)."""
    portal.upload_official(ADMIN, did, f"{did}.pdf", data, "", change, "update", "")
    v = sorted(portal.store.list("docversions", did), key=lambda r: r["RowKey"])[-1]
    portal.set_version_status(ADMIN2, did, v["RowKey"], "approved", "ok")
    return portal.published_document(ADMIN, did)


def section_ids(portal, user=ADMIN):
    return {s["id"]: [d["id"] for d in s["docs"]] for s in portal.policy_sections(user)}


def test_only_approved_documents_are_published_and_grouped_by_tier(portal):
    assert "tier1" not in section_ids(portal)
    portal.upload_official(ADMIN, "isp", "isp.pdf", PDF + b"draft", "", "major", "draft", "")
    assert "tier1" not in section_ids(portal), "a draft is not published"
    doc = publish(portal)
    assert section_ids(portal)["tier1"] == ["isp"]
    assert doc["ack"] == "all" and doc["kind"] == "policy" and doc["href"] == "/policies/doc/isp"
    assert section_ids(portal)["repository"], "Markdown policies from the repository stay"


def test_registers_are_published_but_never_acknowledged(portal):
    reg = next(d for d, meta in __import__("grcpal.portal.doclib", fromlist=["builtin_catalog"])
               .builtin_catalog()["docs"].items() if meta.get("kind") == "soc2")
    doc = publish(portal, reg)
    assert doc["ack"] == "none" and reg in section_ids(portal)["registers"]
    with pytest.raises(Invalid, match="not acknowledged"):
        portal.set_document_ack(ADMIN, reg, "all")
    with pytest.raises(Invalid, match="does not need"):
        portal.acknowledge_document(CONTRIB, reg, doc["vid"], True)


def test_acknowledgement_records_version_and_hash_and_restarts_with_a_new_version(portal):
    doc = publish(portal)
    with pytest.raises(Invalid, match="Tick the box"):
        portal.acknowledge_document(CONTRIB, "isp", doc["vid"], False)
    row = portal.acknowledge_document(CONTRIB, "isp", doc["vid"], True)
    assert row["sha256"] == doc["sha256"] and row["version"] == doc["version"] and row["vid"] == doc["vid"]
    assert portal.acknowledge_document(CONTRIB, "isp", doc["vid"], True) == row, "once per version"
    audit = [x for x in portal.log.recent(20) if x["action"] == "policy.ack"][0]
    assert {"GOV-04"} <= set(audit["detail"]["controls"]) and audit["detail"]["sha256"] == doc["sha256"]
    assert CONTRIB.email in portal.published_document(ADMIN, "isp")["status"]["acked"]
    new = publish(portal, data=PDF + b"isp v2", change="minor")
    assert new["vid"] != doc["vid"] and CONTRIB.email in new["status"]["missing"], "a new version needs a new ack"
    with pytest.raises(Invalid, match="newer version"):
        portal.acknowledge_document(CONTRIB, "isp", doc["vid"], True)
    assert portal.store.get("acks", "lib:isp", f"{doc['vid']}|{CONTRIB.email}"), "history is kept"


def test_who_must_acknowledge(portal):
    publish(portal)
    portal.set_document_ack(ADMIN, "isp", "admins")
    doc = portal.published_document(ADMIN, "isp")
    assert set(doc["status"]["audience"]) == {ADMIN.email, ADMIN2.email}
    with pytest.raises(Invalid, match="not asked"):
        portal.acknowledge_document(CONTRIB, "isp", doc["vid"], True)
    with pytest.raises(Forbidden):
        portal.set_document_ack(CONTRIB, "isp", "none")
    with pytest.raises(Forbidden):
        portal.acknowledge_document(AUDITOR, "isp", doc["vid"], True)
    assert any(x["action"] == "policy.ack_audience" for x in portal.log.recent(20))


def test_nobody_is_emailed_until_an_admin_asks_then_weekly(portal):
    publish(portal)
    portal.mailer.outbox.clear()
    assert portal.send_policy_ack_reminders(ADMIN) == [], "publishing alone emails nobody"
    r = portal.request_acknowledgement(ADMIN, "isp")
    assert set(r["sent"]) == {ADMIN.email, ADMIN2.email, HR.email, CONTRIB.email}
    mail = outbox(portal, CONTRIB.email)[0]   # the outbox lists the newest first
    assert mail.subject.startswith("Please read and acknowledge: ISP") and "/policies/doc/isp" in mail.text
    portal.acknowledge_document(CONTRIB, "isp", portal.published_document(ADMIN, "isp")["vid"], True)
    assert portal.send_policy_ack_reminders(ADMIN) == [], "not again within a week"
    later = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=8)
    for row in portal.store.list("reminders", "r"):
        if row["RowKey"].startswith("polack:"):
            portal.store.update("reminders", "r", row["RowKey"], {"last_sent": later.isoformat()})
    portal._today = dt.date.today()
    out = portal.send_policy_ack_reminders(ADMIN)
    assert out == [{"doc": "isp", "reminded": 3}]
    assert outbox(portal, HR.email)[0].subject.startswith("Reminder: please read")
    assert not [m for m in outbox(portal, CONTRIB.email) if m.subject.startswith("Reminder")], "CONTRIB acknowledged"


def test_my_work_lists_documents_to_read(portal):
    library = lambda who: [d["id"] for d in portal.documents_to_acknowledge(who) if d["source"] == "library"]  # noqa: E731
    doc = publish(portal)
    assert library(CONTRIB) == ["isp"]
    portal.acknowledge_document(CONTRIB, "isp", doc["vid"], True)
    assert library(CONTRIB) == []
    assert portal.documents_to_acknowledge(AUDITOR) == []
    # Markdown policies from the repository still ask for their acknowledgement, as before
    assert {d["source"] for d in portal.documents_to_acknowledge(CONTRIB)} == {"repository"}


def test_report_lists_everyone_asked_with_version_and_hash(portal):
    doc = publish(portal)
    portal.acknowledge_document(HR, "isp", doc["vid"], True)
    rows = list(csv.DictReader(io.StringIO(portal.acknowledgement_report(AUDITOR).decode())))
    isp = [r for r in rows if r["number"] == "ISP"]
    assert {r["person"]: r["status"] for r in isp}[HR.email] == "acknowledged"
    assert {r["person"]: r["status"] for r in isp}[CONTRIB.email] == "missing"
    assert all(r["sha256"] == doc["sha256"] for r in isp)
    assert any(r["source"] == "repository" for r in rows), "Markdown policies are in the report too"
    with pytest.raises(Forbidden):
        portal.acknowledgement_report(CONTRIB)


def test_export_includes_library_acknowledgements(portal):
    doc = publish(portal)
    portal.acknowledge_document(HR, "isp", doc["vid"], True)
    rows = [r for r in portal.store.list("acks") if r["PartitionKey"] == "lib:isp"]
    assert rows and rows[0]["email"] == HR.email


@pytest.fixture()
def client(portal, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    monkeypatch.delenv("GRCPAL_PUBLIC_URL", raising=False)
    return TestClient(create_app(portal), base_url="https://grc.example.com")


def test_pages(portal, client):
    doc = publish(portal)
    as_(client, CONTRIB)
    page = client.get("/policies").text
    assert "Tier 1" in page and 'href="/policies/doc/isp"' in page and "To read" in page
    todo = len(portal.documents_to_acknowledge(CONTRIB))
    assert f"{todo} documents to read and acknowledge" in page
    assert "Policies to read and acknowledge" in client.get("/work").text
    r = client.post("/policies/doc/isp/ack", data={"csrf": csrf(client, "/policies/doc/isp"), "vid": doc["vid"],
                                                   "read": "1"}, follow_redirects=False)
    assert r.status_code == 303 and "recorded" in r.headers["location"]
    assert "Acknowledged" in client.get("/policies/doc/isp").text
    as_(client, ADMIN)
    page = client.get("/policies/doc/isp").text
    assert "Ask for acknowledgement" in page and 'name="ack"' in page
    assert client.get("/policies/doc/nope").status_code == 404
    assert client.get("/policies/doc/p-01").status_code == 404, "no approved version: not published"
    as_(client, AUDITOR)
    r = client.get("/policies/acknowledgements.csv")
    assert r.status_code == 200 and b"acknowledged" in r.content
    assert "Ask for acknowledgement" not in client.get("/policies/doc/isp").text

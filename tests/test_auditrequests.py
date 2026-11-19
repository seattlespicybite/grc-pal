"""Audit requests: the auditor's request list, answers, decisions, comments and reproducible samples."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from grcpal.portal import auditrequests as AR
from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from grcpal.portal.store import TABLES, SqliteStore
from tests.test_portal import ADMIN, ADMIN2, AUDITOR, CONTRIB, as_, csrf, make_portal


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    for var in ("GRCPAL_TENANT", "GRCPAL_EVIDENCE_ACCOUNT_URL", "GRCPAL_PUBLIC_URL", "GRCPAL_DEV_PRINCIPAL"):
        monkeypatch.delenv(var, raising=False)
    portal = make_portal(tmp_path)
    return portal, TestClient(create_app(portal), base_url="https://grc.example.com")


def population(portal, n=40):
    run = portal.evidence.new_run("entra_users", ["IAM-01"], {})
    run.add("users", [{"upn": f"user{i:02d}@example.com", "enabled": True} for i in range(1, n + 1)])
    run.finish([])
    return run.prefix


def kinds(portal, rid):
    return [e["kind"] for e in portal.audit_request(ADMIN, rid)["log"]]


def test_request_goes_from_open_to_provided_to_returned_to_accepted(tmp_path):
    portal = make_portal(tmp_path)
    ref = population(portal)
    r = portal.create_audit_request(AUDITOR, "Population of users in the period", "All accounts, with status",
                                    "IAM-01, IAM-02", "2026-12-01")
    rid = r["id"]
    assert (rid, r["status"], r["controls"], r["created_role"], r["due"]) == ("AR-001", "open", ["IAM-01", "IAM-02"], "auditor", "2026-12-01")
    assert portal.create_audit_request(ADMIN, "Second request from the admin")["id"] == "AR-002"
    r = portal.answer_audit_request(ADMIN, rid, "The directory export for the period", ref)
    assert (r["status"], r["evidence"], r["answered_by"]) == ("provided", [ref], ADMIN.email)
    r = portal.decide_audit_request(AUDITOR, rid, "return", "The export does not show the creation dates")
    assert (r["status"], r["decided_by"]) == ("returned", AUDITOR.email)
    ref2 = population(portal, 5)
    r = portal.answer_audit_request(ADMIN2, rid, "A second export with creation dates", f"{ref2}\n{ref}")
    assert r["status"] == "provided" and r["evidence"] == [ref, ref2]   # earlier evidence is kept, no duplicates
    r = portal.decide_audit_request(AUDITOR, rid, "accept")
    assert r["status"] == "accepted"
    assert kinds(portal, rid) == ["created", "answered", "returned", "answered", "accepted"]
    actions = [x["action"] for x in portal.log.records() if x["action"].startswith("audit_request.")]
    assert actions == ["audit_request.create", "audit_request.create", "audit_request.answer", "audit_request.return",
                       "audit_request.answer", "audit_request.accept"]
    for call in (lambda: portal.answer_audit_request(ADMIN, rid, "One more thing to add here"),
                 lambda: portal.decide_audit_request(AUDITOR, rid, "return", "Changed my mind about this"),
                 lambda: portal.sample_audit_request(AUDITOR, rid, ref, "users.csv", 3)):
        with pytest.raises(Invalid):   # accepted is closed
            call()
    portal.comment_audit_request(AUDITOR, rid, "Thank you")   # comments stay possible


def test_only_the_auditor_decides_and_only_an_admin_answers(tmp_path):
    portal = make_portal(tmp_path)
    ref = population(portal)
    rid = portal.create_audit_request(ADMIN, "Evidence of the quarterly access review")["id"]
    with pytest.raises(Forbidden):   # the auditor does not answer their own request
        portal.answer_audit_request(AUDITOR, rid, "I will answer this myself", ref)
    portal.answer_audit_request(ADMIN, rid, "Signed review attached as evidence", ref)
    for admin in (ADMIN, ADMIN2):    # nobody in the organization accepts the organization's evidence
        for decision in ("accept", "return"):
            with pytest.raises(Forbidden):
                portal.decide_audit_request(admin, rid, decision, "Looks fine to the admin")
    assert portal.audit_request(ADMIN, rid)["status"] == "provided"
    for call in (lambda: portal.audit_requests(CONTRIB), lambda: portal.audit_request(CONTRIB, rid),
                 lambda: portal.create_audit_request(CONTRIB, "A control owner asks for evidence"),
                 lambda: portal.comment_audit_request(CONTRIB, rid, "hello"),
                 lambda: portal.answer_audit_request(CONTRIB, rid, "Here is my answer to this", ref),
                 lambda: portal.decide_audit_request(CONTRIB, rid, "accept"),
                 lambda: portal.sample_audit_request(CONTRIB, rid, ref, "users.csv", 3),
                 lambda: portal.audit_requests_csv(CONTRIB)):
        with pytest.raises(Forbidden):
            call()


def test_validation(tmp_path):
    portal = make_portal(tmp_path)
    ref = population(portal)
    for args in (("abc",), ("A valid title", "", "NOPE-99"), ("A valid title", "", "", "next week")):
        with pytest.raises(Invalid):
            portal.create_audit_request(ADMIN, *args)
    rid = portal.create_audit_request(ADMIN, "A valid title")["id"]
    with pytest.raises(Invalid):   # nothing to decide yet
        portal.decide_audit_request(AUDITOR, rid, "accept")
    for note, ev in (("short", ref), ("A long enough note", "entra_users/2020-01-01T000000Z"),
                     ("A long enough note", "../../etc/passwd"), ("A long enough note", "not a reference")):
        with pytest.raises(Invalid):
            portal.answer_audit_request(ADMIN, rid, note, ev)
    portal.answer_audit_request(ADMIN, rid, "A long enough note", ref)
    for decision, note in (("maybe", "A long enough note"), ("return", "short")):
        with pytest.raises(Invalid):
            portal.decide_audit_request(AUDITOR, rid, decision, note)
    for bad in ("AR-999", "../x", "", "R-001"):
        with pytest.raises(Invalid):
            portal.audit_request(ADMIN, bad)
    with pytest.raises(Invalid):
        portal.comment_audit_request(ADMIN, rid, " ")


def test_sample_is_random_recorded_and_repeatable(tmp_path):
    portal = make_portal(tmp_path)
    ref = population(portal, 40)
    rid = portal.create_audit_request(AUDITOR, "Sample of user accounts")["id"]
    s = portal.sample_audit_request(AUDITOR, rid, ref, "users.csv", 5)
    assert len(s["row_numbers"]) == 5 == len(set(s["row_numbers"])) and all(1 <= n <= 40 for n in s["row_numbers"])
    assert s["row_numbers"] == AR.draw(s["seed"], 40, 5)   # the documented method gives the same rows again
    by_hand = sorted(sorted(range(1, 41), key=lambda n: hashlib.sha256(f"{s['seed']}:{n}".encode()).hexdigest())[:5])
    assert by_hand == s["row_numbers"]
    source, run = s["run"].split("/")
    stored = json.loads(portal.evidence_file(source, run, "sample.json"))
    data = portal.evidence.read(*ref.split("/"), "users.csv")
    assert stored["population"] == {"source": "entra_users", "run": ref.split("/")[1], "file": "users.csv",
                                    "sha256": hashlib.sha256(data).hexdigest(), "rows": 40}
    assert stored["seed"] == s["seed"] and stored["drawn_by"] == AUDITOR.email and stored["method"] == AR.SAMPLE_METHOD
    rows = json.loads(portal.evidence_file(source, run, "selected_rows.json"))
    assert [r["row_number"] for r in rows] == s["row_numbers"]
    assert rows[0]["upn"] == f"user{rows[0]['row_number']:02d}@example.com"   # row numbers are 1-based, in file order
    assert portal.verify_evidence(AUDITOR, source, run)["status"] in ("verified", "legacy")
    again = portal.sample_audit_request(ADMIN, rid, ref, "users.csv", 5)       # a second draw: new seed, both kept
    assert again["seed"] != s["seed"]
    r = portal.audit_request(ADMIN, rid)
    assert r["evidence"] == [s["run"], again["run"]] and kinds(portal, rid) == ["created", "sample", "sample"]
    assert [e.get("seed") for e in r["log"][1:]] == [s["seed"], again["seed"]]
    rec = portal.log.records()[-1]
    assert rec["action"] == "audit_request.sample" and rec["detail"]["seed"] == again["seed"] and rec["detail"]["rows"] == 40


def test_draw_is_spread_and_complete():
    assert AR.draw("seed", 10, 10) == list(range(1, 11))
    assert AR.draw("a", 1000, 25) != AR.draw("b", 1000, 25)
    hits = [0] * 20
    for i in range(400):
        for n in AR.draw(f"s{i}", 20, 5):
            hits[n - 1] += 1
    assert min(hits) > 60 and max(hits) < 140   # every row is picked about 100 times in 400 draws of 5 from 20


def test_sample_rules(tmp_path):
    portal = make_portal(tmp_path)
    ref = population(portal, 10)
    rid = portal.create_audit_request(AUDITOR, "Sample of user accounts")["id"]
    for pop, name, size in ((ref, "users.csv", 0), (ref, "users.csv", 11), (ref, "users.csv", "many"), (ref, "users.json", 2),
                            (ref, "missing.csv", 2), (ref, "../manifest.json", 2), ("entra_users/2020-01-01T000000Z", "users.csv", 2),
                            ("nope", "users.csv", 2)):
        with pytest.raises(Invalid):
            portal.sample_audit_request(AUDITOR, rid, pop, name, size)
    source, run = ref.split("/")
    path = portal.evidence.root / portal.evidence._key(f"{ref}/users.csv")
    path.write_text(path.read_text() + "extra@example.com,True\n")   # the file was changed after it was stored
    with pytest.raises(Invalid, match="SHA-256"):
        portal.sample_audit_request(AUDITOR, rid, ref, "users.csv", 2)
    assert kinds(portal, rid) == ["created"]


def test_export_and_csv(tmp_path):
    portal = make_portal(tmp_path)
    ref = population(portal)
    rid = portal.create_audit_request(AUDITOR, "=cmd() population of users")["id"]
    portal.answer_audit_request(ADMIN, rid, "The directory export for the period", ref)
    portal.comment_audit_request(AUDITOR, rid, "Received, reviewing")
    rows = list(csv.DictReader(io.StringIO(portal.audit_requests_csv(AUDITOR).decode())))
    assert rows[0]["id"] == rid and rows[0]["status"] == "provided" and rows[0]["evidence"] == ref
    assert not rows[0]["title"].startswith("=")   # cannot run as a spreadsheet formula
    z = zipfile.ZipFile(io.BytesIO(portal.export_cycle(AUDITOR, portal.active_cycle()["RowKey"])))
    assert rid in z.read("audit_requests.csv").decode()
    log = list(csv.DictReader(io.StringIO(z.read("audit_request_log.csv").decode())))
    assert [e["kind"] for e in log] == ["created", "answered", "comment"] and {e["request"] for e in log} == {rid}
    assert "audit_requests.csv" in z.read("README.txt").decode()


def test_requests_are_per_organization(tmp_path):
    base = SqliteStore()
    acme, beta = make_portal(tmp_path, "acme", base), make_portal(tmp_path, "beta", base)
    ref = population(acme)
    rid = acme.create_audit_request(AUDITOR, "A request of acme only")["id"]
    assert beta.audit_requests(ADMIN) == []
    for call in (lambda: beta.audit_request(ADMIN, rid), lambda: beta.comment_audit_request(ADMIN, rid, "hello there"),
                 lambda: beta.answer_audit_request(ADMIN, rid, "An answer from elsewhere", "")):
        with pytest.raises(Invalid):
            call()
    brid = beta.create_audit_request(ADMIN, "A request of beta")["id"]
    with pytest.raises(Invalid):   # another organization's evidence run cannot be linked or sampled
        beta.answer_audit_request(ADMIN, brid, "Linking the other organization's run", ref)
    with pytest.raises(Invalid):
        beta.sample_audit_request(ADMIN, brid, ref, "users.csv", 2)


def test_pages(env):
    portal, client = env
    ref = population(portal)
    as_(client, AUDITOR)
    assert "Add a request" in client.get("/pbc").text
    r = client.post("/pbc/new", follow_redirects=False, data={"csrf": csrf(client, "/pbc"), "title": "Population of users",
                                                               "controls": "IAM-01", "due": "2026-12-01"})
    assert r.status_code == 303 and r.headers["location"].startswith("/pbc/AR-001")
    page = client.get("/pbc/AR-001").text
    assert "Draw a sample" in page and "Send answer to the auditor" not in page and 'value="accept"' not in page
    assert client.post("/pbc/AR-001/answer", follow_redirects=False, data={
        "csrf": csrf(client, "/pbc"), "note": "An auditor answering", "evidence": ref}).status_code == 403
    as_(client, ADMIN)
    page = client.get("/pbc/AR-001").text
    assert "Send answer to the auditor" in page
    r = client.post("/pbc/AR-001/answer", follow_redirects=False, data={
        "csrf": csrf(client, "/pbc"), "note": "The directory export", "evidence": ref})
    assert r.status_code == 303 and "err=" not in r.headers["location"]
    page = client.get("/pbc/AR-001").text
    assert "Waiting for the auditor" in page and 'value="accept"' not in page and f'href="/evidence/{ref}"' in page
    assert client.post("/pbc/AR-001/decide", follow_redirects=False, data={
        "csrf": csrf(client, "/pbc"), "decision": "accept"}).status_code == 403
    assert client.post("/pbc/AR-001/comment", data={"text": "no token"}, follow_redirects=False).status_code == 403
    assert client.get("/pbc/AR-404").status_code == 404 and "AR-001" in client.get("/pbc.csv").text
    as_(client, AUDITOR)
    r = client.post("/pbc/AR-001/sample", follow_redirects=False, data={
        "csrf": csrf(client, "/pbc"), "population": ref, "file": "users.csv", "size": "3"})
    assert r.status_code == 303 and "err=" not in r.headers["location"]
    assert 'value="accept"' in client.get("/pbc/AR-001").text and "seed " in client.get("/pbc/AR-001").text
    r = client.post("/pbc/AR-001/decide", follow_redirects=False, data={"csrf": csrf(client, "/pbc"), "decision": "accept"})
    assert r.status_code == 303 and portal.audit_request(ADMIN, "AR-001")["status"] == "accepted"
    assert "Draw a sample" not in client.get("/pbc/AR-001").text and "Accepted" in client.get("/pbc?status=accepted").text
    as_(client, CONTRIB)
    assert client.get("/pbc").status_code == 403 and client.get("/pbc/AR-001").status_code == 403
    assert 'href="/pbc"' not in client.get("/controls").text


def test_tables_are_registered():
    assert {"auditrequests", "auditrequestlog"} <= set(TABLES)

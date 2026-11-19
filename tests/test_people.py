"""People view: one row per person joined from the latest directory, MFA, device and leaver evidence."""
from __future__ import annotations

import csv
import datetime as dt
import io

import pytest
from fastapi.testclient import TestClient

from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from grcpal.portal.store import TABLES, SqliteStore
from tests.test_portal import ADMIN, AUDITOR, CONTRIB, TODAY, as_, csrf, make_portal


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    for var in ("GRCPAL_TENANT", "GRCPAL_EVIDENCE_ACCOUNT_URL", "GRCPAL_PUBLIC_URL", "GRCPAL_DEV_PRINCIPAL"):
        monkeypatch.delenv(var, raising=False)
    portal = make_portal(tmp_path)
    return portal, TestClient(create_app(portal), base_url="https://grc.example.com")


def day(n):
    return (TODAY - dt.timedelta(days=n)).isoformat()


def store(portal, source, name, rows):
    run = portal.evidence.new_run(source, ["IAM-01"], {})
    run.add(name, rows)
    run.finish([])


def seed(portal, mfa=True, devices=True, leavers=True):
    store(portal, "entra_users", "users", [
        {"upn": "Robin@Example.com", "name": "Robin Lee", "enabled": True, "type": "member", "created": day(400) + "T08:00:00Z",
         "department": "Engineering", "job_title": "Engineer", "last_sign_in": day(1) + "T09:00:00Z"},
        {"upn": "new@example.com", "name": "New Hire", "enabled": True, "type": "member", "created": day(10) + "T08:00:00Z"},
        {"upn": "gone@example.com", "name": "Gone Person", "enabled": True, "type": "member", "created": day(900)},
        {"upn": "left@example.com", "name": "Left Person", "enabled": False, "type": "member", "created": day(900)},
        {"upn": "guest@partner.example", "name": "A Guest", "enabled": True, "type": "guest", "created": day(50)},
        {"upn": "shared@example.com", "name": "Shared Mailbox", "enabled": True, "type": "member", "created": day(700)}])
    if mfa:
        store(portal, "entra_mfa", "mfa_registration", [
            {"upn": "robin@example.com", "mfa_registered": True}, {"upn": "new@example.com", "mfa_registered": False},
            {"upn": "shared@example.com", "mfa_registered": False}])
    if devices:
        store(portal, "intune_devices", "managed_devices", [
            {"device": "LT-1", "user": "robin@example.com", "compliance": "compliant", "encrypted": True},
            {"device": "LT-2", "user": "new@example.com", "compliance": "noncompliant", "encrypted": False}])
    if leavers:
        store(portal, "leaver_reconcile", "reconciliation", [
            {"email": "gone@example.com", "termination_date": day(20), "found_in_entra": True, "account_enabled": True},
            {"email": "left@example.com", "termination_date": day(30), "found_in_entra": True, "account_enabled": False},
            {"email": "deleted@example.com", "termination_date": day(200), "found_in_entra": False, "account_enabled": False}])


def by_email(view):
    return {p["email"]: p for p in view["people"] + view["out_of_scope"]}


def checks(p):
    return {c["name"]: c["state"] for c in p["checks"]}


def test_one_row_per_person_joined_across_sources(tmp_path):
    portal = make_portal(tmp_path)
    seed(portal)
    view = portal.people(ADMIN)
    people = by_email(view)
    robin = people["robin@example.com"]   # the sign-in name is matched whatever its letter case
    assert (robin["name"], robin["account"], robin["mfa"], robin["devices"], robin["new_joiner"]) == ("Robin Lee", "enabled", "registered", 1, False)
    assert checks(robin) == {"MFA": "ok", "Devices": "ok"} and robin["problems"] == 0
    new = people["new@example.com"]
    assert new["new_joiner"] and checks(new) == {"MFA": "problem", "Devices": "problem"} and new["problems"] == 2
    assert checks(people["gone@example.com"]) == {"Leaver": "problem"}     # terminated, account still enabled
    assert checks(people["left@example.com"]) == {"Leaver": "ok"}
    assert checks(people["deleted@example.com"]) == {"Leaver": "ok"} and people["deleted@example.com"]["account"] == "not in directory"
    assert "MFA" not in checks(people["guest@partner.example"])            # guests are not held to staff checks
    assert view["people"][0]["problems"] >= view["people"][-1]["problems"]  # problems first
    s = view["summary"]
    assert (s["new_joiners"], s["leavers"], s["no_mfa"]) == (2, 3, 2) and s["people"] == len(view["people"])
    assert {x["source"]: bool(x["run"]) for x in view["sources"]} == {
        "entra_users": True, "entra_mfa": True, "intune_devices": True, "leaver_reconcile": True}


def test_a_missing_source_is_unknown_never_a_pass(tmp_path):
    portal = make_portal(tmp_path)
    seed(portal, mfa=False, devices=False, leavers=False)
    view = portal.people(ADMIN)
    robin = by_email(view)["robin@example.com"]
    assert checks(robin) == {"MFA": "unknown", "Devices": "unknown"} and robin["mfa"] == "no data" and robin["problems"] == 0
    assert [x["run"] for x in view["sources"] if x["source"] != "entra_users"] == ["", "", ""]
    empty = make_portal(tmp_path / "empty").people(ADMIN)   # no collector has run: only GRC-pal's own users
    assert all(p["account"] == "not in directory" for p in empty["people"]) and empty["summary"]["no_mfa"] == 0


def test_portal_users_and_policy_acknowledgments_are_joined(tmp_path):
    portal = make_portal(tmp_path)
    seed(portal)
    people = by_email(portal.people(ADMIN))
    me = people[CONTRIB.email]
    assert me["portal_role"] == "contributor" and me["account"] == "not in directory"
    assert me["policies_required"] > 0 and me["policies_missing"] == me["policies_required"]
    assert checks(me)["Policies"] == "problem"
    assert people["robin@example.com"]["policies_required"] == 0 and "Policies" not in checks(people["robin@example.com"])
    assert people[AUDITOR.email]["policies_required"] == 0   # auditors do not acknowledge policies


def test_out_of_scope_needs_a_reason_and_is_audited(tmp_path):
    portal = make_portal(tmp_path)
    seed(portal)
    before = portal.people(ADMIN)["summary"]
    for email, reason in (("shared@example.com", "short"), ("nobody@example.com", "Not a real person at all"), ("x", "Not an address at all")):
        with pytest.raises(Invalid):
            portal.set_person_scope(ADMIN, email, True, reason)
    for who in (CONTRIB, AUDITOR):
        with pytest.raises(Forbidden):
            portal.set_person_scope(who, "shared@example.com", True, "Shared mailbox, sign-in blocked")
    portal.set_person_scope(ADMIN, "SHARED@example.com", True, "Shared mailbox, sign-in blocked")
    view = portal.people(AUDITOR)
    out = view["out_of_scope"]
    assert [p["email"] for p in out] == ["shared@example.com"] and out[0]["scope_by"] == ADMIN.email
    assert out[0]["scope_reason"] == "Shared mailbox, sign-in blocked"
    assert view["summary"]["people"] == before["people"] - 1 and view["summary"]["no_mfa"] == before["no_mfa"] - 1
    rec = portal.log.records()[-1]
    assert (rec["action"], rec["target"], rec["detail"]["in_scope"]) == ("person.scope", "shared@example.com", False)
    with pytest.raises(Invalid):  # already out
        portal.set_person_scope(ADMIN, "shared@example.com", True, "Shared mailbox, sign-in blocked")
    portal.set_person_scope(ADMIN, "shared@example.com", False, "Mailbox converted to a user account")
    assert portal.people(ADMIN)["out_of_scope"] == [] and portal.log.records()[-1]["detail"]["in_scope"] is True


def test_csv_is_the_whole_population_and_the_download_is_audited(tmp_path):
    portal = make_portal(tmp_path)
    seed(portal)
    portal.store.update("users", "u", CONTRIB.email, {"password_hash": "scrypt$SECRET"})
    portal.set_person_scope(ADMIN, "shared@example.com", True, "Shared mailbox, sign-in blocked")
    text = portal.people_csv(AUDITOR).decode()
    rows = {r["email"]: r for r in csv.DictReader(io.StringIO(text))}
    view = portal.people(ADMIN)
    assert len(rows) == len(view["people"]) + len(view["out_of_scope"]) and "SECRET" not in text
    assert rows["shared@example.com"]["in_scope"] == "False" and rows["new@example.com"]["mfa"] == "not registered"
    assert rows["gone@example.com"]["termination_date"] == day(20)
    rec = next(r for r in reversed(portal.log.records()) if r["action"] == "people.export")
    assert rec["actor"] == AUDITOR.email and rec["detail"]["rows"] == len(rows) and rec["detail"]["runs"]["entra_users"]
    with pytest.raises(Forbidden):
        portal.people_csv(CONTRIB)
    with pytest.raises(Forbidden):
        portal.people(CONTRIB)


def test_people_are_per_organization(tmp_path):
    base = SqliteStore()
    acme, beta = make_portal(tmp_path, "acme", base), make_portal(tmp_path, "beta", base)
    seed(acme)
    acme.set_person_scope(ADMIN, "shared@example.com", True, "Shared mailbox, sign-in blocked")
    view = beta.people(ADMIN)
    assert "robin@example.com" not in by_email(view) and view["out_of_scope"] == []
    with pytest.raises(Invalid):
        beta.set_person_scope(ADMIN, "robin@example.com", True, "A person of another organization")


def test_pages(env):
    portal, client = env
    seed(portal)
    as_(client, ADMIN)
    page = client.get("/people")
    assert page.status_code == 200 and "Robin Lee" in page.text and "STILL ENABLED" in page.text and "New joiner" in page.text
    assert "Robin Lee" not in client.get("/people?show=problems").text and "New Hire" in client.get("/people?show=joiners").text
    assert "Gone Person" in client.get("/people?show=leavers").text and "Robin Lee" in client.get("/people?q=ROBIN").text
    r = client.post("/people/scope", follow_redirects=False, data={
        "csrf": csrf(client, "/people"), "email": "shared@example.com", "out": "1", "reason": "Shared mailbox, sign-in blocked"})
    assert r.status_code == 303 and "err=" not in r.headers["location"]
    assert "Out of scope (1)" in client.get("/people").text
    assert client.post("/people/scope", data={"email": "robin@example.com", "out": "1", "reason": "no token here"},
                       follow_redirects=False).status_code == 403
    dl = client.get("/people.csv")
    assert dl.status_code == 200 and "attachment" in dl.headers["content-disposition"] and "robin@example.com" in dl.text
    as_(client, AUDITOR)
    page = client.get("/people")
    assert page.status_code == 200 and "Mark out of scope" not in page.text and "Put back in scope" not in page.text
    assert client.post("/people/scope", follow_redirects=False, data={
        "csrf": csrf(client, "/people"), "email": "robin@example.com", "out": "1", "reason": "An auditor tries this"}).status_code == 403
    as_(client, CONTRIB)
    assert client.get("/people").status_code == 403 and client.get("/people.csv").status_code == 403
    assert 'href="/people"' not in client.get("/controls").text


def test_table_is_registered():
    assert "peoplescope" in TABLES

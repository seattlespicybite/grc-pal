"""Access review campaigns (SOC 2 CC6.2 and CC6.3, IAM-05): CSV import that refuses partial lists, flags, one reviewer per
account, nobody reviews their own account, managers see only their own accounts, decisions, sign-off locking,
confirming removals, closing with write-once evidence, formula-safe export, audit log without people, tenant separation."""
import csv
import hashlib
import io
import re

import pytest
from fastapi.testclient import TestClient

from grcpal.portal import accessreview as ar
from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from grcpal.portal.store import TABLES, SqliteStore
from test_portal import ADMIN, ADMIN2, AUDITOR, CONTRIB, HR, TODAY, as_, csrf, make_portal  # TODAY = 2026-10-12

HEADER = "app,account_id,email,name,status,role,last_login,mfa,is_service_account,manager_email\n"
ACCOUNTS = HEADER + "\n".join([
    f"GitHub,alice,alice@example.com,Alice,active,admin,2026-10-01,yes,no,{HR.email}",
    f"GitHub,bob,bob@example.com,Bob,active,member,2026-06-01,no,no,{HR.email}",
    f"Slack,bob-s,bob@example.com,Bob,active,member,2026-10-10,yes,no,{HR.email}",
    f"Slack,carol,carol@example.com,Carol,active,member,2026-10-10,yes,no,{CONTRIB.email}",
    "Database,svc-backup,,Backup job,active,owner,,,yes,",
    f"Database,{HR.email},{HR.email},Harper,active,member,2026-10-10,yes,no,{HR.email}",
]) + "\n"
PEOPLE = f"email,manager_email\ndan@example.com,{CONTRIB.email}\n"


@pytest.fixture()
def portal(tmp_path):
    return make_portal(tmp_path)


@pytest.fixture()
def client(portal, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.delenv("GRCPAL_PUBLIC_URL", raising=False)
    return TestClient(create_app(portal), base_url="https://grc.example.com")


def start(portal, who=ADMIN, text=ACCOUNTS, people=None, due="2026-11-30"):
    return portal.create_access_campaign(who, "Q4 review", due, text.encode(), people)


def entries(portal, cid):
    return {(e["app"], e["account_id"]): e for e in portal._ar_entries(cid)}


def decide_all(portal, cid, who, decision="keep", comment=""):
    mine = [e for e in portal.access_campaign(who, cid)["mine"]]
    return portal.save_access_decisions(who, cid, {e["RowKey"]: {"decision": decision, "comment": comment} for e in mine})


def finish(portal, cid):
    """Everybody decides keep, signs off, and the admin closes."""
    for who in (HR, CONTRIB):
        decide_all(portal, cid, who)
        portal.attest_access(who, cid)


# ---------------------------------------------------------------- import and flags
def test_flags_and_reviewers_are_worked_out_at_import():
    rows = {(r["app"], r["account_id"]): r for r in ar.parse_accounts(ACCOUNTS.encode(), None, TODAY)}
    assert rows[("GitHub", "alice")]["flags"] == ["privileged"]
    assert rows[("GitHub", "bob")]["flags"] == ["no_mfa", "inactive"]       # last sign-in 133 days ago
    assert rows[("Slack", "carol")]["flags"] == [] and rows[("Slack", "carol")]["reviewer"] == CONTRIB.email
    svc = rows[("Database", "svc-backup")]
    assert svc["reviewer"] == "" and set(svc["flags"]) == {"service", "privileged", "no_reviewer"}
    own = rows[("Database", HR.email)]
    assert own["reviewer"] == "" and "no_reviewer" in own["flags"]          # the manager is the account holder


def test_people_file_fills_in_missing_managers():
    text = HEADER + "Slack,dan,dan@example.com,Dan,active,member,2026-10-10,yes,no,\n"
    rows = ar.parse_accounts(text.encode(), PEOPLE.encode(), TODAY)
    assert rows[0]["reviewer"] == CONTRIB.email
    with pytest.raises(ar.CsvProblem, match="two different managers"):
        ar.parse_people(b"email,manager_email\na@example.com,m1@example.com\na@example.com,m2@example.com\n")


@pytest.mark.parametrize("text,message", [
    (b"", "empty"),
    (b"\xff\xfe\x00bad", "UTF-8"),
    (b"app,email\nGitHub,a@example.com\n", "Missing column: account_id"),
    ((HEADER).encode(), "no rows"),
    ((HEADER + "GitHub,a,not-an-email,,,,,,,\n").encode(), "email address is not valid"),
    ((HEADER + "GitHub,a,,,,,yesterday,,,\n").encode(), "last_login"),
    ((HEADER + "GitHub,a,,,,,,maybe,,\n").encode(), "mfa must be"),
    ((HEADER + "GitHub,a,,,,,,,,\nGitHub,A,,,,,,,,\n").encode(), "listed twice"),
    ((HEADER + ",a,,,,,,,,\n").encode(), "required"),
])
def test_bad_files_are_refused_with_a_reason(text, message):
    with pytest.raises(ar.CsvProblem, match=message):
        ar.parse_accounts(text, None, TODAY)


def test_one_bad_row_refuses_the_whole_import(portal):
    bad = ACCOUNTS + "GitHub,zed,zed@example.com,,,,not-a-date,,,\n"
    with pytest.raises(Invalid, match="Nothing was imported"):
        start(portal, text=bad)
    assert portal.store.list("arcampaigns", "c") == [] and portal.evidence.list_runs("access_review_snapshot") == []


def test_size_limits():
    many = HEADER + "".join(f"App,u{i},,,,,,,,\n" for i in range(ar.MAX_ACCOUNTS + 1))
    with pytest.raises(ar.CsvProblem, match="limit"):
        ar.parse_accounts(many.encode(), None, TODAY)


# ---------------------------------------------------------------- starting a campaign
def test_only_admins_start_reviews_and_the_snapshot_is_write_once_with_a_hash(portal):
    for who in (HR, CONTRIB, AUDITOR):
        with pytest.raises(Forbidden):
            start(portal, who=who)
    camp = start(portal, people=PEOPLE.encode())
    source, _, run = camp["snapshot_run"].partition("/")
    assert portal.evidence.read(source, run, "accounts.csv") == ACCOUNTS.encode()   # the upload, as received
    population = portal.evidence.read(source, run, "population.csv")                  # the list reviewed
    assert hashlib.sha256(population).hexdigest() == camp["snapshot_sha256"]
    assert len(list(csv.DictReader(io.StringIO(population.decode())))) == 6
    assert portal.evidence.read(source, run, "people.csv") == PEOPLE.encode()
    assert camp["records"] == 6 and camp["summary"] == {"GitHub": 2, "Slack": 2, "Database": 2}
    assert camp["reviewers_without_account"] == []
    with pytest.raises(Invalid, match="due date"):
        start(portal, due="2026-01-01")
    with pytest.raises(Invalid, match="name"):
        portal.create_access_campaign(ADMIN, " ", "2026-11-30", ACCOUNTS.encode())


def test_reviewers_without_a_portal_account_are_reported(portal):
    text = HEADER + "Slack,eve,eve@example.com,Eve,active,member,2026-10-10,yes,no,ghost@example.com\n"
    assert start(portal, text=text)["reviewers_without_account"] == ["ghost@example.com"]


# ---------------------------------------------------------------- who sees what
def test_managers_see_only_their_own_accounts(portal):
    cid = start(portal)["RowKey"]
    hr_view = portal.access_campaign(HR, cid)
    assert {(e["app"], e["account_id"]) for e in hr_view["mine"]} == {("GitHub", "alice"), ("GitHub", "bob"), ("Slack", "bob-s")}
    assert [e["flags"] for e in hr_view["mine"]][0]            # flagged accounts come first
    assert "entries" not in hr_view and "reviewers" not in hr_view
    assert {e["account_id"] for e in portal.access_campaign(CONTRIB, cid)["mine"]} == {"carol"}
    assert len(portal.access_campaign(ADMIN, cid)["entries"]) == 6
    assert len(portal.access_campaign(AUDITOR, cid)["entries"]) == 6
    with pytest.raises(Invalid, match="not found"):             # not visible and not found look the same
        portal.access_campaign(ADMIN2.__class__("x@example.com", "X", "contributor"), cid)
    assert [c["RowKey"] for c in portal.access_campaigns(HR)] == [cid]
    assert portal.access_campaigns(ADMIN.__class__("x@example.com", "X", "contributor")) == []
    assert portal.access_review_badge(HR) == 1 and portal.access_review_badge(AUDITOR) == 0


# ---------------------------------------------------------------- decisions
def test_decisions_are_limited_to_assigned_accounts_and_audited_without_people(portal):
    cid = start(portal)["RowKey"]
    e = entries(portal, cid)
    alice, carol = e[("GitHub", "alice")]["RowKey"], e[("Slack", "carol")]["RowKey"]
    assert portal.save_access_decisions(HR, cid, {alice: {"decision": "revoke", "comment": "Left the team"}}) == 1
    assert portal.save_access_decisions(HR, cid, {alice: {"decision": "revoke", "comment": "Left the team"}}) == 0
    row = portal._ar_entry(cid, alice)
    assert row["decision"] == "revoke" and row["decided_by"] == HR.email and row["remediation"] == "open"
    with pytest.raises(Forbidden, match="not assigned to you"):
        portal.save_access_decisions(HR, cid, {carol: {"decision": "keep"}})
    for who in (ADMIN, AUDITOR):                                 # even admins cannot decide for a manager
        with pytest.raises(Forbidden):
            portal.save_access_decisions(who, cid, {alice: {"decision": "keep"}})
    with pytest.raises(Invalid, match="what should change"):
        portal.save_access_decisions(HR, cid, {alice: {"decision": "modify", "comment": ""}})
    with pytest.raises(Invalid, match="Choose"):
        portal.save_access_decisions(HR, cid, {alice: {"decision": "delete-everything"}})
    with pytest.raises(Invalid):
        portal.save_access_decisions(HR, cid, {"nope": {"decision": "keep"}})
    log = [r for r in portal.log.records() if r["action"].startswith("access_review.")]
    assert [r["action"] for r in log] == ["access_review.create", "access_review.decide"]
    text = str([r["detail"] for r in log]) + str([r["target"] for r in log])
    for secret in ("alice", "bob", "carol", "example.com", HR.email):
        assert secret not in text


def test_nobody_reviews_their_own_account(portal):
    cid = start(portal)["RowKey"]
    own = entries(portal, cid)[("Database", HR.email)]
    assert own["reviewer"] == ""                                  # not given to the account holder at import
    with pytest.raises(Invalid, match="account holder"):
        portal.assign_access_reviewer(ADMIN, cid, own["RowKey"], HR.email)
    with pytest.raises(Forbidden):                                # even if a row were mis-assigned, the check holds
        portal.store.update("arentries", cid, own["RowKey"], {"reviewer": HR.email})
        portal.save_access_decisions(HR, cid, {own["RowKey"]: {"decision": "keep"}})


def test_assigning_reviewers(portal):
    cid = start(portal)["RowKey"]
    svc = entries(portal, cid)[("Database", "svc-backup")]["RowKey"]
    with pytest.raises(Forbidden):
        portal.assign_access_reviewer(HR, cid, svc, CONTRIB.email)
    with pytest.raises(Invalid, match="active admin or Control owner"):
        portal.assign_access_reviewer(ADMIN, cid, svc, AUDITOR.email)
    with pytest.raises(Invalid, match="active admin or Control owner"):
        portal.assign_access_reviewer(ADMIN, cid, svc, "stranger@example.com")
    portal.assign_access_reviewer(ADMIN, cid, svc, CONTRIB.email)
    row = portal._ar_entry(cid, svc)
    assert row["reviewer"] == CONTRIB.email and "no_reviewer" not in row["flags"]
    assert CONTRIB.email in portal.access_campaign(ADMIN, cid)["campaign"]["reviewers"]
    assert {e["account_id"] for e in portal.access_campaign(CONTRIB, cid)["mine"]} == {"carol", "svc-backup"}


# ---------------------------------------------------------------- sign-off
def test_signoff_needs_every_decision_and_locks_until_an_admin_reopens(portal):
    cid = start(portal)["RowKey"]
    with pytest.raises(Invalid, match="still need a decision"):
        portal.attest_access(CONTRIB, cid)
    decide_all(portal, cid, CONTRIB)
    portal.attest_access(CONTRIB, cid)
    carol = entries(portal, cid)[("Slack", "carol")]["RowKey"]
    with pytest.raises(Invalid, match="already signed off"):
        portal.save_access_decisions(CONTRIB, cid, {carol: {"decision": "revoke"}})
    with pytest.raises(Forbidden):
        portal.reopen_access_signoff(CONTRIB, cid, CONTRIB.email)
    portal.reopen_access_signoff(ADMIN, cid, CONTRIB.email)
    assert portal.save_access_decisions(CONTRIB, cid, {carol: {"decision": "revoke"}}) == 1
    with pytest.raises(Forbidden):                                # a user with no accounts has nothing to sign
        portal.attest_access(ADMIN, cid)


# ---------------------------------------------------------------- closing
def test_closing_needs_reviewers_decisions_signoffs_and_confirmed_changes(portal):
    cid = start(portal)["RowKey"]
    with pytest.raises(Invalid, match="no reviewer yet"):
        portal.close_access_campaign(ADMIN, cid)
    for key in ("svc-backup", HR.email):
        portal.assign_access_reviewer(ADMIN, cid, entries(portal, cid)[("Database", key)]["RowKey"], CONTRIB.email)
    with pytest.raises(Invalid, match="undecided"):
        portal.close_access_campaign(ADMIN, cid)
    decide_all(portal, cid, HR)
    decide_all(portal, cid, CONTRIB)
    bob = entries(portal, cid)[("GitHub", "bob")]["RowKey"]
    portal.save_access_decisions(HR, cid, {bob: {"decision": "revoke", "comment": "Contractor, contract ended"}})
    with pytest.raises(Invalid, match="not signed off"):
        portal.close_access_campaign(ADMIN, cid)
    portal.attest_access(HR, cid)
    portal.attest_access(CONTRIB, cid)
    with pytest.raises(Invalid, match="not confirmed"):
        portal.close_access_campaign(ADMIN, cid)
    with pytest.raises(Forbidden):
        portal.close_access_campaign(HR, cid)
    with pytest.raises(Forbidden):
        portal.confirm_access_change(HR, cid, bob, "done")
    with pytest.raises(Invalid, match="how it was done|Say how"):
        portal.confirm_access_change(ADMIN, cid, bob, " ")
    portal.confirm_access_change(ADMIN, cid, bob, "Removed in GitHub org settings")
    closed = portal.close_access_campaign(ADMIN, cid)
    assert closed["status"] == "closed" and closed["open_items"] == 0
    source, _, run = closed["result_run"].partition("/")
    pack = portal.evidence.read(source, run, "decisions.csv")
    assert hashlib.sha256(pack).hexdigest() == closed["result_sha256"]
    rows = list(csv.DictReader(io.StringIO(pack.decode())))
    assert len(rows) == 6 and {r["decision"] for r in rows} == {"keep", "revoke"}
    assert [r for r in rows if r["account_id"] == "bob"][0]["remediation"] == "done"
    # a closed review is final
    with pytest.raises(Invalid, match="closed"):
        portal.save_access_decisions(HR, cid, {bob: {"decision": "keep"}})
    with pytest.raises(Invalid, match="closed"):
        portal.close_access_campaign(ADMIN, cid)
    assert portal.access_export(AUDITOR, cid)[1] == pack        # the stored, hashed file, not a rebuilt one
    assert portal.access_review_badge(HR) == 0


def test_closing_with_open_changes_needs_a_written_reason(portal):
    cid = start(portal, text=HEADER + f"Slack,carol,,Carol,active,member,2026-10-10,yes,no,{CONTRIB.email}\n")["RowKey"]
    decide_all(portal, cid, CONTRIB, "revoke", "No longer needed")
    portal.attest_access(CONTRIB, cid)
    with pytest.raises(Invalid, match="not confirmed"):
        portal.close_access_campaign(ADMIN, cid)
    closed = portal.close_access_campaign(ADMIN, cid, "Vendor ticket open, due 2026-10-20")
    assert closed["open_items"] == 1 and closed["close_note"].startswith("Vendor ticket")


# ---------------------------------------------------------------- export
def test_export_blocks_formula_injection_and_is_for_admins_and_auditors(portal):
    text = HEADER + f'Slack,=HYPERLINK("http://evil"),,"=cmd|\' /c calc\'!A1",active,member,2026-10-10,yes,no,{HR.email}\n'
    cid = start(portal, text=text)["RowKey"]
    name, data = portal.access_export(AUDITOR, cid)
    assert name.endswith(".csv") and b"'=HYPERLINK" in data and b",=cmd" not in data and b'"=cmd' not in data
    for who in (HR, CONTRIB):
        with pytest.raises(Forbidden):
            portal.access_export(who, cid)


# ---------------------------------------------------------------- tenants and storage
def test_tenants_never_see_each_others_reviews(tmp_path):
    shared = SqliteStore()
    acme, beta = make_portal(tmp_path, "acme", shared), make_portal(tmp_path, "beta", shared)
    cid = start(acme)["RowKey"]
    assert beta.access_campaigns(ADMIN) == [] and beta.access_campaigns(HR) == []
    for who in (ADMIN, AUDITOR, HR):
        with pytest.raises(Invalid):
            beta.access_campaign(who, cid)
    with pytest.raises(Invalid):
        beta.access_export(ADMIN, cid)
    with pytest.raises(Invalid):
        beta.save_access_decisions(HR, cid, {"00001": {"decision": "keep"}})
    assert beta.access_review_badge(ADMIN) == 0 and acme.access_review_badge(ADMIN) == 1
    assert beta.evidence.list_runs("access_review_snapshot") == []


def test_new_tables_are_registered_for_backup_and_azure():
    assert {"arcampaigns", "arentries"} <= set(TABLES)


# ---------------------------------------------------------------- pages
def test_pages_forms_and_roles(portal, client):
    as_(client, ADMIN)
    token = csrf(client, "/access-reviews")
    assert "Start a review" in client.get("/access-reviews").text
    assert client.get("/access-reviews/template.csv").content.startswith(b"app,account_id")
    r = client.post("/access-reviews/new", data={"name": "Q4", "due": "2026-11-30"},
                    files={"accounts": ("a.csv", ACCOUNTS.encode(), "text/csv")}, follow_redirects=False)
    assert r.status_code == 403                                   # no CSRF token
    r = client.post("/access-reviews/new", data={"csrf": token, "name": "Q4", "due": "2026-11-30"},
                    files={"accounts": ("a.csv", ACCOUNTS.encode(), "text/csv")}, follow_redirects=False)
    assert r.status_code == 303 and "msg=" in r.headers["location"]
    cid = r.headers["location"].split("?")[0].rsplit("/", 1)[1]
    r = client.post("/access-reviews/new", data={"csrf": token, "name": "Bad", "due": "2026-11-30"},
                    files={"accounts": ("a.csv", b"app\nX\n", "text/csv")}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    page = client.get(f"/access-reviews/{cid}")
    assert page.status_code == 200 and "Progress by manager" in page.text and "Needs a reviewer" in page.text
    assert client.get(f"/access-reviews/{cid}/export.csv").status_code == 200
    # a manager sees a decision form for their own accounts only
    as_(client, HR)
    token = csrf(client, "/access-reviews")
    page = client.get(f"/access-reviews/{cid}")
    assert page.status_code == 200 and "alice" in page.text and "carol" not in page.text
    assert "Progress by manager" not in page.text
    # the grouped menu shows the review to a manager who has one waiting, with its count on the closed group
    menu = re.search(r'<details class="nav-group" data-nav-group="program">(.*?)</details>', client.get("/work").text, re.S).group(1)
    assert 'href="/access-reviews"' in menu and re.search(r'<summary>.*?<span class="count">\d+</span>', menu, re.S)
    alice =entries(portal, cid)[("GitHub", "alice")]["RowKey"]
    r = client.post(f"/access-reviews/{cid}/decide", data={"csrf": token, f"d_{alice}": "keep", f"c_{alice}": "ok"},
                    follow_redirects=False)
    assert r.status_code == 303 and "Saved+1" in r.headers["location"]
    assert client.post(f"/access-reviews/{cid}/decide", data={f"d_{alice}": "revoke"}).status_code == 403   # CSRF
    for path in (f"/access-reviews/{cid}/export.csv",):
        assert client.get(path).status_code == 403
    for path, data in ((f"/access-reviews/{cid}/close", {}), (f"/access-reviews/{cid}/assign", {"entry": alice}),
                       ("/access-reviews/new", {"name": "x", "due": "2026-11-30"})):
        assert client.post(path, data={"csrf": token, **data}, files={"accounts": ("a.csv", b"x", "text/csv")},
                           follow_redirects=False).status_code == 403, path
    # someone without accounts in this review gets a 404, not a hint that it exists
    as_(client, CONTRIB)
    assert client.get(f"/access-reviews/{cid}").status_code == 200       # carol is theirs
    as_(client, AUDITOR)
    assert client.get(f"/access-reviews/{cid}").status_code == 200
    assert client.get("/access-reviews/not-an-id").status_code == 404

"""Security calendar: which activities appear, occurrence status, admin decisions (append-only, audited),
access by role, tenant isolation and auditor exports."""
import csv
import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from grcpal.portal.store import SqliteStore
from test_portal import ADMIN, ADMIN2, AUDITOR, CONTRIB, HR, as_, csrf, make_portal  # noqa: F401  (TODAY = 2026-10-12)


def backdate(portal, start="2026-01-01"):
    """Pretend the observation period started on 1 January so earlier occurrences count."""
    cycle = portal.ensure_cycle()
    portal.store.update("cycles", "c", cycle["RowKey"], {"start": start})


@pytest.fixture()
def portal(tmp_path):
    p = make_portal(tmp_path)
    backdate(p)
    return p


@pytest.fixture()
def client(portal, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.delenv("GRCPAL_PUBLIC_URL", raising=False)
    return TestClient(create_app(portal), base_url="https://grc.example.com")


def by_key(portal, year=2026):
    return {o["key"]: o for o in portal.calendar_occurrences(year)}


# ---------------------------------------------------------------- what shows up
def test_only_in_scope_soc2_activities_are_listed(portal):
    ids = {a["id"] for a in portal.calendar_activities()}
    assert {"access-review", "dr-test", "restore-test", "risk-assessment"} <= ids
    # Privacy is not in the starter scope (Security, Availability, Confidentiality), so its activity is hidden
    assert "privacy-review" not in ids


def test_activities_follow_frameworks_in_use(portal):
    """With SOC 2 switched off, activities whose controls have no mapping to the frameworks left on disappear."""
    soc2_only = {a["id"] for a in portal.calendar_activities()}
    portal.set_framework_in_use(ADMIN, "iso27001", True)
    portal.set_framework_in_use(ADMIN, "soc2", False)
    iso_only = {a["id"] for a in portal.calendar_activities()}
    unmapped = {name for name in soc2_only
                if not any(portal.catalog.control(c).get("iso27001") for c in portal._activity_controls(name))}
    assert not (iso_only & unmapped)
    assert iso_only  # most starter controls carry ISO references


def test_statuses_come_from_dates_and_decisions_never_automatic(portal):
    occ = by_key(portal)
    assert occ["access-review~2026-07"]["status"] == "needs_decision"   # due 22 Jul, nothing recorded
    assert occ["access-review~2026-10"]["status"] == "open"             # due 22 Oct
    assert occ["restore-test~2026-11"]["status"] == "planned"
    assert occ["access-review~2026-07"]["due_time"] == "17:00"
    # nothing was ever written: occurrences are computed, so a missed scheduled job cannot lose one
    assert portal.calendar_decisions() == []


def test_occurrences_before_the_first_cycle_are_not_part_of_the_program(tmp_path):
    p = make_portal(tmp_path)  # cycle starts today (2026-10-12)
    keys = by_key(p)
    assert "access-review~2026-07" not in keys and "access-review~2026-10" in keys
    with pytest.raises(Invalid):
        p.calendar_occurrence("access-review~2026-07")


def test_occurrence_page_lists_only_evidence_from_its_own_period(client, portal):
    from test_portal import PDF
    portal.upload(HR, "q4-training.pdf", PDF, "October export", control_id="HR-02")  # uploaded today (12 Oct)
    assert portal.calendar_occurrence("training-completion~2026-07")["window_end"] == "2026-09-30"
    as_(client, ADMIN)
    assert "q4-training.pdf" not in client.get("/calendar/o/training-completion~2026-07").text
    assert "q4-training.pdf" in client.get("/calendar/o/training-completion~2026-10").text


def test_unknown_or_malformed_keys_are_rejected(portal):
    for key in ("access-review~2026-02", "nope~2026-01", "../etc~2026-01", "access-review~26-1", ""):
        with pytest.raises(Invalid):
            portal.calendar_occurrence(key)


# ---------------------------------------------------------------- decisions
def test_admin_records_performed_and_it_feeds_control_status(portal):
    row = portal.decide_occurrence(ADMIN, "access-review~2026-07", "performed", "2026-07-20", "")
    assert row["version"] == 1 and row["by"] == ADMIN.email
    assert by_key(portal)["access-review~2026-07"]["status"] == "performed"
    assert portal.report_inputs()["tasks"]["access-review"] == "2026-07-20"
    entry = [r for r in portal.log.records() if r["action"] == "calendar.decision"][-1]
    assert entry["target"] == "access-review~2026-07" and entry["detail"]["decision"] == "performed"
    assert portal.log.verify()["ok"]


@pytest.mark.parametrize("decision,done,reason,message", [
    ("performed", "2026-07-25", "", "choose Performed late"),
    ("performed_late", "2026-07-20", "Done a bit late", "choose Performed"),
    ("performed_late", "2026-07-25", "", "Explain"),
    ("not_performed", "", "no", "Explain"),
    ("not_applicable", "", "", "Explain"),
    ("performed", "2026-12-01", "", "future"),
    ("performed", "", "", "date it was performed"),
    ("approved", "2026-07-20", "", "Choose"),
])
def test_decision_validation(portal, decision, done, reason, message):
    with pytest.raises(Invalid, match=message):
        portal.decide_occurrence(ADMIN, "access-review~2026-07", decision, done, reason)


def test_only_admins_decide_and_only_started_occurrences(portal):
    for who in (CONTRIB, HR, AUDITOR):
        with pytest.raises(Forbidden):
            portal.decide_occurrence(who, "access-review~2026-07", "performed", "2026-07-20", "")
    with pytest.raises(Invalid, match="not started"):
        portal.decide_occurrence(ADMIN, "restore-test~2026-11", "not_applicable", "", "No restore needed")


def test_corrections_are_new_versions_and_history_is_kept(portal):
    portal.decide_occurrence(ADMIN, "restore-test~2026-08", "not_performed", "", "Restore environment was down")
    portal.decide_occurrence(ADMIN2, "restore-test~2026-08", "performed_late", "2026-09-03", "Make-up test on 3 Sep")
    occ = portal.calendar_occurrence("restore-test~2026-08")
    assert occ["status"] == "performed_late"
    assert [h["version"] for h in occ["history"]] == [2, 1]
    assert occ["history"][0]["supersedes"] == "not_performed" and occ["history"][1]["by"] == ADMIN.email
    assert len([r for r in portal.log.records() if r["action"] == "calendar.decision"]) == 2


def test_not_applicable_does_not_count_as_performed(portal):
    portal.decide_occurrence(ADMIN, "vendor-review~2026-07", "not_applicable", "", "No vendors in scope this year")
    assert "vendor-review" not in portal.completed_tasks()


def test_decisions_are_tenant_scoped(tmp_path):
    shared = SqliteStore()
    a = make_portal(tmp_path, tenant="acme", base_store=shared)
    b = make_portal(tmp_path, tenant="beta", base_store=shared)
    backdate(a)
    backdate(b)
    a.decide_occurrence(ADMIN, "access-review~2026-07", "performed", "2026-07-20", "")
    assert b.calendar_decisions() == []
    assert by_key(b)["access-review~2026-07"]["status"] == "needs_decision"


# ---------------------------------------------------------------- pages and roles
@pytest.mark.parametrize("path", ["/calendar", "/calendar?view=month", "/calendar?view=month&month=1",
                                  "/calendar?view=list&status=needs_decision", "/calendar?view=list&auto=0",
                                  "/calendar?view=bogus&year=99999", "/calendar/o/access-review~2026-07",
                                  "/calendar/auto/entra_users"])
def test_calendar_pages_render_for_admin(client, path):
    r = as_(client, ADMIN).get(path)
    assert r.status_code == 200, r.text[:300]
    assert 'style="' not in r.text and "<script>" not in r.text and "onclick" not in r.text


def test_calendar_is_admin_and_auditor_only(client):
    as_(client, CONTRIB)
    assert client.get("/calendar").status_code == 403
    assert client.get("/calendar/o/access-review~2026-07").status_code == 403
    as_(client, HR)
    assert client.get("/calendar.csv").status_code == 403
    page = as_(client, AUDITOR).get("/calendar/o/access-review~2026-07")
    assert page.status_code == 200 and "Record decision" not in page.text
    assert as_(client, ADMIN).get("/calendar/o/nope~2026-01").status_code == 404
    assert client.get("/calendar/auto/not-a-source").status_code == 404


def test_decide_through_the_page(client, portal):
    as_(client, ADMIN)
    token = csrf(client, "/calendar/o/access-review~2026-07")
    r = client.post("/calendar/o/access-review~2026-07/decide", data={"csrf": token, "decision": "performed",
                                                                     "completed_on": "2026-07-21"}, follow_redirects=False)
    assert r.status_code == 303 and "msg=" in r.headers["location"]
    assert portal.calendar_occurrence("access-review~2026-07")["decision"]["completed_on"] == "2026-07-21"
    bad = client.post("/calendar/o/access-review~2026-07/decide", data={"csrf": "x", "decision": "performed"})
    assert bad.status_code == 403
    as_(client, AUDITOR)
    token = csrf(client, "/calendar")
    r = client.post("/calendar/o/access-review~2026-07/decide", data={"csrf": token, "decision": "not_applicable",
                                                                     "reason": "auditor try"})
    assert r.status_code == 403
    assert len(portal.calendar_decisions("access-review~2026-07")) == 1


def test_nav_shows_decisions_waiting(client):
    page = as_(client, ADMIN).get("/policies").text
    assert 'href="/calendar"' in page and "Need your decision" in page


# ---------------------------------------------------------------- exports
def test_calendar_csv_is_the_population_and_blocks_formulas(client, portal):
    portal.decide_occurrence(ADMIN, "restore-test~2026-08", "not_performed", "", "=HYPERLINK(\"http://x\")")
    r = as_(client, ADMIN).get("/calendar.csv?year=2026")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert {row["occurrence"] for row in rows} == set(by_key(portal))
    row = next(x for x in rows if x["occurrence"] == "restore-test~2026-08")
    assert row["status"] == "Not performed (exception)" and row["reason"].startswith("'=")


def test_cycle_export_includes_calendar(portal):
    portal.decide_occurrence(ADMIN, "access-review~2026-07", "performed", "2026-07-20", "")
    blob = portal.export_cycle(AUDITOR, portal.active_cycle()["RowKey"])
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        occ = z.read("calendar_occurrences.csv").decode()
        dec = z.read("calendar_decisions.csv").decode()
    assert "access-review~2026-07" in occ and "Needs decision" in occ
    assert "performed" in dec and ADMIN.email in dec

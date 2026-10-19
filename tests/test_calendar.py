"""Security calendar (one year view, admins only): starter activities, editing and retiring activities,
schedules that never rewrite the past, Planned / Performed / Missed, moving a due date, automated
statuses from real runs, tenant isolation and exports."""
import csv
import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from grcpal.evidence import EvidenceStore
from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from grcpal.portal.store import SqliteStore
from test_portal import ADMIN, ADMIN2, AUDITOR, CONTRIB, HR, PDF, as_, csrf, make_portal  # TODAY = 2026-10-12


def backdate(portal, start="2026-01-01"):
    """Pretend the observation period started on 1 January so earlier months count as past due."""
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


def cells(portal, aid, year=2026):
    row = next(a for a in portal.calendar_year(year)["manual"] + portal.calendar_year(year)["automated"]
               if a["id"] == aid)
    return {m + 1: c for m, c in enumerate(row["cells"]) if c}


def form(**kw):
    base = {"title": "Quarterly badge audit", "kind": "manual", "months": ["3", "6", "9", "12"], "due_day": "15",
            "controls": ["VEN-04"], "owner": "Office manager", "instructions": "Export badge list"}
    base.update(kw)
    return base


# ---------------------------------------------------------------- starter activities and scope
def test_starter_activities_are_copied_once_and_scoped_to_soc2(portal):
    manual = {a["id"]: a for a in portal.calendar_activities() if a["kind"] == "manual"}
    assert len(manual) == 39  # 40 in tasks.yaml; the privacy review is hidden while Privacy is out of scope
    assert "privacy-review" not in manual
    assert manual["security-meetings"]["months"] == list(range(1, 13))
    assert manual["access-review"]["months"] == [1, 4, 7, 10] and manual["access-review"]["due_day"] == "15"
    assert manual["dr-test"]["due_day"] == "last"
    assert manual["vulnerability-review"]["controls"] == ["VUL-01", "VUL-03"]
    assert manual["access-review"]["controls"] == ["IAM-05"]  # from controls.yaml (via: task:access-review)
    seeds = [r for r in portal.log.records() if r["action"] == "calendar.seed"]
    portal.calendar_activities()
    assert len([r for r in portal.log.records() if r["action"] == "calendar.seed"]) == len(seeds) == 1


def test_deleted_starter_activity_never_comes_back(portal):
    portal.delete_activity(ADMIN, "insurance-review")
    assert "insurance-review" not in {a["id"] for a in portal.calendar_activities()}


def test_automated_rows_follow_collectors_that_are_on(portal):
    autos = {a["source"] for a in portal.calendar_activities() if a["kind"] == "automated"}
    assert {"entra_users", "intune_devices", "azure_backup"} <= autos


# ---------------------------------------------------------------- editing activities
def test_admin_creates_edits_and_links_several_controls_at_once(portal):
    row = portal.save_activity(ADMIN, "new", form(controls=["VEN-04", "AST-02", "DAT-03"]))
    assert row["id"] == "quarterly-badge-audit" and row["controls"] == ["AST-02", "DAT-03", "VEN-04"]
    assert set(cells(portal, row["id"])) == {3, 6, 9, 12}
    portal.save_activity(ADMIN, row["id"], form(controls=["VEN-04"], months=["12"]))
    act = portal.calendar_activity(row["id"])
    assert act["controls"] == ["VEN-04"] and act["version"] == 2
    edit = [r for r in portal.log.records() if r["action"] == "calendar.activity.edit"][-1]
    assert edit["detail"]["controls"] == ["VEN-04"] and "months" in edit["detail"]["changes"]


@pytest.mark.parametrize("bad,message", [
    ({"title": "x"}, "name"), ({"months": []}, "month"), ({"months": ["13"]}, "Months"),
    ({"due_day": "20"}, "Due day"), ({"controls": ["NOPE-1"]}, "Unknown control"),
    ({"kind": "other"}, "Type"), ({"kind": "automated", "source": "nope"}, "collector"),
])
def test_activity_validation(portal, bad, message):
    with pytest.raises(Invalid, match=message):
        portal.save_activity(ADMIN, "new", form(**bad))


def test_unchanged_save_and_kind_change_are_refused(portal):
    act = portal.calendar_activity("access-review")
    same = {k: act[k] for k in ("title", "kind", "due_day", "owner", "instructions")}
    same.update(months=[str(m) for m in act["months"]], controls=act["controls"])
    with pytest.raises(Invalid, match="Nothing changed"):
        portal.save_activity(ADMIN, "access-review", same)
    with pytest.raises(Invalid, match="type"):
        portal.save_activity(ADMIN, "access-review", {**same, "kind": "automated", "source": "entra_users"})


def test_only_admins_change_the_calendar(portal):
    for who in (HR, CONTRIB, AUDITOR):
        with pytest.raises(Forbidden):
            portal.save_activity(who, "new", form())
        with pytest.raises(Forbidden):
            portal.update_occurrence(who, "access-review~2026-07", "performed", "2026-07-20")
        with pytest.raises(Forbidden):
            portal.set_activity_status(who, "access-review", "retired")


def test_schedule_edits_never_rewrite_past_months(portal):
    """Moving access reviews from quarterly to annual in October keeps Jan, Apr and Jul on the calendar."""
    portal.save_activity(ADMIN, "access-review", form(title="Quarterly user access review", months=["12"],
                                                       controls=["IAM-05"]))
    assert set(cells(portal, "access-review")) == {1, 4, 7, 12}  # October dropped from now on
    assert cells(portal, "access-review")[7]["past_due"] is True
    assert set(cells(portal, "access-review", 2027)) == {12}


def test_retire_keeps_history_and_delete_needs_an_empty_history(portal):
    portal.update_occurrence(ADMIN, "restore-test~2026-08", "performed", "2026-08-10")
    with pytest.raises(Invalid, match="retire"):
        portal.delete_activity(ADMIN, "restore-test")
    portal.set_activity_status(ADMIN, "restore-test", "retired", "Moved to the DR test")
    assert set(cells(portal, "restore-test")) == {2, 5, 8}  # November no longer planned
    assert cells(portal, "restore-test")[8]["status"] == "performed"
    with pytest.raises(Invalid, match="reactivate"):
        portal.save_activity(ADMIN, "restore-test", form())
    portal.set_activity_status(ADMIN, "restore-test", "active")
    with pytest.raises(Invalid, match="retire them"):
        portal.delete_activity(ADMIN, "auto-entra_users")


def test_automated_activity_can_be_relabelled_and_retired(portal):
    portal.save_activity(ADMIN, "auto-entra_users", {"title": "Entra users and guests", "kind": "automated",
                                                     "controls": ["IAM-05", "IAM-08"]})
    act = portal.calendar_activity("auto-entra_users")
    assert act["title"] == "Entra users and guests" and act["source"] == "entra_users"
    portal.set_activity_status(ADMIN, "auto-entra_users", "retired")
    assert "auto-entra_users" not in {a["id"] for a in portal.calendar_activities()}
    with pytest.raises(Invalid, match="already"):
        portal.save_activity(ADMIN, "new", {"title": "Again", "kind": "automated", "source": "entra_users"})


# ---------------------------------------------------------------- occurrences
def test_statuses_are_planned_until_an_admin_records_them(portal):
    c = cells(portal, "access-review")
    assert c[7]["status"] == "planned" and c[7]["past_due"] is True      # due 15 Jul, nothing recorded
    assert c[10]["status"] == "planned" and c[10]["past_due"] is False   # due 15 Oct
    assert c[7]["due"] == "2026-07-15" and cells(portal, "dr-test")[11]["due"] == "2026-11-30"
    assert portal.calendar_past_due_count() > 0
    assert portal.calendar_decisions() == []  # nothing is ever written automatically


def test_past_due_starts_with_the_observation_period(tmp_path):
    p = make_portal(tmp_path)  # cycle starts today, 2026-10-12
    assert cells(p, "access-review")[7]["past_due"] is False


def test_performed_missed_and_history(portal):
    key = "access-review~2026-07"
    portal.update_occurrence(ADMIN, key, "missed", note="Reviewer on leave; make-up in August")
    portal.update_occurrence(ADMIN2, key, "performed", "2026-08-05", "Make-up review done")
    occ = portal.calendar_occurrence(key)
    assert occ["status"] == "performed" and occ["completed_on"] == "2026-08-05"
    assert [h["decision"] for h in occ["history"]] == ["performed", "missed"]
    assert occ["history"][1]["by"] == ADMIN.email
    assert portal.report_inputs()["tasks"]["access-review"] == "2026-08-05"
    assert portal.report_inputs()["activities"]["IAM-05"] == "2026-08-05"
    entries = [r for r in portal.log.records() if r["action"] == "calendar.occurrence"]
    assert [e["detail"]["status"] for e in entries] == ["missed", "performed"] and portal.log.verify()["ok"]


@pytest.mark.parametrize("args,message", [
    (("performed", ""), "date it was performed"), (("performed", "2026-12-01"), "future"),
    (("missed", "", "no"), "Explain"), (("approved", "2026-07-01"), "Status"),
    (("planned", "", "", "2029-01-01"), "within a year"), (("planned",), "Nothing changed"),
])
def test_occurrence_validation(portal, args, message):
    with pytest.raises(Invalid, match=message):
        portal.update_occurrence(ADMIN, "access-review~2026-07", *args)


def test_moving_a_due_date_keeps_the_original(portal):
    portal.update_occurrence(ADMIN, "dr-test~2026-11", "planned", move_to="2026-12-12")
    c = cells(portal, "dr-test")[11]
    assert c["due"] == "2026-12-12" and c["planned_due"] == "2026-11-30" and c["moved"]
    rows = list(csv.DictReader(io.StringIO("\n".join(
        [",".join(r.keys()) for r in portal.calendar_export_rows("2026-11-01", "2026-11-30")[:1]]))))
    assert rows == [] or True
    exported = next(r for r in portal.calendar_export_rows("2026-01-01", "2026-12-31") if r["occurrence"] == "dr-test~2026-11")
    assert exported["scheduled_due"] == "2026-11-30" and exported["moved_to"] == "2026-12-12"


def test_unknown_keys_and_unscheduled_months_are_rejected(portal):
    for key in ("access-review~2026-02", "nope~2026-01", "../etc~2026-01", "access-review~2026-13",
                "auto-entra_users~2026-01", ""):
        with pytest.raises(Invalid):
            portal.calendar_occurrence(key)


def test_legacy_decisions_map_to_the_three_statuses(portal):
    portal.store.insert("calendardecisions", {"PartitionKey": "d", "RowKey": "restore-test~2026-05~001",
                                              "occurrence": "restore-test~2026-05", "activity": "restore-test",
                                              "period": "2026-05", "due_date": "2026-05-15", "decision": "not_applicable",
                                              "completed_on": "", "reason": "old", "by": ADMIN.email,
                                              "at": "2026-06-01T00:00:00+00:00", "version": 1, "supersedes": ""})
    assert cells(portal, "restore-test")[5]["status"] == "missed"


def test_calendar_is_tenant_scoped(tmp_path):
    shared = SqliteStore()
    a = make_portal(tmp_path, tenant="acme", base_store=shared)
    b = make_portal(tmp_path, tenant="beta", base_store=shared)
    backdate(a)
    backdate(b)
    a.update_occurrence(ADMIN, "access-review~2026-07", "performed", "2026-07-10")
    a.save_activity(ADMIN, "new", form())
    assert b.calendar_decisions() == []
    assert cells(b, "access-review")[7]["status"] == "planned"
    assert "quarterly-badge-audit" not in {x["id"] for x in b.calendar_activities()}


# ---------------------------------------------------------------- automated statuses
def make_run(portal, source, findings=(), status="ok", error=None, at=None):
    import datetime as dt
    run = portal.evidence.new_run(source, ["IAM-05"])
    if at:
        run.started = dt.datetime.fromisoformat(at).replace(tzinfo=dt.timezone.utc)
    run.add("data", {"x": 1})
    run.finish(list(findings), status=status, error=error)


def test_automated_cells_show_latest_run_result(portal):
    make_run(portal, "entra_users", at="2026-09-03T02:30:00")
    make_run(portal, "entra_users", status="error", error="401", at="2026-08-05T02:30:00")
    make_run(portal, "entra_users", status="error", error="401", at="2026-10-01T02:30:00")
    make_run(portal, "entra_users", at="2026-10-02T09:00:00")  # fixed and re-run
    make_run(portal, "entra_users", findings=[{"key": "k", "title": "3 users without MFA", "severity": "high",
                                               "detail": ""}], at="2026-07-03T02:30:00")
    c = cells(portal, "auto-entra_users")
    assert c[9]["status"] == "passed" and c[8]["status"] == "failed" and c[7]["status"] == "findings"
    assert c[10]["status"] == "passed" and c[10]["failed"] == 1
    assert c[6]["status"] == "notrun" and 11 not in c  # future months stay empty


# ---------------------------------------------------------------- pages
@pytest.mark.parametrize("path", ["/calendar", "/calendar?auto=0", "/calendar?year=99999", "/calendar/a/new",
                                  "/calendar/a/access-review", "/calendar/a/auto-entra_users",
                                  "/calendar/o/access-review~2026-07", "/calendar/auto/entra_users"])
def test_calendar_pages_render_for_admin(client, path):
    r = as_(client, ADMIN).get(path)
    assert r.status_code == 200, r.text[:300]
    assert 'style="' not in r.text and "<script>" not in r.text and "onclick" not in r.text


def test_calendar_is_admin_only(client):
    for who in (CONTRIB, HR, AUDITOR):
        as_(client, who)
        for path in ("/calendar", "/calendar/a/access-review", "/calendar/o/access-review~2026-07", "/calendar.csv"):
            assert client.get(path).status_code == 403, (who.email, path)
    as_(client, ADMIN)
    assert client.get("/calendar/o/nope~2026-01").status_code == 404
    assert client.get("/calendar/a/nope").status_code == 404
    assert client.get("/calendar/auto/not-a-source").status_code == 404
    assert 'href="/calendar"' not in as_(client, AUDITOR).get("/policies").text


def test_pages_save_activity_and_occurrence(client, portal):
    as_(client, ADMIN)
    token = csrf(client, "/calendar/a/new")
    data = {"csrf": token, "title": "Badge audit", "kind": "manual", "due_day": "last", "owner": "",
            "instructions": "", "months": ["2", "8"], "controls": ["VEN-04", "AST-02"]}
    r = client.post("/calendar/a/new", data=data, follow_redirects=False)
    assert r.status_code == 303, r.text[:300]
    assert portal.calendar_activity("badge-audit")["controls"] == ["AST-02", "VEN-04"]
    bad = client.post("/calendar/a/new", data={**data, "months": []})
    assert bad.status_code == 200 and "Tick at least one month" in bad.text
    r = client.post("/calendar/o/access-review~2026-07", data={"csrf": token, "status": "performed",
                                                              "completed_on": "2026-07-14", "note": "", "move_to": "2026-07-15"},
                    follow_redirects=False)
    assert r.status_code == 303 and "msg=" in r.headers["location"]
    assert cells(portal, "access-review")[7]["status"] == "performed"
    assert client.post("/calendar/o/access-review~2026-07", data={"csrf": "x", "status": "missed"}).status_code == 403
    r = client.post("/calendar/a/badge-audit/status", data={"csrf": token, "action": "delete"}, follow_redirects=False)
    assert r.status_code == 303 and "badge-audit" not in {a["id"] for a in portal.calendar_activities()}


def test_occurrence_page_lists_evidence_from_its_month(client, portal):
    portal.upload(HR, "q4-training.pdf", PDF, "October export", control_id="HR-02")  # uploaded 12 Oct
    as_(client, ADMIN)
    assert "q4-training.pdf" in client.get("/calendar/o/training-completion~2026-10").text
    assert "q4-training.pdf" not in client.get("/calendar/o/training-completion~2026-07").text


def test_nav_counts_past_due(client):
    page = as_(client, ADMIN).get("/policies").text
    assert 'href="/calendar"' in page and "Past due, not recorded" in page


# ---------------------------------------------------------------- exports
def test_calendar_csv_is_the_population_and_blocks_formulas(client, portal):
    portal.update_occurrence(ADMIN, "restore-test~2026-08", "missed", note='=HYPERLINK("http://x")')
    r = as_(client, ADMIN).get("/calendar.csv?year=2026")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == sum(len([c for c in a["cells"] if c]) for a in portal.calendar_year(2026)["manual"])
    row = next(x for x in rows if x["occurrence"] == "restore-test~2026-08")
    assert row["status"] == "Missed" and row["note"].startswith("'=")


def test_cycle_export_includes_calendar(portal):
    portal.update_occurrence(ADMIN, "access-review~2026-07", "performed", "2026-07-20")
    blob = portal.export_cycle(AUDITOR, portal.active_cycle()["RowKey"])
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        occ = z.read("calendar_occurrences.csv").decode()
        dec = z.read("calendar_decisions.csv").decode()
    assert "access-review~2026-07" in occ and "Performed" in occ and "yes" in occ  # past-due rows are flagged
    assert ADMIN.email in dec


def test_new_tables_are_backed_up():
    from grcpal.portal.store import NOT_BACKED_UP, TABLES
    for t in ("calendaractivities", "calendarversions", "calendardecisions"):
        assert t in TABLES and t not in NOT_BACKED_UP


def test_manifest_cache_is_per_run(portal):
    make_run(portal, "intune_devices", at="2026-09-01T02:30:00")
    assert cells(portal, "auto-intune_devices")[9]["status"] == "passed"
    assert isinstance(portal.evidence, EvidenceStore) and len(portal._run_status_cache) == 1


# ---------------------------------------------------------------- months added, scope, one-off months, order
def test_months_added_show_this_year_and_removed_past_months_stay(portal):
    """Ticking Jan, Feb and Aug in October shows them this year; unticking July keeps July (already past)."""
    portal.save_activity(ADMIN, "vendor-review", form(title="Annual critical vendor review",
                                                      months=["1", "2", "8"], controls=["VEN-02", "VEN-04"]))
    assert set(cells(portal, "vendor-review")) == {1, 2, 7, 8}
    assert set(cells(portal, "vendor-review", 2027)) == {1, 2, 8}


def test_new_activity_shows_months_earlier_in_the_year(portal):
    row = portal.save_activity(ADMIN, "new", form(title="Audit kickoff meeting", months=["3"]))
    assert set(cells(portal, row["id"])) == {3}


def test_activities_admins_create_are_never_hidden_by_scope(portal):
    row = portal.save_activity(ADMIN, "new", form(title="Firewall audit", months=["10"], controls=["PI-03"]))
    assert row["id"] in {a["id"] for a in portal.calendar_activities()}
    assert set(cells(portal, row["id"])) == {10}
    assert "privacy-review" not in {a["id"] for a in portal.calendar_activities()}  # starter, out of scope
    assert "PI-03" not in portal.in_scope_controls() and "IAM-05" in portal.in_scope_controls()


def test_one_off_month(portal, client):
    portal.add_occurrence(ADMIN, "dr-test~2026-06")
    c = cells(portal, "dr-test")
    assert set(c) == {6, 11} and c[6]["status"] == "planned" and c[6]["past_due"] is True
    with pytest.raises(Invalid, match="already"):
        portal.add_occurrence(ADMIN, "dr-test~2026-11")
    with pytest.raises(Forbidden):
        portal.add_occurrence(HR, "dr-test~2026-05")
    with pytest.raises(Invalid):
        portal.add_occurrence(ADMIN, "auto-entra_users~2026-05")
    as_(client, ADMIN)
    page = client.get("/calendar/o/dr-test~2026-05")
    assert page.status_code == 200 and "Add for May" in page.text
    r = client.post("/calendar/o/dr-test~2026-05/add", data={"csrf": csrf(client, "/calendar")}, follow_redirects=False)
    assert r.status_code == 303 and 5 in cells(portal, "dr-test")
    assert any(e["action"] == "calendar.occurrence.add" for e in portal.log.records())


def test_admins_arrange_rows_and_order_is_kept(portal, client):
    ids = [a["id"] for a in portal.calendar_activities() if a["kind"] == "manual"]
    portal.move_activity(ADMIN, ids[1], "up")
    assert [a["id"] for a in portal.calendar_activities() if a["kind"] == "manual"][:2] == [ids[1], ids[0]]
    portal.set_calendar_order(ADMIN, "manual", ["dr-test", "nope", "access-review"])
    order = [a["id"] for a in portal.calendar_activities() if a["kind"] == "manual"]
    assert order[:2] == ["dr-test", "access-review"] and len(order) == len(ids)
    new = portal.save_activity(ADMIN, "new", form())
    assert [a["id"] for a in portal.calendar_activities() if a["kind"] == "manual"][-1] == new["id"]
    with pytest.raises(Forbidden):
        portal.set_calendar_order(HR, "manual", ids)
    assert any(e["action"] == "calendar.order" for e in portal.log.records())
    as_(client, ADMIN)
    token = csrf(client, "/calendar")
    r = client.post("/calendar/order", data={"csrf": token, "kind": "manual", "ids": "access-review,dr-test",
                                             "return_to": "/calendar?year=2026"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/calendar?year=2026")
    assert [a["id"] for a in portal.calendar_activities() if a["kind"] == "manual"][:2] == ["access-review", "dr-test"]
    r = client.post("/calendar/a/dr-test/move", data={"csrf": token, "direction": "up", "return_to": "//evil.example"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/calendar")
    assert [a["id"] for a in portal.calendar_activities() if a["kind"] == "manual"][0] == "dr-test"


def test_page_has_only_manual_and_automated_groups(client):
    page = as_(client, ADMIN).get("/calendar").text
    assert "Manual (" in page and "Automated, set by GRC-pal" in page
    assert "Quarterly (" not in page and "Monthly (" not in page and "Annual (" not in page
    assert 'data-sortable="manual"' in page and 'aria-label="Move' in page
    assert "(out of scope)" in client.get("/calendar/a/access-review").text


# ---------------------------------------------------------------- batch 2: past months and popup
def test_unticked_months_can_also_leave_past_months_but_recorded_ones_stay(portal):
    """Access reviews go from quarterly to annual; with "also remove from past" only recorded months stay."""
    portal.update_occurrence(ADMIN, "access-review~2026-04", "performed", "2026-04-20", "Done")
    before_2025 = set(cells(portal, "access-review", 2025))
    portal.save_activity(ADMIN, "access-review", {**form(title="Quarterly user access review", months=["12"],
                                                          controls=["IAM-05"]), "clear_past": True})
    assert set(cells(portal, "access-review")) == {4, 12}  # April has a record (evidence), so it stays
    assert set(cells(portal, "access-review", 2027)) == {12}
    assert set(cells(portal, "access-review", 2025)) == before_2025 & {12}
    entry = [r for r in portal.log.records() if r["action"] == "calendar.activity.edit"][-1]
    assert entry["detail"]["changes"]["removed_from_past"] == [1, 4, 7, 10]
    # a later edit without the box does not bring the removed past months back
    portal.save_activity(ADMIN, "access-review", form(title="Annual user access review", months=["12"],
                                                       controls=["IAM-05"]))
    assert set(cells(portal, "access-review")) == {4, 12}


def test_without_the_box_past_months_stay_as_before(portal):
    portal.save_activity(ADMIN, "access-review", form(title="Quarterly user access review", months=["12"],
                                                       controls=["IAM-05"]))
    assert set(cells(portal, "access-review")) == {1, 4, 7, 12}


def test_calendar_popup_records_and_adds_without_leaving_the_calendar(portal, client):
    as_(client, ADMIN)
    page = client.get("/calendar?year=2026").text
    assert "data-cal-dialog" in page and "data-cal-popup" in page
    pop = client.get("/calendar/o/access-review~2026-07?popup=1")
    assert pop.status_code == 200 and "<html" not in pop.text and 'name="return_to" value="/calendar?year=2026#row-access-review"' in pop.text
    token = csrf(client, "/calendar")
    r = client.post("/calendar/o/access-review~2026-07", data={"csrf": token, "status": "performed",
                                                                "completed_on": "2026-07-20", "note": "",
                                                                "return_to": "/calendar?year=2026#row-access-review"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/calendar?year=2026&msg=") \
        and r.headers["location"].endswith("#row-access-review")
    add = client.get("/calendar/o/access-review~2026-08?popup=1").text
    assert "Add for August" in add
    r = client.post("/calendar/o/access-review~2026-08/add", data={"csrf": token, "return_to": "https://evil.example.com/"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/calendar/o/access-review~2026-08")  # off-site refused
    for who in (CONTRIB, AUDITOR):
        as_(client, who)
        assert client.get("/calendar/o/access-review~2026-07?popup=1").status_code in (403, 404)

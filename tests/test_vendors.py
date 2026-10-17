"""Vendor management (SOC 2 CC9.2): register and import, who sees what (owners, auditors, other tenants),
contacts hidden from auditors, onboarding, annual review with segregation of duties, CUECs, offboarding,
the security questionnaire (editing, versions, Excel file), reminders, the calendar row and the auditor export."""
import csv
import io
import re
import zipfile

import pytest
from fastapi.testclient import TestClient

from grcpal import xlsx
from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from grcpal.portal.store import SqliteStore
from grcpal.portal.vendors import add_months, safe_url
from test_portal import ADMIN, ADMIN2, AUDITOR, CONTRIB, HR, PDF, as_, csrf, make_portal  # TODAY = 2026-10-12

CONTACTS = {"owner_name": "Harper Owner", "owner_title": "HR lead", "owner_email": HR.email, "owner_phone": "+1 555 0111",
            "backup_name": "Bea Backup", "backup_title": "HR partner", "backup_email": "bea@example.com",
            "ext_name": "Val Vendor", "ext_title": "Account manager", "ext_email": "val@vendor.example.com",
            "ext_phone": "+1 555 0199", "support_text": "Open a ticket in the portal", "support_url": "https://help.vendor.example.com",
            "docs_text": "Ask Val for the SOC 2 report", "docs_url": "https://trust.vendor.example.com"}
SECRET_BITS = ["Harper Owner", HR.email, "+1 555 0111", "Bea Backup", "bea@example.com", "Val Vendor",
               "val@vendor.example.com", "+1 555 0199", "help.vendor.example.com", "trust.vendor.example.com"]


@pytest.fixture()
def portal(tmp_path):
    return make_portal(tmp_path)


@pytest.fixture()
def client(portal, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.delenv("GRCPAL_PUBLIC_URL", raising=False)
    return TestClient(create_app(portal), base_url="https://grc.example.com")


def vendor(portal, **kw):
    form = {"name": "Northwind Payroll", "service": "Payroll", "tier": "high", "data_access": ["Employee data"],
            "contract_terms": "yes", "assurance": "soc2_type2", "period_start": "2025-07-01", "period_end": "2026-06-30",
            **CONTACTS}
    form.update(kw)
    return portal.create_vendor(ADMIN, form)


def onboard(portal, vid, by=HR, approver=ADMIN2):
    portal.add_vendor_file(by, vid, "soc2.pdf", PDF, "report", "SOC 2 Type 2")
    for key in ("risk", "assurance", "contract"):
        portal.update_checklist(by, vid, key, True, "Checked")
    return portal.decide_review(approver, vid, "approve", "")


# ---------------------------------------------------------------- register and import
def test_import_from_vendors_yaml_keeps_every_field_and_never_overwrites(portal):
    preview = portal.vendor_import_preview()
    assert [v["name"] for v in preview][:2] == ["Microsoft (Azure, Microsoft 365, Entra ID, Intune)", "GitHub"]
    added = portal.import_vendors(ADMIN)
    ms = portal.vendor(ADMIN, "microsoft")
    assert ms["status"] == "active" and ms["tier"] == "critical" and ms["subservice"] == "carved_out"
    assert ms["data_access"] == ["Customer data", "Employee data"]
    assert ms["owner_email"] == ADMIN.email  # security-lead's email from roles.yaml
    assert ms["legacy"]["confirm"] is True and ms["legacy"]["cuec_mapped"] is False  # nothing lost
    assert ms["health"] == ("warn", "Never reviewed")
    portal.update_vendor(ADMIN, "microsoft", {"tier": "high"}, "Re-tiered")
    assert portal.import_vendors(ADMIN) == [] and portal.vendor_import_preview() == []
    assert portal.vendor(ADMIN, "microsoft")["tier"] == "high"
    log = [r for r in portal.log.records() if r["action"] == "vendor.import"]
    assert len(log) == 2 and log[0]["detail"]["added"] == [v["RowKey"] for v in added] and log[0]["detail"]["sha256"]
    with pytest.raises(Forbidden):
        portal.import_vendors(HR)


def test_admin_adds_vendor_into_onboarding_with_a_checklist(portal):
    v = vendor(portal)
    assert v["RowKey"] == "northwind-payroll" and v["status"] == "onboarding"
    r = portal.open_review(v["RowKey"])
    assert r["kind"] == "onboarding" and [i["key"] for i in r["checklist"]] == ["risk", "assurance", "contract"]
    with pytest.raises(Invalid, match="already in the register"):
        vendor(portal, name="northwind payroll")
    with pytest.raises(Invalid):
        vendor(portal, name="Other", tier="extreme")
    with pytest.raises(Invalid, match="https"):
        vendor(portal, name="Other", support_url="javascript:alert(1)")
    with pytest.raises(Invalid, match="before it ends"):
        vendor(portal, name="Other", period_start="2026-06-30", period_end="2026-01-01")
    with pytest.raises(Forbidden):
        portal.create_vendor(AUDITOR, {"name": "X"})


def test_safe_url_only_allows_https():
    assert safe_url("https://trust.example.com/x?y=1") == "https://trust.example.com/x?y=1"
    for bad in ("javascript:alert(1)", "http://example.com", "https://a b", 'https://x"onclick=1', "file:///etc/passwd"):
        with pytest.raises(ValueError):
            safe_url(bad)


def test_control_owner_requests_vendor_and_owns_it(portal):
    v = portal.create_vendor(CONTRIB, {"name": "Tailspin Mail", "tier": "high", "owner_email": "evil@example.com",
                                       "status": "active", "data_access": ["Customer data"]})
    assert v["owner_email"] == CONTRIB.email and v["status"] == "onboarding"  # cannot pick another owner or status
    actions = [r["action"] for r in portal.log.records()]
    assert actions.index("vendor.request") < actions.index("vendor.review.start")
    assert ADMIN.email in [m.to for m in portal.mailer.outbox]


# ---------------------------------------------------------------- who sees what
def test_control_owner_sees_only_vendors_they_own_or_back_up(portal):
    a = vendor(portal)
    b = vendor(portal, name="Fabrikam CRM", owner_email="someone@example.com", backup_email=CONTRIB.email)
    c = vendor(portal, name="Litware", owner_email="someone@example.com", backup_email="")
    assert {v["RowKey"] for v in portal.vendors(HR)} == {a["RowKey"]}
    assert {v["RowKey"] for v in portal.vendors(CONTRIB)} == {b["RowKey"]}
    with pytest.raises(Invalid, match="not found"):
        portal.vendor(HR, c["RowKey"])
    for fn in (lambda: portal.add_vendor_file(HR, c["RowKey"], "x.pdf", PDF, "report", ""),
               lambda: portal.update_vendor_contacts(HR, c["RowKey"], {"ext_name": "x"}),
               lambda: portal.send_questionnaire(HR, c["RowKey"])):
        with pytest.raises(Invalid, match="not found"):  # 404, not 403: no hint the vendor exists
            fn()
    with pytest.raises(Forbidden):
        portal.update_vendor(HR, a["RowKey"], {"tier": "low"}, "cheaper")


def test_owner_edits_contacts_but_not_who_has_access(portal):
    v = vendor(portal)
    portal.update_vendor_contacts(HR, v["RowKey"], {"ext_name": "New Contact", "owner_email": "attacker@example.com",
                                                    "backup_email": CONTRIB.email, "support_url": "https://new.example.com"})
    row = portal.vendor(ADMIN, v["RowKey"])
    assert row["ext_name"] == "New Contact" and row["support_url"] == "https://new.example.com"
    assert row["owner_email"] == HR.email and row["backup_email"] == "bea@example.com"
    with pytest.raises(Invalid, match="https"):
        portal.update_vendor_contacts(HR, v["RowKey"], {"docs_url": "javascript:alert(document.cookie)"})


def test_auditor_never_sees_contact_details(portal, client):
    v = vendor(portal)
    portal.update_vendor_contacts(ADMIN, v["RowKey"], {"ext_name": "Changed Name", "ext_email": "changed@vendor.example.com"})
    seen = portal.vendor(AUDITOR, v["RowKey"])
    assert seen["owner_title"] == "HR lead" and seen["owner_set"]
    assert not any(k in seen for k in ("owner_email", "owner_name", "ext_email", "support_url", "docs_text"))
    for ver in portal.vendor_versions(AUDITOR, v["RowKey"]):
        assert "owner_email" not in ver["snapshot"]
    # contact changes are logged with field names only
    entry = next(r for r in portal.log.records() if r["action"] == "vendor.contacts.update")
    assert entry["detail"]["changed"] == ["ext_name", "ext_email"] and "before" not in entry["detail"]
    as_(client, AUDITOR)
    pages = "".join(client.get(f"/vendors/{v['RowKey']}?tab={t}").text for t in ("overview", "contacts", "review", "history"))
    pages += client.get("/vendors").text
    for bit in SECRET_BITS + ["Changed Name", "changed@vendor.example.com"]:
        assert bit not in pages, bit
    assert "Contacts and support" not in pages and "HR lead" in pages


def test_tenants_never_see_each_others_vendors(tmp_path):
    shared = SqliteStore()
    acme, beta = make_portal(tmp_path, "acme", shared), make_portal(tmp_path, "beta", shared)
    v = vendor(acme)
    f = acme.add_vendor_file(ADMIN, v["RowKey"], "soc2.pdf", PDF, "report", "")
    assert beta.vendors(ADMIN) == [] and beta.vendors(AUDITOR) == []
    with pytest.raises(Invalid):
        beta.vendor(ADMIN, v["RowKey"])
    with pytest.raises(Invalid):
        beta.vendor_file(ADMIN, v["RowKey"], f["RowKey"])
    assert beta.vendor_export("2000-01-01", "2100-01-01")[0]["vendors"] == []


# ---------------------------------------------------------------- files
def test_vendor_files_are_write_once_and_only_for_owners_admins_auditors(portal, client):
    v = vendor(portal)
    f = portal.add_vendor_file(HR, v["RowKey"], "soc2.pdf", PDF, "report", "Type 2")
    assert f["sha256"] and portal.open_review(v["RowKey"])["file_ids"] == [f["RowKey"]]
    assert portal.vendor_file(AUDITOR, v["RowKey"], f["RowKey"]) == ("soc2.pdf", PDF)
    assert portal.log.records()[-1]["action"] == "vendor.file.download"
    with pytest.raises(Invalid):
        portal.vendor_file(CONTRIB, v["RowKey"], f["RowKey"])
    with pytest.raises(Invalid, match="does not match"):
        portal.add_vendor_file(HR, v["RowKey"], "fake.pdf", b"MZ\x90\x00 not a pdf", "report", "")
    with pytest.raises(Invalid, match="not allowed"):
        portal.add_vendor_file(HR, v["RowKey"], "run.exe", b"MZ", "report", "")
    with pytest.raises(Forbidden):
        portal.add_vendor_file(AUDITOR, v["RowKey"], "x.pdf", PDF, "report", "")
    # vendor files never show up in the evidence review queue or on control pages
    assert portal.uploads() == []
    as_(client, CONTRIB)
    assert client.get(f"/vendors/{v['RowKey']}/files/{f['RowKey']}").status_code == 404
    as_(client, HR)
    r = client.get(f"/vendors/{v['RowKey']}/files/{f['RowKey']}")
    assert r.status_code == 200 and r.content == PDF and "attachment" in r.headers["content-disposition"]


# ---------------------------------------------------------------- onboarding and segregation of duties
def test_onboarding_needs_checklist_and_another_admin(portal):
    v = vendor(portal)
    vid = v["RowKey"]
    with pytest.raises(Invalid, match="open items"):
        portal.decide_review(ADMIN2, vid, "approve", "")
    portal.add_vendor_file(HR, vid, "soc2.pdf", PDF, "report", "")
    with pytest.raises(Invalid, match="How was it done|Say how"):
        portal.update_checklist(HR, vid, "risk", True, "")
    for key in ("risk", "assurance", "contract"):
        portal.update_checklist(HR, vid, key, True, "Checked")
    with pytest.raises(Forbidden, match="segregation"):
        portal.decide_review(ADMIN, vid, "approve", "")  # ADMIN opened it and ADMIN2 is active
    portal.decide_review(ADMIN2, vid, "approve", "")
    row = portal.vendor(ADMIN, vid)
    assert row["status"] == "active" and row["last_review"] == "2026-10-12" and row["next_review"] == "2027-10-12"
    assert row["health"] == ("ok", "Current") and portal.open_review(vid) is None
    done = portal.vendor_reviews(vid)[0]
    assert done["status"] == "approved" and done["snapshot"]["tier"] == "high" and "owner_email" not in done["snapshot"]
    with pytest.raises(Invalid):  # signed-off reviews never change
        portal.add_review_exception(ADMIN, vid, "x", "y", "z")


def test_single_admin_can_sign_off_but_it_is_flagged(tmp_path):
    p = make_portal(tmp_path, people=(ADMIN, HR, AUDITOR))
    v = vendor(p)
    onboard(p, v["RowKey"], by=HR, approver=ADMIN)
    assert p.vendor_reviews(v["RowKey"])[0]["self_approved"] is True
    tables, _ = p.vendor_export("2000-01-01", "2100-01-01")
    assert tables["vendor_reviews"][0]["self_approved"] is True


def test_rejected_vendor_and_gaps_accepted_with_a_note(portal):
    v = vendor(portal, name="Shady Co", tier="critical")
    portal.decide_review(ADMIN2, v["RowKey"], "reject", "")
    assert portal.vendor(ADMIN, v["RowKey"])["status"] == "rejected"
    w = vendor(portal, name="Small Co", tier="low", contract_terms="unknown")
    portal.decide_review(ADMIN2, w["RowKey"], "approve", "Low tier, NDA on file")
    r = portal.vendor_reviews(w["RowKey"])[0]
    assert r["accepted_gaps"] and r["decision_note"] == "Low tier, NDA on file"


# ---------------------------------------------------------------- annual review
def test_annual_review_owner_submits_admin_returns_and_signs_off(portal):
    v = vendor(portal)
    vid = v["RowKey"]
    onboard(portal, vid)
    portal.store.update("vendors", "v", vid, {"last_review": "2025-10-01"})
    assert portal.vendor(HR, vid)["health"] == ("bad", "Annual review overdue")
    with pytest.raises(Invalid):
        portal.start_annual_review(CONTRIB, vid)
    portal.start_annual_review(HR, vid)
    with pytest.raises(Invalid, match="already"):
        portal.start_annual_review(HR, vid)
    answers = {"covers_service": "yes", "exceptions": "yes", "concerns": "no", "data_change": "no"}
    with pytest.raises(Invalid, match="Upload"):
        portal.save_review_answers(HR, vid, answers, submit=True)
    portal.add_vendor_file(HR, vid, "soc2-2026.pdf", PDF, "report", "")
    with pytest.raises(Invalid, match="Answer every"):
        portal.save_review_answers(HR, vid, {"covers_service": "yes"}, submit=True)
    with pytest.raises(Invalid):
        portal.save_review_answers(HR, vid, {**answers, "covers_service": "maybe"}, submit=False)
    portal.save_review_answers(HR, vid, answers, submit=True)
    assert portal.vendor(ADMIN, vid)["health"] == ("info", "Waiting for sign-off")
    with pytest.raises(Invalid, match="waiting"):
        portal.add_vendor_file(HR, vid, "late.pdf", PDF, "report", "")
    with pytest.raises(Invalid, match="what is missing"):
        portal.decide_review(ADMIN, vid, "return", "")
    portal.decide_review(ADMIN, vid, "return", "Please attach our questionnaire too")
    assert portal.open_review(vid)["status"] == "returned"
    portal.add_vendor_file(HR, vid, "questionnaire.xlsx", portal.send_questionnaire(HR, vid)[1], "questionnaire", "")
    portal.save_review_answers(HR, vid, answers, submit=True)
    portal.add_review_exception(ADMIN, vid, "CC6.2: one late access removal", "None", "Accepted")
    gaps = portal.review_gaps(portal._vendor_row(vid), portal.open_review(vid))
    assert gaps == ["No CUECs recorded from the SOC 2 report"]
    portal.save_cuec(ADMIN, vid, "new", {"text": "Customers review payroll change reports", "controls": ["HR-01"],
                                         "how": "Payroll lead reviews each run", "status": "met"})
    assert portal.review_gaps(portal._vendor_row(vid), portal.open_review(vid)) == []
    portal.decide_review(ADMIN, vid, "approve", "")  # HR submitted, so ADMIN may sign off
    r = portal.vendor_reviews(vid)[0]
    assert r["kind"] == "annual" and r["status"] == "approved" and r["questionnaire_version"] == 1
    assert r["snapshot"]["cuecs"][0]["controls"] == ["HR-01"] and r["exceptions"][0]["response"] == "Accepted"
    assert portal.vendor(ADMIN, vid)["next_review"] == "2027-10-12"
    assert HR.email in [m.to for m in portal.mailer.outbox]


def test_stale_report_is_an_open_item(portal):
    v = vendor(portal, period_start="2024-01-01", period_end="2024-12-31")
    onboard(portal, v["RowKey"])
    portal.start_annual_review(HR, v["RowKey"])
    gaps = portal.review_gaps(portal._vendor_row(v["RowKey"]), portal.open_review(v["RowKey"]))
    assert any("more than 12 months ago" in g for g in gaps)


def test_cuec_rules(portal):
    v = vendor(portal)
    with pytest.raises(Invalid, match="pick our control"):
        portal.save_cuec(ADMIN, v["RowKey"], "new", {"text": "x", "status": "met", "controls": []})
    with pytest.raises(Invalid, match="Unknown control"):
        portal.save_cuec(ADMIN, v["RowKey"], "new", {"text": "x", "status": "not_mapped", "controls": ["NOPE-1"]})
    with pytest.raises(Forbidden):
        portal.save_cuec(HR, v["RowKey"], "new", {"text": "x", "status": "not_mapped"})
    c = portal.save_cuec(ADMIN, v["RowKey"], "new", {"text": "Restrict deletes", "status": "not_mapped"})
    assert portal.vendor(ADMIN, v["RowKey"])["cuecs"][0]["id"] == c["id"]
    portal.remove_cuec(ADMIN, v["RowKey"], c["id"])
    assert portal.vendor(ADMIN, v["RowKey"])["cuecs"] == []


# ---------------------------------------------------------------- offboarding
def test_offboarding_needs_evidence_for_every_item(portal):
    v = vendor(portal)
    vid = v["RowKey"]
    onboard(portal, vid)
    with pytest.raises(Invalid, match="why"):
        portal.start_offboarding(ADMIN, vid, "")
    with pytest.raises(Forbidden):
        portal.start_offboarding(HR, vid, "done")
    portal.start_offboarding(ADMIN, vid, "Moved in-house")
    r = portal.open_review(vid)
    assert r["kind"] == "offboarding" and portal.vendor(ADMIN, vid)["status"] == "offboarding"
    for key in ("access", "keys", "data", "contract"):
        portal.update_checklist(HR, vid, key, True, f"{key} done")
    gaps = portal.review_gaps(portal._vendor_row(vid), portal.open_review(vid))
    assert gaps == ["No offboarding evidence uploaded"]
    portal.add_vendor_file(HR, vid, "deletion-letter.pdf", PDF, "offboarding", "Certificate of deletion")
    portal.decide_review(ADMIN2, vid, "approve", "")
    row = portal.vendor(ADMIN, vid)
    assert row["status"] == "offboarded" and row["end_date"] == "2026-10-12" and row["next_review"] == ""
    closed = [r for r in portal.log.records() if r["action"] == "vendor.review.approve"][-1]
    assert closed["detail"]["controls"] == ["VEN-05"] and closed["detail"]["kind"] == "offboarding"


# ---------------------------------------------------------------- questionnaire
def test_starter_questionnaire_and_versions(portal):
    q = portal.questionnaire_version()
    ids = [x["id"] for s in q["sections"] for x in s["questions"]]
    assert q["version"] == 1 and len(ids) == 47 and len(set(ids)) == 47 and len(q["sections"]) == 10
    assert all(c in portal.catalog.criteria for s in q["sections"] for x in s["questions"] for c in x["criteria"])
    with pytest.raises(Forbidden):
        portal.edit_questionnaire(HR, "add_section", {"title": "x"})
    with pytest.raises(Invalid, match="Nothing has changed"):
        portal.publish_questionnaire(ADMIN, "no-op")


def test_questions_move_between_sections_and_keep_their_ids(portal):
    d = portal.questionnaire_draft(ADMIN)
    first, second = d["sections"][0], d["sections"][1]
    top = second["questions"][0]["id"]
    d = portal.edit_questionnaire(ADMIN, "move_question", {"question": top, "direction": "up"})
    assert d["sections"][0]["questions"][-1]["id"] == top  # top of a section moves to the end of the one above
    d = portal.edit_questionnaire(ADMIN, "move_to_section", {"question": top, "target": second["id"]})
    assert d["sections"][1]["questions"][-1]["id"] == top
    d = portal.edit_questionnaire(ADMIN, "move_section", {"section": second["id"], "direction": "up"})
    assert d["sections"][0]["id"] == second["id"] and d["sections"][1]["id"] == first["id"]
    with pytest.raises(Invalid, match="Move or remove"):
        portal.edit_questionnaire(ADMIN, "delete_section", {"section": first["id"]})
    d = portal.edit_questionnaire(ADMIN, "add_question", {"section": first["id"], "text": "Do you use AI on our data?",
                                                          "type": "yesno", "criteria": ["CC9.2"]})
    new_id = d["sections"][1]["questions"][-1]["id"]
    assert new_id == "Q-048"
    with pytest.raises(Invalid, match="Unknown criterion"):
        portal.edit_questionnaire(ADMIN, "edit_question", {"question": new_id, "text": "x", "type": "text", "criteria": ["ZZ9"]})
    assert portal.questionnaire_version()["version"] == 1  # nobody else sees the draft
    with pytest.raises(Invalid, match="what changed"):
        portal.publish_questionnaire(ADMIN, "")
    v2 = portal.publish_questionnaire(ADMIN, "Reordered sections, added AI question")
    assert v2["version"] == 2 and portal.questionnaire_version(1)["sections"][0]["id"] == first["id"]  # v1 unchanged
    portal.edit_questionnaire(ADMIN, "delete_question", {"question": new_id})
    portal.publish_questionnaire(ADMIN, "Removed AI question")
    d = portal.edit_questionnaire(ADMIN, "add_question", {"section": first["id"], "text": "Again?", "type": "text"})
    assert d["sections"][1]["questions"][-1]["id"] == "Q-049"  # a published id is never reused
    assert len([r for r in portal.log.records() if r["action"] == "questionnaire.publish"]) == 2


def test_questionnaire_excel_is_valid_has_dropdowns_and_no_formulas(portal):
    v = vendor(portal, name="=HYPERLINK(\"https://evil.example\",\"x\")")
    name, data = portal.send_questionnaire(ADMIN, v["RowKey"])
    assert name.endswith("-v1.xlsx")
    z = zipfile.ZipFile(io.BytesIO(data))
    assert z.testzip() is None and "xl/worksheets/sheet2.xml" in z.namelist()
    info, questions = z.read("xl/worksheets/sheet1.xml").decode(), z.read("xl/worksheets/sheet2.xml").decode()
    assert "<f>" not in info + questions and 'type="list"' in questions and "Yes,No,N/A" in questions
    assert "=HYPERLINK(&quot;" in info or "=HYPERLINK(\"https" in info  # stored as plain text, never as a formula
    assert "sheetProtection" in questions and "Q-001" in questions and questions.count("<row ") == 48
    assert portal.open_review(v["RowKey"])["questionnaire_version"] == 1


def test_xlsx_writer_strips_bad_characters():
    data = xlsx.workbook([{"name": "A/B:C?", "rows": [["ok\x00\x07text", ("<b>", xlsx.HEADER)]]}])
    z = zipfile.ZipFile(io.BytesIO(data))
    sheet = z.read("xl/worksheets/sheet1.xml").decode()
    assert "oktext" in sheet and "&lt;b&gt;" in sheet and "\x00" not in sheet
    assert 'name="A B C"' in z.read("xl/workbook.xml").decode()
    assert xlsx.col_letter(1) == "A" and xlsx.col_letter(27) == "AA"


# ---------------------------------------------------------------- reminders and calendar
def test_reminders_once_before_due_then_while_overdue(portal):
    v = vendor(portal)
    onboard(portal, v["RowKey"])
    portal.store.update("vendors", "v", v["RowKey"], {"last_review": add_months("2026-10-12", -12)[:8] + "30"})
    portal.mailer.outbox.clear()
    sent = portal.remind_vendor_reviews(ADMIN)
    assert sent and not sent[0]["overdue"] and HR.email in sent[0]["sent"]
    assert portal.remind_vendor_reviews(ADMIN) == []  # once per due date
    portal.store.update("vendors", "v", v["RowKey"], {"last_review": "2025-09-01"})
    assert portal.remind_vendor_reviews(ADMIN)[0]["overdue"] is True
    assert portal.remind_vendor_reviews(ADMIN) == []  # 12-hour cooldown
    assert portal.log.records()[-1]["action"] == "vendor.remind"
    months = portal.vendor_calendar(2026)
    assert months[8] and months[8][0]["name"] == "Northwind Payroll"


# ---------------------------------------------------------------- auditor export
def test_export_has_vendor_population_reviews_and_files_but_no_contacts(portal):
    v = vendor(portal, notes="-2+3 formula?")
    onboard(portal, v["RowKey"])
    portal.save_cuec(ADMIN, v["RowKey"], "new", {"text": "=cmd|' /C calc'!A0", "status": "not_mapped"})
    blob = portal.export_cycle(AUDITOR, portal.active_cycle()["RowKey"])
    z = zipfile.ZipFile(io.BytesIO(blob))
    names = set(z.namelist())
    for t in ("vendors", "vendor_reviews", "vendor_cuecs", "vendor_files", "vendor_exceptions",
              "vendor_register_history", "subservice_organizations", "questionnaire_versions"):
        assert f"{t}.csv" in names, t
    assert any(n.startswith("vendor_files/northwind-payroll/") for n in names)
    everything = "".join(z.read(n).decode("utf-8", "ignore") for n in names if n.startswith(("vendor", "subservice")))
    for bit in [b for b in SECRET_BITS if b != HR.email]:  # HR is also a portal user (uploads, users.csv)
        assert bit not in everything, bit
    rows = list(csv.DictReader(io.StringIO(z.read("vendor_cuecs.csv").decode())))
    assert rows[0]["text"].startswith("'=")  # formula neutralized
    vend = list(csv.DictReader(io.StringIO(z.read("vendors.csv").decode())))[0]
    assert vend["owner_title"] == "HR lead" and vend["has_internal_owner"] == "True" and vend["notes"].startswith("'-")
    files = list(csv.DictReader(io.StringIO(z.read("vendor_files.csv").decode())))
    manifest = {r["file"]: r["sha256"] for r in csv.DictReader(io.StringIO(z.read("MANIFEST.csv").decode()))}
    assert manifest[files[0]["file"]] == files[0]["sha256"]


# ---------------------------------------------------------------- pages
@pytest.mark.parametrize("who", [ADMIN, HR, AUDITOR, CONTRIB])
def test_pages_render_for_every_role_with_strict_csp(portal, client, who):
    portal.import_vendors(ADMIN)
    v = vendor(portal)
    portal.add_vendor_file(HR, v["RowKey"], "soc2.pdf", PDF, "report", "")
    portal.save_cuec(ADMIN, v["RowKey"], "new", {"text": "x", "status": "not_mapped"})
    as_(client, who)
    paths = ["/vendors", "/vendors?show=overdue&tier=high&q=north", "/vendors?show=closed", "/vendors/questionnaire",
             "/vendors/questionnaire?version=1", "/calendar" if who is ADMIN else "/vendors"]
    paths += [f"/vendors/{v['RowKey']}?tab={t}" for t in ("overview", "contacts", "review", "cuecs", "history")]
    if who.can_write:
        paths.append("/vendors/new")
    if who is ADMIN:
        paths.append(f"/vendors/{v['RowKey']}/edit")
    for path in paths:
        r = client.get(path)
        expect = 404 if who is CONTRIB and "/vendors/northwind" in path else 200
        assert r.status_code == expect, (who.email, path, r.status_code, r.text[:300])
        assert 'style="' not in r.text and "<script>" not in r.text and "onclick" not in r.text
    assert client.get("/vendors/questionnaire.xlsx").status_code == 200
    if who is not ADMIN:
        assert client.get(f"/vendors/{v['RowKey']}/edit").status_code == 403


def test_forms_need_csrf_and_respect_roles(portal, client):
    v = vendor(portal)
    as_(client, HR)
    token = csrf(client)
    r = client.post(f"/vendors/{v['RowKey']}/contacts", data={"ext_name": "No token"}, follow_redirects=False)
    assert r.status_code == 403
    r = client.post(f"/vendors/{v['RowKey']}/contacts", data={"csrf": token, "ext_name": "With token"}, follow_redirects=False)
    assert r.status_code == 303 and portal.vendor(ADMIN, v["RowKey"])["ext_name"] == "With token"
    r = client.post(f"/vendors/{v['RowKey']}/files", data={"csrf": token, "kind": "report"},
                    files={"file": ("soc2.pdf", PDF, "application/pdf")}, follow_redirects=False)
    assert r.status_code == 303 and "msg=" in r.headers["location"]
    r = client.post(f"/vendors/{v['RowKey']}/questionnaire", data={"csrf": token})
    assert r.status_code == 200 and r.content[:2] == b"PK"
    for path, data in ((f"/vendors/{v['RowKey']}/review/decide", {"decision": "approve"}),
                       (f"/vendors/{v['RowKey']}/offboard", {"reason": "x"}),
                       ("/vendors/questionnaire/edit", {"op": "add_section", "title": "x"}),
                       ("/vendors/import", {})):
        assert client.post(path, data={"csrf": token, **data}, follow_redirects=False).status_code == 403, path
    as_(client, ADMIN)
    token = csrf(client)
    r = client.post("/vendors/new", data={"csrf": token, "name": "Woodgrove", "tier": "low", "data_access": "No company data"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/vendors/woodgrove")
    r = client.post("/vendors/woodgrove/edit", data={"csrf": token, "name": "Woodgrove", "tier": "moderate", "reason": ""})
    assert r.status_code == 200 and "Say why" in r.text
    r = client.post("/vendors/questionnaire/edit", data={"csrf": token, "op": "add_section", "title": "AI use"},
                    follow_redirects=False)
    assert r.status_code == 303 and "AI use" in client.get("/vendors/questionnaire").text
    assert re.search(r"Save as version 2", client.get("/vendors/questionnaire").text)


def test_audit_log_never_holds_vendor_contact_emails(portal):
    v = vendor(portal, owner_email="finance.owner@example.com", backup_email="")
    onboard(portal, v["RowKey"], by=ADMIN2)
    portal.store.update("vendors", "v", v["RowKey"], {"last_review": "2025-09-01"})
    assert portal.remind_vendor_reviews(ADMIN)[0]["sent"]
    log = str([r["detail"] for r in portal.log.records()])
    assert "finance.owner@example.com" not in log and "val@vendor.example.com" not in log
    queued = [r for r in portal.log.records() if r["action"] == "mail.queued" and r["target"] == "vendor"]
    assert queued and all("to" not in r["detail"] and r["detail"]["recipients"] >= 1 for r in queued)
    history = portal.vendor_history(AUDITOR, v["RowKey"])
    assert {"vendor.create", "vendor.review.approve", "vendor.remind"} <= {r["action"] for r in history}


def test_long_cuec_and_exception_lists_are_refused(portal):
    v = vendor(portal)
    with pytest.raises(Invalid, match="too long"):
        for _ in range(40):
            portal.save_cuec(ADMIN, v["RowKey"], "new", {"text": "x" * 600, "status": "not_mapped"})
    assert 15 <= len(portal.vendor(ADMIN, v["RowKey"])["cuecs"]) < 40

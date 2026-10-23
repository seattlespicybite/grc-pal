"""Control matrix: data file export, import (preview, apply, discard), report (HTML and Word).

The import is a privileged bulk change to the control set, so most tests are about what it must refuse:
other organizations' files, stale or conflicting rows, unknown requirements, unsafe files, the wrong role."""
from __future__ import annotations

import io
import re
import zipfile
import xml.etree.ElementTree as ET

import pytest
from fastapi.testclient import TestClient

from grcpal import xlsx
from grcpal.portal import matrix
from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from test_portal import ADMIN, ADMIN2, AUDITOR, CONTRIB, HR, as_, csrf, make_portal


@pytest.fixture()
def portal(tmp_path):
    return make_portal(tmp_path)


def rewrite(data: bytes, edit=None, keep_about=True, about_edit=None) -> bytes:
    """What a person does in Excel: open the data file, change cells, save. `edit(rows)` changes the Controls
    sheet in place (row 0 is the header)."""
    sheets = xlsx.read_values(data)
    rows, about = sheets[matrix.DATA_SHEET], sheets[matrix.META_SHEET]
    if edit:
        edit(rows)
    if about_edit:
        about_edit(about)
    out = [{"name": matrix.DATA_SHEET, "rows": rows}, {"name": matrix.HELP_SHEET, "rows": sheets[matrix.HELP_SHEET]}]
    if keep_about:
        out.append({"name": matrix.META_SHEET, "rows": about, "hidden": True})
    return xlsx.workbook(out)


def col(rows, header_start: str) -> int:
    return next(i for i, h in enumerate(rows[0]) if h.startswith(header_start))


def row_of(rows, cid: str) -> list:
    r = next(r for r in rows[1:] if r and r[0] == cid)
    r += [""] * (len(rows[0]) - len(r))
    return r


def set_cell(cid: str, header: str, value: str):
    def edit(rows):
        row_of(rows, cid)[col(rows, header)] = value
    return edit


# ================================================================ export
def test_export_has_every_control_enabled_frameworks_only_and_is_audited(portal):
    data = portal.matrix_xlsx(ADMIN)
    sheets = xlsx.read_values(data)
    header = sheets["Controls"][0]
    assert header[:8] == [label for _, label in matrix.EDIT_COLS]
    assert "SOC 2 criteria [soc2]" in header and not any("[iso27001]" in h for h in header)  # ISO is off
    assert len(sheets["Controls"]) - 1 == len(portal.catalog.controls)
    about = {r[0]: r[1] for r in sheets["About"][1:] if r and r[0] != "stamp"}
    assert about["tenant"] == "acme" and about["format"] == matrix.FORMAT
    assert '<sheet name="About" sheetId="3" state="hidden"' in zipfile.ZipFile(io.BytesIO(data)).read("xl/workbook.xml").decode()
    assert [e for e in portal.log.records() if e["action"] == "control.matrix.export" and e["actor"] == ADMIN.email]

    portal.set_framework_in_use(ADMIN, "iso27001", True)
    header = xlsx.read_values(portal.matrix_xlsx(ADMIN))["Controls"][0]
    assert any(h.endswith("[iso27001]") for h in header)


def test_export_roles(portal):
    assert portal.matrix_xlsx(AUDITOR)[:2] == b"PK"            # auditors download (read only)
    for who in (CONTRIB, HR):                                  # control owners see only their own controls
        with pytest.raises(Forbidden):
            portal.matrix_xlsx(who)
        with pytest.raises(Forbidden):
            portal.matrix_report(who)


# ================================================================ import: the happy paths
def test_unchanged_file_has_nothing_to_import(portal):
    r = portal.matrix_preview(ADMIN, "m.xlsx", portal.matrix_xlsx(ADMIN))
    assert r["errors"] == [] and r["changes"] == [] and r["import_id"] == ""
    assert r["unchanged"] == len(portal.catalog.controls)
    assert portal.store.list("matriximports", "i") == []


def test_update_builtin_control_preview_then_apply(portal):
    before = portal.control_definition("GOV-02")
    data = rewrite(portal.matrix_xlsx(ADMIN), lambda rows: (
        set_cell("GOV-02", "Title", "Roles and org chart kept current")(rows),
        set_cell("GOV-02", "SOC 2", "CC1.3; CC1.5; CC2.2; CC5.3; CC1.4")(rows)))
    r = portal.matrix_preview(ADMIN, "m.xlsx", data)
    assert r["errors"] == [] and [c["id"] for c in r["changes"]] == ["GOV-02"]
    fields = {f["field"]: f for f in r["changes"][0]["fields"]}
    assert fields["Title"]["old"] == before["title"] and fields["Title"]["new"] == "Roles and org chart kept current"
    assert "CC1.4" in fields["SOC 2"]["new"]
    assert portal.control_definition("GOV-02") == before         # preview changes nothing
    pending = portal.matrix_import(r["import_id"])
    assert pending["status"] == "pending" and pending["file_sha256"] == r["file_sha256"]

    with pytest.raises(Invalid, match="why"):
        portal.matrix_apply(ADMIN, r["import_id"], r["plan_hash"], "short")
    res = portal.matrix_apply(ADMIN, r["import_id"], r["plan_hash"], "Annual review of governance controls")
    assert res["status"] == "applied" and [c["id"] for c in res["applied"]] == ["GOV-02"]
    after = portal.control_definition("GOV-02")
    assert after["title"] == "Roles and org chart kept current" and "CC1.4" in after["mappings"]["soc2"]
    hist = portal.control_definition_history("GOV-02")
    assert hist and "Annual review" in hist[0]["reason"] and r["import_id"] in hist[0]["reason"]
    assert portal.matrix_import(r["import_id"])["status"] == "applied"
    actions = [e["action"] for e in portal.log.records()]
    assert "control.matrix.preview" in actions and "control.matrix.import" in actions and "control.edit" in actions
    # the uploaded file and the result are write-once evidence
    run = pending["run"]
    assert portal.evidence.read(matrix.SOURCE_IMPORT, run, f"upload-{r['import_id']}.xlsx") == data
    assert portal.evidence.list_runs(matrix.SOURCE_APPLY)
    with pytest.raises(Invalid, match="already applied"):          # one preview, one apply
        portal.matrix_apply(ADMIN, r["import_id"], r["plan_hash"], "Annual review of governance controls")


def test_missing_rows_are_left_alone_and_extra_columns_ignored(portal):
    def keep_one(rows):
        rows[0].append("My notes")
        keep = [rows[0], row_of(rows, "GOV-02") + ["anything"]]
        row_of(keep, "GOV-02")[col(keep, "Title")] = "Only this one changes"
        rows[:] = keep
    r = portal.matrix_preview(ADMIN, "m.xlsx", rewrite(portal.matrix_xlsx(ADMIN), keep_one))
    assert [c["id"] for c in r["changes"]] == ["GOV-02"] and r["errors"] == []
    portal.matrix_apply(ADMIN, r["import_id"], r["plan_hash"], "Rename one control only")
    assert len(portal.catalog.controls) == 78 and portal.catalog.control("GOV-01")  # nothing deleted


def test_new_row_creates_custom_control_and_status_retires_it(portal):
    def add(rows):
        new = [""] * len(rows[0])
        new[0], new[col(rows, "Title")], new[col(rows, "Owner role")] = "CUS-77", "Clean desk walk-through", "it-lead"
        new[col(rows, "Frequency")], new[col(rows, "SOC 2")] = "quarterly", "CC6.4"
        new[col(rows, "Owner emails")] = "Facilities@Example.com"
        rows.append(new)
    r = portal.matrix_preview(ADMIN, "m.xlsx", rewrite(portal.matrix_xlsx(ADMIN), add))
    assert r["errors"] == [] and [(c["id"], c["action"]) for c in r["changes"]] == [("CUS-77", "create")]
    portal.matrix_apply(ADMIN, r["import_id"], r["plan_hash"], "Add the clean desk control")
    c = portal.catalog.control("CUS-77")
    assert c and c["custom"] and c["frequency"] == "quarterly" and c["owner_emails"] == ["facilities@example.com"]
    assert portal.user_row("facilities@example.com")["role"] == "contributor"   # same as the form

    data = rewrite(portal.matrix_xlsx(ADMIN), set_cell("CUS-77", "Status", "retired"))
    r = portal.matrix_preview(ADMIN, "m.xlsx", data)
    assert [(c["id"], c["action"]) for c in r["changes"]] == [("CUS-77", "retire")]
    portal.matrix_apply(ADMIN, r["import_id"], r["plan_hash"], "Merged into PHY-01")
    assert portal.catalog.control("CUS-77") is None and portal.custom_control("CUS-77")["status"] == "retired"


def test_discard(portal):
    data = rewrite(portal.matrix_xlsx(ADMIN), set_cell("GOV-02", "Title", "Changed title"))
    r = portal.matrix_preview(ADMIN, "m.xlsx", data)
    portal.matrix_discard(ADMIN, r["import_id"])
    assert portal.matrix_import(r["import_id"])["status"] == "discarded"
    with pytest.raises(Invalid):
        portal.matrix_apply(ADMIN, r["import_id"], r["plan_hash"], "Should not apply this one")
    assert portal.control_definition("GOV-02")["title"] != "Changed title"


# ================================================================ import: what it must refuse
def test_only_the_library_owner_imports(portal):
    data = portal.matrix_xlsx(ADMIN)
    for who in (ADMIN2, AUDITOR, CONTRIB):     # ADMIN2 is an admin but not the library owner
        with pytest.raises(Forbidden):
            portal.matrix_preview(who, "m.xlsx", data)
    r = portal.matrix_preview(ADMIN, "m.xlsx", rewrite(data, set_cell("GOV-02", "Title", "Changed title")))
    with pytest.raises(Forbidden):
        portal.matrix_apply(ADMIN2, r["import_id"], r["plan_hash"], "Somebody else applies it")


def test_file_from_another_organization_is_refused(tmp_path):
    acme, other = make_portal(tmp_path, tenant="acme"), make_portal(tmp_path, tenant="globex")
    data = acme.matrix_xlsx(ADMIN)
    with pytest.raises(Invalid, match="different organization"):
        other.matrix_preview(ADMIN, "m.xlsx", data)
    with pytest.raises(Invalid, match="not a GRC-pal control matrix"):   # About sheet removed
        acme.matrix_preview(ADMIN, "m.xlsx", rewrite(data, keep_about=False))


def test_row_changed_in_grcpal_after_export_is_a_conflict(portal):
    data = portal.matrix_xlsx(ADMIN)
    form = {**{k: v for k, v in portal.control_definition("GOV-02").items() if k in ("title", "description", "owner")},
            "title": "Edited in the portal", "owner_emails": "", "extra_evidence": "", "map_soc2": "CC1.3, CC1.5, CC2.2, CC5.3",
            "reason": "Edited directly in the portal"}
    portal.save_control_definition(ADMIN, "GOV-02", form)
    r = portal.matrix_preview(ADMIN, "m.xlsx", rewrite(data, set_cell("GOV-02", "Description (how", "From the file")))
    assert r["changes"] == [] and any("GOV-02" in e and "after the file was exported" in e for e in r["errors"])


def test_changes_after_preview_make_the_import_stale(portal):
    data = rewrite(portal.matrix_xlsx(ADMIN), set_cell("GOV-02", "Title", "From the file"))
    r = portal.matrix_preview(ADMIN, "m.xlsx", data)
    form = {"title": "Changed meanwhile", "description": "x", "owner": "hr-lead", "owner_emails": "", "extra_evidence": "",
            "map_soc2": "CC1.3", "reason": "A parallel edit in the portal", "confirm_uncovered": "yes"}
    portal.save_control_definition(ADMIN, "GOV-02", form)
    with pytest.raises(Invalid, match="changed in GRC-pal since the preview"):
        portal.matrix_apply(ADMIN, r["import_id"], r["plan_hash"], "Apply after somebody else edited")
    assert portal.control_definition("GOV-02")["title"] == "Changed meanwhile"
    assert portal.matrix_import(r["import_id"])["status"] == "stale"


def test_bad_rows_block_the_whole_import(portal):
    def bad(rows):
        set_cell("GOV-02", "Title", "Fine change")(rows)
        set_cell("GOV-01", "SOC 2", "CC1.1; CC99.9")(rows)          # unknown requirement
        set_cell("GOV-03", "Owner role", "nobody-role")(rows)        # not in roles.yaml
        set_cell("GOV-04", "Status", "retired")(rows)                # built-in cannot be retired
        rows.append(list(row_of(rows, "GOV-02")))                    # duplicate ID
    r = portal.matrix_preview(ADMIN, "m.xlsx", rewrite(portal.matrix_xlsx(ADMIN), bad))
    text = " | ".join(r["errors"])
    assert "CC99.9" in text and "nobody-role" in text and "cannot be retired" in text and "more than once" in text
    assert r["import_id"] == "" and portal.store.list("matriximports", "i") == []    # nothing kept, nothing applied


def test_leaving_a_criterion_without_control_needs_confirmation(portal):
    cov = portal.catalog.coverage()
    crit, (only,) = next((k, v) for k, v in cov.items() if len(v) == 1 and k in portal.catalog.in_scope_criteria)
    keep = [x for x in portal.control_definition(only)["mappings"]["soc2"] if x != crit]
    if not keep:
        pytest.skip("control maps to a single criterion")
    r = portal.matrix_preview(ADMIN, "m.xlsx", rewrite(portal.matrix_xlsx(ADMIN), set_cell(only, "SOC 2", "; ".join(keep))))
    assert r["gaps"] == [crit]
    with pytest.raises(Invalid, match="no control"):
        portal.matrix_apply(ADMIN, r["import_id"], r["plan_hash"], "Remove a mapping on purpose")
    portal.matrix_apply(ADMIN, r["import_id"], r["plan_hash"], "Remove a mapping on purpose", accept_gaps=True)
    assert crit not in portal.control_definition(only)["mappings"]["soc2"]


def test_builtin_frequency_change_is_ignored_with_a_note(portal):
    r = portal.matrix_preview(ADMIN, "m.xlsx", rewrite(portal.matrix_xlsx(ADMIN), set_cell("GOV-02", "Frequency", "daily")))
    assert r["changes"] == [] and any("Frequency of built-in" in w for w in r["warnings"])


# ================================================================ reading uploaded files safely
def _raw_xlsx(sheet_xml: str, shared: str | None = None, extra: dict | None = None) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("xl/workbook.xml", '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                   '<sheets><sheet name="S" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="x" Target="worksheets/sheet1.xml"/></Relationships>')
        z.writestr("xl/worksheets/sheet1.xml", '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                   f"<sheetData>{sheet_xml}</sheetData></worksheet>")
        if shared is not None:
            z.writestr("xl/sharedStrings.xml", f'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">{shared}</sst>')
        for k, v in (extra or {}).items():
            z.writestr(k, v)
    return out.getvalue()


def test_reader_handles_excel_shared_strings_and_rich_text():
    data = _raw_xlsx('<row r="1"><c r="A1" t="s"><v>0</v></c><c r="C1" t="s"><v>1</v></c><c r="D1"><v>3.0</v></c></row>',
                     "<si><t>GOV-01</t></si><si><r><t>Rich </t></r><r><t>text</t></r></si>")
    assert xlsx.read_values(data) == {"S": [["GOV-01", "", "Rich text", "3"]]}


@pytest.mark.parametrize("data, message", [
    (b"", "empty"),
    (b"ID,Title\nGOV-01,x\n", "not an .xlsx"),
    (b"PK\x03\x04garbage", "damaged"),
    (_raw_xlsx('<row r="1"><c r="A1"><f>HYPERLINK("https://evil.example","x")</f><v>0</v></c></row>'), "formula"),
    (_raw_xlsx("", extra={"xl/sharedStrings.xml": '<!DOCTYPE x [<!ENTITY a "aaaa">]><sst>&a;</sst>'}), "DOCTYPE"),
    (b"PK" + b"\0" * (xlsx.MAX_READ_BYTES + 1), "larger than"),
])
def test_reader_refuses_unsafe_or_wrong_files(data, message):
    with pytest.raises(xlsx.ReadError, match=message):
        xlsx.read_values(data)


def test_reader_refuses_zip_bomb():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("xl/worksheets/sheet1.xml", b"\0" * (xlsx.MAX_TOTAL_BYTES + 1))
    assert len(out.getvalue()) < 1024 * 1024
    with pytest.raises(xlsx.ReadError, match="too large"):
        xlsx.read_values(out.getvalue())


def test_preview_refuses_non_xlsx_name(portal):
    with pytest.raises(Invalid, match=".xlsx"):
        portal.matrix_preview(ADMIN, "m.xls", portal.matrix_xlsx(ADMIN))


# ================================================================ report
def test_report_and_word_file(portal):
    r = portal.matrix_report(AUDITOR)
    assert len(r["controls"]) == len(portal.catalog.controls) and r["xref"][0]["id"] == "soc2"
    data = portal.matrix_docx(ADMIN)
    z = zipfile.ZipFile(io.BytesIO(data))
    assert {"[Content_Types].xml", "word/document.xml", "word/styles.xml"} <= set(z.namelist())
    body = ET.fromstring(z.read("word/document.xml"))     # well-formed XML
    text = "".join(t.text or "" for t in body.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t"))
    assert "GOV-01" in text and "Cross-reference" in text
    assert [e for e in portal.log.records() if e["action"] == "control.matrix.report"]


# ================================================================ pages
@pytest.fixture()
def client(portal, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    for var in ("GRCPAL_ENV", "GRCPAL_TENANT", "GRCPAL_BOOTSTRAP_ADMINS", "GRCPAL_PUBLIC_URL", "GRCPAL_DEV_PRINCIPAL"):
        monkeypatch.delenv(var, raising=False)
    return TestClient(create_app(portal), base_url="https://grc.example.com")


@pytest.mark.parametrize("path", ["/matrix", "/matrix/report", "/controls"])
def test_pages_render_with_strict_csp(client, path):
    for who in (ADMIN, AUDITOR):
        r = as_(client, who).get(path)
        assert r.status_code == 200, r.text[:300]
        assert 'style="' not in r.text and "<script>" not in r.text and "onclick" not in r.text
    assert "/matrix" in as_(client, ADMIN).get("/controls").text


def test_pages_refuse_control_owners(client):
    as_(client, CONTRIB)
    for path in ("/matrix", "/matrix/report", "/matrix/data.xlsx", "/matrix/report.docx"):
        assert client.get(path).status_code == 403, path


def test_upload_preview_and_apply_through_the_pages(client, portal):
    as_(client, AUDITOR)
    r = client.get("/matrix/data.xlsx")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert "Upload and preview" not in client.get("/matrix").text      # auditors cannot import

    as_(client, ADMIN)
    token = csrf(client, "/matrix")
    data = rewrite(client.get("/matrix/data.xlsx").content, set_cell("GOV-02", "Title", "Changed through the page"))
    page = client.post("/matrix/import", data={"csrf": token}, files={"file": ("matrix.xlsx", data)})
    assert page.status_code == 200 and "Changed through the page" in page.text and 'style="' not in page.text
    import_id = re.search(r'/matrix/import/([^/"]+)/apply', page.text).group(1)
    plan = re.search(r'name="plan" value="([^"]+)"', page.text).group(1)
    r = client.post(f"/matrix/import/{import_id}/apply", data={"csrf": token, "plan": plan,
                                                              "reason": "Bulk edit from the page"}, follow_redirects=False)
    assert r.status_code == 303 and "Import+applied" in r.headers["location"]
    assert portal.control_definition("GOV-02")["title"] == "Changed through the page"

    as_(client, ADMIN2)   # an admin who is not the library owner
    r = client.post("/matrix/import", data={"csrf": csrf(client, "/matrix")}, files={"file": ("m.xlsx", data)})
    assert r.status_code == 403


def test_word_file_opens_with_python_docx(portal):
    docx = pytest.importorskip("docx")
    doc = docx.Document(io.BytesIO(portal.matrix_docx(ADMIN)))
    assert doc.paragraphs[0].text.startswith("Control matrix") and len(doc.tables) > 10


def test_storage_failure_mid_import_is_recorded_honestly(portal, monkeypatch):
    def two(rows):
        set_cell("GOV-02", "Title", "First change")(rows)
        set_cell("GOV-03", "Title", "Second change")(rows)
    r = portal.matrix_preview(ADMIN, "m.xlsx", rewrite(portal.matrix_xlsx(ADMIN), two))
    real = portal.save_control_definition
    calls = []

    def flaky(actor, cid, form, dry_run=False):
        if not dry_run:
            calls.append(cid)
        if len(calls) == 2 and not dry_run:
            raise RuntimeError("storage unavailable")
        return real(actor, cid, form, dry_run)
    monkeypatch.setattr(portal, "save_control_definition", flaky)
    res = portal.matrix_apply(ADMIN, r["import_id"], r["plan_hash"], "Two edits, storage fails")
    assert res["status"] == "partial" and len(res["applied"]) == 1 and "storage unavailable" in res["failed"]["error"]
    assert portal.matrix_import(r["import_id"])["status"] == "partial"
    entry = [e for e in portal.log.records() if e["action"] == "control.matrix.import"][-1]
    assert entry["detail"]["failed"]["id"] == res["failed"]["id"]

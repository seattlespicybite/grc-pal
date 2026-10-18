"""Document library: built-in templates (no organization names, valid Word files), official versions with
major/minor numbering and variants, approval by a second admin, superseding, replaceable templates, who sees what,
write-once files, upload safety, tenant isolation and the audit log."""
import hashlib
import io
import re
import zipfile

import pytest
import yaml
from fastapi.testclient import TestClient

from grcpal.portal import doclib
from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from grcpal.portal.store import SqliteStore
from test_portal import ADMIN, ADMIN2, AUDITOR, CONTRIB, PDF, as_, csrf, make_portal

DOCX = doclib.builtin_template("p-05")[1]  # any real Word file will do as an "uploaded" document


@pytest.fixture()
def portal(tmp_path):
    return make_portal(tmp_path)


@pytest.fixture()
def client(portal, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.delenv("GRCPAL_PUBLIC_URL", raising=False)
    return TestClient(create_app(portal), base_url="https://grc.example.com")


def actions(portal):
    return [r["action"] for r in portal.log.records()]


def official(portal, did="p-05", **kw):
    args = dict(variant="", change="major", comment="")
    args.update(kw)
    return portal.upload_official(ADMIN, did, "access-control.docx", DOCX, args["variant"], args["change"], args["comment"])


# ------------------------------------------------------------------ the built-in catalog and templates
def test_catalog_is_complete_and_consistent():
    cat = doclib.builtin_catalog()
    docs, folders = cat["docs"], {f["id"] for f in cat["folders"]}
    assert len(docs) >= 50 and len({d["number"] for d in docs.values()}) == len(docs)
    for d in docs.values():
        assert d["folder"] in folders and d["title"] and doclib.builtin_template(d["id"]), d["id"]
        assert not d.get("parent") or d["parent"] in docs, d["id"]
    kinds = {d["folder"]: 0 for d in docs.values()}
    for d in docs.values():
        kinds[d["folder"]] += 1
    assert kinds["tier1"] == 1 and kinds["tier2"] == 13 and kinds["tier3"] == 13 and kinds["tier4"] == 20 and kinds["soc2"] == 6


def test_templates_are_valid_word_files_without_org_names():
    from docx import Document

    for did in doclib.builtin_catalog()["docs"]:
        name, data = doclib.builtin_template(did)
        assert name == f"{did}.docx" and data[:4] == b"PK\x03\x04"
        doc = Document(io.BytesIO(data))
        text = "\n".join(p.text for p in doc.paragraphs) + "\n".join(c.text for t in doc.tables for r in t.rows for c in r.cells)
        assert "[Company Name]" in text, did
        assert not re.search(r"\bHSP\b|Azure|Entra|Intune|SharePoint|VP of Security", text), did


def test_full_policies_have_testable_statements():
    from docx import Document

    for did in ["isp"] + [f"p-{n:02d}" for n in range(1, 14)]:
        doc = Document(io.BytesIO(doclib.builtin_template(did)[1]))
        heads = [t.rows[0].cells[2].text for t in doc.tables if len(t.columns) == 3]
        assert heads and all(h == "How it is tested" for h in heads), did
        statements = sum(len(t.rows) - 1 for t in doc.tables if len(t.columns) == 3)
        assert statements >= 6, did


def test_catalog_file_matches_the_sources():
    src = yaml.safe_load(open("tools/doctemplates/registry.yaml"))
    assert {d["id"] for d in src["docs"]} == set(doclib.builtin_catalog()["docs"])


def test_control_ids_in_catalog_exist(portal):
    known = {c["id"] for c in portal.catalog.controls}
    for d in doclib.builtin_catalog()["docs"].values():
        for part in re.findall(r"[A-Z]+-\d+", d.get("controls", "")):
            assert part in known, (d["id"], part)


# ------------------------------------------------------------------ library list and permissions
def test_admin_and_auditor_see_everything_staff_only_approved(portal):
    lib = portal.library(ADMIN)
    assert lib["total"] == len(doclib.builtin_catalog()["docs"]) and {f["id"] for f in lib["folders"]} >= {"tier1", "tier2"}
    assert portal.library(AUDITOR)["total"] == lib["total"]
    assert portal.library(CONTRIB)["total"] == 0
    with pytest.raises(Invalid):
        portal.library_doc(CONTRIB, "p-05")
    v = official(portal)
    portal.set_version_status(ADMIN2, "p-05", v["RowKey"], "approved")
    assert [d["id"] for d in portal.library(CONTRIB)["docs"]] == ["p-05"]
    assert portal.library_doc(CONTRIB, "p-05")["current"][0]["label"] == "1.0"
    only = portal.library(ADMIN, folder="tier2", q="access")
    assert [d["id"] for d in only["docs"]] == ["p-05"]


def test_only_admins_write(portal):
    for who in (CONTRIB, AUDITOR):
        with pytest.raises(Forbidden):
            portal.upload_official(who, "p-05", "a.docx", DOCX, "", "major", "")
        with pytest.raises(Forbidden):
            portal.upload_template(who, "p-05", "a.docx", DOCX, "")
        with pytest.raises(Forbidden):
            portal.edit_doc(who, "p-05", {"title": "Changed title"})
        with pytest.raises(Forbidden):
            portal.add_doc(who, "tier2", "P-99", "New document")
        with pytest.raises(Forbidden):
            portal.restore_builtin_template(who, "p-05")


# ------------------------------------------------------------------ versions
def test_version_numbers_major_minor_and_variants(portal):
    labels = [official(portal, change="major")["label"], official(portal, change="minor")["label"],
              official(portal, change="minor")["label"], official(portal, change="major")["label"],
              official(portal, variant="Product A", change="minor")["label"],
              official(portal, variant="  Product   A ", change="major")["label"]]
    assert labels == ["1.0", "1.1", "1.2", "2.0", "1.0", "2.0"]
    assert doclib.bump(["1.9", "2.0", "x"], "minor") == "2.1"
    with pytest.raises(Invalid):
        official(portal, change="huge")


def test_files_are_write_once_with_hash_and_listed_newest_first(portal):
    a = official(portal, comment="first")
    b = official(portal, change="minor")
    assert a["sha256"] == hashlib.sha256(DOCX).hexdigest() and a["size"] == len(DOCX) and a["status"] == "draft"
    assert a["evidence_run"] != b["evidence_run"]
    name, data = portal.doc_file(ADMIN, "p-05", a["RowKey"])
    assert name == "access-control.docx" and data == DOCX
    rows = portal.doc_versions(ADMIN, "p-05")["official"]
    assert [r["label"] for r in rows] == ["1.1", "1.0"]
    assert "doclib.upload" in actions(portal)


def test_file_list_includes_templates_for_admins_only(portal):
    files = portal.library_files(ADMIN, "tier2")
    assert len(files) == 13 and all(f["status"] == "template" and f["filename"].endswith(".docx") for f in files)
    assert portal.library_files(AUDITOR, "tier2")[0]["sha256"] and portal.library_files(CONTRIB) == []
    v = official(portal)
    portal.upload_template(ADMIN, "p-05", "mine.docx", DOCX, "")
    portal.set_version_status(ADMIN2, "p-05", v["RowKey"], "approved")
    files = portal.library_files(ADMIN, "tier2")
    assert files[0]["status"] == "approved" and [f["filename"] for f in files if f["PartitionKey"] == "p-05"][-1] == "mine.docx"
    assert [f["status"] for f in portal.library_files(CONTRIB)] == ["approved"]


def test_status_flow_segregation_and_superseding(portal):
    v1 = official(portal)
    with pytest.raises(Forbidden):  # ADMIN uploaded it, ADMIN2 exists
        portal.set_version_status(ADMIN, "p-05", v1["RowKey"], "approved")
    portal.set_version_status(ADMIN, "p-05", v1["RowKey"], "in_review")
    assert portal.set_version_status(ADMIN2, "p-05", v1["RowKey"], "approved")["approved_by"] == ADMIN2.email
    v2 = official(portal, change="minor")
    portal.set_version_status(ADMIN2, "p-05", v2["RowKey"], "approved")
    states = {v["label"]: v["status"] for v in portal.doc_versions(ADMIN, "p-05")["official"]}
    assert states == {"1.0": "approved", "1.1": "superseded"} or states == {"1.1": "approved", "1.0": "superseded"}
    assert states["1.1"] == "approved" and states["1.0"] == "superseded"
    # another product's approved version is not superseded
    other = official(portal, variant="Product A")
    portal.set_version_status(ADMIN2, "p-05", other["RowKey"], "approved")
    assert {c["variant"] for c in portal.library_doc(ADMIN, "p-05")["current"]} == {"", "Product A"}
    with pytest.raises(Invalid):
        portal.set_version_status(ADMIN2, "p-05", v1["RowKey"], "approved")  # superseded cannot be approved again
    with pytest.raises(Invalid):
        portal.set_version_status(ADMIN2, "p-05", v2["RowKey"], "archived")  # needs a reason
    portal.set_version_status(ADMIN2, "p-05", v2["RowKey"], "archived", "Withdrawn")
    assert "doclib.status.approved" in actions(portal)


def test_sole_admin_may_self_approve_and_it_is_marked(tmp_path):
    portal = make_portal(tmp_path, tenant="solo", people=(ADMIN, AUDITOR))
    v = portal.upload_official(ADMIN, "p-05", "a.docx", DOCX, "", "major", "")
    done = portal.set_version_status(ADMIN, "p-05", v["RowKey"], "approved")
    assert done["self_approved"] is True
    rec = [r for r in portal.log.records() if r["action"] == "doclib.status.approved"][-1]
    assert rec["detail"]["self_approved"] is True


def test_staff_download_only_approved_files(portal):
    v = official(portal)
    for who in (CONTRIB,):
        with pytest.raises(Invalid):
            portal.doc_file(who, "p-05", v["RowKey"])
    portal.set_version_status(ADMIN2, "p-05", v["RowKey"], "approved")
    assert portal.doc_file(CONTRIB, "p-05", v["RowKey"])[1] == DOCX
    assert "doclib.download" in actions(portal)  # non-admin downloads are audited
    with pytest.raises(Invalid):
        portal.doc_file(CONTRIB, "p-05", "template")  # staff never get templates
    with pytest.raises(Invalid):
        portal.doc_file(ADMIN, "p-05", "../../etc/passwd")


# ------------------------------------------------------------------ templates
def test_template_replace_history_and_restore(portal):
    name, built_in = portal.doc_file(ADMIN, "p-05", "template")
    assert name == "p-05.docx" and built_in == doclib.builtin_template("p-05")[1]
    assert portal.library_doc(ADMIN, "p-05")["template_source"] == "Built-in"
    mine = built_in + b"extra"  # still starts with the zip signature
    portal.upload_template(ADMIN, "p-05", "my-template.docx", mine, "Company version")
    assert portal.library_doc(AUDITOR, "p-05")["template_source"] == "Custom"
    assert portal.doc_file(AUDITOR, "p-05", "template") == ("my-template.docx", mine)
    portal.restore_builtin_template(ADMIN, "p-05")
    assert portal.doc_file(ADMIN, "p-05", "template")[1] == built_in
    hist = portal.doc_versions(ADMIN, "p-05")["templates"]
    assert len(hist) == 2 and hist[0]["builtin"] and hist[1]["filename"] == "my-template.docx"
    assert portal.doc_file(ADMIN, "p-05", hist[1]["RowKey"])[1] == mine  # old template still downloadable
    assert {"doclib.template.replace", "doclib.template.restore"} <= set(actions(portal))


# ------------------------------------------------------------------ details and custom documents
def test_edit_title_keeps_number_and_is_audited(portal):
    d = portal.edit_doc(ADMIN, "p-05", {"title": "  Access   Control and Identity Policy ", "owner": "IT lead",
                                        "classification": "Internal", "next_review": "2027-10-01"})
    assert d["title"] == "Access Control and Identity Policy" and d["number"] == "P-05"
    assert d["owner_name"] == "IT lead" and d["builtin_title"] == "Access Control Policy"
    rec = [r for r in portal.log.records() if r["action"] == "doclib.edit"][-1]
    assert rec["detail"]["before"]["title"] == "Access Control Policy" and rec["detail"]["after"]["next_review"] == "2027-10-01"
    n = len(portal.log.records())
    portal.edit_doc(ADMIN, "p-05", {"title": "Access Control and Identity Policy"})
    assert len(portal.log.records()) == n  # no change, no entry
    for bad in ({"title": "x"}, {"classification": "Secret"}, {"next_review": "01/02/2027"}):
        with pytest.raises(Invalid):
            portal.edit_doc(ADMIN, "p-05", bad)


def test_add_custom_document_and_review_dates(portal):
    d = portal.add_doc(ADMIN, "tier2", "P-14", "Privacy Policy", "policy")
    assert d["custom"] and d["id"].startswith("x-p-14-") and portal.library(ADMIN, folder="tier2")["docs"][-1]["id"] == d["id"]
    with pytest.raises(Invalid):
        portal.add_doc(ADMIN, "nope", "", "Some title")
    v = portal.upload_official(ADMIN, d["id"], "privacy.docx", DOCX, "", "major", "")
    portal.set_version_status(ADMIN2, d["id"], v["RowKey"], "approved")
    portal.edit_doc(ADMIN, d["id"], {"next_review": "2026-01-01"})
    assert portal.library_doc(ADMIN, d["id"])["review_state"] == "overdue"
    portal.edit_doc(ADMIN, d["id"], {"next_review": "2026-11-01"})
    assert portal.library_doc(ADMIN, d["id"])["review_state"] == "soon"
    with pytest.raises(Invalid):
        portal.doc_file(ADMIN, d["id"], "template")  # a custom document has no built-in template


# ------------------------------------------------------------------ upload safety and tenants
def test_upload_validation(portal):
    for name, data in (("run.exe", b"MZ\x90"), ("a.docm", DOCX), ("a.docx", b"not a zip"), ("a.docx", b""),
                       ("a.pdf", b"PK\x03\x04")):
        with pytest.raises(Invalid):
            portal.upload_official(ADMIN, "p-05", name, data, "", "major", "")
    with pytest.raises(Invalid):
        portal.upload_official(ADMIN, "no-such-doc", "a.docx", DOCX, "", "major", "")
    portal.upload_official(ADMIN, "p-05", "../../evil name.PDF", PDF, "", "major", "")
    assert portal.doc_versions(ADMIN, "p-05")["official"][0]["filename"] == "evil_name.PDF"


def test_other_tenant_sees_nothing(tmp_path):
    base = SqliteStore()
    one = make_portal(tmp_path, tenant="one", base_store=base)
    two = make_portal(tmp_path, tenant="two", base_store=base)
    v = one.upload_official(ADMIN, "p-05", "a.docx", DOCX, "", "major", "")
    one.edit_doc(ADMIN, "p-05", {"title": "Tenant one title"})
    assert two.doc_versions(ADMIN, "p-05")["official"] == [] and two.library_doc(ADMIN, "p-05")["title"] == "Access Control Policy"
    with pytest.raises(Invalid):
        two.doc_file(ADMIN, "p-05", v["RowKey"])
    with pytest.raises(Invalid):
        two.set_version_status(ADMIN2, "p-05", v["RowKey"], "approved")


# ------------------------------------------------------------------ web pages
def test_pages_render_under_strict_csp(portal, client):
    v = official(portal, variant="Product A")
    portal.set_version_status(ADMIN2, "p-05", v["RowKey"], "approved")
    portal.upload_template(ADMIN, "p-05", "t.docx", DOCX, "")
    paths = ["/library", "/library?f=tier2", "/library?view=files", "/library?q=access&view=files", "/library/p-05", "/library/isp",
             "/library/p-05-s1", "/library/soc2-03", "/library?f=other"]
    for who in (ADMIN, AUDITOR):
        as_(client, who)
        for path in paths:
            r = client.get(path)
            assert r.status_code == 200, (who.role, path, r.text[:300])
            assert 'style="' not in r.text and "<script>" not in r.text and "onclick" not in r.text
    as_(client, ADMIN)
    assert 'class="on">All files' in client.get("/library?view=files").text  # not the program-wide "view" variable
    assert 'class="on">Documents' in client.get("/library").text
    page = client.get("/library/p-05").text
    assert "Upload an official version" in page and "Replace the template" in page and "Product A" in page
    as_(client, AUDITOR)
    page = client.get("/library/p-05").text
    assert "Upload an official version" not in page and "Replace the template" not in page and "Download template" in page


def test_staff_pages_show_only_published(portal, client):
    as_(client, CONTRIB)
    assert "No approved documents" in client.get("/library").text
    assert client.get("/library/p-05").status_code == 404
    v = official(portal)
    portal.set_version_status(ADMIN2, "p-05", v["RowKey"], "approved")
    page = client.get("/library/p-05").text
    assert client.get("/library/p-05").status_code == 200 and "Download template" not in page and "Replace the template" not in page
    assert client.get(f"/library/p-05/files/{v['RowKey']}").status_code == 200
    assert client.get("/library/p-05/files/template").status_code == 404


def test_forms_need_csrf_and_role_and_download_is_attachment(portal, client):
    as_(client, ADMIN)
    token = csrf(client, "/library")
    files = {"file": ("ac.docx", DOCX, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}
    assert client.post("/library/p-05/official", data={"change": "major"}, files=files, follow_redirects=False).status_code == 403
    r = client.post("/library/p-05/official", data={"csrf": token, "change": "major", "variant": "Product A"}, files=files,
                    follow_redirects=False)
    assert r.status_code == 303 and "msg=" in r.headers["location"]
    vid = portal.doc_versions(ADMIN, "p-05")["official"][0]["RowKey"]
    r = client.get(f"/library/p-05/files/{vid}")
    assert r.headers["content-disposition"].startswith("attachment") and "sandbox" in r.headers["content-security-policy"]
    r = client.post(f"/library/p-05/versions/{vid}/status", data={"csrf": token, "status": "approved"}, follow_redirects=False)
    assert r.status_code == 403  # the uploader cannot approve while another admin exists
    assert portal.doc_versions(ADMIN, "p-05")["official"][0]["status"] == "draft"
    r = client.post("/library/p-05/edit", data={"csrf": token, "title": "Renamed Access Policy"}, follow_redirects=False)
    assert r.status_code == 303 and portal.library_doc(ADMIN, "p-05")["title"] == "Renamed Access Policy"
    r = client.post("/library/p-05/official", data={"csrf": token, "change": "major"}, follow_redirects=False)
    assert "err=" in r.headers["location"]  # no file chosen
    for who in (CONTRIB, AUDITOR):
        as_(client, who)
        tok = csrf(client, "/policies")
        assert client.post("/library/p-05/edit", data={"csrf": tok, "title": "Hacked title"}, follow_redirects=False).status_code == 403
        assert client.post("/library/add", data={"csrf": tok, "folder": "tier2", "title": "Hacked"}, follow_redirects=False).status_code == 403


def test_tables_are_in_backups(portal):
    from grcpal.portal import store

    assert {"docs", "docversions"} <= set(store.TABLES) and not {"docs", "docversions"} & set(store.NOT_BACKED_UP)
    assert zipfile.is_zipfile(io.BytesIO(DOCX))

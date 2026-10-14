"""Knowledge base: article format, validation against the catalog, and the portal pages."""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from grcpal import kb
from grcpal.catalog import Catalog
from grcpal.portal.app import create_app
from test_portal import ADMIN, AUDITOR, CONTRIB, HR, make_portal

ROOT = Path(__file__).resolve().parents[1] / "grcpal" / "starter"


@pytest.fixture
def catalog():
    return Catalog.load(ROOT)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    for var in ("GRCPAL_ENV", "GRCPAL_TENANT", "GRCPAL_BOOTSTRAP_ADMINS", "GRCPAL_PUBLIC_URL", "GRCPAL_DEV_PRINCIPAL"):
        monkeypatch.delenv(var, raising=False)
    portal = make_portal(tmp_path)
    return portal, TestClient(create_app(portal))


def login(client, who):
    import json
    client.cookies.clear()
    client.headers["X-Dev-Principal"] = json.dumps({"email": who.email, "name": who.name})


def test_starter_articles_are_valid(catalog):
    articles = kb.load()
    assert {"CC6.1", "A1.3", "C1.2"} <= set(articles)
    assert kb.validate(catalog, articles) == []
    for a in articles.values():
        assert a.status in kb.STATUSES and a.criterion in catalog.criteria


def test_validation_catches_unknown_ids_and_unsupported_review(catalog):
    bad = {"CC6.1": kb.Article("CC6.1", "Title", "reviewed", summary="s",
                               points=[{"id": "CC6.1-PF99", "what_auditor_tests": "x", "frequency": "",
                                        "evidence_standard": ["y"], "good_examples": ["z"], "common_mistakes": []}]),
           "ZZ9.9": kb.Article("ZZ9.9", "T", summary="s")}
    problems = kb.validate(catalog, bad)
    assert any("ZZ9.9: not a criterion" in p for p in problems)
    assert any("CC6.1-PF99 is not a point of focus" in p for p in problems)
    assert any("reviewed article needs reviewed_by" in p for p in problems)


def test_program_repository_article_replaces_starter(tmp_path):
    (tmp_path / "kb").mkdir()
    (tmp_path / "kb" / "CC6.1.yaml").write_text("criterion: CC6.1\ntitle: Our own access guide\nsummary: ours\n")
    (tmp_path / "kb" / "evil.yaml").write_text("criterion: CC6.2\ntitle: wrong file name\nsummary: x\n")
    articles = kb.load(tmp_path)
    assert articles["CC6.1"].title == "Our own access guide" and articles["CC6.1"].source == "program"
    assert articles.get("CC6.2") is None or articles["CC6.2"].source == "starter"


def test_kb_pages_for_every_role_and_links(env):
    portal, client = env
    for who in (ADMIN, AUDITOR, HR, CONTRIB):
        login(client, who)
        index = client.get("/kb")
        assert index.status_code == 200 and "Knowledge base" in index.text and 'href="/kb/CC6.1"' in index.text
        page = client.get("/kb/CC6.1")
        assert page.status_code == 200 and 'id="CC6.1-PF01"' in page.text and "Evidence standard" in page.text
    login(client, ADMIN)
    # unknown or malformed ids are a plain 404, never a file path
    for bad in ("ZZ9.9", "..%2F..%2Fsecrets", "CC6.1.yaml"):
        assert client.get(f"/kb/{bad}").status_code == 404
    # a criterion without an article yet still has a page that says so
    missing = client.get("/kb/CC1.2")
    assert missing.status_code == 200 and "not written yet" in missing.text
    # control pages link each point of focus to its guidance section
    ctl = client.get("/controls/IAM-02").text
    assert re.search(r'href="/kb/CC6\.1#CC6\.1-PF\d\d"', ctl)
    # criterion page links to its article
    assert 'href="/kb/CC6.1"' in client.get("/criteria/CC6.1").text
    # nav shows the knowledge base
    assert '<a href="/kb"' in client.get("/").text


def test_kb_article_text_is_escaped(env, tmp_path):
    portal, client = env
    kbdir = Path(portal.base_catalog.base) / "kb"
    kbdir.mkdir(exist_ok=True)
    (kbdir / "CC6.2.yaml").write_text("criterion: CC6.2\ntitle: \"<script>alert(1)</script>\"\nsummary: \"<b>x</b>\"\n")
    portal.reload_kb()
    login(client, ADMIN)
    page = client.get("/kb/CC6.2").text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page and "<script>alert(1)" not in page


def test_evidence_request_links_to_guidance(env):
    portal, client = env
    from test_portal import assign
    a = assign(portal, "IAM-02", CONTRIB)
    login(client, CONTRIB)
    page = client.get(f"/assignments/{a['RowKey']}").text
    assert 'href="/kb/CC6.1"' in page and "What good evidence looks like" in page

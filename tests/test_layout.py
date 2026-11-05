"""Layout: slim menu, framework view in two panes (criteria tree + criterion), and the control side panel
(/controls/<id>/panel). The panel must follow exactly the same visibility rules as the full control page."""
import re

import pytest
from fastapi.testclient import TestClient

from grcpal.portal.app import create_app
from test_portal import ADMIN, AUDITOR, CONTRIB, HR, as_, make_portal


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    for var in ("GRCPAL_TENANT", "GRCPAL_BOOTSTRAP_ADMINS", "GRCPAL_PUBLIC_URL", "GRCPAL_DEV_PRINCIPAL"):
        monkeypatch.delenv(var, raising=False)
    portal = make_portal(tmp_path)
    return portal, TestClient(create_app(portal), base_url="https://grc.example.com")


def panel(client, who, cid):
    return as_(client, who).get(f"/controls/{cid}/panel")


def test_panel_is_a_fragment_with_tabs(env):
    _, client = env
    r = panel(client, ADMIN, "IAM-02")
    assert r.status_code == 200 and r.headers["Cache-Control"] == "no-store"
    html = r.text
    assert "<html" not in html and "<nav class=\"nav\"" not in html, "no page layout inside the panel"
    tabs = re.findall(r'role="tab" id="(cpt-\w+)"', html)
    assert tabs == ["cpt-overview", "cpt-evidence", "cpt-tests", "cpt-docs", "cpt-history", "cpt-comments"]
    for t in tabs:  # every tab has its panel, and only the first shows before the script runs
        assert f'id="{t.replace("cpt-", "cp-")}"' in html
    assert html.count('class="tab-panel" hidden') == len(tabs) - 1
    assert 'href="/controls/IAM-02">Open full page' in html and "data-drawer-close" in html
    assert 'style="' not in html and "<script" not in html and "onclick" not in html


def test_control_owner_sees_only_their_own_controls_in_the_panel(env):
    _, client = env
    assert panel(client, CONTRIB, "IAM-02").status_code == 404, "same rule as the full page"
    r = panel(client, HR, "GOV-02")   # HR owns hr-lead controls
    assert r.status_code == 200
    assert "cpt-tests" not in r.text and "cpt-history" not in r.text, "admin and auditor tabs only"


def test_auditor_reads_but_gets_no_actions(env):
    _, client = env
    html = panel(client, AUDITOR, "IAM-02").text
    assert "cpt-tests" in html and "cpt-history" in html
    assert "Upload evidence</a>" not in html and "Add a check" not in html and 'action="/comments"' not in html


def test_unknown_control_is_404(env):
    _, client = env
    assert panel(client, ADMIN, "NOPE-99").status_code == 404


def test_documents_tab_lists_policies_and_library_documents(env):
    portal, client = env
    html = panel(client, ADMIN, "GOV-01").text
    docs = html.split('id="cp-docs"')[1].split("</section>")[0]
    assert 'href="/policies/information-security-policy"' in docs
    assert 'href="/library/isp"' in docs and "No approved version" in docs
    # staff see only library documents that have an approved version (same rule as the library)
    assert portal.control_documents(HR, "GOV-01")["docs"] == []
    assert [d["id"] for d in portal.control_documents(ADMIN, "GOV-01")["docs"]] == ["isp"]


def test_lists_open_controls_in_the_panel_and_keep_a_link_without_javascript(env):
    _, client = env
    as_(client, ADMIN)
    html = client.get("/controls").text
    assert re.search(r'<a href="/controls/IAM-02" data-panel="IAM-02"><b>IAM-02</b></a>', html)
    assert 'data-panel-row="IAM-02"' in html
    crit = client.get("/criteria/CC6.1").text
    assert 'href="/controls/IAM-02?from=CC6.1" data-panel="IAM-02"' in crit


def test_framework_view_has_the_criteria_tree(env):
    _, client = env
    as_(client, ADMIN)
    html = client.get("/criteria/CC6.1").text
    assert '<div class="fw-split">' in html and '<nav class="fw-tree" aria-label="SOC 2 criteria">' in html
    current = re.findall(r'class="fw-crit on" href="/criteria/([\w.]+)" aria-current="page"', html)
    assert current == ["CC6.1"]
    assert re.search(r'<details class="fw-fam" open>\s*<summary><span class="fw-fam-id">CC6</span>', html)
    assert 'href="/criteria/P5.1"' not in html, "only in-scope families are in the tree"
    overview = client.get("/criteria").text
    assert '<a class="fw-top on" href="/criteria" aria-current="page">Overview</a>' in overview


def test_shell_has_the_menu_toggle_and_the_panel_container(env):
    _, client = env
    html = as_(client, ADMIN).get("/controls").text
    assert re.search(r'<button type="button" class="nav-toggle" data-nav-toggle aria-controls="main-nav"[^>]* hidden>', html)
    assert 'id="main-nav"' in html
    assert re.search(r'<aside class="drawer" id="drawer" role="dialog"[^>]*data-drawer hidden>', html)


def test_control_page_has_section_links(env):
    _, client = env
    html = as_(client, ADMIN).get("/controls/GOV-01").text
    nav = html.split('<nav class="section-nav"')[1].split("</nav>")[0]
    for anchor in ("#what", "#notes", "#submissions", "#checks", "#documents", "#comments", "#ai"):
        assert f'href="{anchor}"' in nav
        assert f'id="{anchor[1:]}"' in html, f"{anchor} must exist on the page"
    assert 'id="documents"' in html and "/library/isp" in html
    contrib_nav = as_(client, HR).get("/controls/GOV-02").text.split('<nav class="section-nav"')[1].split("</nav>")[0]
    assert "#checks" not in contrib_nav and "#ai" not in contrib_nav


@pytest.mark.parametrize("path", ["/criteria", "/criteria/CC6.1", "/controls"])
def test_auditor_framework_and_list_pages(env, path):
    _, client = env
    assert as_(client, AUDITOR).get(path).status_code == 200

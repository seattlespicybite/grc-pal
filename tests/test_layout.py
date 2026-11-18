"""Layout: slim menu, framework view in two panes (criteria tree + criterion), and the control side panel
(/controls/<id>/panel). The panel must follow exactly the same visibility rules as the full control page."""
import re
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

from grcpal.portal.app import _panel_dest, create_app
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


def sections(html):
    """Section ids and form targets of a control body: what a person sees and can do."""
    body = html.split("data-unsaved-watch", 1)[1]
    return (re.findall(r'<(?:section|details|div) class="[^"]*card[^"]*" id="([\w-]+)"', body),
            sorted(set(re.findall(r'<form method="post" action="([^"]+)"', body))))


def test_panel_is_a_fragment_with_every_section(env):
    _, client = env
    r = panel(client, ADMIN, "IAM-02")
    assert r.status_code == 200 and r.headers["Cache-Control"] == "no-store"
    html = r.text
    assert "<html" not in html and "<nav class=\"nav\"" not in html, "no page layout inside the panel"
    assert 'href="/controls/IAM-02">Open full page' in html and "data-drawer-close" in html
    assert 'style="' not in html and "<script" not in html and "onclick" not in html
    ids, _ = sections(html)
    for sid in ("what", "notes", "upload", "submissions", "comments", "documents", "checks", "ai"):
        assert sid in ids, f"panel shows the {sid} section"


@pytest.mark.parametrize("who,cid", [(ADMIN, "IAM-02"), (ADMIN, "GOV-01"), (HR, "GOV-02"), (AUDITOR, "IAM-02")])
def test_panel_and_page_show_the_same_sections_per_role(env, who, cid):
    _, client = env
    page = as_(client, who).get(f"/controls/{cid}")
    side = panel(client, who, cid)
    assert page.status_code == side.status_code == 200
    assert sections(side.text) == sections(page.text), "one include, same sections and forms for this role"


def test_every_section_form_has_a_save_button(env):
    _, client = env
    for path in ("/controls/GOV-01", "/controls/GOV-01/panel"):
        body = as_(client, ADMIN).get(path).text.split("data-unsaved-watch", 1)[1]
        forms = re.findall(r'<form method="post"(.*?)</form>', body, re.S)
        assert len(forms) >= 5
        for f in forms:
            buttons = re.findall(r'<button[^>]*type="submit"[^>]*>([^<]+)</button>', f)
            assert buttons and all(b.strip() for b in buttons), f"form without a labelled Save button: {f[:200]}"
    page = as_(client, ADMIN).get("/controls/GOV-01").text
    assert re.search(r'id="notes".*?<button class="btn small mt-s" type="submit">Save notes</button>', page, re.S)


def test_control_owner_sees_only_their_own_controls_in_the_panel(env):
    _, client = env
    assert panel(client, CONTRIB, "IAM-02").status_code == 404, "same rule as the full page"
    r = panel(client, HR, "GOV-02")   # HR owns hr-lead controls
    assert r.status_code == 200
    ids, _ = sections(r.text)
    assert "checks" not in ids and "ai" not in ids and "definition-history" not in ids, "admin and auditor sections only"
    assert 'id="notes"' in r.text and 'action="/controls/GOV-02/upload"' in r.text


def test_auditor_reads_but_gets_no_actions(env):
    _, client = env
    html = panel(client, AUDITOR, "IAM-02").text
    ids, forms = sections(html)
    assert "checks" in ids and "ai" in ids
    assert forms == [], "auditors are read-only: no form in the panel"
    assert "Add a check" not in html and "Auditors have read-only access." in html


def test_unknown_control_is_404(env):
    _, client = env
    assert panel(client, ADMIN, "NOPE-99").status_code == 404


def test_documents_tab_lists_policies_and_library_documents(env):
    portal, client = env
    html = panel(client, ADMIN, "GOV-01").text
    docs = html.split('id="documents"')[1].split("</section>")[0]
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
    assert '<div class="drawer-backdrop" data-drawer-backdrop hidden></div>' in html


def test_menu_state_script_runs_before_the_page_content(env):
    """nav.js restores open groups, slim menu and menu scroll; it must load right after the menu (not at the end)
    so the menu is right on the first paint, and never inline (strict CSP)."""
    _, client = env
    html = as_(client, ADMIN).get("/controls").text
    nav_end = html.index("</nav>", html.index('id="main-nav"'))
    script = html.index('<script src="/static/nav.js?v=')
    assert nav_end < script < html.index('<main class="main"'), "runs before the page content is drawn"
    assert re.findall(r'data-nav-group="(\w+)"', html) == ["program", "docs", "config"]
    assert re.search(r'<details class="nav-group" data-nav-group="program" open>', html), "current page group open"
    js = client.get("/static/nav.js").text
    assert "localStorage" in js and "try {" in js and "grcpal-nav-groups" in js and "grcpal-nav-scroll" in js


def test_unsaved_changes_dialog_is_in_every_page(env):
    _, client = env
    for path in ("/controls", "/controls/GOV-01"):
        html = as_(client, ADMIN).get(path).text
        dialog = html.split('<dialog class="unsaved-dialog" data-unsaved-dialog')[1].split("</dialog>")[0]
        assert ">Keep editing</button>" in dialog and ">Close without saving</button>" in dialog
        assert "data-unsaved-list" in dialog
    page = as_(client, ADMIN).get("/controls/GOV-01").text
    assert '<div class="control-sections" data-unsaved-watch>' in page
    assert 'data-unsaved-watch data-unsaved-title="GOV-01"' in panel(client, ADMIN, "GOV-01").text


@pytest.mark.parametrize("path", ["/controls", "/controls/GOV-02", "/controls/GOV-02/panel"])
@pytest.mark.parametrize("who", [ADMIN, HR, AUDITOR])
def test_control_pages_render_under_strict_csp(env, who, path):
    _, client = env
    r = as_(client, who).get(path)
    assert r.status_code == 200, r.text[:300]
    assert 'style="' not in r.text and "onclick" not in r.text
    assert not re.search(r"<script(?![^>]*\bsrc=)", r.text), "no inline script"


# ---------------------------------------------------------------- saving from the panel
def note_post(client, who, cid, query=""):
    as_(client, who)
    token = re.search(r'<meta name="csrf-token" content="([^"]+)">', client.get("/controls").text).group(1)
    return client.post(f"/controls/{cid}/note{query}", data={"csrf": token, "text": "Covered by policy section 6."},
                       follow_redirects=False)


def test_saving_on_the_full_page_stays_on_the_page(env):
    _, client = env
    r = note_post(client, ADMIN, "GOV-01")
    assert r.status_code == 303 and r.headers["location"].startswith("/controls/GOV-01?msg=")


def test_saving_from_the_panel_goes_back_to_the_list_with_the_panel_open(env):
    portal, client = env
    r = note_post(client, ADMIN, "GOV-01", "?" + urlencode({"panel": "/controls?status=ok&owner=it-lead&evil=x"}))
    loc = r.headers["location"]
    assert r.status_code == 303 and loc.startswith("/controls?status=ok&owner=it-lead&msg=")
    assert loc.endswith("#control=GOV-01") and "evil" not in loc, "only known list filters are kept"
    assert portal.control_note("GOV-01")["text"] == "Covered by policy section 6."
    r = note_post(client, ADMIN, "GOV-01", "?" + urlencode({"panel": "/criteria/CC6.1"}))
    assert r.headers["location"].startswith("/criteria/CC6.1?msg=") and r.headers["location"].endswith("#control=GOV-01")


@pytest.mark.parametrize("bad", ["//evil.example.com/controls", "https://evil.example.com/controls", "/settings",
                                 "/controls/../settings", "/criteria/a/b", "/\\evil.example.com", "javascript:alert(1)"])
def test_panel_return_never_leaves_the_list_pages(env, bad):
    _, client = env
    r = note_post(client, ADMIN, "GOV-01", "?" + urlencode({"panel": bad}))
    assert r.headers["location"].startswith("/controls/GOV-01?msg="), "unknown targets keep the normal redirect"


def test_panel_return_does_not_change_who_may_save(env):
    _, client = env
    r = note_post(client, CONTRIB, "IAM-02", "?" + urlencode({"panel": "/controls"}))
    assert r.status_code == 404, "control owners still cannot touch other controls"


def test_panel_dest_rules():
    assert _panel_dest("/controls?q=a", "/controls/GOV-01?msg=Saved#notes") == "/controls?q=a&msg=Saved#control=GOV-01"
    assert _panel_dest("/controls", "/controls/GOV-01/edit") == "", "only the same control's page is rewritten"
    assert _panel_dest("/controls", "/assignments/abc?msg=x") == ""
    assert _panel_dest("/controls", "https://evil.example.com/controls/GOV-01") == ""


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

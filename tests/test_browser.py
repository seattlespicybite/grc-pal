"""Real-browser smoke test: forms must work in Chromium with the strict security headers.

Skipped when Playwright or its Chromium is not installed (pip install playwright && playwright install chromium).
This catches problems unit tests cannot, such as a Referrer-Policy that makes browsers send `Origin: null`.
"""
import socket
import threading
import time

import pytest

playwright = pytest.importorskip("playwright.sync_api")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def server(tmp_path, monkeypatch):
    import uvicorn

    from grcpal.portal import demo
    from grcpal.portal.app import create_app
    from test_portal import make_portal

    port = _free_port()
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    monkeypatch.setenv("GRCPAL_KEY_FILE", str(tmp_path / "key"))
    monkeypatch.setenv("GRCPAL_JOBS_SYNC", "1")
    monkeypatch.setenv("GRCPAL_PUBLIC_URL", f"http://127.0.0.1:{port}")
    portal = make_portal(tmp_path, people=())
    demo.seed(portal)
    srv = uvicorn.Server(uvicorn.Config(create_app(portal), host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield portal, f"http://127.0.0.1:{port}"
    srv.should_exit = True
    t.join(5)


def test_forms_work_in_chromium(server):
    portal, base = server
    with playwright.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"Chromium not available: {exc}")
        page = browser.new_page()
        page.goto(base + "/dev/login")
        page.click("text=Alex Admin")
        page.goto(base + "/controls/HR-01")
        page.click("button:has-text('Send reminder')")
        page.wait_for_load_state()
        assert "Reminder sent" in page.content() or "skipped" in page.content(), page.content()[:500]
        page.goto(base + "/settings/organization")
        page.fill("input[name=GRCPAL_ORG_NAME]", "Browser Test Co")
        page.click("button:has-text('Save and apply')")
        page.wait_for_load_state()
        assert portal.settings.get("GRCPAL_ORG_NAME") == "Browser Test Co"
        browser.close()


def test_control_panel_and_slim_menu_in_chromium(server):
    """The control side panel opens from a list (no new page), tabs work with the keyboard, Esc closes it, a
    #control= link opens it, and the slim menu is remembered. Also: no errors under the strict CSP."""
    portal, base = server
    with playwright.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"Chromium not available: {exc}")
        page = browser.new_page(viewport={"width": 1400, "height": 900})
        errors = []
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.goto(base + "/dev/login")
        page.click("text=Alex Admin")
        page.goto(base + "/criteria/CC6.1")
        page.click('a[data-panel="IAM-02"] >> nth=0')
        page.wait_for_selector("[data-drawer]:not([hidden])")
        assert page.url.endswith("/criteria/CC6.1#control=IAM-02"), "the list stays; no new page"
        assert page.evaluate("document.activeElement.id") == "drawer-title"
        assert page.is_visible("#cp-overview") and page.is_hidden("#cp-evidence")
        page.focus("#cpt-overview")
        page.keyboard.press("ArrowRight")
        assert page.is_visible("#cp-evidence") and page.get_attribute("#cpt-evidence", "aria-selected") == "true"
        page.keyboard.press("Escape")
        assert page.is_hidden("[data-drawer]") and "#control=" not in page.url
        page.goto(base + "/controls#control=HR-01")
        page.wait_for_selector("[data-drawer]:not([hidden])")
        assert "HR-01" in page.inner_text("[data-drawer]")
        page.evaluate("window.location.hash = '#control=IAM-02'")
        page.wait_for_selector('[data-panel-id="IAM-02"]')  # the hash alone switches the panel
        page.click("[data-drawer-close]")
        page.click("[data-nav-toggle]")
        assert page.evaluate("document.body.classList.contains('nav-slim')")
        page.goto(base + "/controls")
        assert page.evaluate("document.body.classList.contains('nav-slim')"), "remembered in this browser"
        assert page.get_attribute("[data-nav-toggle]", "aria-expanded") == "false"
        assert not errors, errors
        browser.close()

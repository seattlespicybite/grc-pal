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


def _browser(p):
    try:
        return p.chromium.launch()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Chromium not available: {exc}")


def _signed_in(browser, base, errors):
    page = browser.new_page(viewport={"width": 1400, "height": 900})
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(base + "/dev/login")
    page.click("text=Alex Admin")
    return page


def test_control_panel_and_slim_menu_in_chromium(server):
    """The control side panel opens from a list (no new page) at 80% width over a backdrop; Escape, the backdrop
    and the browser's Back close it and the list keeps its scroll; a #control= link opens it; the whole row opens
    it; the menu remembers open groups and the slim mode. Also: no errors under the strict CSP."""
    portal, base = server
    with playwright.sync_playwright() as p:
        browser = _browser(p)
        errors = []
        page = _signed_in(browser, base, errors)
        page.goto(base + "/criteria/CC6.1")
        page.click('a[data-panel="IAM-02"] >> nth=0')
        page.wait_for_selector("[data-drawer]:not([hidden])")
        assert page.url.endswith("/criteria/CC6.1#control=IAM-02"), "the list stays; no new page"
        assert page.evaluate("document.activeElement.id") == "drawer-title"
        assert page.is_visible("[data-drawer-backdrop]")
        assert abs(page.evaluate("document.querySelector('[data-drawer]').getBoundingClientRect().width") - 1120) < 2
        assert page.is_visible("[data-drawer] #notes") and page.is_visible("[data-drawer] #upload"), "every section"
        page.keyboard.press("Escape")
        assert page.is_hidden("[data-drawer]") and "#control=" not in page.url

        page.goto(base + "/controls?sort=title")
        page.evaluate("window.scrollTo(0, 400)")
        y = page.evaluate("window.scrollY")
        page.click('tr[data-panel-row="HR-01"] td:last-child')  # not the link: the whole row opens the panel
        page.wait_for_selector('[data-panel-id="HR-01"]')
        assert page.url.endswith("/controls?sort=title#control=HR-01")
        page.go_back()
        page.wait_for_selector("[data-drawer]", state="hidden")
        assert page.url.endswith("/controls?sort=title") and page.evaluate("window.scrollY") == y, "Back closes, scroll kept"
        page.click('tr[data-panel-row="HR-01"] td:last-child')
        page.wait_for_selector('[data-panel-id="HR-01"]')
        page.mouse.click(40, 450)  # the backdrop, left of the panel
        page.wait_for_selector("[data-drawer]", state="hidden")
        assert page.url.endswith("/controls?sort=title")

        page.goto(base + "/controls#control=HR-01")
        page.wait_for_selector("[data-drawer]:not([hidden])")
        page.evaluate("window.location.hash = '#control=IAM-02'")
        page.wait_for_selector('[data-panel-id="IAM-02"]')  # the hash alone switches the panel
        page.click("[data-drawer-close]")

        assert page.evaluate("document.querySelector('[data-nav-group=docs]').open") is False
        page.click("[data-nav-group=docs] > summary")
        page.goto(base + "/controls")
        assert page.evaluate("document.querySelector('[data-nav-group=docs]').open"), "open group remembered"
        assert page.evaluate("document.querySelector('[data-nav-group=program]').open"), "current page's group open"
        page.click("[data-nav-toggle]")
        assert page.evaluate("document.body.classList.contains('nav-slim')")
        page.goto(base + "/controls")
        assert page.evaluate("document.body.classList.contains('nav-slim')"), "remembered in this browser"
        assert page.get_attribute("[data-nav-toggle]", "aria-expanded") == "false"
        assert not errors, errors
        browser.close()


def test_unsaved_changes_and_saving_in_chromium(server):
    """A changed form asks before the panel closes or the page is left (in-page dialog naming the section and
    field). Saving from the panel comes back to the list with the same panel open and the message; saving on the
    full page stays there."""
    portal, base = server
    with playwright.sync_playwright() as p:
        browser = _browser(p)
        errors = []
        page = _signed_in(browser, base, errors)
        page.goto(base + "/controls?sort=title")
        page.click('a[data-panel="HR-01"] >> nth=0')
        page.wait_for_selector('[data-panel-id="HR-01"]')
        page.click("[data-drawer] #notes details > summary")
        page.fill("[data-drawer] #note-text", "Covered by the onboarding procedure, section 2.")
        page.keyboard.press("Escape")
        page.wait_for_selector("[data-unsaved-dialog][open]")
        listed = page.inner_text("[data-unsaved-list]")
        assert "How we meet this control" in listed and "Notes" in listed, listed
        page.click("[data-unsaved-keep]")
        assert page.is_visible("[data-drawer]") and page.input_value("[data-drawer] #note-text").startswith("Covered")
        page.mouse.click(40, 450)
        page.wait_for_selector("[data-unsaved-dialog][open]")
        page.keyboard.press("Escape")  # Escape on the question = keep editing
        page.wait_for_selector("[data-unsaved-dialog]:not([open])", state="attached")
        assert page.is_visible("[data-drawer]")
        page.mouse.click(40, 450)
        page.wait_for_selector("[data-unsaved-dialog][open]")
        page.click("[data-unsaved-discard]")
        page.wait_for_selector("[data-drawer]", state="hidden")

        page.click('a[data-panel="HR-01"] >> nth=0')
        page.wait_for_selector('[data-panel-id="HR-01"]')
        page.click("[data-drawer] #notes details > summary")
        page.fill("[data-drawer] #note-text", "Covered by the onboarding procedure, section 2.")
        page.click("[data-drawer] button:has-text('Save notes')")
        page.wait_for_selector('[data-panel-id="HR-01"]')
        assert "/controls?sort=title" in page.url and page.url.endswith("#control=HR-01"), page.url
        assert "Implementation notes saved" in page.inner_text(".flash.ok")
        assert portal.control_note("HR-01")["text"] == "Covered by the onboarding procedure, section 2."

        page.goto(base + "/controls/HR-01")
        page.click("#notes details > summary")
        page.fill("#note-text", "Second version.")
        page.click("a[href='/vendors']")
        page.wait_for_selector("[data-unsaved-dialog][open]")
        page.click("[data-unsaved-keep]")
        assert page.url.endswith("/controls/HR-01")
        page.click("button:has-text('Save notes')")
        page.wait_for_load_state()
        assert "/controls/HR-01?msg=" in page.url, "saved on the full page: stay there"
        assert portal.control_note("HR-01")["text"] == "Second version."
        assert not errors, errors
        browser.close()

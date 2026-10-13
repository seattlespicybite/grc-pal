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

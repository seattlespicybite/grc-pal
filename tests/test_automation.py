"""Automation failure alerts and digests (batch 5)."""
import datetime as dt

import pytest
from fastapi.testclient import TestClient

from grcpal.portal.app import create_app
from grcpal.portal.auth import SYSTEM
from grcpal.portal.service import Forbidden
from grcpal.portal.store import SqliteStore
from test_calendar import backdate, make_run
from test_portal import ADMIN, ADMIN2, AUDITOR, CONTRIB, as_, csrf, make_portal  # TODAY = 2026-10-12 (Monday)


@pytest.fixture()
def portal(tmp_path):
    p = make_portal(tmp_path)
    backdate(p)
    return p


def mails(portal, kind):
    return [m for m in portal.mailer.outbox if m.kind == kind]


def test_failed_run_alerts_admins_once_and_again_on_the_next_failure(portal):
    make_run(portal, "entra_users", at="2026-10-11T02:30:00")
    make_run(portal, "entra_users", status="error", error="HTTPError: 401 Unauthorized\nstack...", at="2026-10-12T02:30:00")
    got = portal.send_automation_alerts(SYSTEM)
    assert [f["source"] for f in got] == ["entra_users"]
    sent = mails(portal, "automation")
    assert {m.to for m in sent} == {ADMIN.email, ADMIN2.email}  # admins only, never control owners or auditors
    assert "401 Unauthorized" in sent[0].text and "stack..." not in sent[0].text  # first line of the error only
    assert portal.send_automation_alerts(SYSTEM) == []  # same failed run: no second email
    make_run(portal, "entra_users", status="error", error="HTTPError: 401 Unauthorized", at="2026-10-12T09:00:00")
    again = portal.send_automation_alerts(SYSTEM)
    assert again[0]["streak"] == 2 and "2 runs in a row" in mails(portal, "automation")[0].text
    assert any(r["action"] == "automation.alert" for r in portal.log.records())


def test_passing_runs_send_no_alert(portal):
    make_run(portal, "entra_users", status="error", error="boom", at="2026-10-11T02:30:00")
    make_run(portal, "entra_users", at="2026-10-12T02:30:00")  # fixed
    assert portal.send_automation_alerts(SYSTEM) == [] and not mails(portal, "automation")


def test_admin_can_turn_alerts_off_and_choose_digests(portal):
    portal.set_notify_prefs(ADMIN2, False, ["weekly", "bogus"])
    assert portal.notify_prefs(ADMIN2) == {"alerts": False, "digests": ["weekly"]}
    make_run(portal, "entra_users", status="error", error="boom", at="2026-10-12T02:30:00")
    portal.send_automation_alerts(SYSTEM)
    assert {m.to for m in mails(portal, "automation")} == {ADMIN.email}
    for who in (CONTRIB, AUDITOR):
        with pytest.raises(Forbidden):
            portal.set_notify_prefs(who, True, ["daily"])
    assert any(r["action"] == "notify.prefs" for r in portal.log.records())


def test_digests_are_opt_in_and_sent_on_their_day_once(portal):
    make_run(portal, "entra_users", at="2026-10-11T02:30:00")
    make_run(portal, "entra_users", status="error", error="Timeout", at="2026-10-12T02:30:00")
    assert portal.send_digests(SYSTEM) == []  # nobody opted in
    portal.set_notify_prefs(ADMIN, True, ["daily", "weekly", "monthly"])
    sent = portal.send_digests(SYSTEM)
    assert [d["kind"] for d in sent] == ["daily", "weekly"]  # Monday 12 October: no monthly digest
    daily = next(m for m in mails(portal, "digest") if "morning" in m.subject)
    assert daily.to == ADMIN.email and "Failing now" in daily.text and "Timeout" in daily.text
    assert "Did not run in this period" in daily.text  # sources that are on but never ran are called out
    assert portal.send_digests(SYSTEM) == []  # at most once a day
    portal._today = dt.date(2026, 11, 1)
    assert [d["kind"] for d in portal.send_digests(SYSTEM)] == ["daily", "monthly"]
    monthly = next(m for m in mails(portal, "digest") if "monthly" in m.subject)
    assert "October 2026" in monthly.text


def test_digests_and_alerts_are_tenant_scoped(tmp_path):
    shared = SqliteStore(tmp_path / "shared.db")
    a = make_portal(tmp_path / "a", tenant="acme", base_store=shared)
    b = make_portal(tmp_path / "b", tenant="globex", base_store=shared)
    make_run(a, "entra_users", status="error", error="boom", at="2026-10-12T02:30:00")
    assert a.send_automation_alerts(SYSTEM) and not b.send_automation_alerts(SYSTEM)


def test_email_alerts_page(portal, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.delenv("GRCPAL_PUBLIC_URL", raising=False)
    client = TestClient(create_app(portal), base_url="https://grc.example.com")
    as_(client, ADMIN)
    page = client.get("/calendar/notifications").text
    assert 'name="alerts" value="1" checked' in page and 'style="' not in page
    assert 'href="/calendar/notifications"' in client.get("/calendar").text
    r = client.post("/calendar/notifications", data={"csrf": csrf(client, "/calendar"), "digests": ["daily"]},
                    follow_redirects=False)
    assert r.status_code == 303 and portal.notify_prefs(ADMIN) == {"alerts": False, "digests": ["daily"]}
    as_(client, AUDITOR)
    assert client.get("/calendar/notifications").status_code == 403


def test_collect_job_sends_alerts_and_never_fails_because_of_email(portal, monkeypatch, capsys):
    from grcpal import cli

    make_run(portal, "entra_users", status="error", error="boom", at="2026-10-12T02:30:00")
    monkeypatch.setattr(cli, "_admin_portal", lambda args: portal)
    cli._automation_mail(object())
    assert mails(portal, "automation") and "alert entra_users" in capsys.readouterr().out

    def broken(args):
        raise RuntimeError("mail server down")
    monkeypatch.setattr(cli, "_admin_portal", broken)
    cli._automation_mail(object())  # must not raise: the evidence is already collected
    assert "WARN  automation email" in capsys.readouterr().err

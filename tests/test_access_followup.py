"""Access reviews after the list is built (grcpal/portal/accessfollowup.py, grcpal/tickets.py): invitations and
reminders to reviewers, remediation tickets in Jira or GitHub (never automatic disabling), checking removals against
the nightly account pull, and the review schedule. Jira, GitHub and the applications are simulated."""
import datetime as dt
import json

import pytest
from fastapi.testclient import TestClient

from grcpal import checks, tickets
from grcpal.checks import Response
from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from test_accessreview import ACCOUNTS, HEADER, decide_all
from test_accesssources import FakeApi, FakeClients
from test_portal import ADMIN, ADMIN2, AUDITOR, CONTRIB, HR, TODAY, as_, csrf, make_portal, outbox

JIRA = "https://acme.atlassian.net"


@pytest.fixture()
def portal(tmp_path, monkeypatch):
    for key in ("GRCPAL_MS_ENABLED", "GRCPAL_AZURE_ENABLED", "GRCPAL_GITHUB_ENABLED"):
        monkeypatch.setenv(key, "true")
    for key in ("GRCPAL_TICKETS_SYSTEM", "GRCPAL_JIRA_URL", "GRCPAL_JIRA_TOKEN", "GRCPAL_JIRA_EMAIL",
                "GRCPAL_JIRA_PROJECT", "GRCPAL_TICKETS_REPO", "GRCPAL_GRC_REPO", "GRCPAL_GITHUB_TOKEN",
                "GRCPAL_SSO_ENABLED", "GRCPAL_AUTH_MODE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GRCPAL_JOBS_SYNC", "1")
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", "test-only-key-0123456789abcdef")
    return make_portal(tmp_path)


def start(portal, due="2026-11-30", text=ACCOUNTS):
    return portal.create_access_campaign(ADMIN, "Q4 review", due, text.encode())["RowKey"]


def jira_on(monkeypatch):
    monkeypatch.setenv("GRCPAL_TICKETS_SYSTEM", "jira")
    monkeypatch.setenv("GRCPAL_JIRA_URL", JIRA)
    monkeypatch.setenv("GRCPAL_JIRA_EMAIL", "grc-bot@example.com")
    monkeypatch.setenv("GRCPAL_JIRA_TOKEN", "jira-token-not-real")
    monkeypatch.setenv("GRCPAL_JIRA_PROJECT", "IT")


class FakeJira:
    def __init__(self, status=201):
        self.status, self.sent, self.n = status, [], 0

    def __call__(self, method, url, headers=None, body=None, timeout=15, allow_private=None, user_agent="", **kw):
        self.sent.append({"method": method, "url": url, "headers": dict(headers or {}),
                          "body": json.loads(body) if body else None, "allow_private": allow_private})
        if self.status >= 400:
            data = {"errorMessages": ["Field 'issuetype' is not valid"]}
        elif url.endswith("/rest/api/2/myself"):
            data = {"displayName": "GRC bot"}
        elif "/rest/api/2/project/" in url:
            data = {"key": "IT"}
        else:
            self.n += 1
            data = {"id": str(10000 + self.n), "key": f"IT-{self.n}"}
        return Response(self.status if method == "POST" or self.status >= 400 else 200, {},
                        json.dumps(data).encode(), 5, url, "203.0.113.20")


# ================================================================ invitations
def test_invitation_emails_carry_counts_never_accounts(portal):
    cid = start(portal)
    r = portal.invite_access_reviewers(ADMIN, cid)
    assert sorted(r["sent"]) == sorted([HR.email, CONTRIB.email]) and not r["created"]
    mail = outbox(portal, HR.email)[-1]
    assert "3 accounts to review by 2026-11-30" in mail.subject
    assert "GitHub, Slack" in mail.text and f"/access-reviews/{cid}" in mail.text
    assert "alice" not in mail.text and "bob@example.com" not in mail.text, "no account details in email"
    camp = portal._ar_campaign(cid)
    assert camp["invited"] == {HR.email: TODAY.isoformat(), CONTRIB.email: TODAY.isoformat()}
    audit = [x for x in portal.log.recent(30) if x["action"] == "access_review.invite"][0]
    assert audit["detail"] == {"invited": 2, "accounts_created": 0, "without_account": 0}


def test_signed_off_reviewers_are_not_invited_again(portal):
    cid = start(portal)
    decide_all(portal, cid, HR)
    portal.attest_access(HR, cid)
    assert portal.invite_access_reviewers(ADMIN, cid)["sent"] == [CONTRIB.email]


def test_managers_without_an_account_get_one_only_when_asked(portal):
    text = HEADER + "Slack,dan,dan@example.com,Dan,active,member,2026-10-10,yes,no,newboss@example.com\n"
    cid = start(portal, text=text)
    r = portal.invite_access_reviewers(ADMIN, cid)
    assert r["without_account"] == ["newboss@example.com"] and not r["sent"]
    assert portal.user_row("newboss@example.com") is None
    r = portal.invite_access_reviewers(ADMIN, cid, create_accounts=True)
    row = portal.user_row("newboss@example.com")
    assert r["created"] == ["newboss@example.com"] and row["role"] == "contributor" and row["source"] == "access_review"
    subjects = [m.subject for m in outbox(portal, "newboss@example.com")]
    assert "Set up your GRC-pal account" in subjects, "local sign-in: a password link comes first"
    assert any("to review by" in s for s in subjects)


def test_managers_get_microsoft_sign_in_when_it_is_set_up(portal, monkeypatch):
    monkeypatch.setattr(type(portal), "ms_signin_ready", lambda self: True)
    text = HEADER + "Slack,dan,dan@example.com,Dan,active,member,2026-10-10,yes,no,newboss@example.com\n"
    cid = start(portal, text=text)
    portal.invite_access_reviewers(ADMIN, cid, create_accounts=True)
    assert portal.user_row("newboss@example.com")["signin"] == "microsoft"
    assert "Set up your GRC-pal account" not in [m.subject for m in outbox(portal, "newboss@example.com")]


def test_only_admins_invite_and_only_while_open(portal):
    cid = start(portal)
    with pytest.raises(Forbidden):
        portal.invite_access_reviewers(CONTRIB, cid)
    with pytest.raises(Forbidden):
        portal.invite_access_reviewers(AUDITOR, cid)
    for who in (HR, CONTRIB):
        decide_all(portal, cid, who)
        portal.attest_access(who, cid)
    with pytest.raises(Invalid, match="signed off"):
        portal.invite_access_reviewers(ADMIN, cid)


# ================================================================ reminders
def test_reminders_start_a_week_before_and_repeat_every_few_days(portal):
    cid = start(portal, due="2026-10-30")                      # 18 days away
    assert portal.send_access_review_reminders(ADMIN) == []
    portal._today = dt.date(2026, 10, 24)                      # 6 days left
    out = portal.send_access_review_reminders(ADMIN)
    assert out == [{"campaign": cid, "reminded": 2, "overdue": False}]
    assert "Reminder: access review due 2026-10-30" in outbox(portal, HR.email)[-1].subject
    assert portal.send_access_review_reminders(ADMIN) == [], "not twice in a few days"
    decide_all(portal, cid, HR)
    portal.attest_access(HR, cid)
    portal._today = dt.date(2026, 10, 27)
    out = portal.send_access_review_reminders(ADMIN)
    assert out[0]["reminded"] == 1 and outbox(portal, CONTRIB.email)[-1].subject.startswith("Reminder")
    assert sum(1 for m in outbox(portal, HR.email) if m.subject.startswith("Reminder")) == 1, "HR signed off"


def test_overdue_reviewers_and_admins_are_told(portal):
    cid = start(portal, due="2026-10-12")
    portal._today = dt.date(2026, 10, 14)
    out = portal.send_access_review_reminders(ADMIN)
    assert out[0]["overdue"] is True
    assert outbox(portal, HR.email)[-1].subject.startswith("Overdue: access review was due 2026-10-12")
    admin_notice = [m for m in outbox(portal, ADMIN2.email) if m.subject.startswith("Access review overdue")]
    assert len(admin_notice) == 1 and HR.email in admin_notice[0].text
    portal._today = dt.date(2026, 10, 18)
    portal.send_access_review_reminders(ADMIN)
    assert len([m for m in outbox(portal, ADMIN2.email) if m.subject.startswith("Access review overdue")]) == 1
    assert portal._ar_campaign(cid)["overdue_notified"] == "2026-10-14"


def test_closed_reviews_get_no_reminders(portal):
    cid = start(portal, due="2026-10-14")
    for who in (HR, CONTRIB):
        decide_all(portal, cid, who)
        portal.attest_access(who, cid)
    unassigned = [e for e in portal._ar_entries(cid) if not e["reviewer"]]
    for e in unassigned:
        portal.assign_access_reviewer(ADMIN, cid, e["RowKey"], ADMIN2.email)
    decide_all(portal, cid, ADMIN2)
    portal.attest_access(ADMIN2, cid)
    portal.close_access_campaign(ADMIN, cid)
    portal._today = dt.date(2026, 10, 20)
    assert portal.send_access_review_reminders(ADMIN) == []


# ================================================================ remediation tickets
def revoke_bob(portal, cid):
    mine = {e["account_id"]: e for e in portal.access_campaign(HR, cid)["mine"]}
    portal.save_access_decisions(HR, cid, {
        mine["alice"]["RowKey"]: {"decision": "keep"},
        mine["bob"]["RowKey"]: {"decision": "revoke", "comment": "Left the team @everyone [~admin] {code}"},
        mine["bob-s"]["RowKey"]: {"decision": "modify", "comment": "Member to guest"}})


def test_tickets_need_a_ticket_system(portal):
    cid = start(portal)
    revoke_bob(portal, cid)
    with pytest.raises(Invalid, match="Remediation tickets"):
        portal.create_access_tickets(ADMIN, cid)


def test_one_jira_ticket_per_application_and_never_twice(portal, monkeypatch):
    jira_on(monkeypatch)
    cid = start(portal)
    revoke_bob(portal, cid)
    fake = FakeJira()
    r = portal.create_access_tickets(ADMIN, cid, request_fn=fake)
    assert [(t["app"], t["key"], t["accounts"]) for t in r["created"]] == [("GitHub", "IT-1", 1), ("Slack", "IT-2", 1)]
    assert not r["failed"]
    post = fake.sent[0]
    assert post["url"] == f"{JIRA}/rest/api/2/issue" and post["method"] == "POST"
    assert post["headers"]["Authorization"].startswith("Basic ") and "jira-token" not in json.dumps(post["body"])
    fields = post["body"]["fields"]
    assert fields["project"] == {"key": "IT"} and fields["issuetype"] == {"name": "Task"}
    assert fields["summary"] == "Access review: remove 1 account in GitHub"
    assert "- bob (Bob / bob@example.com): Remove access" in fields["description"]
    assert "@\u200beveryone" in fields["description"], "no mentions"
    assert "\\[~admin\\]" in fields["description"] and "\\{code\\}" in fields["description"], "no Jira markup"
    assert "never changes accounts itself" in fields["description"]
    by_id = {e["account_id"]: e for e in portal._ar_entries(cid)}
    assert by_id["bob"]["ticket_key"] == "IT-1" and by_id["bob"]["ticket_url"] == f"{JIRA}/browse/IT-1"
    assert "ticket_key" not in by_id["alice"]
    assert by_id["bob"]["remediation"] == "open", "a ticket is not a confirmation"
    acts = [x for x in portal.log.recent(30) if x["action"] == "access_review.ticket"]
    assert {a["detail"]["ticket"] for a in acts} == {"IT-1", "IT-2"}
    with pytest.raises(Invalid, match="No removals"):
        portal.create_access_tickets(ADMIN, cid, request_fn=fake)


def test_jira_refusal_is_reported_and_nothing_is_marked(portal, monkeypatch):
    jira_on(monkeypatch)
    cid = start(portal)
    revoke_bob(portal, cid)
    r = portal.create_access_tickets(ADMIN, cid, request_fn=FakeJira(status=400))
    assert not r["created"] and len(r["failed"]) == 2 and "issuetype" in r["failed"][0]["error"]
    assert not any(e.get("ticket_key") for e in portal._ar_entries(cid))


def test_jira_data_center_uses_a_bearer_token_and_its_own_private_opt_in(portal, monkeypatch):
    jira_on(monkeypatch)
    monkeypatch.delenv("GRCPAL_JIRA_EMAIL")
    cid = start(portal)
    revoke_bob(portal, cid)
    fake = FakeJira()
    portal.create_access_tickets(ADMIN, cid, request_fn=fake)
    assert fake.sent[0]["headers"]["Authorization"] == "Bearer jira-token-not-real"
    assert fake.sent[0]["allow_private"] is False
    monkeypatch.setenv("GRCPAL_JIRA_ALLOW_PRIVATE", "1")
    tickets.jira_create(portal.settings, "t", ["x"], request_fn=fake)
    assert fake.sent[-1]["allow_private"] is True


def test_github_issue_per_application(portal, monkeypatch):
    monkeypatch.setenv("GRCPAL_TICKETS_SYSTEM", "github")
    monkeypatch.setenv("GRCPAL_GRC_REPO", "acme/acme-grc")
    monkeypatch.setenv("GRCPAL_GITHUB_TOKEN", "github_pat_not_real")

    class GH:
        posts = []

        def gh_post(self, path, body):
            self.posts.append((path, body))
            return {"number": 40 + len(self.posts), "html_url": f"https://github.com/acme/acme-grc/issues/{40 + len(self.posts)}"}

    cid = start(portal)
    revoke_bob(portal, cid)
    gh = GH()
    r = portal.create_access_tickets(ADMIN, cid, clients=gh)
    assert [t["key"] for t in r["created"]] == ["#41", "#42"]
    assert gh.posts[0][0] == "/repos/acme/acme-grc/issues" and "Remove access" in gh.posts[0][1]["body"]


def test_last_sign_off_opens_tickets_by_itself(portal, monkeypatch):
    jira_on(monkeypatch)
    fake = FakeJira()
    monkeypatch.setattr(checks, "safe_request", fake)
    cid = start(portal)
    revoke_bob(portal, cid)
    portal.attest_access(HR, cid)
    assert not fake.sent, "CONTRIB has not signed off yet"
    for e in [e for e in portal._ar_entries(cid) if not e["reviewer"]]:
        portal.assign_access_reviewer(ADMIN, cid, e["RowKey"], ADMIN2.email)
    decide_all(portal, cid, ADMIN2)
    portal.attest_access(ADMIN2, cid)
    decide_all(portal, cid, CONTRIB)
    portal.attest_access(CONTRIB, cid)
    assert len([s for s in fake.sent if s["method"] == "POST"]) == 2
    assert {t["key"] for t in portal._ar_campaign(cid)["tickets"]} == {"IT-1", "IT-2"}


def test_ticket_text_is_plain():
    assert tickets.plain("a\nb\x00c @team [link|http://x] {panel}") == \
        "a b c @\u200bteam \\[link\\|http://x\\] \\{panel\\}"


def test_jira_settings_and_connection_test(portal, monkeypatch):
    from grcpal.integrations import Result
    jira_on(monkeypatch)
    monkeypatch.setenv("GRCPAL_JIRA_URL", "http://jira.internal")
    assert "https://" in tickets.problems(portal.settings)[0]
    monkeypatch.setenv("GRCPAL_JIRA_URL", JIRA)
    res = Result()
    tickets.validate(portal.settings, None, res, request_fn=FakeJira())
    assert res.ok and [c.name for c in res.checks] == ["Jira sign-in", "Jira project IT"]
    from grcpal.settings import ENDPOINT_SECRETS
    assert ENDPOINT_SECRETS["GRCPAL_JIRA_URL"] == ("GRCPAL_JIRA_TOKEN",), "changing the address clears the token"


# ================================================================ checking removals against the account pull
def pulled_review(portal):
    crm = portal.add_access_app(ADMIN, "Customer portal", "rest", "")
    portal.update_access_app(ADMIN, crm["RowKey"], {
        "name": "Customer portal", "url": "https://api.example.com/v1/users", "method": "GET", "auth": "bearer",
        "items_path": "users", "paging": "none", "map_account_id": "login", "map_email": "mail", "map_role": "role",
        "map_status": "state"}, token="crm-secret-token-123")
    api = FakeApi({"https://api.example.com/v1/users": {"users": [
        {"login": "alice", "mail": "alice@example.com", "role": "owner", "state": "active"},
        {"login": "carol", "mail": "carol@example.com", "role": "agent", "state": "active"}]}})
    people = f"email,manager_email\nalice@example.com,{HR.email}\ncarol@example.com,{CONTRIB.email}\n".encode()
    job = portal.start_access_review(ADMIN, "CRM review", "2026-11-30", [crm["RowKey"]], people=people, request_fn=api)
    assert job["status"] == "done", job.get("message")
    cid = job["result"]["campaign"]
    mine = portal.access_campaign(HR, cid)["mine"]
    portal.save_access_decisions(HR, cid, {mine[0]["RowKey"]: {"decision": "revoke"}})
    theirs = portal.access_campaign(CONTRIB, cid)["mine"]
    portal.save_access_decisions(CONTRIB, cid, {theirs[0]["RowKey"]: {"decision": "modify", "comment": "agent to viewer"}})
    return crm, cid


def pull(portal, crm, users):
    import time
    time.sleep(1.05)  # a pull in the same second as the decision does not count as "after" it
    api = FakeApi({"https://api.example.com/v1/users": {"users": users}})
    assert portal.pull_access_snapshots(ADMIN, [crm["RowKey"]], request_fn=api)[0]["ok"]


def checks_of(portal, cid):
    return {e["account_id"]: e.get("pull_check") for e in portal._ar_entries(cid)}


def test_pull_check_needs_a_pull_after_the_decision(portal):
    _, cid = pulled_review(portal)  # its only pull was taken before the decisions, often in the same second
    counts = portal.check_access_changes(ADMIN, cid)
    assert counts["no_newer_pull"] == 2 and checks_of(portal, cid) == {"alice": "no_newer_pull", "carol": "no_newer_pull"}
    with pytest.raises(Invalid, match="No removal or change is shown as done"):
        portal.confirm_checked_changes(ADMIN, cid)


def test_pull_shows_removed_and_changed_accounts_and_admin_confirms_them(portal):
    crm, cid = pulled_review(portal)
    pull(portal, crm, [{"login": "carol", "mail": "carol@example.com", "role": "viewer", "state": "active"}])
    counts = portal.check_access_changes(ADMIN, cid)
    assert counts["gone"] == 1 and counts["changed"] == 1
    assert checks_of(portal, cid) == {"alice": "gone", "carol": "changed"}
    assert all(e["remediation"] == "open" for e in portal._ar_entries(cid)), "checking confirms nothing by itself"
    assert portal.confirm_checked_changes(ADMIN, cid) == 2
    alice = next(e for e in portal._ar_entries(cid) if e["account_id"] == "alice")
    assert alice["remediation"] == "done" and alice["remediated_by"] == ADMIN.email
    assert "Account no longer in the application in the account pull of" in alice["remediation_note"]
    assert f"access-{crm['RowKey']}/" in alice["remediation_note"], "the note names the stored pull (evidence)"
    assert sum(1 for x in portal.log.recent(40) if x["action"] == "access_review.confirm") == 2


def test_pull_shows_disabled_and_still_there(portal):
    crm, cid = pulled_review(portal)
    pull(portal, crm, [{"login": "alice", "mail": "alice@example.com", "role": "owner", "state": "suspended"},
                       {"login": "carol", "mail": "carol@example.com", "role": "agent", "state": "active"}])
    portal.check_access_changes(ADMIN, cid)
    assert checks_of(portal, cid) == {"alice": "disabled", "carol": "still_there"}
    assert portal.confirm_checked_changes(ADMIN, cid) == 1


def test_csv_only_reviews_are_not_pulled(portal):
    cid = start(portal)
    revoke_bob(portal, cid)
    assert portal.check_access_changes(ADMIN, cid)["no_pull"] == 2
    with pytest.raises(Forbidden):
        portal.check_access_changes(AUDITOR, cid)


# ================================================================ schedule
def crm_app(portal):
    crm = portal.add_access_app(ADMIN, "Customer portal", "rest", ADMIN2.email)
    portal.update_access_app(ADMIN, crm["RowKey"], {
        "name": "Customer portal", "url": "https://api.example.com/v1/users", "method": "GET", "auth": "bearer",
        "items_path": "users", "paging": "none", "map_account_id": "login", "map_email": "mail", "map_role": "role"},
        token="crm-secret-token-123")
    return crm


CRM = FakeApi({"https://api.example.com/v1/users": {"users": [
    {"login": "alice", "mail": "alice@example.com", "role": "owner"},
    {"login": "carol", "mail": "carol@example.com", "role": "agent"}]}})


def schedule(portal, crm, **kw):
    args = dict(active=True, name="User access review", every="3", first_month="1", start_day="1", days="14",
                app_ids=[crm["RowKey"]], entra_managers=True, invite=True)
    args.update(kw)
    return portal.save_access_schedule(ADMIN, **args)


def test_schedule_starts_on_its_day_once_and_invites(portal):
    crm = crm_app(portal)
    s = schedule(portal, crm)
    assert s["next_start"] == "2027-01-01"
    assert portal.run_access_review_schedules(ADMIN, clients=FakeClients(), request_fn=CRM) == []
    portal._today = dt.date(2027, 1, 1)
    out = portal.run_access_review_schedules(ADMIN, clients=FakeClients(), request_fn=CRM)
    assert len(out) == 1 and out[0]["period"] == "2027-01-01"
    camp = portal._ar_campaign(out[0]["campaign"])
    assert camp["name"] == "User access review 2027-01" and camp["due"] == "2027-01-15" and camp["records"] == 2
    assert set(camp["invited"]) == {HR.email, CONTRIB.email}, "reviewers from Entra direct reports were emailed"
    assert any(m.subject == "Access review started: User access review 2027-01" for m in outbox(portal, ADMIN2.email))
    assert portal.run_access_review_schedules(ADMIN, clients=FakeClients(), request_fn=CRM) == [], "once per period"
    assert portal.access_schedule(ADMIN)["next_start"] == "2027-04-01"


def test_schedule_never_starts_a_period_that_began_before_it_was_saved(portal):
    crm = crm_app(portal)
    s = schedule(portal, crm, first_month="10")       # this period began 2026-10-01; today is 2026-10-12
    assert s["next_start"] == "2027-01-01"
    assert portal.run_access_review_schedules(ADMIN, clients=FakeClients(), request_fn=CRM) == []


def test_late_job_still_gives_reviewers_time(portal):
    crm = crm_app(portal)
    schedule(portal, crm)
    portal._today = dt.date(2027, 1, 20)                # the nightly job did not run for three weeks
    out = portal.run_access_review_schedules(ADMIN, clients=FakeClients(), request_fn=CRM)
    assert portal._ar_campaign(out[0]["campaign"])["due"] == "2027-02-03"


def test_failed_scheduled_start_tells_admins_and_does_not_retry_every_night(portal):
    crm = crm_app(portal)
    schedule(portal, crm)
    portal._today = dt.date(2027, 1, 1)
    out = portal.run_access_review_schedules(ADMIN, clients=FakeClients(), request_fn=FakeApi({}, status=500))
    assert "error" in out[0] and portal.access_campaigns(ADMIN) == []
    assert any(m.subject.startswith("Scheduled access review did not start") for m in outbox(portal, ADMIN2.email))
    assert portal.access_schedule(ADMIN)["last_error"]
    portal._today = dt.date(2027, 1, 2)
    assert portal.run_access_review_schedules(ADMIN, clients=FakeClients(), request_fn=CRM) == []


def test_schedule_rules(portal):
    crm = crm_app(portal)
    csv_app = portal.add_access_app(ADMIN, "Payroll", "csv", "")
    with pytest.raises(Invalid, match="every 3, 6 or 12"):
        schedule(portal, crm, every="5")
    with pytest.raises(Invalid, match="every 3, 6 or 12"):
        schedule(portal, crm, start_day="31")
    with pytest.raises(Invalid, match="cannot be pulled"):
        schedule(portal, crm, app_ids=[csv_app["RowKey"]])
    with pytest.raises(Invalid, match="at least one application"):
        schedule(portal, crm, app_ids=[])
    with pytest.raises(Forbidden):
        portal.save_access_schedule(CONTRIB, True, "x", "3", "1", "1", "14", [crm["RowKey"]], False, False)
    off = schedule(portal, crm, active=False, app_ids=[])
    assert not off["active"] and off["next_start"] == ""
    assert portal.run_access_review_schedules(ADMIN) == []
    acts = [x for x in portal.log.recent(20) if x["action"] == "access_review.schedule"]
    assert acts and acts[0]["detail"]["active"] is False


def test_six_monthly_and_yearly_starts(portal):
    crm = crm_app(portal)
    assert schedule(portal, crm, every="6", first_month="3", start_day="15")["next_start"] == "2027-03-15"
    assert schedule(portal, crm, every="12", first_month="11")["next_start"] == "2026-11-01"


# ================================================================ pages
@pytest.fixture()
def client(portal, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    monkeypatch.delenv("GRCPAL_PUBLIC_URL", raising=False)
    return TestClient(create_app(portal), base_url="https://grc.example.com")


def test_pages_show_schedule_invitations_and_tickets(portal, client):
    cid = start(portal)
    revoke_bob(portal, cid)
    as_(client, ADMIN)
    page = client.get("/access-reviews").text
    assert 'id="schedule"' in page and "Set up a schedule" in page and 'name="invite"' in page
    page = client.get(f"/access-reviews/{cid}").text
    assert "Email reviewers who have not signed off (2)" in page
    assert "set up <a href=\"/settings/tickets\">Remediation tickets</a>" in page
    token = csrf(client, f"/access-reviews/{cid}")
    r = client.post(f"/access-reviews/{cid}/invite", data={"csrf": token}, follow_redirects=False)
    assert r.status_code == 303 and "Emailed+2+reviewers" in r.headers["location"]
    assert "Invited 2026-10-12" in client.get(f"/access-reviews/{cid}").text
    as_(client, AUDITOR)
    page = client.get(f"/access-reviews/{cid}").text
    assert "Email reviewers" not in page and "/tickets" not in page
    as_(client, HR)
    assert "Email reviewers" not in client.get(f"/access-reviews/{cid}").text


def test_new_tables_and_fields_are_registered():
    from grcpal.portal.store import _JSON_FIELDS, TABLES
    assert "arschedules" in TABLES
    assert {"invited", "reminded", "tickets", "app_ids"} <= _JSON_FIELDS


def test_nightly_job_sends_reminders(portal, monkeypatch, capsys):
    from grcpal import cli
    cid = start(portal, due="2026-10-15")
    monkeypatch.setattr(cli, "_admin_portal", lambda args: portal)
    cli._automation_mail(object())
    assert f"access review {cid}: 2 reminder(s)" in capsys.readouterr().out

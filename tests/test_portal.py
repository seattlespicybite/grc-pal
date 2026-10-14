"""Portal tests: sign-in, roles, tenant isolation, evidence workflow, comments, email, reminders,
cycles, overrides, policies, exports, audit-log integrity, CSRF and the CLI."""
import base64
import csv
import datetime as dt
import io
import json
import re
import shutil
import zipfile
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from grcpal import cli, report
from grcpal.catalog import Catalog
from grcpal.evidence import EvidenceStore
from grcpal.portal import auth, mailer
from grcpal.portal.app import create_app
from grcpal.portal.auth import SYSTEM, Identity, User
from grcpal.portal.service import Forbidden, Invalid, Portal
from grcpal.portal.store import SqliteStore, TenantStore

ROOT = Path(__file__).resolve().parents[1] / "grcpal" / "starter"
TODAY = dt.date(2026, 10, 12)
ADMIN = User("sec@example.com", "Sec Lead", "admin")
ADMIN2 = User("vp@example.com", "VP", "admin")
HR = User("hr@example.com", "HR Lead", "contributor")          # owns hr-lead controls in roles.yaml
CONTRIB = User("pat@example.com", "Pat", "contributor")       # sees only what is assigned
AUDITOR = User("cpa@firm.example", "Auditor", "auditor")
PDF = b"%PDF-1.4\n% test evidence\n"


def make_portal(tmp_path, tenant="acme", base_store=None, people=(ADMIN, ADMIN2, HR, CONTRIB, AUDITOR)):
    base = tmp_path / f"repo-{tenant}"
    if not base.exists():
        shutil.copytree(ROOT, base, ignore=shutil.ignore_patterns("github"))
        roles = yaml.safe_load((base / "catalog/roles.yaml").read_text())
        roles["roles"]["hr-lead"]["email"] = HR.email
        roles["roles"]["security-lead"]["email"] = ADMIN.email
        roles["roles"]["system-owners"]["email"] = [HR.email, "it@example.com"]
        (base / "catalog/roles.yaml").write_text(yaml.safe_dump(roles))
    store = TenantStore(base_store or SqliteStore(), tenant)
    portal = Portal(Catalog.load(base), store, EvidenceStore(tmp_path / "evidence", namespace=tenant),
                    mailer=mailer.ConsoleMailer("grc@example.com", sync=True), today=TODAY,
                    public_url="https://grc.example.com")
    for u in people:
        portal._create_user(u.email, u.name, u.role, "test", "test")
    if ADMIN in people:  # ADMIN is the control library owner in tests; ADMIN2 is an ordinary admin
        store.update("users", "u", ADMIN.email, {"library_owner": True})
    return portal


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    for var in ("GRCPAL_ENV", "GRCPAL_TENANT", "GRCPAL_BOOTSTRAP_ADMINS", "GRCPAL_EVIDENCE_ACCOUNT_URL",
                "GRCPAL_ALLOWED_TENANT_IDS", "GRCPAL_PUBLIC_URL", "GRCPAL_DEV_PRINCIPAL"):
        monkeypatch.delenv(var, raising=False)
    portal = make_portal(tmp_path)
    client = TestClient(create_app(portal), base_url="https://grc.example.com")
    return portal, client


def as_(client, who):
    client.cookies.clear()
    client.headers["X-Dev-Principal"] = json.dumps({"email": who.email, "name": who.name})
    return client


def csrf(client, path="/policies"):
    m = re.search(r'name="csrf-token" content="([^"]+)"', client.get(path).text)
    assert m, f"no csrf token on {path}"
    return m.group(1)


def outbox(portal, to=None):
    return [m for m in portal.mailer.outbox if to is None or m.to == to]


def assign(portal, control="HR-01", who=CONTRIB, due="2026-10-30", note="Q3 evidence"):
    return portal.create_assignment(ADMIN, "control", control, who.email, [], due, note)


# ================================================================ sign-in and identity
def test_sign_in_required(env):
    _, client = env
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/dev/login")
    assert client.get("/healthz").status_code == 200


def test_easyauth_identity_tenant_allow_list(monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "easyauth")
    claims = {"claims": [{"typ": "preferred_username", "val": "Jane@Example.com"}, {"typ": "name", "val": "Jane"},
                         {"typ": "tid", "val": "TENANT-A"}, {"typ": "groups", "val": "G1"}]}
    header = base64.b64encode(json.dumps(claims).encode()).decode()
    ident = auth.identity_from_request({"x-ms-client-principal": header})
    assert ident.email == "jane@example.com" and ident.tenant_id == "tenant-a" and "g1" in ident.groups
    monkeypatch.setenv("GRCPAL_ALLOWED_TENANT_IDS", "tenant-b")
    with pytest.raises(auth.AuthError) as exc:
        auth.identity_from_request({"x-ms-client-principal": header})
    assert exc.value.status == 403
    with pytest.raises(auth.AuthError):
        auth.identity_from_request({"x-dev-principal": json.dumps({"email": "a@b.co"})})  # ignored outside dev
    with pytest.raises(auth.AuthError):
        auth.identity_from_request({})


def test_proxy_mode(monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "proxy")
    assert auth.identity_from_request({"x-forwarded-email": "Bo@Example.com"}).email == "bo@example.com"
    with pytest.raises(auth.AuthError):
        auth.identity_from_request({})


def test_dev_mode_blocked_in_production(monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "production")
    with pytest.raises(RuntimeError):
        auth.auth_mode()


def test_provisioning_rules(env, monkeypatch):
    portal, _ = env
    with pytest.raises(auth.AuthError) as exc:
        portal.resolve(Identity("stranger@example.com", "Stranger"))
    assert exc.value.status == 403
    monkeypatch.setenv("GRCPAL_BOOTSTRAP_ADMINS", "boss@example.com")
    assert portal.resolve(Identity("boss@example.com", "Boss")).role == "admin"
    monkeypatch.setenv("GRCPAL_GROUP_AUDITOR", "grp-audit")
    assert portal.resolve(Identity("ext@firm.example", "Ext", frozenset({"grp-audit"}))).role == "auditor"
    assert portal.resolve(Identity("it@example.com", "IT")).role == "contributor"  # listed in roles.yaml
    portal.set_active(ADMIN, "it@example.com", False)
    with pytest.raises(auth.AuthError):
        portal.resolve(Identity("it@example.com", "IT"))
    sources = {r["detail"]["source"] for r in portal.log.records() if r["action"] == "user.create"}
    assert {"bootstrap", "group", "roles.yaml"} <= sources


def test_dev_login_first_user_becomes_admin(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    portal = make_portal(tmp_path, people=())
    client = TestClient(create_app(portal), base_url="https://grc.example.com")
    page = client.get("/dev/login")
    assert "Create the first admin" in page.text
    token = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = client.post("/dev/login", data={"csrf": token, "email": "Me@Example.com", "next": "/users"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/users"
    assert portal.user_row("me@example.com")["role"] == "admin"
    assert client.get("/users").status_code == 200
    r = client.post("/dev/login", data={"csrf": token, "email": "nobody@example.com"}, follow_redirects=False)
    assert "err=" in r.headers["location"]


# ================================================================ pages and roles
ADMIN_PAGES = ["/", "/controls", "/controls/IAM-04", "/criteria", "/criteria?open=CC6", "/criteria/CC6.1", "/criteria/P5.1",
               "/controls/IAM-02?from=CC6.1", "/controls/IAM-02?from=../../evil", "/work",
               "/reviews", "/evidence", "/overrides", "/audit", "/audit?verify=1&action=user.", "/users", "/cycles",
               "/policies", "/policies/information-security-policy", "/dev/outbox",
               "/controls?status=not_started&category=privacy&sort=owner"]


@pytest.mark.parametrize("path", ADMIN_PAGES)
def test_admin_pages_render(env, path):
    portal, client = env
    a = assign(portal)
    portal.upload(CONTRIB, "x.pdf", PDF, "note", assignment_id=a["RowKey"])
    r = as_(client, ADMIN).get(path)
    assert r.status_code == 200, r.text[:500]
    assert "Content-Security-Policy" in r.headers and r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Request-ID"]
    # the strict CSP blocks inline styles and scripts, so pages must not use them
    assert 'style="' not in r.text and "<script>" not in r.text and "onclick" not in r.text


def test_contributor_sees_only_assigned_or_owned_controls(env):
    portal, client = env
    as_(client, CONTRIB)
    assert client.get("/", follow_redirects=False).headers["location"] == "/work"
    assert "HR-01" not in client.get("/controls").text
    assert client.get("/controls/HR-01").status_code == 404
    for path in ("/criteria", "/evidence", "/audit", "/users", "/cycles", "/reviews", "/overrides", "/users.csv"):
        assert client.get(path).status_code == 403, path
    a = assign(portal)
    page = client.get("/controls")
    assert "HR-01" in page.text and "CHG-01" not in page.text
    assert client.get("/controls/HR-01").status_code == 200
    assert client.get(f"/assignments/{a['RowKey']}").status_code == 200
    other = assign(portal, "CHG-01", HR)
    assert client.get(f"/assignments/{other['RowKey']}").status_code == 404
    # control owners (roles.yaml) see their controls without an assignment
    as_(client, HR)
    assert client.get("/controls/HR-02").status_code == 200
    assert client.get("/controls/IAM-04").status_code == 404


def test_auditor_is_read_only(env):
    portal, client = env
    a = assign(portal)
    u = portal.upload(CONTRIB, "x.pdf", PDF, "", assignment_id=a["RowKey"])
    as_(client, AUDITOR)
    for path in ("/", "/controls/HR-01", f"/assignments/{a['RowKey']}", "/evidence", "/audit", "/overrides", "/cycles"):
        assert client.get(path).status_code == 200, path
    assert client.get("/users").status_code == 403
    token = csrf(client)
    r = client.post("/comments", data={"csrf": token, "body": "hi", "assignment_id": a["RowKey"],
                                       "return_to": "/work"}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    r = client.post(f"/assignments/{a['RowKey']}/upload", data={"csrf": token},
                    files={"file": ("x.pdf", PDF, "application/pdf")}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    r = client.post("/assignments", data={"csrf": token, "target_type": "control", "target_id": "HR-01",
                                          "assignee": CONTRIB.email, "due": "2026-10-30"}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    with pytest.raises(Forbidden):
        portal.review(AUDITOR, u["RowKey"], "approve", "")
    assert client.get(f"/uploads/{u['RowKey']}/download").status_code == 200
    assert any(r["action"] == "evidence.download" for r in portal.log.records())


# ================================================================ evidence workflow with comments and email
def test_full_workflow_with_comments_and_notifications(env):
    portal, client = env
    as_(client, ADMIN)
    token = csrf(client)
    r = client.post("/assignments", data={"csrf": token, "target_type": "control", "target_id": "HR-01",
                                          "assignee": "new.person@example.com", "due": "2026-10-30",
                                          "instructions": "Q3 background checks"}, follow_redirects=False)
    assert r.status_code == 303 and "/assignments/" in r.headers["location"]
    aid = r.headers["location"].split("/assignments/")[1].split("?")[0]
    newbie = User("new.person@example.com", "new.person@example.com", "contributor")
    assert portal.user_row(newbie.email)["role"] == "contributor"  # provisioned by the assignment
    mail = outbox(portal, newbie.email)[0]
    assert f"https://grc.example.com/assignments/{aid}" in mail.text and "Q3 background checks" in mail.text

    as_(client, newbie)
    token = csrf(client, f"/assignments/{aid}")
    bad = client.post(f"/assignments/{aid}/upload", data={"csrf": token},
                      files={"file": ("x.exe", b"MZ", "application/octet-stream")}, follow_redirects=False)
    assert "not+allowed" in bad.headers["location"]
    spoof = client.post(f"/assignments/{aid}/upload", data={"csrf": token},
                        files={"file": ("x.pdf", b"<html>", "application/pdf")}, follow_redirects=False)
    assert "does+not+match" in spoof.headers["location"]
    ok = client.post(f"/assignments/{aid}/upload", data={"csrf": token, "comment": "BGC export"},
                     files={"file": ("../../checks Q3.pdf", PDF, "application/pdf")}, follow_redirects=False)
    assert "uploaded" in ok.headers["location"]
    up = portal.uploads()[0]
    assert up["filename"] == "checks_Q3.pdf" and up["status"] == "pending" and up["cycle"]
    assert portal.assignment(aid)["status"] == "submitted"
    assert any("Evidence submitted" in m.subject for m in outbox(portal, ADMIN.email))

    # comment thread on the upload; participants are emailed, the author is not
    as_(client, ADMIN)
    token = csrf(client, f"/assignments/{aid}")
    r = client.post("/comments", data={"csrf": token, "body": "Does this include contractors?", "upload_id": up["RowKey"],
                                       "return_to": f"/assignments/{aid}"}, follow_redirects=False)
    assert "Comment+posted" in r.headers["location"]
    assert any("include contractors" in m.text for m in outbox(portal, newbie.email))
    portal.add_comment(newbie, "Yes, rows 14-15.", assignment_id=aid)
    assert any("rows 14-15" in m.text for m in outbox(portal, ADMIN.email))
    assert len(portal.comments(assignment=aid)) == 2
    assert "rows 14-15" in client.get(f"/assignments/{aid}").text
    with pytest.raises(Forbidden):
        portal.add_comment(CONTRIB, "not mine", assignment_id=aid)

    with pytest.raises(Forbidden):
        portal.review(newbie, up["RowKey"], "approve", "")
    token = csrf(client, "/reviews")
    r = client.post(f"/uploads/{up['RowKey']}/review", data={"csrf": token, "decision": "approve", "note": "Complete"},
                    follow_redirects=False)
    assert "approved" in r.headers["location"]
    assert portal.assignment(aid)["status"] == "approved"
    assert any("approved" in m.subject for m in outbox(portal, newbie.email))
    assert portal.evidence.list_runs("portal_upload") and portal.evidence.list_runs("portal_review")
    data = report.build(portal.catalog, portal.evidence, TODAY, portal=portal.report_inputs())
    hr01 = next(c for c in data["controls"] if c["id"] == "HR-01")
    assert any(i["via"] == "portal" and i["status"] == "ok" for i in hr01["evidence"])
    queued = [r for r in portal.log.records() if r["action"] == "mail.queued"]
    assert {r["target"] for r in queued} >= {"assigned", "uploaded", "commented", "reviewed"}


def test_owner_direct_upload_on_control(env):
    portal, client = env
    as_(client, HR)
    token = csrf(client, "/controls/HR-02")
    r = client.post("/controls/HR-02/upload", data={"csrf": token, "comment": "LMS export"},
                    files={"file": ("training.csv", b"name,done\npat,yes\n", "text/csv")}, follow_redirects=False)
    assert "uploaded" in r.headers["location"]
    u = portal.uploads(control="HR-02")[0]
    assert u["assignment"] == "" and u["controls"] == ["HR-02"]
    with pytest.raises(Forbidden):
        portal.upload(CONTRIB, "x.pdf", PDF, "", control_id="HR-02")
    portal.review(ADMIN, u["RowKey"], "return", "Add the completion dates column")
    assert portal.upload_row(u["RowKey"])["status"] == "returned"


def test_segregation_of_duties(env):
    portal, _ = env
    u = portal.upload(ADMIN, "x.pdf", PDF, "", control_id="IAM-04")
    with pytest.raises(Forbidden):
        portal.review(ADMIN, u["RowKey"], "approve", "")
    assert u["RowKey"] not in {x["RowKey"] for x in portal.reviewable(ADMIN)}
    portal.review(ADMIN2, u["RowKey"], "approve", "ok")


def test_assignment_validation(env):
    portal, _ = env
    with pytest.raises(Forbidden):
        portal.create_assignment(HR, "control", "HR-01", CONTRIB.email, [], "2026-10-30", "")
    with pytest.raises(Invalid):
        portal.create_assignment(ADMIN, "control", "HR-01", "not-an-email", [], "2026-10-30", "")
    with pytest.raises(Invalid):
        portal.create_assignment(ADMIN, "control", "HR-01", CONTRIB.email, [], "2026-01-01", "")
    with pytest.raises(Invalid):
        portal.create_assignment(ADMIN, "control", "HR-01", AUDITOR.email, [], "2026-10-30", "")
    a = portal.create_assignment(ADMIN, "point", "P5.1-PF01", CONTRIB.email, [], "2026-11-01", "ID verification")
    assert a["controls"] == ["PRV-04"]


def test_return_requires_note(env):
    portal, _ = env
    a = assign(portal, "BCP-03")
    up = portal.upload(CONTRIB, "restore.txt", b"restore ok 42 minutes", "", assignment_id=a["RowKey"])
    with pytest.raises(Invalid):
        portal.review(ADMIN, up["RowKey"], "return", "no")
    portal.review(ADMIN, up["RowKey"], "return", "Add the RPO measurement")
    assert portal.assignment(a["RowKey"])["status"] == "returned"


# ================================================================ reminders
def test_reminder_button_email_content_and_rate_limit(env):
    portal, client = env
    a = assign(portal, note="Upload the Q3 hire list with check dates")
    portal.upload(CONTRIB, "q3.pdf", PDF, "", assignment_id=a["RowKey"])
    as_(client, ADMIN)
    token = csrf(client, "/controls/HR-01")
    r = client.post("/controls/HR-01/remind", data={"csrf": token, "note": "Auditor needs this Friday"},
                    follow_redirects=False)
    assert "Reminder+sent+to+pat%40example.com" in r.headers["location"]
    mail = [m for m in outbox(portal, CONTRIB.email) if m.kind == "reminder"][0]
    ctl = portal.catalog.control("HR-01")
    for expected in ("https://grc.example.com/controls/HR-01", ctl["description"], "Evidence we are looking for",
                     "Upload the Q3 hire list", "q3.pdf", "Auditor needs this Friday", "Submitted this cycle"):
        assert expected in mail.text, expected
    assert "https://grc.example.com/controls/HR-01" in mail.html and "<script" not in mail.html
    again = portal.remind(ADMIN, "HR-01")
    assert again == {"sent": [], "skipped": [CONTRIB.email]}
    # no open request: the owner from roles.yaml is reminded
    r = portal.remind(ADMIN, "HR-03")
    assert r["sent"] == [HR.email]
    with pytest.raises(Forbidden):
        portal.remind(CONTRIB, "HR-01")
    with pytest.raises(Invalid):
        portal.remind(ADMIN, "CHG-01")  # engineering-lead has no email yet
    assert any(r["action"] == "reminder.send" for r in portal.log.records())


def test_remind_overdue(env):
    portal, _ = env
    a = assign(portal, due="2026-10-13")
    portal._today = dt.date(2026, 10, 20)
    sent = portal.remind_overdue(SYSTEM)
    assert sent and sent[0]["assignment"] == a["RowKey"] and sent[0]["sent"] == [CONTRIB.email]


# ================================================================ cycles
def test_cycle_carry_forward_and_last_cycle_evidence(env):
    portal, client = env
    first = portal.active_cycle()
    a = assign(portal, note="Hire list with check dates")
    u = portal.upload(CONTRIB, "fy26-checks.pdf", PDF, "FY26 list", assignment_id=a["RowKey"])
    portal.review(ADMIN, u["RowKey"], "approve", "ok")
    assign(portal, "HR-02")
    cancelled = assign(portal, "HR-03")
    portal.cancel_assignment(ADMIN, cancelled["RowKey"], "not needed")
    with pytest.raises(Forbidden):
        portal.start_cycle(CONTRIB, "FY2027", "2026-10-12", "2027-10-11")
    new = portal.start_cycle(ADMIN, "FY2027", "2026-10-12", "2027-10-11", carry_forward=True)
    assert portal.active_cycle()["RowKey"] == new["RowKey"] == "fy2027"
    assert portal.cycle(first["RowKey"])["status"] == "closed"
    work = portal.assignments()
    assert sorted(x["controls"][0] for x in work) == ["HR-01", "HR-02"]
    carried = next(x for x in work if x["controls"] == ["HR-01"])
    assert carried["previous"] == a["RowKey"] and carried["status"] == "open" and carried["assignee"] == CONTRIB.email
    with pytest.raises(Invalid):
        portal.upload(CONTRIB, "late.pdf", PDF, "", assignment_id=a["RowKey"])  # closed cycle is read-only
    as_(client, CONTRIB)
    page = client.get("/controls/HR-01").text
    assert "Last cycle" in page and "fy26-checks.pdf" in page
    page = client.get(f"/assignments/{carried['RowKey']}").text
    assert "fy26-checks.pdf" in page and "Hire list with check dates" in page
    portal.remind(ADMIN, "HR-01")
    mail = [m for m in outbox(portal, CONTRIB.email) if m.kind == "reminder"][-1]
    assert "Last cycle" in mail.text and "fy26-checks.pdf" in mail.text
    with pytest.raises(Invalid):
        portal.start_cycle(ADMIN, "FY2027", "2027-10-12", "2028-10-11")


# ================================================================ overrides
def test_override_lifecycle_and_cycle_scope(env):
    portal, client = env
    with pytest.raises(Forbidden):
        portal.create_override(HR, "IAM-04", "x" * 40, "2026-12-31", "")
    with pytest.raises(Invalid):
        portal.create_override(ADMIN, "IAM-04", "too short", "2026-12-31", "")
    with pytest.raises(Invalid):
        portal.create_override(ADMIN, "IAM-04", "x" * 40, "2028-01-01", "")
    as_(client, ADMIN)
    token = csrf(client, "/overrides")
    just = "HR system emails termination before payroll; account disabled same day per ticket export"
    r = client.post("/overrides", data={"csrf": token, "control": "IAM-04", "justification": just,
                                        "expires": "2027-01-31", "evidence_ref": "ticket IT-1"}, follow_redirects=False)
    assert "Override+recorded" in r.headers["location"]
    data = report.build(portal.catalog, portal.evidence, TODAY, portal=portal.report_inputs())
    iam04 = next(c for c in data["controls"] if c["id"] == "IAM-04")
    assert iam04["status"] == "accepted" and iam04["computed_status"] != "accepted"
    portal.start_cycle(ADMIN, "Next", "2026-10-12", "2027-10-11")
    assert portal.active_overrides() == {}  # must be re-justified each cycle
    oid = portal.overrides()[0]["RowKey"]
    portal.revoke_override(ADMIN, oid, "Fixed upstream")
    actions = [r["action"] for r in portal.log.records()]
    assert "override.create" in actions and "override.revoke" in actions


# ================================================================ tenant isolation
def test_tenant_isolation_store_and_evidence(tmp_path, monkeypatch):
    monkeypatch.delenv("GRCPAL_TENANT", raising=False)
    shared = SqliteStore()
    acme = make_portal(tmp_path, "acme", shared)
    globex = make_portal(tmp_path, "globex", shared, people=(User("boss@globex.example", "Boss", "admin"),))
    a = assign(acme)
    acme.upload(CONTRIB, "secret.pdf", PDF, "", assignment_id=a["RowKey"])
    assert globex.assignments(cycle=None) == [] and globex.uploads(cycle=None) == []
    assert globex.user_row(ADMIN.email) is None and [u["RowKey"] for u in globex.users()] == ["boss@globex.example"]
    assert all(r["actor"] != CONTRIB.email for r in globex.log.records())
    with pytest.raises(Invalid):
        globex.assignment(a["RowKey"])
    assert globex.log.verify()["ok"] and acme.log.verify()["ok"]
    # evidence namespaces: the same run path resolves to different, non-overlapping storage
    run = acme.uploads()[0]["evidence_run"]
    source, run_id = run.split("/")
    assert acme.evidence.read(source, run_id, "secret.pdf") == PDF
    assert globex.evidence.read(source, run_id, "secret.pdf") is None
    assert (tmp_path / "evidence" / "acme" / source).is_dir()
    assert acme.evidence.read("..", "acme", "x") is None
    # the guard refuses rows from another tenant even if a backend returned them
    leaky = TenantStore(shared, "globex")
    shared_row = shared.list_prefix("assignments", "acme|")[0]
    with pytest.raises(PermissionError):
        leaky._out(shared_row)
    for bad in ("", "Acme", "a|b", "../x", "x" * 41):
        with pytest.raises(ValueError):
            TenantStore(shared, bad)
    with pytest.raises(ValueError):
        EvidenceStore(tmp_path, namespace="../x")


# ================================================================ audit log integrity and tracing
def test_audit_chain_detects_tampering(env, tmp_path):
    from grcpal import collectors

    portal, _ = env
    a = assign(portal)
    portal.upload(CONTRIB, "x.pdf", PDF, "", assignment_id=a["RowKey"])
    result = portal.log.verify()
    assert result["ok"] and result["records"] >= 6
    seqs = [r["seq"] for r in portal.log.records()]
    assert seqs == list(range(1, len(seqs) + 1))
    victim = portal.log.records()[2]
    portal.store.update("audit", victim["PartitionKey"], victim["RowKey"], {"actor": "someone-else@example.com"})
    bad = portal.log.verify()
    assert not bad["ok"] and any("edited" in p for p in bad["problems"])
    ctx = collectors.Context(clients=None, catalog=portal.catalog, today=TODAY)
    ctx.portal_store = portal.store
    run = EvidenceStore(tmp_path / "ev2").new_run("portal_audit", [], {})
    findings = collectors.get("portal_audit").run(ctx, run)
    assert {"audit_log.json", "audit_chain_verification.json", "users.json", "comments.json"} <= {f["name"] for f in run.files}
    assert any(f["key"] == "audit-chain" and f["severity"] == "high" for f in findings)


def test_audit_chain_detects_truncation(env):
    portal, _ = env
    assign(portal)
    last = portal.log.records()[-1]
    portal.store._base._db.execute("DELETE FROM entities WHERE tbl='audit' AND rk=?", (last["RowKey"],))
    assert any("head pointer" in p for p in portal.log.verify()["problems"])


def test_request_id_traced_into_audit(env):
    portal, client = env
    as_(client, ADMIN)
    token = csrf(client)
    r = client.post("/users", data={"csrf": token, "email": "x@example.com", "role": "auditor"},
                    headers={"X-Request-ID": "trace-abc-123"}, follow_redirects=False)
    assert r.headers["X-Request-ID"] == "trace-abc-123"
    rec = next(r for r in portal.log.records() if r["action"] == "user.create" and r["target"] == "x@example.com")
    assert rec["request_id"] == "trace-abc-123"
    r = client.get("/controls/NOPE-1")
    assert r.status_code == 404 and r.headers["X-Request-ID"] in r.text
    assert client.get("/", headers={"X-Request-ID": "bad id with spaces"}).headers["X-Request-ID"] != "bad id with spaces"


# ================================================================ users
def test_user_admin_and_last_admin_guard(env):
    portal, client = env
    as_(client, ADMIN)
    token = csrf(client, "/users")
    r = client.post("/users", data={"csrf": token, "email": "New@Example.com", "name": "New", "role": "auditor"},
                    follow_redirects=False)
    assert "added" in r.headers["location"] and portal.user_row("new@example.com")["role"] == "auditor"
    r = client.post("/users/new%40example.com/role", data={"csrf": token, "role": "contributor"}, follow_redirects=False)
    assert portal.user_row("new@example.com")["role"] == "contributor"
    portal.set_active(ADMIN, ADMIN2.email, False)
    with pytest.raises(Invalid):
        portal.set_role(ADMIN, ADMIN.email, "auditor")
    with pytest.raises(Invalid):
        portal.set_active(ADMIN, ADMIN.email, False)
    with pytest.raises(Forbidden):
        portal.add_user(CONTRIB, "z@example.com", "", "admin")
    client.post(f"/users/{CONTRIB.email}/active", data={"csrf": token, "active": "0"})
    assert client.get("/users.csv").text.count("\n") == len(portal.users()) + 1
    assert as_(client, CONTRIB).get("/work").status_code == 403


# ================================================================ policies
def test_policy_acknowledgment(env):
    portal, client = env
    pol = portal.catalog.policy("acceptable-use")
    assert pol and pol["version"] == "1.0" and len(pol["sha256"]) == 64
    as_(client, CONTRIB)
    token = csrf(client, "/policies/acceptable-use")
    r = client.post("/policies/acceptable-use/ack", data={"csrf": token}, follow_redirects=False)
    assert "recorded" in r.headers["location"]
    portal.acknowledge(CONTRIB, "acceptable-use")  # idempotent
    st = portal.policy_status(pol)
    assert st["acked"] == [CONTRIB.email] and AUDITOR.email not in st["missing"] and ADMIN.email in st["missing"]
    with pytest.raises(Forbidden):
        portal.acknowledge(AUDITOR, "acceptable-use")
    r = portal.remind_policy(ADMIN, "acceptable-use")
    assert CONTRIB.email not in r["sent"] and HR.email in r["sent"]


# ================================================================ export
def test_auditor_export_zip(env):
    portal, client = env
    a = assign(portal)
    u = portal.upload(CONTRIB, "x.pdf", PDF, "", assignment_id=a["RowKey"])
    portal.add_comment(ADMIN, "looks good", upload_id=u["RowKey"])
    portal.review(ADMIN, u["RowKey"], "approve", "ok")
    as_(client, AUDITOR)
    r = client.get(f"/cycles/{portal.active_cycle()['RowKey']}/export")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    assert {"MANIFEST.csv", "uploads_and_reviews.csv", "comments.csv", "audit_log.csv", "users.csv",
            "audit_chain_verification.json", "control_status.json", "README.txt"} <= names
    evidence = [n for n in names if n.startswith("evidence/")]
    assert evidence and z.read(evidence[0]) == PDF
    rows = list(csv.DictReader(io.StringIO(z.read("uploads_and_reviews.csv").decode())))
    assert rows[0]["status"] == "approved" and rows[0]["reviewed_by"] == ADMIN.email
    import hashlib
    manifest = {row["file"]: row["sha256"] for row in csv.DictReader(io.StringIO(z.read("MANIFEST.csv").decode()))}
    assert manifest[evidence[0]] == hashlib.sha256(PDF).hexdigest()
    assert as_(client, CONTRIB).get(f"/cycles/{portal.active_cycle()['RowKey']}/export").status_code == 403


# ================================================================ email backends
def test_mailer_from_env(monkeypatch):
    monkeypatch.setenv("GRCPAL_MAIL_BACKEND", "smtp")
    monkeypatch.delenv("GRCPAL_SMTP_HOST", raising=False)
    with pytest.raises(RuntimeError):
        mailer.from_env()
    monkeypatch.setenv("GRCPAL_MAIL_BACKEND", "graph")
    monkeypatch.setenv("GRCPAL_MAIL_FROM", "nope")
    with pytest.raises(RuntimeError):
        mailer.from_env()
    monkeypatch.setenv("GRCPAL_MAIL_FROM", "grc@example.com")
    assert isinstance(mailer.from_env(), mailer.GraphMailer)
    monkeypatch.setenv("GRCPAL_MAIL_BACKEND", "carrier-pigeon")
    with pytest.raises(RuntimeError):
        mailer.from_env()


def test_smtp_delivery(monkeypatch):
    calls = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            calls.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context):
            calls.append(("starttls",))

        def login(self, user, password):
            calls.append(("login", user))

        def send_message(self, msg):
            calls.append(("send", msg["To"], msg["Subject"], msg.get_content_type()))

    monkeypatch.setattr(mailer.smtplib, "SMTP", FakeSMTP)
    m = mailer.SmtpMailer("grc@example.com", "smtp.example.com", 587, "user", "pw", sync=True)
    m.send(mailer.Message(to="a@example.com", subject="Hello\r\nBcc: evil@example.com", text="t", html="<p>t</p>"))
    assert calls[0] == ("connect", "smtp.example.com", 587) and ("starttls",) in calls and ("login", "user") in calls
    send = [c for c in calls if c[0] == "send"][0]
    assert send[1] == "a@example.com" and "\n" not in send[2] and send[3] == "multipart/alternative"


def test_mail_failure_is_audited(env):
    portal, _ = env

    class Broken(mailer.Mailer):
        name = "broken"

        def deliver(self, msg):
            raise ConnectionError("smtp down")

    portal.mailer = Broken("grc@example.com", sync=True)
    portal.mailer.on_result = portal._mail_result
    assign(portal)
    fail = [r for r in portal.log.records() if r["action"] == "mail.failed"]
    assert fail and "smtp down" in fail[0]["detail"]["error"]


# ================================================================ CSRF and origin
def test_csrf_and_origin_enforced(env):
    _, client = env
    as_(client, ADMIN)
    form = {"target_type": "control", "target_id": "HR-01", "assignee": CONTRIB.email, "due": "2026-10-30"}
    assert client.post("/assignments", data=form).status_code == 403
    token = csrf(client)
    r = client.post("/assignments", data={**form, "csrf": token}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    r = client.post("/assignments", data={**form, "csrf": token, "return_to": "//evil.example"},
                    headers={"Origin": "https://grc.example.com"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/assignments/")
    as_(client, CONTRIB)
    r = client.post("/comments", data={"csrf": token, "body": "x", "control_id": "HR-01"})  # token bound to another user
    assert r.status_code == 403


# ================================================================ evidence browsing safety
def test_evidence_download_safe(env):
    portal, client = env
    a = assign(portal, "HR-02")
    up = portal.upload(CONTRIB, "training.csv", b"name,done\npat,yes\n", "", assignment_id=a["RowKey"])
    source, run = up["evidence_run"].split("/")
    as_(client, AUDITOR)
    r = client.get(f"/evidence/{source}/{run}/training.csv")
    assert r.status_code == 200 and r.headers["content-disposition"].startswith("attachment")
    assert client.get(f"/evidence/{source}/{run}/..%2F..%2Fsecret").status_code == 404
    assert client.get(f"/evidence/{source}/not-a-run/manifest.json").status_code == 404
    assert client.get(f"/evidence/unknown/{run}/manifest.json").status_code == 404
    as_(client, HR)  # owner of HR-02 may download its uploads but not browse the raw store
    assert client.get(f"/uploads/{up['RowKey']}/download").status_code == 200
    assert client.get(f"/evidence/{source}/{run}/training.csv").status_code == 403
    as_(client, User("other@example.com", "Other", "contributor"))
    portal._create_user("other@example.com", "Other", "contributor", "test", "test")
    assert client.get(f"/uploads/{up['RowKey']}/download").status_code == 404


# ================================================================ recurring tasks, demo, CLI
def test_open_due_tasks_idempotent(env):
    portal, _ = env
    first = portal.open_due_tasks(SYSTEM)
    assert "hr-quarterly-attestation" in {a["task"] for a in first}
    assert all(a["assignee"] for a in first)
    assert portal.open_due_tasks(SYSTEM) == []


def test_demo_seed_renders_for_every_role(tmp_path, monkeypatch):
    from grcpal.portal import demo

    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    portal = make_portal(tmp_path, people=())
    assert demo.seed(portal) and not demo.seed(portal)
    assert len(portal.cycles()) == 2 and portal.previous_cycle()
    assert portal.log.verify()["ok"]
    client = TestClient(create_app(portal), base_url="https://grc.example.com")
    for who in demo.PEOPLE:
        as_(client, who)
        for path in ("/", "/work", "/controls", "/controls/HR-01", "/policies"):
            r = client.get(path)
            assert r.status_code in (200, 403, 404), (who.email, path, r.status_code)
        if who.role != "auditor":
            assert client.get("/controls/HR-01").status_code in (200, 404)
    as_(client, demo.HR)
    page = client.get("/controls/HR-01").text
    assert "Last cycle" in page and "contractors" in page


def test_cli_init_users_audit(tmp_path, monkeypatch, capsys):
    target = tmp_path / "acme-grc"
    assert cli.main(["init", str(target), "--org", "Acme Inc"]) == 0
    assert (target / ".github/workflows/collect-daily.yml").exists() and (target / "catalog/controls.yaml").exists()
    assert "organization: Acme Inc" in (target / "catalog/scope.yaml").read_text()
    assert cli.main(["--base", str(target), "validate"]) == 0
    assert cli.main(["init", str(target)]) == 1
    monkeypatch.setenv("GRCPAL_SQLITE", str(tmp_path / "portal.db"))
    monkeypatch.setenv("GRCPAL_TENANT", "acme")
    monkeypatch.setenv("GRCPAL_MAIL_BACKEND", "console")
    assert cli.main(["--base", str(target), "users", "add", "Me@Acme.example", "--role", "admin"]) == 0
    assert cli.main(["--base", str(target), "users", "list"]) == 0
    assert "me@acme.example" in capsys.readouterr().out
    assert cli.main(["--base", str(target), "audit", "verify"]) == 0
    assert cli.main(["--base", str(target), "remind", "--overdue", "--dry-run"]) == 0
    out = tmp_path / "x.zip"
    assert cli.main(["--base", str(target), "--evidence", str(tmp_path / "ev"), "export", "--out", str(out)]) == 0
    assert zipfile.ZipFile(out).testzip() is None


def test_config_bundle_extract_is_safe(tmp_path):
    import tarfile

    from grcpal import configbundle

    bundle = configbundle.build(ROOT)
    out = configbundle.extract(bundle, tmp_path / "cfg")
    assert (out / "catalog/controls.yaml").exists() and (out / "policies/acceptable-use.md").exists()
    assert Catalog.load(out).control("HR-01")
    evil = io.BytesIO()
    with tarfile.open(fileobj=evil, mode="w:gz") as tar:
        for name, data in (("../escape.txt", b"x"), ("catalog/../../escape2.txt", b"x"), ("other/x.txt", b"x"),
                           ("/abs.txt", b"x"), ("catalog/ok.yaml", b"a: 1\n")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("catalog/link")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        tar.addfile(link)
    dest = configbundle.extract(evil.getvalue(), tmp_path / "evil")
    files = sorted(str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_file())
    assert files == ["catalog/ok.yaml"]
    assert not (tmp_path / "escape.txt").exists() and not (tmp_path / "escape2.txt").exists()


def test_publish_config_bundle_to_file(tmp_path, monkeypatch):
    target = tmp_path / "prog"
    cli.main(["init", str(target)])
    out = tmp_path / "bundle.tar.gz"
    assert cli.main(["--base", str(target), "publish-config", "--out", str(out)]) == 0
    assert out.stat().st_size > 1000


def test_starter_and_repo_yaml_is_valid():
    import glob

    repo = ROOT.parents[1]
    files = glob.glob(str(ROOT / "github/**/*.yml"), recursive=True) + glob.glob(str(repo / ".github/**/*.yml"), recursive=True)
    assert files
    for f in files:
        data = yaml.safe_load(Path(f).read_text())
        for item in (data.get("body") or []) if "ISSUE_TEMPLATE" in f and isinstance(data, dict) else []:
            assert all(v is not None for v in item.get("attributes", {}).values()), f


# ================================================================ SOC 2 view: families, criterion order, evidence sources
def test_soc2_families_order_and_evidence_labels(env):
    from grcpal.portal import soc2

    portal, _ = env
    cat = portal.catalog
    assert [soc2.family_of(x) for x in ("CC6.1", "A1.2", "C1.1", "PI1.3", "P4.2", "P8.1")] == ["CC6", "A1", "C1", "PI1", "P", "P"]
    order = soc2.ordered_criteria(cat)
    assert order[0] == "CC1.1" and order.index("CC6.1") == order.index("CC5.3") + 1
    assert soc2.neighbours(order, "CC1.1")[0] is None and soc2.neighbours(order, "nope") == (None, None, 0)
    fams = {f["id"]: f for f in soc2.families(cat, {})}
    assert fams["CC6"]["name"] == "Logical and physical access" and fams["CC6"]["counts"]["not_started"] == fams["CC6"]["total"]
    assert [c["id"] for c in fams["CC6"]["criteria"]][:2] == ["CC6.1", "CC6.2"]
    # sources that are switched off for this client are not shown as how the control is evidenced
    iam02 = cat.control("IAM-02")
    how = soc2.evidenced_by(iam02, {"aws_iam"})
    assert how["label"] == "Automatic" and how["sources"] == ["Entra ID"] and how["hidden"] == ["AWS"]
    only_aws = {**iam02, "evidence": [{"artifact": "x", "via": "collector:aws_iam"}]}
    assert soc2.evidenced_by(only_aws, {"aws_iam"})["type"] == "manual"   # nothing automatic is connected
    assert soc2.worst(["ok", "findings", "not_started"]) == "findings" and soc2.worst([]) == "not_started"


def test_soc2_overview_and_criterion_pages(env):
    portal, client = env
    as_(client, ADMIN)
    page = client.get("/criteria?open=CC6").text
    assert "SOC 2 Trust Services Criteria" in page and "Logical and physical access" in page
    assert '<details class="fam" open id="CC6">' in page and 'href="/criteria/CC6.1"' in page
    crit = client.get("/criteria/CC6.1").text
    assert 'href="/criteria/CC5.3"' in crit and 'href="/criteria/CC6.2"' in crit and "Criterion 18 of" in crit
    assert 'href="/controls/IAM-02?from=CC6.1"' in crit and "How it is evidenced" in crit
    assert client.get("/frameworks/soc2", follow_redirects=False).headers["location"] == "/criteria"
    # categories outside the report scope are shown as not in scope
    portal.base_catalog.scope["in_scope_categories"] = ["security", "availability"]
    page = client.get("/criteria").text
    assert "Not in scope" in page and "In scope: Security, Availability ·" in page
    as_(client, AUDITOR)
    assert client.get("/criteria/CC6.1").status_code == 200


def test_control_page_remembers_where_you_came_from(env):
    portal, client = env
    as_(client, ADMIN)
    client.get("/view?f=soc2&next=/")
    page = client.get("/controls/IAM-02?from=CC6.1").text
    assert 'href="/criteria/CC6.1">← Back to CC6.1' in page and 'href="/criteria">All SOC 2 criteria' in page
    siblings = portal.catalog.coverage()["CC6.1"]
    i = siblings.index("IAM-02")
    assert f'href="/controls/{siblings[i - 1]}?from=CC6.1"' in page and f'href="/controls/{siblings[i + 1]}?from=CC6.1"' in page
    assert f"Control {i + 1} of {len(siblings)} in CC6.1" in page and "you came from here" in page
    # the left menu stays on the SOC 2 criteria, not Controls
    assert re.search(r'<a href="/criteria" class="active">', page) and not re.search(r'<a href="/controls" class="active">', page)
    # only a known criterion id is accepted; anything else is ignored, never turned into a link
    for bad in ("https://evil.example", "//evil.example", "../../criteria/CC6.1", "CC6.1<script>"):
        r = client.get("/controls/IAM-02", params={"from": bad}).text
        assert "Back to" not in r and "evil.example" not in r
    # from the list: the back link keeps the filters, and only known filter keys survive
    page = client.get("/controls/IAM-05", params={"list": "family=CC6&criterion=CC6.3&next=https://evil.example&q=rev"}).text
    assert 'href="/controls?family=CC6&amp;criterion=CC6.3&amp;q=rev">← Back to controls list' in page
    assert "evil.example" not in page
    # control owners do not get the criteria trail (criteria pages are for admins and auditors)
    as_(client, HR)
    page = client.get("/controls/HR-02?from=CC1.4").text
    assert "Back to CC1.4" not in page and 'href="/criteria"' not in page


def test_controls_list_soc2_filters(env):
    portal, client = env
    as_(client, ADMIN)
    page = client.get("/controls?family=CC6&criterion=CC6.3").text
    expected = portal.catalog.coverage()["CC6.3"]
    assert f"{len(expected)} controls shown" in page and all(f">{c}</b>" in page for c in expected)
    assert '<span class="hit">CC6.3</span>' in page
    assert 'href="/controls/IAM-05?list=family%3DCC6%26criterion%3DCC6.3' in page
    # a criterion outside the chosen family is ignored rather than returning an empty list
    assert "filtered to CC6" in client.get("/controls?family=CC6&criterion=CC1.1").text
    auto = client.get("/controls?evidenced=manual").text
    assert "IAM-02</b>" not in auto


def test_admin_edits_request_people_due_date_and_access_follows(env):
    portal, client = env
    a = assign(portal, "HR-01", CONTRIB)
    u = portal.upload(CONTRIB, "x.pdf", PDF, "first upload", assignment_id=a["RowKey"])
    portal.mailer.outbox.clear()
    with pytest.raises(Forbidden):
        portal.edit_assignment(CONTRIB, a["RowKey"], CONTRIB.email, [], a["due"], "")
    row = portal.edit_assignment(ADMIN, a["RowKey"], HR.email, [CONTRIB.email, "new.helper@example.com"],
                                 "2026-11-15", a["instructions"])
    assert row["assignee"] == HR.email and row["contributors"] == sorted([CONTRIB.email, "new.helper@example.com"])
    assert row["due"] == "2026-11-15"
    # only people who were not on the request before are emailed
    emailed = {m.to for m in portal.mailer.outbox}
    assert emailed == {HR.email, "new.helper@example.com"}
    entry = [e for e in portal.log.records() if e["action"] == "assignment.edit"][-1]
    assert entry["detail"]["assignee"] == {"from": CONTRIB.email, "to": HR.email}
    # the earlier upload keeps its original uploader
    assert portal.uploads(assignment=a["RowKey"], cycle=None)[0]["uploaded_by"] == CONTRIB.email == u["uploaded_by"]
    # someone removed from the request loses access to it
    portal.edit_assignment(ADMIN, a["RowKey"], HR.email, [], "2026-11-15", a["instructions"])
    as_(client, CONTRIB)
    assert client.get(f"/assignments/{a['RowKey']}").status_code == 404
    # closed requests cannot be changed; past due dates are refused
    with pytest.raises(Invalid):
        portal.edit_assignment(ADMIN, a["RowKey"], HR.email, [], "2020-01-01", "")
    portal.cancel_assignment(ADMIN, a["RowKey"], "not needed")
    with pytest.raises(Invalid):
        portal.edit_assignment(ADMIN, a["RowKey"], HR.email, [], "2026-11-20", "")


def test_control_library_owner_is_one_admin_handed_over_and_cleared(env):
    portal, client = env
    assert portal.library_owner() == ADMIN.email
    assert portal.is_library_owner(ADMIN) and not portal.is_library_owner(ADMIN2)
    # only the holder hands it over; other admins and non-admins cannot take it
    with pytest.raises(Forbidden):
        portal.set_library_owner(ADMIN2, ADMIN2.email)
    with pytest.raises(Forbidden):
        portal.set_library_owner(CONTRIB, CONTRIB.email)
    with pytest.raises(Invalid):
        portal.set_library_owner(ADMIN, AUDITOR.email)   # must be an active admin
    portal.set_library_owner(ADMIN, ADMIN2.email)
    assert portal.library_owner() == ADMIN2.email and not portal.is_library_owner(ADMIN)
    assert [u for u in portal.users() if u.get("library_owner")] == [portal.user_row(ADMIN2.email)]
    e = [x for x in portal.log.records() if x["action"] == "library_owner.set"][-1]
    assert e["detail"] == {"from": ADMIN.email, "to": ADMIN2.email}
    # losing admin rights clears it at once; then any admin can assign it
    portal.set_role(ADMIN, ADMIN2.email, "contributor")
    assert portal.library_owner() == ""
    assert any(x["action"] == "library_owner.cleared" for x in portal.log.records())
    portal.set_library_owner(ADMIN, ADMIN.email)
    assert portal.library_owner() == ADMIN.email
    # only the holder can create or change custom controls
    with pytest.raises(Forbidden):
        portal.save_custom_control(ADMIN2, {"id": "CUS-50", "title": "Should fail", "map_soc2": "CC1.1"})
    # Users page shows the holder
    as_(client, ADMIN)
    assert "Control library owner" in client.get("/users").text

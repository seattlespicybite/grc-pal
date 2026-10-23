"""Access review sources (step A): Entra ID / Microsoft 365 users, Entra enterprise apps, Azure role assignments, GitHub,
custom REST applications and GRC-pal itself, with managers from Entra direct reports, identity maps, application owners
as fallback reviewers, encrypted per-application tokens, SSRF and token-leak guards, nothing created on a partial pull,
tenant separation and the pages. All platform calls use canned responses."""
import csv
import hashlib
import io
import json

import pytest
from fastapi.testclient import TestClient

from grcpal import accesssources as src
from grcpal.checks import Response
from grcpal.clients import ApiError, Clients
from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid
from grcpal.portal.store import TABLES, SqliteStore
from test_portal import ADMIN, ADMIN2, AUDITOR, CONTRIB, HR, as_, csrf, make_portal  # TODAY = 2026-10-12

GA = "62e90394-69f5-4237-9190-012177145e10"
USERS = [
    {"id": "u-hr", "displayName": "Harper", "userPrincipalName": HR.email, "mail": HR.email, "accountEnabled": True,
     "userType": "Member", "assignedLicenses": [{"skuId": "x"}]},
    {"id": "u-pat", "displayName": "Pat", "userPrincipalName": CONTRIB.email, "mail": CONTRIB.email, "accountEnabled": True,
     "userType": "Member", "assignedLicenses": [{"skuId": "x"}]},
    {"id": "u-alice", "displayName": "Alice", "userPrincipalName": "alice@example.com", "mail": "alice@example.com",
     "accountEnabled": True, "userType": "Member", "assignedLicenses": [{"skuId": "x"}],
     "signInActivity": {"lastSuccessfulSignInDateTime": "2026-10-01T08:00:00Z"}},
    {"id": "u-bob", "displayName": "Bob", "userPrincipalName": "bob@example.com", "mail": "bob@example.com",
     "accountEnabled": False, "userType": "Member", "assignedLicenses": [],
     "signInActivity": {"lastSignInDateTime": "2026-05-01T08:00:00Z"}},
    {"id": "u-guest", "displayName": "Partner", "userPrincipalName": "partner_other.example#EXT#@tenant.onmicrosoft.com",
     "mail": "partner@other.example", "accountEnabled": True, "userType": "Guest", "assignedLicenses": []},
]
REPORTS = {"u-hr": [{"id": "u-alice", "mail": "alice@example.com"}, {"id": "u-bob", "mail": "bob@example.com"}],
           "u-pat": [{"id": "u-carol", "mail": "carol@example.com"}]}


class FakeClients:
    def __init__(self, p1=True, groups=True, owner_token=True, assignment_required=True, gh_pages_cut=False):
        self.p1, self.groups, self.owner_token, self.required, self.cut = p1, groups, owner_token, assignment_required, gh_pages_cut
        self.calls = []

    def graph_list(self, path, params=None, headers=None):
        self.calls.append(path)
        params = params or {}
        if path == "/users":
            if "signInActivity" in params.get("$select", "") and not self.p1:
                raise ApiError(403, path, "needs premium")
            keep = set(params.get("$select", "").split(","))
            return [{k: v for k, v in u.items() if k in keep} for u in USERS]
        if path == "/reports/authenticationMethods/userRegistrationDetails":
            return [{"id": "u-alice", "isMfaRegistered": True}, {"id": "u-bob", "isMfaRegistered": False}]
        if path == "/roleManagement/directory/roleDefinitions":
            return [{"id": GA, "displayName": "Global Administrator"}]
        if path == "/roleManagement/directory/roleAssignments":
            return [{"principalId": "u-alice", "roleDefinitionId": GA}]
        if path.endswith("/directReports"):
            return REPORTS.get(path.split("/")[2], [])
        if path == "/servicePrincipals":
            return [{"id": "sp-1", "displayName": "monday.com", "appRoleAssignmentRequired": self.required,
                     "appRoles": [{"id": "role-admin", "displayName": "Admin"}]}]
        if path == "/servicePrincipals/sp-1/appRoleAssignedTo":
            return [{"principalType": "User", "principalId": "u-alice", "appRoleId": "role-admin"},
                    {"principalType": "Group", "principalId": "g-1", "principalDisplayName": "Sales", "appRoleId": "00000000"},
                    {"principalType": "ServicePrincipal", "principalId": "sp-bot", "principalDisplayName": "Sync bot",
                     "appRoleId": "00000000"}]
        if path.startswith("/groups/"):
            if not self.groups:
                raise ApiError(403, path, "Authorization_RequestDenied")
            return [{"id": "u-alice", "userPrincipalName": "alice@example.com", "mail": "alice@example.com"},
                    {"id": "u-bob", "userPrincipalName": "bob@example.com", "mail": "bob@example.com"}]
        raise AssertionError(f"unexpected Graph call {path}")

    def arg_query(self, query, subscriptions=None):
        if "roledefinitions" in query:
            return [{"id": "/providers/microsoft.authorization/roledefinitions/owner-guid", "roleName": "Owner"},
                    {"id": "/providers/microsoft.authorization/roledefinitions/reader-guid", "roleName": "Reader"}]
        sub = "/subscriptions/0000"
        return [
            {"principalId": "u-alice", "principalType": "User", "roleDefinitionId": f"{sub}/x/owner-guid", "scope": sub},
            {"principalId": "u-alice", "principalType": "User", "roleDefinitionId": f"{sub}/x/reader-guid", "scope": f"{sub}/rg/app"},
            {"principalId": "g-1", "principalType": "Group", "roleDefinitionId": f"{sub}/x/reader-guid", "scope": sub},
            {"principalId": "sp-ci", "principalType": "ServicePrincipal", "roleDefinitionId": f"{sub}/x/owner-guid", "scope": sub},
            {"principalId": "gone-1", "principalType": "Unknown", "roleDefinitionId": f"{sub}/x/reader-guid", "scope": sub}]

    def gh_list(self, path, params=None, max_pages=50, complete=False):
        params = params or {}
        if self.cut and complete:
            raise RuntimeError(f"More than {max_pages} pages from {path}; refusing an incomplete list")
        if path.endswith("/members") and params.get("filter") == "2fa_disabled":
            if not self.owner_token:
                raise ApiError(403, path, "owners only")
            return [{"login": "bob-gh"}]
        if path.endswith("/members") and params.get("role") == "admin":
            return [{"login": "Alice-GH"}]
        if path.endswith("/members"):
            return [{"login": "Alice-GH", "type": "User"}, {"login": "bob-gh", "type": "User"},
                    {"login": "deploy-bot", "type": "Bot"}]
        if path.endswith("/outside_collaborators"):
            return [{"login": "contractor-x", "type": "User"}]
        raise AssertionError(path)


def rows_by_id(rows):
    return {r["account_id"]: r for r in rows}


# ---------------------------------------------------------------- Microsoft
def test_entra_users_roles_licenses_mfa_and_sign_in():
    ms = src.Microsoft(FakeClients())
    rows = rows_by_id(src.entra_users(ms, {}))
    alice = rows["alice@example.com"]
    assert alice["role"] == "Global Administrator, licensed" and alice["mfa"] == "yes" and alice["last_login"] == "2026-10-01"
    bob = rows["bob@example.com"]
    assert bob["status"] == "disabled" and bob["mfa"] == "no" and bob["role"] == "Member, no license"
    guest = rows["partner_other.example#EXT#@tenant.onmicrosoft.com"]
    assert guest["email"] == "partner@other.example" and guest["role"].startswith("Guest")
    assert ms.notes == []


def test_entra_without_premium_still_reads_everyone_and_says_what_is_missing():
    ms = src.Microsoft(FakeClients(p1=False))
    rows = src.entra_users(ms, {})
    assert len(rows) == len(USERS) and all(r["last_login"] == "" for r in rows)
    assert any("AuditLog.Read.All" in n for n in ms.notes)


def test_managers_come_from_direct_reports():
    managers = src.entra_managers(src.Microsoft(FakeClients()))
    assert managers == {"alice@example.com": HR.email, "bob@example.com": HR.email, "carol@example.com": CONTRIB.email}


def test_entra_app_expands_groups_and_refuses_an_unknown_population():
    rows = rows_by_id(src.entra_app(src.Microsoft(FakeClients()), {"app_id": "11111111-2222-3333-4444-555555555555"}))
    assert set(rows) == {"alice@example.com", "bob@example.com", "sp-bot"}       # alice is listed once
    assert rows["alice@example.com"]["role"] == "Admin, Default access (via group Sales)"
    assert rows["sp-bot"]["is_service_account"] == "yes"
    with pytest.raises(src.SourceError, match="Assignment required"):
        src.entra_app(src.Microsoft(FakeClients(assignment_required=False)), {"app_id": "11111111-2222-3333-4444-555555555555"})
    with pytest.raises(src.SourceError, match="GroupMember.Read.All"):
        src.entra_app(src.Microsoft(FakeClients(groups=False)), {"app_id": "11111111-2222-3333-4444-555555555555"})
    with pytest.raises(src.SourceError, match="client"):
        src.entra_app(src.Microsoft(FakeClients()), {"app_id": "not-a-guid' or 1 eq 1"})   # no filter injection


def test_azure_role_assignments_per_identity():
    rows = rows_by_id(src.azure_rbac(src.Microsoft(FakeClients()), {}))
    assert rows["alice@example.com"]["role"] == ("Owner @ /subscriptions/0000; Reader @ /subscriptions/0000 (via group g-1); "
                                                 "Reader @ /subscriptions/0000/rg/app")       # one row, every path
    assert "via group g-1" in rows["bob@example.com"]["role"]
    assert rows["sp-ci"]["is_service_account"] == "yes" and rows["gone-1"]["status"] == "deleted"


# ---------------------------------------------------------------- GitHub
def test_github_owners_members_collaborators_and_two_factor():
    notes = []
    rows = rows_by_id(src.github_org(FakeClients(), {"org": "example-org"}, notes))
    assert rows["Alice-GH"]["role"] == "Owner" and rows["Alice-GH"]["mfa"] == "yes"
    assert rows["bob-gh"]["mfa"] == "no" and rows["contractor-x"]["role"] == "Outside collaborator"
    assert rows["deploy-bot"]["is_service_account"] == "yes" and notes == []
    rows = src.github_org(FakeClients(owner_token=False), {"org": "example-org"}, notes)
    assert all(r["mfa"] == "" for r in rows) and "organization owners" in notes[0]
    with pytest.raises(RuntimeError, match="incomplete"):
        src.github_org(FakeClients(gh_pages_cut=True), {"org": "example-org"}, [])
    with pytest.raises(src.SourceError):
        src.github_org(FakeClients(), {"org": "../../users"}, [])


def test_gh_list_complete_refuses_to_stop_early(monkeypatch):
    class Resp:
        links = {"next": {"url": "https://api.github.com/orgs/x/members?page=2"}}

        def json(self):
            return [{"login": "a"}]
    c = Clients()
    monkeypatch.setattr(c, "_github_headers", lambda: {})
    monkeypatch.setattr(c, "_request", lambda *a, **k: Resp())
    assert len(c.gh_list("/orgs/x/members", max_pages=3)) == 3            # old behaviour unchanged
    with pytest.raises(RuntimeError, match="incomplete"):
        c.gh_list("/orgs/x/members", max_pages=3, complete=True)


# ---------------------------------------------------------------- custom application (REST)
class FakeApi:
    """Canned JSON pages keyed by (method, url, body); records what was sent."""

    def __init__(self, pages, status=200, headers=None):
        self.pages, self.status, self.headers, self.sent = pages, status, headers or {}, []

    def __call__(self, method, url, headers=None, body=None, timeout=15, max_bytes=0, redirects=3):
        self.sent.append({"method": method, "url": url, "headers": dict(headers or {}), "body": body, "redirects": redirects})
        data = self.pages.get((url, body), self.pages.get(url, []))
        hdrs = self.headers.get(url, {}) if isinstance(self.headers.get(url), dict) else {}
        return Response(self.status, hdrs, json.dumps(data).encode(), 5, url, "203.0.113.10")


def monday_body(page):
    return src.PRESETS["monday"]["config"]["body"].replace("{page}", str(page))


def test_monday_preset_pages_until_empty_and_puts_the_token_in_the_named_header():
    cfg = src.PRESETS["monday"]["config"]
    url = cfg["url"]
    api = FakeApi({(url, monday_body(1)): {"data": {"users": [
        {"id": 1, "name": "Ann", "email": "ann@example.com", "enabled": True, "is_admin": True},
        {"id": 2, "name": "Ben", "email": "ben@example.com", "enabled": False, "is_guest": True}]}},
        (url, monday_body(2)): {"data": {"users": [{"id": 3, "name": "Cy", "email": "cy@example.com", "enabled": True}]}},
        (url, monday_body(3)): {"data": {"users": []}}})
    pages = []
    rows = rows_by_id(src.rest_pull(cfg, "tok-123", api, pages=pages))
    assert rows["1"]["role"] == "Admin" and rows["2"]["role"] == "Guest" and rows["3"]["role"] == "Member"
    assert rows["2"]["status"] == "disabled" and rows["1"]["status"] == "active"
    assert [s["headers"]["Authorization"] for s in api.sent] == ["tok-123"] * 3
    assert all(s["redirects"] == 0 and s["method"] == "POST" for s in api.sent)
    assert "tok-123" not in json.dumps(pages)
    assert len(src.rest_pull(cfg, "tok-123", api, preview=True)) == 2           # a test reads the first page only


def test_workos_preset_follows_the_cursor_and_bearer_token():
    cfg = src.PRESETS["workos"]["config"]
    first = cfg["url"]
    second = "https://api.workos.com/user_management/users?limit=100&after=user_2"
    api = FakeApi({first: {"data": [{"id": "user_1", "email": "a@example.com", "last_sign_in_at": "2026-09-01T00:00:00Z"},
                                    {"id": "user_2", "email": "b@example.com"}], "list_metadata": {"after": "user_2"}},
                   second: {"data": [{"id": "user_3", "email": "c@example.com"}], "list_metadata": {"after": None}}})
    rows = src.rest_pull(cfg, "sk_test", api)
    assert [r["account_id"] for r in rows] == ["user_1", "user_2", "user_3"] and rows[0]["last_login"] == "2026-09-01"
    assert api.sent[0]["headers"]["Authorization"] == "Bearer sk_test"


def custom(**kw):
    cfg = {"url": "https://api.example.com/v1/users", "method": "GET", "auth": "bearer", "items_path": "users",
           "paging": "next_url", "next_path": "next", "map": {"account_id": "login", "email": "mail", "status": "!locked"}}
    cfg.update(kw)
    return cfg


def test_next_page_links_must_stay_on_the_same_host():
    api = FakeApi({"https://api.example.com/v1/users": {"users": [{"login": "a", "mail": "a@example.com", "locked": True}],
                                                        "next": "https://evil.example.net/steal"}})
    with pytest.raises(src.SourceError, match="different site"):
        src.rest_pull(custom(), "secret-token", api)
    assert len(api.sent) == 1                                                 # the token never went to the other host


def test_custom_api_errors_are_plain_and_never_partial():
    cfg = custom(paging="none")
    assert src.rest_pull(cfg, "t", FakeApi({cfg["url"]: {"users": [{"login": "a", "locked": True}]}}))[0]["status"] == "disabled"
    with pytest.raises(src.SourceError, match="HTTP 401"):
        src.rest_pull(cfg, "t", FakeApi({}, status=401))
    with pytest.raises(src.SourceError, match="No list of users"):
        src.rest_pull(cfg, "t", FakeApi({cfg["url"]: {"users": "nope"}}))
    with pytest.raises(src.SourceError, match="account ID"):
        src.rest_pull(cfg, "t", FakeApi({cfg["url"]: {"users": [{"mail": "x@example.com"}]}}))
    with pytest.raises(src.SourceError, match="token is not set"):
        src.rest_pull(cfg, "", FakeApi({}))
    endless = FakeApi({})
    endless.pages = type("Always", (dict,), {"get": lambda self, k, d=None: {"users": [{"login": "x"}]}})()
    with pytest.raises(src.SourceError, match="pages"):
        src.rest_pull(custom(paging="page", page_param="page", map={"account_id": "login"}), "t", endless)


@pytest.mark.parametrize("cfg,message", [
    (custom(url="http://api.example.com/users"), "https"),
    (custom(url="https://user:pw@api.example.com/users"), "https"),
    (custom(auth="header", header_name="Host"), "header name"),
    (custom(auth="header", header_name="X-Key\r\nEvil: 1"), "header name"),
    (custom(map={"email": "mail"}), "account ID"),
    (custom(method="DELETE"), "GET or POST"),
    (custom(paging="cursor"), "Cursor"),
])
def test_custom_settings_are_validated(cfg, message):
    assert any(message.lower() in e.lower() for e in src.validate_rest(cfg))


def test_internal_and_metadata_addresses_are_blocked():
    with pytest.raises(src.SourceError, match="blocked"):
        src.rest_pull(custom(url="https://169.254.169.254/latest/meta-data", paging="none"), "t")
    with pytest.raises(src.SourceError, match="blocked"):
        src.rest_pull(custom(url="https://127.0.0.1/users", paging="none"), "t")


# ---------------------------------------------------------------- portal: applications
@pytest.fixture()
def portal(tmp_path, monkeypatch):
    for key in ("GRCPAL_MS_ENABLED", "GRCPAL_AZURE_ENABLED", "GRCPAL_GITHUB_ENABLED"):
        monkeypatch.setenv(key, "true")
    monkeypatch.setenv("GRCPAL_JOBS_SYNC", "1")
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", "test-only-key-0123456789abcdef")
    return make_portal(tmp_path)


def setup_apps(portal):
    entra = portal.add_access_app(ADMIN, "Microsoft 365", "entra_users", ADMIN2.email)
    gh = portal.add_access_app(ADMIN, "GitHub", "github_org", ADMIN2.email)
    portal.update_access_app(ADMIN, gh["RowKey"], {"name": "GitHub", "owner_email": ADMIN2.email, "org": "example-org"})
    portal.set_access_app_identities(ADMIN, gh["RowKey"], b"account_id,email\nAlice-GH,alice@example.com\nbob-gh,bob@example.com\n")
    crm = portal.add_access_app(ADMIN, "Customer portal", "rest", "")
    portal.update_access_app(ADMIN, crm["RowKey"], {
        "name": "Customer portal", "url": "https://api.example.com/v1/users", "method": "GET", "auth": "bearer",
        "items_path": "users", "paging": "none", "map_account_id": "login", "map_email": "mail", "map_role": "role"},
        token="crm-secret-token-123")
    return entra, gh, crm


CRM = FakeApi({"https://api.example.com/v1/users": {"users": [
    {"login": "alice", "mail": "alice@example.com", "role": "owner"},
    {"login": "carol", "mail": "carol@example.com", "role": "agent"}]}})


def test_only_admins_change_applications_and_auditors_see_them_without_secrets(portal):
    for who in (HR, CONTRIB, AUDITOR):
        with pytest.raises(Forbidden):
            portal.add_access_app(who, "X", "grcpal")
    with pytest.raises(Forbidden):
        portal.access_apps(CONTRIB)
    _, _, crm = setup_apps(portal)
    with pytest.raises(Invalid, match="already"):
        portal.add_access_app(ADMIN, "Entra again", "entra_users")
    with pytest.raises(Invalid, match="name"):
        portal.add_access_app(ADMIN, "github", "csv")
    seen = portal.access_app(AUDITOR, crm["RowKey"])
    assert seen["token_set"] and "token_enc" not in seen and "identities" not in seen
    raw = portal.store.get("arapps", "a", crm["RowKey"])
    assert "crm-secret-token-123" not in json.dumps(raw) and raw["token_enc"].startswith("v1:")
    assert "crm-secret-token-123" not in json.dumps(portal.log.records())
    assert portal.settings_store.open_secret(f"arapp:{crm['RowKey']}", raw["token_enc"]) == "crm-secret-token-123"
    with pytest.raises(Invalid, match="https"):
        portal.update_access_app(ADMIN, crm["RowKey"], {"name": "Customer portal", "url": "http://api.example.com",
                                                       "map_account_id": "login"})
    portal.update_access_app(ADMIN, crm["RowKey"], {"name": "Customer portal", "url": "https://api.example.com/v1/users",
                                                   "auth": "bearer", "items_path": "users", "map_account_id": "login"},
                             clear_token=True)
    assert portal.access_app(ADMIN, crm["RowKey"])["token_set"] is False


def test_tokens_are_bound_to_their_tenant(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", "test-only-key-0123456789abcdef")
    shared = SqliteStore()
    acme, beta = make_portal(tmp_path, "acme", shared), make_portal(tmp_path, "beta", shared)
    a = acme.add_access_app(ADMIN, "Portal", "rest")
    acme.update_access_app(ADMIN, a["RowKey"], {"name": "Portal", "url": "https://api.example.com/u", "auth": "bearer",
                                                "items_path": "users", "map_account_id": "id"}, token="t0k")
    sealed = acme.store.get("arapps", "a", a["RowKey"])["token_enc"]
    assert beta.access_apps(ADMIN) == []
    with pytest.raises(Invalid):
        beta.access_app(ADMIN, a["RowKey"])
    with pytest.raises(Exception):                                           # bound to tenant and application
        beta.settings_store.open_secret(f"arapp:{a['RowKey']}", sealed)


def test_starting_a_review_from_applications(portal):
    entra, gh, crm = setup_apps(portal)
    me = portal.add_access_app(ADMIN, "GRC-pal", "grcpal", ADMIN2.email)
    job = portal.start_access_review(ADMIN, "Q4 review", "2026-11-30",
                                     [entra["RowKey"], gh["RowKey"], crm["RowKey"], me["RowKey"]],
                                     accounts=b"app,account_id,email,manager_email\nPayroll,p1,carol@example.com,\n",
                                     entra_managers=True, clients=FakeClients(), request_fn=CRM)
    assert job["status"] == "done", job.get("message")
    cid = job["result"]["campaign"]
    camp = portal.access_campaign(ADMIN, cid)["campaign"]
    assert camp["pulled"] == {"Microsoft 365": {"kind": "entra_users", "records": 5}, "GitHub": {"kind": "github_org", "records": 4},
                              "Customer portal": {"kind": "rest", "records": 2}, "GRC-pal": {"kind": "grcpal", "records": 5}}
    assert camp["records"] == 5 + 4 + 2 + 5 + 1
    entries = {(e["app"], e["account_id"]): e for e in portal._ar_entries(cid)}
    assert entries[("GitHub", "Alice-GH")]["email"] == "alice@example.com"            # identity map
    assert entries[("GitHub", "Alice-GH")]["reviewer"] == HR.email                    # manager from direct reports
    assert entries[("Customer portal", "carol")]["reviewer"] == CONTRIB.email
    assert entries[("Payroll", "p1")]["reviewer"] == CONTRIB.email                    # the CSV uses Entra managers too
    assert entries[("GitHub", "contractor-x")]["reviewer"] == ADMIN2.email            # no person: the app owner
    assert entries[("Microsoft 365", HR.email)]["reviewer"] == ADMIN2.email           # no manager: the app owner
    assert entries[("GRC-pal", HR.email)]["reviewer"] == ADMIN2.email
    assert entries[("GRC-pal", ADMIN2.email)]["reviewer"] == ""                       # never the account holder
    assert entries[("Payroll", "p1")]["flags"] == []
    assert "privileged" in entries[("Microsoft 365", "alice@example.com")]["flags"]
    # evidence: the reviewed list hashed, each source's normalized accounts, the managers used
    source, _, run = camp["snapshot_run"].partition("/")
    population = portal.evidence.read(source, run, "population.csv")
    assert hashlib.sha256(population).hexdigest() == camp["snapshot_sha256"]
    assert len(list(csv.DictReader(io.StringIO(population.decode())))) == camp["records"]
    pulled = json.loads(portal.evidence.read(source, run, f"source_{crm['RowKey']}.json"))
    assert pulled["records"] == 2 and pulled["requests"] == ["https://api.example.com/v1/users"]
    assert b"carol@example.com," + CONTRIB.email.encode() in portal.evidence.read(source, run, "entra_managers.csv")
    log = json.dumps([r["detail"] for r in portal.log.records() if r["action"] == "access_review.create"])
    assert '"GitHub": 4' in log and "example.com" not in log and "crm-secret" not in log


def test_one_unreadable_application_means_no_review(portal):
    entra, _, crm = setup_apps(portal)
    job = portal.start_access_review(ADMIN, "Q4", "2026-11-30", [entra["RowKey"], crm["RowKey"]],
                                     clients=FakeClients(), request_fn=FakeApi({}, status=500))
    assert job["status"] == "failed" and "Customer portal" in job["message"] and "Nothing was created" in job["message"]
    assert portal.store.list("arcampaigns", "c") == [] and portal.evidence.list_runs("access_review_snapshot") == []


def test_turned_off_platforms_and_bad_choices_are_refused(portal, monkeypatch):
    entra, _, _ = setup_apps(portal)
    monkeypatch.setenv("GRCPAL_MS_ENABLED", "false")
    job = portal.start_access_review(ADMIN, "Q4", "2026-11-30", [entra["RowKey"]], clients=FakeClients())
    assert job["status"] == "failed" and "Microsoft collection is turned off" in job["message"]
    with pytest.raises(Invalid, match="at least one"):
        portal.start_access_review(ADMIN, "Q4", "2026-11-30", [])
    with pytest.raises(Invalid, match="not found"):
        portal.start_access_review(ADMIN, "Q4", "2026-11-30", ["no-such-app"])
    other = portal.add_access_app(ADMIN, "Payroll", "csv")
    with pytest.raises(Invalid, match="CSV"):
        portal.start_access_review(ADMIN, "Q4", "2026-11-30", [other["RowKey"]])
    with pytest.raises(Forbidden):
        portal.start_access_review(HR, "Q4", "2026-11-30", [entra["RowKey"]])
    with pytest.raises(Invalid, match="Nothing was imported"):                 # an uploaded file is checked at once
        portal.start_access_review(ADMIN, "Q4", "2026-11-30", [entra["RowKey"]], accounts=b"app,account_id\n,x\n")


def test_a_test_keeps_counts_never_accounts(portal):
    _, gh, crm = setup_apps(portal)
    result = portal.test_access_app(ADMIN, crm["RowKey"], request_fn=CRM)
    assert result == {**result, "ok": True, "records": 2, "with_email": 2}
    stored = json.dumps(portal.store.get("arapps", "a", crm["RowKey"])["last_test"])
    assert "alice" not in stored and "carol" not in stored
    failed = portal.test_access_app(ADMIN, gh["RowKey"], clients=FakeClients(gh_pages_cut=True))
    assert failed["ok"] is False and "incomplete" in failed["error"]
    with pytest.raises(Forbidden):
        portal.test_access_app(AUDITOR, crm["RowKey"])


def test_identity_map_is_validated(portal):
    _, gh, _ = setup_apps(portal)
    with pytest.raises(Invalid, match="columns"):
        portal.set_access_app_identities(ADMIN, gh["RowKey"], b"login,mail\na,b@example.com\n")
    with pytest.raises(Invalid, match="not valid"):
        portal.set_access_app_identities(ADMIN, gh["RowKey"], b"account_id,email\na,not-an-email\n")
    with pytest.raises(Forbidden):
        portal.set_access_app_identities(HR, gh["RowKey"], b"account_id,email\na,a@example.com\n")


def test_the_new_table_is_registered():
    assert "arapps" in TABLES


# ---------------------------------------------------------------- pages
@pytest.fixture()
def client(portal, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.delenv("GRCPAL_PUBLIC_URL", raising=False)
    return TestClient(create_app(portal), base_url="https://grc.example.com")


def test_application_pages(portal, client):
    _, _, crm = setup_apps(portal)
    as_(client, ADMIN)
    token = csrf(client, "/access-reviews/apps")
    page = client.get("/access-reviews/apps")
    assert page.status_code == 200 and "Customer portal" in page.text
    detail = client.get(f"/access-reviews/apps/{crm['RowKey']}")
    assert detail.status_code == 200 and "crm-secret-token-123" not in detail.text and "saved; leave blank" in detail.text
    r = client.post("/access-reviews/apps/new", data={"csrf": token, "name": "This portal", "kind": "grcpal"},
                    follow_redirects=False)
    assert r.status_code == 303
    aid = r.headers["location"].split("?")[0].rsplit("/", 1)[1]
    assert client.post("/access-reviews/apps/new", data={"name": "No token", "kind": "grcpal"}).status_code == 403
    r = client.post(f"/access-reviews/apps/{aid}/test", data={"csrf": token}, follow_redirects=False)
    assert "Test+passed" in r.headers["location"]
    start = client.get("/access-reviews")
    assert 'name="apps"' in start.text and "This portal" in start.text
    r = client.post("/access-reviews/new", data={"csrf": token, "name": "Q4", "due": "2026-11-30", "apps": [aid]},
                    follow_redirects=False)
    assert r.status_code == 303 and "msg=" in r.headers["location"]
    assert len(portal.store.list("arcampaigns", "c")) == 1
    assert "Open the review" in client.get("/access-reviews").text
    as_(client, AUDITOR)
    page = client.get(f"/access-reviews/apps/{crm['RowKey']}")
    assert page.status_code == 200 and 'type="password"' not in page.text
    assert client.post(f"/access-reviews/apps/{aid}/test", data={"csrf": csrf(client, "/access-reviews")}).status_code == 403
    as_(client, HR)
    assert client.get("/access-reviews/apps").status_code == 403
    assert client.get(f"/access-reviews/apps/{crm['RowKey']}").status_code == 403

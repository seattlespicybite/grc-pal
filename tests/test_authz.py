"""Authorization suite: every route x every kind of caller, object by object, organization by organization.

The expectation table is tests/authz_matrix.py; the objects are built in tests/authz_world.py. How it works:

  * Every route of the app (dev and local sign-in modes) must be in the table, and every table entry must be a
    real route. A new route without an entry fails the suite, on purpose.
  * Each allowed role gets through (no 401/403/404, and a POST changes data). Each refused role is refused, and
    a refused POST changes nothing: no table row, no evidence file, no email. The data is put back to the same
    starting point after every change (SQLite online backup), so one role's write cannot hide another role's.
  * Object level: a Control owner asks by ID for things that are not theirs. Two organizations in one store:
    an admin of one never reaches the other's rows. CSRF and download headers are checked on every route.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import authz_matrix as M
import authz_world as W
from grcpal import checks as checks_mod
from grcpal import collectors
from grcpal.portal import security
from grcpal.portal.app import create_app
from grcpal.portal.auth import User
from test_portal import make_portal

ROLES = W.ROLES
LOGIN_PAGES = ("/dev/login", "/login")
CSP_DOWNLOAD = ("default-src 'none'; sandbox", "default-src 'none'; style-src 'unsafe-inline'; sandbox")


# ====================================================================================== the harness
class Harness:
    """One portal for the organization "acme" (the rows of "other" live in the same store), a client, and a way to
    put the data back exactly as it was. `mode` is the sign-in mode: "dev" (an identity header) or "local" (a
    session cookie, as in a real installation)."""

    def __init__(self, tmp: Path, mp, mode: str) -> None:
        mp.setenv("GRCPAL_AUTH_MODE", mode)
        mp.setenv("GRCPAL_ENV", "dev")
        mp.setenv("GRCPAL_JOBS_SYNC", "1")
        mp.setenv("GRCPAL_UPDATE_CHECK", "off")
        for var in ("GRCPAL_TENANT", "GRCPAL_BOOTSTRAP_ADMINS", "GRCPAL_PUBLIC_URL", "GRCPAL_DEV_PRINCIPAL",
                    "GRCPAL_ALLOWED_TENANT_IDS", "GRCPAL_EVIDENCE_ACCOUNT_URL"):
            mp.delenv(var, raising=False)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        mp.setenv("GRCPAL_EVIDENCE_SIGNING_KEY", Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
        # No network: a custom HTTP check answers from a stub, and only the offline collector runs.
        mp.setattr(checks_mod, "run_http", lambda cfg, headers, secret_names=None, requester=None:
                   checks_mod.CheckResult(ok=True, summary="stub answer"))
        mp.setattr(collectors, "NAMES", ["catalog_validate"])
        self.mode, self.tmp = mode, tmp
        self.base, self.w, self.o = W.build_all(tmp)
        self.portal = self.w.portal
        self.evidence_root = tmp / "evidence"
        self.app = create_app(self.portal)
        self.client = TestClient(self.app, base_url="https://grc.example.com", follow_redirects=False,
                                 raise_server_exceptions=False)
        self.routes = app_routes(self.app)
        self.admin2 = User(self.w.admin2_email, "Sam Security", "admin")
        extra = W.open_sessions(self.portal, {"admin2": self.admin2})
        self.tokens = {self.w.who[r].email: t for r, t in self.w.sessions.items()}
        self.tokens[self.admin2.email] = extra["admin2"]
        self.warm()
        self.save_start()

    # ------------------------------------------------------------------ the starting point
    def serves(self, route) -> bool:
        """False for a route this sign-in mode does not have (the dev outbox exists only in dev mode)."""
        return route in self.routes

    def warm(self) -> None:
        """Open every page once as an admin, so rows that are created the first time a page is shown exist now."""
        for method, template in sorted(M.EXPECT):
            if method == "GET":
                self.call("admin", "GET", resolve(template, self.w))

    def save_start(self) -> None:
        self.snap_db = self.tmp / "start.db"
        self.base.snapshot(str(self.snap_db)).close()
        self.snap_ev = self.tmp / "start-evidence"
        if self.snap_ev.exists():
            shutil.rmtree(self.snap_ev)
        shutil.copytree(self.evidence_root, self.snap_ev)

    def reset(self) -> None:
        W.restore_db(self.snap_db, self.base)
        W.copy_tree(self.snap_ev, self.evidence_root)
        self.portal.mailer.outbox.clear()
        self.portal._changed()
        self.portal._kb_cache = None
        self.app.state.report_cache = (0.0, None)

    def state(self):
        return (W.dump(self.base), W.evidence_files(self.evidence_root), len(self.portal.mailer.outbox))

    # ------------------------------------------------------------------ calling the app
    def person(self, role: str, world=None) -> User | None:
        return (world or self.w).who[role]

    def _auth(self, role: str, who: User | None):
        """(headers, cookies, form-token subject) for one caller."""
        if who is None:
            return {}, {}, None
        if self.mode == "dev":
            return {"X-Dev-Principal": json.dumps({"email": who.email, "name": who.name})}, {}, f"{who.email}|"
        token = self.tokens.get(who.email, "no-such-session")
        return {}, {"grcpal_session": token}, f"{who.email}|{security.session_binding(token)}"

    def call(self, role, method, path, data=None, headers=None, who=None, token="valid", origin=None):
        """token: "valid" (the caller's own), "missing", or "other" (a token that belongs to somebody else)."""
        who = who if who is not None else self.person(role)
        data = dict(data or {})
        files = data.pop("__files__", None)
        hdr, cookies, subject = self._auth(role, who)
        hdr.update(headers or {})
        if origin:
            hdr["Origin"] = origin
        self.client.cookies.clear()
        for k, v in cookies.items():
            self.client.cookies.set(k, v)
        if method == "GET":
            return self.client.get(path, headers=hdr)
        if token == "valid":
            data["csrf"] = security.csrf_token(subject or "anonymous|")
        elif token == "other":
            data["csrf"] = security.csrf_token("somebody.else@example.com|")
        return self.client.post(path, data=data, files=files, headers=hdr)

    def checked_post(self, role, template, world=None, **kw):
        """Call a POST with its valid form. Returns (response, changed?) and puts the data back if it changed."""
        w = world or self.w
        before = self.state()
        r = self.call(role, "POST", resolve(template, w), data=form_for("POST", template, w), **kw)
        changed = self.state() != before
        if changed:
            self.reset()
        return r, changed


def resolve(path: str, w) -> str:
    """Fill the {placeholders} of a route template with the IDs of one organization's world."""
    params = M.PARAMS.get(path, {})
    for name in re.findall(r"\{(\w+)\}", path):
        if name not in params:
            raise KeyError(f"{path}: no PARAMS entry for {{{name}}}")
        path = path.replace("{" + name + "}", str(getattr(w, params[name])))
    return path


def form_for(method: str, template: str, w) -> dict:
    spec = M.FORMS.get((method, template), {})
    return dict(spec(w) if callable(spec) else spec)


def app_routes(app) -> set[tuple[str, str]]:
    return {(m, r.path) for r in app.routes if isinstance(r, APIRoute) for m in r.methods if m != "HEAD"}


# ---------------------------------------------------------------------------------- what an answer means
def to_login(r) -> bool:
    return r.status_code in (301, 302, 303, 307) and r.headers.get("location", "").startswith(LOGIN_PAGES)


def redirected(r) -> bool:
    return r.status_code in (301, 302, 303, 307)


def refused(r) -> bool:
    """The caller was turned away: 401/403/404, or sent to the sign-in page."""
    return r.status_code in (401, 403, 404) or to_login(r)


def let_in(r) -> bool:
    """The caller got past authorization: a page, a file, or a redirect that is not the sign-in page."""
    return not refused(r) and r.status_code < 500 and r.status_code != 422


def explained(r) -> bool:
    """A refused POST answers with a refusal, an error message on the page it sends the caller back to, or the
    form again. (Whether it changed anything is checked separately and is the real test.)"""
    return refused(r) or (redirected(r) and "err=" in r.headers.get("location", "")) or r.status_code == 200


@pytest.fixture(scope="module", params=["dev", "local"])
def h(request, tmp_path_factory):
    mp = pytest.MonkeyPatch()
    harness = Harness(tmp_path_factory.mktemp(f"authz-{request.param}"), mp, request.param)
    yield harness
    mp.undo()


ROUTES = sorted(M.EXPECT)


def rid(route):
    return f"{route[0]} {route[1]}"


# ====================================================================================== the table is complete
def test_table_matches_the_routes_of_both_sign_in_modes(tmp_path, monkeypatch):
    """A route that is not in the table fails here, and so does a table entry for a route that no longer exists."""
    found = set()
    for mode in ("dev", "local"):
        monkeypatch.setenv("GRCPAL_AUTH_MODE", mode)
        monkeypatch.setenv("GRCPAL_ENV", "dev")
        found |= app_routes(create_app(make_portal(tmp_path / mode, people=())))
    assert not (found - M.PUBLIC - set(M.EXPECT)), (
        "These routes are not in tests/authz_matrix.py. Add each one to EXPECT (who may call it), PARAMS (its "
        f"{{ids}}) and, for a POST, FORMS: {sorted(found - M.PUBLIC - set(M.EXPECT))}")
    assert not (set(M.EXPECT) - found), f"In the table but not in the app: {sorted(set(M.EXPECT) - found)}"
    assert not (M.PUBLIC - found), f"Listed as public but not in the app: {sorted(M.PUBLIC - found)}"
    assert not (M.PUBLIC & set(M.EXPECT))


def test_table_is_well_formed():
    for method, template in M.EXPECT:
        names = re.findall(r"\{(\w+)\}", template)
        assert set(names) == set(M.PARAMS.get(template, {})), f"PARAMS for {template}"
    assert {k for k in M.EXPECT if k[0] == "POST"} <= set(M.FORMS), "every POST needs a valid form"
    assert M.NO_WRITE <= set(M.EXPECT) and all(k[0] == "POST" for k in M.NO_WRITE)
    assert set(M.XFAIL) <= set(M.EXPECT) and set(M.DOWNLOAD_XFAIL) <= set(M.EXPECT)
    for key, roles in M.EXPECT.items():
        assert roles <= {"admin", "owner", "contributor", "auditor"}, (
            f"{key}: anonymous, expired auditors and disabled admins are never allowed anywhere")


def test_auditors_never_write():
    """An auditor reads. No POST in the table allows the auditor role, except their own two-step sign-in."""
    assert [k for k, roles in M.EXPECT.items()
            if k[0] == "POST" and "auditor" in roles and k not in M.SELF_SERVICE] == []


# ====================================================================================== route x role
@pytest.mark.parametrize("route", ROUTES, ids=rid)
def test_route_by_role(h, route):
    method, template = route
    allowed_roles = M.EXPECT[route]
    if not h.serves(route):
        pytest.skip("not served in this sign-in mode")
    if route in M.XFAIL:
        pytest.xfail(M.XFAIL[route])
    refusal_probe = None
    for role in ROLES:
        who = h.person(role)
        if method == "GET":
            r = h.call(role, "GET", resolve(template, h.w))
            changed = False
        else:
            r, changed = h.checked_post(role, template)
        where = f"{role} {method} {template} -> {r.status_code} {r.headers.get('location', '')[:100]}"
        assert r.status_code < 500, f"server error: {where}"
        if role in allowed_roles:
            assert let_in(r), f"allowed role was refused: {where}"
            if method == "POST" and route not in M.NO_WRITE:
                assert changed, f"allowed role got through but nothing changed (is the form valid?): {where}"
            continue
        # ---- not allowed
        if who is None or role in ("expired_auditor", "disabled_admin"):
            # refused before the route runs: there is no signed-in, active person
            assert r.status_code in (401, 403) or to_login(r), f"not turned away at the door: {where}"
            if method == "POST":
                assert r.status_code in (401, 403), f"POST was not refused outright: {where}"
        elif method == "GET":
            assert refused(r), f"role should be refused: {where}"
        else:
            assert explained(r), f"refused POST gave no refusal: {where}"
        if method == "POST":
            assert not changed, f"a refused POST changed data: {where}"
            if who is not None and refusal_probe is None and role not in ("expired_auditor", "disabled_admin"):
                refusal_probe = (r.status_code, r.headers.get("location", ""))
    if method == "POST" and route in M.NO_WRITE and refusal_probe:
        # nothing to see in the data: the allowed role must at least get a different answer than a refused one
        for role in allowed_roles:
            r, _ = h.checked_post(role, template)
            assert (r.status_code, r.headers.get("location", "")) != refusal_probe, (
                f"{role} gets the same answer as a refused role on {template}")


# ====================================================================================== object level
FOREIGN = ("owner", "contributor")   # people who own none of control B's objects


def foreign_cases(w):
    """(method, path, form) for objects of control B, vendor B, a draft library version, a foreign access review..."""
    cases = [
        ("GET", f"/controls/{w.ctl_b}", None), ("GET", f"/assignments/{w.assign_b}", None),
        ("GET", f"/uploads/{w.upload_b}/download", None), ("GET", f"/vendors/{w.vendor_b}", None),
        ("GET", f"/vendors/{w.vendor_b}/files/{w.vendor_file_b}", None),
        ("GET", f"/library/{w.doc}/files/{w.ver_draft}", None),
        ("GET", f"/access-reviews/{w.campaign_b}", None),
        ("GET", f"/library/{w.doc_trashed}", None),
    ]
    files = {"__files__": {"file": ("evidence.pdf", W.PDF, "application/pdf")}}
    cases += [
        ("POST", f"/controls/{w.ctl_b}/upload", {"comment": "x", "approval_note": "Reviewed and complete.", **files}),
        ("POST", f"/controls/{w.ctl_b}/note", {"text": "A note on a control that is not mine"}),
        ("POST", f"/assignments/{w.assign_b}/upload", {"comment": "x", "approval_note": "Reviewed and complete.", **files}),
        ("POST", "/comments", {"body": "Not my request", "assignment_id": w.assign_b, "upload_id": "", "control_id": "",
                               "return_to": "/work"}),
        ("POST", "/comments", {"body": "Not my upload", "assignment_id": "", "upload_id": w.upload_b, "control_id": "",
                               "return_to": "/work"}),
        ("POST", f"/vendors/{w.vendor_b}/contacts", {"ext_name": "Intruder"}),
        ("POST", f"/vendors/{w.vendor_b}/files", {"kind": "report", "comment": "x", **files}),
        ("POST", f"/vendors/{w.vendor_b}/review/checklist", {"key": "risk", "done": "1", "note": "x"}),
        ("POST", f"/vendors/{w.vendor_b}/questionnaire", {"q": "full"}),
        ("POST", f"/library/{w.doc}/versions/{w.ver_draft}/status", {"status": "archived", "note": "x"}),
        ("POST", f"/library/{w.doc}/review/{w.ver_draft}", {"decision": "approve", "read": "1", "note": ""}),
        ("POST", f"/access-reviews/{w.campaign_b}/decide", {f"d_{w.entry_b}": "keep", f"c_{w.entry_b}": "x"}),
        ("POST", f"/access-reviews/{w.campaign_b}/signoff", {}),
        ("POST", f"/matrix/import/{w.matrix_import}/apply", {"plan": w.matrix_plan, "reason": "Not my change to apply."}),
        ("POST", f"/matrix/import/{w.matrix_import}/discard", {}),
        ("POST", "/matrix/import", {"__files__": {"file": ("matrix.xlsx", w.matrix_file, "application/octet-stream")}}),
    ]
    return cases


@pytest.mark.parametrize("role", FOREIGN)
def test_object_level_foreign_objects(h, role):
    """A Control owner asks by ID for objects that belong to somebody else. Nothing is shown, nothing changes."""
    for method, path, form in foreign_cases(h.w):
        before = h.state()
        r = h.call(role, method, path, data=form)
        where = f"{role} {method} {path} -> {r.status_code} {r.headers.get('location', '')[:100]}"
        assert r.status_code < 500, where
        if method == "GET":
            assert refused(r), f"a foreign object was shown: {where}"
        else:
            assert explained(r), where
            changed = h.state() != before
            if changed:
                h.reset()
            assert not changed, f"a foreign object was changed: {where}"


def test_object_level_second_admin_is_not_the_library_owner(h):
    """Only the control library owner changes control definitions and applies a matrix import. A second admin,
    who may do everything else an admin does, is refused."""
    w = h.w
    admin2 = h.admin2
    for method, path, form in [
        ("GET", f"/controls/{w.ctl_a}/definition", None),
        ("POST", f"/controls/{w.ctl_a}/definition", M._definition(w)),
        ("POST", f"/controls/{w.ctl_edited}/definition/reset", {"reason": "Back to the starter wording for the test."}),
        ("POST", "/controls/new", M._custom(w, "CUS-TWO")),
        ("POST", f"/controls/{w.custom}/retire", {"reason": "Retired by somebody who may not."}),
        ("POST", "/frameworks/new", form_for("POST", "/frameworks/new", w)),
        ("POST", "/matrix/import", form_for("POST", "/matrix/import", w)),
        ("POST", f"/matrix/import/{w.matrix_import}/apply", form_for("POST", "/matrix/import/{import_id}/apply", w)),
    ]:
        before = h.state()
        r = h.call("admin", method, path, data=form, who=admin2)
        where = f"second admin {method} {path} -> {r.status_code} {r.headers.get('location', '')[:100]}"
        assert r.status_code < 500, where
        assert (refused(r) if method == "GET" else explained(r)), where
        changed = h.state() != before
        if changed:
            h.reset()
        assert not changed, f"a second admin changed library data: {where}"
    # ...and the library owner can hand the role over only from their own account
    r, changed = h.checked_post("admin", "/users/{email}/library-owner")
    assert let_in(r) and changed
    before = h.state()
    r = h.call("admin", "POST", f"/users/{w.admin2_email}/library-owner", who=admin2)
    assert explained(r) and h.state() == before


def test_object_level_owner_cannot_reach_what_is_not_assigned_to_them(h):
    """The Control owner sees control A (theirs) but cannot widen that by guessing: other IDs for A's pages, and
    the same IDs in different places, are refused."""
    w = h.w
    assert let_in(h.call("owner", "GET", f"/controls/{w.ctl_a}"))
    assert refused(h.call("owner", "GET", f"/controls/{w.ctl_b}"))
    assert refused(h.call("owner", "GET", f"/assignments/{w.assign_b}"))
    # an upload ID is not an assignment ID
    assert refused(h.call("owner", "GET", f"/assignments/{w.upload_a}"))
    assert refused(h.call("owner", "GET", f"/uploads/{w.assign_a}/download"))
    # an entry that is not in this review (the owner's own entries are 00001 and 00002 in review A)
    before = h.state()
    r = h.call("owner", "POST", f"/access-reviews/{w.campaign_a}/decide", data={"d_99999": "revoke"})
    assert explained(r) and h.state() == before


# ====================================================================================== two organizations
def cross_cases():
    out = []
    for method, template in ROUTES:
        params = M.PARAMS.get(template, {})
        unique = [a for a in params.values() if a not in M.SHARED]
        if unique or (method, template) in M.CROSS_FORMS:
            out.append((method, template))
    return out


def test_two_organizations_in_one_store(h):
    """An admin of "acme" asks for every ID-bearing route with the other organization's IDs. They are never shown
    and nothing changes. Then every page the admin may open is searched for the other organization's IDs."""
    w, o = h.w, h.o
    cases = cross_cases()
    assert len(cases) > 60, "the two-organization test must cover most ID-bearing routes"
    for method, template in cases:
        path = resolve(template, o)
        before = h.state()
        if method == "GET":
            r = h.call("admin", "GET", path)
            where = f"admin of acme: GET {path} (other organization's IDs) -> {r.status_code}"
            assert r.status_code != 200 and r.status_code < 500, where
        else:
            r = h.call("admin", "POST", path, data=form_for("POST", template, o))
            where = f"admin of acme: POST {path} (other organization's IDs) -> {r.status_code} {r.headers.get('location', '')[:80]}"
            assert r.status_code < 500, where
        after = h.state()
        mine_before = {k: v for k, v in before[0].items() if k[1].startswith("other|")}
        mine_after = {k: v for k, v in after[0].items() if k[1].startswith("other|")}
        assert mine_before == mine_after, f"the other organization's rows changed: {where}"
        if method == "POST":
            assert before == after, f"a request with another organization's IDs changed something: {where}"
        if before != after:
            h.reset()
    # no page of acme shows the other organization's IDs, names or addresses
    secrets_ = {str(getattr(o, a)) for a in vars(o) if a not in ("portal", "who", "matrix_file", "sessions", "tenant", "owner",
                                                               "other_owner") and len(str(getattr(o, a))) >= 8
                and a not in M.SHARED and str(getattr(o, a)) not in {str(getattr(w, a, "")) for a in M.SHARED}}
    secrets_ -= {str(getattr(w, a)) for a in vars(w) if a not in ("portal", "who", "matrix_file", "sessions")}
    secrets_ = {x for x in secrets_ if not re.match(r"^\d{4}-\d\d-\d\d", x)}   # dates and run times are not secrets
    assert len(secrets_) > 30
    for method, template in ROUTES:
        if method != "GET":
            continue
        r = h.call("admin", "GET", resolve(template, w))
        if r.status_code == 200:
            hit = [s for s in secrets_ if s in r.text]
            assert not hit, f"GET {template} shows the other organization's data: {hit[:3]}"
    for text in (f"@{o.tenant}.example", "Zeta Vendor other", "Other Vendor other"):
        for page in ("/", "/vendors", "/users", "/work", "/library", "/access-reviews", "/controls"):
            body = h.call("admin", "GET", page).text
            assert text not in body, f"{page} shows {text}"


# ====================================================================================== CSRF
def csrf_cases():
    return [(m, t) for m, t in ROUTES if m == "POST"]


@pytest.mark.parametrize("route", csrf_cases(), ids=rid)
def test_csrf(h, route):
    """Every writing POST refuses a missing token, another person's token and a cross-site Origin: each gets a
    403 and changes nothing. (A valid token from the right person is the control: it works.)"""
    method, template = route
    if not h.serves(route):
        pytest.skip("not served in this sign-in mode")
    role = "owner" if "owner" in M.EXPECT[route] and "admin" not in M.EXPECT[route] else "admin"
    w = h.w
    cases = {"missing token": {"token": "missing"}, "another person's token": {"token": "other"},
             "cross-site Origin": {"origin": "https://evil.example"}}
    for label, kw in cases.items():
        before = h.state()
        r = h.call(role, "POST", resolve(template, w), data=form_for("POST", template, w), **kw)
        where = f"{role} POST {template} with {label} -> {r.status_code}"
        assert r.status_code == 403, where
        assert h.state() == before, f"changed data: {where}"


# ====================================================================================== downloads
DOWNLOADS_SEEN: dict[tuple[str, str], tuple] = {}


def reader_of(route) -> str:
    roles = M.EXPECT[route]
    return "admin" if "admin" in roles else sorted(roles)[0]


@pytest.mark.parametrize("route", ROUTES, ids=rid)
def test_downloads_are_attachments(h, route):
    """Every download (GET or POST) is served as an attachment with a sandbox CSP and nosniff, so a stored file can
    never run inside the portal's origin. Pages (HTML) are exempt; everything else counts as a download."""
    method, template = route
    if not h.serves(route):
        pytest.skip("not served in this sign-in mode")
    if route in M.DOWNLOAD_XFAIL:
        pytest.xfail(M.DOWNLOAD_XFAIL[route])
    role = reader_of(route)
    if method == "GET":
        r = h.call(role, "GET", resolve(template, h.w))
    else:
        r, _ = h.checked_post(role, template)
    ctype = r.headers.get("content-type", "")
    disposition = r.headers.get("content-disposition", "")
    if r.status_code != 200 or (ctype.startswith("text/html") and not disposition):
        return                                          # a page, a redirect or an error
    if ctype.startswith("application/json") and not disposition:
        assert r.headers.get("x-content-type-options") == "nosniff"
        return                                          # a data answer for the page's script, not a file
    if "attachment" not in disposition and not ctype.startswith("text/html"):
        pytest.fail(f"{method} {template} sends {ctype or 'no type'} without Content-Disposition: attachment")
    assert disposition.startswith("attachment"), f"{method} {template}: {disposition}"
    assert r.headers.get("content-security-policy") in CSP_DOWNLOAD, f"{method} {template}: {r.headers.get('content-security-policy')}"
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert not ctype.startswith(("text/html", "image/svg")), f"{method} {template} sends {ctype}"
    # the file name carries only safe characters, whatever the ID in the path was
    name = re.search(r'filename="([^"]*)"', disposition)
    assert name and re.fullmatch(r"[A-Za-z0-9._-]+", name.group(1)), disposition


def test_download_name_cannot_carry_header_tricks(h):
    """An ID with quotes, semicolons or line breaks never reaches Content-Disposition unchanged."""
    for bad in ('x"; filename="evil.html', "a%0d%0aSet-Cookie:%20x=1", "../../etc/passwd"):
        r = h.call("admin", "GET", f"/cycles/{bad}/export")
        assert "evil.html" not in r.headers.get("content-disposition", "")
        assert "Set-Cookie" not in r.headers.get("content-disposition", "")
        assert "set-cookie" not in {k.lower() for k in r.headers}


# ====================================================================================== robustness
@pytest.mark.parametrize("route", [k for k in ROUTES if k[0] == "POST"], ids=rid)
def test_empty_forms_never_crash(h, route):
    """A POST with only the CSRF token is a clean refusal or a clean error message, never a server error."""
    method, template = route
    role = "owner" if "owner" in M.EXPECT[route] and "admin" not in M.EXPECT[route] else "admin"
    before = h.state()
    r = h.call(role, "POST", resolve(template, h.w), data={})
    if h.state() != before:
        h.reset()
    assert r.status_code < 500, f"{role} POST {template} with an empty form -> {r.status_code}"

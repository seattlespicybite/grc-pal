"""Where access review accounts come from: pull the user list of one application, read-only.

Each puller returns (rows, notes). A row has the access review CSV columns (without "app"): account_id, email,
name, status, role, last_login, mfa, is_service_account, manager_email, all strings. Notes are plain sentences
about data that could not be read (for example MFA when the token is not an organization owner); they never
contain secrets or people.

Rules every puller follows, because an access review on a partial list is an audit finding:
- Read-only calls only.
- Every page is fetched, or the pull fails. Nothing is silently cut off.
- If the population cannot be known (an Entra app where "assignment required" is off, a group whose members
  cannot be read), the pull fails with a message that says what to change.

Sources and the permissions they need:
- entra_users   Microsoft Entra ID / Microsoft 365 users and guests: User.Read.All (AuditLog.Read.All for last sign-in
                and MFA, RoleManagement.Read.Directory for admin roles; both optional, noted when missing).
- entra_app     users assigned to one Entra enterprise (SSO) application: Application.Read.All, User.Read.All,
                GroupMember.Read.All (to expand groups).
- azure_rbac    Azure role assignments (Reader on the subscriptions), plus User.Read.All and GroupMember.Read.All.
- github_org    organization owners, members and outside collaborators: fine-grained token, Members read.
- rest          a custom application's JSON user list over HTTPS (see `rest_pull`).
Managers come from Entra direct reports (`entra_managers`): Microsoft documents that reading a user's manager is not
available to application identities, while listing direct reports is (User.Read.All).
"""
from __future__ import annotations

import datetime as dt
import json
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from grcpal.clients import ApiError

KINDS = {
    "entra_users": "Microsoft Entra ID / Microsoft 365 (all users and guests)",
    "entra_app": "Entra enterprise application (an app people sign in to with Microsoft)",
    "azure_rbac": "Azure (role assignments on subscriptions)",
    "github_org": "GitHub organization",
    "rest": "Custom application (REST API that lists users)",
    "grcpal": "This GRC-pal portal (its own users)",
    "csv": "Other application (upload a CSV when you start a review)",
}
NEEDS = {"entra_users": ("GRCPAL_MS_ENABLED", "Microsoft"), "entra_app": ("GRCPAL_MS_ENABLED", "Microsoft"),
         "azure_rbac": ("GRCPAL_AZURE_ENABLED", "Azure"), "github_org": ("GRCPAL_GITHUB_ENABLED", "GitHub")}
MAX_PAGES = 200
MAX_ROWS = 2000
MAX_BYTES = 5 * 1024 * 1024
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
ORG_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
EMAIL_RE = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")
PATH_RE = re.compile(r"^[A-Za-z0-9_.\-:, !\[\]]{0,300}$")
HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,60}$")
BLOCKED_HEADERS = {"host", "content-length", "cookie", "transfer-encoding", "connection"}
MAP_FIELDS = ("account_id", "email", "name", "status", "role", "last_login", "mfa", "is_service_account")
PAGING = {"none": "One response holds every user", "page": "Page numbers (page=1, 2, 3 ... until a page is empty)",
          "cursor": "Cursor (the response gives the value for the next request)",
          "next_url": "Next-page link inside the response", "link_header": "Next-page link in the Link header"}
AUTH = {"none": "No authentication", "bearer": "Bearer token (Authorization: Bearer ...)",
        "header": "Token in a header you name (for example Authorization or X-API-Key)"}
USER_SELECT = "id,displayName,userPrincipalName,mail,accountEnabled,userType,assignedLicenses"

# Ready-made settings for custom applications people often ask about. The admin still pastes their own token.
PRESETS = {
    "monday": {"label": "monday.com (account users)", "config": {
        "url": "https://api.monday.com/v2", "method": "POST", "auth": "header", "header_name": "Authorization",
        "body": '{"query": "{ users(limit: 500, page: {page}) { id name email enabled is_admin is_guest is_view_only } }"}',
        "items_path": "data.users", "paging": "page", "page_param": "page",
        "map": {"account_id": "id", "email": "email", "name": "name", "status": "enabled",
                "role": "is_admin:Admin, is_guest:Guest, is_view_only:Viewer"}}},
    "workos": {"label": "WorkOS (users who sign in to your product)", "config": {
        "url": "https://api.workos.com/user_management/users?limit=100", "method": "GET", "auth": "bearer",
        "items_path": "data", "paging": "cursor", "cursor_path": "list_metadata.after", "cursor_param": "after",
        "map": {"account_id": "id", "email": "email", "name": "first_name", "last_login": "last_sign_in_at"}}},
}


class SourceError(RuntimeError):
    """The application's accounts could not be read completely; the message says what to change."""


# ---------------------------------------------------------------- small helpers
def email(value) -> str:
    text = str(value or "").strip().lower()
    return text if EMAIL_RE.match(text) and "#ext#" not in text else ""


def date(value) -> str:
    """ISO date from an ISO timestamp, a date, or Unix seconds/milliseconds; "" when unknown."""
    if value in (None, "", 0):
        return ""
    if isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e12 else value
        try:
            return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).date().isoformat()
        except (OverflowError, OSError, ValueError):
            return ""
    text = str(value).strip()[:10]
    try:
        return dt.date.fromisoformat(text).isoformat()
    except ValueError:
        return ""


def yesno(value) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value if value is not None else "").strip().lower()
    if text in ("yes", "y", "true", "1", "enabled", "on"):
        return "yes"
    if text in ("no", "n", "false", "0", "disabled", "off"):
        return "no"
    return ""


def row(account_id, email_="", name="", status="active", role="", last_login="", mfa="", service=False) -> dict:
    return {"account_id": str(account_id)[:200], "email": email(email_), "name": str(name or "")[:120],
            "status": str(status or "active").lower()[:30], "role": str(role or "")[:300], "last_login": date(last_login),
            "mfa": yesno(mfa), "is_service_account": "yes" if service else "no", "manager_email": ""}


def need_platform(kind: str, settings) -> None:
    if kind in NEEDS and settings is not None:
        flag, label = NEEDS[kind]
        if not settings.flag(flag):
            raise SourceError(f"{label} collection is turned off. Turn it on under Configuration, then try again")


# ---------------------------------------------------------------- Microsoft Entra ID and Azure
class Microsoft:
    """Graph and Azure reads shared by several applications in one pull, so users are fetched once."""

    def __init__(self, clients):
        self.clients = clients
        self._users: list[dict] | None = None
        self._members: dict[str, list[dict]] = {}
        self.notes: list[str] = []

    def users(self) -> list[dict]:
        if self._users is None:
            try:
                self._users = self.clients.graph_list("/users", {"$select": USER_SELECT + ",signInActivity", "$top": 999})
            except ApiError as exc:
                if exc.status != 403:
                    raise
                self.notes.append("Last sign-in dates need AuditLog.Read.All and Entra ID P1 or P2; they are left empty")
                self._users = self.clients.graph_list("/users", {"$select": USER_SELECT, "$top": 999})
        return self._users

    def by_id(self) -> dict[str, dict]:
        return {u["id"]: u for u in self.users()}

    def group_members(self, group_id: str) -> list[dict]:
        if group_id not in self._members:
            try:
                self._members[group_id] = self.clients.graph_list(
                    f"/groups/{group_id}/transitiveMembers/microsoft.graph.user",
                    {"$select": "id,displayName,userPrincipalName,mail,accountEnabled"})
            except ApiError as exc:
                raise SourceError("A group has access, but its members cannot be read. Grant the Microsoft Graph "
                                  "application permission GroupMember.Read.All (run deploy/azure/grant-permissions.ps1 "
                                  f"again). Details: HTTP {exc.status}") from exc
        return self._members[group_id]


def _last_sign_in(u: dict) -> str:
    s = u.get("signInActivity") or {}
    return s.get("lastSuccessfulSignInDateTime") or s.get("lastSignInDateTime") or ""


def _user_row(u: dict, role: str, mfa: str = "") -> dict:
    return row(u.get("userPrincipalName") or u.get("id"), u.get("mail") or u.get("userPrincipalName"),
               u.get("displayName"), "active" if u.get("accountEnabled", True) else "disabled", role,
               _last_sign_in(u), mfa)


def entra_users(ms: Microsoft, config: dict) -> list[dict]:
    users = ms.users()
    mfa: dict[str, str] = {}
    try:
        for r in ms.clients.graph_list("/reports/authenticationMethods/userRegistrationDetails",
                                       {"$select": "id,isMfaRegistered"}):
            mfa[r["id"]] = "yes" if r.get("isMfaRegistered") else "no"
    except ApiError:
        ms.notes.append("MFA registration needs AuditLog.Read.All and Entra ID P1 or P2; MFA is left empty")
    roles: dict[str, set[str]] = {}
    try:
        names = {d["id"]: d.get("displayName") for d in ms.clients.graph_list(
            "/roleManagement/directory/roleDefinitions", {"$select": "id,displayName"})}
        for a in ms.clients.graph_list("/roleManagement/directory/roleAssignments",
                                       {"$select": "principalId,roleDefinitionId"}):
            roles.setdefault(a.get("principalId"), set()).add(names.get(a.get("roleDefinitionId")) or "Directory role")
    except ApiError:
        ms.notes.append("Admin roles need RoleManagement.Read.Directory; roles show only Member or Guest")
    rows = []
    for u in users:
        kind = "Guest" if u.get("userType") == "Guest" else "Member"
        parts = sorted(roles.get(u["id"], ())) or [kind]
        if roles.get(u["id"]) and kind == "Guest":
            parts.append("Guest")
        parts.append("licensed" if u.get("assignedLicenses") else "no license")
        rows.append(_user_row(u, ", ".join(parts), mfa.get(u["id"], "")))
    return rows


def entra_managers(ms: Microsoft) -> dict[str, str]:
    """person email -> manager email, built from each enabled member's direct reports."""
    out: dict[str, str] = {}
    for u in ms.users():
        manager = email(u.get("mail") or u.get("userPrincipalName"))
        if not manager or not u.get("accountEnabled", True) or u.get("userType") == "Guest":
            continue
        for r in ms.clients.graph_list(f"/users/{u['id']}/directReports", {"$select": "id,mail,userPrincipalName"}):
            person = email(r.get("mail") or r.get("userPrincipalName"))
            if person and person != manager:
                out[person] = manager
    return out


def entra_app(ms: Microsoft, config: dict) -> list[dict]:
    app_id = config.get("app_id", "")
    if not GUID_RE.match(app_id):
        raise SourceError("Enter the application's Application (client) ID from Entra ID > Enterprise applications")
    sps = ms.clients.graph_list("/servicePrincipals", {"$filter": f"appId eq '{app_id.lower()}'",
                                                       "$select": "id,displayName,appRoleAssignmentRequired,appRoles"})
    if not sps:
        raise SourceError("No enterprise application with that Application (client) ID in this tenant")
    sp = sps[0]
    if not sp.get("appRoleAssignmentRequired"):
        raise SourceError(f"“Assignment required” is off for {sp.get('displayName', 'this application')} in Entra ID, so "
                          "every user in the tenant can sign in and the assigned list is not the real population. Turn "
                          "it on (Enterprise applications > Properties), or review the app's own user list instead")
    app_roles = {r["id"]: r.get("displayName") or r.get("value") or "App role" for r in sp.get("appRoles") or []}
    people = ms.by_id()
    found: dict[str, dict] = {}
    for a in ms.clients.graph_list(f"/servicePrincipals/{sp['id']}/appRoleAssignedTo"):
        role = app_roles.get(a.get("appRoleId"), "Default access")
        kind, pid = a.get("principalType"), a.get("principalId")
        if kind == "User":
            targets, via = [people.get(pid) or {"id": pid}], ""
        elif kind == "Group":
            targets, via = ms.group_members(pid), f" (via group {a.get('principalDisplayName') or pid})"
        else:
            found.setdefault(pid, {"svc": a.get("principalDisplayName") or pid, "roles": set()})["roles"].add(role)
            continue
        for t in targets:
            entry = found.setdefault(t["id"], {"user": people.get(t["id"], t), "roles": set()})
            entry["roles"].add(role + via)
    rows = []
    for pid, e in found.items():
        if "svc" in e:
            rows.append(row(pid, "", e["svc"], "active", ", ".join(sorted(e["roles"])), service=True))
        else:
            rows.append(_user_row(e["user"], ", ".join(sorted(e["roles"]))))
    return rows


def azure_rbac(ms: Microsoft, config: dict) -> list[dict]:
    from grcpal.collectors.azure_rbac import ASSIGNMENTS, DEFINITIONS

    names = {d["id"].rsplit("/", 1)[-1]: d["roleName"] for d in ms.clients.arg_query(DEFINITIONS)}
    people = ms.by_id()
    found: dict[str, dict] = {}
    for a in ms.clients.arg_query(ASSIGNMENTS):
        role = names.get(a["roleDefinitionId"].rsplit("/", 1)[-1], "Custom role")
        where = f"{role} @ {a.get('scope') or '/'}"
        kind, pid = a.get("principalType"), a.get("principalId")
        if kind == "User":
            targets, via = [people.get(pid) or {"id": pid, "userPrincipalName": pid, "accountEnabled": True}], ""
        elif kind == "Group":
            targets, via = ms.group_members(pid), f" (via group {pid})"
        else:
            label = "Service principal" if kind == "ServicePrincipal" else "Deleted or unknown identity"
            entry = found.setdefault(pid, {"svc": label, "deleted": kind not in ("ServicePrincipal",), "roles": set()})
            entry["roles"].add(where)
            continue
        for t in targets:
            found.setdefault(t["id"], {"user": people.get(t["id"], t), "roles": set()})["roles"].add(where + via)
    rows = []
    for pid, e in found.items():
        roles = "; ".join(sorted(e["roles"]))
        if "svc" in e:
            rows.append(row(pid, "", e["svc"], "deleted" if e["deleted"] else "active", roles, service=True))
        else:
            rows.append(_user_row(e["user"], roles))
    return rows


# ---------------------------------------------------------------- GitHub
def github_org(clients, config: dict, notes: list[str]) -> list[dict]:
    org = config.get("org", "")
    if not ORG_RE.match(org):
        raise SourceError("Enter the GitHub organization name, for example example-org")
    base = f"/orgs/{org}"
    try:
        members = clients.gh_list(f"{base}/members", {"role": "all"}, max_pages=100, complete=True)
        owners = {m["login"].lower() for m in clients.gh_list(f"{base}/members", {"role": "admin"}, max_pages=100,
                                                              complete=True)}
        collaborators = clients.gh_list(f"{base}/outside_collaborators", None, max_pages=100, complete=True)
    except ApiError as exc:
        raise SourceError(f"GitHub refused the request (HTTP {exc.status}). The token needs the organization permission "
                          "Members: read for this organization") from exc
    try:
        no_2fa = {m["login"].lower() for m in clients.gh_list(f"{base}/members", {"filter": "2fa_disabled"},
                                                              max_pages=100, complete=True)}
        mfa = lambda login: "no" if login.lower() in no_2fa else "yes"  # noqa: E731
    except ApiError:
        notes.append("GitHub shows two-factor status only to organization owners; MFA is left empty")
        mfa = lambda login: ""  # noqa: E731
    rows = []
    for m in members:
        login = m["login"]
        rows.append(row(login, "", login, "active", "Owner" if login.lower() in owners else "Member", "", mfa(login),
                        m.get("type") == "Bot"))
    for c in collaborators:
        rows.append(row(c["login"], "", c["login"], "active", "Outside collaborator", "", "", c.get("type") == "Bot"))
    return rows


# ---------------------------------------------------------------- custom application (REST)
def dig(obj, path: str):
    """Value at a dotted path such as data.users or profile.email; None when missing."""
    for part in (path or "").split("."):
        if not part:
            continue
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list) and part.isdigit() and int(part) < len(obj):
            obj = obj[int(part)]
        else:
            return None
    return obj


def mapped(item: dict, spec: dict) -> dict:
    """One account from one item of the API response, using the admin's field map."""
    def get(field):
        path = (spec.get(field) or "").strip()
        if not path:
            return None
        if path.startswith("!"):
            value = dig(item, path[1:])
            return None if value is None else not (value if isinstance(value, bool) else yesno(value) == "yes")
        return dig(item, path)

    role_spec = (spec.get("role") or "").strip()
    if ":" in role_spec:  # "is_admin:Admin, is_guest:Guest": labels of the true fields, else Member
        labels = [label.strip() for pair in role_spec.split(",") if ":" in pair
                  for path, label in [pair.split(":", 1)] if yesno(dig(item, path.strip())) == "yes"]
        role = ", ".join(labels) or "Member"
    else:
        value = get("role")
        role = ", ".join(map(str, value)) if isinstance(value, list) else ("" if value is None else str(value))
    status = get("status")
    if isinstance(status, bool) or yesno(status) in ("yes", "no") and status not in (None, ""):
        status = "active" if yesno(status) == "yes" else "disabled"
    account = get("account_id")
    if account in (None, ""):
        raise SourceError("An item in the response has no value at the account ID path. Check the field map")
    return row(account, get("email"), get("name"), status or "active", role, get("last_login"), get("mfa"),
               yesno(get("is_service_account")) == "yes")


def validate_rest(config: dict) -> list[str]:
    errors = []
    parts = urlsplit(config.get("url", ""))
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or len(config.get("url", "")) > 500:
        errors.append("The URL must start with https:// and must not contain a user name or password")
    if config.get("method", "GET") not in ("GET", "POST"):
        errors.append("Method must be GET or POST")
    if len(config.get("body", "")) > 4000 or (config.get("body") and config.get("method") != "POST"):
        errors.append("A request body is only for POST and must be under 4,000 characters")
    if config.get("auth", "none") not in AUTH:
        errors.append("Choose how the API checks the token")
    if config.get("auth") == "header" and (not HEADER_RE.match(config.get("header_name", ""))
                                           or config.get("header_name", "").lower() in BLOCKED_HEADERS):
        errors.append("Enter a header name such as Authorization or X-API-Key")
    if config.get("paging", "none") not in PAGING:
        errors.append("Choose how the API pages its results")
    for key in ("items_path", "page_param", "cursor_path", "cursor_param", "next_path"):
        if not PATH_RE.match(config.get(key, "")):
            errors.append(f"{key.replace('_', ' ').capitalize()} has characters that are not allowed")
    for key, value in (config.get("map") or {}).items():
        if key not in MAP_FIELDS or not PATH_RE.match(value or ""):
            errors.append(f"Field map for {key} has characters that are not allowed")
    if not (config.get("map") or {}).get("account_id"):
        errors.append("Say where the account ID is in each item (field map: account ID)")
    paging = config.get("paging", "none")
    if paging == "page" and not config.get("page_param") and "{page}" not in config.get("body", ""):
        errors.append("Page numbers need the page parameter name (or {page} in the POST body)")
    if paging == "cursor" and not (config.get("cursor_path") and (config.get("cursor_param") or "{cursor}" in config.get("body", ""))):
        errors.append("Cursor paging needs where the next cursor is in the response and the parameter to send it in")
    if paging == "next_url" and not config.get("next_path"):
        errors.append("Say where the next-page link is in the response")
    return errors


def _with_param(url: str, name: str, value) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name] + [(name, str(value))]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _next_link(header: str) -> str:
    for part in (header or "").split(","):
        if 'rel="next"' in part and "<" in part and ">" in part:
            return part[part.index("<") + 1:part.index(">")]
    return ""


def redact(url: str) -> str:
    """The URL without its query string: a token someone put in the query never reaches evidence or logs."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def rest_pull(config: dict, token: str, request_fn=None, preview: bool = False, pages: list | None = None) -> list[dict]:
    """Read a custom application's user list. Public HTTPS only (the checks SSRF guard), no redirects (a redirect would
    send the token elsewhere), next-page links must stay on the same host, and every page is read or the pull fails."""
    from grcpal.checks import Blocked, safe_request

    request_fn = request_fn or safe_request
    errors = validate_rest(config)
    if errors:
        raise SourceError("; ".join(errors))
    if config.get("auth", "none") != "none" and not token:
        raise SourceError("The API token is not set for this application")
    origin = urlsplit(config["url"])
    headers = {"Accept": "application/json"}
    if config.get("auth") == "bearer":
        headers["Authorization"] = f"Bearer {token}"
    elif config.get("auth") == "header":
        headers[config["header_name"]] = token
    method, paging = config.get("method", "GET"), config.get("paging", "none")
    if method == "POST":
        headers["Content-Type"] = "application/json"
    url, page, cursor, rows = config["url"], 1, None, []
    for n in range(1, MAX_PAGES + 1):
        target, body = url, config.get("body") or None
        if paging == "page":
            if body and "{page}" in body:
                body = body.replace("{page}", str(page))
            else:
                target = _with_param(url, config["page_param"], page)
        elif paging == "cursor" and cursor is not None:
            if body and "{cursor}" in body:
                body = body.replace("{cursor}", json.dumps(str(cursor))[1:-1])
            else:
                target = _with_param(url, config["cursor_param"], cursor)
        if body and "{cursor}" in body:
            body = body.replace('"{cursor}"', "null").replace("{cursor}", "")
        try:
            resp = request_fn(method, target, headers=headers, body=body, timeout=30, max_bytes=MAX_BYTES, redirects=0)
        except Blocked as exc:
            raise SourceError(f"The request was blocked: {exc}. Only public HTTPS addresses are allowed, and redirects "
                              "are not followed; enter the final URL") from exc
        except OSError as exc:
            raise SourceError(f"The API could not be reached ({type(exc).__name__})") from exc
        if pages is not None:
            pages.append(redact(target))
        if resp.status >= 400:
            raise SourceError(f"The API answered HTTP {resp.status}. Check the URL and the token")
        if getattr(resp, "truncated", False):
            raise SourceError("A response was larger than 5 MB. Use smaller pages")
        try:
            data = json.loads(resp.body)
        except ValueError as exc:
            raise SourceError("The API did not answer with JSON") from exc
        if isinstance(data, dict) and data.get("errors") and not dig(data, config.get("items_path", "")):
            raise SourceError("The API answered with an error. Check the request body and the token")
        items = dig(data, config.get("items_path", ""))
        if not isinstance(items, list):
            raise SourceError("No list of users at the items path. Check where the users are in the response")
        rows.extend(mapped(i, config.get("map") or {}) for i in items if isinstance(i, dict))
        if len(rows) > MAX_ROWS:
            raise SourceError(f"More than {MAX_ROWS} accounts; split the review")
        if preview or paging == "none" or not items:
            return rows
        if paging == "page":
            page += 1
            continue
        if paging == "cursor":
            cursor = dig(data, config["cursor_path"])
            if cursor in (None, ""):
                return rows
            continue
        nxt = dig(data, config["next_path"]) if paging == "next_url" else _next_link(resp.headers.get("link", ""))
        if not nxt:
            return rows
        nxt = urljoin(url, str(nxt))
        parts = urlsplit(nxt)
        if parts.scheme != "https" or parts.hostname != origin.hostname:
            raise SourceError("The next-page link points to a different site; the token is not sent there")
        url = nxt
    raise SourceError(f"More than {MAX_PAGES} pages. Use bigger pages or split the review")

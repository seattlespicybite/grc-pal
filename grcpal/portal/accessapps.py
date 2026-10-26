"""Applications for access reviews: the in-scope systems and where their accounts come from.

Plain model:
- Admins add each application once: a name, an owner (who reviews accounts that have no manager) and a source:
  Microsoft Entra ID / Microsoft 365, an Entra enterprise (SSO) application, Azure, a GitHub organization, a custom
  application's REST API, this portal itself, or a CSV upload. The source settings never include people.
- A custom application's API token is encrypted (AES-GCM, bound to this tenant and this application) and never shown
  again, logged or sent anywhere but that application's host.
- An identity map (account ID -> email) links accounts that do not carry an email, such as GitHub logins, to people.
  It is kept per application and reused every quarter.
- Starting a review pulls every chosen application in the background. If one cannot be read completely, nothing is
  created: an access review on a partial list is an audit finding.
- Admins change applications; auditors see them read-only without secrets; others do not see this page.
  Every change is in the audit log without tokens or people.
"""
from __future__ import annotations

import datetime as dt
import json
import re

from grcpal import accesssources as src
from grcpal.portal.accessreview import (CONTROLS, DISABLED_WORDS, FLAGS, PRIVILEGED, CsvProblem, MAX_ACCOUNTS,
                                        _read_csv, parse_accounts, parse_people)
from grcpal.portal.security import csv_cell

SNAPSHOT_PREFIX = "access-"   # evidence source per application: access-<application id>
FRESH_HOURS = 24              # a review reuses a pull younger than this instead of pulling again
HISTORY = 10                  # pulls shown on the Accounts page
CHANGE_FIELDS = ("email", "status", "role", "mfa")
SNAPSHOT_COLUMNS = ("app", "account_id", "email", "name", "status", "role", "last_login", "mfa", "is_service_account")
ACCOUNT_FLAGS = {**{k: v for k, v in FLAGS.items() if k != "no_reviewer"}, "not_in_directory": "Not found in Entra ID"}
APP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
SINGLE = {"entra_users", "azure_rbac", "grcpal"}      # one application of these kinds is enough
MAX_IDENTITIES = 20000
ROLE_NAMES = {"admin": "Admin", "contributor": "Control owner", "auditor": "Auditor"}
REST_KEYS = ("url", "method", "body", "auth", "header_name", "items_path", "paging", "page_param", "cursor_path",
             "cursor_param", "next_path")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:36] or "app"


def _csv_bytes(app: str, rows: list[dict]) -> bytes:
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    cols = ("app", "account_id", "email", "name", "status", "role", "last_login", "mfa", "is_service_account",
            "manager_email")
    writer.writerow(cols)
    for r in rows:
        writer.writerow([app] + [r.get(c, "") for c in cols[1:]])
    return buf.getvalue().encode("utf-8")


class AccessAppsMixin:
    # ------------------------------------------------------------------ helpers
    def _aa_get(self, aid: str) -> dict:
        row = self.store.get("arapps", "a", aid) if APP_ID_RE.match(aid or "") else None
        if not row:
            raise self._invalid("Application not found")
        return row

    @staticmethod
    def _aa_public(row: dict) -> dict:
        """What pages may show: never the token, only how many identities are mapped."""
        out = {k: v for k, v in row.items() if k not in ("token_enc", "identities")}
        out["token_set"] = bool(row.get("token_enc"))
        out["identity_count"] = len(row.get("identities") or {})
        return out

    def _aa_see(self, user) -> None:
        if user.role not in ("admin", "auditor"):
            raise self._forbidden("Only admins and auditors can see the applications list")

    def _aa_name_free(self, name: str, aid: str = "") -> None:
        if any(a["name"].lower() == name.lower() and a["RowKey"] != aid for a in self.store.list("arapps", "a")):
            raise self._invalid("Another application already has that name")

    # ------------------------------------------------------------------ reading
    def access_apps(self, user, active_only: bool = False) -> list[dict]:
        self._aa_see(user)
        rows = [self._aa_public(a) for a in self.store.list("arapps", "a") if a.get("active", True) or not active_only]
        return sorted(rows, key=lambda a: (not a.get("active", True), a["name"].lower()))

    def access_app(self, user, aid: str) -> dict:
        self._aa_see(user)
        return self._aa_public(self._aa_get(aid))

    def access_review_jobs(self, user) -> list[dict]:
        if not user.is_admin:
            return []
        return self.jobs.recent(3, "access_review")

    # ------------------------------------------------------------------ changing
    def add_access_app(self, actor, name: str, kind: str, owner: str = "", preset: str = "") -> dict:
        self._ar_admin(actor, "add applications")
        name, owner = (name or "").strip(), (owner or "").strip().lower()
        if not name or len(name) > 60:
            raise self._invalid("Give the application a name (up to 60 characters)")
        if kind not in src.KINDS:
            raise self._invalid("Choose where the accounts come from")
        if owner and not src.EMAIL_RE.match(owner):
            raise self._invalid("The owner must be an email address")
        self._aa_name_free(name)
        if kind in SINGLE and any(a["kind"] == kind for a in self.store.list("arapps", "a")):
            raise self._invalid(f"{src.KINDS[kind]} is already in the list")
        config = {}
        if kind == "rest" and preset:
            if preset not in src.PRESETS:
                raise self._invalid("Unknown preset")
            config = json.loads(json.dumps(src.PRESETS[preset]["config"]))
        aid, n = _slug(name), 2
        while self.store.get("arapps", "a", aid):
            aid, n = f"{_slug(name)}-{n}", n + 1
        row = {"PartitionKey": "a", "RowKey": aid, "name": name, "kind": kind, "owner_email": owner, "description": "",
               "config": config, "token_enc": "", "identities": {}, "active": True, "last_test": {},
               "created_by": actor.email, "created_at": _now(), "updated_at": _now()}
        self.store.insert("arapps", row)
        self.audit(actor, "access_review.app.create", aid, {"kind": kind, "preset": preset or "none"})
        return self._aa_public(row)

    def update_access_app(self, actor, aid: str, form: dict, token: str = "", clear_token: bool = False) -> dict:
        """form: name, owner_email, description, active, and the source settings of this kind (strings; for a custom
        application also map_<field>). A blank token keeps the saved one."""
        self._ar_admin(actor, "change applications")
        app = self._aa_get(aid)
        name = (form.get("name") or "").strip()
        owner = (form.get("owner_email") or "").strip().lower()
        if not name or len(name) > 60:
            raise self._invalid("Give the application a name (up to 60 characters)")
        if owner and not src.EMAIL_RE.match(owner):
            raise self._invalid("The owner must be an email address")
        self._aa_name_free(name, aid)
        kind, config = app["kind"], dict(app.get("config") or {})
        if kind == "entra_app":
            config["app_id"] = (form.get("app_id") or "").strip().lower()
            if not src.GUID_RE.match(config["app_id"]):
                raise self._invalid("Enter the Application (client) ID, a value like 00000000-0000-0000-0000-000000000000")
        elif kind == "github_org":
            config["org"] = (form.get("org") or "").strip()
            if not src.ORG_RE.match(config["org"]):
                raise self._invalid("Enter the GitHub organization name, for example example-org")
        elif kind == "rest":
            config = {k: (form.get(k) or "").strip() for k in REST_KEYS}
            config["method"] = config["method"] or "GET"
            config["auth"] = config["auth"] or "none"
            config["paging"] = config["paging"] or "none"
            config["map"] = {f: (form.get(f"map_{f}") or "").strip() for f in src.MAP_FIELDS if (form.get(f"map_{f}") or "").strip()}
            errors = src.validate_rest(config)
            if errors:
                raise self._invalid("; ".join(errors))
        fields = {"name": name, "owner_email": owner, "description": (form.get("description") or "").strip()[:300],
                  "active": str(form.get("active", "true")).lower() in ("true", "on", "1"), "config": config,
                  "updated_at": _now(), "updated_by": actor.email}
        token_change = ""
        if clear_token:
            fields["token_enc"], token_change = "", "cleared"
        elif (token or "").strip():
            if len(token) > 4000:
                raise self._invalid("The token is too long")
            fields["token_enc"] = self.settings_store.seal_secret(f"arapp:{aid}", token.strip())
            token_change = "set"
        changed = sorted(k for k in ("name", "owner_email", "description", "active", "config") if app.get(k) != fields[k])
        self.store.update("arapps", "a", aid, fields)
        self.audit(actor, "access_review.app.update", aid, {"changed": changed, **({"token": token_change} if token_change else {})})
        return self._aa_public({**app, **fields})

    def set_access_app_identities(self, actor, aid: str, data: bytes) -> int:
        """Replace the identity map from a CSV with the columns account_id and email."""
        self._ar_admin(actor, "change applications")
        self._aa_get(aid)
        try:
            names, rows = _read_csv(data, "identity map")
        except CsvProblem as exc:
            raise self._invalid(str(exc)) from exc
        if "account_id" not in names or "email" not in names:
            raise self._invalid("The identity map needs the columns account_id and email")
        if len(rows) > MAX_IDENTITIES:
            raise self._invalid(f"The identity map has more than {MAX_IDENTITIES} rows")
        mapping = {}
        for n, r in enumerate(rows, start=2):
            account, mail = r.get("account_id", "").strip().lower(), r.get("email", "").strip().lower()
            if not account:
                continue
            if not src.EMAIL_RE.match(mail) or len(account) > 200:
                raise self._invalid(f"Identity map row {n}: the email address or account ID is not valid")
            mapping[account] = mail
        self.store.update("arapps", "a", aid, {"identities": mapping, "updated_at": _now(), "updated_by": actor.email})
        self.audit(actor, "access_review.app.identities", aid, {"mapped": len(mapping)})
        return len(mapping)

    # ------------------------------------------------------------------ pulling
    def _aa_pull(self, app: dict, clients, ms, request_fn, notes: list, preview: bool = False, pages=None) -> list[dict]:
        kind, cfg = app["kind"], app.get("config") or {}
        src.need_platform(kind, self.settings)
        if kind == "grcpal":
            rows = [src.row(u["RowKey"], u["RowKey"], u.get("name"), "active" if u.get("active", True) else "disabled",
                            ROLE_NAMES.get(u["role"], u["role"]) + (", control library owner" if u.get("library_owner") else ""),
                            u.get("last_seen", "")) for u in self.users()]
        elif kind == "entra_users":
            rows = src.entra_users(ms(), cfg)
        elif kind == "entra_app":
            rows = src.entra_app(ms(), cfg)
        elif kind == "azure_rbac":
            rows = src.azure_rbac(ms(), cfg)
        elif kind == "github_org":
            rows = src.github_org(clients(), cfg, notes)
        elif kind == "rest":
            token = self.settings_store.open_secret(f"arapp:{app['RowKey']}", app.get("token_enc", ""))
            rows = src.rest_pull(cfg, token, request_fn, preview, pages)
        else:
            raise src.SourceError("This application's accounts come from the CSV you upload when you start a review")
        identities = app.get("identities") or {}
        for r in rows:
            if not r["email"] and r["account_id"].lower() in identities:
                r["email"] = identities[r["account_id"].lower()]
        return rows

    def _aa_clients(self, clients=None):
        """Lazy clients: nothing signs in to Microsoft or GitHub unless an application needs it."""
        cache: dict = {}

        def get_clients():
            if "c" not in cache:
                from grcpal.clients import Clients

                cache["c"] = clients or Clients(self.settings)
            return cache["c"]

        def get_ms():
            if "ms" not in cache:
                cache["ms"] = src.Microsoft(get_clients())
            return cache["ms"]
        return get_clients, get_ms, cache

    def test_access_app(self, actor, aid: str, clients=None, request_fn=None) -> dict:
        """Read the application once (a custom API: first page only) and keep counts, never the accounts."""
        self._ar_admin(actor, "test applications")
        app = self._aa_get(aid)
        get_clients, get_ms, cache = self._aa_clients(clients)
        notes: list[str] = []
        try:
            rows = self._aa_pull(app, get_clients, get_ms, request_fn, notes, preview=True)
            result = {"ok": True, "at": _now(), "records": len(rows), "with_email": sum(1 for r in rows if r["email"]),
                      "service": sum(1 for r in rows if r["is_service_account"] == "yes"),
                      "filled": [f for f in ("email", "name", "role", "last_login", "mfa") if any(r[f] for r in rows)],
                      "first_page_only": app["kind"] == "rest" and (app.get("config") or {}).get("paging", "none") != "none",
                      "notes": notes + (cache["ms"].notes if "ms" in cache else [])}
        except Exception as exc:  # noqa: BLE001 - the message is shown to the admin
            result = {"ok": False, "at": _now(), "error": _plain(exc)}
        self.store.update("arapps", "a", aid, {"last_test": result})
        self.audit(actor, "access_review.app.test", aid, {"ok": result["ok"], "records": result.get("records", 0)})
        return result

    def start_access_review(self, actor, name: str, due: str, app_ids: list[str], accounts: bytes | None = None,
                            people: bytes | None = None, entra_managers: bool = False, clients=None,
                            request_fn=None) -> dict:
        """Start a review from applications (and optionally a CSV) as a background job. Returns the job."""
        self._ar_admin(actor, "start an access review")
        name, due = self._ar_check_start(name, due)
        apps = [self._aa_get(a) for a in dict.fromkeys(app_ids or [])]
        for app in apps:
            if not app.get("active", True):
                raise self._invalid(f"{app['name']} is retired")
            if app["kind"] == "csv":
                raise self._invalid(f"{app['name']} gets its accounts from the CSV upload; put them in the accounts file")
        if not apps and not accounts:
            raise self._invalid("Choose at least one application, or upload an accounts file")
        try:  # check uploaded files now, so a mistake shows at once instead of in the background job
            if accounts:
                parse_accounts(accounts, None, self.today)
            if people:
                parse_people(people)
        except CsvProblem as exc:
            raise self._invalid(str(exc)) from exc
        if self.jobs.running("access_review"):
            raise self._invalid("Another review is being prepared. Wait for it to finish")

        def work(job):
            get_clients, get_ms, cache = self._aa_clients(clients)
            notes: list[str] = []
            pulled, files, sources = {}, {}, []
            for i, app in enumerate(apps):
                job.progress(i, len(apps) + 1, f"Reading {app['name']}")
                fresh = self._aa_fresh_snapshot(app["RowKey"])
                if fresh:  # last night's (or a recent) pull: the review covers exactly that stored list
                    snapshot, rows, pages, pulled_at = fresh
                else:
                    try:
                        snapshot, rows, pages = self._aa_snapshot(actor, app, get_clients, get_ms, request_fn, notes)
                    except Exception as exc:  # noqa: BLE001
                        raise src.SourceError(f"{app['name']}: {_plain(exc)}. Nothing was created") from exc
                    pulled_at = _now()
                sources.append((app, rows))
                pulled[app["name"]] = {"kind": app["kind"], "records": len(rows), "snapshot": snapshot}
                files[f"source_{app['RowKey']}.json"] = json.dumps(
                    {"application": app["name"], "kind": app["kind"], "pulled_at": pulled_at, "records": len(rows),
                     "snapshot": snapshot, "requests": pages, "accounts": rows}, indent=1, sort_keys=True).encode()
            managers: dict[str, str] = {}
            if entra_managers:
                job.progress(len(apps), len(apps) + 1, "Reading managers from Entra ID")
                src.need_platform("entra_users", self.settings)
                managers = src.entra_managers(get_ms())
                files["entra_managers.csv"] = "\r\n".join(["email,manager_email"] + [f"{p},{m}" for p, m in sorted(managers.items())]).encode()
            notes.extend(cache["ms"].notes if "ms" in cache else [])
            rows: list[dict] = []
            try:
                if accounts:
                    rows.extend(parse_accounts(accounts, people, self.today, managers))
                for app, pulled_rows in sources:
                    if pulled_rows:
                        rows.extend(parse_accounts(_csv_bytes(app["name"], pulled_rows), people, self.today, managers))
            except CsvProblem as exc:
                raise src.SourceError(f"{exc}") from exc
            seen = set()
            for r in rows:
                key = (r["app"].lower(), r["account_id"].lower())
                if key in seen:
                    raise src.SourceError(f"{r['app']} lists the same account twice (also check the CSV); nothing was created")
                seen.add(key)
            if not rows:
                raise src.SourceError("No accounts were found; nothing was created")
            if len(rows) > MAX_ACCOUNTS:
                raise src.SourceError(f"{len(rows)} accounts; the limit is {MAX_ACCOUNTS} per review. Split it by application")
            files.update({"accounts.csv": accounts, "people.csv": people})
            camp = self._ar_create(actor, name, due, rows, files, pulled,
                                   {a["name"]: a.get("owner_email", "") for a in apps}, sorted(set(notes)))
            return {"campaign": camp["RowKey"], "records": camp["records"],
                    "without_account": len(camp["reviewers_without_account"]), "notes": camp["pull_notes"]}

        return self.jobs.submit("access_review", f"Start access review: {name}", actor.email, work)

    # ------------------------------------------------------------------ daily account snapshots
    def _aa_last_ok(self, aid: str) -> tuple[str, dict] | None:
        """The newest successful snapshot run of one application and its manifest."""
        source = snapshot_source(aid)
        for run in reversed(self.evidence.list_runs(source)):
            raw = self.evidence.read(source, run, "manifest.json")
            manifest = json.loads(raw) if raw else {}
            if manifest.get("status") == "ok":
                return run, manifest
        return None

    def _aa_snapshot_file(self, aid: str, run: str, name: str, default):
        raw = self.evidence.read(snapshot_source(aid), run, name)
        return json.loads(raw) if raw else default

    def _aa_fresh_snapshot(self, aid: str):
        """(snapshot path, rows, requests, pulled at) when the last good pull is under FRESH_HOURS old, else None."""
        last = self._aa_last_ok(aid)
        if not last:
            return None
        run, manifest = last
        started = dt.datetime.fromisoformat(manifest["started"])
        if dt.datetime.now(dt.timezone.utc) - started > dt.timedelta(hours=FRESH_HOURS):
            return None
        return (f"{snapshot_source(aid)}/{run}", self._aa_snapshot_file(aid, run, "accounts.json", []),
                self._aa_snapshot_file(aid, run, "requests.json", []), manifest["started"])

    def _aa_snapshot(self, actor, app: dict, get_clients, get_ms, request_fn, notes: list) -> tuple[str, list, list]:
        """Pull one application and store the full list write-once with what changed since the last good pull.
        A failed or partial pull is stored as a failed run (calendar and failure email show it) and raises: nothing
        partial is ever kept."""
        aid, source = app["RowKey"], snapshot_source(app["RowKey"])
        previous = self._aa_last_ok(aid)
        run = self.evidence.new_run(source, CONTROLS, {"application": app["name"], "kind": app["kind"],
                                                        "description": "Daily account list for access reviews"})
        taken = set(self.evidence.list_runs(source))
        while run.prefix.split("/", 1)[1] in taken:  # one folder per second
            run.started += dt.timedelta(seconds=1)
        pages: list[str] = []
        mine: list[str] = []
        try:
            rows = self._aa_pull(app, get_clients, get_ms, request_fn, mine, pages=pages)
            if rows:  # the same checks a review applies, so a stored list can always start a review
                parse_accounts(_csv_bytes(app["name"], rows), None, self.today)
        except Exception as exc:  # noqa: BLE001 - recorded, then raised to the caller
            message = _plain(exc)
            run.finish([], status="error", error=message)
            self.store.update("arapps", "a", aid, {"last_pull": {"ok": False, "at": _now(), "run": run.prefix,
                                                                  "error": message}})
            self.audit(actor, "access_review.pull", aid, {"ok": False})
            raise src.SourceError(message) from exc
        notes.extend(mine)
        old = self._aa_snapshot_file(aid, previous[0], "accounts.json", []) if previous else []
        changes = diff_accounts(old, rows)
        changes["previous"] = f"{source}/{previous[0]}" if previous else ""
        counts = {"records": len(rows), "added": len(changes["added"]), "removed": len(changes["removed"]),
                  "changed": len(changes["changed"])}
        run.meta.update({**counts, "notes": mine})
        run.add_bytes("accounts.json", json.dumps(rows, indent=1, sort_keys=True).encode())
        run.add_bytes("accounts.csv", evidence_csv(app["name"], rows))
        run.add_bytes("changes.json", json.dumps(changes, indent=1, sort_keys=True).encode())
        run.add_bytes("requests.json", json.dumps(pages).encode())
        run.finish(snapshot_findings(rows))
        self.store.update("arapps", "a", aid, {"last_pull": {"ok": True, "at": _now(), "run": run.prefix, **counts}})
        self.audit(actor, "access_review.pull", aid, {"ok": True, **counts})
        return run.prefix, rows, pages

    def pull_access_snapshots(self, actor, app_ids: list[str] | None = None, clients=None, request_fn=None) -> list[dict]:
        """Pull every active application that has an API source (the nightly job), or the chosen ones. One failing
        application never stops the others. Returns one result per application, without people."""
        self._ar_admin(actor, "pull accounts")
        apps = [a for a in self.store.list("arapps", "a") if a.get("active", True) and a["kind"] != "csv"]
        if app_ids is not None:
            wanted = set(app_ids)
            apps = [a for a in apps if a["RowKey"] in wanted]
        get_clients, get_ms, _ = self._aa_clients(clients)
        results = []
        for app in sorted(apps, key=lambda a: a["RowKey"]):
            try:
                path, rows, _ = self._aa_snapshot(actor, app, get_clients, get_ms, request_fn, [])
                results.append({"app": app["name"], "ok": True, "run": path, "records": len(rows)})
            except Exception as exc:  # noqa: BLE001 - recorded as a failed run; carry on with the others
                results.append({"app": app["name"], "ok": False, "error": _plain(exc)})
        return results

    def request_access_pull(self, actor, aid: str = "", clients=None, request_fn=None) -> dict:
        """The Pull now button: pull one application (or all) in the background."""
        self._ar_admin(actor, "pull accounts")
        ids = [self._aa_get(aid)["RowKey"]] if aid else None
        if self.jobs.running("access_pull"):
            raise self._invalid("A pull is already running. Wait for it to finish")

        def work(job):
            results = self.pull_access_snapshots(actor, ids, clients, request_fn)
            failed = [r for r in results if not r["ok"]]
            if failed:
                raise src.SourceError("; ".join(f"{r['app']}: {r['error']}" for r in failed))
            return {"pulled": len(results)}

        return self.jobs.submit("access_pull", "Pull accounts now", actor.email, work)

    def access_accounts(self, user, aid: str = "") -> dict:
        """The Accounts page: every application's last pull, and for the chosen one its current accounts with flags,
        what changed in the last pull, and the recent pull history. Admins and auditors only."""
        self._aa_see(user)
        apps = [self._aa_public(a) for a in self.store.list("arapps", "a") if a["kind"] != "csv"]
        apps.sort(key=lambda a: (not a.get("active", True), a["name"].lower()))
        out = {"apps": apps, "selected": None, "jobs": self.jobs.recent(3, "access_pull") if user.is_admin else []}
        if not aid:
            return out
        app = self._aa_get(aid)
        if app["kind"] == "csv":
            raise self._invalid("This application's accounts come from a CSV upload, so there are no daily pulls")
        last = self._aa_last_ok(aid)
        rows = self._aa_snapshot_file(aid, last[0], "accounts.json", []) if last else []
        directory = None
        entra = next((a for a in self.store.list("arapps", "a") if a["kind"] == "entra_users" and a["RowKey"] != aid), None)
        elast = self._aa_last_ok(entra["RowKey"]) if entra else None
        if elast:
            directory = {r["email"] for r in self._aa_snapshot_file(entra["RowKey"], elast[0], "accounts.json", [])
                         if r["email"]}
        flagged = parse_accounts(_csv_bytes(app["name"], rows), None, self.today) if rows else []
        accounts = []
        for r in flagged:
            flags = [f for f in r["flags"] if f != "no_reviewer"]
            if directory is not None and not r["service"] and r["email"] not in directory:
                flags.append("not_in_directory")
            accounts.append({**r, "flags": flags})
        accounts.sort(key=lambda r: (not r["flags"], r["account_id"].lower()))
        history = []
        source = snapshot_source(aid)
        for run in list(reversed(self.evidence.list_runs(source)))[:HISTORY]:
            raw = self.evidence.read(source, run, "manifest.json")
            m = json.loads(raw) if raw else {}
            history.append({"run": run, "status": m.get("status", "error"), "records": m.get("records"),
                            "added": m.get("added"), "removed": m.get("removed"), "changed": m.get("changed"),
                            "error": m.get("error") or ""})
        out["selected"] = {"app": self._aa_public(app), "run": f"{source}/{last[0]}" if last else "",
                           "pulled_at": last[1]["started"] if last else "", "accounts": accounts,
                           "changes": self._aa_snapshot_file(aid, last[0], "changes.json", {}) if last else {},
                           "history": history, "directory": directory is not None}
        return out


def snapshot_source(aid: str) -> str:
    """Evidence source of one application's daily account lists."""
    return f"{SNAPSHOT_PREFIX}{aid}"


def diff_accounts(old: list[dict], new: list[dict]) -> dict:
    """What changed between two pulls of one application: account IDs added and removed, and field changes."""
    before = {r["account_id"].lower(): r for r in old}
    after = {r["account_id"].lower(): r for r in new}
    changed = []
    for key in sorted(before.keys() & after.keys()):
        for f in CHANGE_FIELDS:
            if (before[key].get(f) or "") != (after[key].get(f) or ""):
                changed.append({"account_id": after[key]["account_id"], "field": f, "before": before[key].get(f) or "",
                                "after": after[key].get(f) or ""})
    return {"added": sorted(after[k]["account_id"] for k in after.keys() - before.keys()),
            "removed": sorted(before[k]["account_id"] for k in before.keys() - after.keys()), "changed": changed}


def snapshot_findings(rows: list[dict]) -> list[dict]:
    """Findings for the run manifest: counts only, never people (manifests show on the calendar and in emails)."""
    risky = sum(1 for r in rows if r.get("mfa") == "no" and r.get("status") not in DISABLED_WORDS
                and PRIVILEGED.search(r.get("role") or ""))
    if not risky:
        return []
    return [{"key": "privileged_without_mfa", "severity": "high",
             "title": f"{risky} admin-type account{'s' if risky != 1 else ''} without MFA",
             "detail": "Open Access reviews > Accounts to see which accounts"}]


def evidence_csv(app: str, rows: list[dict]) -> bytes:
    """The stored account list as CSV for auditors, safe against spreadsheet formula injection."""
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(SNAPSHOT_COLUMNS)
    for r in rows:
        writer.writerow([csv_cell(app)] + [csv_cell(r.get(c, "")) for c in SNAPSHOT_COLUMNS[1:]])
    return buf.getvalue().encode("utf-8")


def _plain(exc: Exception) -> str:
    """A short message for people. API errors keep the status but not response bodies, URLs or tokens."""
    from grcpal.clients import ApiError

    if isinstance(exc, src.SourceError):
        return str(exc)
    if isinstance(exc, ApiError):
        return f"the platform refused the request (HTTP {exc.status}); check the permissions in docs/access-reviews.md"
    return f"{type(exc).__name__}: {str(exc)[:200]}"

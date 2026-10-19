"""Access review campaigns (SOC 2 CC6.2 and CC6.3, control IAM-05).

Plain model:
- An admin starts a campaign by uploading a CSV of accounts exported from any system (GitHub, Slack, a database,
  a SaaS admin console ...). Optionally a second CSV (email, manager_email) says who manages whom. The files
  are kept write-once in the evidence store with a SHA-256: that is the proof of which list was reviewed.
  The whole import is refused if any row is wrong, so a campaign never starts from a partial list.
- Each account goes to one reviewer, the account holder's manager. Accounts with no manager, service accounts
  and accounts whose manager is the account holder have no reviewer until an admin assigns one. Nobody can
  review their own account: not by import, not by assignment.
- Managers sign in as Control owners (or admins). A manager sees only the accounts assigned to them, across
  all applications on one screen, and decides keep, remove or change for each. Accounts that deserve a closer
  look are flagged (admin-type role, no MFA, no sign-in for 90 days, disabled but still present, service account).
- When all of a manager's accounts are decided, the manager signs off. That locks their decisions; an admin
  can reopen a sign-off, and every change is in the hash-chained audit log.
- Removals and changes are tracked until an admin confirms they were done. The campaign can be closed once every
  account has a reviewer, a decision and a sign-off; closing with unconfirmed removals needs a written reason.
  Closing stores the result (decisions CSV and summary) write-once in the evidence store.
- Who sees what: admins and auditors see every account (auditors read-only); managers see only their own.
  Audit log entries name the campaign, the application and the entry number, never people.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import re
import uuid

from grcpal.portal.security import MAX_UPLOAD_BYTES, csv_cell

CONTROLS = ["IAM-05"]
DECISIONS = {"keep": "Keep", "revoke": "Remove access", "modify": "Change access"}
FLAGS = {"privileged": "Admin-type role", "no_mfa": "No MFA", "inactive": "No sign-in for 90+ days",
         "disabled": "Disabled but still listed", "service": "Service account",
         "no_reviewer": "Needs a reviewer"}
STATUS = {"open": "Open", "closed": "Closed"}
COLUMNS = ("app", "account_id", "email", "name", "status", "role", "last_login", "mfa", "is_service_account",
           "manager_email")
TEMPLATE_CSV = ("app,account_id,email,name,status,role,last_login,mfa,is_service_account,manager_email\r\n"
                "GitHub,jdoe,jdoe@example.com,Jane Doe,active,member,2026-09-30,yes,no,boss@example.com\r\n")
MAX_ACCOUNTS = 2000          # per campaign: every account is one stored row
MAX_PEOPLE = 20000
INACTIVE_DAYS = 90
MAX_PROBLEMS_SHOWN = 10
DISABLED_WORDS = {"disabled", "suspended", "deactivated", "inactive", "deprovisioned", "locked", "blocked"}
YES = {"yes", "y", "true", "1", "enabled", "on"}
NO = {"no", "n", "false", "0", "disabled", "off"}
PRIVILEGED = re.compile(r"admin|owner|root|superuser|super user|maintain|full control|global", re.I)
EMAIL_RE = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ID_RE = re.compile(r"^\d{8}-[0-9a-f]{6}$")
ENTRY_RE = re.compile(r"^\d{5}$")
PACK_COLUMNS = ("campaign", "app", "account_id", "email", "name", "status", "role", "last_login", "mfa",
                "service_account", "flags", "reviewer", "decision", "comment", "decided_by", "decided_at",
                "remediation", "remediation_note", "remediated_by", "remediated_at")


class CsvProblem(ValueError):
    """The uploaded file cannot be used; the message says what to fix."""


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _header(name: str) -> str:
    return re.sub(r"[\s\-]+", "_", (name or "").strip().lower())


def _read_csv(data: bytes, what: str) -> tuple[list[str], list[dict]]:
    if len(data) > MAX_UPLOAD_BYTES:
        raise CsvProblem(f"The {what} file is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CsvProblem(f"The {what} file must be UTF-8 text (save it as CSV UTF-8)") from exc
    try:
        reader = csv.reader(io.StringIO(text))
        header = next(reader, None)
        if header is None:
            raise CsvProblem(f"The {what} file is empty")
        names = [_header(h) for h in header]
        rows = [dict(zip(names, [c.strip() for c in r])) for r in reader if any(c.strip() for c in r)]
    except csv.Error as exc:
        raise CsvProblem(f"The {what} file is not a valid CSV: {exc}") from exc
    return names, rows


def parse_people(data: bytes) -> dict[str, str]:
    """email -> manager email, from a CSV with the columns email and manager_email."""
    names, rows = _read_csv(data, "people")
    if "email" not in names or "manager_email" not in names:
        raise CsvProblem("The people file needs the columns email and manager_email")
    if len(rows) > MAX_PEOPLE:
        raise CsvProblem(f"The people file has more than {MAX_PEOPLE} rows")
    out: dict[str, str] = {}
    for n, row in enumerate(rows, start=2):
        email, manager = row.get("email", "").lower(), row.get("manager_email", "").lower()
        if not email:
            continue
        if not EMAIL_RE.match(email) or (manager and not EMAIL_RE.match(manager)):
            raise CsvProblem(f"People file row {n}: an email address is not valid")
        if email in out and out[email] != manager:
            raise CsvProblem(f"People file row {n}: this person is listed with two different managers")
        out[email] = manager
    return out


def parse_accounts(data: bytes, people: bytes | None, today: dt.date) -> list[dict]:
    """Validate the accounts CSV and return one normalized record per account. Raises CsvProblem listing the first
    problems; nothing is imported unless every row is valid."""
    names, rows = _read_csv(data, "accounts")
    missing = [c for c in ("app", "account_id") if c not in names]
    if missing:
        found = ", ".join(n for n in names if n) or "none"
        raise CsvProblem(f"Missing column: {', '.join(missing)}. Columns found: {found}")
    if not rows:
        raise CsvProblem("The accounts file has no rows")
    if len(rows) > MAX_ACCOUNTS:
        raise CsvProblem(f"The accounts file has {len(rows)} rows; the limit is {MAX_ACCOUNTS} per campaign. "
                         "Split it by application.")
    managers = parse_people(people) if people else {}
    problems: list[str] = []
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for n, row in enumerate(rows, start=2):
        app, account = row.get("app", ""), row.get("account_id", "")
        if not app or not account:
            problems.append(f"Row {n}: app and account_id are both required")
            continue
        if len(app) > 60 or len(account) > 200:
            problems.append(f"Row {n}: app or account_id is too long")
            continue
        if (app.lower(), account.lower()) in seen:
            problems.append(f"Row {n}: the same account is listed twice for {app}")
            continue
        seen.add((app.lower(), account.lower()))
        email, manager = row.get("email", "").lower(), row.get("manager_email", "").lower()
        if (email and not EMAIL_RE.match(email)) or (manager and not EMAIL_RE.match(manager)):
            problems.append(f"Row {n}: an email address is not valid")
            continue
        last = row.get("last_login", "")
        last_date = None
        if last:
            try:
                last_date = dt.date.fromisoformat(last[:10]) if DATE_RE.match(last[:10]) else None
            except ValueError:
                last_date = None
            if last_date is None:
                problems.append(f"Row {n}: last_login must start with a date like 2026-09-30")
                continue
        mfa = row.get("mfa", "").lower()
        if mfa and mfa not in YES | NO:
            problems.append(f"Row {n}: mfa must be yes or no (or empty)")
            continue
        service_text = row.get("is_service_account", "").lower()
        if service_text and service_text not in YES | NO:
            problems.append(f"Row {n}: is_service_account must be yes or no (or empty)")
            continue
        service = service_text in YES
        status = row.get("status", "").lower()[:30] or "active"
        manager = manager or managers.get(email, "")
        reviewer = manager if manager and manager != email and not service else ""
        flags = []
        if service:
            flags.append("service")
        if status in DISABLED_WORDS:
            flags.append("disabled")
        if PRIVILEGED.search(row.get("role", "")):
            flags.append("privileged")
        if mfa in NO:
            flags.append("no_mfa")
        if last_date and status not in DISABLED_WORDS and (today - last_date).days >= INACTIVE_DAYS:
            flags.append("inactive")
        if not reviewer:
            flags.append("no_reviewer")
        out.append({"app": app, "account_id": account, "email": email, "name": row.get("name", "")[:120],
                    "status": status, "role": row.get("role", "")[:120], "last_login": last_date.isoformat() if last_date else "",
                    "mfa": "yes" if mfa in YES else ("no" if mfa in NO else ""), "service": service,
                    "manager_email": manager, "reviewer": reviewer, "flags": flags})
    if problems:
        more = f" ({len(problems) - MAX_PROBLEMS_SHOWN} more)" if len(problems) > MAX_PROBLEMS_SHOWN else ""
        raise CsvProblem("Nothing was imported. " + "; ".join(problems[:MAX_PROBLEMS_SHOWN]) + more)
    return out


def pack_csv(campaign_id: str, entries: list[dict]) -> bytes:
    """The auditor's decisions file. Every cell is checked against spreadsheet formula injection."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(PACK_COLUMNS)
    for e in entries:
        writer.writerow([csv_cell(v) for v in (
            campaign_id, e["app"], e["account_id"], e.get("email", ""), e.get("name", ""), e.get("status", ""),
            e.get("role", ""), e.get("last_login", ""), e.get("mfa", ""), "yes" if e.get("service") else "no",
            ";".join(e.get("flags") or []), e.get("reviewer", ""), e.get("decision", ""), e.get("comment", ""),
            e.get("decided_by", ""), e.get("decided_at", ""), e.get("remediation", ""), e.get("remediation_note", ""),
            e.get("remediated_by", ""), e.get("remediated_at", ""))])
    return buf.getvalue().encode("utf-8")


def progress(entries: list[dict]) -> dict:
    out = {"total": len(entries), "decided": 0, "keep": 0, "revoke": 0, "modify": 0, "unassigned": 0, "to_confirm": 0}
    for e in entries:
        out["unassigned"] += 0 if e.get("reviewer") else 1
        if e.get("decision"):
            out["decided"] += 1
            out[e["decision"]] += 1
        if e.get("remediation") == "open":
            out["to_confirm"] += 1
    return out


class AccessReviewMixin:
    # ------------------------------------------------------------------ helpers
    def _ar_admin(self, actor, what: str = "manage access reviews") -> None:
        if not actor.is_admin:
            raise self._forbidden(f"Only admins can {what}")

    def _ar_campaign(self, cid: str) -> dict:
        row = self.store.get("arcampaigns", "c", cid) if ID_RE.match(cid or "") else None
        if not row:
            raise self._invalid("Review not found")
        return row

    def _ar_open(self, camp: dict) -> None:
        if camp["status"] != "open":
            raise self._invalid("This review is closed; its decisions can no longer change")

    def _ar_entries(self, cid: str) -> list[dict]:
        return sorted(self.store.list("arentries", cid), key=lambda e: e["RowKey"])

    def _ar_entry(self, cid: str, eid: str) -> dict:
        row = self.store.get("arentries", cid, eid) if ENTRY_RE.match(eid or "") else None
        if not row:
            raise self._invalid("Account not found in this review")
        return row

    def _ar_refresh_reviewers(self, cid: str) -> None:
        reviewers = sorted({e["reviewer"] for e in self._ar_entries(cid) if e.get("reviewer")})
        self.store.update("arcampaigns", "c", cid, {"reviewers": reviewers})

    def _ar_can_review(self, email: str) -> bool:
        row = self.user_row(email)
        return bool(row and row.get("active", True) and row.get("role") in ("admin", "contributor"))

    def access_reviewer_choices(self, actor) -> list[dict]:
        self._ar_admin(actor)
        return [{"email": u["RowKey"], "name": u.get("name") or u["RowKey"]} for u in self.users()
                if u.get("active", True) and u["role"] in ("admin", "contributor")]

    # ------------------------------------------------------------------ start a campaign
    def create_access_campaign(self, actor, name: str, due: str, accounts: bytes, people: bytes | None = None) -> dict:
        self._ar_admin(actor, "start an access review")
        name = (name or "").strip()
        if not name or len(name) > 120:
            raise self._invalid("Give the review a name (up to 120 characters), for example “Q4 2026 user access review”")
        if not DATE_RE.match(due or "") or dt.date.fromisoformat(due) < self.today:
            raise self._invalid("The due date must be today or later (YYYY-MM-DD)")
        try:
            rows = parse_accounts(accounts, people or None, self.today)
        except CsvProblem as exc:
            raise self._invalid(str(exc)) from exc
        cid = f"{self.today:%Y%m%d}-{uuid.uuid4().hex[:6]}"
        run = self.evidence.new_run("access_review_snapshot", CONTROLS,
                                    {"campaign": cid, "campaign_name": name, "created_by": actor.email,
                                     "records": len(rows)})
        taken = set(self.evidence.list_runs("access_review_snapshot"))
        while run.prefix.split("/", 1)[1] in taken:  # one folder per second
            run.started += dt.timedelta(seconds=1)
        run.add_bytes("accounts.csv", accounts)
        if people:
            run.add_bytes("people.csv", people)
        manifest = run.finish([])
        sha = manifest["files"][0]["sha256"]
        apps: dict[str, int] = {}
        for r in rows:
            apps[r["app"]] = apps.get(r["app"], 0) + 1
        reviewers = sorted({r["reviewer"] for r in rows if r["reviewer"]})
        camp = {"PartitionKey": "c", "RowKey": cid, "name": name, "due": due, "status": "open",
                "created_by": actor.email, "created_at": _now(), "snapshot_run": run.prefix, "snapshot_sha256": sha,
                "records": len(rows), "summary": apps, "reviewers": reviewers, "attestations": {}}
        self.store.insert("arcampaigns", camp)
        for i, r in enumerate(rows, start=1):
            self.store.insert("arentries", {"PartitionKey": cid, "RowKey": f"{i:05d}", **r, "decision": "", "comment": "",
                                            "decided_by": "", "decided_at": "", "remediation": "", "remediation_note": "",
                                            "remediated_by": "", "remediated_at": ""})
        self.audit(actor, "access_review.create", cid, {"name": name, "records": len(rows), "applications": len(apps),
                                                         "reviewers": len(reviewers), "snapshot_sha256": sha,
                                                         "unassigned": sum(1 for r in rows if not r["reviewer"])})
        no_account = [e for e in reviewers if not self._ar_can_review(e)]
        return {**camp, "reviewers_without_account": no_account}

    # ------------------------------------------------------------------ reading
    def access_campaigns(self, user) -> list[dict]:
        me = user.email.lower()
        rows = []
        for c in self.store.list("arcampaigns", "c"):
            if user.role in ("admin", "auditor"):
                rows.append(c)
            elif me in (c.get("reviewers") or []):
                rows.append(c)
        return sorted(rows, key=lambda c: c["created_at"], reverse=True)

    def access_review_badge(self, user) -> int:
        """Open reviews waiting for this person (admins: every open review). Shown in the menu."""
        if user.is_auditor:
            return 0
        me = user.email.lower()
        count = 0
        for c in self.store.list("arcampaigns", "c"):
            if c["status"] != "open":
                continue
            if user.is_admin or (me in (c.get("reviewers") or []) and me not in (c.get("attestations") or {})):
                count += 1
        return count

    def access_campaign(self, user, cid: str) -> dict:
        camp = self._ar_campaign(cid)
        entries = self._ar_entries(cid)
        me = user.email.lower()
        sees_all = user.role in ("admin", "auditor")
        mine = [e for e in entries if e.get("reviewer") == me]
        if not sees_all and not mine:
            raise self._invalid("Review not found")  # not visible and not found look the same
        order = lambda e: (not e["flags"], e["app"].lower(), e["account_id"].lower())  # noqa: E731
        att = camp.get("attestations") or {}
        view = {"campaign": camp, "mine": sorted(mine, key=order), "progress_mine": progress(mine),
                "signed_off": att.get(me), "locked": camp["status"] != "open" or me in att,
                "sees_all": sees_all}
        if sees_all:
            by_reviewer: dict[str, list[dict]] = {}
            for e in entries:
                if e.get("reviewer"):
                    by_reviewer.setdefault(e["reviewer"], []).append(e)
            view.update(
                entries=sorted(entries, key=order), progress=progress(entries),
                reviewers=[{"email": r, "progress": progress(es), "signed_off": att.get(r),
                            "has_account": self._ar_can_review(r)} for r, es in sorted(by_reviewer.items())],
                unassigned=[e for e in entries if not e.get("reviewer")],
                to_confirm=[e for e in entries if e.get("remediation") == "open"])
        return view

    # ------------------------------------------------------------------ decisions
    def save_access_decisions(self, actor, cid: str, decisions: dict) -> int:
        """decisions: {entry id: {"decision": keep|revoke|modify|"", "comment": text}}. Returns how many changed."""
        camp = self._ar_campaign(cid)
        self._ar_open(camp)
        me = actor.email.lower()
        if not actor.can_write:
            raise self._forbidden("Your role cannot make review decisions")
        if me in (camp.get("attestations") or {}):
            raise self._invalid("You already signed off this review. Ask an admin to reopen it to change a decision")
        changed = 0
        for eid, d in decisions.items():
            e = self._ar_entry(cid, eid)
            if e.get("reviewer") != me or e.get("email") == me:
                raise self._forbidden("This account is not assigned to you for review")
            decision = (d.get("decision") or "").strip()
            comment = (d["comment"] if "comment" in d else e.get("comment", "")).strip()[:500]
            if decision and decision not in DECISIONS:
                raise self._invalid("Choose keep, remove or change for each account")
            if decision == "modify" and not comment:
                raise self._invalid("Say what should change when you choose “Change access”")
            if decision == e.get("decision", "") and comment == e.get("comment", ""):
                continue
            fields = {"decision": decision, "comment": comment, "decided_by": me if decision else "",
                      "decided_at": _now() if decision else "",
                      "remediation": "open" if decision in ("revoke", "modify") else "",
                      "remediation_note": "", "remediated_by": "", "remediated_at": ""}
            self.store.update("arentries", cid, eid, fields)
            self.audit(actor, "access_review.decide", f"{cid}/{eid}",
                       {"application": e["app"], "decision": decision or "cleared", "previous": e.get("decision") or "none"})
            changed += 1
        return changed

    def attest_access(self, actor, cid: str) -> dict:
        camp = self._ar_campaign(cid)
        self._ar_open(camp)
        me = actor.email.lower()
        mine = [e for e in self._ar_entries(cid) if e.get("reviewer") == me]
        if not actor.can_write or not mine:
            raise self._forbidden("You have no accounts to sign off in this review")
        att = dict(camp.get("attestations") or {})
        if me in att:
            raise self._invalid("You already signed off this review")
        left = sum(1 for e in mine if not e.get("decision"))
        if left:
            raise self._invalid(f"{left} account{'s' if left != 1 else ''} still need a decision")
        stats = progress(mine)
        att[me] = {"at": _now(), "accounts": stats["total"], "keep": stats["keep"], "revoke": stats["revoke"],
                   "modify": stats["modify"]}
        self.store.update("arcampaigns", "c", cid, {"attestations": att})
        self.audit(actor, "access_review.signoff", cid, att[me])
        return att[me]

    def reopen_access_signoff(self, actor, cid: str, reviewer: str) -> None:
        self._ar_admin(actor)
        camp = self._ar_campaign(cid)
        self._ar_open(camp)
        att = dict(camp.get("attestations") or {})
        if (reviewer or "").lower() not in att:
            raise self._invalid("That reviewer has not signed off")
        del att[reviewer.lower()]
        self.store.update("arcampaigns", "c", cid, {"attestations": att})
        self.audit(actor, "access_review.reopen", cid, {"reviewers_reopened": 1})

    def assign_access_reviewer(self, actor, cid: str, eid: str, reviewer: str) -> None:
        self._ar_admin(actor)
        camp = self._ar_campaign(cid)
        self._ar_open(camp)
        e = self._ar_entry(cid, eid)
        reviewer = (reviewer or "").strip().lower()
        if not EMAIL_RE.match(reviewer):
            raise self._invalid("Choose a reviewer")
        if reviewer == e.get("email"):
            raise self._invalid("The reviewer cannot be the account holder")
        if not self._ar_can_review(reviewer):
            raise self._invalid("The reviewer must be an active admin or Control owner in this portal")
        if reviewer in (camp.get("attestations") or {}):
            raise self._invalid("That reviewer already signed off. Reopen their sign-off first")
        flags = [f for f in e.get("flags") or [] if f != "no_reviewer"]
        self.store.update("arentries", cid, eid, {
            "reviewer": reviewer, "flags": flags, "decision": "", "comment": "", "decided_by": "", "decided_at": "",
            "remediation": "", "remediation_note": "", "remediated_by": "", "remediated_at": ""})
        self._ar_refresh_reviewers(cid)
        self.audit(actor, "access_review.assign", f"{cid}/{eid}", {"application": e["app"],
                                                                    "previous": "set" if e.get("reviewer") else "none"})

    def confirm_access_change(self, actor, cid: str, eid: str, note: str) -> None:
        """An admin confirms a removal or change was made in the application."""
        self._ar_admin(actor)
        self._ar_open(self._ar_campaign(cid))
        e = self._ar_entry(cid, eid)
        note = (note or "").strip()[:500]
        if e.get("remediation") != "open":
            raise self._invalid("Nothing to confirm for this account")
        if not note:
            raise self._invalid("Say how it was done, for example “Removed in the GitHub org settings on 2026-10-20”")
        self.store.update("arentries", cid, eid, {"remediation": "done", "remediation_note": note,
                                                  "remediated_by": actor.email.lower(), "remediated_at": _now()})
        self.audit(actor, "access_review.confirm", f"{cid}/{eid}", {"application": e["app"], "decision": e["decision"]})

    # ------------------------------------------------------------------ close and export
    def close_access_campaign(self, actor, cid: str, note: str = "") -> dict:
        self._ar_admin(actor)
        camp = self._ar_campaign(cid)
        self._ar_open(camp)
        entries = self._ar_entries(cid)
        note = (note or "").strip()[:500]
        no_reviewer = sum(1 for e in entries if not e.get("reviewer"))
        if no_reviewer:
            raise self._invalid(f"{no_reviewer} account{'s have' if no_reviewer != 1 else ' has'} no reviewer yet. Assign one first")
        undecided = sum(1 for e in entries if not e.get("decision"))
        if undecided:
            raise self._invalid(f"{undecided} account{'s are' if undecided != 1 else ' is'} still undecided")
        att = camp.get("attestations") or {}
        waiting = [r for r in camp.get("reviewers") or [] if r not in att]
        if waiting:
            raise self._invalid(f"{len(waiting)} reviewer{'s have' if len(waiting) != 1 else ' has'} not signed off yet")
        stats = progress(entries)
        if stats["to_confirm"] and not note:
            raise self._invalid(f"{stats['to_confirm']} removal{'s or changes are' if stats['to_confirm'] != 1 else ' or change is'} "
                                "not confirmed. Confirm them, or write why the review closes with open items")
        pack = pack_csv(cid, entries)
        run = self.evidence.new_run("access_review_result", CONTROLS,
                                    {"campaign": cid, "campaign_name": camp["name"], "closed_by": actor.email,
                                     "snapshot_run": camp["snapshot_run"], "snapshot_sha256": camp["snapshot_sha256"]})
        taken = set(self.evidence.list_runs("access_review_result"))
        while run.prefix.split("/", 1)[1] in taken:
            run.started += dt.timedelta(seconds=1)
        run.add_bytes("decisions.csv", pack)
        run.add("summary", {"campaign": cid, "name": camp["name"], "created_at": camp["created_at"],
                            "closed_at": _now(), "snapshot_sha256": camp["snapshot_sha256"], "progress": stats,
                            "signoffs": att, "closed_with_open_items": stats["to_confirm"], "close_note": note})
        manifest = run.finish([])
        sha = next(f["sha256"] for f in manifest["files"] if f["name"] == "decisions.csv")
        fields = {"status": "closed", "closed_at": _now(), "closed_by": actor.email, "close_note": note,
                  "result_run": run.prefix, "result_sha256": sha, "open_items": stats["to_confirm"]}
        self.store.update("arcampaigns", "c", cid, fields)
        self.audit(actor, "access_review.close", cid, {"records": stats["total"], "keep": stats["keep"],
                                                        "revoke": stats["revoke"], "modify": stats["modify"],
                                                        "open_items": stats["to_confirm"], "result_sha256": sha})
        return {**camp, **fields}

    def access_export(self, user, cid: str) -> tuple[str, bytes]:
        """Decisions file for auditors. A closed review returns the stored, hashed file, not a rebuilt one."""
        if user.role not in ("admin", "auditor"):
            raise self._forbidden("Only admins and auditors can export a review")
        camp = self._ar_campaign(cid)
        if camp["status"] == "closed":
            source, _, run = camp["result_run"].partition("/")
            data = self.evidence.read(source, run, "decisions.csv")
            if data is not None:
                return f"access-review-{cid}.csv", data
        return f"access-review-{cid}.csv", pack_csv(cid, self._ar_entries(cid))

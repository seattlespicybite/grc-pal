"""The data the authorization suite runs against: one portal full of objects and seven kinds of caller.

Why a separate module: tests/authz_matrix.py (the expectation table) and tests/test_authz.py (the machinery) both
need the same objects, and the table must stay readable. Everything here uses demo users (example.com).

Two organizations live in one store (tenants "acme" and "other") so the suite can prove that an admin of one
never reaches the other's rows. Each has its own control owner, vendor, document, access review and so on, and
every ID that is unique to one organization is a plain attribute (w.assign_a, w.upload_b, ...)."""
from __future__ import annotations

import datetime as dt
import io
import json
import os
import shutil
import sqlite3
from pathlib import Path
from types import SimpleNamespace

from grcpal import xlsx
from grcpal.portal import demo, matrix
from grcpal.portal import vendor_import as imod
from grcpal.portal.auth import User
from grcpal.portal.store import SqliteStore
from test_portal import TODAY, make_portal

# The seven callers. "anonymous" sends no identity at all.
ROLES = ("anonymous", "admin", "owner", "contributor", "auditor", "expired_auditor", "disabled_admin")

PDF = b"%PDF-1.4\n% authz test file\n%%EOF\n"
CONTRIB_NOTHING = User("nina.nothing@example.com", "Nina Nothing", "contributor")  # nothing assigned, owns nothing
SPARE = User("sid.spare@example.com", "Sid Spare", "contributor")                  # a target for user-admin routes
EXPIRED = User("old.auditor@cpa-firm.example", "Old Auditor", "auditor")           # access_until in the past
DISABLED = User("gone.admin@example.com", "Gone Admin", "admin")                   # an admin whose account is off


def callers(tenant: str) -> dict[str, User | None]:
    """Who each role is. In the second organization the same names get another domain, so nobody is shared."""
    if tenant == "acme":
        return {"anonymous": None, "admin": demo.ADMIN, "owner": demo.HR, "contributor": CONTRIB_NOTHING,
                "auditor": demo.AUDITOR, "expired_auditor": EXPIRED, "disabled_admin": DISABLED}
    sfx = tenant
    return {"anonymous": None,
            "admin": User(f"boss@{sfx}.example", "Boss", "admin"),
            "owner": User(f"owner@{sfx}.example", "Owner", "contributor"),
            "contributor": User(f"nobody@{sfx}.example", "Nobody", "contributor"),
            "auditor": User(f"audit@{sfx}.example", "Audit", "auditor"),
            "expired_auditor": None, "disabled_admin": None}


def open_sessions(portal, who) -> dict[str, str]:
    """A signed-in session per person (local sign-in mode): role -> cookie value."""
    import secrets

    from grcpal.portal import accounts

    out = {}
    for role, u in who.items():
        if u is None:
            continue
        token = secrets.token_urlsafe(32)
        portal.store.insert("sessions", {"PartitionKey": "s", "RowKey": accounts._digest(token), "email": u.email,
                                         "created": accounts._now(), "last_used": accounts._now(),
                                         "expires": accounts._later(accounts.SESSION_HOURS)})
        out[role] = token
    return out


def base_runs(tmp: Path, source: str) -> list[str]:
    """Run ids of one source in the first organization (used to keep the second organization's ids different)."""
    d = tmp / "evidence" / "acme" / source
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def _month_key(portal) -> str:
    """The calendar key of one occurrence this month (a real activity that is scheduled in TODAY's month)."""
    year = portal.calendar_year(TODAY.year)
    for row in year["rows"] if "rows" in year else []:
        for cell in row.get("cells", []):
            if cell and cell.get("key"):
                return cell["key"]
    return f"access-review~{TODAY:%Y-%m}"


def build(tmp: Path, base: SqliteStore, tenant: str) -> SimpleNamespace:
    """Create one organization and return the namespace of its IDs."""
    os.environ["GRCPAL_JOBS_SYNC"] = "1"
    who = callers(tenant)
    portal = make_portal(tmp, tenant=tenant, base_store=base, people=())
    w = SimpleNamespace(tenant=tenant, portal=portal, who=who)
    admin = who["admin"]
    if tenant == "acme":
        demo.seed(portal)
        for u in (CONTRIB_NOTHING, SPARE, EXPIRED, DISABLED):
            portal._create_user(u.email, u.name, u.role, "test", "test")
        w.sessions = open_sessions(portal, who)         # local sign-in mode uses these; made before the accounts change
        portal.store.update("users", "u", EXPIRED.email, {"access_until": (TODAY - dt.timedelta(days=30)).isoformat()})
        portal.store.update("users", "u", DISABLED.email, {"active": False})
        owner, other_owner = demo.HR, demo.ENG
        w.ctl_a, w.ctl_b = "HR-01", "BCP-03"            # owned by hr-lead (Harper) and engineering-lead (Erin)
    else:
        # A smaller second organization: other people, the same starter catalog, its own objects.
        for u in (who["admin"], who["owner"], who["contributor"], who["auditor"]):
            portal._create_user(u.email, u.name, u.role, "test", "test")
        portal.store.update("users", "u", admin.email, {"library_owner": True})
        portal.catalog.roles["hr-lead"]["email"] = who["owner"].email
        portal.catalog.roles["engineering-lead"]["email"] = who["contributor"].email
        owner, other_owner = who["owner"], who["contributor"]
        w.ctl_a, w.ctl_b = "HR-01", "BCP-03"
    w.owner, w.other_owner = owner, other_owner

    # ---- evidence requests, uploads, overrides, comments
    cycle = portal.active_cycle()
    w.cycle_active = cycle["RowKey"]
    w.cycle_closed = next((c["RowKey"] for c in portal.store.list("cycles", "c") if c["RowKey"] != cycle["RowKey"]),
                          cycle["RowKey"])
    due = (TODAY + dt.timedelta(days=20)).isoformat()
    if tenant == "acme":
        by_control = {a["controls"][0]: a for a in portal.assignments(cycle=cycle["RowKey"])}
        a_a, a_b = by_control[w.ctl_a], by_control[w.ctl_b]
    else:
        a_a = portal.create_assignment(admin, "control", w.ctl_a, owner.email, [], due, "x")
        a_b = portal.create_assignment(admin, "control", w.ctl_b, other_owner.email, [], due, "x")
        portal.upload(owner, f"{tenant}-a.pdf", PDF, "a", assignment_id=a_a["RowKey"])
        portal.upload(other_owner, f"{tenant}-b.pdf", PDF, "b", assignment_id=a_b["RowKey"])
    w.assign_a, w.assign_b = a_a["RowKey"], a_b["RowKey"]
    ups = portal.uploads(cycle=None)
    w.upload_a = next(u["RowKey"] for u in ups if u["assignment"] == w.assign_a)
    w.upload_b = next(u["RowKey"] for u in ups if u["assignment"] == w.assign_b)
    # an assignment we can edit, cancel and remind, with a pending upload to review
    w.assign_extra = portal.create_assignment(admin, "control", "IAM-02", other_owner.email, [], due, "extra")["RowKey"]
    w.upload_pending = portal.upload(other_owner, f"{tenant}-pending.pdf", PDF + b"pending", "waiting for review",
                                     assignment_id=w.assign_extra)["RowKey"]
    w.override = (portal.store.list("overrides", "o") or [
        portal.create_override(admin, "END-02", "Mobile devices are not used for company data; the MDM policy "
                               "blocks enrollment of personal phones.", due, "ticket")])[0]["RowKey"]
    w.override_revoke = portal.create_override(admin, "END-01", "Hardware is leased and retired on a fixed schedule "
                                               "by the vendor; confirmed with IT.", due, "ticket")["RowKey"]
    w.policy = portal.catalog.policies[0]["id"]
    w.crit = sorted(portal.catalog.in_scope_criteria)[0]
    w.section, w.step, w.framework, w.framework_off = "organization", "welcome", "soc2", "iso27001"
    w.admin_email = admin.email
    w.auto_source = next(iter(portal.automated_sources()))
    w.collector = "catalog_validate"  # runs everywhere, needs no connection
    # ---- an evidence run that only this organization has (a source name the portal knows, a run id nobody else has)
    taken = set(base_runs(tmp, "portal_upload")) if tenant != "acme" else set()
    run = portal.evidence.new_run("portal_upload", [w.ctl_a], {"note": f"authz test {tenant}"})
    while run.prefix.split("/", 1)[1] in taken:       # same second as one of the first organization's runs
        run.started += dt.timedelta(seconds=1)
    run.add_bytes("result.json", json.dumps({"tenant": tenant}).encode())
    run.finish([])
    w.ev_source, w.ev_run, w.ev_file = "portal_upload", run.prefix.split("/", 1)[1], "result.json"
    # ---- people
    w.spare = SPARE.email if tenant == "acme" else f"spare@{tenant}.example"
    if tenant != "acme":
        portal._create_user(w.spare, "Spare", "contributor", "test", "test")
    w.user_target = w.spare
    # ---- custom control, check, AI review and audit (job)
    w.custom = f"CUS-{tenant[:3].upper()}"
    portal.save_custom_control(admin, {
        "id": w.custom, "title": f"Custom control of {tenant}", "description": "A control made for the authz suite.",
        "frequency": "annual", "owner_emails": admin.email, "map_soc2": "CC9.2",
        "evidence_wanted": "A test file"})
    w.check = f"chk-{tenant}"
    portal.save_check(admin, w.ctl_a, {"id": w.check, "type": "http", "url": "https://example.com/health",
                                       "schedule": "manual", "method": "GET", "expect_status": "200-399"})
    from grcpal import report

    health = report.build(portal.catalog, portal.evidence, portal.today, portal=portal.report_inputs())
    status = {c["id"]: c for c in health["controls"]}
    portal.save_settings(admin, "ai", {"GRCPAL_AI_PROVIDER": "demo", "GRCPAL_AI_REDACT_EMAILS": "true",
                                       "GRCPAL_AI_MAX_TOKENS": "4000", "GRCPAL_AI_DAILY_LIMIT": "200"})
    review = portal.ai_review(admin, w.ctl_a, status[w.ctl_a])
    w.ai_review = review["RowKey"]
    audit = portal.start_ai_audit(admin, "soc2", lambda cid: status.get(cid, {"status": "not_started", "evidence": []}),
                                  limit=2)
    w.ai_audit, w.job = audit["audit"] if "audit" in audit else audit.get("RowKey", ""), audit["job"]
    # ---- calendar: an activity and one of its occurrences
    w.activity = portal.store.list("calendaractivities", "a")[0]["RowKey"]
    months = portal.calendar_activity(w.activity)["months"]
    free = next(m for m in range(1, 13) if m not in months)
    w.occurrence = f"{w.activity}~{TODAY.year}-{months[0]:02d}"        # a month the activity is scheduled in
    w.occ_new = f"{w.activity}~{TODAY.year}-{free:02d}"               # a month it is not (a one-off can be added)
    # ---- document library: a draft, a version waiting for the owner's approval, a trashed doc and one to trash
    folder = "other"
    d1 = portal.add_doc(admin, folder, f"T-{tenant}", f"Authz test policy {tenant}")
    w.doc = d1["id"]
    portal.edit_doc(admin, w.doc, {"approver": owner.email, "owner": admin.email})
    portal.upload_official(admin, w.doc, "policy.pdf", PDF + b"v1", "", "major", "first draft", "")
    portal.upload_official(admin, w.doc, "policy.pdf", PDF + b"v2", "", "minor", "second draft", "")
    versions = sorted(portal.store.list("docversions", w.doc), key=lambda v: v["RowKey"])
    w.ver_draft, w.ver_review = versions[0]["RowKey"], versions[1]["RowKey"]
    portal.request_approval(admin, w.doc, w.ver_review, "please review")
    w.doc_trashed = portal.add_doc(admin, folder, f"Z-{tenant}", f"Trashed doc {tenant}")["id"]
    portal.trash_docs(admin, [w.doc_trashed], "not needed")
    w.doc_to_trash = portal.add_doc(admin, folder, f"Y-{tenant}", f"Doc to trash {tenant}")["id"]
    # ---- vendors (the demo vendor files are created above for acme; the second organization gets its own)
    vname = f"Zeta Vendor {tenant}"
    v = portal.create_vendor(admin, {"name": vname, "service": "Test service", "tier": "high",
                                     "data_access": ["Customer data"], "owner_email": owner.email,
                                     "owner_name": owner.name})
    w.vendor_a = v["RowKey"]                      # owned by the control owner
    portal.add_vendor_file(owner, w.vendor_a, "report.pdf", PDF + b"vendor-a", "report", "SOC 2 report")
    w.vendor_file_a = portal.store.list("vendorfiles", w.vendor_a)[0]["RowKey"]
    v2 = portal.create_vendor(admin, {"name": f"Other Vendor {tenant}", "service": "Another service", "tier": "moderate",
                                      "data_access": ["Customer data"], "owner_email": other_owner.email,
                                      "owner_name": other_owner.name})
    w.vendor_b = v2["RowKey"]                     # owned by someone else
    portal.add_vendor_file(admin, w.vendor_b, "report-b.pdf", PDF + b"vendor-b", "report", "SOC 2 report")
    w.vendor_file_b = portal.store.list("vendorfiles", w.vendor_b)[0]["RowKey"]
    v3 = portal.create_vendor(admin, {"name": f"Spare Vendor {tenant}", "service": "Spare", "tier": "low",
                                      "data_access": ["Customer data"]})
    w.vendor_c = v3["RowKey"]
    csv_bytes = (imod.template_csv().decode("utf-8-sig").rstrip() + "\r\n"
                 + ",".join([f"Imported Vendor {tenant}", "Imported service", "moderate"] + [""] * (len(imod.FIELDS) - 3))
                 + "\r\n").encode()
    w.vendor_import = portal.vendor_import_upload(admin, "vendors.csv", csv_bytes)["RowKey"]
    # ---- access reviews: one with an entry for the owner, one for somebody else
    mgr = lambda email: ("app,account_id,email,name,status,role,last_login,mfa,is_service_account,manager_email\r\n"  # noqa: E731
                         f"GitHub,acc-{tenant}-1,jdoe@example.com,Jane Doe,active,member,2026-10-01,yes,no,{email}\r\n"
                         f"GitHub,acc-{tenant}-2,jroe@example.com,Joe Roe,active,member,2026-10-01,yes,no,{email}\r\n"
                         ).encode()
    c1 = portal.create_access_campaign(admin, f"Review of {tenant} for owner", due, mgr(owner.email))
    c2 = portal.create_access_campaign(admin, f"Review of {tenant} for others", due, mgr(other_owner.email))
    w.campaign_a, w.campaign_b = c1["RowKey"], c2["RowKey"]
    w.entry_a = portal.store.list("arentries", w.campaign_a)[0]["RowKey"]
    w.entry_b = portal.store.list("arentries", w.campaign_b)[0]["RowKey"]
    app_row = portal.add_access_app(admin, f"App of {tenant}", "csv", "", "")
    w.access_app = app_row["RowKey"]
    w.auditor_email = who["auditor"].email
    w.admin2_email = demo.ADMIN2.email if tenant == "acme" else f"admin2@{tenant}.example"
    if tenant != "acme":
        portal._create_user(w.admin2_email, "Admin Two", "admin", "test", "test")
    admin2 = User(w.admin2_email, "Admin Two", "admin")
    # vendor_c becomes an active vendor (checklist done, assurance saved, a second admin signed it off)
    portal.add_vendor_file(admin, w.vendor_c, "spare-report.pdf", PDF + b"vendor-c", "report", "SOC 2 report")
    for key in ("risk", "assurance", "contract"):
        portal.update_checklist(admin, w.vendor_c, key, True, "Checked")
    portal.save_assurance(admin, w.vendor_c, "independent", {})
    portal.decide_review(admin2, w.vendor_c, "approve", "Gaps accepted for the authz test.")
    # vendor_d: an active vendor owned by the control owner, with a yearly review open
    v4 = portal.create_vendor(admin, {"name": f"Yearly Vendor {tenant}", "service": "Yearly", "tier": "low",
                                      "data_access": ["Customer data"], "owner_email": owner.email,
                                      "owner_name": owner.name})
    w.vendor_d = v4["RowKey"]
    for key in ("risk", "assurance", "contract"):
        portal.update_checklist(admin, w.vendor_d, key, True, "Checked")
    portal.save_assurance(admin, w.vendor_d, "independent", {})
    portal.decide_review(admin2, w.vendor_d, "approve", "Gaps accepted for the authz test.")
    portal.start_annual_review(admin, w.vendor_d)
    # a built-in control whose definition was changed once (so "reset" has something to undo)
    w.ctl_edited = "HR-02"
    d = portal.control_definition(w.ctl_edited)
    portal.save_control_definition(admin, w.ctl_edited, {
        "reason": "Clarifying the title for the authz suite.", "title": d["title"] + " (edited)", "owner": d["owner"],
        "owner_emails": ", ".join(d["owner_emails"]), "description": d["description"],
        **{f"map_{fid}": " ".join(ids) for fid, ids in d["mappings"].items()}})
    # ---- more access reviews, each in the state one route needs
    me = owner.email

    def decided(name, decision="keep", sign=False, only_first=False):
        c = portal.create_access_campaign(admin, f"{name} {tenant}", due, mgr(me))
        ents = sorted(portal.store.list("arentries", c["RowKey"]), key=lambda e: e["RowKey"])
        portal.save_access_decisions(owner, c["RowKey"], {e["RowKey"]: {"decision": decision, "comment": "ok"}
                                                          for e in (ents[:1] if only_first else ents)})
        if sign:
            portal.attest_access(owner, c["RowKey"])
        return c["RowKey"], ents[0]["RowKey"]

    w.campaign_c, _ = decided("Ready to sign off")
    w.campaign_d, _ = decided("Signed off", sign=True)
    w.campaign_e, w.entry_e = decided("To confirm", decision="revoke", only_first=True)
    w.campaign_f, _ = decided("Ready to close", sign=True)
    # ---- control matrix import waiting for the library owner
    data = portal.matrix_xlsx(admin)
    sheets = xlsx.read_values(data)
    rows = sheets[matrix.DATA_SHEET]
    ci = next(i for i, h in enumerate(rows[0]) if h.startswith("Title"))
    row = next(r for r in rows[1:] if r and r[0] == w.ctl_a)
    row += [""] * (len(rows[0]) - len(row))
    row[ci] = row[ci] + " (edited)"
    edited = xlsx.workbook([{"name": matrix.DATA_SHEET, "rows": rows},
                            {"name": matrix.HELP_SHEET, "rows": sheets[matrix.HELP_SHEET]},
                            {"name": matrix.META_SHEET, "rows": sheets[matrix.META_SHEET], "hidden": True}])
    w.matrix_file = edited
    preview = portal.matrix_preview(admin, "matrix.xlsx", edited)
    w.matrix_import = preview["import_id"]
    w.matrix_plan = preview.get("plan_hash", "") or preview.get("plan", "")
    return w


def build_all(tmp: Path) -> tuple[SqliteStore, SimpleNamespace, SimpleNamespace]:
    """Both organizations in one file-backed store (so a copy of it can be taken with SQLite's online backup)."""
    base = SqliteStore(str(tmp / "world.db"))
    a = build(tmp, base, "acme")
    b = build(tmp, base, "other")
    return base, a, b


def copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst) if src.exists() else dst.mkdir(parents=True)


def restore_db(snapshot: Path, live: SqliteStore) -> None:
    """Put the live in-memory connection back to the snapshot (SQLite online backup, snapshot -> live)."""
    src = sqlite3.connect(str(snapshot))
    try:
        with live._lock:
            src.backup(live._db)
    finally:
        src.close()


def dump(base: SqliteStore, skip_tables=("events", "sessions")) -> dict:
    """Every row of the store as text, to compare before and after a request. Not counted as a change: the event
    log (it records refusals on purpose), sign-in sessions (their "last used" time moves) and a person's
    "last seen" time (signing in updates it)."""
    rows = base._db.execute("SELECT tbl, pk, rk, data FROM entities").fetchall()
    out = {}
    for tbl, pk, rk, data in rows:
        if tbl in skip_tables:
            continue
        if tbl == "users":
            row = json.loads(data)
            row.pop("last_seen", None)
            data = json.dumps(row, sort_keys=True)
        out[(tbl, pk, rk)] = data
    return out


def evidence_files(root: Path) -> dict:
    out = {}
    for p in sorted(root.rglob("*")) if root.exists() else []:
        if p.is_file():
            out[str(p.relative_to(root))] = p.stat().st_size
    return out


__all__ = ["ROLES", "build_all", "callers", "copy_tree", "restore_db", "dump", "evidence_files", "io"]

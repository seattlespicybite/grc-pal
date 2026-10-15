"""grcpal command line.

Getting started
    grcpal serve --demo                   run the portal locally with sample data (http://localhost:8000)
    grcpal init my-grc --org "Acme Inc"   create your own program repository from the starter kit

Program operations
    grcpal validate                       check catalog, registers and coverage
    grcpal collect --all [--open-issues]  run every enabled collector
    grcpal collect entra_mfa azure_rbac   run named collectors
    grcpal store --source prowler --controls MON-01,NET-01 out/*.json
    grcpal tasks [--dry-run]              open recurring control tasks due this month
    grcpal report --out report.html       control health dashboard
    grcpal publish-config                 send catalog/registers/policies to the deployed portal

Portal administration (uses GRCPAL_TABLES_URL or GRCPAL_SQLITE)
    grcpal users add you@example.com --role admin
    grcpal users list
    grcpal remind --overdue [--dry-run]   email owners of overdue requests
    grcpal audit verify                   check the tamper-evident audit log
    grcpal checks run                     run custom HTTP, TLS and command checks
    grcpal ai review --control HR-01      AI evidence review of one control
    grcpal ai audit --framework soc2      AI mock audit across a framework
    grcpal export --cycle 2026 --out export.zip
    grcpal backup keygen --key-file backup.key            new backup key (keep it outside the instance)
    grcpal backup create acme.grcbak --key-file backup.key   whole-instance encrypted backup
    grcpal backup verify acme.grcbak --key-file backup.key   prove a backup is complete and unchanged
    grcpal backup kit --out recovery-kit.json              backup key + app key, for a password manager
    grcpal backup restore acme.grcbak --kit recovery-kit.json   restore into an empty instance (or --into DIR)
"""
from __future__ import annotations

import argparse
import getpass
import os
import json
import sys
from pathlib import Path

from grcpal import collectors, report, tasks
from grcpal.catalog import Catalog, validate
from grcpal.evidence import EvidenceStore


def _settings():
    """Saved configuration from the portal store when one is configured, else environment variables only."""
    from grcpal.settings import Settings, SettingsStore

    if os.getenv("GRCPAL_TABLES_URL") or os.getenv("GRCPAL_SQLITE"):
        from grcpal.portal.store import from_env

        store = from_env()
        return SettingsStore(store, store.tenant).load()
    return Settings()


def _ctx(args, settings=None):
    from grcpal.clients import Clients

    settings = settings if settings is not None else _settings()
    return collectors.Context(clients=Clients(settings), catalog=Catalog.load(args.base), settings=settings)


def cmd_validate(args) -> int:
    cat = Catalog.load(args.base)
    errors, warnings = validate(cat, set(collectors.NAMES))
    from grcpal import kb
    articles = kb.load(cat.base)
    errors += [f"knowledge base: {x}" for x in kb.validate(cat, articles)]
    missing = kb.missing_points(cat, articles, cat.in_scope_criteria)
    if missing:
        warnings.append(f"knowledge base: {len(missing)} in-scope points of focus have no guidance yet")
    for w in warnings:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERROR {e}")
    in_scope = cat.in_scope_criteria
    covered = sum(1 for c in in_scope if cat.coverage().get(c))
    print(f"{len(cat.controls)} controls · {covered}/{len(in_scope)} in-scope criteria covered · "
          f"{len(errors)} errors · {len(warnings)} warnings")
    return 1 if errors else 0


def cmd_collect(args) -> int:
    ctx = _ctx(args)
    store = EvidenceStore(args.evidence)
    names = collectors.NAMES if args.all else args.names
    source_controls = ctx.catalog.sources("collector")
    failed = 0
    for name in names:
        mod = collectors.get(name)
        if not collectors.platform_enabled(mod, ctx.catalog, ctx.settings):
            print(f"skip  {name}: platform '{mod.PLATFORM}' is turned off (Configuration page or scope.yaml)")
            continue
        if hasattr(mod, "enabled") and not mod.enabled():
            print(f"skip  {name}: not configured")
            continue
        run = store.new_run(name, sorted(source_controls.get(name, [])), {"description": mod.DESCRIPTION})
        try:
            findings = mod.run(ctx, run) or []
            manifest = run.finish(findings)
            print(f"ok    {name}: {len(manifest['files'])} files, {len(findings)} findings -> {run.prefix}")
            if args.open_issues:
                url = tasks.sync_deficiencies(ctx, name, findings)
                if url:
                    print(f"      deficiency issue: {url}")
        except Exception as exc:  # noqa: BLE001 - record and continue with other collectors
            failed += 1
            run.finish([], status="error", error=f"{type(exc).__name__}: {exc}")
            print(f"FAIL  {name}: {type(exc).__name__}: {exc}", file=sys.stderr)
    if getattr(args, "checks", False) and (os.getenv("GRCPAL_TABLES_URL") or os.getenv("GRCPAL_SQLITE")):
        failed += _run_checks(args, force=False)
    return 1 if failed else 0


def _run_checks(args, force: bool) -> int:
    from grcpal.portal.auth import SYSTEM

    portal = _admin_portal(args)
    bad = 0
    for r in portal.run_due_checks(SYSTEM, allow_commands=True, force=force):
        print(f"{'ok   ' if r.get('ok') else 'FAIL '} check {r['id']}: {r.get('summary', '')}")
        bad += 0 if r.get("ok") else 1
    return bad


def cmd_checks(args) -> int:
    """Run HTTP, TLS and command checks (command checks only come from catalog/checks.yaml)."""
    if not (os.getenv("GRCPAL_TABLES_URL") or os.getenv("GRCPAL_SQLITE")):
        from grcpal import checks as checks_mod

        cat = Catalog.load(args.base)
        evidence = EvidenceStore(args.evidence)
        bad = 0
        for chk in cat.checks:
            headers = {k: os.path.expandvars(str(v)) for k, v in (chk.get("headers") or {}).items()}
            if chk["type"] == "http":
                res = checks_mod.run_http(chk, headers, {k for k, v in (chk.get("headers") or {}).items() if "$" in str(v)})
            elif chk["type"] == "tls":
                res = checks_mod.run_tls(chk)
            else:
                res = checks_mod.run_command(chk, allow_commands=True)
            checks_mod.store_result(evidence, chk, res)
            print(f"{'ok   ' if res.ok else 'FAIL '} check {chk['id']}: {res.summary}")
            bad += 0 if res.ok else 1
        return 1 if bad else 0
    return 1 if _run_checks(args, force=True) else 0


def cmd_ai(args) -> int:
    from grcpal.portal.auth import SYSTEM

    portal = _admin_portal(args)
    data = report.build(portal.catalog, portal.evidence, portal.today, portal=portal.report_inputs())
    status = {c["id"]: c for c in data["controls"]}
    if args.action == "review":
        if not args.control:
            raise SystemExit("grcpal ai review --control HR-01")
        row = portal.ai_review(SYSTEM, args.control, status.get(args.control))
        print(json.dumps({"verdict": row["verdict"], "summary": (row["result"] or {}).get("summary", row["error"]),
                          "evidence_run": row["evidence_run"]}, indent=2))
        return 0 if row["verdict"] != "error" else 1
    portal.jobs.sync = True
    portal.jobs._pool = None
    out = portal.start_ai_audit(SYSTEM, args.framework, lambda cid: status.get(cid), limit=args.limit)
    audit = portal.ai_audit(out["audit"])
    print(json.dumps({"audit": out["audit"], "status": audit["status"], "counts": (audit.get("summary") or {}).get("counts"),
                      "readiness": (audit.get("summary") or {}).get("overall_readiness"),
                      "evidence_run": audit.get("evidence_run")}, indent=2))
    return 0


def cmd_store(args) -> int:
    store = EvidenceStore(args.evidence)
    run = store.new_run(args.source, [c for c in args.controls.split(",") if c], {"tool": args.source})
    for f in args.files:
        p = Path(f)
        if p.is_file():
            run.add_bytes(p.name, p.read_bytes())
    findings = [{"key": "tool-reported", "severity": "medium",
                 "title": f"{args.findings} findings reported by {args.source}", "detail": {}}] if args.findings else []
    manifest = run.finish(findings)
    print(f"stored {len(manifest['files'])} files -> {run.prefix}")
    return 0


def cmd_tasks(args) -> int:
    cat = Catalog.load(args.base)
    portal = None if args.github else _portal(cat, EvidenceStore(args.evidence))
    if portal:  # portal deployed: tasks open as portal assignments for people without GitHub
        from grcpal.portal.auth import SYSTEM

        if args.dry_run:
            from grcpal.tasks import due_this_month
            for name, _ in due_this_month(cat, portal.today):
                print(f"(dry run) portal task {name}")
            return 0
        for a in portal.open_due_tasks(SYSTEM):
            print(f"portal assignment {a['RowKey']}: {a['label'].splitlines()[0]} -> {a['assignee']} due {a['due']}")
        return 0
    ctx = _ctx(args)
    for line in tasks.open_due(ctx, dry_run=args.dry_run):
        print(line)
    return 0


def _portal(cat, evidence, required: bool = False):
    """Portal service when a portal store is configured (GRCPAL_TABLES_URL or GRCPAL_SQLITE), else None."""
    if not (os.getenv("GRCPAL_TABLES_URL") or os.getenv("GRCPAL_SQLITE")):
        if required:
            raise SystemExit("Set GRCPAL_TABLES_URL (Azure Table Storage) or GRCPAL_SQLITE (local file) first")
        return None
    from grcpal.portal import mailer
    from grcpal.portal.service import Portal
    from grcpal.portal.store import from_env

    portal = Portal(cat, from_env(), evidence)  # applies email settings saved in the portal, then the environment
    try:
        # scheduled jobs exit when done, so send synchronously instead of in the background
        sync_mailer = mailer.from_settings(portal.settings, sync=True)
    except Exception:  # noqa: BLE001 - incomplete settings: keep what the portal chose (it logged why)
        return portal
    sync_mailer.on_result = portal._mail_result
    portal.mailer = sync_mailer
    return portal


def _admin_portal(args):
    return _portal(Catalog.load(args.base), EvidenceStore(args.evidence), required=True)


def cmd_publish_config(args) -> int:
    from grcpal import configbundle

    base = Path(args.base or ".")
    if not (base / "catalog").is_dir():
        raise SystemExit("Run from your program repository (it needs a catalog/ folder) or pass --base")
    cat = Catalog.load(base)
    errors, _ = validate(cat, set(collectors.NAMES))
    if errors:
        raise SystemExit(f"Catalog has {len(errors)} errors; run grcpal validate")
    url = os.getenv("GRCPAL_EVIDENCE_ACCOUNT_URL")
    if args.out:
        Path(args.out).write_bytes(configbundle.build(base))
        print(f"bundle -> {args.out}")
        return 0
    if not url:
        raise SystemExit("Set GRCPAL_EVIDENCE_ACCOUNT_URL (deploy.sh sets it as a repository variable)")
    digest = configbundle.publish(base, url, os.getenv("GRCPAL_TENANT", "default"))
    print(f"published program configuration sha256={digest[:16]}; the portal loads it at its next start "
          "(az containerapp revision restart applies it now)")
    return 0


def cmd_serve(args) -> int:
    try:
        import uvicorn
    except ImportError:
        raise SystemExit('The portal needs extra packages: pip install "grc-pal[portal]"')
    os.environ.setdefault("GRCPAL_AUTH_MODE", "dev" if args.demo else "local")
    if args.demo:
        os.environ["GRCPAL_DEMO"] = "1"
        os.environ.setdefault("GRCPAL_SQLITE", ":memory:" if not args.db else args.db)
    if args.db:
        os.environ["GRCPAL_SQLITE"] = args.db
    os.environ.setdefault("GRCPAL_SQLITE", "grcpal.db")
    os.environ.setdefault("GRCPAL_EVIDENCE_DIR", args.evidence)
    os.environ.setdefault("GRCPAL_PUBLIC_URL", f"http://{args.host}:{args.port}")
    if args.base:
        os.environ["GRCPAL_BASE"] = str(Path(args.base).resolve())
    print(f"GRC-pal portal on http://{args.host}:{args.port}  (auth: {os.environ['GRCPAL_AUTH_MODE']}, "
          f"data: {os.environ['GRCPAL_SQLITE']}{', demo data' if args.demo else ''})")
    uvicorn.run("grcpal.portal.app:app", host=args.host, port=args.port, log_level="warning")
    return 0


def cmd_init(args) -> int:
    import shutil

    from grcpal.catalog import STARTER

    dest = Path(args.directory)
    if dest.exists() and any(dest.iterdir()):
        print(f"{dest} exists and is not empty; choose a new directory", file=sys.stderr)
        return 1
    shutil.copytree(STARTER, dest, ignore=shutil.ignore_patterns("__pycache__"), dirs_exist_ok=True)
    (dest / "github").rename(dest / ".github")
    scope = dest / "catalog/scope.yaml"
    if args.org:
        text = scope.read_text(encoding="utf-8").replace("organization: Example Co", f"organization: {args.org}")
        scope.write_text(text, encoding="utf-8")
    print(f"Created {dest}\n\nNext steps:\n"
          f"  1. cd {dest} && git init && git add . && git commit -m 'GRC program from GRC-pal starter'\n"
          "  2. Edit catalog/roles.yaml (names and work emails) and catalog/scope.yaml\n"
          "  3. grcpal validate\n"
          f"  4. grcpal serve --base {dest}   (local portal on your catalog)\n"
          "  5. Deploy: see docs/deploy-azure.md in the GRC-pal repository")
    return 0


def cmd_users(args) -> int:
    from grcpal.portal.auth import SYSTEM

    portal = _admin_portal(args)
    if args.action == "add":
        if not args.email:
            raise SystemExit("grcpal users add EMAIL --role ROLE")
        if portal.user_row(args.email):
            portal.set_role(SYSTEM, args.email, args.role)
            portal.set_active(SYSTEM, args.email, True)
            print(f"updated {args.email.lower()} -> {args.role}")
        else:
            portal.add_user(SYSTEM, args.email, args.name or "", args.role)
            print(f"added {args.email.lower()} as {args.role}")
    else:
        for u in portal.users():
            print(f"{u['RowKey']:40} {u['role']:12} {'active' if u.get('active', True) else 'disabled':9} {u.get('source', '')}")
    return 0


def cmd_create_admin(args) -> int:
    """First admin and break-glass admin for local sign-in. Needs shell access to the server, which is the
    point: whoever runs this already controls the VM. The password is typed, never passed as an argument."""
    from grcpal.portal.service import Invalid

    portal = _admin_portal(args)
    password = getpass.getpass("Password (at least 12 characters): ")
    if password != getpass.getpass("Type it again: "):
        raise SystemExit("The two passwords do not match; nothing was changed")
    try:
        portal.create_local_admin(args.email, args.name or "", password)
    except Invalid as exc:
        raise SystemExit(str(exc)) from exc
    print(f"{args.email.lower()} is a local admin (break-glass: password sign-in only). Sign in at "
          f"{portal.public_url or 'the portal'}/login")
    return 0


def cmd_remind(args) -> int:
    from grcpal.portal.auth import SYSTEM

    portal = _admin_portal(args)
    overdue = [a for a in portal.assignments() if a["overdue"]]
    if args.dry_run:
        for a in overdue:
            print(f"(dry run) overdue {a['due']} {a['label'].splitlines()[0]} -> {a['assignee']}")
        return 0
    for r in portal.remind_overdue(SYSTEM):
        print(f"{r['label'].splitlines()[0]}: sent {', '.join(r['sent']) or '-'}; skipped {', '.join(r['skipped']) or '-'}")
    portal.mailer._pool and portal.mailer._pool.shutdown(wait=True)
    return 0


def cmd_audit(args) -> int:
    result = _admin_portal(args).log.verify()
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 2


def cmd_export(args) -> int:
    from grcpal.portal.auth import SYSTEM

    portal = _admin_portal(args)
    cycle = args.cycle or portal.active_cycle()["RowKey"]
    data = report.build(portal.catalog, portal.evidence, portal=portal.report_inputs())
    blob = portal.export_cycle(SYSTEM, cycle, control_status=data["controls"])
    Path(args.out).write_bytes(blob)
    print(f"export for cycle {cycle} -> {args.out} ({len(blob):,} bytes)")
    return 0


def cmd_backup(args) -> int:
    from grcpal import backup

    try:
        if args.action == "keygen":
            path = Path(args.key_file) if args.key_file else backup.default_key_file()
            if path is None:
                print(backup.new_key())
            else:
                backup._write_private(path, backup.new_key() + "\n")
                print(f"backup key -> {path}", file=sys.stderr)
            print("Next: grcpal backup kit --out recovery-kit.json, and keep that file in a password manager, "
                  "apart from the backups. Without the key a backup cannot be read.", file=sys.stderr)
            return 0
        kit = backup.load_kit(Path(args.kit).read_text()) if getattr(args, "kit", None) else None
        try:
            key = kit["key"] if kit else backup.resolve_key(args.key_file)
        except backup.BackupError as exc:
            raise SystemExit(str(exc)) from None
        if args.action == "kit":
            if not args.out:
                raise SystemExit("grcpal backup kit needs --out FILE")
            settings_key = backup._settings_key()
            backup._write_private(Path(args.out), backup.make_kit(key, settings_key, os.getenv("GRCPAL_PUBLIC_URL", "")))
            _audit_all_tenants(args, "backup.kit_export", {"file": Path(args.out).name})
            out = {"ok": True, "kit": args.out, "backup_key_id": backup.key_id(key),
                   "settings_key_included": bool(settings_key)}
            print(json.dumps(out, indent=2))
            if not settings_key:
                print("Warning: GRCPAL_ENCRYPTION_KEY is not set here, so the kit has no settings key.", file=sys.stderr)
            return 0
        if not args.file:
            raise SystemExit(f"grcpal backup {args.action} needs a file name")
        if args.action == "create":
            manifest = backup.create(backup.from_env(args.evidence), Path(args.file), key)
            report = {"ok": all(a["ok"] for a in manifest["audit"].values()), "problems": [],
                      "manifest": manifest}
            report["problems"] = [f"audit log of tenant {t} does not verify"
                                  for t, a in manifest["audit"].items() if not a["ok"]]
            out = {**backup.summary(report), "file": args.file, "sha256": manifest["file_sha256"]}
        elif args.action == "restore":
            target = backup.folder_instance(Path(args.into)) if args.into else backup.from_env(args.evidence, create=True)
            out = backup.restore(Path(args.file), key, target, accept_audit_problems=args.accept_audit_problems)
            if args.into:
                out["restored_into"] = args.into
            for w in out["warnings"]:
                print(f"Note: {w}", file=sys.stderr)
        else:
            report = backup.verify(Path(args.file), key)
            out = backup.summary(report)
    except backup.BackupError as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, indent=2))
    return 0 if out["ok"] else 2


def _audit_all_tenants(args, action: str, detail: dict) -> None:
    """Best effort: record a CLI operator action in every tenant's audit log."""
    from grcpal import backup
    from grcpal.portal.auditlog import AuditLog
    from grcpal.portal.store import TenantStore

    try:
        inst = backup.from_env(args.evidence)
    except backup.BackupError:
        return
    tenants = {r["PartitionKey"].split("|", 1)[0] for r in inst.base.list_prefix("users", "")}
    for t in sorted(tenants):
        AuditLog(TenantStore(inst.base, t)).append("cli", action, "backup", detail)


def cmd_report(args) -> int:
    cat = Catalog.load(args.base)
    evidence = EvidenceStore(args.evidence)
    portal = _portal(cat, evidence)
    data = report.build(cat, evidence, portal=portal.report_inputs() if portal else None)
    Path(args.out).write_text(report.to_html(data), encoding="utf-8")
    Path(args.out).with_suffix(".json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"report -> {args.out} · in-scope control status: {data['counts']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="grcpal", description="GRC-pal framework")
    p.add_argument("--base", default=os.getenv("GRCPAL_BASE") or ("." if Path("catalog").is_dir() else None),
                   help="instance directory with catalog/ and registers/ (default: current directory if it has "
                        "a catalog, otherwise the built-in starter kit)")
    p.add_argument("--evidence", default=os.getenv("GRCPAL_EVIDENCE_DIR", "evidence"), help="local evidence directory")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("validate").set_defaults(fn=cmd_validate)

    c = sub.add_parser("collect")
    c.add_argument("names", nargs="*")
    c.add_argument("--all", action="store_true")
    c.add_argument("--open-issues", action="store_true", help="open or update deficiency issues")
    c.add_argument("--checks", action="store_true", help="also run due custom checks (needs a portal store)")
    c.set_defaults(fn=cmd_collect)

    s = sub.add_parser("store")
    s.add_argument("--source", required=True)
    s.add_argument("--controls", default="")
    s.add_argument("--findings", type=int, default=0)
    s.add_argument("files", nargs="+")
    s.set_defaults(fn=cmd_store)

    t = sub.add_parser("tasks")
    t.add_argument("--dry-run", action="store_true")
    t.add_argument("--github", action="store_true", help="open GitHub issues even if the portal is configured")
    t.set_defaults(fn=cmd_tasks)

    r = sub.add_parser("report")
    r.add_argument("--out", default="report.html")
    r.set_defaults(fn=cmd_report)

    ck = sub.add_parser("checks", help="run custom HTTP, TLS and command checks now")
    ck.add_argument("action", choices=["run"])
    ck.set_defaults(fn=cmd_checks)

    ai = sub.add_parser("ai", help="AI evidence review or full mock audit (uses the saved AI settings)")
    ai.add_argument("action", choices=["review", "audit"])
    ai.add_argument("--control", help="control ID for review")
    ai.add_argument("--framework", default="soc2", help="framework ID for audit (default soc2)")
    ai.add_argument("--limit", type=int, default=0, help="review only the first N controls (trial runs)")
    ai.set_defaults(fn=cmd_ai)

    pc = sub.add_parser("publish-config", help="send catalog, registers and policies to the deployed portal")
    pc.add_argument("--out", help="write the bundle to a file instead of uploading")
    pc.set_defaults(fn=cmd_publish_config)

    sv = sub.add_parser("serve", help="run the portal locally")
    sv.add_argument("--demo", action="store_true", help="load sample users and evidence (in memory unless --db)")
    sv.add_argument("--db", help="SQLite file for portal data (default grcpal.db)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(fn=cmd_serve)

    i = sub.add_parser("init", help="create a program repository from the starter kit")
    i.add_argument("directory")
    i.add_argument("--org", help="organization name for catalog/scope.yaml")
    i.set_defaults(fn=cmd_init)

    u = sub.add_parser("users", help="list or add portal users")
    u.add_argument("action", choices=["list", "add"])
    u.add_argument("email", nargs="?")
    u.add_argument("--role", choices=["admin", "contributor", "auditor"], default="contributor",
                   help="contributor is shown as Control owner in the portal")
    u.add_argument("--name")
    u.set_defaults(fn=cmd_users)

    ca = sub.add_parser("create-admin", help="create the first admin or a break-glass admin (local sign-in)")
    ca.add_argument("email")
    ca.add_argument("--name")
    ca.set_defaults(fn=cmd_create_admin)

    rm = sub.add_parser("remind", help="email people with overdue requests")
    rm.add_argument("--overdue", action="store_true", required=True)
    rm.add_argument("--dry-run", action="store_true")
    rm.set_defaults(fn=cmd_remind)

    au = sub.add_parser("audit", help="audit log tools")
    au.add_argument("action", choices=["verify"])
    au.set_defaults(fn=cmd_audit)

    ex = sub.add_parser("export", help="auditor export zip for a cycle")
    ex.add_argument("--cycle", help="cycle ID (default: active cycle)")
    ex.add_argument("--out", default="grcpal-export.zip")
    ex.set_defaults(fn=cmd_export)

    # allow_abbrev=False: "--key <value>" must fail, never be read as --key-file (keys stay out of shell history)
    bk = sub.add_parser("backup", help="encrypted backup of the whole instance (tables, evidence, inbox, config)",
                        allow_abbrev=False)
    bk.add_argument("action", choices=["create", "verify", "restore", "keygen", "kit"])
    bk.add_argument("file", nargs="?", help="backup file (.grcbak) to write, check or restore")
    bk.add_argument("--key-file", help="file holding the backup key (default: GRCPAL_BACKUP_KEY, then "
                                       "keys/backup.key next to the database)")
    bk.add_argument("--kit", help="recovery kit file (holds the backup key) instead of --key-file")
    bk.add_argument("--into", help="restore: a new, empty folder to restore into instead of this instance")
    bk.add_argument("--accept-audit-problems", action="store_true",
                    help="restore even if an audit log in the backup does not verify (recorded)")
    bk.add_argument("--out", help="kit: where to write the recovery kit")
    bk.set_defaults(fn=cmd_backup)

    args = p.parse_args(argv)
    if args.cmd == "collect" and not (args.all or args.names):
        p.error("collect needs collector names or --all")
    if args.base is None and args.cmd not in ("init", "serve", "publish-config"):
        from grcpal import configbundle

        fetched = configbundle.fetch()  # deployed jobs: use the catalog published by the program repo
        args.base = str(fetched) if fetched else None
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())

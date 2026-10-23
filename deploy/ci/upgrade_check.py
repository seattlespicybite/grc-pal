"""Upgrade test: data made by the previous release must survive an upgrade to this commit unchanged.

    python -I deploy/ci/upgrade_check.py seed DIR    # run with the PREVIOUS release installed
    python -I deploy/ci/upgrade_check.py check DIR   # run with THIS commit installed

seed: demo data in DIR/grcpal.db and DIR/evidence, a backup made by the old version, and before.json
(every row, every evidence file's SHA-256, each organization's audit-chain head).
check: applies migrations as the portal would at start, then proves:
  * every old row is still there and every old field still has its value (migrations may only add);
  * every evidence file is byte-identical;
  * each audit chain still verifies and still contains everything it had;
  * the new portal starts on this data and its pages answer;
  * the old version's backup restores into a clean folder with this version.
Only APIs that exist in every release since 0.2.0 are used in seed.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path


def rows_by_table(base, tables):
    return {t: sorted(base.list_prefix(t, ""), key=lambda r: (r["PartitionKey"], r["RowKey"])) for t in tables}


def evidence_hashes(folder: Path) -> dict:
    return {p.relative_to(folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.rglob("*")) if p.is_file()}


def seed(folder: Path) -> int:
    import grcpal
    from grcpal import backup
    from grcpal.catalog import Catalog
    from grcpal.evidence import EvidenceStore
    from grcpal.portal import mailer
    from grcpal.portal.auditlog import AuditLog
    from grcpal.portal.demo import seed as demo_seed
    from grcpal.portal.service import Portal
    from grcpal.portal.store import TABLES, SqliteStore, TenantStore

    folder.mkdir(parents=True, exist_ok=True)
    base = SqliteStore(str(folder / "grcpal.db"))
    portal = Portal(Catalog.load(None), TenantStore(base, "default"), EvidenceStore(folder / "evidence"),
                    mailer=mailer.ConsoleMailer("grc@example.com", sync=True))
    demo_seed(portal)
    key_text = backup.new_key()
    (folder / "backup.key").write_text(key_text)
    inst = backup.Instance(base, {"evidence": backup.LocalArea(folder / "evidence"),
                                  "inbox": backup.LocalArea(folder / "inbox")})
    backup.create(inst, folder / "old.grcbak", backup.load_key(key_text))
    before = {"version": grcpal.__version__, "tables": rows_by_table(base, TABLES),
              "evidence": evidence_hashes(folder / "evidence"),
              "audit": AuditLog(TenantStore(base, "default")).verify()}
    (folder / "before.json").write_text(json.dumps(before, default=str))
    print(f"seeded with GRC-pal {grcpal.__version__}: {sum(len(v) for v in before['tables'].values())} rows, "
          f"{len(before['evidence'])} evidence files")
    return 0


def check(folder: Path) -> int:
    import grcpal
    from grcpal import backup, migrations
    from grcpal.catalog import Catalog
    from grcpal.evidence import EvidenceStore
    from grcpal.portal import mailer
    from grcpal.portal.auditlog import AuditLog
    from grcpal.portal.service import Portal
    from grcpal.portal.store import SqliteStore, TenantStore

    before = json.loads((folder / "before.json").read_text())
    base = SqliteStore(str(folder / "grcpal.db"))
    applied = migrations.migrate(base, audit=migrations.audit_all(base))
    problems = []

    after = rows_by_table(base, before["tables"].keys())
    for table, old_rows in before["tables"].items():
        new_rows = {(r["PartitionKey"], r["RowKey"]): r for r in after[table]}
        for old in old_rows:
            new = new_rows.get((old["PartitionKey"], old["RowKey"]))
            if new is None:
                problems.append(f"{table}: row {old['RowKey']} is missing after the upgrade")
                continue
            changed = [k for k, v in old.items() if json.dumps(new.get(k), default=str, sort_keys=True)
                       != json.dumps(v, default=str, sort_keys=True)]
            if table == "audit" and old["RowKey"] == "head":
                continue  # the head pointer moves forward when migrations are recorded
            if changed:
                problems.append(f"{table}: row {old['RowKey']} changed {changed[:5]} (migrations may only add)")
    if evidence_hashes(folder / "evidence") != before["evidence"]:
        problems.append("evidence files changed during the upgrade")
    chain = AuditLog(TenantStore(base, "default")).verify()
    if not chain["ok"] or chain["records"] < before["audit"]["records"]:
        problems.append(f"audit chain after upgrade: ok={chain['ok']} records={chain['records']} "
                        f"(before {before['audit']['records']}): {chain['problems'][:3]}")

    os.environ.setdefault("GRCPAL_AUTH_MODE", "dev")
    os.environ.setdefault("GRCPAL_ENV", "dev")      # dev sign-in fails closed without it (this script is CI only)
    from fastapi.testclient import TestClient

    from grcpal.portal.app import create_app

    portal = Portal(Catalog.load(None), TenantStore(base, "default"), EvidenceStore(folder / "evidence"),
                    mailer=mailer.ConsoleMailer("grc@example.com", sync=True))
    admin = next((u for u in portal.users() if u["role"] == "admin" and u.get("active", True)), None)
    client = TestClient(create_app(portal), base_url="https://grc.example.com")
    if admin:
        client.headers["X-Dev-Principal"] = json.dumps({"email": admin["RowKey"], "name": admin.get("name", "")})
    for path in ("/healthz", "/", "/controls", "/criteria", "/calendar", "/audit", "/backups"):
        r = client.get(path)
        if r.status_code != 200:
            problems.append(f"GET {path} answered {r.status_code} after the upgrade")

    key = backup.load_key((folder / "backup.key").read_text())
    try:
        result = backup.restore(folder / "old.grcbak", key, backup.folder_instance(folder / "restored"))
        if not result["ok"]:
            problems.append(f"restoring the {before['version']} backup: audit {result['audit']}")
    except backup.BackupError as exc:
        problems.append(f"restoring the {before['version']} backup failed: {exc}")

    for p in problems:
        print(f"UPGRADE PROBLEM: {p}", file=sys.stderr)
    print(f"upgrade {before['version']} -> {grcpal.__version__}: migrations {applied or 'none'}, "
          f"{'OK' if not problems else f'{len(problems)} problem(s)'}")
    return 1 if problems else 0


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("seed", "check"):
        raise SystemExit(__doc__)
    raise SystemExit({"seed": seed, "check": check}[sys.argv[1]](Path(sys.argv[2])))

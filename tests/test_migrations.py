"""Data model migrations: additive, in order, once, recorded; older versions refused only when they can't read."""
from __future__ import annotations

import hashlib
import json

import pytest
from test_backup import make_instance

from grcpal import backup, migrations
from grcpal.portal.auditlog import AuditLog
from grcpal.portal.store import SCHEMA_VERSION, SqliteStore, TenantStore


def add_field(base):
    """Example additive migration: a new field with a default on every user."""
    for row in base.list_prefix("users", ""):
        if "timezone" not in row:
            base.upsert("users", {**row, "timezone": "UTC"})


@pytest.fixture
def fake(monkeypatch):
    """Pretend this build has data model 3: migration 2 (additive) and 3 (additive)."""
    seen = []

    def m3(base):
        seen.append(3)
        for row in base.list_prefix("users", ""):
            base.upsert("users", {**row, "notes_version": 1})

    ms = (migrations.Migration(2, "users get a timezone", lambda b: (seen.append(2), add_field(b))),
          migrations.Migration(3, "users get notes_version", m3))
    monkeypatch.setattr(migrations, "MIGRATIONS", ms)
    monkeypatch.setattr(migrations, "SCHEMA_VERSION", 3)
    monkeypatch.setattr(backup, "SCHEMA_VERSION", 3)
    return seen


def tree_hashes(folder):
    return {p.relative_to(folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.rglob("*")) if p.is_file()}


def test_repository_has_no_migrations_yet_and_rules_pass():
    assert SCHEMA_VERSION == 1 + len(migrations.MIGRATIONS)
    assert migrations.release_problems() == []


def test_fresh_instance_starts_at_the_current_version_without_running_anything(fake):
    base = SqliteStore(":memory:")
    assert migrations.migrate(base) == [] and fake == []
    assert migrations.read_meta(base)["schema_version"] == 3


def test_existing_install_without_meta_is_version_1(tmp_path, fake):
    inst = make_instance(tmp_path)
    assert migrations.current(inst.base)["schema_version"] == 1
    assert [m.version for m in migrations.pending(inst.base)] == [2, 3]


def test_migrations_run_in_order_once_and_are_recorded(tmp_path, fake):
    inst = make_instance(tmp_path)
    before = tree_hashes(tmp_path / "evidence")
    applied = migrations.migrate(inst.base, audit=migrations.audit_all(inst.base))
    assert applied == [2, 3] and fake == [2, 3]
    assert migrations.migrate(inst.base) == [] and fake == [2, 3]  # second start: nothing to do
    meta = migrations.read_meta(inst.base)
    assert meta["schema_version"] == 3 and [h["version"] for h in meta["history"]] == [2, 3]
    users = inst.base.list_prefix("users", "")
    assert all(u["timezone"] == "UTC" and u["notes_version"] == 1 for u in users)
    for t in ("acme", "globex"):
        log = AuditLog(TenantStore(inst.base, t))
        assert [r["detail"]["version"] for r in log.records() if r["action"] == "system.migration"] == [2, 3]
        assert log.verify()["ok"]
    assert tree_hashes(tmp_path / "evidence") == before  # evidence is never touched


def test_migration_code_has_no_way_to_reach_evidence():
    import inspect

    source = inspect.getsource(migrations)
    assert "EvidenceStore" not in source and "grcpal.evidence" not in source
    for m in migrations.MIGRATIONS:
        assert list(inspect.signature(m.run).parameters) == ["base"]


def test_old_version_may_start_on_additively_upgraded_data(tmp_path, fake, monkeypatch):
    inst = make_instance(tmp_path)
    migrations.migrate(inst.base)
    monkeypatch.setattr(migrations, "SCHEMA_VERSION", 1)  # roll back to the previous image
    assert migrations.check(inst.base)["schema_version"] == 3


def test_old_version_is_refused_after_a_breaking_migration(tmp_path, monkeypatch):
    ms = (migrations.Migration(2, "add", add_field), migrations.Migration(3, "rename a field", lambda b: None, breaking=True))
    monkeypatch.setattr(migrations, "MIGRATIONS", ms)
    monkeypatch.setattr(migrations, "SCHEMA_VERSION", 3)
    inst = make_instance(tmp_path)
    migrations.migrate(inst.base)
    assert migrations.read_meta(inst.base)["readable_by"] == 3
    monkeypatch.setattr(migrations, "SCHEMA_VERSION", 2)
    with pytest.raises(migrations.SchemaError, match="restore the backup taken before the update"):
        migrations.check(inst.base)
    with pytest.raises(migrations.SchemaError):
        migrations.migrate(inst.base)


def test_second_replica_waits_for_the_first(tmp_path, fake):
    inst = make_instance(tmp_path)
    migrations.migrate(inst.base)  # replica 1 finished
    inst.base.insert("meta", {"PartitionKey": "_system", "RowKey": "lock-4"})
    assert migrations.migrate(inst.base) == []  # nothing pending: lock irrelevant


def test_a_stuck_lock_gives_a_clear_message(tmp_path, fake):
    inst = make_instance(tmp_path)
    inst.base.insert("meta", {"PartitionKey": "_system", "RowKey": "lock-2"})  # another process died mid-way
    with pytest.raises(migrations.SchemaError, match="lock-2"):
        migrations.migrate(inst.base, wait_seconds=0)
    assert fake == []


def test_restore_of_an_older_backup_upgrades_the_data(tmp_path, monkeypatch):
    key = backup.load_key(backup.new_key())
    out = tmp_path / "old.grcbak"
    backup.create(make_instance(tmp_path / "src"), out, key)  # made at data model 1
    ms = (migrations.Migration(2, "users get a timezone", add_field),)
    monkeypatch.setattr(migrations, "MIGRATIONS", ms)
    monkeypatch.setattr(migrations, "SCHEMA_VERSION", 2)
    monkeypatch.setattr(backup, "SCHEMA_VERSION", 2)
    target = backup.folder_instance(tmp_path / "new")
    result = backup.restore(out, key, target)
    assert result["migrations_applied"] == [2] and result["ok"]
    assert all(u["timezone"] == "UTC" for u in target.base.list_prefix("users", ""))


def test_restore_target_with_only_a_meta_row_counts_as_empty(tmp_path, fake):
    key = backup.load_key(backup.new_key())
    out = tmp_path / "b.grcbak"
    backup.create(make_instance(tmp_path / "src"), out, key)
    target = backup.folder_instance(tmp_path / "new")
    migrations.migrate(target.base)  # the app started once on the empty instance
    assert backup.restore(out, key, target)["ok"]


def test_portal_refuses_to_start_on_data_it_cannot_read(tmp_path, monkeypatch):
    from grcpal.portal import app as app_mod

    db = tmp_path / "grcpal.db"
    base = SqliteStore(str(db))
    base.insert("users", {"PartitionKey": "default|u", "RowKey": "a@example.com"})
    base.upsert("meta", {"PartitionKey": "_system", "RowKey": "schema", "schema_version": 9, "readable_by": 9,
                         "history": []})
    monkeypatch.setenv("GRCPAL_SQLITE", str(db))
    monkeypatch.setenv("GRCPAL_EVIDENCE_DIR", str(tmp_path / "evidence"))
    for var in ("GRCPAL_TABLES_URL", "GRCPAL_DEMO", "GRCPAL_EVIDENCE_ACCOUNT_URL", "GRCPAL_TENANT"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(migrations.SchemaError, match="cannot read it"):
        app_mod.portal_from_env()


def test_cli_migrate_check(tmp_path, monkeypatch, capsys):
    from grcpal import cli

    make_instance(tmp_path)
    monkeypatch.setenv("GRCPAL_SQLITE", str(tmp_path / "grcpal.db"))
    monkeypatch.delenv("GRCPAL_TABLES_URL", raising=False)
    assert cli.main(["migrate", "--check"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["schema_version"] == 1 and info["pending"] == []


# ---------------------------------------------------------------- release rules
def M(n, breaking=False):
    return migrations.Migration(n, f"m{n}", lambda base: None, breaking)


@pytest.mark.parametrize("version,releases,ms,schema,expect", [
    ("0.2.1", {"0.2.0": 1}, (M(2),), 2, "patch release but changes the data model"),
    ("0.3.0", {"0.2.0": 1}, (M(2),), 2, None),
    ("1.0.1", {"1.0.0": 1}, (), 1, None),
    ("1.1.0", {"1.0.0": 1}, (M(2, breaking=True),), 2, "breaking migration 2"),
    ("2.0.0", {"1.0.0": 1}, (M(2, breaking=True),), 2, None),
    ("0.3.0", {"0.2.0": 1}, (M(3),), 2, "numbered 2, 3"),
    ("0.3.0", {"0.2.0": 1}, (M(2),), 1, "SCHEMA_VERSION is 1"),
    ("0.1.9", {"0.2.0": 1}, (), 1, "versions must increase"),
])
def test_release_rules(version, releases, ms, schema, expect):
    problems = migrations.release_problems(version, releases, ms, schema)
    if expect is None:
        assert problems == []
    else:
        assert any(expect in p for p in problems), problems


def test_release_check_needs_matching_tag(capsys):
    from grcpal import __version__

    assert migrations.main(["--release-check", f"v{__version__}"]) == (0 if __version__ in migrations.RELEASES else 1)
    assert migrations.main(["--release-check", "v9.9.9"]) == 1
    assert "does not match" in capsys.readouterr().err

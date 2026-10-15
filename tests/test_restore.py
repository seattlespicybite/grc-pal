"""Restore from a .grcbak file: only into empty targets, only after full verification, chain continues."""
from __future__ import annotations

import json
import stat

import pytest
from test_backup import FakeContainer, make_instance, write_raw

from grcpal import backup
from grcpal.evidence import EvidenceStore
from grcpal.portal.auditlog import AuditLog
from grcpal.portal.store import SqliteStore, TenantStore


@pytest.fixture
def key() -> bytes:
    return backup.load_key(backup.new_key())


@pytest.fixture
def made(tmp_path, key):
    """(source instance, backup file, manifest)."""
    inst = make_instance(tmp_path / "src")
    out = tmp_path / "b.grcbak"
    return inst, out, backup.create(inst, out, key)


def rows_of(base, table):
    return sorted((r["PartitionKey"], r["RowKey"], json.dumps(r, sort_keys=True, default=str))
                  for r in base.list_prefix(table, ""))


def test_round_trip_into_a_new_folder(tmp_path, key, made):
    src, out, manifest = made
    target = backup.folder_instance(tmp_path / "restored")
    result = backup.restore(out, key, target)
    assert result["ok"] and result["tenants"] == ["acme", "globex"]
    assert result["files"] == len(manifest["files"])
    for table in backup.BACKUP_TABLES:
        if table != "audit":
            assert rows_of(target.base, table) == rows_of(src.base, table), table
    # evidence is byte-identical and readable through the normal evidence store
    for f in manifest["files"]:
        area, rel = f["name"].split("/", 1)
        restored = (tmp_path / "restored" / area / rel).read_bytes()
        assert restored == (tmp_path / "src" / area / rel).read_bytes()
    ev = EvidenceStore(tmp_path / "restored" / "evidence", namespace="acme")
    assert ev.latest_manifest("entra_users")["source"] == "entra_users"


def test_each_tenant_chain_continues_with_a_restore_record(tmp_path, key, made):
    _, out, manifest = made
    target = backup.folder_instance(tmp_path / "restored")
    backup.restore(out, key, target)
    for t in ("acme", "globex"):
        log = AuditLog(TenantStore(target.base, t))
        assert log.verify()["ok"]
        last = log.records()[-1]
        assert last["action"] == "backup.restore" and last["target"] == manifest["backup_id"]
        assert last["detail"]["from_version"] == manifest["app_version"]


def test_tenants_stay_separate_after_restore(tmp_path, key, made):
    _, out, _ = made
    target = backup.folder_instance(tmp_path / "restored")
    backup.restore(out, key, target)
    acme = TenantStore(target.base, "acme").list("users")
    assert [u["RowKey"] for u in acme] == ["admin@acme.example.com"]


@pytest.mark.parametrize("busy", ["row", "evidence"])
def test_refuses_a_target_that_has_data(tmp_path, key, made, busy):
    _, out, _ = made
    target = backup.folder_instance(tmp_path / "restored")
    if busy == "row":
        target.base.insert("users", {"PartitionKey": "acme|u", "RowKey": "x@example.com"})
    else:
        (tmp_path / "restored" / "evidence" / "keep.txt").parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "restored" / "evidence" / "keep.txt").write_text("existing")
    with pytest.raises(backup.BackupError, match="empty"):
        backup.restore(out, key, target)
    assert (tmp_path / "restored" / "evidence" / "keep.txt").exists() if busy == "evidence" else True


def test_tampered_backup_writes_nothing(tmp_path, key, made):
    _, out, _ = made
    data = bytearray(out.read_bytes())
    data[len(data) // 2] ^= 1
    out.write_bytes(bytes(data))
    target = backup.folder_instance(tmp_path / "restored")
    with pytest.raises(backup.BackupError):
        backup.restore(out, key, target)
    assert target.base.is_empty() and all(a.is_empty() for a in target.areas.values())


def test_backup_from_a_newer_data_model_is_refused(tmp_path, key, made, monkeypatch):
    _, out, _ = made
    monkeypatch.setattr(backup, "SCHEMA_VERSION", 0)
    with pytest.raises(backup.BackupError, match="Install"):
        backup.restore(out, key, backup.folder_instance(tmp_path / "restored"))


def test_broken_audit_chain_needs_explicit_acceptance(tmp_path, key):
    inst = make_instance(tmp_path / "src")
    ts = TenantStore(inst.base, "acme")
    rec = [r for r in AuditLog(ts).records() if int(r["seq"]) == 1][0]
    ts.update("audit", rec["PartitionKey"], rec["RowKey"], {"target": "edited"})
    out = tmp_path / "b.grcbak"
    backup.create(inst, out, key)
    with pytest.raises(backup.BackupError, match="accept-audit-problems"):
        backup.restore(out, key, backup.folder_instance(tmp_path / "r1"))
    result = backup.restore(out, key, backup.folder_instance(tmp_path / "r2"), accept_audit_problems=True)
    assert result["audit"]["acme"]["ok"] is False and result["audit"]["globex"]["ok"] is True
    last = AuditLog(TenantStore(SqliteStore(str(tmp_path / "r2" / "grcpal.db")), "acme")).records()[-1]
    assert last["detail"]["accepted_audit_problems"] is True


def test_forged_content_is_never_restored(tmp_path, key, made):
    """Even with a valid key, a file whose content differs from its manifest entry stops the restore."""
    import tarfile

    _, good, _ = made
    members = {}
    with good.open("rb") as f, tarfile.open(fileobj=backup._DecryptReader(f, key), mode="r|") as tar:
        for m in tar:
            members[m.name] = tar.extractfile(m).read()
    members["inbox/hr_leavers.csv"] = b"email\nforged@example.com\n"
    forged = tmp_path / "forged.grcbak"
    write_raw(forged, key, members)
    target = backup.folder_instance(tmp_path / "restored")
    with pytest.raises(backup.BackupError, match="did not pass"):
        backup.restore(forged, key, target)
    assert target.base.is_empty()


def test_settings_key_mismatch_is_reported(tmp_path, key, monkeypatch):
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", "key-used-when-backing-up-0123456789")
    inst = make_instance(tmp_path / "src")
    out = tmp_path / "b.grcbak"
    backup.create(inst, out, key)
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", "a-different-key-on-the-new-machine-000")
    result = backup.restore(out, key, backup.folder_instance(tmp_path / "restored"))
    assert any("GRCPAL_ENCRYPTION_KEY" in w for w in result["warnings"])


def test_snapshot_keeps_rows_written_during_a_backup_out(tmp_path, key, monkeypatch):
    inst = make_instance(tmp_path / "src")
    real = SqliteStore.snapshot

    def snapshot_then_write(self, path):
        snap = real(self, path)
        self.insert("users", {"PartitionKey": "acme|u", "RowKey": "late@example.com"})  # after the snapshot
        return snap

    monkeypatch.setattr(SqliteStore, "snapshot", snapshot_then_write)
    manifest = backup.create(inst, tmp_path / "b.grcbak", key)
    assert manifest["rows"]["acme"]["users"] == 1
    assert not list((tmp_path / "src").glob(".grcpal-snapshot-*"))  # the temporary copy is removed


class WritableContainer(FakeContainer):
    def upload_blob(self, name, data, overwrite=False):
        assert not overwrite and name not in self.blobs
        self.blobs[name] = bytes(data)


def test_restore_into_blob_storage(tmp_path, key, made):
    """Azure path: evidence, inbox and config go to (write-once) containers, never overwriting."""
    src, out, manifest = made
    containers = {a: WritableContainer({}) for a in backup.AREAS}
    target = backup.Instance(SqliteStore(":memory:"), {a: backup.BlobArea(c) for a, c in containers.items()})
    backup.restore(out, key, target)
    names = {f"evidence/{n}" for n in containers["evidence"].blobs} | {f"inbox/{n}" for n in containers["inbox"].blobs}
    assert names == {f["name"] for f in manifest["files"]}


def test_recovery_kit_round_trip(tmp_path, key, made, monkeypatch):
    _, out, _ = made
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", "app-settings-key-0123456789abcdef")
    text = backup.make_kit(key, backup._settings_key(), "https://grc.example.com")
    kit = backup.load_kit(text)
    assert kit["key"] == key and kit["settings_key"] == "app-settings-key-0123456789abcdef"
    assert backup.restore(out, kit["key"], backup.folder_instance(tmp_path / "restored"))["ok"]
    with pytest.raises(backup.BackupError):
        backup.load_kit("{}")
    tampered = json.loads(text)
    tampered["backup_key"] = backup.new_key()
    with pytest.raises(backup.BackupError, match="damaged"):
        backup.load_kit(json.dumps(tampered))


def test_ensure_key_creates_a_private_key_once(tmp_path):
    path = tmp_path / "keys" / "backup.key"
    first = backup.ensure_key(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert backup.ensure_key(path) == first


def test_cli_kit_and_restore(tmp_path, monkeypatch, capsys):
    from grcpal import cli

    make_instance(tmp_path / "src")
    monkeypatch.delenv("GRCPAL_TABLES_URL", raising=False)
    monkeypatch.delenv("GRCPAL_EVIDENCE_ACCOUNT_URL", raising=False)
    monkeypatch.delenv("GRCPAL_BACKUP_KEY", raising=False)
    monkeypatch.delenv("GRCPAL_BACKUP_KEY_FILE", raising=False)
    monkeypatch.setenv("GRCPAL_SQLITE", str(tmp_path / "src" / "grcpal.db"))
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", "app-settings-key-0123456789abcdef")
    ev = ["--evidence", str(tmp_path / "src" / "evidence")]
    assert cli.main(ev + ["backup", "keygen"]) == 0  # default: keys/backup.key next to the database
    assert (tmp_path / "src" / "keys" / "backup.key").is_file()
    out = tmp_path / "b.grcbak"
    assert cli.main(ev + ["backup", "create", str(out)]) == 0
    kit = tmp_path / "kit.json"
    assert cli.main(ev + ["backup", "kit", "--out", str(kit)]) == 0
    assert stat.S_IMODE(kit.stat().st_mode) == 0o600
    capsys.readouterr()
    assert cli.main(ev + ["backup", "restore", str(out), "--kit", str(kit), "--into", str(tmp_path / "new")]) == 0
    printed = capsys.readouterr()
    assert '"ok": true' in printed.out and "signs in again" in printed.err
    assert json.loads(kit.read_text())["settings_key"] not in printed.out + printed.err
    # restoring the same backup over the live instance is refused, the live data is untouched
    assert cli.main(ev + ["backup", "restore", str(out), "--kit", str(kit)]) == 2
    actions = [r["action"] for r in AuditLog(TenantStore(SqliteStore(str(tmp_path / "src" / "grcpal.db")), "acme")).records()]
    assert "backup.kit_export" in actions and "backup.restore" not in actions

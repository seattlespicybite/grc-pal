"""Whole-instance backup file (.grcbak): completeness, integrity, encryption and safe reading."""
from __future__ import annotations

import io
import json
import os
import stat
import tarfile
from pathlib import Path

import pytest

from grcpal import backup
from grcpal.evidence import EvidenceStore
from grcpal.portal.auditlog import AuditLog
from grcpal.portal.store import TABLES, SqliteStore, TenantStore


def make_instance(tmp_path: Path) -> backup.Instance:
    """Two tenants with users, settings, audit records, evidence and an inbox file."""
    base = SqliteStore(str(tmp_path / "grcpal.db"))
    for tenant in ("acme", "globex"):
        ts = TenantStore(base, tenant)
        ts.insert("users", {"PartitionKey": "u", "RowKey": f"admin@{tenant}.example.com", "role": "admin"})
        ts.insert("config", {"PartitionKey": "settings", "RowKey": "azure", "secrets": {"key": "v1:ciphertext"}})
        log = AuditLog(ts)
        log.append("admin@example.com", "user.add", f"admin@{tenant}.example.com")
        log.append("admin@example.com", "settings.save", "azure")
        ev = EvidenceStore(tmp_path / "evidence", namespace=tenant)
        run = ev.new_run("entra_users", ["IAM-01"])
        run.add("users", [{"upn": f"a@{tenant}.example.com"}])
        run.finish([])
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "hr_leavers.csv").write_text("email,termination_date\nx@example.com,2026-09-01\n")
    return backup.Instance(base=base, areas={"evidence": backup.LocalArea(tmp_path / "evidence"),
                                             "inbox": backup.LocalArea(inbox)})


@pytest.fixture
def key() -> bytes:
    return backup.load_key(backup.new_key())


def plaintext(path: Path, key: bytes) -> bytes:
    with path.open("rb") as f:
        return backup._DecryptReader(f, key).read()


def test_round_trip_captures_every_table_tenant_and_file(tmp_path, key):
    inst = make_instance(tmp_path)
    out = tmp_path / "b.grcbak"
    manifest = backup.create(inst, out, key)
    assert set(manifest["tables"]) == set(TABLES)  # a new table can never be silently left out
    assert manifest["tenants"] == ["acme", "globex"]
    assert manifest["rows"]["acme"]["users"] == 1
    names = {f["name"] for f in manifest["files"]}
    assert "inbox/hr_leavers.csv" in names
    assert any(n.startswith("evidence/acme/entra_users/") and n.endswith("manifest.json") for n in names)
    assert any(n.startswith("evidence/globex/") for n in names)
    assert manifest["audit"]["acme"]["ok"] and manifest["audit"]["globex"]["ok"]

    report = backup.verify(out, key)
    assert report["ok"], report["problems"]
    assert report["manifest"]["files"] == manifest["files"]


def test_backup_is_recorded_in_each_tenant_audit_log(tmp_path, key):
    inst = make_instance(tmp_path)
    manifest = backup.create(inst, tmp_path / "b.grcbak", key)
    for tenant in ("acme", "globex"):
        actions = [r["action"] for r in AuditLog(TenantStore(inst.base, tenant)).records()]
        assert actions[-2:] == ["backup.create", "backup.complete"]
        assert AuditLog(TenantStore(inst.base, tenant)).verify()["ok"]
    # the start record is inside the backup itself, so the restored chain shows the backup happened
    assert manifest["audit"]["acme"]["records"] == 3


def test_file_is_private_encrypted_and_never_overwritten(tmp_path, key):
    inst = make_instance(tmp_path)
    out = tmp_path / "b.grcbak"
    backup.create(inst, out, key)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    raw = out.read_bytes()
    assert b"admin@acme.example.com" not in raw and b"hr_leavers" not in raw
    assert b"admin@acme.example.com" in plaintext(out, key)
    with pytest.raises(backup.BackupError, match="already exists"):
        backup.create(inst, out, key)


def test_app_encryption_key_is_never_in_the_backup(tmp_path, key, monkeypatch):
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", "app-key-0123456789abcdef-do-not-copy")
    out = tmp_path / "b.grcbak"
    backup.create(make_instance(tmp_path), out, key)
    assert b"app-key-0123456789abcdef" not in plaintext(out, key)


def test_wrong_key_gives_a_clear_message(tmp_path, key):
    out = tmp_path / "b.grcbak"
    backup.create(make_instance(tmp_path), out, key)
    other = backup.load_key(backup.new_key())
    with pytest.raises(backup.BackupError, match="different backup key"):
        backup.verify(out, other)


@pytest.mark.parametrize("where", ["header", "middle", "end"])
def test_any_changed_byte_is_detected(tmp_path, key, where):
    out = tmp_path / "b.grcbak"
    backup.create(make_instance(tmp_path), out, key)
    data = bytearray(out.read_bytes())
    pos = {"header": len(backup.MAGIC) + 5, "middle": len(data) // 2, "end": len(data) - 3}[where]
    data[pos] ^= 0x01
    out.write_bytes(bytes(data))
    with pytest.raises(backup.BackupError):
        backup.verify(out, key)


def test_truncated_file_is_detected(tmp_path, key):
    out = tmp_path / "b.grcbak"
    backup.create(make_instance(tmp_path), out, key)
    data = out.read_bytes()
    out.write_bytes(data[: len(data) - 40])
    with pytest.raises(backup.BackupError, match="incomplete|damaged"):
        backup.verify(out, key)


def test_large_file_spans_many_chunks(tmp_path, key, monkeypatch):
    monkeypatch.setattr(backup, "CHUNK", 4096)
    inst = make_instance(tmp_path)
    blob = os.urandom(50_000)
    (tmp_path / "inbox" / "big.bin").write_bytes(blob)
    out = tmp_path / "b.grcbak"
    backup.create(inst, out, key)
    assert backup.verify(out, key)["ok"]


def write_raw(path: Path, key: bytes, members: dict[str, bytes]) -> None:
    """A hand-made backup, to prove verify rejects content the create step would never produce."""
    with path.open("wb") as f:
        w = backup._EncryptWriter(f, key)
        with tarfile.open(fileobj=w, mode="w|", format=tarfile.PAX_FORMAT) as tar:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        w.close()


@pytest.mark.parametrize("name", ["../escape.txt", "/etc/passwd", "evidence/../../x", "unknown/area.txt"])
def test_verify_rejects_unsafe_names(tmp_path, key, name):
    out = tmp_path / "evil.grcbak"
    write_raw(out, key, {name: b"x"})
    with pytest.raises(backup.BackupError, match="unexpected entry"):
        backup.verify(out, key)


def test_verify_reports_files_that_do_not_match_the_manifest(tmp_path, key):
    good = tmp_path / "b.grcbak"
    backup.create(make_instance(tmp_path), good, key)
    members = {}
    with good.open("rb") as f, tarfile.open(fileobj=backup._DecryptReader(f, key), mode="r|") as tar:
        for m in tar:
            members[m.name] = tar.extractfile(m).read()
    members["inbox/hr_leavers.csv"] = b"email\nchanged@example.com\n"  # re-encrypted with a valid key
    forged = tmp_path / "forged.grcbak"
    write_raw(forged, key, members)
    report = backup.verify(forged, key)
    assert not report["ok"]
    assert any("hr_leavers.csv" in p for p in report["problems"])


def test_a_broken_audit_chain_is_still_backed_up_and_reported(tmp_path, key):
    inst = make_instance(tmp_path)
    ts = TenantStore(inst.base, "acme")
    rec = [r for r in AuditLog(ts).records() if r["seq"] in (1, "1")][0]
    ts.update("audit", rec["PartitionKey"], rec["RowKey"], {"target": "edited"})
    out = tmp_path / "b.grcbak"
    manifest = backup.create(inst, out, key)
    assert manifest["audit"]["acme"]["ok"] is False and manifest["audit"]["globex"]["ok"] is True
    report = backup.verify(out, key)
    assert not report["ok"] and any("acme" in p and "audit" in p for p in report["problems"])


def test_symlinks_in_local_storage_are_not_followed(tmp_path, key):
    inst = make_instance(tmp_path)
    secret = tmp_path / "outside" / "secret.txt"
    secret.parent.mkdir()
    secret.write_text("host secret")
    (tmp_path / "evidence" / "link.txt").symlink_to(secret)
    (tmp_path / "evidence" / "linkdir").symlink_to(secret.parent, target_is_directory=True)
    out = tmp_path / "b.grcbak"
    manifest = backup.create(inst, out, key)
    assert not any("link" in f["name"] for f in manifest["files"])
    assert b"host secret" not in plaintext(out, key)


class FakeBlob:
    def __init__(self, name, data):
        self.name, self.size, self._data = name, len(data), data
        self.last_modified = None


class FakeContainer:
    def __init__(self, blobs: dict[str, bytes]):
        self.blobs = blobs

    def list_blobs(self):
        return [FakeBlob(n, d) for n, d in self.blobs.items()]

    def download_blob(self, name):
        data = self.blobs[name]

        class Stream:
            def chunks(self):
                yield data[:3]
                yield data[3:]
        return Stream()


def test_blob_areas_are_backed_up(tmp_path, key):
    base = SqliteStore(":memory:")
    container = FakeContainer({"acme/aws_iam/2026-10-01T000000Z/manifest.json": b'{"files": []}',
                               "acme/aws_iam/2026-10-01T000000Z/users.json": b"[]"})
    inst = backup.Instance(base=base, areas={"evidence": backup.BlobArea(container)})
    out = tmp_path / "b.grcbak"
    manifest = backup.create(inst, out, key)
    assert {f["name"] for f in manifest["files"]} == {"evidence/" + n for n in container.blobs}
    assert backup.verify(out, key)["ok"]


def test_cli_keygen_create_verify(tmp_path, monkeypatch, capsys):
    from grcpal import cli

    inst = make_instance(tmp_path)
    monkeypatch.setenv("GRCPAL_SQLITE", str(tmp_path / "grcpal.db"))
    monkeypatch.delenv("GRCPAL_TABLES_URL", raising=False)
    monkeypatch.delenv("GRCPAL_EVIDENCE_ACCOUNT_URL", raising=False)
    keyfile = tmp_path / "backup.key"
    assert cli.main(["backup", "keygen", "--key-file", str(keyfile)]) == 0
    assert stat.S_IMODE(keyfile.stat().st_mode) == 0o600
    out = tmp_path / "cli.grcbak"
    ev = str(tmp_path / "evidence")
    assert cli.main(["--evidence", ev, "backup", "create", str(out), "--key-file", str(keyfile)]) == 0
    assert cli.main(["--evidence", ev, "backup", "verify", str(out), "--key-file", str(keyfile)]) == 0
    printed = capsys.readouterr().out
    assert '"ok": true' in printed and keyfile.read_text().strip() not in printed
    del inst


def test_cli_needs_a_key_and_never_takes_it_on_the_command_line(tmp_path, monkeypatch):
    from grcpal import cli

    monkeypatch.delenv("GRCPAL_BACKUP_KEY", raising=False)
    monkeypatch.setenv("GRCPAL_SQLITE", str(tmp_path / "grcpal.db"))
    with pytest.raises(SystemExit, match="GRCPAL_BACKUP_KEY"):
        cli.main(["backup", "create", str(tmp_path / "x.grcbak")])
    with pytest.raises(SystemExit):
        cli.main(["backup", "create", str(tmp_path / "x.grcbak"), "--key", "abc"])


def test_load_key_rejects_weak_or_malformed_keys():
    for bad in ("", "short", "not base64 !!!", backup.new_key()[:-8]):
        with pytest.raises(backup.BackupError):
            backup.load_key(bad)


def test_manifest_records_versions(tmp_path, key):
    from grcpal import __version__
    from grcpal.portal.store import SCHEMA_VERSION

    manifest = backup.create(make_instance(tmp_path), tmp_path / "b.grcbak", key)
    assert manifest["app_version"] == __version__ and manifest["schema_version"] == SCHEMA_VERSION
    assert manifest["format"] == backup.FORMAT and json.dumps(manifest)

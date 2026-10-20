"""Signed update files, the self-test, and the VM updater's apply / trial / health gate / rollback / restore."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from test_backup import make_instance

from grcpal import update

UPDATER = Path(__file__).resolve().parents[1] / "deploy" / "vm" / "grcpal-update"


# ====================================================================== signed update files
@pytest.fixture(scope="module")
def keys():
    return update.keygen()


def bundle(tmp_path, keys, version="0.3.0", image=b"fake image layers", private=None):
    tar = tmp_path / f"image-{version}.tar"
    tar.write_bytes(image)
    out = tmp_path / f"grcpal-{version}.grcupdate"
    update.make_bundle(out, tar, version, f"ghcr.io/example/grc-pal:{version}", "sha256:" + "a" * 64,
                       private or keys[0], 1, "Release notes")
    return out


def test_signed_bundle_verifies(tmp_path, keys):
    m = update.verify_bundle(bundle(tmp_path, keys), [keys[1]])
    assert m["version"] == "0.3.0" and m["notes"] == "Release notes"


def test_bundle_signed_by_another_key_is_refused(tmp_path, keys):
    other_private, _ = update.keygen()
    with pytest.raises(update.UpdateError, match="not signed"):
        update.verify_bundle(bundle(tmp_path, keys, private=other_private), [keys[1]])


def test_key_rotation_accepts_any_listed_key(tmp_path, keys):
    new_private, new_public = update.keygen()
    pub = tmp_path / "keys.pub"
    pub.write_text(keys[1] + "\n" + new_public)
    assert update.verify_bundle(bundle(tmp_path, keys, private=new_private), update.public_keys(pub))


def test_swapped_image_is_refused(tmp_path, keys):
    import io
    import tarfile

    good = bundle(tmp_path, keys)
    with tarfile.open(good) as tar:
        members = {n: tar.extractfile(n).read() for n in tar.getnames()}
    members["image.tar"] = b"malicious layers"
    evil = tmp_path / "evil.grcupdate"
    with tarfile.open(evil, "w") as tar:
        for n, d in members.items():
            info = tarfile.TarInfo(n)
            info.size = len(d)
            tar.addfile(info, io.BytesIO(d))
    with pytest.raises(update.UpdateError, match="does not match its signed checksum"):
        update.verify_bundle(evil, [keys[1]])


def test_edited_manifest_is_refused(tmp_path, keys):
    import io
    import tarfile

    good = bundle(tmp_path, keys)
    with tarfile.open(good) as tar:
        members = {n: tar.extractfile(n).read() for n in tar.getnames()}
    m = json.loads(members["manifest.json"])
    m["version"] = "9.9.9"
    members["manifest.json"] = json.dumps(m).encode()
    evil = tmp_path / "evil.grcupdate"
    with tarfile.open(evil, "w") as tar:
        for n, d in members.items():
            info = tarfile.TarInfo(n)
            info.size = len(d)
            tar.addfile(info, io.BytesIO(d))
    with pytest.raises(update.UpdateError, match="not signed"):
        update.verify_bundle(evil, [keys[1]])


def test_truncated_or_extra_content_is_refused(tmp_path, keys):
    good = bundle(tmp_path, keys)
    cut = tmp_path / "cut.grcupdate"
    cut.write_bytes(good.read_bytes()[:300])
    with pytest.raises(update.UpdateError):
        update.verify_bundle(cut, [keys[1]])


@pytest.mark.parametrize("cur,new,kind", [("0.2.0", "0.2.1", "patch"), ("0.2.1", "0.3.0", "minor"),
                                          ("0.9.0", "1.0.0", "major"), ("0.2.0", "0.2.0", "same"),
                                          ("0.3.0", "0.2.9", "older")])
def test_kind_of(cur, new, kind):
    assert update.kind_of(cur, new) == kind


# ====================================================================== self-test
def test_selftest_passes_on_healthy_data_and_catches_damage(tmp_path):
    inst = make_instance(tmp_path)
    expect = update.counts(inst.base)
    ok = update.selftest(inst.base, tmp_path / "evidence", expect)
    assert ok["ok"] and ok["checked"]["evidence"]["files"] >= 2
    run_file = next(p for p in (tmp_path / "evidence").rglob("users.json"))
    run_file.write_text("[]")
    inst.base.delete("users", "globex|u", "admin@globex.example.com")
    bad = update.selftest(inst.base, tmp_path / "evidence", expect)
    assert not bad["ok"]
    assert any("changed" in p for p in bad["problems"]) and any("table users" in p for p in bad["problems"])


# ====================================================================== Azure trial (copy of the tables)
def _rows(base):
    from grcpal.backup import BACKUP_TABLES
    return {t: sorted(json.dumps(r, sort_keys=True, default=str) for r in base.list_prefix(t, ""))
            for t in BACKUP_TABLES}


def test_azure_trial_migrates_a_copy_and_leaves_live_tables_alone(tmp_path, monkeypatch):
    from grcpal import migrations

    inst = make_instance(tmp_path)
    seen = []

    def add_column(base):  # an additive migration, as the next release would ship
        for r in base.list_prefix("users", ""):
            seen.append(r["RowKey"])
            base.upsert("users", {**r, "new_field": "x"})

    monkeypatch.setattr(migrations, "MIGRATIONS", (migrations.Migration(2, "add new_field", add_column),))
    monkeypatch.setattr(migrations, "SCHEMA_VERSION", 2)
    before = _rows(inst.base)
    result = update.trial_copy(inst.base, "acme")
    assert result["ok"], result["problems"]
    assert result["checked"]["migrations_applied"] == [2] and seen
    after = _rows(inst.base)
    assert {t: v for t, v in after.items() if t != "config"} == {t: v for t, v in before.items() if t != "config"}
    assert all("new_field" not in r for r in inst.base.list_prefix("users", ""))  # only the copy was migrated
    assert update.load_expected(inst.base, "acme") == update.counts(inst.base) | {"config": update.counts(inst.base)["config"] - 1}


def test_azure_trial_stops_on_a_crashing_migration(tmp_path, monkeypatch):
    from grcpal import migrations

    inst = make_instance(tmp_path)

    def broken(base):
        raise RuntimeError("bad migration")

    monkeypatch.setattr(migrations, "MIGRATIONS", (migrations.Migration(2, "broken", broken),))
    monkeypatch.setattr(migrations, "SCHEMA_VERSION", 2)
    result = update.trial_copy(inst.base, "acme")
    assert not result["ok"] and "bad migration" in result["problems"][0]


def test_saved_counts_catch_lost_rows_after_the_switch(tmp_path):
    inst = make_instance(tmp_path)
    update.save_expected(inst.base, "acme")
    assert update.selftest(inst.base, None, update.load_expected(inst.base, "acme"), skip_evidence=True)["ok"]
    inst.base.delete("users", "globex|u", "admin@globex.example.com")
    bad = update.selftest(inst.base, None, update.load_expected(inst.base, "acme"), skip_evidence=True)
    assert not bad["ok"] and any("table users" in p for p in bad["problems"])


def test_saved_counts_expire(tmp_path):
    inst = make_instance(tmp_path)
    inst.base.upsert("config", {"PartitionKey": "acme|state", "RowKey": update.EXPECTED_KEY,
                                "json": json.dumps({"counts": {}, "at": "2020-01-01T00:00:00+00:00"})})
    with pytest.raises(update.UpdateError, match="older than"):
        update.load_expected(inst.base, "acme")
    with pytest.raises(update.UpdateError, match="No row counts"):
        update.load_expected(inst.base, "globex")


def test_record_only_accepts_update_events(tmp_path):
    inst = make_instance(tmp_path)
    update.record(inst.base, "update.applied", {"to": "0.3.0"})
    with pytest.raises(update.UpdateError):
        update.record(inst.base, "user.add", {})


def test_portal_requests_are_small_files(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_UPDATE_REQUESTS", str(tmp_path))
    req = update.write_request("apply", {"version": "0.3.0"}, "sec@example.com")
    assert (tmp_path / f"{req['id']}.json").is_file()
    assert update.pending_requests()[0]["version"] == "0.3.0"
    with pytest.raises(update.UpdateError):
        update.write_request("shell", {"cmd": "rm -rf /"}, "x")
    with pytest.raises(update.UpdateError, match="too large"):
        update.write_request("policy", {"x": "y" * 5000}, "x")


# ====================================================================== the VM updater
def load_updater(tmp_path, monkeypatch):
    if sys.platform == "win32":
        pytest.skip("VM updater runs on Linux only")
    monkeypatch.setenv("GRCPAL_ROOT", str(tmp_path / "root"))
    monkeypatch.setenv("GRCPAL_ETC", str(tmp_path / "etc"))
    monkeypatch.setenv("GRCPAL_HEALTH_SECONDS", "0")
    loader = importlib.machinery.SourceFileLoader("grcpal_update_under_test", str(UPDATER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    mod.time.sleep = lambda s: None
    return mod


def done(rc=0, out=""):
    return subprocess.CompletedProcess([], rc, stdout=out, stderr="" if rc == 0 else out)


class FakeHost:
    """Docker + systemd + HTTP as the updater sees them. Flags choose where things go wrong."""

    def __init__(self, mod, *, signature_ok=True, trial_ok=True, new_healthy=True, new_selftest_ok=True,
                 loaded_id="sha256:" + "b" * 64):
        self.mod, self.calls, self.events = mod, [], []
        self.signature_ok, self.trial_ok = signature_ok, trial_ok
        self.new_healthy, self.new_selftest_ok, self.loaded_id = new_healthy, new_selftest_ok, loaded_id
        self.up = True

    def current_image(self):
        return self.mod.image()["image"]

    def docker(self, *args, check=True, timeout=0):
        self.calls.append(args)
        mod = self.mod
        a = list(args)
        if a[0] == "load":
            return done()
        if a[0] == "image":
            return done(out=self.loaded_id + "\n")
        if a[0] == "rmi":
            return done()
        cmd = a[a.index("grcpal") + 1:] if "grcpal" in a[1:] else []
        if a[0] == "exec":
            cmd = a[3:]
        if cmd[:2] == ["update", "verify"]:
            if not self.signature_ok:
                return self._fail(check, "update: not signed by GRC-pal's release key")
            mounted = next(x for x in a if ".grcupdate:/u/" in x)
            version = re.search(r"grcpal-(\d+\.\d+\.\d+)\.grcupdate", mounted).group(1)
            return done(out=json.dumps({"version": version, "image_ref": f"ghcr.io/example/grc-pal:{version}",
                                        "image_id": "sha256:" + "b" * 64, "notes": "n"}))
        if cmd[:2] == ["backup", "pre-update"]:
            name = "grcpal-acme-20261015T010000Z-pre-update.grcbak"
            (mod.BACKUPS / name).write_bytes(b"backup")
            return done(out=json.dumps({"ok": True, "file": name}))
        if cmd[:2] == ["update", "counts"]:
            return done(out=json.dumps({"users": 2}))
        if cmd[:2] == ["backup", "verify"]:
            return done(out=json.dumps({"ok": True}))
        if cmd[:2] == ["backup", "restore"] and "--into" in cmd:
            return done(out=json.dumps({"ok": True})) if self.trial_ok else self._fail(check, "migration 2 failed")
        if cmd[:2] == ["backup", "restore"]:
            (mod.DATA / "grcpal.db").write_text("restored rows")
            return done(out=json.dumps({"ok": True}))
        if cmd[:2] == ["update", "selftest"]:
            new = self.current_image() == "sha256:" + "b" * 64
            if "--tables-only" in cmd:
                return done(0 if self.trial_ok else 2, json.dumps({"ok": self.trial_ok}))
            ok = self.new_selftest_ok or not new
            return done(0 if ok else 2, json.dumps({"ok": ok, "problems": [] if ok else ["audit log of acme broken"]}))
        if cmd[:2] == ["update", "record"]:
            self.events.append(cmd[cmd.index("--event") + 1])
            return done()
        raise AssertionError(f"unexpected docker call {args}")

    def _fail(self, check, msg):
        if check:
            raise self.mod.Failed(msg)
        return done(2, msg)

    def systemctl(self, action, unit):
        self.calls.append(("systemctl", action))
        if action == "stop":
            self.up = False
        else:
            self.up = True
            if self.current_image() == "sha256:" + "b" * 64:  # the new version migrates at start
                (self.mod.DATA / "grcpal.db").write_text("rows migrated by 0.3.0")

    def running(self):
        return self.up

    def healthy(self):
        return self.up and (self.new_healthy or self.current_image() != "sha256:" + "b" * 64)

    def chown(self, path):
        pass


@pytest.fixture
def vm(tmp_path, monkeypatch):
    mod = load_updater(tmp_path, monkeypatch)
    for d in (mod.DATA / "evidence", mod.DATA / "keys", mod.BACKUPS, mod.UPDATES, mod.STATE, mod.REQUESTS):
        d.mkdir(parents=True, exist_ok=True)
    (mod.DATA / "grcpal.db").write_text("original rows")
    (mod.DATA / "keys" / "backup.key").write_text("key")
    (mod.DATA / "evidence" / "run.json").write_text("evidence")
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "update-signing.pub").write_text("-----BEGIN PUBLIC KEY-----x-----END PUBLIC KEY-----")
    mod.set_image("sha256:" + "a" * 64, "0.2.0")
    staged = mod.UPDATES / "grcpal-0.3.0.grcupdate"
    import io
    import tarfile
    with tarfile.open(staged, "w") as tar:
        info = tarfile.TarInfo("image.tar")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"img!"))
    return mod, staged


def use(mod, **flags):
    host = FakeHost(mod, **flags)
    mod.HOST = host
    return host


def test_successful_update(vm):
    mod, staged = vm
    host = use(mod)
    assert mod.apply(staged) is True
    assert mod.image() == {"image": "sha256:" + "b" * 64, "version": "0.3.0"}
    assert (mod.DATA / "grcpal.db").read_text() == "rows migrated by 0.3.0"
    assert json.loads((mod.STATE / "status.json").read_text())["state"] == "done"
    assert "update.applied" in host.events
    saved = json.loads((mod.STATE / "previous.json").read_text())["saved"]
    assert Path(saved, "grcpal.db").read_text() == "original rows"  # the copy taken before the switch
    assert not Path(saved, "evidence").exists()  # evidence is never copied or touched
    def first(pred):
        return next(i for i, c in enumerate(host.calls) if pred(c))
    backup_at = first(lambda c: "pre-update" in c)
    trial_at = first(lambda c: "restore" in c and "--tables-only" in c)
    stop_at = first(lambda c: c == ("systemctl", "stop"))
    assert backup_at < trial_at < stop_at  # backup, then trial, and only then the live system is touched


def test_bad_signature_changes_nothing(vm):
    mod, staged = vm
    host = use(mod, signature_ok=False)
    with pytest.raises(mod.Failed, match="did not pass its check"):
        mod.apply(staged)
    assert mod.image()["version"] == "0.2.0" and (mod.DATA / "grcpal.db").read_text() == "original rows"
    assert not any(c[0] in ("load", "systemctl") for c in host.calls)


def test_image_id_mismatch_stops_before_any_change(vm):
    mod, staged = vm
    use(mod, loaded_id="sha256:" + "c" * 64)
    with pytest.raises(mod.Failed, match="does not match the signed manifest"):
        mod.apply(staged)
    assert mod.image()["version"] == "0.2.0"


def test_trial_failure_leaves_the_live_system_untouched(vm):
    mod, staged = vm
    host = use(mod, trial_ok=False)
    assert mod.apply(staged) is False
    assert mod.image()["version"] == "0.2.0" and (mod.DATA / "grcpal.db").read_text() == "original rows"
    assert ("systemctl", "stop") not in host.calls
    assert json.loads((mod.STATE / "status.json").read_text())["state"] == "failed"
    assert "update.trial_failed" in host.events and not mod.TRIAL.exists()


@pytest.mark.parametrize("flag", ["new_healthy", "new_selftest_ok"])
def test_failed_health_gate_rolls_back_image_and_data(vm, flag):
    mod, staged = vm
    host = use(mod, **{flag: False})
    assert mod.apply(staged) is False
    assert mod.image() == {"image": "sha256:" + "a" * 64, "version": "0.2.0"}
    assert (mod.DATA / "grcpal.db").read_text() == "original rows"  # migrated copy put aside
    assert (mod.DATA / "evidence" / "run.json").read_text() == "evidence"
    st = json.loads((mod.STATE / "status.json").read_text())
    assert st["state"] == "rolled_back" and "update.rolled_back" in host.events
    failed = next(mod.ROLLBACK.glob("*-failed"))
    assert (failed / "grcpal.db").read_text() == "rows migrated by 0.3.0"  # kept for diagnosis


def test_older_or_same_version_is_not_installed(vm):
    mod, staged = vm
    use(mod)
    mod.set_image("sha256:" + "a" * 64, "0.3.0")
    assert mod.apply(staged) is False and mod.image()["version"] == "0.3.0"


def test_monthly_check_installs_patches_but_waits_for_approval_on_minor(vm):
    mod, staged = vm
    use(mod)
    mod.check()  # 0.2.0 -> 0.3.0 is a minor release
    assert mod.image()["version"] == "0.2.0"
    avail = json.loads((mod.STATE / "available.json").read_text())
    assert avail["version"] == "0.3.0" and avail["kind"] == "minor"
    mod.set_image("sha256:" + "a" * 64, "0.2.9")
    mod.check()  # still minor
    mod.set_image("sha256:" + "a" * 64, "0.3.0")
    mod.check()
    assert json.loads((mod.STATE / "available.json").read_text()) == {}


def stage(mod, version):
    import io
    import tarfile
    path = mod.UPDATES / f"grcpal-{version}.grcupdate"
    with tarfile.open(path, "w") as tar:
        info = tarfile.TarInfo("image.tar")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"img!"))
    return path


def test_patch_is_installed_automatically_only_when_turned_on(vm):
    mod, staged = vm
    staged.unlink()
    stage(mod, "0.2.1")
    host = use(mod)
    (mod.STATE / "policy.json").write_text(json.dumps({"auto_patch": True}))
    mod.check()
    assert mod.image()["version"] == "0.2.1" and "update.applied" in host.events


def test_patch_waits_for_approval_by_default(vm):
    mod, staged = vm
    staged.unlink()
    stage(mod, "0.2.1")
    host = use(mod)
    assert mod.policy()["auto_patch"] is False
    mod.check()
    assert mod.image()["version"] == "0.2.0" and "update.applied" not in host.events
    assert json.loads((mod.STATE / "available.json").read_text())["kind"] == "patch"


def test_approved_request_applies_the_staged_update(vm):
    mod, staged = vm
    host = use(mod)
    (mod.REQUESTS / "r1.json").write_text(json.dumps({"action": "apply", "version": "0.3.0", "by": "sec@example.com"}))
    mod.handle_requests()
    assert mod.image()["version"] == "0.3.0" and not list(mod.REQUESTS.glob("*.json"))
    assert "update.applied" in host.events


@pytest.mark.parametrize("req", [
    {"action": "shell", "cmd": "id"},
    {"action": "apply", "version": "0.3.0; rm -rf /"},
    {"action": "restore", "backup": "../../etc/shadow"},
    {"action": "policy", "auto_patch": "yes"},
])
def test_invalid_requests_are_ignored(vm, req):
    mod, staged = vm
    host = use(mod)
    (mod.REQUESTS / "bad.json").write_text(json.dumps(req))
    mod.handle_requests()
    assert mod.image()["version"] == "0.2.0" and ("systemctl", "stop") not in host.calls
    assert not list(mod.REQUESTS.glob("*.json"))


def test_symlinked_request_is_never_followed(vm, tmp_path):
    mod, staged = vm
    use(mod)
    target = tmp_path / "secret.json"
    target.write_text(json.dumps({"action": "apply", "version": "0.3.0"}))
    (mod.REQUESTS / "link.json").symlink_to(target)
    mod.handle_requests()
    assert mod.image()["version"] == "0.2.0" and target.exists()


def test_restore_request_swaps_in_the_backup_and_keeps_the_old_data(vm):
    mod, staged = vm
    host = use(mod)
    name = "grcpal-acme-20261001T020000Z-scheduled.grcbak"
    (mod.BACKUPS / name).write_bytes(b"backup")
    (mod.REQUESTS / "r.json").write_text(json.dumps({"action": "restore", "backup": name, "by": "sec@example.com"}))
    mod.handle_requests()
    assert (mod.DATA / "grcpal.db").read_text() == "restored rows"
    assert (mod.DATA / "keys" / "backup.key").read_text() == "key"
    before = next(mod.ROLLBACK.glob("*-before-restore"))
    assert (before / "grcpal.db").read_text() == "original rows" and (before / "evidence" / "run.json").exists()
    assert "restore.completed" in host.events


def test_policy_request(vm):
    mod, staged = vm
    use(mod)
    (mod.REQUESTS / "p.json").write_text(json.dumps({"action": "policy", "auto_patch": False, "by": "sec@example.com"}))
    mod.handle_requests()
    assert mod.policy()["auto_patch"] is False


def test_check_request(vm):
    mod, staged = vm
    host = use(mod)
    (mod.REQUESTS / "c.json").write_text(json.dumps({"action": "check", "by": "sec@example.com"}))
    mod.handle_requests()
    assert not list(mod.REQUESTS.glob("*.json"))
    assert "update.checked" in host.events
    history_lines = (mod.STATE / "history.jsonl").read_text().splitlines()
    assert any("update.checked" in line for line in history_lines)


def test_only_one_updater_at_a_time(vm):
    import fcntl

    mod, staged = vm
    use(mod)
    with (mod.STATE / ".lock").open("w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        assert mod.main(["requests"]) == 3


def test_containers_are_hardened():
    if sys.platform == "win32":
        pytest.skip("VM updater runs on Linux only")
    mod_args = None
    loader = importlib.machinery.SourceFileLoader("grcpal_update_args", str(UPDATER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    mod_args = " ".join(mod.base_args())
    for flag in ("--read-only", "--cap-drop ALL", "no-new-privileges", "--user 10001:10001", "/state:ro"):
        assert flag in mod_args


def test_rollback_keeps_the_app_owning_its_files(vm):
    """Found by the end-to-end test: root-made copies left the app unable to write its database."""
    import os
    mod, staged = vm
    if os.geteuid() != 0:
        pytest.skip("needs root to change owners")
    for p in (mod.DATA / "grcpal.db", mod.DATA / "keys", mod.DATA / "keys" / "backup.key"):
        os.chown(p, 10001, 10001)
    use(mod, new_healthy=False)
    mod.apply(staged)
    for p in (mod.DATA / "grcpal.db", mod.DATA / "keys", mod.DATA / "keys" / "backup.key"):
        assert p.stat().st_uid == 10001, p


def test_second_backup_location_is_mounted_only_when_safe(tmp_path, monkeypatch):
    mod = load_updater(tmp_path, monkeypatch)
    (tmp_path / "etc").mkdir()
    share = tmp_path / "nas"
    share.mkdir()
    env = tmp_path / "etc" / "grcpal.env"
    env.write_text(f"GRCPAL_ENV=production\nGRCPAL_BACKUP_DIR_2_HOST={share}\n")
    args = " ".join(mod.base_args())
    assert f"{share}:/backups2" in args and "GRCPAL_BACKUP_DIR_2=/backups2" in args
    for bad in (str(tmp_path / "missing"), str(mod.ROOT / "data"), "/"):
        env.write_text(f"GRCPAL_BACKUP_DIR_2_HOST={bad}\n")
        assert "/backups2" not in " ".join(mod.base_args())


def test_rollback_copies_are_kept_for_30_days(vm):
    import datetime as dt
    mod, _ = vm
    mod.ROLLBACK.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    names = [f"{now - dt.timedelta(days=d):%Y%m%dT%H%M%SZ}-0.{d}.0" for d in (1, 10, 20, 40, 50, 60)]
    for n in names:
        (mod.ROLLBACK / n).mkdir()
    mod.prune_rollbacks()
    left = sorted(p.name for p in mod.ROLLBACK.iterdir())
    assert left == sorted(names[:3])  # the last 30 days (also more than the newest two)
    for n in names[3:5]:
        (mod.ROLLBACK / n).mkdir()
    shutil.rmtree(mod.ROLLBACK / names[0])
    shutil.rmtree(mod.ROLLBACK / names[1])
    shutil.rmtree(mod.ROLLBACK / names[2])
    mod.prune_rollbacks()
    assert sorted(p.name for p in mod.ROLLBACK.iterdir()) == sorted(names[3:5])  # never fewer than two


# ================================================================ release list: "do I need this update?"
CHANGELOG = """# Changelog

## [Unreleased]
### Added
- not released yet

## [0.3.1] - 2026-11-02
### Security
- Fix session fixation
### Fixed
- Backups page typo
- Calendar order

## [0.3.0] - 2026-10-20
### Added
- Updates page progress
"""


def test_changelog_section_is_the_release_notes():
    notes = update.changelog_section(CHANGELOG, "0.3.1")
    assert notes.startswith("### Security") and "Calendar order" in notes and "Updates page progress" not in notes
    with pytest.raises(update.UpdateError, match="no section for 0.9.9"):
        update.changelog_section(CHANGELOG, "0.9.9")


def test_notes_summary_and_advice():
    s = update.notes_summary(update.changelog_section(CHANGELOG, "0.3.1"))
    assert s == {"security": 1, "fixed": 2, "added": 0, "changed": 0}
    assert update.advice("patch", s)["level"] == "security"
    assert update.advice("minor", update.notes_summary("### Added\n- x"))["level"] == "features"
    assert update.advice("patch", update.notes_summary("### Fixed\n- x"))["level"] == "fixes"
    assert update.advice("major", update.notes_summary("### Added\n- x"))["level"] == "major"


def test_newer_releases_ignores_drafts_bad_tags_older_and_foreign_links():
    rows = [{"tag_name": "v0.3.1", "body": "### Security\n- a", "html_url": "https://github.com/o/r/releases/tag/v0.3.1",
             "published_at": "2026-11-02T10:00:00Z"},
            {"tag_name": "v0.3.0", "body": "### Added\n- b", "html_url": "javascript:alert(1)"},
            {"tag_name": "v0.4.0", "draft": True}, {"tag_name": "v0.5.0", "prerelease": True},
            {"tag_name": "v0.2.0"}, {"tag_name": "v0.1.9"}, {"tag_name": "<script>"}, "not a dict"]
    out = update.newer_releases(rows, "0.2.0")
    assert [r["version"] for r in out] == ["0.3.1", "0.3.0"]
    assert out[0]["kind"] == "minor" and out[0]["advice"]["level"] == "security" and out[0]["published"] == "2026-11-02"
    assert out[1]["url"] == ""

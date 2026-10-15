"""Backups page: admins only, one organization per instance, configured locations only, everything audited."""
from __future__ import annotations

import datetime as dt
import json
import os

import pytest
from fastapi.testclient import TestClient
from test_portal import ADMIN, AUDITOR, CONTRIB, as_, csrf, make_portal

from grcpal import backup, backup_store
from grcpal.portal.app import create_app
from grcpal.portal.service import Forbidden, Invalid


@pytest.fixture()
def site(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_JOBS_SYNC", "1")
    monkeypatch.setenv("GRCPAL_BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("GRCPAL_BACKUP_DIR_HOST", "/var/lib/grcpal/backups")
    monkeypatch.setenv("GRCPAL_BACKUP_KEY_FILE", str(tmp_path / "keys" / "backup.key"))
    for var in ("GRCPAL_ENV", "GRCPAL_TENANT", "GRCPAL_BOOTSTRAP_ADMINS", "GRCPAL_EVIDENCE_ACCOUNT_URL",
                "GRCPAL_TABLES_URL", "GRCPAL_PUBLIC_URL", "GRCPAL_DEV_PRINCIPAL", "GRCPAL_SQLITE", "GRCPAL_BACKUP_KEY",
                "GRCPAL_BACKUP_DIR_2"):
        monkeypatch.delenv(var, raising=False)
    portal = make_portal(tmp_path)
    run = portal.evidence.new_run("entra_users", ["IAM-01"])
    run.add("users", [{"upn": "a@example.com"}])
    run.finish([])
    return portal, TestClient(create_app(portal), base_url="https://grc.example.com"), tmp_path


def actions(portal):
    return [r["action"] for r in portal.log.records()]


def test_backup_now_writes_a_checked_backup_where_the_operator_said(site):
    portal, _, tmp = site
    job = portal.backup_now(ADMIN, "local")
    assert job["status"] == "done", job
    files = list((tmp / "backups").glob("grcpal-acme-*-manual.grcbak"))
    assert len(files) == 1
    assert job["result"]["verified"] is True
    assert job["result"]["where"].startswith("/var/lib/grcpal/backups/grcpal-acme-")
    key = backup.load_key((tmp / "keys" / "backup.key").read_text())  # created on first use
    assert backup.verify(files[0], key)["ok"]
    assert {"backup.requested", "backup.create", "backup.complete"} <= set(actions(portal))
    listed = portal.backups_overview(ADMIN)["places"][0]["backups"]
    assert listed[0]["summary"]["verified_ok"] is True and listed[0]["kind"] == "manual"


@pytest.mark.parametrize("who", [CONTRIB, AUDITOR])
def test_only_admins(site, who):
    portal, client, _ = site
    with pytest.raises(Forbidden):
        portal.backup_now(who, "local")
    with pytest.raises(Forbidden):
        portal.recovery_kit(who)
    assert as_(client, who).get("/backups").status_code == 403


def test_page_and_actions_need_csrf(site):
    portal, client, _ = site
    as_(client, ADMIN)
    page = client.get("/backups")
    assert page.status_code == 200 and "Download your recovery kit" in page.text
    r = client.post("/backups/now", data={"destination": "local", "csrf": "wrong"}, follow_redirects=False)
    assert r.status_code in (400, 403)
    assert not portal.jobs.recent(5, "backup")


def test_download_streams_the_file_and_is_audited(site):
    portal, client, tmp = site
    portal.backup_now(ADMIN, "local")
    name = next((tmp / "backups").glob("*.grcbak")).name
    as_(client, ADMIN)
    token = csrf(client, "/backups")
    r = client.post("/backups/download", data={"destination": "local", "name": name, "csrf": token})
    assert r.status_code == 200 and r.content == (tmp / "backups" / name).read_bytes()
    assert "attachment" in r.headers["content-disposition"] and r.headers["cache-control"] == "no-store"
    assert "backup.download" in actions(portal)


@pytest.mark.parametrize("name", ["../grcpal.db", "grcpal-acme-20261012T010000Z-manual.grcbak.json",
                                  "grcpal-globex-20261012T010000Z-manual.grcbak", "x.grcbak"])
def test_download_refuses_anything_but_a_listed_backup(site, name):
    portal, _, tmp = site
    (tmp / "backups").mkdir(exist_ok=True)
    (tmp / "backups" / "grcpal-globex-20261012T010000Z-manual.grcbak").write_bytes(b"other")
    with pytest.raises(Invalid):
        portal.backup_download(ADMIN, "local", name)


def test_recovery_kit_opens_the_backups_and_is_recorded(site, monkeypatch):
    portal, client, tmp = site
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", "app-key-for-integrations-0123456789")
    portal.backup_now(ADMIN, "local")
    as_(client, ADMIN)
    r = client.post("/backups/kit", data={"csrf": csrf(client, "/backups")})
    kit = backup.load_kit(r.text)
    assert kit["settings_key"] == "app-key-for-integrations-0123456789"
    assert backup.verify(next((tmp / "backups").glob("*.grcbak")), kit["key"])["ok"]
    assert "backup.kit_export" in actions(portal)
    assert "app-key-for-integrations" not in json.dumps([r["detail"] for r in portal.log.records()])
    assert "Download your recovery kit" not in client.get("/backups").text


def test_instance_with_another_organization_is_blocked(site):
    """A whole-instance backup would include the other organization's data: page refuses, CLI only."""
    portal, client, tmp = site
    portal.store.backend.insert("users", {"PartitionKey": "globex|u", "RowKey": "x@globex.example.com"})
    with pytest.raises(Invalid, match="more than one organization"):
        portal.backup_now(ADMIN, "local")
    with pytest.raises(Invalid):
        portal.recovery_kit(ADMIN)
    assert portal.run_due_backups() == []
    assert "more than one organization" in as_(client, ADMIN).get("/backups").text
    assert not (tmp / "backups").exists() or not list((tmp / "backups").glob("*.grcbak"))


def test_schedule_is_validated_and_audited(site):
    portal, _, _ = site
    with pytest.raises(Invalid, match="hour"):
        portal.save_backup_schedule(ADMIN, {"frequency": "daily", "hour": "25", "destination": "local"})
    with pytest.raises(Invalid, match="locations"):
        portal.save_backup_schedule(ADMIN, {"frequency": "daily", "hour": "2", "destination": "/etc"})
    saved = portal.save_backup_schedule(ADMIN, {"frequency": "weekly", "hour": "3", "destination": "local",
                                                "keep_daily": "5", "keep_weekly": "2", "keep_monthly": "6",
                                                "keep_pre_update": "2"})
    assert portal.backup_schedule()["frequency"] == "weekly" and saved["keep_daily"] == 5
    assert portal.log.records()[-1]["action"] == "backup.schedule"


def test_run_due_makes_the_scheduled_backup_once(site, monkeypatch):
    portal, _, tmp = site
    done = portal.run_due_backups(now=dt.datetime(2026, 10, 12, 5, 0, tzinfo=dt.timezone.utc))
    assert [d["kind"] for d in done] == ["scheduled"] and done[0]["verified"]
    # same day again: nothing to do (the real file is dated now, so test due() directly as well)
    existing = backup_store.FolderDestination("local", "x", tmp / "backups").list()
    assert not backup_store.due(portal.backup_schedule(), existing, existing[0]["created"] + dt.timedelta(hours=1))


def test_queued_request_on_azure_is_picked_up_by_the_job(site, monkeypatch):
    portal, _, tmp = site
    monkeypatch.setenv("GRCPAL_TABLES_URL", "https://example.table.core.windows.net")  # queue mode only
    out = portal.backup_now(ADMIN, "local")
    assert out["queued"] and not list((tmp / "backups").glob("*.grcbak"))
    assert portal.backups_overview(ADMIN)["request"]["by"] == ADMIN.email
    portal.save_backup_schedule(ADMIN, {"frequency": "off", "hour": "2", "destination": "local"})
    done = portal.run_due_backups()
    assert [d["kind"] for d in done] == ["manual"] and done[0]["requested_by"] == ADMIN.email
    assert portal.run_due_backups() == []  # request cleared


def test_retention_removes_old_backups_and_records_it(site):
    portal, _, tmp = site
    folder = tmp / "backups"
    folder.mkdir()
    now = dt.datetime.now(dt.timezone.utc)
    for days in range(1, 40):
        (folder / backup_store.file_name("acme", "scheduled", now - dt.timedelta(days=days))).write_bytes(b"x")
    portal.save_backup_schedule(ADMIN, {"frequency": "daily", "hour": "2", "destination": "local", "keep_daily": "7",
                                        "keep_weekly": "2", "keep_monthly": "1", "keep_pre_update": "3"})
    result = portal.backup_now(ADMIN, "local")["result"]
    left = sorted(p.name for p in folder.glob("*.grcbak"))
    assert len(left) <= 7 + 2 + 1 and any(n.endswith("-manual.grcbak") for n in left)
    assert result["removed_by_retention"] and "backup.retention_delete" in actions(portal)


def test_to_keep_grandfather_father_son():
    now = dt.datetime(2026, 10, 12, 3, tzinfo=dt.timezone.utc)
    items = [backup_store.parse_name(backup_store.file_name("acme", "scheduled", now - dt.timedelta(days=d)))
             for d in range(400)]
    items += [backup_store.parse_name(backup_store.file_name("acme", "pre-update", now - dt.timedelta(days=d, hours=1)))
              for d in range(10)]
    keep = backup_store.to_keep(items, backup_store.schedule({}))
    regular = [n for n in keep if n.endswith("-scheduled.grcbak")]
    pre = [n for n in keep if n.endswith("-pre-update.grcbak")]
    assert len(pre) == 3
    assert 7 <= len(regular) <= 7 + 4 + 12
    newest = backup_store.file_name("acme", "scheduled", now)
    assert newest in keep


def test_due_rules():
    sched = backup_store.schedule({"frequency": "daily", "hour": 2})
    at = dt.datetime(2026, 10, 12, 1, tzinfo=dt.timezone.utc)
    assert not backup_store.due(sched, [], at)
    assert backup_store.due(sched, [], at.replace(hour=3))
    today = [backup_store.parse_name(backup_store.file_name("acme", "scheduled", at.replace(hour=2)))]
    assert not backup_store.due(sched, today, at.replace(hour=3))
    manual = [backup_store.parse_name(backup_store.file_name("acme", "manual", at.replace(hour=2)))]
    assert backup_store.due(sched, manual, at.replace(hour=3))
    assert not backup_store.due(backup_store.schedule({"frequency": "off"}), [], at.replace(hour=3))


@pytest.mark.parametrize("name", ["../x.grcbak", "grcpal-acme-2026-manual.grcbak", "grcpal-ACME-20261012T010000Z-manual.grcbak",
                                  "grcpal-acme-20261012T010000Z-other.grcbak", "/abs/grcpal-acme-20261012T010000Z-manual.grcbak"])
def test_parse_name_is_strict(name):
    assert backup_store.parse_name(name) is None


class Blob:
    def __init__(self, name, data):
        self.name, self.size = name, len(data)


class Container:
    container_name = "backups"

    def __init__(self):
        self.blobs = {}

    def list_blobs(self):
        return [Blob(n, d) for n, d in self.blobs.items()]

    def upload_blob(self, name, data, overwrite=False):
        assert not overwrite and name not in self.blobs, "write-once"
        self.blobs[name] = data.read() if hasattr(data, "read") else bytes(data)

    def download_blob(self, name):
        data = self.blobs[name]

        class S:
            def chunks(self):
                yield data
        return S()


def test_blob_destination_is_write_once(site):
    portal, _, tmp = site
    dest = backup_store.BlobDestination("azure", "Azure", Container())
    key = backup.load_key(backup.new_key())
    result = backup_store.run(portal._backup_instance(), dest, key, "acme", "manual",
                              sched=backup_store.schedule({}))
    assert result.summary["verified_ok"] and result.pruned == []
    listed = dest.list()
    assert listed[0]["name"] == result.name and listed[0]["summary"]["verified_ok"]
    assert backup_store.verify_existing(dest, result.name, key)["ok"]
    with pytest.raises(backup.BackupError, match="write-once"):
        dest.delete(result.name)
    import tempfile
    assert not [p for p in os.listdir(tempfile.gettempdir()) if p.startswith(("grcpal-backup-", "grcpal-verify-"))]

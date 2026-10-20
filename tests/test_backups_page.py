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


def test_run_due_skips_while_another_run_is_in_progress(site):
    """The Azure job checks every 15 minutes; a long backup must not be started twice."""
    portal, _, tmp = site
    now = dt.datetime(2026, 10, 12, 5, 0, tzinfo=dt.timezone.utc)
    portal.settings_store.set_state(backup_store.RUNNING_KEY, {"at": (now - dt.timedelta(minutes=20)).isoformat()})
    assert portal.run_due_backups(now=now) == []
    assert not list((tmp / "backups").glob("*.grcbak"))
    # a marker left by a run that crashed long ago does not block backups forever
    portal.settings_store.set_state(backup_store.RUNNING_KEY, {"at": (now - dt.timedelta(hours=7)).isoformat()})
    assert [d["kind"] for d in portal.run_due_backups(now=now)] == ["scheduled"]
    assert portal.settings_store.state(backup_store.RUNNING_KEY, None) is None  # cleared when done


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
              for d in range(0, 65, 5)]
    keep = backup_store.to_keep(items, backup_store.schedule({}), now=now)
    regular = [n for n in keep if n.endswith("-scheduled.grcbak")]
    pre = [n for n in keep if n.endswith("-pre-update.grcbak")]
    assert len(pre) == 6  # every pre-update backup from the last 30 days (rollback window), at least the newest 3
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


# ================================================================ Updates page and in-app restore (VM)
@pytest.fixture()
def vm_site(site, monkeypatch):
    portal, client, tmp = site
    (tmp / "requests").mkdir()
    (tmp / "state").mkdir()
    monkeypatch.setenv("GRCPAL_UPDATE_REQUESTS", str(tmp / "requests"))
    monkeypatch.setenv("GRCPAL_UPDATE_STATE", str(tmp / "state"))
    return portal, client, tmp


def requests_in(tmp):
    return [json.loads(p.read_text()) for p in sorted((tmp / "requests").glob("*.json"))]


def test_approve_only_what_the_updater_offered(vm_site):
    portal, client, tmp = vm_site
    with pytest.raises(Invalid, match="not waiting"):
        portal.approve_update(ADMIN, "0.3.0")
    (tmp / "state" / "available.json").write_text(json.dumps({"version": "0.3.0", "kind": "minor", "notes": "New"}))
    as_(client, ADMIN)
    page = client.get("/updates")
    assert "Approve and install 0.3.0" in page.text
    r = client.post("/updates/approve", data={"version": "0.3.0", "csrf": csrf(client, "/updates")}, follow_redirects=False)
    assert r.status_code == 303
    assert requests_in(tmp) == [{**requests_in(tmp)[0], "action": "apply", "version": "0.3.0", "by": ADMIN.email}]
    assert portal.log.records()[-1]["action"] == "update.approved"
    with pytest.raises(Invalid):
        portal.approve_update(ADMIN, "9.9.9")


@pytest.mark.parametrize("who", [CONTRIB, AUDITOR])
def test_updates_are_admin_only(vm_site, who):
    portal, client, tmp = vm_site
    (tmp / "state" / "available.json").write_text(json.dumps({"version": "0.3.0", "kind": "minor"}))
    with pytest.raises(Forbidden):
        portal.approve_update(who, "0.3.0")
    with pytest.raises(Forbidden):
        portal.set_update_policy(who, False, False)
    assert as_(client, who).get("/updates").status_code == 403
    assert requests_in(tmp) == []


def test_policy_request_is_audited(vm_site):
    portal, _, tmp = vm_site
    portal.set_update_policy(ADMIN, auto_patch=False, online=True)
    assert requests_in(tmp)[0]["auto_patch"] is False and requests_in(tmp)[0]["online"] is True
    assert portal.log.records()[-1]["action"] == "update.policy_requested"


def test_status_and_history_from_the_updater_are_shown(vm_site):
    portal, client, tmp = vm_site
    (tmp / "state" / "status.json").write_text(json.dumps({"state": "rolled_back", "message": "Back on 0.2.0: self-test failed",
                                                           "at": "2026-10-15T01:00:00+00:00"}))
    (tmp / "state" / "history.jsonl").write_text(json.dumps({"at": "2026-10-15T01:00:00+00:00", "event": "update.rolled_back",
                                                             "from": "0.3.0", "to": "0.2.0"}) + "\n")
    page = as_(client, ADMIN).get("/updates").text
    assert "Back on 0.2.0" in page and "update rolled back" in page


def test_in_app_restore_needs_a_checked_backup_and_typed_confirmation(vm_site):
    portal, client, tmp = vm_site
    portal.backup_now(ADMIN, "local")
    name = next((tmp / "backups").glob("*.grcbak")).name
    with pytest.raises(Invalid, match="RESTORE"):
        portal.request_restore(ADMIN, "local", name, "yes")
    with pytest.raises(Invalid, match="Unknown"):
        portal.request_restore(ADMIN, "local", "../grcpal.db", "RESTORE")
    with pytest.raises(Forbidden):
        portal.request_restore(CONTRIB, "local", name, "RESTORE")
    as_(client, ADMIN)
    assert "Restore this backup" in client.get("/backups").text
    r = client.post("/backups/restore", data={"destination": "local", "name": name, "confirm": "RESTORE",
                                              "csrf": csrf(client, "/backups")}, follow_redirects=False)
    assert r.status_code == 303 and "/updates" in r.headers["location"]
    assert requests_in(tmp)[-1]["action"] == "restore" and requests_in(tmp)[-1]["backup"] == name
    assert portal.log.records()[-1]["action"] == "restore.requested"


def test_unchecked_backup_cannot_be_restored(vm_site):
    portal, _, tmp = vm_site
    folder = tmp / "backups"
    folder.mkdir()
    name = backup_store.file_name("acme", "manual")
    (folder / name).write_bytes(b"x")  # no summary: never checked
    with pytest.raises(Invalid, match="Check this backup first"):
        portal.request_restore(ADMIN, "local", name, "RESTORE")


def test_without_the_vm_updater_there_is_no_in_app_restore(site):
    portal, client, tmp = site
    portal.backup_now(ADMIN, "local")
    name = next((tmp / "backups").glob("*.grcbak")).name
    with pytest.raises(Invalid, match="VM updater"):
        portal.request_restore(ADMIN, "local", name, "RESTORE")
    assert "Restore this backup" not in as_(client, ADMIN).get("/backups").text
    assert "Manual installation" in client.get("/updates").text


def test_progress_endpoint_reports_step_and_percent(vm_site):
    portal, client, tmp = vm_site
    (tmp / "state" / "status.json").write_text(json.dumps({"state": "trial", "message": "Trying 0.3.0 on a copy",
                                                           "at": "2026-10-17T01:00:00+00:00", "percent": 40,
                                                           "backup": "secret-name-not-needed"}))
    r = as_(client, ADMIN).get("/updates/progress")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert r.json() == {"state": "trial", "message": "Trying 0.3.0 on a copy", "at": "2026-10-17T01:00:00+00:00",
                        "percent": 40, "active": True, "pending": False}
    page = client.get("/updates").text
    assert 'data-update-progress="/updates/progress"' in page and "Trial on a copy" in page
    (tmp / "state" / "status.json").write_text(json.dumps({"state": "done", "message": "Updated", "percent": 100}))
    assert client.get("/updates/progress").json()["active"] is False


def test_progress_counts_a_request_the_updater_has_not_picked_up(vm_site):
    portal, client, tmp = vm_site
    (tmp / "state" / "available.json").write_text(json.dumps({"version": "0.3.0", "kind": "minor"}))
    portal.approve_update(ADMIN, "0.3.0")
    p = as_(client, ADMIN).get("/updates/progress").json()
    assert p["pending"] is True and p["active"] is True


@pytest.mark.parametrize("who", [CONTRIB, AUDITOR])
def test_progress_is_admin_only(vm_site, who):
    _, client, _ = vm_site
    assert as_(client, who).get("/updates/progress").status_code == 403


ROWS = [{"tag_name": "v99.0.1", "body": "### Security\n- fixed a thing\n### Fixed\n- <b>bold</b>",
         "html_url": "https://github.com/seattlespicybite/grc-pal/releases/tag/v99.0.1"},
        {"tag_name": "v99.0.0", "body": "### Added\n- big feature"}]


@pytest.fixture()
def feed(monkeypatch):
    from grcpal import update
    from grcpal.portal import updates
    calls = []

    def fetch(repo, timeout=5):
        calls.append(repo)
        return ROWS
    monkeypatch.setenv("GRCPAL_UPDATE_CHECK", "on")
    monkeypatch.setattr(update, "fetch_releases", fetch)
    monkeypatch.setattr(updates, "_FEED", {})
    return calls


def test_release_list_says_whether_an_update_is_needed(site, feed, monkeypatch):
    portal, client, _ = site
    from grcpal.portal import updates
    monkeypatch.setattr(updates.UpdatesMixin, "deployment", property(lambda s: "azure"))
    page = as_(client, ADMIN).get("/updates").text
    assert "99.0.1" in page and "99.0.0" in page and "Contains security fixes" in page
    assert "&lt;b&gt;bold&lt;/b&gt;" in page and "<b>bold</b>" not in page  # notes from the internet are escaped
    assert "run the" in page.lower() and "with version 99.0.1" in page
    client.get("/updates")
    assert feed == ["seattlespicybite/grc-pal"]  # cached: GitHub is asked once


def test_release_list_is_off_on_an_offline_vm_and_with_the_switch(vm_site, feed, monkeypatch):
    portal, client, tmp = vm_site
    assert "99.0.1" not in as_(client, ADMIN).get("/updates").text  # VM without "download releases"
    (tmp / "state" / "policy.json").write_text(json.dumps({"online": True}))
    assert "99.0.1" in client.get("/updates").text
    monkeypatch.setenv("GRCPAL_UPDATE_CHECK", "off")
    assert portal.release_feed(True) == {"enabled": False, "releases": []}


def test_release_list_survives_github_being_down(site, monkeypatch):
    from grcpal import update
    from grcpal.portal import updates
    monkeypatch.setenv("GRCPAL_UPDATE_CHECK", "on")
    monkeypatch.setattr(updates, "_FEED", {})

    def down(repo, timeout=5):
        raise OSError("network unreachable")
    monkeypatch.setattr(update, "fetch_releases", down)
    portal, client, _ = site
    r = as_(client, ADMIN).get("/updates")
    assert r.status_code == 200 and "Could not reach GitHub" in r.text


def test_manual_check_triggers_feed_refresh_and_writes_vm_request(vm_site, feed):
    portal, client, tmp = vm_site
    (tmp / "state" / "policy.json").write_text(json.dumps({"online": True}))
    as_(client, ADMIN)
    r = client.post("/updates/check", data={"csrf": csrf(client, "/updates")}, follow_redirects=False)
    assert r.status_code == 303 and "/updates" in r.headers["location"]
    reqs = requests_in(tmp)
    assert any(req.get("action") == "check" and req.get("by") == ADMIN.email for req in reqs)
    actions_list = [rec["action"] for rec in portal.log.records()]
    assert "update.checked" in actions_list


@pytest.mark.parametrize("who", [CONTRIB, AUDITOR])
def test_manual_check_is_admin_only(vm_site, who):
    _, client, _ = vm_site
    as_(client, who)
    r = client.post("/updates/check", data={"csrf": "test"}, follow_redirects=False)
    assert r.status_code == 403


def test_manual_check_needs_valid_csrf(vm_site):
    _, client, _ = vm_site
    as_(client, ADMIN)
    r = client.post("/updates/check", data={"csrf": "invalid-token"}, follow_redirects=False)
    assert r.status_code in (400, 403)


def test_verify_installation_endpoint(vm_site):
    portal, client, _ = vm_site
    as_(client, ADMIN)
    r = client.post("/updates/verify", data={"csrf": csrf(client, "/updates")}, follow_redirects=True)
    assert r.status_code == 200
    assert "Verification passed" in r.text
    actions_list = [rec["action"] for rec in portal.log.records()]
    assert "update.verified" in actions_list


@pytest.mark.parametrize("who", [CONTRIB, AUDITOR])
def test_verify_installation_is_admin_only(vm_site, who):
    _, client, _ = vm_site
    as_(client, who)
    r = client.post("/updates/verify", data={"csrf": "test"}, follow_redirects=False)
    assert r.status_code == 403


def test_rollback_endpoint_and_validation(vm_site):
    portal, client, tmp = vm_site
    as_(client, ADMIN)
    token = csrf(client, "/updates")
    # No previous recorded
    with pytest.raises(Invalid, match="Nothing to roll back to"):
        portal.request_rollback(ADMIN, "ROLLBACK")
    r_bad_confirm = client.post("/updates/rollback", data={"confirm": "NO", "csrf": token}, follow_redirects=False)
    assert r_bad_confirm.status_code == 303
    # Setup previous
    (tmp / "state" / "previous.json").write_text(json.dumps({"version": "0.2.0", "image": "sha256:prev"}))
    with pytest.raises(Invalid, match="Type ROLLBACK"):
        portal.request_rollback(ADMIN, "wrong")
    r_ok = client.post("/updates/rollback", data={"confirm": "ROLLBACK", "csrf": csrf(client, "/updates")}, follow_redirects=False)
    assert r_ok.status_code == 303
    reqs = requests_in(tmp)
    assert any(req.get("action") == "rollback" and req.get("by") == ADMIN.email for req in reqs)
    actions_list = [rec["action"] for rec in portal.log.records()]
    assert "update.rollback_requested" in actions_list


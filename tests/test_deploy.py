"""The Azure template stays in step with the app: everything the backup feature and its alert need."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BICEP = (ROOT / "deploy/azure/main.bicep").read_text()


def test_backups_are_wired_on_azure():
    # the app reads these (backup_store.destinations / backup_key); without them the Backups page cannot work
    assert "{ name: 'GRCPAL_BACKUP_KEY', secretRef: 'backup-key' }" in BICEP
    assert "GRCPAL_BACKUP_CONTAINER" in BICEP
    assert "args: ['backup', 'run-due']" in BICEP
    # write-once backups, removed by storage after their retention, account protected from deletion
    assert re.search(r"resource backupsImmutability .+?immutabilityPeriodSinceCreationInDays: backupRetentionDays",
                     BICEP, re.S)
    assert "prefixMatch: ['backups/']" in BICEP
    assert "level: 'CanNotDelete'" in BICEP
    assert "cron: backupCheckCron" in BICEP and "'*/15 * * * *'" in BICEP


def test_backup_alert_matches_what_the_job_prints(monkeypatch, capsys):
    from grcpal import cli

    class FakePortal:
        def run_due_backups(self):
            return [{"kind": "scheduled", "name": "grcpal-acme-20261012T050000Z-scheduled.grcbak", "verified": True}]

    monkeypatch.setattr(cli, "_admin_portal", lambda args: FakePortal())
    monkeypatch.setattr("grcpal.configbundle.fetch", lambda: None)
    assert cli.main(["backup", "run-due"]) == 0
    line = capsys.readouterr().out.strip()
    assert "\n" not in line  # one log row
    query = re.search(r"query: '(.+)'", BICEP).group(1).replace("\\'", "'")
    needles = [a or b for a, b in re.findall(r"(?:has|contains) (?:\"([^\"]+)\"|'([^']+)')", query)]
    assert len(needles) == 3 and all(n in line for n in needles), (needles, line)


def test_only_the_platform_proxy_is_believed_for_client_addresses():
    # security.client_ip: Container Apps ingress (Azure) and Caddy (VM) are each one trusted hop
    assert "{ name: 'GRCPAL_TRUSTED_PROXY_HOPS', value: '1' }" in BICEP
    assert "GRCPAL_TRUSTED_PROXY_HOPS=1" in (ROOT / "deploy/vm/install.sh").read_text()


def test_deploy_writes_a_recovery_kit_that_restore_accepts(tmp_path, monkeypatch):
    import base64
    import importlib.util

    import pytest

    from grcpal import backup

    spec = importlib.util.spec_from_file_location("write_kit", ROOT / "deploy/azure/write_kit.py")
    write_kit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(write_kit)
    key = bytes(range(32))
    monkeypatch.setenv("GRCPAL_BACKUP_KEY", base64.b64encode(key).decode())
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", "app-key-for-integrations-0123456789")
    out = tmp_path / "kit.json"
    write_kit.main(str(out), "https://grc.example.com")
    kit = backup.load_kit(out.read_text())
    assert kit["key"] == key and kit["settings_key"] == "app-key-for-integrations-0123456789"
    assert backup.load_kit(backup.make_kit(key, "app-key-for-integrations-0123456789"))["backup_key_id"] == kit["backup_key_id"]
    assert out.stat().st_mode & 0o077 == 0  # readable by the owner only
    with pytest.raises(FileExistsError):  # an existing kit is never overwritten
        write_kit.main(str(out), "")
    script = (ROOT / "deploy/azure/deploy.sh").read_text()
    assert "--kit-out" in script and 'python3 -I "$HERE/write_kit.py"' in script
    assert 'echo "  GRCPAL_ENCRYPTION_KEY=$ENCRYPTION_KEY"' not in script  # keys are not printed to the terminal

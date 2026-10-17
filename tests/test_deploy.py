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

"""B-025: failed runs are emailed by the app from inside the run; a run that never starts needs Azure's alert."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BICEP = (ROOT / "deploy/azure/main.bicep").read_text()


def test_azure_alerts_when_the_daily_collection_does_not_run():
    assert "resource collectAlert 'Microsoft.Insights/scheduledQueryRules" in BICEP
    assert "Log_s has \"collect.run_all\"" in BICEP and "windowSize: collectAlertWindow" in BICEP
    assert "param collectAlertWindow string = 'P2D'" in BICEP
    assert "collect.run_all" in (ROOT / "grcpal/cli.py").read_text()


def test_collect_all_prints_the_line_the_alert_looks_for(tmp_path, monkeypatch, capsys):
    from grcpal import cli, collectors

    monkeypatch.setattr(collectors, "NAMES", [])
    for var in ("GRCPAL_TABLES_URL", "GRCPAL_SQLITE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GRCPAL_EVIDENCE_DIR", str(tmp_path / "evidence"))
    assert cli.main(["collect", "--all"]) == 0
    line = [x for x in capsys.readouterr().out.splitlines() if "collect.run_all" in x][-1]
    assert json.loads(line) == {"event": "collect.run_all", "ok": True, "failed": 0, "version": cli.__version__}

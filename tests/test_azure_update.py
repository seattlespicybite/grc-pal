"""deploy/azure/update.sh against stand-ins for az, curl and gh (tests/fake_azure): the order of the safety
steps, and that traffic never moves when a backup, trial, health check or self-test fails."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "azure" / "update.sh"
FAKES = ROOT / "tests" / "fake_azure"
OLD = "ghcr.io/seattlespicybite/grc-pal:0.2.0"
NEW = "ghcr.io/seattlespicybite/grc-pal@sha256:" + "b" * 64

pytestmark = pytest.mark.skipif(shutil.which("bash") is None or shutil.which("python3") is None,
                                reason="needs bash and python3")


@pytest.fixture
def azure(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"serving": "grcpal-acme--old", "labels": {}, "tags": {"grcpal-version": "0.2.0"},
                                 "revisions": {"grcpal-acme--old": {"image": OLD, "active": True}},
                                 "executions": [], "jobs": {}}))
    log = tmp_path / "az.log"
    log.write_text("")

    def run(*args, **env):
        e = {**os.environ, "PATH": f"{FAKES}:{os.environ['PATH']}", "FAKE_STATE": str(state), "FAKE_LOG": str(log),
             **env}
        r = subprocess.run(["bash", str(SCRIPT), "--name", "acme", *args], capture_output=True, text=True, env=e,
                           timeout=60)
        return r, json.loads(state.read_text()), [json.loads(x) for x in log.read_text().splitlines()]
    return run


def job_args(st):
    return [" ".join(x["args"]) for x in st["executions"]]


def test_patch_update_runs_every_safety_step_in_order(azure):
    r, st, calls = azure("--auto")
    assert r.returncode == 0, r.stderr + r.stdout
    assert job_args(st) == ["backup pre-update", "update trial", "update selftest-saved",
                            job_args(st)[3]]
    assert job_args(st)[3].startswith("update record update.applied")
    assert [x["image"] for x in st["executions"][:3]] == [OLD, NEW, NEW]  # backup by the current version
    new_rev = next(r for r in st["revisions"] if r != "grcpal-acme--old")
    assert st["serving"] == new_rev and st["revisions"][new_rev]["image"] == NEW  # pinned by digest
    assert st["labels"]["previous"] == "grcpal-acme--old" and st["revisions"]["grcpal-acme--old"]["active"]
    assert set(st["jobs"].values()) == {NEW} and len(st["jobs"]) == 4
    assert st["tags"] == {"grcpal-version": "0.2.1", "grcpal-previous-version": "0.2.0"}
    # traffic was pinned to the old revision before the new one was created
    flat = [" ".join(c) for c in calls]
    pin = flat.index(next(c for c in flat if "traffic set" in c))
    create = flat.index(next(c for c in flat if c.startswith("containerapp update")))
    assert pin < create and "grcpal-acme--old=100" in flat[pin]


@pytest.mark.parametrize("fail", ["backup pre-update", "update trial"])
def test_failure_before_the_switch_changes_nothing(azure, fail):
    r, st, calls = azure("--auto", FAKE_FAIL=fail)
    assert r.returncode != 0 and "nothing was changed" in r.stderr
    assert st["serving"] == "grcpal-acme--old" and list(st["revisions"]) == ["grcpal-acme--old"]
    assert not any(c[:2] == ["containerapp", "update"] for c in calls) and st["jobs"] == {}


@pytest.mark.parametrize("env", [{"FAKE_HEALTH": "down"}, {"FAKE_FAIL": "update selftest-saved"}])
def test_failed_health_gate_keeps_traffic_on_the_old_revision(azure, env):
    r, st, _ = azure("--auto", **env)
    assert r.returncode != 0 and "traffic stays on grcpal-acme--old" in r.stderr
    new_rev = next(r for r in st["revisions"] if r != "grcpal-acme--old")
    assert st["serving"] == "grcpal-acme--old" and not st["revisions"][new_rev]["active"]
    assert st["jobs"] == {} and st["tags"]["grcpal-version"] == "0.2.0"
    assert any(a.startswith("update record update.rolled_back") for a in job_args(st))


def test_failed_provenance_check_stops_before_the_backup(azure):
    r, st, _ = azure("--auto", FAKE_PROVENANCE="1")
    assert r.returncode != 0 and "provenance" in r.stderr and st["executions"] == []


@pytest.mark.parametrize("latest,word", [("0.3.0", "feature release"), ("1.0.0", "major release")])
def test_monthly_run_waits_for_approval_on_minor_and_major(azure, latest, word):
    r, st, _ = azure("--auto", FAKE_LATEST=latest)
    assert r.returncode == 0 and word in r.stdout and st["executions"] == []


def test_major_needs_explicit_flag(azure):
    r, st, _ = azure("--version", "1.0.0", "--yes")
    assert r.returncode != 0 and "--major" in r.stderr and st["executions"] == []


def test_rollback_returns_traffic_and_jobs_to_the_previous_revision(azure):
    azure("--auto")
    r, st, _ = azure("--rollback", "--yes")
    assert r.returncode == 0, r.stderr
    assert st["serving"] == "grcpal-acme--old" and set(st["jobs"].values()) == {OLD}
    assert st["tags"]["grcpal-version"] == "0.2.0"
    assert job_args(st)[-1].startswith("update record update.rolled_back")


def test_job_arguments_never_look_like_azure_cli_options():
    for line in SCRIPT.read_text().splitlines():
        if "run_job " in line and not line.strip().startswith(("#", "run_job()")):
            after = line.split("run_job ", 1)[1].split()[1:]
            assert not any(w.strip('"').startswith("--") for w in after if not w.startswith((">", "||", "2>"))), line


def test_workflow_never_installs_on_its_own():
    """Updates are manual: the scheduled run only reports; installing needs a person-entered version."""
    wf = (ROOT / "grcpal" / "starter" / "github" / "workflows" / "grcpal-update.yml").read_text()
    assert "--auto" not in wf
    assert '--status | tee -a "$GITHUB_STEP_SUMMARY"' in wf


def test_progress_is_shown_as_percent_steps(azure):
    r, _, _ = azure("--auto")
    import re
    pcts = [int(p) for p in re.findall(r"==> \[(\d+)%\]", r.stdout)]
    assert pcts == sorted(pcts) and pcts[0] > 0 and pcts[-1] == 100


def test_status_lists_newer_releases_with_advice(azure):
    rows = [{"tag_name": "v0.2.1", "body": "### Security\n- fix", "html_url": "https://github.com/o/r/releases/tag/v0.2.1"},
            {"tag_name": "v0.3.0", "body": "### Added\n- feature"}, {"tag_name": "v0.1.0"}]
    r, st, _ = azure("--status", FAKE_RELEASES=json.dumps(rows))
    assert r.returncode == 0, r.stderr
    assert "- 0.3.0 (minor): New features" in r.stdout and "- 0.2.1 (patch): Contains security fixes" in r.stdout
    assert "0.1.0" not in r.stdout and job_args(st) == []  # status changes nothing

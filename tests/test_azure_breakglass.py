"""deploy/azure/breakglass.sh against the stand-ins in tests/fake_azure: Easy Auth is turned off only after the
app stopped believing its header, turned on again before anything else, and nothing opens without confirmation."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "azure" / "breakglass.sh"
UPDATE = ROOT / "deploy" / "azure" / "update.sh"
FAKES = ROOT / "tests" / "fake_azure"
IMAGE = "ghcr.io/seattlespicybite/grc-pal:0.6.0"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None or shutil.which("python3") is None,
                                reason="needs bash and python3")


@pytest.fixture
def azure(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"serving": "grcpal-acme--old", "labels": {}, "tags": {"grcpal-version": "0.6.0"},
                                 "revisions": {"grcpal-acme--old": {"image": IMAGE, "active": True}},
                                 "executions": [], "jobs": {}, "easyauth": True,
                                 "env": {"GRCPAL_AUTH_MODE": "easyauth"}}))
    log = tmp_path / "az.log"

    def run(*args, script=SCRIPT, stdin="", **env):
        log.write_text("")
        e = {**os.environ, "PATH": f"{FAKES}:{os.environ['PATH']}", "FAKE_STATE": str(state), "FAKE_LOG": str(log),
             **env}
        r = subprocess.run(["bash", str(script), "--name", "acme", *args], capture_output=True, text=True, env=e,
                           input=stdin, timeout=60)
        calls = [" ".join(json.loads(x)) for x in log.read_text().splitlines()]
        return r, json.loads(state.read_text()), calls
    return run


def first(calls, text):
    return next(i for i, c in enumerate(calls) if text in c)


def test_arm_opens_password_sign_in_only_after_the_app_stopped_trusting_the_header(azure):
    r, st, calls = azure("arm", "--yes", "--hours", "2")
    assert r.returncode == 0, r.stderr + r.stdout
    assert st["env"]["GRCPAL_AUTH_MODE"] == "local" and st["env"]["GRCPAL_BREAK_GLASS_UNTIL"].endswith("Z")
    assert st["easyauth"] is False
    assert "--bg-" in st["serving"] and st["revisions"][st["serving"]]["env"]["GRCPAL_AUTH_MODE"] == "local"
    # the order that keeps a forged identity header useless at every moment
    new_rev = first(calls, "containerapp update")
    to_new = first(calls, f"--revision-weight {st['serving']}=100")
    auth_off = first(calls, "auth update")
    assert new_rev < to_new < auth_off
    assert st["tags"]["grcpal-breakglass-until"] == st["env"]["GRCPAL_BREAK_GLASS_UNTIL"]
    assert st["tags"]["grcpal-breakglass-from"] == "grcpal-acme--old"


def test_arm_that_fails_its_health_check_never_turns_easy_auth_off(azure):
    r, st, calls = azure("arm", "--yes", FAKE_HEALTH="down")
    assert r.returncode == 1 and "Easy Auth is still on" in r.stderr
    assert st["easyauth"] is True and st["serving"] == "grcpal-acme--old"
    assert not any("auth update" in c for c in calls)


def test_arm_needs_the_instance_name_typed(azure):
    r, st, calls = azure("arm", stdin="yes\n")
    assert r.returncode == 1 and "nothing was changed" in r.stderr
    assert st["easyauth"] is True and st["env"]["GRCPAL_AUTH_MODE"] == "easyauth"
    r, st, _ = azure("arm", stdin="acme\n")
    assert r.returncode == 0 and st["easyauth"] is False


@pytest.mark.parametrize("hours", ["0", "25", "4h", "-1"])
def test_arm_window_is_one_to_24_hours(azure, hours):
    r, st, _ = azure("arm", "--yes", "--hours", hours)
    assert r.returncode == 1 and st["easyauth"] is True


def test_arm_twice_is_refused(azure):
    assert azure("arm", "--yes")[0].returncode == 0
    r, st, _ = azure("arm", "--yes")
    assert r.returncode == 1 and "already open" in r.stderr


def test_disarm_turns_easy_auth_on_first_and_restores_microsoft_sign_in(azure):
    azure("arm", "--yes")
    r, st, calls = azure("disarm")
    assert r.returncode == 0, r.stderr + r.stdout
    changes = [c for c in calls if any(w in c for w in ("auth update", "containerapp update", "traffic set"))]
    assert "auth update" in changes[0] and "--enabled true" in changes[0]  # before anything else changes
    assert st["easyauth"] is True
    assert st["env"] == {"GRCPAL_AUTH_MODE": "easyauth"}  # the closing time is gone from the template too
    assert "--bgoff-" in st["serving"]
    assert not any(v["active"] for k, v in st["revisions"].items() if "--bg-" in k)
    assert st["tags"]["grcpal-breakglass-until"] == ""


def test_disarm_when_not_armed_still_makes_sure_easy_auth_is_on(azure, tmp_path):
    state = json.loads((tmp_path / "state.json").read_text())
    state["easyauth"] = False  # someone switched it off by hand
    (tmp_path / "state.json").write_text(json.dumps(state))
    r, st, calls = azure("disarm")
    assert r.returncode == 0 and st["easyauth"] is True
    assert not any("containerapp update" in c for c in calls)


def test_update_refuses_while_armed(azure):
    azure("arm", "--yes")
    r, st, calls = azure("--auto", script=UPDATE)
    assert r.returncode == 1 and "disarm first" in r.stderr
    assert not any("job start" in c for c in calls)


def test_set_password_runs_create_admin_with_two_step_inside_the_app(azure):
    r, st, _ = azure("set-password", "--email", "BreakGlass@Example.com")
    assert r.returncode == 0, r.stderr
    assert st["exec"] == "grcpal create-admin breakglass@example.com --two-step"


@pytest.mark.parametrize("email", ["", "not-an-email", "a@example.com; rm -rf /", "$(id)@example.com"])
def test_set_password_refuses_anything_but_a_plain_email(azure, email):
    r, st, _ = azure("set-password", "--email", email)
    assert r.returncode == 1 and "exec" not in st

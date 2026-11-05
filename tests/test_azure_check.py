"""deploy/azure/check.py, kit.sh and the re-run safety of deploy.sh, against the stand-ins in tests/fake_azure_check."""
from __future__ import annotations

import base64
import datetime as dt
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AZ = ROOT / "deploy" / "azure"
FAKES = ROOT / "tests" / "fake_azure_check"
FQDN = "grcpal-acme.example.azurecontainerapps.io"
REDIRECT = f"https://{FQDN}/.auth/login/aad/callback"
LOGIN = "https://login.microsoftonline.com/t/oauth2/v2.0/authorize"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None or shutil.which("python3") is None,
                                reason="needs bash and python3")


def load(name):
    spec = importlib.util.spec_from_file_location(name, AZ / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def healthy_state():
    end = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=300)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "app": {"properties": {"configuration": {"ingress": {"external": True, "fqdn": FQDN}},
                               "template": {"containers": [{"image": "ghcr.io/seattlespicybite/grc-pal:0.6.1"}]}}},
        "revisions": [{"name": "grcpal-acme--new", "properties": {"active": True, "trafficWeight": 100,
                                                                 "healthState": "Healthy", "runningState": "Running"}}],
        "auth": {"properties": {"platform": {"enabled": True},
                                "globalValidation": {"unauthenticatedClientAction": "RedirectToLoginPage"},
                                "identityProviders": {"azureActiveDirectory": {"registration": {"clientId": "app-1"}}}}},
        "apps": [{"displayName": "GRC-pal (acme)", "appId": "app-1", "web": {"redirectUris": [REDIRECT]},
                  "passwordCredentials": [{"endDateTime": end}]}],
        "assignment_required": True,
        "http": {"/healthz": ["200 "], "/": [f"302 {LOGIN}"], "/dev/login": [f"302 {LOGIN}"], "/login": ["401 "]},
        "secrets": {"backup-key": base64.b64encode(b"k" * 32).decode(), "encryption-key": "a" * 64},
    }


@pytest.fixture
def azure(tmp_path, monkeypatch):
    state, log = tmp_path / "state.json", tmp_path / "az.log"
    monkeypatch.setenv("PATH", f"{FAKES}:{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_STATE", str(state))
    monkeypatch.setenv("FAKE_LOG", str(log))
    check = load("check")
    monkeypatch.setattr(check.time, "sleep", lambda s: None)

    def run(st, *args):
        state.write_text(json.dumps(st))
        log.write_text("")
        code = check.main(["--name", "acme", *args])
        calls = [" ".join(json.loads(x)) for x in log.read_text().splitlines()]
        return code, json.loads(state.read_text()), calls
    return run


def test_healthy_instance_passes_without_changing_anything(azure, capsys):
    code, _, calls = azure(healthy_state())
    out = capsys.readouterr().out
    assert code == 0 and "0 failed, 0 warnings" in out and "FAIL" not in out
    assert "V-1 forged identity header: refused (302)" in out and "V-3 password sign-in: refused (401)" in out
    assert not any(" update" in c for c in calls)  # report only


def test_missing_redirect_fails_and_fix_registers_it(azure, capsys):
    st = healthy_state()
    st["apps"][0]["web"]["redirectUris"] = []
    code, _, _ = azure(st)
    out = capsys.readouterr().out
    assert code == 1 and "AADSTS500113" in out and "--fix" in out
    code, after, calls = azure(st, "--fix")
    assert code == 0 and after["apps"][0]["web"]["redirectUris"] == [REDIRECT]
    assert any(c.startswith(f"ad app update --id app-1 --web-redirect-uris {REDIRECT}") for c in calls)


@pytest.mark.parametrize("path", ["/", "/dev/login", "/login"])
def test_a_request_that_gets_past_sign_in_fails(azure, capsys, path):
    st = healthy_state()
    st["http"][path] = ["200 "]
    code, _, _ = azure(st)
    assert code == 1 and "an unauthenticated request got through" in capsys.readouterr().out


def test_a_redirect_somewhere_else_is_not_a_refusal(azure):
    st = healthy_state()
    st["http"]["/"] = ["302 https://evil.example/login"]
    assert azure(st)[0] == 1


def test_unhealthy_serving_revision_fails_and_a_stale_one_is_flagged(azure, capsys):
    st = healthy_state()
    st["revisions"][0]["properties"]["healthState"] = "Unhealthy"
    st["revisions"].append({"name": "grcpal-acme--old", "properties": {"active": True, "trafficWeight": 0,
                                                                      "healthState": "None",
                                                                      "runningState": "Activating"}})
    code, _, _ = azure(st)
    out = capsys.readouterr().out
    assert code == 1 and "grcpal-acme--new serves 100% of traffic but is Unhealthy" in out
    assert "WARN  grcpal-acme--old is still active" in out
    assert "revision deactivate -g rg-grcpal-acme -n grcpal-acme --revision grcpal-acme--old" in out


def test_portal_that_wakes_up_slowly_still_passes(azure, capsys):
    st = healthy_state()
    st["http"]["/healthz"] = ["000 ", "000 ", "200 "]  # scaled to zero: the first requests time out
    assert azure(st)[0] == 0


def test_portal_that_never_answers_fails_and_skips_the_probes(azure, capsys):
    st = healthy_state()
    st["http"]["/healthz"] = ["000 "]
    code, _, _ = azure(st)
    out = capsys.readouterr().out
    assert code == 1 and "/healthz answers 000" in out and "V-1" not in out


def test_expiring_secret_and_open_assignment_are_warnings(azure, capsys):
    st = healthy_state()
    soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    st["apps"][0]["passwordCredentials"] = [{"endDateTime": soon}]
    st["assignment_required"] = False
    code, _, _ = azure(st)
    out = capsys.readouterr().out
    assert code == 0 and "expires in" in out and "anyone in your directory" in out and "2 warnings" in out


def test_sign_in_not_enforced_fails(azure, capsys):
    st = healthy_state()
    st["auth"]["properties"]["platform"]["enabled"] = False
    assert azure(st)[0] == 1 and "not enforced" in capsys.readouterr().out


def test_missing_app_fails_cleanly(azure, capsys):
    st = healthy_state()
    st["app"] = None
    assert azure(st)[0] == 1 and "no container app grcpal-acme" in capsys.readouterr().out


def test_kit_sh_writes_the_running_instances_keys_and_never_overwrites(tmp_path):
    st, state, log = healthy_state(), tmp_path / "state.json", tmp_path / "az.log"
    state.write_text(json.dumps(st))
    env = {**os.environ, "PATH": f"{FAKES}:{os.environ['PATH']}", "FAKE_STATE": str(state), "FAKE_LOG": str(log)}
    out = tmp_path / "kit.json"
    r = subprocess.run(["bash", str(AZ / "kit.sh"), "--name", "acme", "--out", str(out)], capture_output=True,
                       text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr + r.stdout
    kit = json.loads(out.read_text())
    assert kit["backup_key"] == st["secrets"]["backup-key"] and kit["settings_key"] == "a" * 64
    assert kit["instance"] == f"https://{FQDN}" and out.stat().st_mode & 0o077 == 0
    assert st["secrets"]["backup-key"] not in r.stdout + r.stderr  # keys are never printed
    again = subprocess.run(["bash", str(AZ / "kit.sh"), "--name", "acme", "--out", str(out)], capture_output=True,
                           text=True, env=env, timeout=60)
    assert again.returncode == 1 and "already exists" in again.stdout


def test_write_kit_matches_only_the_same_keys(tmp_path, monkeypatch):
    write_kit = load("write_kit")
    monkeypatch.setenv("GRCPAL_BACKUP_KEY", base64.b64encode(b"k" * 32).decode())
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", "a" * 64)
    kit = tmp_path / "kit.json"
    write_kit.main(str(kit), "https://grc.example.com")
    assert write_kit.matches(str(kit))
    monkeypatch.setenv("GRCPAL_BACKUP_KEY", base64.b64encode(b"x" * 32).decode())
    assert not write_kit.matches(str(kit))


def test_deploy_sh_does_the_essential_steps_first_and_is_safe_to_repeat():
    s = (AZ / "deploy.sh").read_text()
    assert "Safe to repeat" in s
    deploy = s.index('step "Deploying storage')
    redirect, kit = s.index('step "Registering the sign-in redirect"'), s.index('step "Recovery kit"')
    github, restore = s.index('step "GitHub repository variables'), s.index('step "Restoring')
    check, done = s.index('step "Checking the instance"'), s.index('step "Done"')
    assert deploy < redirect < kit < github < restore < check < done
    # a re-run keeps a kit that holds the same keys instead of stopping, and refuses one with other keys
    assert '--matches "$KIT_OUT"' in s and "already exists; choose a new file name" not in s.split("HERE=")[0]
    assert 'python3 -I "$HERE/check.py" --name "$NAME"' in s

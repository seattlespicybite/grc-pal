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


def test_break_glass_alert_matches_what_the_app_logs(tmp_path, monkeypatch):
    """The Azure log alert must fire on the exact line the app writes when the break-glass account signs in."""
    import json
    import logging

    from grcpal.portal.observability import JsonFormatter
    from test_portal import make_portal

    portal = make_portal(tmp_path)
    records = []
    handler = logging.Handler()
    handler.emit = records.append
    logging.getLogger("grcpal").addHandler(handler)
    try:
        portal.events.security("Break-glass sign-in", actor="glass@example.com", ip="203.0.113.5", break_glass=True)
    finally:
        logging.getLogger("grcpal").removeHandler(handler)
    line = JsonFormatter().format(records[-1])
    assert json.loads(line)["msg"] == "Break-glass sign-in"
    rule = BICEP.split("resource breakGlassAlert")[1].split("\n}\n")[0]
    query = re.search(r"query: '(.+)'", rule).group(1).replace("\\'", "'")
    needles = [a or b for a, b in re.findall(r"(?:has|contains) (?:\"([^\"]+)\"|'([^']+)')", query)]
    assert needles == ["Break-glass sign-in", '"break_glass": true'] and all(n in line for n in needles), (needles, line)
    assert "operator: 'GreaterThan'" in rule and "windowSize: 'PT5M'" in rule


def test_custom_domain_is_kept_in_the_template():
    # a re-deploy must never drop the binding, and links use the custom address once its certificate exists
    assert "customDomains: empty(customDomain) ? []" in BICEP
    assert "bindingType: 'SniEnabled'" in BICEP and "bindingType: 'Disabled'" in BICEP
    assert "var publicUrl = empty(customDomain) || empty(customDomainCertificateId) ? defaultUrl" in BICEP
    assert "output customDomainVerificationId string" in BICEP


def test_servers_do_not_announce_themselves():
    assert "header -Server" in (ROOT / "deploy/vm/install.sh").read_text()
    assert '"--no-server-header"' in (ROOT / "Dockerfile").read_text()
    assert "server_header=False" in (ROOT / "grcpal/cli.py").read_text()


def _deploy(tmp_path, *args, dns_ready=False):
    """Run deploy.sh against tests/fake_azure_deploy/az; returns (exit code, output, az calls, deploy parameters)."""
    import json
    import os
    import subprocess

    env = {**os.environ, "PATH": f"{ROOT / 'tests' / 'fake_azure_deploy'}:{os.environ['PATH']}",
           "FAKE_LOG": str(tmp_path / "az.log"), "FAKE_STATE": str(tmp_path / "state.json"),
           "FAKE_DNS_READY": "1" if dns_ready else "0"}
    r = subprocess.run(["bash", str(ROOT / "deploy/azure/deploy.sh"), "--name", "acme", "--admins", "you@example.com",
                        *args], env=env, capture_output=True, text=True, timeout=60)
    calls = [json.loads(x) for x in (tmp_path / "az.log").read_text().splitlines()] if (tmp_path / "az.log").exists() else []
    state = json.loads((tmp_path / "state.json").read_text()) if (tmp_path / "state.json").exists() else {}
    return r.returncode, r.stdout + r.stderr, calls, state.get("deploys", [])


def _finished(code, out):
    """deploy.sh got to the end. The small fake az here does not model the instance check that runs last
    (deploy/azure/check.py, tested with its own fakes in test_azure_check.py), so that check may report problems."""
    assert "==> Done" in out and "Portal:" in out, out
    assert code == 0 or out.rstrip().endswith("then run ./deploy/azure/check.sh --name acme"), out
    return True


def _redirects(calls):
    upd = [c for c in calls if c[:3] == ["ad", "app", "update"]][-1]
    i = upd.index("--web-redirect-uris")
    return [x for x in upd[i + 1:] if not x.startswith("-") and x != "none"]


def test_deploy_without_dns_records_prints_them_and_keeps_the_default_address(tmp_path):
    code, out, calls, deploys = _deploy(tmp_path, "--custom-domain", "GRC.example.com")
    assert _finished(code, out)
    assert "CNAME  grc.example.com  ->  grcpal-acme.happy-sea.eastus2.azurecontainerapps.io" in out
    assert "TXT    asuid.grc.example.com  ->  VERIFY123" in out
    assert len(deploys) == 1 and "customDomain" not in deploys[0], "the template never gets a name Azure cannot verify"
    assert _redirects(calls) == ["https://grcpal-acme.happy-sea.eastus2.azurecontainerapps.io/.auth/login/aad/callback"]


def test_deploy_with_dns_records_binds_and_keeps_the_binding(tmp_path):
    code, out, calls, deploys = _deploy(tmp_path, "--custom-domain", "grc.example.com", dns_ready=True)
    assert _finished(code, out)
    bind = next(c for c in calls if c[:3] == ["containerapp", "hostname", "bind"])
    assert bind[bind.index("--hostname") + 1] == "grc.example.com" and "CNAME" in bind
    assert len(deploys) == 2 and deploys[1]["customDomain"] == "grc.example.com"
    assert deploys[1]["customDomainCertificateId"].endswith("/managedCertificates/mc-1")
    assert _redirects(calls) == ["https://grcpal-acme.happy-sea.eastus2.azurecontainerapps.io/.auth/login/aad/callback",
                                 "https://grc.example.com/.auth/login/aad/callback"]
    assert "Portal:        https://grc.example.com" in out
    # a later re-run finds the certificate and deploys once, with the binding
    code, out, calls, deploys = _deploy(tmp_path, "--custom-domain", "grc.example.com", dns_ready=True)
    assert _finished(code, out) and len(deploys) == 3 and deploys[2]["customDomainCertificateId"].endswith("mc-1")
    assert not [c for c in calls if c[:3] == ["containerapp", "hostname", "bind"]][1:], "bound once only"


def test_deploy_rejects_a_bad_domain(tmp_path):
    code, out, calls, _ = _deploy(tmp_path, "--custom-domain", "grc example.com")
    assert code == 1 and "must be a host name" in out and not calls


def test_image_is_built_only_from_pinned_inputs():
    """What CI tested and scanned is what the release ships: base image by digest, every package hash-locked."""
    import tomllib

    dockerfile = (ROOT / "Dockerfile").read_text()
    froms = re.findall(r"^FROM (\S+)", dockerfile, re.M)
    assert froms and all(re.fullmatch(r"python:3\.12-slim@sha256:[0-9a-f]{64}", f) for f in froms), froms
    assert "--require-hashes --only-binary :all: -r requirements/image.txt" in dockerfile
    assert "--no-deps --no-build-isolation --no-index ." in dockerfile, "GRC-pal itself must not pull anything"
    lock = (ROOT / "requirements/image.txt").read_text()
    pinned = {m.lower().replace("_", "-") for m in re.findall(r"^([A-Za-z0-9_.-]+)==", lock, re.M)}
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    wanted = list(project["dependencies"])
    for extra in ("portal", "aws", "gcp"):
        wanted += project["optional-dependencies"][extra]
    names = {re.split(r"[\[<>=!~ ;]", w, maxsplit=1)[0].lower().replace("_", "-") for w in wanted}
    missing = names - pinned
    assert not missing, f"requirements/image.txt is stale, regenerate it (see the Dockerfile): {missing}"
    for block in re.split(r"\n(?=[A-Za-z0-9_.-]+==)", lock.split("\n", 2)[2]):
        if "==" in block:
            assert "--hash=sha256:" in block, block.splitlines()[0]


def test_release_scans_the_pushed_digest_before_tagging_it():
    wf = (ROOT / ".github/workflows/release.yml").read_text()
    build, scan, tag = wf.index("push-by-digest=true"), wf.index("--exit-code 1"), wf.index("imagetools create")
    assert build < scan < tag, "push untagged, scan that digest, then tag"
    assert '"$IMAGE@$DIGEST"' in wf[scan - 400:scan + 200]
    assert "tags: ${{ steps.meta.outputs.tags }}" not in wf, "no tags at build time"
    assert "for platform in linux/amd64 linux/arm64" in wf

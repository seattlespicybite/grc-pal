"""Evidence integrity: SHA256SUMS, signed manifests, audit-log anchors, verification and export."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import shutil
import subprocess
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from grcpal import cli, evidence as ev
from grcpal.evidence import EvidenceStore
from grcpal.portal.store import SqliteStore
from tests.test_portal import ADMIN, AUDITOR, CONTRIB, assign, make_portal

KEY = "11" * 32


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", KEY)
    for var in ("GRCPAL_EVIDENCE_SIGNING_KEY", "GRCPAL_EVIDENCE_ACCOUNT_URL", "GRCPAL_TENANT"):
        monkeypatch.delenv(var, raising=False)


def _run(store, source="entra_users", when=None, rows=None):
    run = store.new_run(source, ["IAM-01"], {})
    if when:
        run.started = when
    run.add("users", rows or [{"upn": "pat@example.com", "enabled": True}])
    run.finish([])
    return run


def _path(store, run, name):
    return store.root / store._key(f"{run.prefix}/{name}")


def test_signed_run_verifies_with_standard_tools(tmp_path):
    store = EvidenceStore(tmp_path / "ev")
    run = _run(store)
    manifest = json.loads(_path(store, run, "manifest.json").read_text())
    assert manifest["integrity"]["signature"] == "ed25519"
    assert manifest["integrity"]["key_id"] == ev.key_id(ev.signing_key().public_key())
    r = store.verify_run(*run.prefix.split("/"))
    assert r["status"] == "verified" and r["signed"] and r["files"] == 2 and not r["problems"]
    if shutil.which("sha256sum"):  # an auditor's own check, no GRC-pal needed
        out = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=_path(store, run, "SHA256SUMS").parent,
                             capture_output=True, text=True)
        assert out.returncode == 0, out.stdout + out.stderr


def test_changed_file_fails(tmp_path):
    store = EvidenceStore(tmp_path / "ev")
    run = _run(store)
    _path(store, run, "users.csv").write_text("upn,enabled\nsomeone-else@example.com,True\n")
    r = store.verify_run(*run.prefix.split("/"))
    assert r["status"] == "failed" and any("users.csv" in p for p in r["problems"])


def test_rewritten_manifest_fails_signature(tmp_path):
    """The attack the signature exists for: change a file AND its hash in the manifest."""
    store = EvidenceStore(tmp_path / "ev")
    run = _run(store)
    data = b"upn,enabled\nsomeone-else@example.com,True\n"
    _path(store, run, "users.csv").write_bytes(data)
    m = json.loads(_path(store, run, "manifest.json").read_text())
    for f in m["files"]:
        if f["name"] == "users.csv":
            f["sha256"], f["bytes"] = hashlib.sha256(data).hexdigest(), len(data)
    _path(store, run, "manifest.json").write_text(json.dumps(m, indent=2))
    _path(store, run, "SHA256SUMS").write_text(ev.sums_text(m["files"]))
    r = store.verify_run(*run.prefix.split("/"))
    assert r["status"] == "failed" and any("signature does not match" in p for p in r["problems"])


def test_other_key_and_published_key(tmp_path):
    store = EvidenceStore(tmp_path / "ev")
    run = _run(store)
    published = ev.load_public_key(ev.public_key_pem())
    assert store.verify_run(*run.prefix.split("/"), public_key=published)["status"] == "verified"
    other = Ed25519PrivateKey.generate().public_key()
    r = store.verify_run(*run.prefix.split("/"), public_key=other)
    assert r["status"] == "failed" and any("different key" in p for p in r["problems"])


def test_separate_signing_key_overrides_derived(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization

    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    monkeypatch.setenv("GRCPAL_EVIDENCE_SIGNING_KEY", pem)
    store = EvidenceStore(tmp_path / "ev")
    run = _run(store)
    sig = base64.b64decode(_path(store, run, "manifest.sig").read_bytes())
    private.public_key().verify(sig, _path(store, run, "manifest.json").read_bytes())


def test_legacy_runs_and_signature_stripping(tmp_path, monkeypatch):
    store = EvidenceStore(tmp_path / "ev")
    old = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    monkeypatch.delenv("GRCPAL_ENCRYPTION_KEY")
    monkeypatch.setenv("GRCPAL_KEY_FILE", str(tmp_path / "missing.key"))
    legacy = _run(store, when=old)
    m = json.loads(_path(store, legacy, "manifest.json").read_text())
    m.pop("integrity")  # what runs written before this release look like
    _path(store, legacy, "manifest.json").write_text(json.dumps(m))
    monkeypatch.setenv("GRCPAL_ENCRYPTION_KEY", KEY)
    signed = _run(store, when=old + dt.timedelta(days=1))
    stripped = _run(store, when=old + dt.timedelta(days=2))
    m = json.loads(_path(store, stripped, "manifest.json").read_text())
    m.pop("integrity")
    _path(store, stripped, "manifest.json").write_text(json.dumps(m))
    results = {r["run"]: r for r in ev.verify_source(store, "entra_users")}
    assert results[legacy.prefix.split("/")[1]]["status"] == "legacy"
    assert results[signed.prefix.split("/")[1]]["status"] == "verified"
    assert results[stripped.prefix.split("/")[1]]["status"] == "failed"


def test_reserved_names_cannot_be_written(tmp_path):
    run = EvidenceStore(tmp_path / "ev").new_run("x", [], {})
    for name in ("manifest.json", "manifest.sig", "SHA256SUMS"):
        with pytest.raises(ValueError):
            run.add_bytes(name, b"x")


# ---------------------------------------------------------------- portal: audit-log anchor
def test_portal_seals_runs_in_audit_log(tmp_path):
    portal = make_portal(tmp_path)
    a = assign(portal, "HR-02")
    up = portal.upload(CONTRIB, "training.csv", b"name,done\npat,yes\n", "", assignment_id=a["RowKey"])
    source, run = up["evidence_run"].split("/")
    sealed = [r for r in portal.log.records() if r["action"] == "evidence.sealed" and r["target"] == up["evidence_run"]]
    assert len(sealed) == 1 and sealed[0]["actor"] == "system@grc-pal.local"
    r = portal.verify_evidence(AUDITOR, source, run)
    assert r["status"] == "verified" and r["anchor"]["seq"] == sealed[0]["seq"]
    assert portal.log.verify()["ok"]
    with pytest.raises(Exception):
        portal.verify_evidence(CONTRIB, source, run)  # control owners cannot browse the raw store


def test_resigned_manifest_caught_by_audit_log(tmp_path):
    """Attacker who also holds the signing key rewrites file, manifest and signature: the audit log still catches it."""
    portal = make_portal(tmp_path)
    store = portal.evidence
    run = _run(store)
    data = b"upn,enabled\nsomeone-else@example.com,True\n"
    _path(store, run, "users.csv").write_bytes(data)
    m = json.loads(_path(store, run, "manifest.json").read_text())
    for f in m["files"]:
        if f["name"] == "users.csv":
            f["sha256"], f["bytes"] = hashlib.sha256(data).hexdigest(), len(data)
    raw = json.dumps(m, indent=2).encode()
    _path(store, run, "manifest.json").write_bytes(raw)
    _path(store, run, "SHA256SUMS").write_text(ev.sums_text(m["files"]))
    _path(store, run, "manifest.sig").write_bytes(base64.b64encode(ev.signing_key().sign(raw)))
    assert store.verify_run(*run.prefix.split("/"))["status"] == "verified"  # files and signature alone pass
    r = portal.verify_evidence(ADMIN, *run.prefix.split("/"))
    assert r["status"] == "failed" and any("audit log record" in p for p in r["problems"])


def test_run_without_portal_is_a_warning(tmp_path):
    portal = make_portal(tmp_path)
    offline = EvidenceStore(tmp_path / "evidence", namespace="acme")  # e.g. collected from a CI runner
    run = _run(offline)
    r = portal.verify_evidence(ADMIN, *run.prefix.split("/"))
    assert r["status"] == "warning" and r["anchor"] is None


def test_tenants_cannot_verify_or_see_each_others_runs(tmp_path):
    base = SqliteStore()
    acme, beta = make_portal(tmp_path, "acme", base), make_portal(tmp_path, "beta", base)
    run = _run(acme.evidence)
    source, rid = run.prefix.split("/")
    assert acme.verify_evidence(ADMIN, source, rid)["status"] == "verified"
    r = beta.verify_evidence(ADMIN, source, rid)
    assert r["status"] == "failed" and r["anchor"] is None
    assert not [x for x in beta.log.records() if x["action"] == "evidence.sealed"]
    assert beta.evidence.list_sources() == []


def test_export_has_key_and_run_verification(tmp_path):
    portal = make_portal(tmp_path)
    run = _run(portal.evidence)
    z = zipfile.ZipFile(io.BytesIO(portal.export_cycle(AUDITOR, portal.active_cycle()["RowKey"])))
    assert z.read("evidence_signing_key.pem").decode() == ev.public_key_pem()
    rows = z.read("evidence_run_verification.csv").decode()
    assert run.prefix.split("/")[1] in rows and "verified" in rows
    assert "sha256sum -c SHA256SUMS" in z.read("README.txt").decode()


def test_evidence_page_shows_integrity(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from grcpal.portal.app import create_app
    from tests.test_portal import as_

    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    portal = make_portal(tmp_path)
    run = _run(portal.evidence)
    client = as_(TestClient(create_app(portal), base_url="https://grc.example.com"), AUDITOR)
    page = client.get(f"/evidence/{run.prefix}")
    assert page.status_code == 200 and "Verified" in page.text and "Record " in page.text
    assert client.get(f"/evidence/{run.prefix}/SHA256SUMS").status_code == 200
    assert client.get(f"/evidence/{run.prefix}/manifest.sig").status_code == 200
    assert client.get("/evidence-signing-key.pem").text == ev.public_key_pem()
    assert as_(client, CONTRIB).get("/evidence-signing-key.pem").status_code == 403


# ---------------------------------------------------------------- provenance and CLI
def test_graph_queries_recorded():
    from grcpal.clients import Clients

    class Resp:
        headers = {"request-id": "abc-123"}

        def __init__(self, body):
            self._body = body

        def json(self):
            return self._body

    pages = [{"value": [{"id": 1}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/next"}, {"value": [{"id": 2}]}]
    c = Clients()
    c._azure_token = lambda scope: "token"
    c._request = lambda *a, **k: Resp(pages.pop(0))
    assert len(c.graph_list("/users", {"$select": "id"})) == 2
    q = c.queries[0]
    assert q["api"] == "microsoft-graph" and q["request"] == "/users?$select=id"
    assert q["records"] == 2 and q["pages"] == 2 and q["request_id"] == "abc-123"
    assert "token" not in json.dumps(c.queries)


def test_cli_verify(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GRCPAL_TABLES_URL", raising=False)
    monkeypatch.delenv("GRCPAL_SQLITE", raising=False)
    store = EvidenceStore(tmp_path / "ev")
    run = _run(store)
    args = ["--evidence", str(tmp_path / "ev"), "evidence", "verify"]
    assert cli.main(args) == 0
    pem = tmp_path / "key.pem"
    pem.write_text(ev.public_key_pem())
    assert cli.main(args + ["--public-key", str(pem)]) == 0
    _path(store, run, "users.json").write_text("[]")
    assert cli.main(args) == 1
    assert "failed" in capsys.readouterr().out

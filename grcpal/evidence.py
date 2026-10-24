"""Evidence store: write-once, timestamped, hashed evidence runs.

Layout (same locally and in Azure Blob Storage):
    [<namespace>/]<source>/<YYYY-MM-DDTHHMMSSZ>/<artifact files>
    [<namespace>/]<source>/<YYYY-MM-DDTHHMMSSZ>/SHA256SUMS      (same hashes, `sha256sum -c` format)
    [<namespace>/]<source>/<YYYY-MM-DDTHHMMSSZ>/manifest.sig    (Ed25519 signature of manifest.json, base64)
    [<namespace>/]<source>/<YYYY-MM-DDTHHMMSSZ>/manifest.json   (written last; SHA-256 of every file)

Integrity layers (see docs/auditor-guide.md, "Evidence integrity"):
1. SHA-256 of every file in the manifest and in SHA256SUMS (anyone can check with standard tools).
2. The manifest is signed with this instance's evidence key, derived from GRCPAL_ENCRYPTION_KEY
   (or GRCPAL_EVIDENCE_SIGNING_KEY, a PEM private key), so a file and its hash cannot both be rewritten.
3. `on_seal` (set by the portal) records the manifest's SHA-256 in the hash-chained audit log.
4. In Azure, the blob container is write-once (below).

The optional namespace (GRCPAL_TENANT) keeps one organization's evidence under its own prefix.
Run prefixes handed to callers ("<source>/<run>") never include it, so a caller cannot
address another namespace.

Set GRCPAL_EVIDENCE_ACCOUNT_URL (https://<account>.blob.core.windows.net) to also upload to a
container with a locked time-based immutability policy (see deploy/azure/main.bicep).
Uploads use overwrite=False, so a run can never be replaced, only added.
"""
from __future__ import annotations

import base64
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MANIFEST = "manifest.json"
SIGNATURE = "manifest.sig"
SUMS = "SHA256SUMS"
INTEGRITY_FILES = (SUMS, SIGNATURE)
_KDF_INFO = b"grc-pal evidence signing key v1"
_NAMESPACE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _to_csv(rows: list[dict]) -> bytes:
    cols: list[str] = []
    for row in rows:
        for key in row:
            if key not in cols:
                cols.append(key)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in row.items()})
    return buf.getvalue().encode()


# ---------------------------------------------------------------- signing key
def _key_material() -> bytes | None:
    """The instance's settings encryption key (already backed up in the recovery kit), or None."""
    key = os.getenv("GRCPAL_ENCRYPTION_KEY")
    if key:
        return key.encode()
    path = Path(os.getenv("GRCPAL_KEY_FILE", ".grcpal.key"))
    return path.read_text().strip().encode() if path.exists() else None


def signing_key():
    """Ed25519 private key for evidence manifests, or None when no key is configured (runs stay unsigned).
    GRCPAL_EVIDENCE_SIGNING_KEY (PEM) wins; otherwise the key is derived from the encryption key with HKDF,
    so no new secret has to be provisioned, backed up or rotated separately."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    pem = os.getenv("GRCPAL_EVIDENCE_SIGNING_KEY")
    if pem:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("GRCPAL_EVIDENCE_SIGNING_KEY must be an Ed25519 private key")
        return key
    material = _key_material()
    if not material:
        return None
    seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_KDF_INFO).derive(material)
    return Ed25519PrivateKey.from_private_bytes(seed)


def _raw_public(public_key) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(public_key) -> str:
    """Short fingerprint printed in manifests and on the evidence page."""
    return hashlib.sha256(_raw_public(public_key)).hexdigest()[:16]


def public_key_pem(public_key=None) -> str | None:
    from cryptography.hazmat.primitives import serialization

    if public_key is None:
        private = signing_key()
        if private is None:
            return None
        public_key = private.public_key()
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def load_public_key(pem: str):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Not an Ed25519 public key")
    return key


def sums_text(files: list[dict]) -> str:
    """`sha256sum -c` format: '<hash>  <name>' per line."""
    return "".join(f"{f['sha256']}  {f['name']}\n" for f in files)


class EvidenceStore:
    def __init__(self, root: str | Path = "evidence", account_url: str | None = None,
                 container: str | None = None, namespace: str | None = None) -> None:
        self.root = Path(root)
        ns = os.getenv("GRCPAL_TENANT", "") if namespace is None else namespace
        if ns and not _NAMESPACE.match(ns):
            raise ValueError("namespace must be 1-40 lowercase letters, digits or hyphens")
        self.namespace = "" if ns in ("", "default") else ns
        self.account_url = account_url or os.getenv("GRCPAL_EVIDENCE_ACCOUNT_URL") or None
        self.container_name = container or os.getenv("GRCPAL_EVIDENCE_CONTAINER", "evidence")
        self._container = None
        # Called after a run is written: on_seal(prefix, manifest_sha256, manifest). The portal sets it to
        # record the manifest hash in the tamper-evident audit log.
        self.on_seal = None

    # ---- blob container (optional) ----
    @property
    def container(self):
        if self.account_url and self._container is None:
            from azure.identity import DefaultAzureCredential
            from azure.storage.blob import BlobServiceClient

            svc = BlobServiceClient(self.account_url, credential=DefaultAzureCredential())
            self._container = svc.get_container_client(self.container_name)
        return self._container

    def _key(self, name: str) -> str:
        return f"{self.namespace}/{name}" if self.namespace else name

    def _put(self, name: str, data: bytes) -> None:
        name = self._key(name)
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        if self.container is not None:
            self.container.upload_blob(name, data, overwrite=False)

    def new_run(self, source: str, controls: list[str], meta: dict | None = None) -> "Run":
        return Run(self, source, controls, meta or {})

    # ---- reading (used by report) ----
    def list_runs(self, source: str) -> list[str]:
        runs: set[str] = set()
        if self.container is not None:
            prefix = self._key(f"{source}/")
            for blob in self.container.list_blobs(name_starts_with=prefix):
                parts = blob.name[len(prefix):].split("/")
                if len(parts) == 2 and parts[1] == MANIFEST:
                    runs.add(parts[0])
        base = self.root / self._key(source)
        if base.is_dir():
            runs.update(p.name for p in base.iterdir() if (p / MANIFEST).exists())
        return sorted(runs)

    def list_sources(self) -> list[str]:
        """Every source that has at least one complete run in this namespace (for verify and export)."""
        found: set[str] = set()
        if self.container is not None:
            prefix = self._key("")
            for blob in self.container.list_blobs(name_starts_with=prefix):
                parts = blob.name[len(prefix):].split("/")
                if len(parts) == 3 and parts[2] == MANIFEST:
                    found.add(parts[0])
        base = self.root / self.namespace if self.namespace else self.root
        if base.is_dir():
            for src in base.iterdir():
                if src.is_dir() and any((r / MANIFEST).is_file() for r in src.iterdir() if r.is_dir()):
                    found.add(src.name)
        return sorted(found)

    def read(self, source: str, run: str, filename: str) -> bytes | None:
        if "/" in source or "/" in run or "/" in filename or ".." in (source, run, filename):
            return None
        key = self._key(f"{source}/{run}/{filename}")
        local = self.root / key
        if local.exists():
            return local.read_bytes()
        if self.container is not None:
            try:
                return self.container.download_blob(key).readall()
            except Exception:  # noqa: BLE001 - missing blob
                return None
        return None

    def latest_manifest(self, source: str) -> dict | None:
        runs = self.list_runs(source)
        if not runs:
            return None
        raw = self.read(source, runs[-1], MANIFEST)
        return json.loads(raw) if raw else None

    # ---- integrity ----
    def verify_run(self, source: str, run: str, public_key=None, check_files: bool = True) -> dict:
        """Check one run. Status: verified (hashes and signature good), legacy (run written before signing;
        hashes good), failed (anything wrong). The audit-log anchor is checked by the portal on top of this.
        public_key defaults to this instance's key; pass one to verify with a published key instead."""
        result = {"source": source, "run": run, "status": "failed", "problems": [], "signed": False,
                  "key_id": None, "manifest_sha256": None, "files": 0}
        problems = result["problems"]
        raw = self.read(source, run, MANIFEST)
        if raw is None:
            problems.append("manifest.json is missing")
            return result
        result["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        try:
            manifest = json.loads(raw)
        except ValueError:
            problems.append("manifest.json is not valid JSON")
            return result
        files = manifest.get("files") or []
        result["files"] = len(files)
        if check_files:
            for f in files:
                data = self.read(source, run, f.get("name", ""))
                if data is None:
                    problems.append(f"{f.get('name')}: file is missing")
                elif hashlib.sha256(data).hexdigest() != f.get("sha256"):
                    problems.append(f"{f.get('name')}: content does not match its SHA-256 (changed)")
        integrity = manifest.get("integrity")
        if not integrity:
            result["status"] = "failed" if problems else "legacy"
            return result
        sums = self.read(source, run, SUMS)
        if sums is None:
            problems.append("SHA256SUMS is missing")
        elif sums.decode(errors="replace") != sums_text(files):
            problems.append("SHA256SUMS does not match the manifest")
        result["key_id"] = integrity.get("key_id")
        sig = self.read(source, run, SIGNATURE)
        if integrity.get("signature") != "ed25519":
            problems.append("run was written without a signing key (unsigned)")
        elif sig is None:
            problems.append("manifest.sig is missing")
        else:
            if public_key is None:
                private = signing_key()
                public_key = private.public_key() if private else None
            if public_key is None:
                problems.append("no evidence key configured here, so the signature cannot be checked")
            elif key_id(public_key) != integrity.get("key_id"):
                problems.append(f"signed with a different key ({integrity.get('key_id')})")
            else:
                from cryptography.exceptions import InvalidSignature

                try:
                    public_key.verify(base64.b64decode(sig, validate=True), raw)
                    result["signed"] = True
                except (InvalidSignature, ValueError):
                    problems.append("signature does not match manifest.json (manifest changed)")
        if not problems:
            result["status"] = "verified"
        return result


@dataclass
class Run:
    store: EvidenceStore
    source: str
    controls: list[str]
    meta: dict
    started: dt.datetime = field(default_factory=utcnow)
    files: list[dict] = field(default_factory=list)
    # How the data was obtained (API, query, record count, identity), for auditors testing
    # completeness and accuracy. Filled by the CLI from Clients.queries; empty for portal uploads.
    provenance: dict = field(default_factory=dict)

    @property
    def prefix(self) -> str:
        return f"{self.source}/{self.started:%Y-%m-%dT%H%M%SZ}"

    def add_bytes(self, filename: str, data: bytes) -> None:
        if filename in (MANIFEST, *INTEGRITY_FILES):
            raise ValueError(f"{filename} is reserved for the run's integrity files")
        self.store._put(f"{self.prefix}/{filename}", data)
        self.files.append({"name": filename, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})

    def add(self, name: str, data: Any) -> None:
        """Store JSON; lists of records are also stored as CSV for auditors."""
        self.add_bytes(f"{name}.json", json.dumps(data, indent=2, default=str, sort_keys=True).encode())
        if isinstance(data, list) and data and all(isinstance(r, dict) for r in data):
            self.add_bytes(f"{name}.csv", _to_csv(data))

    def finish(self, findings: list[dict], status: str = "ok", error: str | None = None) -> dict:
        manifest = {
            "source": self.source,
            "controls": self.controls,
            "started": self.started.isoformat(),
            "finished": utcnow().isoformat(),
            "status": status,
            "error": error,
            "files": self.files,
            "findings_count": len(findings),
            "findings": findings,
            "collector_version": os.getenv("GITHUB_SHA", "local"),
            "run_url": _run_url(),
            **self.meta,
        }
        if self.provenance:
            manifest["provenance"] = self.provenance
        key = signing_key()
        manifest["integrity"] = {"hash": "sha256", "sums_file": SUMS,
                                 "signature": "ed25519" if key else None,
                                 "key_id": key_id(key.public_key()) if key else None}
        raw = json.dumps(manifest, indent=2, default=str).encode()
        # Integrity files first, manifest last: a run only counts as complete once manifest.json exists.
        self.store._put(f"{self.prefix}/{SUMS}", sums_text(self.files).encode())
        if key:
            self.store._put(f"{self.prefix}/{SIGNATURE}", base64.b64encode(key.sign(raw)))
        self.store._put(f"{self.prefix}/{MANIFEST}", raw)
        if self.store.on_seal is not None:
            try:
                self.store.on_seal(self.prefix, hashlib.sha256(raw).hexdigest(), manifest)
            except Exception as exc:  # noqa: BLE001 - the evidence is stored; verification will flag the gap
                import sys

                print(f"WARN  could not record {self.prefix} in the audit log: {type(exc).__name__}: {exc}",
                      file=sys.stderr)
        return manifest


def verify_source(store: EvidenceStore, source: str, verify=None) -> list[dict]:
    """Verify every run of a source, oldest first. Once a source has a signed run, a later run without
    signing data fails: otherwise deleting the signature block would pass a changed run off as "legacy"."""
    verify = verify or (lambda src, run: store.verify_run(src, run))
    results, signed_seen = [], False
    for run in store.list_runs(source):
        r = verify(source, run)
        if r["status"] == "legacy" and signed_seen:
            r["status"] = "failed"
            r["problems"].append("no signature, but earlier runs of this source are signed (signature removed?)")
        signed_seen = signed_seen or r["signed"]
        results.append(r)
    return results


def _run_url() -> str | None:
    server, repo, run_id = os.getenv("GITHUB_SERVER_URL"), os.getenv("GITHUB_REPOSITORY"), os.getenv("GITHUB_RUN_ID")
    return f"{server}/{repo}/actions/runs/{run_id}" if server and repo and run_id else None

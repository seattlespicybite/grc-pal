"""Evidence store: write-once, timestamped, hashed evidence runs.

Layout (same locally and in Azure Blob Storage):
    [<namespace>/]<source>/<YYYY-MM-DDTHHMMSSZ>/<artifact files>
    [<namespace>/]<source>/<YYYY-MM-DDTHHMMSSZ>/manifest.json   (written last; SHA-256 of every file)

The optional namespace (GRCPAL_TENANT) keeps one organization's evidence under its own prefix.
Run prefixes handed to callers ("<source>/<run>") never include it, so a caller cannot
address another namespace.

Set GRCPAL_EVIDENCE_ACCOUNT_URL (https://<account>.blob.core.windows.net) to also upload to a
container with a locked time-based immutability policy (see deploy/azure/main.bicep).
Uploads use overwrite=False, so a run can never be replaced, only added.
"""
from __future__ import annotations

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


@dataclass
class Run:
    store: EvidenceStore
    source: str
    controls: list[str]
    meta: dict
    started: dt.datetime = field(default_factory=utcnow)
    files: list[dict] = field(default_factory=list)

    @property
    def prefix(self) -> str:
        return f"{self.source}/{self.started:%Y-%m-%dT%H%M%SZ}"

    def add_bytes(self, filename: str, data: bytes) -> None:
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
        self.store._put(f"{self.prefix}/{MANIFEST}", json.dumps(manifest, indent=2, default=str).encode())
        return manifest


def _run_url() -> str | None:
    server, repo, run_id = os.getenv("GITHUB_SERVER_URL"), os.getenv("GITHUB_REPOSITORY"), os.getenv("GITHUB_RUN_ID")
    return f"{server}/{repo}/actions/runs/{run_id}" if server and repo and run_id else None

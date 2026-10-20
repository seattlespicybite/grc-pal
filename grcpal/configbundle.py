"""Program configuration bundle: your catalog, registers and policies, delivered to the portal
without building your own container image.

    grcpal publish-config            (run by your program repo's workflow on every merge to main)

uploads catalog/, registers/, policies/, kb/ (your knowledge articles) and frameworks/ as one tar.gz to the storage account's `config`
container under the instance's tenant prefix. The portal downloads it at start-up with its
managed identity. The public GRC-pal image therefore stays generic, and your organization's
data (staff emails in roles.yaml, policies) never goes into a registry.
"""
from __future__ import annotations

import hashlib
import io
import os
import tarfile
from pathlib import Path

FOLDERS = ("catalog", "registers", "policies", "kb", "frameworks")
CONTAINER = "config"
MAX_BYTES = 20 * 1024 * 1024


def _blob_name(tenant: str) -> str:
    tenant = tenant or "default"
    return f"{tenant}/program.tar.gz"


def build(base: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for folder in FOLDERS:
            path = base / folder
            if path.is_dir():
                for f in sorted(path.rglob("*")):
                    if f.is_file() and not any(part.startswith(".") for part in f.relative_to(base).parts):
                        tar.add(f, arcname=str(f.relative_to(base)), recursive=False)
    data = buf.getvalue()
    if len(data) > MAX_BYTES:
        raise ValueError("configuration bundle is larger than 20 MB; keep evidence out of the program repository")
    return data


def extract(data: bytes, dest: Path) -> Path:
    """Extract only regular files under the allowed folders; refuse links and path tricks."""
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            parts = Path(member.name).parts
            if not member.isfile() or not parts or parts[0] not in FOLDERS or ".." in parts or member.name.startswith("/"):
                continue
            target = (root / member.name).resolve()
            if root not in target.parents:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(tar.extractfile(member).read())
    return dest


def _container(account_url: str):
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient

    return BlobServiceClient(account_url, credential=DefaultAzureCredential()).get_container_client(CONTAINER)


def publish(base: Path, account_url: str, tenant: str) -> str:
    data = build(base)
    _container(account_url).upload_blob(_blob_name(tenant), data, overwrite=True,
                                        metadata={"sha256": hashlib.sha256(data).hexdigest()})
    return hashlib.sha256(data).hexdigest()


def fetch(account_url: str | None = None, tenant: str | None = None, dest: Path | None = None) -> Path | None:
    """Download and extract the bundle; None when not configured or not published yet."""
    account_url = account_url or os.getenv("GRCPAL_EVIDENCE_ACCOUNT_URL")
    if not account_url or os.getenv("GRCPAL_CONFIG", "blob") == "off":
        return None
    try:
        data = _container(account_url).download_blob(_blob_name(tenant or os.getenv("GRCPAL_TENANT", "default"))).readall()
    except Exception:  # noqa: BLE001 - not published yet: fall back to the starter catalog
        return None
    return extract(data, dest or Path(os.getenv("GRCPAL_CONFIG_DIR", "/tmp/grcpal-config")))

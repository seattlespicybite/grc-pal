"""Where backups go, which ones are kept, and when the next one is due.

Used by the portal's Backups page (admins) and by `grcpal backup run-due` (the hourly timer on VMs,
the scheduled backup job on Azure). Destinations are configured by whoever runs the server, never typed
into the browser, so the portal can only write backups where the operator allowed:

    GRCPAL_BACKUP_DIR            folder on this server (default: backups/ next to the database)
    GRCPAL_BACKUP_DIR_HOST       how that folder is called on the host, for display (Docker: /var/lib/grcpal/backups)
    GRCPAL_BACKUP_DIR_2          optional second folder, e.g. a mounted network share
    GRCPAL_BACKUP_DIR_2_LABEL    its name on the page (default "Second location")
    GRCPAL_BACKUP_DIR_2_HOST     its host path, for display
    GRCPAL_BACKUP_CONTAINER      Azure: blob container for backups (default "backups" when evidence is in Azure)

File names: grcpal-<tenant>-<YYYYMMDDTHHMMSSZ>-<kind>.grcbak, kind = scheduled | manual | pre-update.
Next to each backup a small <name>.json holds its summary and verification result (no data, no keys).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from grcpal import backup

KINDS = ("scheduled", "manual", "pre-update")
NAME_RE = re.compile(r"^grcpal-([a-z0-9][a-z0-9-]{0,39})-(\d{8}T\d{6}Z)-(scheduled|manual|pre-update)\.grcbak$")
DEFAULT_SCHEDULE = {"frequency": "daily", "hour": 2, "keep_daily": 7, "keep_weekly": 4, "keep_monthly": 12,
                    "keep_pre_update": 3, "destination": ""}
FREQUENCIES = ("daily", "weekly", "off")
STATE_KEY = "backups"            # schedule and kit status, in the config table (state rows)
REQUEST_KEY = "backup_request"   # "Back up now" on Azure, picked up by the backup job
RUNNING_KEY = "backup_running"   # set while a scheduled run works, so overlapping checks skip
RUNNING_STALE = dt.timedelta(hours=6)  # a marker older than this was left by a crashed run; ignore it


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def file_name(tenant: str, kind: str, when: dt.datetime | None = None) -> str:
    if kind not in KINDS:
        raise ValueError(kind)
    return f"grcpal-{tenant}-{(when or _now()):%Y%m%dT%H%M%SZ}-{kind}.grcbak"


def parse_name(name: str) -> dict | None:
    m = NAME_RE.match(name or "")
    if not m:
        return None
    created = dt.datetime.strptime(m.group(2), "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
    return {"name": name, "tenant": m.group(1), "created": created, "kind": m.group(3)}


# ====================================================================== destinations
@dataclass
class FolderDestination:
    id: str
    label: str
    path: Path
    host_path: str = ""
    kind: str = "folder"

    def where(self, name: str = "") -> str:
        base = self.host_path or str(self.path)
        return f"{base.rstrip('/')}/{name}" if name else base

    def ready(self) -> str:
        """'' when usable, else what is wrong (shown on the page)."""
        try:
            self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            return f"Cannot create {self.where()}: {exc.strerror}"
        return "" if os.access(self.path, os.W_OK) else f"{self.where()} is not writable by GRC-pal"

    def list(self) -> list[dict]:
        out = []
        if not self.path.is_dir():
            return out
        for p in self.path.iterdir():
            info = parse_name(p.name)
            if info and p.is_file() and not p.is_symlink():
                st = p.stat()
                info.update(size=st.st_size, where=self.where(p.name), summary=self._sidecar(p.name))
                out.append(info)
        return sorted(out, key=lambda i: i["created"], reverse=True)

    def _sidecar(self, name: str) -> dict:
        try:
            return json.loads((self.path / f"{name}.json").read_text())
        except (OSError, ValueError):
            return {}

    def write(self, name: str, make) -> dict:
        """make(path) writes the backup at path. Built under a hidden name, renamed when complete."""
        partial = self.path / f".partial-{name}"
        make(partial)
        os.replace(partial, self.path / name)
        return {"where": self.where(name)}

    def save_summary(self, name: str, summary: dict) -> None:
        tmp = self.path / f".{name}.json.tmp"
        tmp.write_text(json.dumps(summary, indent=2, default=str))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path / f"{name}.json")

    def open(self, name: str):
        return (self.path / name).open("rb")

    def local_path(self, name: str) -> Path:
        return self.path / name

    def delete(self, name: str) -> None:
        (self.path / name).unlink(missing_ok=True)
        (self.path / f"{name}.json").unlink(missing_ok=True)

    can_delete = True


@dataclass
class BlobDestination:
    """Azure container with a write-once policy: backups cannot be changed or deleted before their retention
    ends, so app-side pruning is off and the storage lifecycle rule removes old ones."""
    id: str
    label: str
    container: object
    kind: str = "blob"
    can_delete = False

    def where(self, name: str = "") -> str:
        cname = getattr(self.container, "container_name", "backups")
        return f"Azure Storage container '{cname}'" + (f", blob {name}" if name else "")

    def ready(self) -> str:
        return ""

    def list(self) -> list[dict]:
        blobs = {b.name: b for b in self.container.list_blobs()}
        out = []
        for name, b in blobs.items():
            info = parse_name(name)
            if info:
                summary = {}
                if f"{name}.json" in blobs:
                    try:
                        summary = json.loads(b"".join(self.container.download_blob(f"{name}.json").chunks()))
                    except ValueError:
                        summary = {}
                info.update(size=b.size, where=self.where(name), summary=summary)
                out.append(info)
        return sorted(out, key=lambda i: i["created"], reverse=True)

    def write(self, name: str, make) -> dict:
        folder = tempfile.mkdtemp(prefix="grcpal-backup-")
        path = Path(folder) / name
        try:
            make(path)
            with path.open("rb") as f:
                self.container.upload_blob(name, f, overwrite=False)
        finally:
            path.unlink(missing_ok=True)
            os.rmdir(folder)
        return {"where": self.where(name)}

    def save_summary(self, name: str, summary: dict) -> None:
        self.container.upload_blob(f"{name}.json", json.dumps(summary, indent=2, default=str).encode(),
                                   overwrite=False)

    def open(self, name: str):
        return backup._IterReader(self.container.download_blob(name).chunks())

    def local_path(self, name: str) -> Path | None:
        return None

    def delete(self, name: str) -> None:
        raise backup.BackupError("Backups in Azure storage are write-once; the storage lifecycle rule removes old ones")


def destinations(evidence_root: Path | None = None) -> list:
    """The places the operator configured, first one is the default."""
    out = []
    if os.getenv("GRCPAL_EVIDENCE_ACCOUNT_URL"):
        from azure.identity import DefaultAzureCredential
        from azure.storage.blob import BlobServiceClient

        svc = BlobServiceClient(os.environ["GRCPAL_EVIDENCE_ACCOUNT_URL"], credential=DefaultAzureCredential())
        out.append(BlobDestination("azure", "Azure backup storage (write-once)",
                                   svc.get_container_client(os.getenv("GRCPAL_BACKUP_CONTAINER", "backups"))))
    first = os.getenv("GRCPAL_BACKUP_DIR")
    if not first and not out:
        if os.getenv("GRCPAL_SQLITE"):
            first = str(Path(os.environ["GRCPAL_SQLITE"]).parent / "backups")
        elif evidence_root is not None:
            first = str(Path(evidence_root).parent / "backups")
    if first:
        out.append(FolderDestination("local", "This server", Path(first), os.getenv("GRCPAL_BACKUP_DIR_HOST", "")))
    if os.getenv("GRCPAL_BACKUP_DIR_2"):
        out.append(FolderDestination("second", os.getenv("GRCPAL_BACKUP_DIR_2_LABEL", "Second location")[:60],
                                     Path(os.environ["GRCPAL_BACKUP_DIR_2"]), os.getenv("GRCPAL_BACKUP_DIR_2_HOST", "")))
    return out


def key_file(evidence_root: Path | None = None) -> Path | None:
    path = backup.default_key_file()
    if path is None and evidence_root is not None and not os.getenv("GRCPAL_EVIDENCE_ACCOUNT_URL"):
        path = Path(evidence_root).parent / "keys" / "backup.key"
    return path


def backup_key(evidence_root: Path | None = None, create: bool = True) -> bytes:
    """GRCPAL_BACKUP_KEY (Azure secret), else the key file, created on first use on VMs."""
    if os.getenv("GRCPAL_BACKUP_KEY"):
        return backup.load_key(os.environ["GRCPAL_BACKUP_KEY"])
    path = key_file(evidence_root)
    if path is None:
        raise backup.BackupError("No backup key configured: set the GRCPAL_BACKUP_KEY secret (deploy.sh does this)")
    return backup.ensure_key(path) if create else backup.load_key(path.read_text())


# ====================================================================== schedule and retention
def schedule(saved: dict | None) -> dict:
    out = dict(DEFAULT_SCHEDULE)
    out.update({k: v for k, v in (saved or {}).items() if k in DEFAULT_SCHEDULE})
    return out


def validate_schedule(form: dict, dest_ids: list[str]) -> dict:
    """Checked values from the page; raises ValueError with a plain message."""
    freq = form.get("frequency", "daily")
    if freq not in FREQUENCIES:
        raise ValueError("Choose daily, weekly or off")
    out = {"frequency": freq}
    for name, lo, hi in (("hour", 0, 23), ("keep_daily", 1, 60), ("keep_weekly", 0, 52), ("keep_monthly", 0, 120),
                         ("keep_pre_update", 1, 20)):
        try:
            out[name] = int(form.get(name, DEFAULT_SCHEDULE[name]))
        except (TypeError, ValueError):
            raise ValueError(f"{name.replace('_', ' ')} must be a whole number") from None
        if not lo <= out[name] <= hi:
            raise ValueError(f"{name.replace('_', ' ')} must be between {lo} and {hi}")
    dest = form.get("destination", "")
    if dest not in dest_ids:
        raise ValueError("Choose one of the backup locations listed")
    out["destination"] = dest
    return out


def due(sched: dict, existing: list[dict], now: dt.datetime | None = None) -> bool:
    """A scheduled backup is due when its hour (UTC) has passed and none was made in this period."""
    now = now or _now()
    if sched["frequency"] == "off" or now.hour < int(sched["hour"]):
        return False
    scheduled = [b for b in existing if b["kind"] == "scheduled"]
    if sched["frequency"] == "weekly":
        if now.weekday() != 6:  # Sunday
            return not any(b["created"] > now - dt.timedelta(days=7) for b in scheduled)
        return not any(b["created"].date() == now.date() for b in scheduled)
    return not any(b["created"].date() == now.date() for b in scheduled)


def to_keep(existing: list[dict], sched: dict) -> set[str]:
    """Grandfather-father-son: newest backup of each of the last N days, weeks and months; pre-update backups
    are kept separately (newest N). The newest verified backup is always kept."""
    keep: set[str] = set()
    regular = sorted((b for b in existing if b["kind"] != "pre-update"), key=lambda b: b["created"], reverse=True)
    for count, period in ((sched["keep_daily"], lambda d: d.date()),
                          (sched["keep_weekly"], lambda d: d.isocalendar()[:2]),
                          (sched["keep_monthly"], lambda d: (d.year, d.month))):
        seen = []
        for b in regular:
            p = period(b["created"])
            if p not in seen:
                if len(seen) >= count:
                    break
                seen.append(p)
                keep.add(b["name"])
    pre = sorted((b for b in existing if b["kind"] == "pre-update"), key=lambda b: b["created"], reverse=True)
    keep |= {b["name"] for b in pre[: sched["keep_pre_update"]]}
    verified = [b for b in regular if (b.get("summary") or {}).get("verified_ok")]
    if verified:
        keep.add(verified[0]["name"])
    return keep


# ====================================================================== running a backup
@dataclass
class Result:
    name: str
    where: str
    summary: dict = field(default_factory=dict)
    pruned: list = field(default_factory=list)


def run(inst: backup.Instance, dest, key: bytes, tenant: str, kind: str, sched: dict | None = None,
        progress=None) -> Result:
    """Create a backup in dest, verify it, record the summary next to it, then apply retention."""
    say = progress or (lambda msg: None)
    if (problem := dest.ready()):
        raise backup.BackupError(problem)
    name = file_name(tenant, kind)
    holder = {}

    def make(path: Path) -> None:
        say("Writing the backup file")
        holder["manifest"] = backup.create(inst, path, key)
        say("Checking the new file")
        holder["report"] = backup.verify(path, key)

    written = dest.write(name, make)
    report, manifest = holder["report"], holder["manifest"]
    summary = {**backup.summary(report), "file_sha256": manifest["file_sha256"], "file_bytes": manifest["file_bytes"],
               "kind": kind, "verified_ok": report["ok"], "verified_at": _now().isoformat()}
    dest.save_summary(name, summary)
    result = Result(name, written["where"], summary)
    if sched is not None and dest.can_delete:
        existing = dest.list()
        keep = to_keep(existing, sched)
        for b in existing:
            if b["name"] not in keep:
                dest.delete(b["name"])
                result.pruned.append(b["name"])
    say(f"Done: {result.where}")
    return result


def verify_existing(dest, name: str, key: bytes) -> dict:
    """Re-check a stored backup; records the result next to it (folders only: Azure copies are write-once)."""
    if not parse_name(name):
        raise backup.BackupError("Unknown backup name")
    path = dest.local_path(name)
    if path is not None:
        report = backup.verify(path, key)
    else:
        folder = tempfile.mkdtemp(prefix="grcpal-verify-")
        tmp = Path(folder) / name
        try:
            with dest.open(name) as src, tmp.open("wb") as out:
                while block := src.read(1 << 20):
                    out.write(block)
            report = backup.verify(tmp, key)
        finally:
            tmp.unlink(missing_ok=True)
            os.rmdir(folder)
    if dest.can_delete:
        summary = {**dest._sidecar(name), **backup.summary(report), "verified_ok": report["ok"],
                   "verified_at": _now().isoformat()}
        dest.save_summary(name, summary)
    return report

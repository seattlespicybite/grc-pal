"""Whole-instance backup file (.grcbak).

One encrypted file that holds everything needed to rebuild an instance on a clean image:
every portal table for every tenant, the evidence store, the HR inbox and the published
configuration bundle. `grcpal backup create` writes it; `grcpal backup verify` proves it is
complete and unchanged without restoring anything.

File layout
    GRCBAK1\\n                       magic
    {"format": 1, ...}\\n             header (key id, nonce prefix); authenticated with every chunk
    [4-byte length | AES-256-GCM chunk] ...   the last chunk has the top bit of its length set
Plaintext is a tar stream:
    tables/<table>.jsonl            every row of every tenant (PartitionKey keeps the "<tenant>|" prefix)
    evidence/<name>, inbox/<name>, config/<name>   files exactly as stored, original names
    manifest.json                   written last: SHA-256 of every file, row counts, audit-chain check

Security
  * The backup key (GRCPAL_BACKUP_KEY or a key file) is separate from GRCPAL_ENCRYPTION_KEY, which is
    never written into a backup. Saved integration secrets stay encrypted with the app key inside it.
  * Each chunk's nonce, number and "last chunk" flag are bound into GCM, so editing, reordering,
    swapping or cutting the file is detected.
  * This module reads every tenant through the raw backend on purpose: it is an operator tool
    (CLI and scheduled job only), never reachable from the portal.

Restore (`grcpal backup restore`) checks the whole file first and writes nothing unless it is intact,
then fills an EMPTY instance or a new folder (`--into`); it never overwrites existing data. Each tenant's
audit log continues the restored chain with a `backup.restore` record.

Recovery kit: one small file with the backup key and the app key (GRCPAL_ENCRYPTION_KEY). Keep it in a
password manager, apart from the backups. With a backup file and the kit, a clean machine can be rebuilt.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import os
import secrets
import struct
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from grcpal import __version__
from grcpal.portal.store import NOT_BACKED_UP, SCHEMA_VERSION, TABLES, SqliteStore, TenantStore

MAGIC = b"GRCBAK1\n"
FORMAT = 1
CHUNK = 1 << 20                     # plaintext bytes per encrypted chunk
_LAST = 0x80000000                  # flag bit in the length prefix of the final chunk
_MAX_HEADER = 4096
_MAX_MANIFEST = 256 << 20
AREAS = ("evidence", "inbox", "config")
ACTOR = "system@grc-pal.local"
BACKUP_TABLES = tuple(t for t in TABLES if t not in NOT_BACKED_UP)


class BackupError(Exception):
    """A problem the operator must act on; the message is safe to show."""


# ====================================================================== keys
def new_key() -> str:
    """A fresh random 256-bit backup key, base64."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


def load_key(text: str) -> bytes:
    try:
        key = base64.b64decode((text or "").strip(), validate=True)
    except ValueError:
        raise BackupError("The backup key is not valid base64. Create one with: grcpal backup keygen") from None
    if len(key) != 32:
        raise BackupError("The backup key must be 32 random bytes. Create one with: grcpal backup keygen")
    return key


def key_id(key: bytes, label: bytes = b"grcpal-backup-key-id") -> str:
    """Short fingerprint that names a key without revealing it."""
    return hashlib.sha256(label + b"\0" + key).hexdigest()[:16]


def _settings_key() -> str | None:
    key = os.getenv("GRCPAL_ENCRYPTION_KEY")
    path = Path(os.getenv("GRCPAL_KEY_FILE", ".grcpal.key"))
    if not key and path.is_file():
        key = path.read_text().strip()
    return key or None


def settings_key_id(key: str | None) -> str | None:
    return key_id(key.encode(), b"grcpal-settings-key-id") if key else None


def _settings_key_id() -> str | None:
    return settings_key_id(_settings_key())


def default_key_file() -> Path | None:
    """GRCPAL_BACKUP_KEY_FILE, else keys/backup.key next to the SQLite database (VM installs)."""
    if os.getenv("GRCPAL_BACKUP_KEY_FILE"):
        return Path(os.environ["GRCPAL_BACKUP_KEY_FILE"])
    if os.getenv("GRCPAL_SQLITE"):
        return Path(os.environ["GRCPAL_SQLITE"]).parent / "keys" / "backup.key"
    return None


def _write_private(path: Path, text: str) -> None:
    """Create a new owner-only file; never overwrite."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise BackupError(f"{path} already exists; it is never overwritten") from None
    with os.fdopen(fd, "w") as f:
        f.write(text)


def ensure_key(path: Path) -> bytes:
    """Read the backup key, creating it (owner-only) on first use."""
    path = Path(path)
    if not path.exists():
        try:
            _write_private(path, new_key() + "\n")
        except BackupError:
            pass  # created by another process in the meantime
    return load_key(path.read_text())


def resolve_key(key_file: str | None = None) -> bytes:
    """--key-file, else GRCPAL_BACKUP_KEY, else the default key file if it exists."""
    if key_file:
        return load_key(Path(key_file).read_text())
    if os.getenv("GRCPAL_BACKUP_KEY"):
        return load_key(os.environ["GRCPAL_BACKUP_KEY"])
    path = default_key_file()
    if path and path.is_file():
        return load_key(path.read_text())
    raise BackupError("No backup key: give --key-file or --kit, set GRCPAL_BACKUP_KEY, or create one with "
                      "grcpal backup keygen")


# ====================================================================== recovery kit
KIT_FORMAT = "grcpal-recovery-kit-1"


def make_kit(backup_key: bytes, settings_key: str | None, instance: str = "") -> str:
    """Text of a recovery kit: the two keys needed to rebuild this instance from a backup file."""
    kit = {"format": KIT_FORMAT, "instance": instance,
           "created": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
           "backup_key": base64.b64encode(backup_key).decode(), "backup_key_id": key_id(backup_key),
           "settings_key": settings_key or "", "settings_key_id": settings_key_id(settings_key),
           "readme": ["Keep this file in a password manager or safe, NOT next to the backups.",
                      "backup_key opens .grcbak backup files.",
                      "settings_key is GRCPAL_ENCRYPTION_KEY: it opens the integration credentials saved in the "
                      "portal. Set it on the new machine before starting GRC-pal after a restore.",
                      "Restore: grcpal backup restore FILE.grcbak --kit THIS-FILE"]}
    return json.dumps(kit, indent=2) + "\n"


def load_kit(text: str) -> dict:
    try:
        kit = json.loads(text)
        if kit.get("format") != KIT_FORMAT:
            raise ValueError
    except (ValueError, AttributeError):
        raise BackupError("This is not a GRC-pal recovery kit") from None
    kit["key"] = load_key(kit.get("backup_key", ""))
    if kit.get("backup_key_id") != key_id(kit["key"]):
        raise BackupError("The recovery kit is damaged (backup key does not match its id)")
    return kit


# ====================================================================== encryption stream
def _aes(key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(key)


class _EncryptWriter:
    """File-like sink: buffers plaintext, writes authenticated encrypted chunks."""

    def __init__(self, out, key: bytes) -> None:
        self._out, self._aes, self._prefix = out, _aes(key), secrets.token_bytes(8)
        header = {"format": FORMAT, "key_id": key_id(key), "nonce_prefix": self._prefix.hex(), "chunk": CHUNK}
        self._header = MAGIC + json.dumps(header, sort_keys=True).encode() + b"\n"
        self._buf, self._n, self.sha256, self.size = bytearray(), 0, hashlib.sha256(), 0
        self._emit(self._header)

    def _emit(self, data: bytes) -> None:
        self._out.write(data)
        self.sha256.update(data)
        self.size += len(data)

    def _chunk(self, data: bytes, last: bool) -> None:
        nonce = self._prefix + struct.pack(">I", self._n)
        ct = self._aes.encrypt(nonce, bytes(data), self._header + struct.pack(">I?", self._n, last))
        self._emit(struct.pack(">I", len(ct) | (_LAST if last else 0)) + ct)
        self._n += 1

    def write(self, data) -> int:
        self._buf += data
        while len(self._buf) > CHUNK:
            self._chunk(self._buf[:CHUNK], False)
            del self._buf[:CHUNK]
        return len(data)

    def close(self) -> None:
        self._chunk(self._buf, True)
        self._buf = bytearray()


class _DecryptReader(io.RawIOBase):
    """Reads and authenticates a .grcbak file chunk by chunk; raises BackupError on any problem."""

    def __init__(self, src, key: bytes) -> None:
        self._src, self._aes = src, _aes(key)
        if src.read(len(MAGIC)) != MAGIC:
            raise BackupError("This is not a GRC-pal backup file")
        line = src.readline(_MAX_HEADER)
        try:
            header = json.loads(line)
            self._prefix = bytes.fromhex(header["nonce_prefix"])
            if header["format"] != FORMAT or len(self._prefix) != 8:
                raise ValueError
        except (ValueError, KeyError, TypeError):
            raise BackupError("The backup file is damaged (unreadable header)") from None
        if header["key_id"] != key_id(key):
            raise BackupError(f"This backup was made with a different backup key (key id {header['key_id']}; "
                              f"the key you gave has id {key_id(key)})")
        self.header, self._header = header, MAGIC + line
        self._buf, self._n, self.done = b"", 0, False

    def readable(self) -> bool:
        return True

    def _next(self) -> None:
        raw = self._src.read(4)
        if len(raw) < 4:
            raise BackupError("The backup file is incomplete (it ends before its last chunk)")
        (n,) = struct.unpack(">I", raw)
        last, size = bool(n & _LAST), n & ~_LAST
        if size > min(int(self.header.get("chunk", CHUNK)), 64 << 20) + 16:  # checked before reading
            raise BackupError("The backup file is damaged (invalid chunk length)")
        ct = self._src.read(size)
        if len(ct) < size:
            raise BackupError("The backup file is incomplete (it ends in the middle of a chunk)")
        from cryptography.exceptions import InvalidTag

        try:
            self._buf = self._aes.decrypt(self._prefix + struct.pack(">I", self._n), ct,
                                          self._header + struct.pack(">I?", self._n, last))
        except InvalidTag:
            raise BackupError(f"The backup file is damaged or was changed (chunk {self._n} failed its "
                              "integrity check)") from None
        self._n += 1
        if last:
            self.done = True
            if self._src.read(1):
                raise BackupError("The backup file is damaged (data after the last chunk)")

    def readinto(self, b) -> int:
        while not self._buf and not self.done:
            self._next()
        n = min(len(b), len(self._buf))
        b[:n], self._buf = self._buf[:n], self._buf[n:]
        return n


# ====================================================================== what is backed up
@dataclass
class LocalArea:
    """Files under a local folder (Docker volume, VM disk). Symbolic links are never followed."""
    root: Path

    def files(self):
        root = Path(self.root)
        if not root.is_dir():
            return
        found = []
        for folder, dirs, names in os.walk(root, followlinks=False):
            dirs.sort()
            found += [Path(folder) / n for n in names]
        for path in sorted(found):
            if path.is_file() and not path.is_symlink():
                st = path.stat()
                modified = dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).replace(microsecond=0)
                yield path.relative_to(root).as_posix(), st.st_size, modified.isoformat(), \
                    (lambda p=path: p.open("rb"))


    def is_empty(self) -> bool:
        return next(iter(self.files()), None) is None

    def write(self, name: str, src) -> tuple[str, int]:
        """Create one file (never overwrite), streaming; returns (sha256, bytes)."""
        root = Path(self.root)
        target = root / name
        if root.resolve() not in target.resolve().parents:
            raise BackupError(f"Refusing to write outside {root}: {name[:200]!r}")
        target.parent.mkdir(parents=True, exist_ok=True)
        h, size = hashlib.sha256(), 0
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            while block := src.read(1 << 16):
                h.update(block)
                size += len(block)
                f.write(block)
        return h.hexdigest(), size


@dataclass
class BlobArea:
    """Every blob in an Azure Storage container."""
    container: object

    def is_empty(self) -> bool:
        return next(iter(self.container.list_blobs()), None) is None

    def write(self, name: str, src) -> tuple[str, int]:
        data = src.read()  # evidence files are size-limited at upload; the SDK needs the length up front
        self.container.upload_blob(name, data, overwrite=False)
        return hashlib.sha256(data).hexdigest(), len(data)

    def files(self):
        for blob in sorted(self.container.list_blobs(), key=lambda b: b.name):
            modified = blob.last_modified.isoformat() if getattr(blob, "last_modified", None) else None
            yield blob.name, blob.size, modified, \
                (lambda n=blob.name: _IterReader(self.container.download_blob(n).chunks()))


class _IterReader(io.RawIOBase):
    def __init__(self, chunks) -> None:
        self._it, self._buf = iter(chunks), b""

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        while not self._buf:
            self._buf = next(self._it, None)
            if self._buf is None:
                self._buf = b""
                return 0
        n = min(len(b), len(self._buf))
        b[:n], self._buf = self._buf[:n], self._buf[n:]
        return n


class _Hashing:
    def __init__(self, src) -> None:
        self._src, self.sha256, self.size = src, hashlib.sha256(), 0

    def read(self, n: int = -1) -> bytes:
        data = self._src.read(n)
        while n > 0 and data and len(data) < n:  # tar needs full reads; network streams return pieces
            more = self._src.read(n - len(data))
            if not more:
                break
            data += more
        self.sha256.update(data)
        self.size += len(data)
        return data


@dataclass
class Instance:
    base: object                                  # SqliteStore or TableStore (all tenants)
    areas: dict = field(default_factory=dict)     # "evidence" | "inbox" | "config" -> LocalArea | BlobArea


def from_env(evidence_dir: str, create: bool = False) -> Instance:
    """The running instance, from the same settings the portal and jobs use. create=True (restore) allows a
    database file that does not exist yet."""
    tables_url, sqlite = os.getenv("GRCPAL_TABLES_URL"), os.getenv("GRCPAL_SQLITE")
    if tables_url:
        from grcpal.portal.store import TableStore

        base = TableStore(tables_url)
    elif sqlite and (create or Path(sqlite).is_file()):
        Path(sqlite).parent.mkdir(parents=True, exist_ok=True)
        base = SqliteStore(sqlite)
    else:
        raise BackupError("Set GRCPAL_TABLES_URL (Azure) or GRCPAL_SQLITE to the portal database file")
    account = os.getenv("GRCPAL_EVIDENCE_ACCOUNT_URL")
    if account:
        from azure.identity import DefaultAzureCredential
        from azure.storage.blob import BlobServiceClient

        from grcpal import configbundle

        svc = BlobServiceClient(account, credential=DefaultAzureCredential())
        areas = {"evidence": BlobArea(svc.get_container_client(os.getenv("GRCPAL_EVIDENCE_CONTAINER", "evidence"))),
                 "inbox": BlobArea(svc.get_container_client("inbox")),
                 "config": BlobArea(svc.get_container_client(configbundle.CONTAINER))}
    else:
        root = Path(evidence_dir)
        areas = {"evidence": LocalArea(root), "inbox": LocalArea(root.parent / "inbox"),
                 "config": LocalArea(root.parent / "config")}
    return Instance(base, areas)


def instance_for(base, evidence) -> Instance:
    """The instance behind a running portal: its raw store and its EvidenceStore's storage."""
    if evidence.account_url:
        from azure.identity import DefaultAzureCredential
        from azure.storage.blob import BlobServiceClient

        from grcpal import configbundle

        svc = BlobServiceClient(evidence.account_url, credential=DefaultAzureCredential())
        return Instance(base, {"evidence": BlobArea(svc.get_container_client(evidence.container_name)),
                               "inbox": BlobArea(svc.get_container_client("inbox")),
                               "config": BlobArea(svc.get_container_client(configbundle.CONTAINER))})
    root = Path(evidence.root)
    return Instance(base, {"evidence": LocalArea(root), "inbox": LocalArea(root.parent / "inbox"),
                           "config": LocalArea(root.parent / "config")})


def tenants_in(base) -> set[str]:
    """Organizations that have data in this instance (from users and audit records)."""
    return {_tenant(r) for t in ("users", "audit") for r in base.list_prefix(t, "")}


def folder_instance(folder: Path) -> Instance:
    """A new, separate data folder laid out like a VM install: grcpal.db, evidence/, inbox/, config/."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    return Instance(SqliteStore(str(folder / "grcpal.db")),
                    {a: LocalArea(folder / a) for a in AREAS})


# ====================================================================== names
def _safe(name: str) -> bool:
    p = PurePosixPath(name)
    return (bool(name) and "\\" not in name and "\x00" not in name and not p.is_absolute()
            and all(part not in ("", ".", "..") for part in name.split("/")))


def _check_entry(member: tarfile.TarInfo) -> str:
    name = member.name
    top = name.split("/", 1)[0]
    ok = member.isfile() and _safe(name) and (
        name == "manifest.json"
        or (top == "tables" and name[7:-6] in BACKUP_TABLES and name.endswith(".jsonl") and name.count("/") == 1)
        or (top in AREAS and "/" in name))
    if not ok:
        raise BackupError(f"The backup contains an unexpected entry: {name[:200]!r}")
    return name


# ====================================================================== audit chain
def _audit_check(audit_rows: list[dict]) -> dict:
    """Verify each tenant's hash chain from the rows exactly as captured."""
    from grcpal.portal.auditlog import AuditLog

    mem = SqliteStore(":memory:")
    tenants = set()
    for row in audit_rows:
        mem.upsert("audit", row)
        tenants.add(row["PartitionKey"].split("|", 1)[0])
    out = {}
    for t in sorted(tenants):
        r = AuditLog(TenantStore(mem, t)).verify()
        out[t] = {"ok": r["ok"], "records": r["records"], "head": r["head"], "problems": r["problems"]}
    return out


def _tenant(row: dict) -> str:
    return row["PartitionKey"].split("|", 1)[0]


# ====================================================================== create
def _read_rows(base) -> dict[str, list[dict]]:
    """Every backed-up row. SQLite is read from a point-in-time copy so rows written meanwhile cannot mix in;
    the copy sits next to the database (not in /tmp, which may be memory) and is deleted afterwards."""
    if not isinstance(base, SqliteStore) or base.path in ("", ":memory:"):
        return {t: base.list_prefix(t, "") for t in BACKUP_TABLES}
    folder = tempfile.mkdtemp(prefix=".grcpal-snapshot-", dir=str(Path(base.path).resolve().parent))
    snap = None
    try:
        snap = base.snapshot(os.path.join(folder, "snapshot.db"))
        return {t: snap.list_prefix(t, "") for t in BACKUP_TABLES}
    finally:
        if snap is not None:
            snap.close()
        for name in os.listdir(folder):
            os.unlink(os.path.join(folder, name))
        os.rmdir(folder)


def create(inst: Instance, out: Path, key: bytes) -> dict:
    """Write the backup file; returns its manifest. The file is created new with mode 0600."""
    out = Path(out)
    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    backup_id = f"{started:%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"
    tenants = sorted({_tenant(r) for t in BACKUP_TABLES for r in inst.base.list_prefix(t, "")})

    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise BackupError(f"{out} already exists; backups are never overwritten") from None

    from grcpal.portal.auditlog import AuditLog

    logs = {t: AuditLog(TenantStore(inst.base, t)) for t in tenants}
    for log in logs.values():  # recorded before the snapshot, so the backup shows it was taken
        log.append(ACTOR, "backup.create", backup_id, {"file": out.name})
    rows = _read_rows(inst.base)

    manifest = {"format": FORMAT, "backup_id": backup_id, "app_version": __version__,
                "schema_version": SCHEMA_VERSION, "created": started.isoformat(), "tenants": tenants,
                "backup_key_id": None, "settings_key_id": _settings_key_id(),
                "tables": {}, "rows": {t: {} for t in tenants}, "table_sha256": {}, "files": [], "audit": {}}
    try:
        with os.fdopen(fd, "wb") as f:
            w = _EncryptWriter(f, key)
            manifest["backup_key_id"] = key_id(key)
            with tarfile.open(fileobj=w, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                def add(name: str, src, size: int) -> _Hashing:
                    info = tarfile.TarInfo(name)
                    info.size, info.mtime, info.mode = size, int(started.timestamp()), 0o600
                    h = _Hashing(src)
                    tar.addfile(info, h)
                    return h

                for table in BACKUP_TABLES:
                    ordered = sorted(rows[table], key=lambda r: (r["PartitionKey"], r["RowKey"]))
                    data = b"".join(json.dumps(r, sort_keys=True, default=str).encode() + b"\n" for r in ordered)
                    manifest["table_sha256"][table] = add(f"tables/{table}.jsonl", io.BytesIO(data), len(data)) \
                        .sha256.hexdigest()
                    manifest["tables"][table] = len(ordered)
                    for r in ordered:
                        counts = manifest["rows"].setdefault(_tenant(r), {})
                        counts[table] = counts.get(table, 0) + 1

                for area in AREAS:
                    if area not in inst.areas:
                        continue
                    for name, size, modified, opener in inst.areas[area].files():
                        if not _safe(name):
                            raise BackupError(f"Cannot back up {area} file with an unsafe name: {name[:200]!r}")
                        src = opener()
                        try:
                            h = add(f"{area}/{name}", src, size)
                        finally:
                            src.close()
                        if h.size != size:
                            raise BackupError(f"{area}/{name} changed while it was being backed up; run again")
                        manifest["files"].append({"name": f"{area}/{name}", "sha256": h.sha256.hexdigest(),
                                                  "bytes": size, "modified": modified})

                manifest["audit"] = _audit_check(rows["audit"])
                data = json.dumps(manifest, indent=2, sort_keys=True).encode()
                add("manifest.json", io.BytesIO(data), len(data))
            w.close()
    except BaseException:
        out.unlink(missing_ok=True)  # never leave a partial file that looks like a backup
        raise

    for log in logs.values():
        log.append(ACTOR, "backup.complete", backup_id, {"file": out.name, "sha256": w.sha256.hexdigest(),
                                                         "bytes": w.size, "files": len(manifest["files"])})
    manifest["file_sha256"], manifest["file_bytes"] = w.sha256.hexdigest(), w.size
    return manifest


# ====================================================================== verify
def verify(path: Path, key: bytes) -> dict:
    """Decrypt and check everything without writing anything. Returns {"ok", "problems", "manifest"}.

    Raises BackupError when the file itself is wrong (key, damage, truncation, unexpected entries);
    returns ok=False when the file is intact but its content does not match its manifest or an audit
    chain inside it is broken.
    """
    seen: dict[str, tuple[str, int]] = {}
    audit_rows: list[dict] = []
    table_lines: dict[str, int] = {}
    manifest = None
    with Path(path).open("rb") as f:
        reader = _DecryptReader(f, key)
        try:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                for member in tar:
                    if manifest is not None:
                        raise BackupError("The backup contains an unexpected entry after its manifest")
                    name = _check_entry(member)
                    if name in seen:
                        raise BackupError(f"The backup contains {name!r} twice")
                    src = tar.extractfile(member)
                    if name == "manifest.json":
                        if member.size > _MAX_MANIFEST:
                            raise BackupError("The backup manifest is too large")
                        manifest = json.loads(src.read())
                        continue
                    h = hashlib.sha256()
                    if name.startswith("tables/"):
                        data = src.read()
                        h.update(data)
                        lines = [json.loads(line) for line in data.splitlines() if line.strip()]
                        table_lines[name[7:-6]] = len(lines)
                        if name == "tables/audit.jsonl":
                            audit_rows = lines
                    else:
                        while block := src.read(1 << 16):
                            h.update(block)
                    seen[name] = (h.hexdigest(), member.size)
            while reader.read(1 << 16):  # authenticate the tail of the stream, through the last chunk
                pass
        except (tarfile.TarError, ValueError, EOFError, OSError) as exc:
            raise BackupError(f"The backup file is damaged ({type(exc).__name__})") from None
    if manifest is None:
        raise BackupError("The backup file is incomplete (no manifest)")

    problems: list[str] = []
    for table in BACKUP_TABLES:
        want = manifest.get("table_sha256", {}).get(table)
        got = seen.get(f"tables/{table}.jsonl")
        if want is None or got is None:
            problems.append(f"table {table} is missing")
        elif got[0] != want or table_lines.get(table) != manifest["tables"].get(table):
            problems.append(f"table {table} does not match the manifest")
    listed = {f["name"]: f for f in manifest.get("files", [])}
    for name, f in listed.items():
        if name not in seen:
            problems.append(f"{name} is listed but missing")
        elif seen[name] != (f["sha256"], f["bytes"]):
            problems.append(f"{name} does not match its SHA-256 in the manifest")
    for name in seen:
        if not name.startswith("tables/") and name not in listed:
            problems.append(f"{name} is not listed in the manifest")
    for tenant, result in _audit_check(audit_rows).items():
        if not result["ok"]:
            problems.append(f"audit log of tenant {tenant} does not verify: {'; '.join(result['problems'][:5])}")
    return {"ok": not problems, "problems": problems, "manifest": manifest}


# ====================================================================== restore
def restore(path: Path, key: bytes, inst: Instance, accept_audit_problems: bool = False) -> dict:
    """Restore a verified backup into an EMPTY instance. Nothing is written unless the whole file verifies;
    every file is re-hashed while it is written, so a file swapped after the check is caught too."""
    report = verify(path, key)
    m = report["manifest"]
    audit_only = all(p.startswith("audit log of tenant") for p in report["problems"])
    if report["problems"] and not (audit_only and accept_audit_problems):
        hint = " (to restore anyway, add --accept-audit-problems; it is recorded)" if audit_only else ""
        raise BackupError("The backup did not pass its checks, so nothing was restored: "
                          + "; ".join(report["problems"][:5]) + hint)
    if int(m.get("schema_version", 0)) > SCHEMA_VERSION:
        raise BackupError(f"This backup was made by GRC-pal {m.get('app_version')} (data model "
                          f"{m.get('schema_version')}); this is {__version__} (data model {SCHEMA_VERSION}). "
                          f"Install {m.get('app_version')} or newer, then restore.")
    needed = {f["name"].split("/", 1)[0] for f in m.get("files", [])}
    if needed - inst.areas.keys():
        raise BackupError(f"This instance has no place for the backup's {', '.join(sorted(needed - inst.areas.keys()))}")
    busy = (["portal tables"] if not inst.base.is_empty() else []) + \
        [a for a, area in inst.areas.items() if not area.is_empty()]
    if busy:
        raise BackupError(f"Restore only goes into an empty instance or a new folder (--into); this one already "
                          f"has data in: {', '.join(busy)}. Nothing was restored.")

    expected = {f["name"]: f for f in m["files"]}
    rows = files = 0
    with Path(path).open("rb") as f:
        reader = _DecryptReader(f, key)
        try:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                for member in tar:
                    name = _check_entry(member)
                    if name == "manifest.json":
                        continue
                    src = tar.extractfile(member)
                    if name.startswith("tables/"):
                        table, data = name[7:-6], src.read()
                        if hashlib.sha256(data).hexdigest() != m["table_sha256"].get(table):
                            raise BackupError(f"{name} changed after it was checked; the restore stopped")
                        for line in data.splitlines():
                            if line.strip():
                                inst.base.upsert(table, json.loads(line))
                                rows += 1
                        continue
                    area, rel = name.split("/", 1)
                    want = expected.get(name)
                    if want is None:
                        raise BackupError(f"{name} is not in the manifest; the restore stopped")
                    if inst.areas[area].write(rel, src) != (want["sha256"], want["bytes"]):
                        raise BackupError(f"{name} changed after it was checked; the restore stopped")
                    files += 1
            while reader.read(1 << 16):
                pass
        except (tarfile.TarError, ValueError, EOFError) as exc:
            raise BackupError(f"The backup file is damaged ({type(exc).__name__}); the restore stopped") from None

    from grcpal.portal.auditlog import AuditLog

    with Path(path).open("rb") as f:
        file_sha = hashlib.file_digest(f, "sha256").hexdigest()  # streamed: backups can be large
    audit = {}
    for t in m.get("tenants", []):
        log = AuditLog(TenantStore(inst.base, t))
        log.append(ACTOR, "backup.restore", m["backup_id"],
                   {"file": Path(path).name, "sha256": file_sha, "from_version": m.get("app_version"),
                    "schema_version": m.get("schema_version"), "backup_created": m.get("created"),
                    "accepted_audit_problems": bool(report["problems"])})
        r = log.verify()
        audit[t] = {"ok": r["ok"], "records": r["records"]}
    warnings = []
    if m.get("settings_key_id") and m["settings_key_id"] != _settings_key_id():
        warnings.append("GRCPAL_ENCRYPTION_KEY here is not the one this backup was made with. Set the "
                        "settings_key from the recovery kit before starting GRC-pal, or re-enter integration "
                        "credentials on the Configuration page.")
    warnings.append("Sign-in sessions are not restored: everyone signs in again.")
    return {"ok": all(a["ok"] for a in audit.values()), "backup_id": m["backup_id"],
            "from_version": m.get("app_version"), "schema_version": m.get("schema_version"),
            "created": m.get("created"), "tenants": m.get("tenants"), "rows": rows, "files": files,
            "audit": audit, "warnings": warnings}


def summary(report: dict) -> dict:
    """Short, printable result for the command line (no row data, no file list)."""
    m = report["manifest"]
    return {"ok": report["ok"], "problems": report["problems"], "backup_id": m.get("backup_id"),
            "created": m.get("created"), "app_version": m.get("app_version"),
            "schema_version": m.get("schema_version"), "tenants": m.get("tenants"),
            "rows": sum(m.get("tables", {}).values()), "files": len(m.get("files", [])),
            "bytes": sum(f["bytes"] for f in m.get("files", [])),
            "audit": {t: {"ok": a["ok"], "records": a["records"]} for t, a in m.get("audit", {}).items()},
            "backup_key_id": m.get("backup_key_id"), "settings_key_id": m.get("settings_key_id")}

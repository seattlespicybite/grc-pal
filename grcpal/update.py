"""Signed update files for VM installs, and the checks the updater runs before and after switching versions.

Update file (.grcupdate), a tar archive:
    manifest.json      {"format", "version", "image_ref", "image_id", "image_sha256", "schema_version",
                        "created", "notes"}
    manifest.sig       Ed25519 signature of manifest.json (base64)
    image.tar          `docker save` of the image
The updater on the VM never trusts the file: the version that is already running checks the signature
against the public key installed with GRC-pal (/etc/grcpal/update-signing.pub) and the SHA-256 of
image.tar, before the image is even loaded.

Self-test (`grcpal update selftest`), run by the updater against a trial copy and after the switch:
    * the data model is readable by this version (migrations.check);
    * every organization's audit chain verifies;
    * evidence files match the SHA-256 in their run manifests (recent runs plus a sample of older ones);
    * no table has fewer rows than before the update (`grcpal update counts` saved them).

Requests from the portal (Updates and Backups pages, VM only) are small JSON files in GRCPAL_UPDATE_REQUESTS.
The updater validates them on its own; the portal can only ask, it can never run anything on the host.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import os
import random
import re
import secrets
import tarfile
from pathlib import Path

FORMAT = "grcpal-update-1"
VERSION_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
REQUEST_ACTIONS = ("apply", "restore", "policy", "check", "rollback")


class UpdateError(Exception):
    """The message is safe to show and says what to do."""


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def version_tuple(v: str) -> tuple[int, int, int]:
    if not VERSION_RE.match(v or ""):
        raise UpdateError(f"Not a version number: {v!r}")
    a, b, c = (int(x) for x in v.split("."))
    return a, b, c


def kind_of(current: str, new: str) -> str:
    """patch | minor | major | same | older"""
    c, n = version_tuple(current), version_tuple(new)
    if n == c:
        return "same"
    if n < c:
        return "older"
    if n[0] != c[0]:
        return "major"
    return "minor" if n[1] != c[1] else "patch"  # in 0.x a minor may also clean up data: it always needs approval


# ====================================================================== keys and signatures
# ====================================================================== release notes and the release list
NOTE_SECTIONS = ("security", "fixed", "added", "changed")
RELEASES_REPO_RE = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")


def changelog_section(text: str, version: str) -> str:
    """The CHANGELOG.md section of one release: the release notes (Security, Fixed, Added, Changed)."""
    version_tuple(version)
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.M | re.S)
    if not m or not m.group(1).strip():
        raise UpdateError(f"CHANGELOG.md has no section for {version}")
    return m.group(1).strip()


def notes_summary(notes: str) -> dict:
    """How many entries each kind of change has (bullets under ### Security / Fixed / Added / Changed)."""
    counts = dict.fromkeys(NOTE_SECTIONS, 0)
    section = ""
    for line in (notes or "").splitlines():
        head = re.match(r"^###\s+(\w+)", line)
        if head:
            section = head.group(1).lower()
        elif section in counts and line.startswith("- "):
            counts[section] += 1
    return counts


def advice(kind: str, summary: dict) -> dict:
    """A plain answer to "do I need this update?" for the Updates page."""
    if summary.get("security"):
        return {"level": "security", "text": "Contains security fixes: install soon."}
    if kind == "major":
        return {"level": "major", "text": "Major release: read the notes and plan a time; going back needs the "
                                          "backup taken before the update."}
    if summary.get("fixed"):
        return {"level": "fixes", "text": "Bug fixes: install when convenient."}
    return {"level": "features", "text": "New features: install when you want them."}


def newer_releases(rows: list, current: str) -> list[dict]:
    """GitHub releases API rows -> published releases newer than `current`, newest first.
    The rows come from the internet: every field is checked, links must point to github.com."""
    out = []
    for r in (rows or [])[:50]:
        if not isinstance(r, dict) or r.get("draft") or r.get("prerelease"):
            continue
        version = str(r.get("tag_name") or "").removeprefix("v")
        if not VERSION_RE.match(version):
            continue
        kind = kind_of(current, version)
        if kind not in ("patch", "minor", "major"):
            continue
        notes = str(r.get("body") or "")[:20000]
        summary = notes_summary(notes)
        url = r.get("html_url")
        out.append({"version": version, "kind": kind, "published": str(r.get("published_at") or "")[:10],
                    "notes": notes, "summary": summary, "advice": advice(kind, summary),
                    "url": url if isinstance(url, str) and url.startswith("https://github.com/") else ""})
    return sorted(out, key=lambda x: version_tuple(x["version"]), reverse=True)


def fetch_releases(repo: str, timeout: float = 5) -> list:
    """Read the public release list from GitHub. Sends nothing about this instance (no tenant data, no
    version), uses the SSRF-guarded client, and only ever this fixed API address."""
    from grcpal.checks import safe_request

    if not RELEASES_REPO_RE.match(repo or ""):
        raise UpdateError(f"Not a GitHub repository: {repo!r}")
    r = safe_request("GET", f"https://api.github.com/repos/{repo}/releases?per_page=30",
                     headers={"Accept": "application/vnd.github+json", "User-Agent": "grc-pal-update-check"},
                     timeout=timeout, redirects=0)
    if r.status != 200 or r.truncated:
        raise UpdateError(f"GitHub answered {r.status}")
    rows = json.loads(r.body)
    if not isinstance(rows, list):
        raise UpdateError("Unexpected answer from GitHub")
    return rows


def keygen() -> tuple[str, str]:
    """(private PEM, public PEM). Keep the private key only in the GitHub release environment secret."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return private, public


def _load_public(pem: str):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key = serialization.load_pem_public_key(pem.encode())
    except ValueError:
        raise UpdateError("The update signing public key is not valid") from None
    if not isinstance(key, Ed25519PublicKey):
        raise UpdateError("The update signing key must be Ed25519")
    return key


def public_keys(path: str | Path | None = None) -> list[str]:
    """One or more PEM public keys (several allow rotating the signing key)."""
    path = Path(path or os.getenv("GRCPAL_UPDATE_PUBLIC_KEY", "/etc/grcpal/update-signing.pub"))
    if not path.is_file():
        raise UpdateError(f"No update signing key at {path}. Install it from deploy/vm/update-signing.pub.")
    text = path.read_text()
    keys = re.findall(r"-----BEGIN PUBLIC KEY-----.+?-----END PUBLIC KEY-----", text, re.S)
    if not keys:
        raise UpdateError(f"{path} holds no public key")
    return keys


def sign(data: bytes, private_pem: str) -> str:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    return base64.b64encode(key.sign(data)).decode()


def signature_ok(data: bytes, sig_b64: str, keys: list[str]) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        sig = base64.b64decode(sig_b64.strip(), validate=True)
    except ValueError:
        return False
    for pem in keys:
        try:
            _load_public(pem).verify(sig, data)
            return True
        except InvalidSignature:
            continue
    return False


# ====================================================================== update files
def make_bundle(out: Path, image_tar: Path, version: str, image_ref: str, image_id: str, private_pem: str,
                schema_version: int, notes: str = "") -> dict:
    """Build a signed .grcupdate (release workflow)."""
    version_tuple(version)
    h = hashlib.sha256()
    with Path(image_tar).open("rb") as f:
        while block := f.read(1 << 20):
            h.update(block)
    manifest = {"format": FORMAT, "version": version, "image_ref": image_ref, "image_id": image_id,
                "image_sha256": h.hexdigest(), "schema_version": int(schema_version), "created": _now(),
                "notes": notes[:20000]}
    data = json.dumps(manifest, indent=2, sort_keys=True).encode()
    sig = sign(data, private_pem).encode()
    with tarfile.open(out, "w") as tar:
        for name, payload in (("manifest.json", data), ("manifest.sig", sig)):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(payload), 0, 0o644
            tar.addfile(info, io.BytesIO(payload))
        tar.add(str(image_tar), arcname="image.tar")
    return manifest


def verify_manifest(data: bytes, sig: str, keys: list[str]) -> dict:
    if not signature_ok(data, sig, keys):
        raise UpdateError("The update file is not signed by GRC-pal's release key; it was not installed")
    try:
        manifest = json.loads(data)
    except ValueError:
        raise UpdateError("The update file's manifest is unreadable") from None
    if manifest.get("format") != FORMAT:
        raise UpdateError("Unknown update file format")
    version_tuple(manifest.get("version", ""))
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", manifest.get("image_id", "")):
        raise UpdateError("The update manifest has no valid image ID")
    return manifest


def verify_bundle(path: Path, keys: list[str]) -> dict:
    """Signature first, then the image's SHA-256. Returns the manifest; raises UpdateError otherwise."""
    try:
        with tarfile.open(path, "r:") as tar:
            names = tar.getnames()
            if sorted(names) != ["image.tar", "manifest.json", "manifest.sig"]:
                raise UpdateError(f"The update file has unexpected contents: {sorted(names)[:5]}")
            data = tar.extractfile("manifest.json").read(1 << 20)
            sig = tar.extractfile("manifest.sig").read(4096).decode()
            manifest = verify_manifest(data, sig, keys)
            member = tar.getmember("image.tar")
            if not member.isfile():
                raise UpdateError("image.tar in the update file is not a regular file")
            h = hashlib.sha256()
            src = tar.extractfile(member)
            while block := src.read(1 << 20):
                h.update(block)
    except (tarfile.TarError, OSError, KeyError, UnicodeDecodeError):
        raise UpdateError("The update file is damaged or incomplete") from None
    if h.hexdigest() != manifest["image_sha256"]:
        raise UpdateError("The image inside the update file does not match its signed checksum; it was not installed")
    return manifest


# ====================================================================== checks before and after
def counts(base) -> dict:
    from grcpal.backup import BACKUP_TABLES

    return {t: len(base.list_prefix(t, "")) for t in BACKUP_TABLES}


def _evidence_runs(root: Path) -> list[Path]:
    return sorted(p.parent for p in Path(root).rglob("manifest.json"))


def selftest(base, evidence_root: Path | None, expect: dict | None = None, sample: int = 200,
             skip_evidence: bool = False) -> dict:
    """Health of the data as seen by this version. {"ok", "problems", "checked": {...}}."""
    from grcpal import migrations
    from grcpal.backup import tenants_in
    from grcpal.portal.auditlog import AuditLog
    from grcpal.portal.store import TenantStore

    problems, checked = [], {}
    try:
        checked["data_model"] = migrations.check(base)
    except migrations.SchemaError as exc:
        problems.append(str(exc))
    for t in sorted(tenants_in(base)):
        r = AuditLog(TenantStore(base, t)).verify()
        checked.setdefault("audit", {})[t] = {"ok": r["ok"], "records": r["records"]}
        if not r["ok"]:
            problems.append(f"audit log of {t}: {'; '.join(r['problems'][:3])}")
    if expect:
        now = counts(base)
        for table, n in expect.items():
            if now.get(table, 0) < int(n):
                problems.append(f"table {table} has {now.get(table, 0)} rows, {n} before the update")
        checked["rows"] = sum(now.values())
    if not skip_evidence and evidence_root is not None and Path(evidence_root).is_dir():
        runs = _evidence_runs(Path(evidence_root))
        recent, older = runs[-50:], runs[:-50]
        picked = recent + random.sample(older, min(len(older), sample))
        files = 0
        for run in picked:
            try:
                man = json.loads((run / "manifest.json").read_text())
            except (OSError, ValueError):
                problems.append(f"evidence run {run.name}: manifest unreadable")
                continue
            for f in man.get("files", []):
                p = run / f.get("name", "")
                try:
                    digest = hashlib.file_digest(p.open("rb"), "sha256").hexdigest()
                except OSError:
                    problems.append(f"evidence {run.relative_to(evidence_root)}/{f.get('name')}: missing")
                    continue
                files += 1
                if digest != f.get("sha256"):
                    problems.append(f"evidence {run.relative_to(evidence_root)}/{f.get('name')}: changed")
        checked["evidence"] = {"runs_checked": len(picked), "runs_total": len(runs), "files": files}
    return {"ok": not problems, "problems": problems[:50], "checked": checked, "at": _now()}


EXPECTED_KEY = "update-expected"


def save_expected(base, tenant: str) -> dict:
    """Row counts before an Azure update, kept in the instance's own state row for the after-switch self-test."""
    data = {"counts": counts(base), "at": _now()}
    base.upsert("config", {"PartitionKey": f"{tenant}|state", "RowKey": EXPECTED_KEY, "json": json.dumps(data)})
    return data


def load_expected(base, tenant: str, max_age_hours: int = 24) -> dict:
    row = base.get("config", f"{tenant}|state", EXPECTED_KEY)
    if not row:
        raise UpdateError("No row counts were saved before this update (run `grcpal update trial` first)")
    data = json.loads(row["json"])
    age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(data["at"])
    if age > dt.timedelta(hours=max_age_hours):
        raise UpdateError(f"The saved row counts are from {data['at']}, older than {max_age_hours} hours; "
                          "run the trial again")
    return data["counts"]


def trial_copy(base, tenant: str | None = None) -> dict:
    """Azure trial run, executed by the NEW version: copy every backed-up table into a scratch database, run
    this version's migrations there and self-test the copy. The live tables are only read (plus the saved row
    counts). Evidence is never migrated, so it is not copied."""
    from grcpal import migrations
    from grcpal.backup import BACKUP_TABLES
    from grcpal.portal.store import SqliteStore

    scratch = SqliteStore(":memory:")
    for table in BACKUP_TABLES:
        for row in base.list_prefix(table, ""):
            scratch.upsert(table, row)
    meta = migrations.read_meta(base)
    if meta is not None:
        scratch.upsert(migrations.META_TABLE, {"PartitionKey": migrations.META_PK, "RowKey": migrations.META_RK,
                                               **{k: v for k, v in meta.items() if k not in ("PartitionKey", "RowKey")}})
    expected = save_expected(base, tenant)["counts"] if tenant else counts(base)
    try:
        applied = migrations.migrate(scratch)
    except migrations.SchemaError as exc:
        return {"ok": False, "problems": [f"migrations failed on the copy: {exc}"], "checked": {}, "at": _now()}
    except Exception as exc:  # noqa: BLE001 - any crash in a migration must stop the update
        return {"ok": False, "problems": [f"a migration crashed on the copy: {type(exc).__name__}: {exc}"[:500]],
                "checked": {}, "at": _now()}
    result = selftest(scratch, None, expected, skip_evidence=True)
    result["checked"]["migrations_applied"] = applied
    return result


def record(base, action: str, detail: dict) -> None:
    """Updater events in every organization's audit log (update.applied, update.rolled_back, ...)."""
    from grcpal import migrations

    if not re.fullmatch(r"(update|restore)\.[a-z_]{2,30}", action):
        raise UpdateError("Unknown update action")
    migrations.audit_all(base)(action, detail)


# ====================================================================== requests and status (portal side)
def requests_dir() -> Path | None:
    value = os.getenv("GRCPAL_UPDATE_REQUESTS")
    return Path(value) if value else None


def state_dir() -> Path | None:
    value = os.getenv("GRCPAL_UPDATE_STATE")
    return Path(value) if value else None


def write_request(action: str, payload: dict, by: str) -> dict:
    """Leave a request for the host updater. Raises UpdateError when this install has no updater."""
    folder = requests_dir()
    if folder is None or not folder.is_dir():
        raise UpdateError("This installation has no updater (requests folder missing); see docs/deploy-vm.md")
    if action not in REQUEST_ACTIONS:
        raise UpdateError("Unknown request")
    req = {"action": action, "by": by, "at": _now(), "id": secrets.token_hex(6), **payload}
    data = json.dumps(req).encode()
    if len(data) > 4096:
        raise UpdateError("Request too large")
    tmp = folder / f".{req['id']}.tmp"
    tmp.write_bytes(data)
    os.replace(tmp, folder / f"{req['id']}.json")
    return req


def pending_requests() -> list[dict]:
    folder = requests_dir()
    out = []
    if folder and folder.is_dir():
        for p in sorted(folder.glob("*.json")):
            try:
                out.append(json.loads(p.read_text()[:4096]))
            except (OSError, ValueError):
                continue
    return out


def read_state(name: str, default=None):
    folder = state_dir()
    if folder is None:
        return default
    try:
        return json.loads((folder / name).read_text())
    except (OSError, ValueError):
        return default


def history(limit: int = 30) -> list[dict]:
    folder = state_dir()
    if folder is None or not (folder / "history.jsonl").is_file():
        return []
    lines = (folder / "history.jsonl").read_text().splitlines()[-limit:]
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out

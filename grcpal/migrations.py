"""Data model versions and migrations: how an update changes stored data without losing any.

Rules (CI checks them in tests/test_release_rules.py):
  1. Migrations only ADD: new fields with defaults, new rows, new tables. They never delete or rename data
     in the same release; a cleanup ships in a later major release, after a release that announced it.
  2. Migrations get the table store only. They have no access to evidence, which an update never changes.
  3. SCHEMA_VERSION (grcpal/portal/store.py) is 1 + the number of migrations here. Patch releases may not
     change it. A migration that older versions cannot read ("breaking") needs a major release
     (a minor release while the version is 0.x).
  4. Each migration runs once, in order, and is recorded with the version that ran it, in the instance's
     meta row and in every organization's audit log.

The meta row (table "meta", key _system/schema) holds:
    schema_version   the data model the data is at
    readable_by      the oldest SCHEMA_VERSION that can still read it (rises only with a breaking migration)
    history          list of {"version", "description", "at", "by_app"}
An older GRC-pal can start on newer data while its SCHEMA_VERSION >= readable_by. That is what makes
rolling back to the previous image safe after a patch or minor update.
"""
from __future__ import annotations

import datetime as dt
import time
from dataclasses import dataclass
from typing import Callable

from grcpal import __version__
from grcpal.portal.store import SCHEMA_VERSION

META_TABLE, META_PK, META_RK = "meta", "_system", "schema"


@dataclass(frozen=True)
class Migration:
    version: int                     # the schema version this migration produces
    description: str
    run: Callable                    # run(base): the raw table store, nothing else
    breaking: bool = False           # True: older versions can no longer read the data


# Baseline is version 1 (the data model of 0.1.0 and 0.2.0). Append new migrations here, numbered 2, 3, ...
MIGRATIONS: tuple[Migration, ...] = ()

# Released versions and the data model each shipped with; add a line in every release commit.
RELEASES = {"0.1.0": 1, "0.2.0": 1}


class SchemaError(Exception):
    """The data cannot be used by this version; the message says what to do."""


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def read_meta(base) -> dict | None:
    return base.get(META_TABLE, META_PK, META_RK)


def _has_data(base) -> bool:
    return not base.is_empty() if hasattr(base, "is_empty") else bool(base.list_prefix("users", ""))


def current(base) -> dict:
    """The data's version. Installs from before migrations existed (no meta row, but data) are version 1."""
    meta = read_meta(base)
    if meta:
        return meta
    if _has_data(base):
        return {"schema_version": 1, "readable_by": 1, "history": []}
    return {"schema_version": SCHEMA_VERSION, "readable_by": _readable_by(SCHEMA_VERSION), "history": []}


def _readable_by(version: int) -> int:
    breaking = [m.version for m in MIGRATIONS if m.breaking and m.version <= version]
    return max(breaking) if breaking else 1


def _write_meta(base, meta: dict) -> None:
    base.upsert(META_TABLE, {"PartitionKey": META_PK, "RowKey": META_RK, **meta})


def pending(base) -> list[Migration]:
    have = int(current(base)["schema_version"])
    return [m for m in MIGRATIONS if m.version > have]


def check(base) -> dict:
    """Can this version use the data? Raises SchemaError with a plain instruction if not."""
    meta = current(base)
    have, readable_by = int(meta["schema_version"]), int(meta.get("readable_by", 1))
    if SCHEMA_VERSION < readable_by:
        raise SchemaError(f"This data was upgraded to data model {have} by a newer GRC-pal, and version "
                          f"{__version__} (data model {SCHEMA_VERSION}) cannot read it. Start the newer version "
                          "again, or restore the backup taken before the update.")
    return {"schema_version": have, "readable_by": readable_by, "app_schema": SCHEMA_VERSION,
            "pending": [m.version for m in pending(base)]}


def migrate(base, audit: Callable[[str, dict], None] | None = None, wait_seconds: float = 120) -> list[int]:
    """Apply pending migrations in order. Safe with two replicas starting at once: each migration takes a
    lock row first; the replica that loses waits for the other to finish."""
    check(base)
    if read_meta(base) is None:  # first run of the framework on this instance: record where the data is
        _write_meta(base, current(base))
    done = []
    for m in pending(base):
        lock = {"PartitionKey": META_PK, "RowKey": f"lock-{m.version}", "at": _now(), "by_app": __version__}
        try:
            base.insert(META_TABLE, lock)
        except Exception:  # noqa: BLE001 - another process holds it: wait for it to finish this migration
            deadline = time.monotonic() + wait_seconds
            while int(current(base)["schema_version"]) < m.version:
                if time.monotonic() > deadline:
                    raise SchemaError(f"Migration {m.version} is held by another process for over {wait_seconds:.0f} "
                                      f"seconds. If no other GRC-pal is running, remove the meta row lock-{m.version}.")
                time.sleep(1)
            continue
        m.run(base)
        meta = current(base)
        meta["history"] = (meta.get("history") or []) + [
            {"version": m.version, "description": m.description, "at": _now(), "by_app": __version__}]
        meta["schema_version"], meta["readable_by"] = m.version, _readable_by(m.version)
        _write_meta(base, meta)
        base.delete(META_TABLE, META_PK, f"lock-{m.version}")
        if audit:
            audit("system.migration", {"version": m.version, "description": m.description, "app": __version__})
        done.append(m.version)
    return done


def set_version(base, version: int) -> None:
    """After a restore: the restored rows are at the backup's data model; migrate() takes them from there."""
    _write_meta(base, {"schema_version": int(version), "readable_by": _readable_by(int(version)),
                       "history": [{"version": int(version), "description": "restored from backup", "at": _now(),
                                    "by_app": __version__}]})


def audit_all(base) -> Callable[[str, dict], None]:
    """Audit callback that records an instance-wide event in every organization's log."""
    from grcpal.backup import tenants_in
    from grcpal.portal.auditlog import AuditLog
    from grcpal.portal.store import TenantStore

    def record(action: str, detail: dict) -> None:
        for t in sorted(tenants_in(base)):
            AuditLog(TenantStore(base, t)).append("system@grc-pal.local", action, "data model", detail)
    return record


# ====================================================================== release rules (used by CI and release)
def _parse(v: str) -> tuple[int, int, int]:
    major, minor, patch = (int(x) for x in v.split(".")[:3])
    return major, minor, patch


def release_problems(version: str = __version__, releases: dict | None = None,
                     migrations: tuple[Migration, ...] | None = None, schema: int | None = None) -> list[str]:
    """Why this version may not be released with this data model, if anything."""
    releases = RELEASES if releases is None else releases
    migrations = MIGRATIONS if migrations is None else migrations
    schema = SCHEMA_VERSION if schema is None else schema
    problems = []
    numbers = [m.version for m in migrations]
    if numbers != list(range(2, 2 + len(numbers))):
        problems.append(f"migrations must be numbered 2, 3, ... in order (found {numbers})")
    if schema != 1 + len(migrations):
        problems.append(f"SCHEMA_VERSION is {schema} but there are {len(migrations)} migrations (expected {1 + len(migrations)})")
    points = sorted(releases.items(), key=lambda kv: _parse(kv[0]))
    if version not in releases:
        points.append((version, schema))
    elif releases[version] != schema:
        problems.append(f"{version} is listed as data model {releases[version]} but SCHEMA_VERSION is {schema}")
    for (old_v, old_s), (new_v, new_s) in zip(points, points[1:]):
        o, n = _parse(old_v), _parse(new_v)
        if n <= o:
            problems.append(f"versions must increase: {old_v} then {new_v}")
        if new_s < old_s:
            problems.append(f"{new_v} lowers the data model ({old_s} to {new_s}); migrations are never removed")
        if new_s != old_s and n[:2] == o[:2]:
            problems.append(f"{new_v} is a patch release but changes the data model ({old_s} to {new_s}); "
                            "release it as a minor version")
        broke = [m for m in migrations if m.breaking and old_s < m.version <= new_s]
        if broke:
            needs_major = n[0] == o[0] if o[0] >= 1 else n[:2] == o[:2]
            if needs_major:
                problems.append(f"{new_v} contains breaking migration {broke[0].version}; release it as a "
                                f"{'major' if o[0] >= 1 else 'new minor (0.x)'} version")
    return problems


def main(argv: list[str] | None = None) -> int:
    """python -m grcpal.migrations --release-check vX.Y.Z  (used by the release workflow)."""
    import argparse
    import sys

    p = argparse.ArgumentParser(prog="python -m grcpal.migrations")
    p.add_argument("--release-check", metavar="TAG", required=True)
    tag = p.parse_args(argv).release_check
    problems = [] if tag == f"v{__version__}" else [f"tag {tag} does not match the package version {__version__}"]
    if __version__ not in RELEASES:
        problems.append(f"add \"{__version__}\": {SCHEMA_VERSION} to RELEASES in grcpal/migrations.py")
    problems += release_problems()
    for line in problems:
        print(f"release check: {line}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())

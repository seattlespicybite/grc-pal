"""SQLite store: reads are safe alongside writes from other threads, and the "data is lost on restart" warning only
fires for a database that really is temporary (in memory or under /tmp), not for a VM's persistent /data volume."""
import threading

import pytest

from grcpal.portal.store import SqliteStore, sqlite_is_temporary


def test_reads_and_writes_from_many_threads(tmp_path):
    db = SqliteStore(str(tmp_path / "grcpal.db"))
    errors: list[BaseException] = []

    def writer(n: int) -> None:
        try:
            for i in range(200):
                db.upsert("t", {"PartitionKey": "p", "RowKey": f"{n}-{i}", "v": i})
        except BaseException as exc:  # noqa: BLE001 - any failure in a thread fails the test
            errors.append(exc)

    def reader() -> None:
        try:
            for _ in range(200):
                db.list("t", "p")
                db.list_prefix("t", "p")
                db.get("t", "p", "0-0")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
    threads += [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(db.list("t", "p")) == 800


@pytest.mark.parametrize("path, temporary", [
    (":memory:", True), ("", True), ("/tmp/grcpal.db", True), ("/var/tmp/grcpal.db", True),
    ("grcpal.db", True),  # relative: inside a container that is the image's own, throw-away disk
    ("/data/grcpal.db", False), ("/var/lib/grcpal/grcpal.db", False),
])
def test_temporary_database_paths(path, temporary):
    assert sqlite_is_temporary(path) is temporary


def test_deployment_check_accepts_a_persistent_sqlite_file(monkeypatch, tmp_path):
    from tests.test_portal import make_portal

    monkeypatch.delenv("GRCPAL_TABLES_URL", raising=False)
    portal = make_portal(tmp_path)
    for path, ok in (("/data/grcpal.db", True), ("/tmp/grcpal.db", False)):
        monkeypatch.setenv("GRCPAL_SQLITE", path)
        item = next(c for c in portal.deployment_checks() if c["name"] == "Portal data storage")
        assert item["ok"] is ok, path

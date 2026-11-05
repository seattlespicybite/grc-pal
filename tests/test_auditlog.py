"""Audit log under concurrency (B-041 / R-02): the head pointer never moves backwards."""
from __future__ import annotations

import contextlib
import threading

from grcpal.portal import auditlog
from grcpal.portal.auditlog import AuditLog
from grcpal.portal.store import SqliteStore, TenantStore


def _store(tmp_path):
    return TenantStore(SqliteStore(str(tmp_path / "a.db")), "acme")


def test_a_late_head_update_from_a_slower_writer_is_ignored(tmp_path):
    log = AuditLog(_store(tmp_path))
    first = log.append("a@example.com", "x.one", "t")
    log.append("b@example.com", "x.two", "t")
    # Writer A (seq 1) finishes its head update after writer B (seq 2) already moved the head.
    log._advance_head(first["seq"], first["hash"], first["PartitionKey"])
    assert log._head()["seq"] == 2
    assert log.verify()["ok"]


def test_two_replicas_appending_at_once_keep_the_chain_verifiable(tmp_path, monkeypatch):
    # Separate replicas do not share the in-process lock: remove it to let appends interleave.
    monkeypatch.setattr(auditlog, "_lock", contextlib.nullcontext())
    store = _store(tmp_path)
    logs = [AuditLog(store), AuditLog(store)]

    def work(i):
        for n in range(25):
            logs[i].append(f"user{i}@example.com", "x.write", f"t{n}")

    threads = [threading.Thread(target=work, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result = logs[0].verify()
    assert result["records"] == 50
    assert result["ok"], result["problems"]


def test_conditional_write_refuses_a_stale_version(tmp_path):
    store = _store(tmp_path)
    row = {"PartitionKey": "p", "RowKey": "r", "n": 1}
    assert store.replace_if("meta", row, None)
    assert not store.replace_if("meta", row, None)  # already exists
    current, version = store.get_versioned("meta", "p", "r")
    assert current["n"] == 1
    assert store.replace_if("meta", {**row, "n": 2}, version)
    assert not store.replace_if("meta", {**row, "n": 3}, version)  # version is stale now
    assert store.get("meta", "p", "r")["n"] == 2


def test_azure_conditional_write_maps_conflicts_to_false():
    from azure.core.exceptions import HttpResponseError, ResourceExistsError

    from grcpal.portal.store import TableStore

    class Client:
        def __init__(self, exc):
            self.exc, self.calls = exc, []

        def create_entity(self, entity):
            self.calls.append(("create", None))
            if self.exc:
                raise self.exc

        def update_entity(self, entity, mode, etag, match_condition):
            self.calls.append(("update", etag))
            if self.exc:
                raise self.exc

    stale = HttpResponseError(message="precondition failed")
    stale.status_code = 412
    for exc, version, expected in ((None, None, True), (ResourceExistsError("exists"), None, False),
                                   (None, 'W/"1"', True), (stale, 'W/"1"', False)):
        ts = object.__new__(TableStore)
        ts._clients = {"audit": Client(exc)}
        assert ts.replace_if("audit", {"PartitionKey": "head", "RowKey": "head", "seq": 1}, version) is expected
        assert ts._clients["audit"].calls[0][1] == version

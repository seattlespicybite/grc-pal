"""Audit log reads (B-043 / R-04): recent() reads month partitions newest-first; the daily verify is stored."""
from __future__ import annotations

from grcpal.portal import auditlog
from grcpal.portal.auditlog import AuditLog
from grcpal.portal.store import SqliteStore, TenantStore


class CountingStore(TenantStore):
    def __init__(self, *a):
        super().__init__(*a)
        self.lists = []

    def list(self, table, pk=None):
        self.lists.append((table, pk))
        return super().list(table, pk)


def _log_over_months(tmp_path, monkeypatch, months=("2026-01", "2026-02", "2026-03", "2026-04"), per_month=30):
    import datetime as dt

    store = CountingStore(SqliteStore(str(tmp_path / "a.db")), "acme")
    log = AuditLog(store)
    for m in months:
        moment = dt.datetime.fromisoformat(f"{m}-15T10:00:00+00:00")
        monkeypatch.setattr(auditlog, "utcnow", lambda moment=moment: moment)
        for n in range(per_month):
            log.append(f"user{n % 3}@example.com", "evidence.upload" if n % 2 else "user.login", f"{m}-{n}")
    return store, log


def test_recent_reads_only_the_newest_months_it_needs(tmp_path, monkeypatch):
    store, log = _log_over_months(tmp_path, monkeypatch)
    store.lists.clear()
    rows = log.recent(50)
    assert [r["seq"] for r in rows] == list(range(120, 70, -1))
    assert store.lists == [("audit", "2026-04"), ("audit", "2026-03")]  # never the whole table


def test_recent_matches_the_full_read_for_filters_and_walks_to_record_one(tmp_path, monkeypatch):
    store, log = _log_over_months(tmp_path, monkeypatch)
    full = list(reversed(log.records()))
    want = [r for r in full if r["action"].startswith("evidence.") and "user1" in r["actor"]]
    got = log.recent(500, actor="USER1", action="evidence.")
    assert [r["seq"] for r in got] == [r["seq"] for r in want]
    assert log.recent(500)[-1]["seq"] == 1


def test_recent_skips_empty_months_and_handles_an_empty_log(tmp_path, monkeypatch):
    assert AuditLog(TenantStore(SqliteStore(":memory:"), "acme")).recent(10) == []
    _, log = _log_over_months(tmp_path, monkeypatch, months=("2025-11", "2026-03"), per_month=5)
    assert [r["seq"] for r in log.recent(100)] == list(range(10, 0, -1))


def test_daily_verify_result_is_stored_and_shown(tmp_path, monkeypatch):
    _, log = _log_over_months(tmp_path, monkeypatch, months=("2026-04",), per_month=3)
    assert log.last_verification() is None
    log.verify()
    assert log.last_verification() is None  # a plain verify (page, CLI, backup) stores nothing
    log.verify(record=True)
    last = log.last_verification()
    assert last["ok"] and last["records"] == 3 and last["verified_at"]
    assert all("seq" in r for r in log.records())  # the stored result is not an audit record

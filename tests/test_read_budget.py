"""Read budget (B-040 / R-01): a page reads each table once per request, not once per control."""
from __future__ import annotations

import collections

import pytest
from fastapi.testclient import TestClient

from grcpal.portal.app import create_app
from grcpal.portal.store import SqliteStore, TenantStore, request_cache
from test_portal import ADMIN, as_, make_portal

# Measured after the fix: about 25 reads for a cold "/" (was 133, 80 of them "checks"). Some headroom for new cards;
# raise it only with a reason.
BUDGET = {"/": 40, "/controls": 30, "/calendar": 30, "/audit": 30}


class Counting(SqliteStore):
    def __init__(self, *a):
        super().__init__(*a)
        self.reads = collections.Counter()

    def get(self, table, pk, rk):
        self.reads[table] += 1
        return super().get(table, pk, rk)

    def list(self, table, pk):
        self.reads[table] += 1
        return super().list(table, pk)

    def list_prefix(self, table, prefix):
        self.reads[table] += 1
        return super().list_prefix(table, prefix)


@pytest.fixture()
def counted(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    base = Counting()
    client = TestClient(create_app(make_portal(tmp_path, base_store=base)), base_url="https://grc.example.com")
    as_(client, ADMIN)
    return base, client


@pytest.mark.parametrize("path", sorted(BUDGET))
def test_page_stays_within_its_read_budget(counted, path):
    base, client = counted
    base.reads.clear()
    assert client.get(path).status_code == 200
    total = sum(base.reads.values())
    assert total <= BUDGET[path], f"{path}: {total} reads {base.reads.most_common(5)}"
    assert base.reads["checks"] <= 1


def test_cache_returns_copies_and_a_write_is_seen_by_the_next_read():
    store = TenantStore(SqliteStore(), "acme")
    store.insert("checks", {"PartitionKey": "k", "RowKey": "1", "title": "a", "config": {"url": "https://example.com"}})
    with request_cache():
        rows = store.list("checks", "k")
        rows[0]["config"]["url"] = "changed"  # a caller changing its copy does not change the cache
        assert store.list("checks", "k")[0]["config"]["url"] == "https://example.com"
        store.update("checks", "k", "1", {"title": "b"})
        assert store.list("checks", "k")[0]["title"] == "b"
        assert store.get("checks", "k", "1")["title"] == "b"
        store.delete("checks", "k", "1")
        assert store.get("checks", "k", "1") is None and store.list("checks") == []


def test_cache_never_answers_for_another_tenant():
    base = SqliteStore()
    a, b = TenantStore(base, "acme"), TenantStore(base, "globex")
    a.insert("checks", {"PartitionKey": "k", "RowKey": "1", "title": "acme only"})
    with request_cache():
        assert len(a.list("checks", "k")) == 1
        assert b.list("checks", "k") == [] and b.get("checks", "k", "1") is None

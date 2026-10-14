"""Portal data store with tenant isolation.

Backends (interchangeable):
  * TableStore  - Azure Table Storage, managed-identity auth (production).
  * SqliteStore - local file or in-memory (development, demo, tests).

Isolation: application code never talks to a backend directly. It receives a TenantStore,
which prefixes every partition key with "<tenant>|" on write and only ever queries inside
that prefix on read, then strips the prefix from results. There is no API on TenantStore
that can read another tenant's rows. For the strongest separation, run one instance (and
one storage account) per customer; the prefix is defense in depth on top of that.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from typing import Iterable

# Version of the stored data model. Raise it only together with a migration (planned: grcpal/migrations.py);
# backups record it so a restore can tell whether the data needs upgrading.
SCHEMA_VERSION = 1
TABLES = ("users", "cycles", "assignments", "uploads", "comments", "overrides", "audit",
          "reminders", "acks", "config", "events", "jobs", "customcontrols", "checks", "frameworks",
          "aireviews", "aiaudits")
_JSON_FIELDS = {"contributors", "points", "detail", "controls", "values", "secrets", "mappings", "evidence",
                "config", "result", "requirements", "findings", "package", "items", "summary", "assertions",
                "headers", "steps", "last_test"}
TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


def _encode(entity: dict) -> dict:
    return {k: (json.dumps(v) if k in _JSON_FIELDS and not isinstance(v, str) else v) for k, v in entity.items()}


def _decode(entity: dict) -> dict:
    out = dict(entity)
    for key in _JSON_FIELDS & out.keys():
        if isinstance(out[key], str):
            try:
                out[key] = json.loads(out[key])
            except ValueError:
                pass
    return out


class SqliteStore:
    def __init__(self, path: str = ":memory:") -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._db.execute("CREATE TABLE IF NOT EXISTS entities (tbl TEXT, pk TEXT, rk TEXT, data TEXT, PRIMARY KEY (tbl, pk, rk))")
        self._db.commit()

    def insert(self, table: str, entity: dict) -> dict:
        with self._lock:
            self._db.execute("INSERT INTO entities VALUES (?, ?, ?, ?)",
                             (table, entity["PartitionKey"], entity["RowKey"], json.dumps(_encode(entity))))
            self._db.commit()
        return entity

    def upsert(self, table: str, entity: dict) -> dict:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO entities VALUES (?, ?, ?, ?)",
                             (table, entity["PartitionKey"], entity["RowKey"], json.dumps(_encode(entity))))
            self._db.commit()
        return entity

    def update(self, table: str, pk: str, rk: str, fields: dict) -> dict:
        with self._lock:
            row = self._db.execute("SELECT data FROM entities WHERE tbl=? AND pk=? AND rk=?", (table, pk, rk)).fetchone()
            if row is None:
                raise KeyError(f"{table}/{rk}")
            entity = json.loads(row[0])
            entity.update(_encode(fields))
            self._db.execute("UPDATE entities SET data=? WHERE tbl=? AND pk=? AND rk=?", (json.dumps(entity), table, pk, rk))
            self._db.commit()
        return _decode(entity)

    def get(self, table: str, pk: str, rk: str) -> dict | None:
        row = self._db.execute("SELECT data FROM entities WHERE tbl=? AND pk=? AND rk=?", (table, pk, rk)).fetchone()
        return _decode(json.loads(row[0])) if row else None

    def delete(self, table: str, pk: str, rk: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM entities WHERE tbl=? AND pk=? AND rk=?", (table, pk, rk))
            self._db.commit()

    def list(self, table: str, pk: str) -> list[dict]:
        rows = self._db.execute("SELECT data FROM entities WHERE tbl=? AND pk=?", (table, pk)).fetchall()
        return [_decode(json.loads(r[0])) for r in rows]

    def list_prefix(self, table: str, prefix: str) -> list[dict]:
        rows = self._db.execute("SELECT data FROM entities WHERE tbl=? AND substr(pk, 1, ?) = ?",
                                (table, len(prefix), prefix)).fetchall()
        return [_decode(json.loads(r[0])) for r in rows]


class TableStore:
    """Azure Table Storage. Endpoint like https://<account>.table.core.windows.net"""

    def __init__(self, endpoint: str) -> None:
        from azure.data.tables import TableServiceClient
        from azure.identity import DefaultAzureCredential

        svc = TableServiceClient(endpoint=endpoint, credential=DefaultAzureCredential())
        self._clients = {}
        for name in TABLES:
            svc.create_table_if_not_exists(f"grcpal{name}")
            self._clients[name] = svc.get_table_client(f"grcpal{name}")

    def insert(self, table: str, entity: dict) -> dict:
        self._clients[table].create_entity(_encode(entity))
        return entity

    def upsert(self, table: str, entity: dict) -> dict:
        from azure.data.tables import UpdateMode

        self._clients[table].upsert_entity(_encode(entity), mode=UpdateMode.REPLACE)
        return entity

    def update(self, table: str, pk: str, rk: str, fields: dict) -> dict:
        from azure.data.tables import UpdateMode

        client = self._clients[table]
        client.update_entity({"PartitionKey": pk, "RowKey": rk, **_encode(fields)}, mode=UpdateMode.MERGE)
        return _decode(dict(client.get_entity(pk, rk)))

    def get(self, table: str, pk: str, rk: str) -> dict | None:
        from azure.core.exceptions import ResourceNotFoundError

        try:
            return _decode(dict(self._clients[table].get_entity(pk, rk)))
        except ResourceNotFoundError:
            return None

    def delete(self, table: str, pk: str, rk: str) -> None:
        from azure.core.exceptions import ResourceNotFoundError

        try:
            self._clients[table].delete_entity(pk, rk)
        except ResourceNotFoundError:
            pass

    def list(self, table: str, pk: str) -> list[dict]:
        items: Iterable = self._clients[table].query_entities("PartitionKey eq @pk", parameters={"pk": pk})
        return [_decode(dict(e)) for e in items]

    def list_prefix(self, table: str, prefix: str) -> list[dict]:
        # "~" sorts after every character allowed in tenant IDs and keys, so this is a prefix range.
        items = self._clients[table].query_entities("PartitionKey ge @lo and PartitionKey lt @hi",
                                                    parameters={"lo": prefix, "hi": prefix + "~"})
        return [_decode(dict(e)) for e in items]


class TenantStore:
    """The only store application code uses. Every key is confined to one tenant."""

    def __init__(self, base, tenant: str) -> None:
        if not TENANT_RE.match(tenant or ""):
            raise ValueError("tenant must be 1-40 lowercase letters, digits or hyphens")
        self._base, self.tenant, self._p = base, tenant, f"{tenant}|"

    def _in(self, entity: dict) -> dict:
        return {**entity, "PartitionKey": self._p + entity["PartitionKey"]}

    def _out(self, entity: dict | None) -> dict | None:
        if entity is None:
            return None
        pk = entity["PartitionKey"]
        if not pk.startswith(self._p):  # never return another tenant's row, whatever the backend did
            raise PermissionError("cross-tenant row blocked")
        return {**entity, "PartitionKey": pk[len(self._p):]}

    def insert(self, table, entity):
        self._base.insert(table, self._in(entity))
        return entity

    def upsert(self, table, entity):
        self._base.upsert(table, self._in(entity))
        return entity

    def update(self, table, pk, rk, fields):
        return self._out(self._base.update(table, self._p + pk, rk, fields))

    def get(self, table, pk, rk):
        return self._out(self._base.get(table, self._p + pk, rk))

    def delete(self, table, pk, rk):
        self._base.delete(table, self._p + pk, rk)

    def list(self, table, pk=None):
        rows = self._base.list(table, self._p + pk) if pk is not None else self._base.list_prefix(table, self._p)
        return [self._out(r) for r in rows]


def from_env() -> TenantStore:
    url = os.getenv("GRCPAL_TABLES_URL")
    base = TableStore(url) if url else SqliteStore(os.getenv("GRCPAL_SQLITE", "grcpal.db"))
    return TenantStore(base, os.getenv("GRCPAL_TENANT", "default"))

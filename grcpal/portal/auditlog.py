"""Tamper-evident audit log.

Each record carries a sequence number and the SHA-256 of the previous record, so deleting,
reordering or editing any record breaks the chain from that point on. `verify()` recomputes
the chain; `grcpal audit verify` and the daily portal_audit collector run it and store the
result as evidence. The daily export to write-once storage anchors the chain externally:
an attacker with database access cannot rewrite history already exported.

Concurrency: a record is inserted with a unique sequence key, so two writers cannot both
claim the same position; the loser retries with the next number.
"""
from __future__ import annotations

import hashlib
import json
import threading

from grcpal.evidence import utcnow
from grcpal.portal.observability import request_id

GENESIS = "0" * 64
_lock = threading.Lock()


def _digest(prev: str, record: dict) -> str:
    body = {k: record.get(k) for k in ("seq", "at", "actor", "action", "target", "detail", "request_id")}
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, default=str)).encode()).hexdigest()


def _as_list(value) -> list:
    return value if isinstance(value, list) else []


class AuditLog:
    TABLE = "audit"

    def __init__(self, store) -> None:
        self.store = store

    def _head(self) -> dict:
        return self.store.get(self.TABLE, "head", "head") or {"seq": 0, "hash": GENESIS, "pk": ""}

    def append(self, actor: str, action: str, target: str, detail: dict | None = None) -> dict:
        with _lock:
            head = self._head()
            seq, prev = int(head["seq"]) + 1, head["hash"]
            for _ in range(50):
                now = utcnow()
                record = {"PartitionKey": f"{now:%Y-%m}", "RowKey": f"{seq:012d}", "seq": seq, "at": now.isoformat(),
                          "actor": actor, "action": action, "target": str(target)[:200], "detail": detail or {},
                          "request_id": request_id.get(), "prev_hash": prev}
                record["hash"] = _digest(prev, record)
                try:
                    self.store.insert(self.TABLE, record)
                except Exception:  # noqa: BLE001 - key taken by another writer; move past it
                    taken = self._find(seq)
                    if taken is None:
                        raise
                    seq, prev = seq + 1, taken["hash"]
                    continue
                self.store.upsert(self.TABLE, {"PartitionKey": "head", "RowKey": "head", "seq": seq,
                                               "hash": record["hash"], "pk": record["PartitionKey"]})
                return record
            raise RuntimeError("audit log contention: could not append after 50 attempts")

    def _find(self, seq: int) -> dict | None:
        rk = f"{seq:012d}"
        now = utcnow()
        for pk in (f"{now:%Y-%m}", self._head().get("pk")):
            if pk:
                row = self.store.get(self.TABLE, pk, rk)
                if row:
                    return row
        return next((r for r in self.records() if r["RowKey"] == rk), None)

    def records(self) -> list[dict]:
        rows = [r for r in self.store.list(self.TABLE) if r.get("PartitionKey") != "head" and "seq" in r]
        return sorted(rows, key=lambda r: int(r["seq"]))

    def recent(self, limit: int = 500, actor: str = "", action: str = "", target: str = "") -> list[dict]:
        rows = self.records()
        if actor:
            rows = [r for r in rows if actor.lower() in r["actor"].lower()]
        if action:
            rows = [r for r in rows if r["action"].startswith(action)]
        if target:
            rows = [r for r in rows if target.lower() in r["target"].lower()
                    or target.upper() in _as_list((r.get("detail") or {}).get("controls"))]
        return list(reversed(rows))[:limit]

    def verify(self) -> dict:
        """Recompute the chain. Returns {"ok", "records", "head", "problems": [...]}."""
        rows = self.records()
        head = self._head()
        problems, prev, expected = [], GENESIS, 1
        for r in rows:
            seq = int(r["seq"])
            if seq != expected:
                problems.append(f"missing records {expected}..{seq - 1}" if seq > expected else f"duplicate record {seq}")
            if r.get("prev_hash") != prev:
                problems.append(f"record {seq}: previous-hash link broken")
            if _digest(r.get("prev_hash", ""), r) != r.get("hash"):
                problems.append(f"record {seq}: content does not match its hash (edited)")
            prev, expected = r.get("hash", ""), seq + 1
        if rows and (int(head["seq"]) != int(rows[-1]["seq"]) or head["hash"] != rows[-1]["hash"]):
            problems.append("head pointer does not match the last record (records removed from the end?)")
        if not rows and int(head["seq"]) != 0:
            problems.append("head pointer present but no records")
        return {"ok": not problems, "records": len(rows), "head": head.get("hash", GENESIS), "problems": problems,
                "verified_at": utcnow().isoformat()}

"""System event log: the important operational events, kept per tenant and searchable on the Logs page.

Not every request is recorded, only what helps troubleshooting or an audit: sign-in refusals, first
sign-ins, configuration saves and connection tests, collector and check runs, emails that failed, AI
requests (never their content), background jobs, exports and unexpected errors with their reference.
Changes to data (who approved what) are in the hash-chained audit log; the Logs page can show both.

Rows: PartitionKey = UTC day (YYYY-MM-DD), so a date range is a handful of partition reads.
Retention: GRCPAL_LOG_RETENTION_DAYS (default 90); older days are removed automatically.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import threading
import uuid

from grcpal.portal.observability import current_actor, event, request_id

LEVELS = ("info", "warning", "error", "security")
CATEGORIES = ("auth", "config", "collector", "check", "mail", "ai", "job", "export", "system", "security")
_SECRETISH = ("password", "secret", "token", "api_key", "apikey", "authorization", "credential")


def _scrub(detail: dict) -> dict:
    out = {}
    for k, v in (detail or {}).items():
        if any(s in k.lower() for s in _SECRETISH):
            out[k] = "[redacted]"
        elif isinstance(v, (dict, list)):
            out[k] = json.loads(json.dumps(v, default=str))
        elif k in ("trace", "exc"):
            out[k] = str(v)[-4000:]   # the end of a traceback is the useful part
        else:
            out[k] = v if isinstance(v, (int, float, bool)) or v is None else str(v)[:1000]
    return out


class EventLog:
    TABLE = "events"

    def __init__(self, store, retention_days: int | None = None):
        self.store = store
        self.retention = retention_days or int(os.getenv("GRCPAL_LOG_RETENTION_DAYS", "90"))
        self._writes = 0
        self._lock = threading.Lock()

    def write(self, level: str, category: str, message: str, actor: str | None = None, **detail) -> dict:
        now = dt.datetime.now(dt.timezone.utc)
        row = {"PartitionKey": f"{now:%Y-%m-%d}", "RowKey": f"{now:%H%M%S%f}-{uuid.uuid4().hex[:6]}",
               "at": now.replace(microsecond=0).isoformat(), "level": level if level in LEVELS else "info",
               "category": category if category in CATEGORIES else "system", "message": message[:500],
               "actor": actor or current_actor.get(), "request_id": request_id.get(), "detail": _scrub(detail)}
        try:
            self.store.insert(self.TABLE, row)
        except Exception:  # noqa: BLE001 - logging must never break the action being logged
            pass
        event(message, {"info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR,
                        "security": logging.WARNING}[row["level"]], category=category, **row["detail"])
        with self._lock:
            self._writes += 1
            prune = self._writes % 200 == 1
        if prune:
            self.prune()
        return row

    def info(self, category, message, **d):
        return self.write("info", category, message, **d)

    def warning(self, category, message, **d):
        return self.write("warning", category, message, **d)

    def error(self, category, message, **d):
        return self.write("error", category, message, **d)

    def security(self, message, **d):
        return self.write("security", "security", message, **d)

    def search(self, q: str = "", level: str = "", category: str = "", days: int = 7, limit: int = 1000,
               today: dt.date | None = None) -> list[dict]:
        today = today or dt.datetime.now(dt.timezone.utc).date()
        rows = []
        for i in range(max(1, min(days, self.retention))):
            rows.extend(self.store.list(self.TABLE, f"{today - dt.timedelta(days=i):%Y-%m-%d}"))
        if level:
            rows = [r for r in rows if r["level"] == level]
        if category:
            rows = [r for r in rows if r["category"] == category]
        if q:
            ql = q.lower()
            rows = [r for r in rows if ql in json.dumps(r, default=str).lower()]
        rows.sort(key=lambda r: (r["PartitionKey"], r["RowKey"]), reverse=True)
        return rows[:limit]

    def prune(self, today: dt.date | None = None) -> int:
        today = today or dt.datetime.now(dt.timezone.utc).date()
        cutoff = f"{today - dt.timedelta(days=self.retention):%Y-%m-%d}"
        removed = 0
        try:
            for r in self.store.list(self.TABLE):
                if r["PartitionKey"] < cutoff:
                    self.store.delete(self.TABLE, r["PartitionKey"], r["RowKey"])
                    removed += 1
        except Exception:  # noqa: BLE001
            pass
        return removed

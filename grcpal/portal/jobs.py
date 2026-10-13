"""Background jobs (collection runs, check runs, AI mock audits) with progress the UI can show.

Jobs run on a small thread pool inside the portal process and record their state in the `jobs` table.
On Azure Container Apps a replica can scale down when nobody is using the portal; the job page refreshes
itself while a job runs, and long jobs (full mock audits) can also run from the command line or the
scheduled job (`grcpal ai audit`, `grcpal collect --all`).
"""
from __future__ import annotations

import datetime as dt
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


class Job:
    def __init__(self, runner, row: dict):
        self._runner, self.id, self.row = runner, row["RowKey"], row

    def progress(self, done: int, total: int, message: str = "") -> None:
        self.row = self._runner.store.update("jobs", "j", self.id, {"done": done, "total": total,
                                                                     "message": message[:300]})

    def log(self, line: str) -> None:
        steps = (self.row.get("steps") or [])[-199:] + [f"{_now()[11:19]} {line[:300]}"]
        self.row = self._runner.store.update("jobs", "j", self.id, {"steps": steps})


class JobRunner:
    def __init__(self, store, events=None, sync: bool = False):
        self.store, self.events, self.sync = store, events, sync
        self._pool = None if sync else ThreadPoolExecutor(max_workers=2, thread_name_prefix="job")

    def submit(self, kind: str, title: str, actor: str, fn, **meta) -> dict:
        row = {"PartitionKey": "j", "RowKey": f"{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:6]}",
               "kind": kind, "title": title[:200], "status": "queued", "by": actor, "created_at": _now(),
               "started_at": "", "finished_at": "", "done": 0, "total": 0, "message": "", "steps": [],
               "result": {}, "meta": "", **{k: str(v) for k, v in meta.items()}}
        self.store.insert("jobs", row)
        job = Job(self, row)
        if self._pool is None:
            self._run(job, fn)
        else:
            self._pool.submit(self._run, job, fn)
        return self.get(row["RowKey"])

    def _run(self, job: Job, fn) -> None:
        self.store.update("jobs", "j", job.id, {"status": "running", "started_at": _now()})
        if self.events:
            self.events.info("job", f"Job started: {job.row['title']}", actor=job.row["by"], job=job.id, kind=job.row["kind"])
        try:
            result = fn(job) or {}
            self.store.update("jobs", "j", job.id, {"status": "done", "finished_at": _now(), "result": result})
            if self.events:
                self.events.info("job", f"Job finished: {job.row['title']}", actor=job.row["by"], job=job.id)
        except Exception as exc:  # noqa: BLE001
            self.store.update("jobs", "j", job.id, {"status": "failed", "finished_at": _now(),
                                                    "message": f"{type(exc).__name__}: {exc}"[:300]})
            if self.events:
                self.events.error("job", f"Job failed: {job.row['title']}", actor=job.row["by"], job=job.id,
                                  error=f"{type(exc).__name__}: {exc}", trace=traceback.format_exc(limit=5))

    def get(self, job_id: str) -> dict | None:
        return self.store.get("jobs", "j", job_id)

    def recent(self, limit: int = 50, kind: str = "") -> list[dict]:
        rows = [r for r in self.store.list("jobs", "j") if not kind or r["kind"] == kind]
        return sorted(rows, key=lambda r: r["RowKey"], reverse=True)[:limit]

    def running(self, kind: str) -> dict | None:
        return next((r for r in self.recent(20, kind) if r["status"] in ("queued", "running")), None)

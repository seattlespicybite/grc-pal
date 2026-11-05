"""Background jobs (collection runs, check runs, AI mock audits) with progress the UI can show.

Jobs run on a small thread pool inside the portal process and record their state in the `jobs` table.
On Azure Container Apps a replica can scale down when nobody is using the portal; the job page refreshes
itself while a job runs, and long jobs (full mock audits) can also run from the command line or the
scheduled job (`grcpal ai audit`, `grcpal collect --all`).

Interrupted jobs (B-042): a replica that is stopped mid-job (scale to zero, restart, update) leaves the row
"running", which used to block new runs of the same kind forever. While a job runs, its runner refreshes
`heartbeat_at` every minute. Any queued or running job whose heartbeat is older than STALE_AFTER is marked
`interrupted` the next time jobs are read (by any replica), with a message saying to start it again.
"""
from __future__ import annotations

import datetime as dt
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor


HEARTBEAT_EVERY = 60  # seconds
STALE_AFTER = dt.timedelta(minutes=10)
INTERRUPTED = ("The portal stopped while this job was running (restart, update or scale down). "
               "Nothing was lost that had already been saved; start the job again.")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _age(row: dict, now: dt.datetime) -> dt.timedelta:
    stamp = row.get("heartbeat_at") or row.get("started_at") or row.get("created_at") or ""
    try:
        return now - dt.datetime.fromisoformat(stamp)
    except (TypeError, ValueError):
        return STALE_AFTER * 2  # no usable time: treat as old


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
        self._active: set[str] = set()
        self._beat: threading.Thread | None = None
        self._guard = threading.Lock()

    def _start_heartbeat(self) -> None:
        with self._guard:
            if self._beat is None or not self._beat.is_alive():
                self._beat = threading.Thread(target=self._heartbeat_loop, name="job-heartbeat", daemon=True)
                self._beat.start()

    def _heartbeat_loop(self) -> None:
        stop = threading.Event()
        while not stop.wait(HEARTBEAT_EVERY):
            self.beat()
            with self._guard:
                if not self._active:
                    self._beat = None
                    return

    def beat(self) -> None:
        """Mark this runner's jobs as alive (called every HEARTBEAT_EVERY seconds while jobs run)."""
        for job_id in list(self._active):
            try:
                self.store.update("jobs", "j", job_id, {"heartbeat_at": _now()})
            except Exception:  # noqa: BLE001 - a missed beat is retried next minute
                pass

    def reap(self, rows: list[dict] | None = None) -> list[dict]:
        """Mark queued/running jobs with an old heartbeat as interrupted. Returns the rows, updated."""
        now = dt.datetime.now(dt.timezone.utc)
        rows = self.store.list("jobs", "j") if rows is None else rows
        out = []
        for r in rows:
            if r.get("status") in ("queued", "running") and r["RowKey"] not in self._active and _age(r, now) > STALE_AFTER:
                r = self.store.update("jobs", "j", r["RowKey"], {"status": "interrupted", "finished_at": _now(),
                                                                "message": INTERRUPTED})
                if self.events:
                    self.events.warning("job", f"Job interrupted: {r.get('title', '')}", actor=r.get("by", ""),
                                        job=r["RowKey"], kind=r.get("kind", ""))
            out.append(r)
        return out

    def submit(self, kind: str, title: str, actor: str, fn, **meta) -> dict:
        row = {"PartitionKey": "j", "RowKey": f"{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:6]}",
               "kind": kind, "title": title[:200], "status": "queued", "by": actor, "created_at": _now(),
               "started_at": "", "finished_at": "", "heartbeat_at": _now(), "done": 0, "total": 0, "message": "", "steps": [],
               "result": {}, "meta": "", **{k: str(v) for k, v in meta.items()}}
        self.store.insert("jobs", row)
        job = Job(self, row)
        if self._pool is None:
            self._run(job, fn)
        else:
            self._active.add(job.id)
            self._start_heartbeat()
            self._pool.submit(self._run, job, fn)
        return self.get(row["RowKey"])

    def _run(self, job: Job, fn) -> None:
        self._active.add(job.id)
        try:
            self._run_inner(job, fn)
        finally:
            self._active.discard(job.id)

    def _run_inner(self, job: Job, fn) -> None:
        self.store.update("jobs", "j", job.id, {"status": "running", "started_at": _now(), "heartbeat_at": _now()})
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
        row = self.store.get("jobs", "j", job_id)
        return self.reap([row])[0] if row else None

    def recent(self, limit: int = 50, kind: str = "") -> list[dict]:
        rows = [r for r in self.reap() if not kind or r["kind"] == kind]
        return sorted(rows, key=lambda r: r["RowKey"], reverse=True)[:limit]

    def running(self, kind: str) -> dict | None:
        return next((r for r in self.recent(20, kind) if r["status"] in ("queued", "running")), None)

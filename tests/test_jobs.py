"""Background jobs left 'running' by a stopped replica are marked interrupted (B-042 / R-05 step 1)."""
from __future__ import annotations

import datetime as dt

from grcpal.portal import jobs as jobs_mod
from grcpal.portal.jobs import JobRunner
from grcpal.portal.store import SqliteStore, TenantStore


def _ago(minutes: int) -> str:
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes)).replace(microsecond=0).isoformat()


def _orphan(store, rk: str, kind: str = "collect", minutes: int = 30, status: str = "running") -> None:
    store.insert("jobs", {"PartitionKey": "j", "RowKey": rk, "kind": kind, "title": "Collect evidence",
                          "status": status, "by": "admin@example.com", "created_at": _ago(minutes + 1),
                          "started_at": _ago(minutes), "finished_at": "", "heartbeat_at": _ago(minutes),
                          "done": 0, "total": 0, "message": "", "steps": [], "result": {}})


class Events:
    def __init__(self):
        self.lines = []

    def info(self, *a, **k):
        self.lines.append(("info", a))

    def warning(self, *a, **k):
        self.lines.append(("warning", a))

    def error(self, *a, **k):
        self.lines.append(("error", a))


def test_orphaned_job_no_longer_blocks_a_new_run(tmp_path):
    store = TenantStore(SqliteStore(str(tmp_path / "j.db")), "acme")
    _orphan(store, "20260101T000000-aaaaaa")
    events = Events()
    runner = JobRunner(store, events, sync=True)  # a new replica after a restart
    assert runner.running("collect") is None
    row = runner.get("20260101T000000-aaaaaa")
    assert row["status"] == "interrupted" and "start the job again" in row["message"]
    assert ("warning", ("job", "Job interrupted: Collect evidence")) in events.lines
    job = runner.submit("collect", "Collect evidence", "admin@example.com", lambda j: {"n": 1})
    assert job["status"] == "done"


def test_a_job_with_a_recent_heartbeat_on_another_replica_is_left_alone(tmp_path):
    store = TenantStore(SqliteStore(str(tmp_path / "j.db")), "acme")
    _orphan(store, "20260101T000000-bbbbbb", minutes=2)
    _orphan(store, "20260101T000000-cccccc", minutes=30, status="queued")
    runner = JobRunner(store, sync=True)
    statuses = {r["RowKey"]: r["status"] for r in runner.recent()}
    assert statuses == {"20260101T000000-bbbbbb": "running", "20260101T000000-cccccc": "interrupted"}
    assert runner.running("collect")["RowKey"] == "20260101T000000-bbbbbb"


def test_running_jobs_send_a_heartbeat(tmp_path, monkeypatch):
    store = TenantStore(SqliteStore(str(tmp_path / "j.db")), "acme")
    runner = JobRunner(store, sync=True)
    seen = {}

    def work(job):
        store.update("jobs", "j", job.id, {"heartbeat_at": _ago(60)})  # pretend an hour passed
        runner.reap()  # its own running job is never reaped
        runner.beat()
        seen.update(store.get("jobs", "j", job.id))
        return {}

    assert runner.submit("collect", "Collect evidence", "admin@example.com", work)["status"] == "done"
    assert seen["status"] == "running"
    assert dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(seen["heartbeat_at"]) < jobs_mod.STALE_AFTER


def test_interrupted_job_page_says_to_start_again():
    from grcpal.portal.routes_extra import job_outcome

    out = job_outcome({"kind": "collect", "status": "interrupted", "message": jobs_mod.INTERRUPTED})
    assert out["ok"] is False and "interrupted" in out["title"] and out["next"] == "Start it again."


def test_heartbeat_thread_runs_while_a_pooled_job_runs(tmp_path, monkeypatch):
    import threading
    import time

    monkeypatch.setattr(jobs_mod, "HEARTBEAT_EVERY", 0.05)
    store = TenantStore(SqliteStore(str(tmp_path / "j.db")), "acme")
    runner = JobRunner(store)
    release = threading.Event()
    job = runner.submit("collect", "Collect evidence", "admin@example.com", lambda j: release.wait(5) and {})
    store.update("jobs", "j", job["RowKey"], {"heartbeat_at": _ago(60)})
    for _ in range(100):
        if _ago(0) <= store.get("jobs", "j", job["RowKey"])["heartbeat_at"]:
            break
        time.sleep(0.02)
    assert runner.get(job["RowKey"])["status"] in ("queued", "running")
    release.set()
    runner._pool.shutdown(wait=True)
    assert runner.get(job["RowKey"])["status"] == "done"

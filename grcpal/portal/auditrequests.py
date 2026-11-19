"""Audit requests: the auditor's request list, worked inside GRC-pal.

During an audit the auditor sends a list of requests ("population of new hires in the period", "evidence of the
access review for Q2") and picks samples. That usually lives in spreadsheets and email. Here each request is a
record with a status, the evidence runs given in answer, a decision by the auditor, comments and any samples drawn.

Statuses: open -> provided (an admin answered) -> accepted or returned (the auditor decided). A returned request
can be answered again. An accepted request is closed.

Who may do what (segregation of duties):
  * an admin or an auditor opens a request, comments and draws a sample;
  * only an admin answers (links evidence runs, with a note);
  * only an auditor accepts or returns: the organization cannot accept its own evidence.
This is the one place where the auditor role writes. Everything else stays read-only for auditors, and an auditor
whose access end date has passed cannot sign in at all.

Samples are reproducible. The population is one CSV file of a stored evidence run. The server draws a random seed
(nobody chooses it), ranks every row by SHA-256("<seed>:<row number>") and takes the first N. The seed, the file's
SHA-256, the row count and the chosen rows are stored as write-once evidence (`audit_sample/`), so anyone can redo
the draw with a few lines of code. Every draw is kept: drawing again does not replace an earlier one.

Nothing here is deleted or edited: answers, decisions, comments and samples are appended to the request's log, and
every action is in the audit log.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import io
import json
import re
import secrets

from grcpal.portal.auth import User
from grcpal.portal.security import csv_cell

STATUSES = {"open": "Open", "provided": "Provided", "returned": "Returned", "accepted": "Accepted"}
STATUS_CSS = {"open": "open", "provided": "pending", "returned": "returned", "accepted": "approved"}
_RID = re.compile(r"^AR-\d{3,5}$")
_REF = re.compile(r"^([A-Za-z0-9_.-]{1,80})/(\d{4}-\d{2}-\d{2}T\d{6}Z)$")
_FILE = re.compile(r"^[A-Za-z0-9_.-]{1,120}\.csv$")
MAX_REFS = 20
MAX_SAMPLE = 200
MAX_POPULATION_BYTES = 10 * 1024 * 1024
MAX_POPULATION_ROWS = 100_000
SAMPLE_METHOD = ("Rows are numbered from 1 in file order (the header is not a row). Each row is ranked by the "
                 "hexadecimal SHA-256 of the text '<seed>:<row number>'; the N lowest are the sample.")


def draw(seed: str, rows: int, size: int) -> list[int]:
    """The sample for a seed: row numbers (1-based), in file order. Pure and repeatable."""
    ranked = sorted(range(1, rows + 1), key=lambda n: hashlib.sha256(f"{seed}:{n}".encode()).hexdigest())
    return sorted(ranked[:size])


class AuditRequestsMixin:
    def _ar_reader(self, actor: User) -> None:
        if not actor.sees_everything:
            raise self._forbidden("Only admins and auditors can see audit requests")

    def _ar_row(self, rid: str) -> dict:
        row = self.store.get("auditrequests", "r", rid) if _RID.match(rid or "") else None
        if not row:
            raise self._invalid("Audit request not found")
        return row

    def _ar_log(self, rid: str, actor: User, kind: str, text: str = "", **extra) -> dict:
        from grcpal.portal.service import _now

        # time-ordered key with a random tail: two people writing at the same moment never collide
        key = f"{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%S%f}-{secrets.token_hex(3)}"
        entry = {"PartitionKey": rid, "RowKey": key, "kind": kind, "by": actor.email, "role": actor.role,
                 "at": _now(), "text": (text or "")[:4000], **extra}
        self.store.insert("auditrequestlog", entry)
        return entry

    def _ar_view(self, r: dict) -> dict:
        today = self.today.isoformat()
        return {**r, "id": r["RowKey"], "status_label": STATUSES[r["status"]], "status_css": STATUS_CSS[r["status"]],
                "overdue": bool(r.get("due")) and r["due"] < today and r["status"] in ("open", "returned")}

    # ------------------------------------------------------------------ reading
    def audit_requests(self, actor: User, cycle: str = "") -> list[dict]:
        self._ar_reader(actor)
        rows = [self._ar_view(r) for r in self.store.list("auditrequests", "r") if not cycle or r["cycle"] == cycle]
        return sorted(rows, key=lambda r: r["id"])

    def audit_request(self, actor: User, rid: str) -> dict:
        self._ar_reader(actor)
        r = self._ar_view(self._ar_row(rid))
        r["log"] = sorted(self.store.list("auditrequestlog", rid), key=lambda e: e["RowKey"])
        return r

    def audit_request_summary(self, rows: list[dict]) -> dict:
        counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES}
        return {"counts": counts, "total": len(rows), "overdue": sum(1 for r in rows if r["overdue"])}

    def audit_requests_csv(self, actor: User, cycle: str = "") -> bytes:
        cols = ("id", "cycle", "title", "description", "controls", "due", "status", "created_by", "created_at",
                "answered_by", "answered_at", "evidence", "decided_by", "decided_at", "decision_note")
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in self.audit_requests(actor, cycle):
            w.writerow({k: csv_cell(" ".join(r[k]) if isinstance(r.get(k), list) else r.get(k, "")) for k in cols})
        return buf.getvalue().encode()

    def audit_request_log_rows(self, cycle: str = "") -> list[dict]:
        """Every log entry of the cycle's requests, for the auditor export."""
        out = []
        for r in sorted(self.store.list("auditrequests", "r"), key=lambda r: r["RowKey"]):
            if cycle and r["cycle"] != cycle:
                continue
            for e in sorted(self.store.list("auditrequestlog", r["RowKey"]), key=lambda e: e["RowKey"]):
                out.append({"request": r["RowKey"], "seq": e["RowKey"], **{k: v for k, v in e.items()
                                                                           if k not in ("PartitionKey", "RowKey")}})
        return out

    # ------------------------------------------------------------------ writing
    def create_audit_request(self, actor: User, title: str, description: str = "", controls: str = "",
                             due: str = "") -> dict:
        self._ar_reader(actor)  # an admin or an auditor
        title, description = (title or "").strip(), (description or "").strip()
        if len(title) < 5:
            raise self._invalid("Give the request a title of at least 5 characters")
        ids = sorted({c for c in re.split(r"[\s,;]+", (controls or "").strip()) if c})
        unknown = [c for c in ids if not self.catalog.control(c)]
        if unknown:
            raise self._invalid(f"Unknown control: {', '.join(unknown[:5])}")
        if due:
            try:
                due = dt.date.fromisoformat(due.strip()).isoformat()
            except ValueError as exc:
                raise self._invalid("The due date must be YYYY-MM-DD") from exc
        from grcpal.portal.service import _now

        nums = [int(r["RowKey"][3:]) for r in self.store.list("auditrequests", "r") if _RID.match(r["RowKey"])]
        rid = f"AR-{max(nums, default=0) + 1:03d}"
        row = {"PartitionKey": "r", "RowKey": rid, "cycle": self.active_cycle()["RowKey"], "title": title[:200],
               "description": description[:4000], "controls": ids, "due": due or "", "status": "open",
               "created_by": actor.email, "created_role": actor.role, "created_at": _now(), "answered_by": "",
               "answered_at": "", "evidence": [], "decided_by": "", "decided_at": "", "decision_note": ""}
        self.store.insert("auditrequests", row)
        self._ar_log(rid, actor, "created", title[:200])
        self.audit(actor, "audit_request.create", rid, {"controls": ids, "title": title[:200], "due": row["due"]})
        return self._ar_view(row)

    def _evidence_refs(self, text: str) -> list[str]:
        refs = []
        for line in re.split(r"[\s,;]+", (text or "").strip()):
            if not line:
                continue
            m = _REF.match(line)
            if not m or m.group(2) not in self.evidence.list_runs(m.group(1)):
                raise self._invalid(f"'{line[:100]}' is not a stored evidence run (write it as source/run, "
                                    "as shown on the Evidence store page)")
            if line not in refs:
                refs.append(line)
        if len(refs) > MAX_REFS:
            raise self._invalid(f"Link at most {MAX_REFS} evidence runs in one answer")
        return refs

    def answer_audit_request(self, actor: User, rid: str, note: str, evidence: str = "") -> dict:
        """An admin answers: a note and the evidence runs that hold the answer. Status becomes provided."""
        if not actor.is_admin:
            raise self._forbidden("Only admins answer audit requests")
        r = self._ar_row(rid)
        if r["status"] == "accepted":
            raise self._invalid("This request is accepted and closed")
        note = (note or "").strip()
        if len(note) < 10:
            raise self._invalid("Say what you are providing (at least 10 characters)")
        refs = self._evidence_refs(evidence)
        from grcpal.portal.service import _now

        merged = list(r.get("evidence") or []) + [x for x in refs if x not in (r.get("evidence") or [])]
        row = self.store.update("auditrequests", "r", rid, {"status": "provided", "answered_by": actor.email,
                                                             "answered_at": _now(), "evidence": merged})
        self._ar_log(rid, actor, "answered", note, evidence=refs)
        self.audit(actor, "audit_request.answer", rid, {"controls": r.get("controls") or [], "evidence": refs})
        return self._ar_view(row)

    def decide_audit_request(self, actor: User, rid: str, decision: str, note: str = "") -> dict:
        """The auditor accepts the answer or returns it. Admins cannot: nobody accepts their own evidence."""
        if not actor.is_auditor:
            raise self._forbidden("Only an auditor accepts or returns an audit request")
        r = self._ar_row(rid)
        if decision not in ("accept", "return"):
            raise self._invalid("Choose accept or return")
        if r["status"] != "provided":
            raise self._invalid("Only a request with an answer waiting can be accepted or returned")
        note = (note or "").strip()
        if decision == "return" and len(note) < 10:
            raise self._invalid("Say what is missing (at least 10 characters)")
        from grcpal.portal.service import _now

        status = "accepted" if decision == "accept" else "returned"
        row = self.store.update("auditrequests", "r", rid, {"status": status, "decided_by": actor.email,
                                                             "decided_at": _now(), "decision_note": note[:4000]})
        self._ar_log(rid, actor, status, note)
        self.audit(actor, f"audit_request.{decision}", rid, {"controls": r.get("controls") or [], "note": note[:500]})
        return self._ar_view(row)

    def comment_audit_request(self, actor: User, rid: str, text: str) -> dict:
        self._ar_reader(actor)
        r = self._ar_row(rid)
        text = (text or "").strip()
        if len(text) < 2:
            raise self._invalid("Write a comment")
        entry = self._ar_log(rid, actor, "comment", text)
        self.audit(actor, "audit_request.comment", rid, {"controls": r.get("controls") or []})
        return entry

    def sample_audit_request(self, actor: User, rid: str, population: str, filename: str, size) -> dict:
        """Draw a reproducible random sample from one CSV file of a stored evidence run and attach it."""
        self._ar_reader(actor)
        r = self._ar_row(rid)
        if r["status"] == "accepted":
            raise self._invalid("This request is accepted and closed")
        m = _REF.match((population or "").strip())
        filename = (filename or "").strip()
        if not m or not _FILE.match(filename) or m.group(2) not in self.evidence.list_runs(m.group(1)):
            raise self._invalid("Choose a stored evidence run (source/run) and a .csv file in it")
        source, run = m.group(1), m.group(2)
        # Read through the evidence store (this organization's namespace only), not through the list of built-in
        # sources: a population can come from any stored source, such as an external tool's output.
        raw = self.evidence.read(source, run, "manifest.json")
        try:
            manifest_files = {f["name"]: f for f in (json.loads(raw) if raw else {}).get("files") or []}
        except (ValueError, TypeError, KeyError) as exc:
            raise self._invalid("That evidence run has no readable manifest") from exc
        data = self.evidence.read(source, run, filename) if filename in manifest_files else None
        if data is None:
            raise self._invalid(f"{filename} is not a file of {source}/{run}")
        if len(data) > MAX_POPULATION_BYTES:
            raise self._invalid("The population file is too large to sample here (over 10 MB)")
        digest = hashlib.sha256(data).hexdigest()
        if digest != manifest_files[filename].get("sha256"):
            raise self._invalid("The population file does not match its recorded SHA-256; it cannot be sampled")
        try:
            rows = list(csv.DictReader(io.StringIO(data.decode("utf-8-sig"))))
        except (UnicodeDecodeError, csv.Error) as exc:
            raise self._invalid("The population file is not a readable CSV") from exc
        if not rows or len(rows) > MAX_POPULATION_ROWS:
            raise self._invalid("The population file has no rows, or more than 100,000")
        try:
            size = int(size)
        except (TypeError, ValueError) as exc:
            raise self._invalid("The sample size must be a number") from exc
        if not 1 <= size <= min(len(rows), MAX_SAMPLE):
            raise self._invalid(f"The sample size must be between 1 and {min(len(rows), MAX_SAMPLE)}")
        seed = secrets.token_hex(16)
        picked = draw(seed, len(rows), size)
        sample = {"request": rid, "population": {"source": source, "run": run, "file": filename, "sha256": digest,
                                                 "rows": len(rows)},
                  "seed": seed, "size": size, "method": SAMPLE_METHOD, "row_numbers": picked,
                  "drawn_by": actor.email, "drawn_role": actor.role}
        ev = self.evidence.new_run("audit_sample", r.get("controls") or [], {"request": rid, "drawn_by": actor.email})
        ev.add("sample", sample)
        ev.add("selected_rows", [{"row_number": n, **rows[n - 1]} for n in picked])
        ev.finish([])
        self.store.update("auditrequests", "r", rid, {"evidence": list(r.get("evidence") or []) + [ev.prefix]})
        self._ar_log(rid, actor, "sample", f"{size} of {len(rows)} rows from {source}/{run}/{filename}",
                     evidence=[ev.prefix], seed=seed)
        self.audit(actor, "audit_request.sample", rid, {"controls": r.get("controls") or [], "run": ev.prefix,
                                                        "population": f"{source}/{run}/{filename}", "rows": len(rows),
                                                        "size": size, "seed": seed})
        return {**sample, "run": ev.prefix}

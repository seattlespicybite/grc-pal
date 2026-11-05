"""Risk register (SOC 2 CC3.1–CC3.4, CC9.1; controls RSK-01, RSK-02).

Plain model:
- The register lives in the portal. An admin can copy in the starter `registers/risks.yaml` (add only; nothing is
  overwritten), then keeps it here.
- Each risk: title, description, category (fraud is its own category, for CC3.3), owner, likelihood × impact before
  controls (inherent) and after them (residual), treatment (mitigate, accept, transfer, avoid), the controls that
  treat it, status (open, closed) and the next review date.
  * mitigate needs at least one control;
  * accept needs a justification, the admin who accepts it and an expiry date (accepted risks are re-decided);
  * residual can never be higher than inherent.
- Every change keeps the previous state as a write-once version (`riskversions`) with a reason, so the register's
  history answers "what did the risk look like on the audit date".
- Once a year (or after a significant change) an admin approves the risk assessment: the whole register is stored
  write-once in the evidence store (CSV + JSON, SHA-256) as RSK-01 evidence, and the approval is recorded.
- Admins change it; auditors read everything and export it. Control owners do not see it.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import io
import json
import re

from grcpal.portal.security import csv_cell

CONTROLS = ["RSK-01"]
CATEGORIES = {"security": "Security", "availability": "Availability", "confidentiality": "Confidentiality",
              "processing_integrity": "Processing integrity", "privacy": "Privacy", "fraud": "Fraud",
              "vendor": "Vendor / third party", "compliance": "Legal and compliance", "operational": "Operational"}
TREATMENTS = {"mitigate": "Mitigate (controls)", "accept": "Accept", "transfer": "Transfer (insurance, contract)",
              "avoid": "Avoid (stop the activity)"}
STATUSES = {"open": "Open", "closed": "Closed"}
LEVELS = {1: "Rare", 2: "Unlikely", 3: "Possible", 4: "Likely", 5: "Almost certain"}
IMPACTS = {1: "Minimal", 2: "Minor", 3: "Moderate", 4: "Major", 5: "Severe"}
REVIEW_MONTHS = 12
_RID = re.compile(r"^R-\d{3,5}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
FIELDS = ("title", "description", "category", "owner", "likelihood", "impact", "residual_likelihood",
          "residual_impact", "treatment", "controls", "status", "next_review", "acceptance_note", "accepted_by",
          "acceptance_expires")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def band(score: int) -> str:
    """Rating used for colour and sorting: 1-4 low, 5-9 medium, 10-16 high, 20-25 critical."""
    return "critical" if score >= 20 else "high" if score >= 10 else "medium" if score >= 5 else "low"


class RisksMixin:
    # ------------------------------------------------------------------ reading
    def _risk_reader(self, user) -> None:
        if not user.sees_everything:
            raise self._forbidden("Only admins and auditors can see the risk register")

    def _risk_row(self, rid: str) -> dict:
        row = self.store.get("risks", "r", rid) if _RID.match(rid or "") else None
        if not row:
            raise self._invalid("Risk not found")
        return row

    def _risk_view(self, r: dict, status: dict | None = None) -> dict:
        score, residual = r["likelihood"] * r["impact"], r["residual_likelihood"] * r["residual_impact"]
        today = self.today.isoformat()
        out = {**r, "id": r["RowKey"], "score": score, "band": band(score), "residual_score": residual,
               "residual_band": band(residual),
               "review_due": r["status"] == "open" and bool(r.get("next_review")) and r["next_review"] < today,
               "acceptance_expired": r["treatment"] == "accept" and bool(r.get("acceptance_expires"))
               and r["acceptance_expires"] < today}
        if status is not None:
            out["control_status"] = [{"id": c, "status": status.get(c, "not_started")} for c in r.get("controls") or []]
        return out

    def risks(self, user, status: dict | None = None) -> list[dict]:
        self._risk_reader(user)
        rows = [self._risk_view(r, status) for r in self.store.list("risks", "r")]
        return sorted(rows, key=lambda r: (r["status"] != "open", -r["residual_score"], -r["score"], r["id"]))

    def risk(self, user, rid: str, status: dict | None = None) -> dict:
        self._risk_reader(user)
        r = self._risk_view(self._risk_row(rid), status)
        r["versions"] = sorted(self.store.list("riskversions", rid), key=lambda v: v["RowKey"], reverse=True)
        return r

    def risk_heatmap(self, rows: list[dict], residual: bool = False) -> list[list[list[str]]]:
        """5×5 grid [impact 5..1][likelihood 1..5] -> risk IDs (open risks only)."""
        grid = [[[] for _ in range(5)] for _ in range(5)]
        for r in rows:
            if r["status"] != "open":
                continue
            lk, im = (r["residual_likelihood"], r["residual_impact"]) if residual else (r["likelihood"], r["impact"])
            grid[5 - im][lk - 1].append(r["id"])
        return grid

    def risk_summary(self, user) -> dict:
        rows = self.risks(user)
        approvals = sorted(self.store.list("riskapprovals", "a"), key=lambda a: a["RowKey"], reverse=True)
        last = approvals[0] if approvals else None
        due = ""
        if last:
            d = dt.date.fromisoformat(last["at"][:10])
            due = d.replace(year=d.year + 1).isoformat() if not (d.month == 2 and d.day == 29) else f"{d.year + 1}-02-28"
        opened = [r for r in rows if r["status"] == "open"]
        return {"total": len(rows), "open": len(opened),
                "by_band": {b: sum(1 for r in opened if r["residual_band"] == b) for b in ("critical", "high", "medium", "low")},
                "fraud": sum(1 for r in opened if r["category"] == "fraud"),
                "review_due": sum(1 for r in opened if r["review_due"]),
                "acceptance_expired": sum(1 for r in opened if r["acceptance_expired"]),
                "last_approval": last, "approval_due": due,
                "approval_overdue": bool(due and due < self.today.isoformat()), "approvals": approvals[:10]}

    # ------------------------------------------------------------------ writing
    def _risk_clean(self, form: dict, actor) -> dict:
        def num(key, default=None):
            raw = str(form.get(key, default if default is not None else "")).strip()
            if not raw.isdigit() or not 1 <= int(raw) <= 5:
                raise self._invalid("Likelihood and impact are 1 (low) to 5 (high)")
            return int(raw)

        title = str(form.get("title", "")).strip()
        if not 5 <= len(title) <= 200:
            raise self._invalid("Give the risk a title (5 to 200 characters) that says what could happen")
        category = str(form.get("category", "")).strip()
        if category not in CATEGORIES:
            raise self._invalid("Choose a category")
        treatment = str(form.get("treatment", "")).strip()
        if treatment not in TREATMENTS:
            raise self._invalid("Choose a treatment")
        status = str(form.get("status", "open")).strip() or "open"
        if status not in STATUSES:
            raise self._invalid("Status is open or closed")
        lk, im = num("likelihood"), num("impact")
        rlk = num("residual_likelihood", lk) if str(form.get("residual_likelihood", "")).strip() else lk
        rim = num("residual_impact", im) if str(form.get("residual_impact", "")).strip() else im
        if rlk * rim > lk * im:
            raise self._invalid("The residual score (after controls) cannot be higher than the inherent score")
        raw_controls = form.get("controls", [])
        if isinstance(raw_controls, str):
            raw_controls = re.split(r"[,;\s]+", raw_controls)
        controls = sorted({str(c).strip().upper() for c in raw_controls if str(c).strip()})
        unknown = [c for c in controls if not self.catalog.control(c)]
        if unknown:
            raise self._invalid(f"Unknown control{'s' if len(unknown) != 1 else ''}: {', '.join(unknown)}")
        if treatment == "mitigate" and status == "open" and not controls:
            raise self._invalid("A mitigated risk needs at least one control that treats it")
        next_review = str(form.get("next_review", "")).strip()
        if next_review and not _DATE.match(next_review):
            raise self._invalid("Next review must be a date (YYYY-MM-DD)")
        owner = str(form.get("owner", "")).strip()[:120]
        if not owner:
            raise self._invalid("Name the risk owner (a person's email or a role)")
        out = {"title": title, "description": str(form.get("description", "")).strip()[:2000], "category": category,
               "owner": owner, "likelihood": lk, "impact": im, "residual_likelihood": rlk, "residual_impact": rim,
               "treatment": treatment, "controls": controls, "status": status,
               "next_review": next_review or self._risk_default_review(),
               "acceptance_note": "", "accepted_by": "", "acceptance_expires": ""}
        if treatment == "accept" and status == "open":
            note = str(form.get("acceptance_note", "")).strip()[:1000]
            expires = str(form.get("acceptance_expires", "")).strip()
            if len(note) < 20:
                raise self._invalid("Say why the risk is accepted (at least 20 characters)")
            if not _DATE.match(expires) or expires <= self.today.isoformat():
                raise self._invalid("An accepted risk needs a future date when the acceptance is decided again")
            out.update(acceptance_note=note, accepted_by=actor.email, acceptance_expires=expires)
        return out

    def _risk_default_review(self) -> str:
        d = self.today
        return dt.date(d.year + 1, d.month, min(d.day, 28)).isoformat()

    def _risk_version(self, rid: str, row: dict, actor_email: str, reason: str, action: str) -> None:
        snap = {k: row.get(k) for k in FIELDS}
        key = f"{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%S%f}"
        self.store.insert("riskversions", {"PartitionKey": rid, "RowKey": key, "action": action, "by": actor_email,
                                           "at": _now(), "reason": reason[:500], "snapshot": snap})

    def _next_risk_id(self) -> str:
        nums = [int(r["RowKey"][2:]) for r in self.store.list("risks", "r") if _RID.match(r["RowKey"])]
        return f"R-{(max(nums) + 1) if nums else 1:03d}"

    def create_risk(self, actor, form: dict) -> dict:
        self._admin(actor)
        fields = self._risk_clean(form, actor)
        rid = self._next_risk_id()
        row = {"PartitionKey": "r", "RowKey": rid, **fields, "created_by": actor.email, "created_at": _now(),
               "updated_by": actor.email, "updated_at": _now(), "last_reviewed": "", "source": "portal"}
        self.store.insert("risks", row)
        self._risk_version(rid, row, actor.email, "Created", "create")
        self.audit(actor, "risk.create", rid, {"controls": CONTROLS, "score": fields["likelihood"] * fields["impact"],
                                               "treatment": fields["treatment"], "category": fields["category"]})
        return row

    def update_risk(self, actor, rid: str, form: dict, reason: str) -> dict:
        self._admin(actor)
        old = self._risk_row(rid)
        reason = (reason or "").strip()
        if len(reason) < 5:
            raise self._invalid("Say why the risk changed (kept in its history)")
        fields = self._risk_clean(form, actor)
        if old.get("treatment") == "accept" and fields["treatment"] == "accept" and \
                old.get("acceptance_note") == fields["acceptance_note"] and old.get("acceptance_expires") == fields["acceptance_expires"]:
            fields["accepted_by"] = old.get("accepted_by", actor.email)   # unchanged acceptance keeps its approver
        changed = sorted(k for k in FIELDS if old.get(k) != fields.get(k))
        if not changed:
            return old
        row = self.store.update("risks", "r", rid, {**fields, "updated_by": actor.email, "updated_at": _now()})
        self._risk_version(rid, row, actor.email, reason, "update")
        self.audit(actor, "risk.update", rid, {"controls": CONTROLS, "changed": changed, "reason": reason[:300],
                                               "score": [old["likelihood"] * old["impact"], fields["likelihood"] * fields["impact"]],
                                               "residual": [old["residual_likelihood"] * old["residual_impact"],
                                                            fields["residual_likelihood"] * fields["residual_impact"]]})
        return row

    def review_risk(self, actor, rid: str, note: str) -> dict:
        """The owner or an admin looked at the risk and it still stands: record it and set the next review."""
        self._admin(actor)
        row = self._risk_row(rid)
        note = (note or "").strip()
        if len(note) < 5:
            raise self._invalid("Write what you checked, for example 'controls still effective, no new incidents'")
        row = self.store.update("risks", "r", rid, {"last_reviewed": self.today.isoformat(),
                                                    "next_review": self._risk_default_review(),
                                                    "updated_by": actor.email, "updated_at": _now()})
        self._risk_version(rid, row, actor.email, f"Reviewed: {note}", "review")
        self.audit(actor, "risk.review", rid, {"controls": CONTROLS, "note": note[:300]})
        return row

    # ------------------------------------------------------------------ import and approval
    def risk_import_preview(self) -> list[dict]:
        have = {str(r.get("legacy_id") or r["RowKey"]) for r in self.store.list("risks", "r")}
        return [r for r in (self.catalog.risks or []) if isinstance(r, dict) and r.get("id") and str(r["id"]) not in have]

    def import_risks(self, actor) -> list[dict]:
        """Copy risks from registers/risks.yaml that are not in the register yet (add only)."""
        self._admin(actor)
        added = []
        for src in self.risk_import_preview():
            role = str(src.get("owner") or "")
            emails = self.role_emails(role) if role else []
            owner = emails[0] if emails else role
            cat = str(src.get("category") or "security")
            title = str(src.get("title") or "")
            form = {"title": title if len(title) >= 5 else f"{title} (imported)", "category": cat if cat in CATEGORIES else "security",
                    "description": str(src.get("description") or ""), "owner": owner or "security-lead",
                    "likelihood": str(src.get("likelihood") or 3), "impact": str(src.get("impact") or 3),
                    "treatment": src.get("treatment") if src.get("treatment") in TREATMENTS else "mitigate",
                    "controls": [c for c in src.get("controls") or [] if self.catalog.control(str(c))]}
            if form["treatment"] == "accept":   # the YAML has no acceptance details: re-decide in the portal
                form["treatment"] = "mitigate"
            if form["treatment"] == "mitigate" and not form["controls"]:
                form["status"] = "closed"
            fields = self._risk_clean(form, actor)
            rid = str(src["id"]) if _RID.match(str(src["id"])) and not self.store.get("risks", "r", str(src["id"])) \
                else self._next_risk_id()
            row = {"PartitionKey": "r", "RowKey": rid, **fields, "created_by": actor.email, "created_at": _now(),
                   "updated_by": actor.email, "updated_at": _now(), "last_reviewed": "", "source": "registers/risks.yaml",
                   "legacy_id": str(src["id"])}
            self.store.insert("risks", row)
            self._risk_version(rid, row, actor.email, "Imported from registers/risks.yaml", "import")
            added.append(row)
        path = self.catalog.base / "registers/risks.yaml"
        sha = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""
        self.audit(actor, "risk.import", "registers/risks.yaml", {"controls": CONTROLS, "added": [r["RowKey"] for r in added],
                                                                   "sha256": sha})
        return added

    def risk_csv(self, user, rows: list[dict] | None = None) -> bytes:
        rows = rows if rows is not None else self.risks(user)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "title", "category", "owner", "likelihood", "impact", "score", "rating", "treatment",
                    "controls", "residual_likelihood", "residual_impact", "residual_score", "residual_rating", "status",
                    "next_review", "last_reviewed", "acceptance_note", "accepted_by", "acceptance_expires", "updated_at"])
        for r in rows:
            w.writerow([csv_cell(x) for x in (
                r["id"], r["title"], CATEGORIES.get(r["category"], r["category"]), r["owner"], r["likelihood"], r["impact"],
                r["score"], r["band"], r["treatment"], " ".join(r.get("controls") or []), r["residual_likelihood"],
                r["residual_impact"], r["residual_score"], r["residual_band"], r["status"], r.get("next_review", ""),
                r.get("last_reviewed", ""), r.get("acceptance_note", ""), r.get("accepted_by", ""),
                r.get("acceptance_expires", ""), r.get("updated_at", ""))])
        return buf.getvalue().encode("utf-8")

    def export_risks(self, user) -> bytes:
        data = self.risk_csv(user)
        self.audit(user, "risk.export", "risks.csv", {"controls": CONTROLS, "rows": data.count(b"\n") - 1})
        return data

    def approve_risk_assessment(self, actor, note: str) -> dict:
        """Approve the risk assessment as it stands: store the whole register write-once as evidence."""
        self._admin(actor)
        note = (note or "").strip()
        if len(note) < 10:
            raise self._invalid("Write what was reviewed, for example 'Annual assessment with the CTO and VP, 2026'")
        rows = self.risks(actor)
        if not any(r["status"] == "open" for r in rows):
            raise self._invalid("The register has no open risks to approve")
        problems = [r["id"] for r in rows if r["status"] == "open" and r["acceptance_expired"]]
        if problems:
            raise self._invalid(f"Decide the expired acceptances first: {', '.join(problems)}")
        data = self.risk_csv(actor, rows)
        sha = hashlib.sha256(data).hexdigest()
        run = self.evidence.new_run("risk_assessment", CONTROLS, {"approved_by": actor.email, "risks": len(rows),
                                                                  "note": note[:500]})
        taken = set(self.evidence.list_runs("risk_assessment"))
        while run.prefix.split("/", 1)[1] in taken:
            run.started += dt.timedelta(seconds=1)
        run.add_bytes("risk_register.csv", data)
        run.add_bytes("risk_register.json", json.dumps([{k: r.get(k) for k in ("id", *FIELDS)} for r in rows],
                                                       indent=1, sort_keys=True).encode())
        run.add("approval", {"approved_by": actor.email, "at": _now(), "note": note, "sha256": sha,
                             "open": sum(1 for r in rows if r["status"] == "open")})
        run.finish([])
        key = f"{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%S%f}"
        row = {"PartitionKey": "a", "RowKey": key, "by": actor.email, "at": _now(), "note": note[:500],
               "risks": len(rows), "sha256": sha, "evidence_run": run.prefix}
        self.store.insert("riskapprovals", row)
        self.audit(actor, "risk.assessment_approved", "risk_register", {"controls": CONTROLS, "risks": len(rows),
                                                                       "sha256": sha, "evidence": run.prefix})
        return row

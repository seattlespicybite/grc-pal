"""Vendor management for SOC 2 CC9.2: the vendor register, contacts, the annual review, onboarding and
offboarding checks, CUEC mapping and the vendor security questionnaire.

Plain model:
- The register lives in the portal. Vendors in `registers/vendors.yaml` are copied in when an admin clicks
  Import (only names not already in the register; nothing is overwritten). Every change keeps the
  previous version (`vendorversions`) and is written to the hash-chained audit log.
- Who sees what: admins see and change everything. A Control owner sees only vendors where they are the
  internal owner or backup, and can update contact and support notes, upload files and answer the review
  questions. Auditors see every vendor read-only, but never contact details (names, emails, phones, links):
  those are removed on the server, left out of the auditor export, and contact changes are logged without
  their values.
- Each vendor gets one review a year. The tier decides what the review needs, not how often.
  New vendors start with an onboarding check, which an admin approves before data is shared. Offboarding
  is a checklist (sign-in removed, keys revoked, data returned or deleted, contract ended).
- A review is signed off by an admin who did not submit it, unless they are the only active admin
  (then the review is marked self-approved for the auditor). Approved reviews never change.
- Vendor files (reports, questionnaires, deletion letters) are stored write-once in the evidence store and
  are only downloadable by admins, auditors and that vendor's owners. They are not sent to AI.
- The questionnaire is edited as a draft; saving makes a new numbered version. Old versions never change,
  and each review records which version was sent.
"""
from __future__ import annotations

import calendar as _cal
import datetime as dt
import hashlib
import json
import re
import uuid

TIERS = {"critical": "Critical", "high": "High", "moderate": "Moderate", "low": "Low"}
STATUSES = {"onboarding": "Onboarding", "active": "Active", "offboarding": "Offboarding",
            "offboarded": "Offboarded", "rejected": "Not approved"}
DATA_ACCESS = ["Customer data", "Employee data", "Source code", "Credentials or secrets", "Financial data",
               "Production systems", "No company data"]
SUBSERVICE = {"no": "No", "carved_out": "Yes, carved out", "inclusive": "Yes, inclusive"}
ASSURANCE = {"": "Not recorded", "soc2_type2": "SOC 2 Type 2", "soc2_type1": "SOC 2 Type 1",
             "iso27001": "ISO 27001 certificate", "questionnaire": "Our questionnaire only", "other": "Other report",
             "none": "None"}
# Report result: what the vendor's own auditor concluded. Stored keys keep the formal terms
# (unqualified, qualified, adverse, disclaimer) so exports and older data stay readable.
OPINIONS = {"": "Not reviewed", "unqualified": "Clean", "qualified": "With exceptions",
            "adverse": "Unfavorable", "disclaimer": "No conclusion", "na": "Not applicable"}
# "unknown" shows as an empty choice: nobody has checked the contract yet.
CONTRACT = {"unknown": "", "yes": "Yes", "partial": "Partly", "no": "No", "na": "Not applicable"}
FILE_KINDS = {"report": "SOC 2 report or certificate", "bridge": "Bridge letter", "questionnaire": "Returned questionnaire",
              "contract": "Contract or DPA", "offboarding": "Offboarding evidence", "other": "Other"}
FILE_CONTROLS = {"report": ["VEN-02"], "bridge": ["VEN-02"], "questionnaire": ["VEN-02"], "contract": ["VEN-03"],
                 "offboarding": ["VEN-05"], "other": ["VEN-02"]}
CUEC_STATUS = {"not_mapped": "Not mapped", "met": "Met", "not_applicable": "Not applicable"}
REVIEW_KINDS = {"onboarding": "Onboarding check", "annual": "Annual review", "offboarding": "Offboarding"}
REVIEW_STATUSES = {"open": "Open", "submitted": "Waiting for sign-off", "returned": "Returned to owner",
                   "approved": "Signed off"}
OPEN_REVIEW = ("open", "submitted", "returned")
QUESTIONS = [  # the owner's plain review questions
    ("covers_service", "Does the report or questionnaire cover the service we use?", ["yes", "no", "unsure"]),
    ("exceptions", "Did the vendor's auditor note any exceptions?", ["no", "yes", "unsure", "na"]),
    ("concerns", "Are any of the vendor's questionnaire answers a concern?", ["no", "yes", "na"]),
    ("data_change", "Has what we share with this vendor changed this year?", ["no", "yes"]),
]
ANSWER_LABELS = {"yes": "Yes", "no": "No", "unsure": "Not sure", "na": "Not applicable"}
CHECKLISTS = {
    "onboarding": [("risk", "Tier, data access and internal owner are set"),
                   ("assurance", "A SOC 2 report, certificate or our returned questionnaire is attached"),
                   ("contract", "The contract has security, confidentiality and breach-notice terms")],
    "offboarding": [("access", "Sign-in removed (SSO app, user accounts)"),
                    ("keys", "API keys, tokens and service accounts revoked"),
                    ("data", "Our data returned or deleted, with the vendor's confirmation"),
                    ("contract", "Contract ended and billing stopped")],
}
# Contact details: hidden from auditors and the auditor export; changes are logged without values.
CONTACT_FIELDS = ("owner_name", "owner_title", "owner_email", "owner_phone", "backup_name", "backup_title",
                  "backup_email", "ext_name", "ext_title", "ext_email", "ext_phone", "support_text", "support_url",
                  "docs_text", "docs_url")
OWNER_LOCKED = ("owner_email", "backup_email")  # grant access to the vendor, so only admins change them
AUDITOR_KEEPS = ("owner_title",)                # auditors see that an owner exists (by title), not who
DETAIL_FIELDS = ("name", "service", "tier", "data_access", "subservice", "contract_terms", "dpa", "contract_note",
                 "assurance", "period_start", "period_end", "opinion", "start_date", "notes", "next_review_override")
RESERVED = {"new", "import", "questionnaire", "export"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,59}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
LIMITS = {"name": 120, "service": 200, "contract_note": 300, "notes": 2000, "support_text": 2000, "docs_text": 2000,
          "support_url": 500, "docs_url": 500, "owner_name": 120, "owner_title": 120, "owner_phone": 40,
          "backup_name": 120, "backup_title": 120, "ext_name": 120, "ext_title": 120, "ext_phone": 40,
          "owner_email": 254, "backup_email": 254, "ext_email": 254}
REVIEW_MONTHS, DUE_SOON_DAYS, MAX_CUECS, MAX_EXCEPTIONS = 12, 30, 60, 40
LIST_BYTES = 16000  # CUECs and exceptions are copied into snapshots; an Azure Table text property holds 32K characters
# Questionnaire limits keep one version inside an Azure Table text property (64 KB, about 32K characters).
Q_TYPES = {"yesno": "Yes / No / N/A", "text": "Text"}
Q_TEXT, Q_GUIDE, Q_TITLE, Q_INTRO, Q_MAX, S_MAX, Q_BYTES = 500, 400, 120, 2000, 200, 30, 30000
Q_ID_RE = re.compile(r"^[QS]-\d{3,4}$")
YES_NO = ["Yes", "No", "N/A"]


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def add_months(day: str, months: int) -> str:
    d = dt.date.fromisoformat(day)
    y, m = divmod(d.month - 1 + months, 12)
    year, month = d.year + y, m + 1
    return dt.date(year, month, min(d.day, _cal.monthrange(year, month)[1])).isoformat()


def slug(text: str) -> str:
    """Short id from a name; text in brackets is dropped ("Microsoft (Azure, M365)" -> "microsoft")."""
    s = re.sub(r"[^a-z0-9]+", "-", re.sub(r"\(.*?\)", "", text or "").lower()).strip("-")
    return (s or "vendor")[:50].strip("-")


def safe_url(url: str) -> str:
    """Only https:// links are kept, so a saved link can never run script (javascript:) or open a local file."""
    url = (url or "").strip()
    if not url:
        return ""
    if not url.lower().startswith("https://") or any(ord(c) < 33 or c in "<>\"'\\" for c in url) or len(url) > 500:
        raise ValueError("Links must start with https:// and contain no spaces or quotes")
    return url


class VendorsMixin:
    """Vendor logic for the Portal. Every write checks the role here and is audited."""

    # ================================================================ access
    def _is_vendor_owner(self, user, v: dict) -> bool:
        return user.is_contributor and user.email in {(v.get("owner_email") or "").lower(),
                                                      (v.get("backup_email") or "").lower()} - {""}

    def can_see_vendor(self, user, v: dict) -> bool:
        return user.sees_everything or self._is_vendor_owner(user, v)

    def can_work_vendor(self, user, v: dict) -> bool:
        """Upload files, answer review questions, update contacts and checklist notes."""
        return user.is_admin or self._is_vendor_owner(user, v)

    def _redact(self, user, v: dict) -> dict:
        if not user.is_auditor:
            return v
        out = {k: val for k, val in v.items() if k not in CONTACT_FIELDS or k in AUDITOR_KEEPS}
        out["owner_set"] = bool(v.get("owner_email") or v.get("owner_name"))
        return out

    def _vendor_row(self, vid: str) -> dict | None:
        return self.store.get("vendors", "v", vid) if ID_RE.match(vid or "") else None

    def vendor(self, user, vid: str) -> dict:
        """One vendor as this user may see it. Not visible and not found look the same (404)."""
        v = self._vendor_row(vid)
        if not v or not self.can_see_vendor(user, v):
            raise self._invalid("Vendor not found")
        return self._vendor_view(self._redact(user, v))

    def vendors(self, user) -> list[dict]:
        rows = [self._vendor_view(self._redact(user, v)) for v in self.store.list("vendors", "v")
                if self.can_see_vendor(user, v)]
        order = {"bad": 0, "warn": 1, "info": 2, "ok": 3, "idle": 4}
        return sorted(rows, key=lambda v: (order[v["health"][0]], v["next_review"] or "9999", v["name"].lower()))

    # ================================================================ computed state
    def _next_review(self, v: dict) -> str:
        if v.get("status") != "active":
            return ""
        if v.get("next_review_override"):
            return v["next_review_override"]
        return add_months(v["last_review"], REVIEW_MONTHS) if v.get("last_review") else self.today.isoformat()

    def _vendor_view(self, v: dict) -> dict:
        v = dict(v)
        v["next_review"] = self._next_review(v)
        open_r = self.open_review(v["RowKey"])
        v["open_review"] = open_r
        today = self.today.isoformat()
        days = (dt.date.fromisoformat(v["next_review"]) - self.today).days if v["next_review"] else None
        v["due_in"] = days
        status = v.get("status", "active")
        if status == "onboarding":
            health = ("info", "Onboarding check open")
        elif status == "offboarding":
            health = ("info", "Offboarding open")
        elif status in ("offboarded", "rejected"):
            health = ("idle", STATUSES[status])
        elif open_r and open_r["status"] == "submitted":
            health = ("info", "Waiting for sign-off")
        elif not v.get("last_review"):
            health = ("warn", "Never reviewed")
        elif v["next_review"] < today:
            health = ("bad", "Annual review overdue")
        elif days is not None and days <= DUE_SOON_DAYS:
            health = ("warn", "Annual review due soon")
        elif any(c.get("status") == "not_mapped" for c in v.get("cuecs") or []):
            health = ("warn", "CUECs not mapped")
        else:
            health = ("ok", "Current")
        v["health"] = health
        v["needs"] = self.tier_needs(v.get("tier", "moderate"))
        return v

    @staticmethod
    def tier_needs(tier: str) -> list[tuple[str, str]]:
        """What a review needs for a tier: (item, requirement)."""
        return {
            "critical": [("Assurance report", "SOC 2 Type 2 or ISO 27001"), ("Our questionnaire", "Required"),
                         ("CUEC mapping", "Required for SOC 2 reports"), ("Contract terms", "Required")],
            "high": [("Assurance report", "SOC 2 or ISO 27001"), ("Our questionnaire", "Required"),
                     ("CUEC mapping", "Required for SOC 2 reports"), ("Contract terms", "Required")],
            "moderate": [("Assurance report", "Report, certificate or our questionnaire"),
                         ("Our questionnaire", "If there is no report"), ("CUEC mapping", "If a SOC 2 report is used"),
                         ("Contract terms", "Required")],
            "low": [("Assurance report", "Not required"), ("Our questionnaire", "Not required"),
                    ("CUEC mapping", "Not required"), ("Contract terms", "NDA or standard terms")],
        }.get(tier, [])

    # ================================================================ create, edit, import
    def _clean_vendor(self, form: dict, fields, current: dict | None = None) -> dict:
        Invalid = self._invalid
        out = {}
        for key in fields:
            if key not in form:
                continue
            val = form[key]
            if key == "data_access":
                vals = [x for x in (val or []) if x in DATA_ACCESS]
                out[key] = vals
                continue
            val = str(val if val is not None else "").strip()
            if key in LIMITS and len(val) > LIMITS[key]:
                raise Invalid(f"{key.replace('_', ' ').capitalize()} is too long (limit {LIMITS[key]} characters)")
            if key == "name" and not val:
                raise Invalid("Give the vendor a name")
            if key == "tier" and val not in TIERS:
                raise Invalid("Choose a tier")
            if key == "subservice" and val not in SUBSERVICE:
                raise Invalid("Choose whether the vendor is a subservice organization")
            if key == "assurance" and val not in ASSURANCE:
                raise Invalid("Choose the type of assurance report")
            if key == "opinion" and val not in OPINIONS:
                raise Invalid("Choose the report result")
            if key in ("contract_terms", "dpa") and val not in CONTRACT:
                raise Invalid("Choose Yes, Partly, No, Not applicable or leave the contract answer empty")
            if key in ("period_start", "period_end", "start_date", "next_review_override") and val:
                if not DATE_RE.match(val):
                    raise Invalid("Dates must look like 2026-12-31")
                try:
                    dt.date.fromisoformat(val)
                except ValueError as exc:
                    raise Invalid(f"{val} is not a real date") from exc
            if key in ("owner_email", "backup_email", "ext_email") and val:
                val = val.lower()
                if not self._email_ok(val):
                    raise Invalid(f"'{val}' is not a valid email address")
            if key in ("support_url", "docs_url"):
                try:
                    val = safe_url(val)
                except ValueError as exc:
                    raise Invalid(str(exc)) from exc
            out[key] = val
        start, end = out.get("period_start", (current or {}).get("period_start")), out.get("period_end", (current or {}).get("period_end"))
        if start and end and start > end:
            raise Invalid("The report period must start before it ends")
        return out

    def _save_version(self, v: dict, by: str, reason: str) -> None:
        snap = {k: val for k, val in v.items() if k not in ("PartitionKey", "RowKey")}
        self.store.insert("vendorversions", {"PartitionKey": v["RowKey"], "RowKey": f"{int(v['version']):06d}",
                                             "snapshot": snap, "by": by, "at": _now(), "reason": reason[:500]})

    def _audit_changes(self, actor, action: str, vid: str, before: dict, after: dict, reason: str) -> list[str]:
        changed = [k for k in after if before.get(k) != after[k]]
        detail = {"changed": changed, "reason": reason[:300]}
        plain = [k for k in changed if k not in CONTACT_FIELDS and k not in ("notes",)]
        if plain:
            detail["before"] = {k: before.get(k) for k in plain}
            detail["after"] = {k: after[k] for k in plain}
        self.audit(actor, action, vid, detail)
        return changed

    def create_vendor(self, actor, form: dict) -> dict:
        """Admins add vendors; Control owners request them. Either way a vendor starts in Onboarding."""
        if not actor.can_write:
            raise self._forbidden("Auditors cannot add vendors")
        fields = DETAIL_FIELDS + CONTACT_FIELDS if actor.is_admin else (
            ("name", "service", "tier", "data_access", "notes") + tuple(f for f in CONTACT_FIELDS if f not in OWNER_LOCKED))
        clean = self._clean_vendor({"tier": "moderate", "subservice": "no", **form}, fields)
        if not actor.is_admin:  # the requester owns what they asked for until an admin changes it
            clean["owner_email"] = actor.email
            clean.setdefault("owner_name", actor.name)
        base = slug(clean["name"])
        vid, n = (base if base not in RESERVED else f"{base}-vendor"), 2
        if any(v.get("name", "").lower() == clean["name"].lower() for v in self.store.list("vendors", "v")):
            raise self._invalid(f"{clean['name']} is already in the register")
        while self.store.get("vendors", "v", vid):
            vid, n = f"{base}-{n}", n + 1
        now = _now()
        row = {"PartitionKey": "v", "RowKey": vid, "status": "onboarding", "subservice": "no", "data_access": [],
               "contract_terms": "unknown", "dpa": "unknown", "assurance": "", "opinion": "", "cuecs": [],
               "last_review": "", "approved_at": "", "end_date": "", "legacy": {}, "version": 1,
               "created_by": actor.email, "created_at": now, "updated_by": actor.email, "updated_at": now, **clean}
        self.store.insert("vendors", row)
        self._save_version(row, actor.email, "Added" if actor.is_admin else "Requested")
        self.audit(actor, "vendor.create" if actor.is_admin else "vendor.request", vid,
                   {"controls": ["VEN-01"], "name": row["name"], "tier": row.get("tier"), "status": "onboarding"})
        self._open_review(actor, vid, "onboarding")
        if not actor.is_admin:
            self._notify("vendor", self.active_emails("admin"), actor, self._vendor_mail(
                row, f"New vendor request: {row['name']}", f"{actor.name} asked to add {row['name']}. "
                "It stays in Onboarding until an admin approves it."), ["VEN-01"])
        return row

    def update_vendor(self, actor, vid: str, form: dict, reason: str) -> dict:
        """Admins change vendor details. A reason is required; the previous version is kept."""
        self._admin(actor)
        v = self._vendor_row(vid)
        if not v:
            raise self._invalid("Vendor not found")
        reason = (reason or "").strip()
        if not reason:
            raise self._invalid("Say why you are changing this vendor (kept in the history for the auditor)")
        clean = self._clean_vendor(form, DETAIL_FIELDS + CONTACT_FIELDS, v)
        if clean.get("name") and clean["name"].lower() != v["name"].lower() and any(
                x.get("name", "").lower() == clean["name"].lower() for x in self.store.list("vendors", "v")):
            raise self._invalid(f"{clean['name']} is already in the register")
        if not [k for k in clean if v.get(k) != clean[k]]:
            return v
        clean.update(version=int(v.get("version", 1)) + 1, updated_by=actor.email, updated_at=_now())
        before = dict(v)
        v = self.store.update("vendors", "v", vid, clean)
        self._save_version(v, actor.email, reason)
        self._audit_changes(actor, "vendor.update", vid, before, {k: clean[k] for k in clean if k not in
                                                                  ("version", "updated_by", "updated_at")}, reason)
        return v

    def update_vendor_contacts(self, actor, vid: str, form: dict) -> dict:
        """Internal owner, backup, vendor contact and support notes. Owners edit their own vendors' contacts,
        except who the owner and backup are (that grants access, so admins decide)."""
        v = self._vendor_row(vid)
        if not v or not self.can_see_vendor(actor, v):
            raise self._invalid("Vendor not found")
        if not self.can_work_vendor(actor, v):
            raise self._forbidden("Only admins and this vendor's owners can change its contacts")
        fields = CONTACT_FIELDS if actor.is_admin else tuple(f for f in CONTACT_FIELDS if f not in OWNER_LOCKED)
        clean = self._clean_vendor(form, fields)
        if not [k for k in clean if v.get(k, "") != clean[k]]:
            return v
        clean.update(version=int(v.get("version", 1)) + 1, updated_by=actor.email, updated_at=_now())
        before = dict(v)
        v = self.store.update("vendors", "v", vid, clean)
        self._save_version(v, actor.email, "Contacts updated")
        self._audit_changes(actor, "vendor.contacts.update", vid, before,
                            {k: clean[k] for k in clean if k in CONTACT_FIELDS}, "Contacts updated")
        return v

    def vendor_versions(self, user, vid: str) -> list[dict]:
        v = self.vendor(user, vid)
        rows = sorted(self.store.list("vendorversions", v["RowKey"]), key=lambda r: r["RowKey"], reverse=True)
        if user.is_auditor:
            rows = [{**r, "snapshot": {k: x for k, x in r["snapshot"].items() if k not in CONTACT_FIELDS}} for r in rows]
        return rows

    def vendor_history(self, user, vid: str) -> list[dict]:
        """Audit log entries for this vendor, newest first. Auditors see the same entries (they hold no
        contact values)."""
        self.vendor(user, vid)
        return [r for r in reversed(self.log.records()) if r.get("target") == vid
                and str(r.get("action", "")).startswith(("vendor.", "questionnaire.sent"))][:200]

    # ---------------------------------------------------------------- import from registers/vendors.yaml
    def vendor_import_preview(self) -> list[dict]:
        names = {v.get("name", "").lower() for v in self.store.list("vendors", "v")}
        return [r for r in (self.catalog.vendors or []) if isinstance(r, dict) and r.get("name")
                and str(r["name"]).strip().lower() not in names]

    def import_vendors(self, actor) -> list[dict]:
        """Copy vendors from registers/vendors.yaml that are not in the register yet. Nothing is overwritten.
        Every original field is kept in `legacy`, so no data is lost."""
        self._admin(actor)
        roles = self.catalog.roles or {}
        added = []
        for src in self.vendor_import_preview():
            name = str(src["name"]).strip()[:120]
            role = roles.get(str(src.get("owner") or ""), {}) or {}
            email = str(role.get("email") or "").strip().lower()
            person = str(role.get("person") or "").strip()
            tokens = [t.strip().lower() for t in str(src.get("data_access") or "").split(",") if t.strip()]
            access = [d for d in DATA_ACCESS if any(t and (t in d.lower() or d.lower().startswith(t.split()[0]))
                                                    for t in tokens)]
            report = str(src.get("soc2_report_date") or "")
            terms = src.get("contract_security_terms")
            row = {"PartitionKey": "v", "RowKey": "", "name": name, "service": str(src.get("service") or "")[:200],
                   "tier": src.get("tier") if src.get("tier") in TIERS else "moderate", "data_access": access,
                   "status": "active", "subservice": "carved_out" if src.get("subservice_org") else "no",
                   "contract_terms": "yes" if terms is True else ("unknown" if terms in (None, "") else "partial"),
                   "dpa": "unknown", "contract_note": "" if terms in (None, True, False) else str(terms)[:300],
                   "assurance": "soc2_type2" if DATE_RE.match(report) else "", "period_start": "",
                   "period_end": report if DATE_RE.match(report) else "", "opinion": "", "start_date": "",
                   "next_review_override": str(src.get("next_review") or "") if DATE_RE.match(str(src.get("next_review") or "")) else "",
                   "notes": "Imported from registers/vendors.yaml." + (" Marked 'confirm' there: check these details."
                                                                       if src.get("confirm") else ""),
                   "owner_name": person if person and person != "TBD" else "",
                   "owner_title": str(role.get("title") or src.get("owner") or "")[:120],
                   "owner_email": email if self._email_ok(email) else "",
                   "cuecs": [], "last_review": "", "approved_at": "", "end_date": "",
                   "legacy": json.loads(json.dumps(src, default=str)), "version": 1,
                   "created_by": actor.email, "created_at": _now(), "updated_by": actor.email, "updated_at": _now()}
            base, n = slug(name), 2
            vid = base if base not in RESERVED else f"{base}-vendor"
            while self.store.get("vendors", "v", vid):
                vid, n = f"{base}-{n}", n + 1
            row["RowKey"] = vid
            self.store.insert("vendors", row)
            self._save_version(row, actor.email, "Imported from registers/vendors.yaml")
            added.append(row)
        path = self.catalog.base / "registers/vendors.yaml"
        sha = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""
        self.audit(actor, "vendor.import", "registers/vendors.yaml",
                   {"controls": ["VEN-01"], "added": [r["RowKey"] for r in added], "sha256": sha})
        return added

    # ================================================================ reviews
    def vendor_reviews(self, vid: str) -> list[dict]:
        return sorted(self.store.list("vendorreviews", vid), key=lambda r: r["RowKey"], reverse=True)

    def open_review(self, vid: str) -> dict | None:
        return next((r for r in self.vendor_reviews(vid) if r["status"] in OPEN_REVIEW), None)

    def _review(self, vid: str, rid: str) -> dict:
        r = self.store.get("vendorreviews", vid, rid) if re.match(r"^[0-9a-z-]{1,40}$", rid or "") else None
        if not r:
            raise self._invalid("Review not found")
        return r

    def _open_review(self, actor, vid: str, kind: str) -> dict:
        rid = f"{len(self.store.list('vendorreviews', vid)) + 1:04d}-{uuid.uuid4().hex[:6]}"  # sorts in order
        row = {"PartitionKey": vid, "RowKey": rid, "kind": kind, "status": "open", "opened_by": actor.email,
               "opened_at": _now(), "answers": {}, "file_ids": [], "exceptions": [],
               "checklist": [{"key": k, "label": label, "done": False, "note": "", "by": "", "at": ""}
                             for k, label in CHECKLISTS.get(kind, [])],
               "questionnaire_version": 0, "questionnaire_sent_at": "", "submitted_by": "", "submitted_at": "",
               "approved_by": "", "approved_at": "", "self_approved": False, "decision_note": "",
               "accepted_gaps": [], "snapshot": {}, "returned_note": ""}
        self.store.insert("vendorreviews", row)
        self.audit(actor, "vendor.review.start", vid, {"controls": ["VEN-01", "VEN-02"], "review": rid, "kind": kind})
        return row

    def _work_review(self, actor, vid: str) -> tuple[dict, dict]:
        v = self._vendor_row(vid)
        if not v or not self.can_see_vendor(actor, v):
            raise self._invalid("Vendor not found")
        if not self.can_work_vendor(actor, v):
            raise self._forbidden("Only admins and this vendor's owners can work on its review")
        r = self.open_review(vid)
        if not r:
            raise self._invalid("There is no open review for this vendor. Start the annual review first.")
        return v, r

    def start_annual_review(self, actor, vid: str) -> dict:
        v = self._vendor_row(vid)
        if not v or not self.can_see_vendor(actor, v):
            raise self._invalid("Vendor not found")
        if not self.can_work_vendor(actor, v):
            raise self._forbidden("Only admins and this vendor's owners can start a review")
        if v.get("status") != "active":
            raise self._invalid("Only active vendors get an annual review")
        if self.open_review(vid):
            raise self._invalid("This vendor already has an open review")
        return self._open_review(actor, vid, "annual")

    def add_vendor_file(self, actor, vid: str, filename: str, data: bytes, kind: str, comment: str) -> dict:
        """Store a vendor file write-once and attach it to the open review (starting the annual review for an
        active vendor that has none)."""
        from grcpal.portal.security import safe_filename, validate_upload

        v = self._vendor_row(vid)
        if not v or not self.can_see_vendor(actor, v):
            raise self._invalid("Vendor not found")
        if not self.can_work_vendor(actor, v):
            raise self._forbidden("Only admins and this vendor's owners can upload files for it")
        if kind not in FILE_KINDS:
            raise self._invalid("Say what the file is")
        r = self.open_review(vid)
        if not r:
            if v.get("status") != "active":
                raise self._invalid("This vendor has no open review")
            r = self._open_review(actor, vid, "annual")
        if r["status"] == "submitted" and not actor.is_admin:
            raise self._invalid("The review is waiting for sign-off. Ask an admin to return it if you need to add files.")
        name = safe_filename(filename)
        error = validate_upload(name, data)
        if error:
            raise self._invalid(error)
        controls = FILE_CONTROLS[kind]
        run = self.evidence.new_run("vendor_upload", controls, {
            "uploaded_by": actor.email, "vendor": vid, "review": r["RowKey"], "kind": kind,
            "comment": (comment or "")[:2000]})
        run.add_bytes(name, data)
        manifest = run.finish([])
        fid = uuid.uuid4().hex
        row = {"PartitionKey": vid, "RowKey": fid, "review": r["RowKey"], "kind": kind, "filename": name,
               "evidence_run": run.prefix, "sha256": manifest["files"][0]["sha256"], "size": len(data),
               "comment": (comment or "").strip()[:2000], "uploaded_by": actor.email, "uploaded_at": _now()}
        self.store.insert("vendorfiles", row)
        self.store.update("vendorreviews", vid, r["RowKey"], {"file_ids": (r.get("file_ids") or []) + [fid]})
        self.audit(actor, "vendor.file.upload", vid, {"controls": controls, "review": r["RowKey"], "kind": kind,
                                                      "file": name, "sha256": row["sha256"], "run": run.prefix})
        return row

    def vendor_files(self, user, vid: str) -> list[dict]:
        self.vendor(user, vid)
        return sorted(self.store.list("vendorfiles", vid), key=lambda f: f["uploaded_at"], reverse=True)

    def vendor_file(self, user, vid: str, fid: str) -> tuple[str, bytes]:
        self.vendor(user, vid)
        f = self.store.get("vendorfiles", vid, fid) if re.match(r"^[0-9a-f]{32}$", fid or "") else None
        if not f:
            raise self._invalid("File not found")
        source, run = f["evidence_run"].split("/", 1)
        data = self.evidence.read(source, run, f["filename"])
        if data is None:
            raise self._invalid("File not found in evidence storage")
        if not user.is_admin:
            self.audit(user, "vendor.file.download", vid, {"file": f["filename"], "sha256": f["sha256"]})
        return f["filename"], data

    def save_review_answers(self, actor, vid: str, answers: dict, submit: bool) -> dict:
        v, r = self._work_review(actor, vid)
        if r["kind"] != "annual":
            raise self._invalid("These questions belong to the annual review")
        if r["status"] == "submitted" and not actor.is_admin:
            raise self._invalid("The review is already waiting for sign-off")
        clean = {}
        for key, _label, options in QUESTIONS:
            val = str(answers.get(key, "") or "")
            if val and val not in options:
                raise self._invalid("Choose one of the answers offered")
            if val:
                clean[key] = val
        fields = {"answers": clean}
        if submit:
            if len(clean) < len(QUESTIONS):
                raise self._invalid("Answer every question before you mark your part done")
            if v.get("tier") != "low" and not r.get("file_ids"):
                raise self._invalid("Upload the vendor's report or the returned questionnaire first")
            fields.update(status="submitted", submitted_by=actor.email, submitted_at=_now(), returned_note="")
        self.store.update("vendorreviews", vid, r["RowKey"], fields)
        self.audit(actor, "vendor.review.submit" if submit else "vendor.review.answers", vid,
                   {"controls": ["VEN-02"], "review": r["RowKey"], "answers": clean})
        if submit:
            self._notify("vendor", self.active_emails("admin"), actor, self._vendor_mail(
                v, f"Vendor review ready for sign-off: {v['name']}",
                f"{actor.name} finished their part of the annual review of {v['name']}."), ["VEN-02"])
        return self._review(vid, r["RowKey"])

    def add_review_exception(self, actor, vid: str, text: str, impact: str, response: str) -> dict:
        self._admin(actor)
        v, r = self._work_review(actor, vid)
        text, impact, response = (text or "").strip()[:500], (impact or "").strip()[:500], (response or "").strip()[:1000]
        if not text or not response:
            raise self._invalid("Describe the exception and how we handle it")
        items = list(r.get("exceptions") or [])
        if len(items) >= MAX_EXCEPTIONS:
            raise self._invalid("Too many exceptions on one review")
        items.append({"id": uuid.uuid4().hex[:8], "text": text, "impact": impact, "response": response,
                      "by": actor.email, "at": _now()})
        if len(json.dumps(items)) > LIST_BYTES:
            raise self._invalid("The exceptions on this review are too long. Shorten them or summarise similar ones.")
        self.store.update("vendorreviews", vid, r["RowKey"], {"exceptions": items})
        self.audit(actor, "vendor.review.exception", vid, {"controls": ["VEN-02"], "review": r["RowKey"],
                                                           "exception": text[:200], "response": response[:200]})
        return items[-1]

    def remove_review_exception(self, actor, vid: str, xid: str) -> None:
        self._admin(actor)
        _v, r = self._work_review(actor, vid)
        items = [x for x in r.get("exceptions") or [] if x["id"] != xid]
        if len(items) == len(r.get("exceptions") or []):
            raise self._invalid("Exception not found")
        self.store.update("vendorreviews", vid, r["RowKey"], {"exceptions": items})
        self.audit(actor, "vendor.review.exception.remove", vid, {"review": r["RowKey"], "exception": xid})

    def update_checklist(self, actor, vid: str, key: str, done: bool, note: str) -> dict:
        v, r = self._work_review(actor, vid)
        if r["kind"] not in CHECKLISTS:
            raise self._invalid("This review has no checklist")
        note = (note or "").strip()[:1000]
        if done and not note:
            raise self._invalid("Say how this was done (for example: app removed in Entra on 2026-10-15)")
        items = r.get("checklist") or []
        if key not in {i["key"] for i in items}:
            raise self._invalid("Unknown checklist item")
        items = [{**i, "done": bool(done), "note": note, "by": actor.email, "at": _now()} if i["key"] == key else i
                 for i in items]
        self.store.update("vendorreviews", vid, r["RowKey"], {"checklist": items})
        self.audit(actor, "vendor.checklist", vid, {"controls": ["VEN-05"] if r["kind"] == "offboarding" else ["VEN-01"],
                                                     "review": r["RowKey"], "item": key, "done": bool(done),
                                                     "note": note[:300]})
        return self._review(vid, r["RowKey"])

    # ---------------------------------------------------------------- CUECs
    def save_cuec(self, actor, vid: str, cid: str, form: dict) -> dict:
        """Add or change one CUEC (complementary user entity control) and how we meet it."""
        self._admin(actor)
        v = self._vendor_row(vid)
        if not v:
            raise self._invalid("Vendor not found")
        text = str(form.get("text", "")).strip()[:600]
        how = str(form.get("how", "")).strip()[:1000]
        status = str(form.get("status", "not_mapped"))
        controls = [c for c in (form.get("controls") or []) if c]
        if not text:
            raise self._invalid("Copy the CUEC text from the vendor's report")
        if status not in CUEC_STATUS:
            raise self._invalid("Choose a status")
        unknown = [c for c in controls if not self.catalog.control(c)]
        if unknown:
            raise self._invalid(f"Unknown control: {', '.join(unknown)}")
        if status == "met" and not (controls and how):
            raise self._invalid("To mark a CUEC as met, pick our control and say how we meet it")
        cuecs = list(v.get("cuecs") or [])
        item = {"id": cid if cid != "new" else uuid.uuid4().hex[:8], "text": text, "controls": controls[:10],
                "how": how, "status": status, "by": actor.email, "at": _now()}
        if cid == "new":
            if len(cuecs) >= MAX_CUECS:
                raise self._invalid("Too many CUECs for one vendor")
            cuecs.append(item)
        elif any(c["id"] == cid for c in cuecs):
            cuecs = [item if c["id"] == cid else c for c in cuecs]
        else:
            raise self._invalid("CUEC not found")
        if len(json.dumps(cuecs)) > LIST_BYTES:
            raise self._invalid("The CUEC list is too long. Shorten the text or combine similar CUECs.")
        v2 = self.store.update("vendors", "v", vid, {"cuecs": cuecs, "version": int(v.get("version", 1)) + 1,
                                                     "updated_by": actor.email, "updated_at": _now()})
        self._save_version(v2, actor.email, "CUEC mapping changed")
        self.audit(actor, "vendor.cuec.update", vid, {"controls": ["VEN-02"] + controls, "cuec": item["id"],
                                                      "status": status, "text": text[:200]})
        return item

    def remove_cuec(self, actor, vid: str, cid: str) -> None:
        self._admin(actor)
        v = self._vendor_row(vid)
        if not v:
            raise self._invalid("Vendor not found")
        cuecs = [c for c in v.get("cuecs") or [] if c["id"] != cid]
        if len(cuecs) == len(v.get("cuecs") or []):
            raise self._invalid("CUEC not found")
        v2 = self.store.update("vendors", "v", vid, {"cuecs": cuecs, "version": int(v.get("version", 1)) + 1,
                                                     "updated_by": actor.email, "updated_at": _now()})
        self._save_version(v2, actor.email, "CUEC removed")
        self.audit(actor, "vendor.cuec.remove", vid, {"controls": ["VEN-02"], "cuec": cid})

    # ---------------------------------------------------------------- sign-off
    def review_gaps(self, v: dict, r: dict) -> list[str]:
        """What the tier needs that this review does not have yet."""
        gaps = []
        files = [f for f in self.store.list("vendorfiles", v["RowKey"]) if f["RowKey"] in (r.get("file_ids") or [])]
        kinds = {f["kind"] for f in files}
        tier = v.get("tier", "moderate")
        if r["kind"] in CHECKLISTS:
            gaps += [f"Checklist: {i['label']}" for i in r.get("checklist") or [] if not i.get("done")]
            if r["kind"] == "offboarding" and not files:
                gaps.append("No offboarding evidence uploaded")
            if r["kind"] == "onboarding":
                if not v.get("tier") or not v.get("data_access") or not v.get("owner_email"):
                    gaps.append("Tier, data access or internal owner email is missing")
                if tier != "low" and not kinds & {"report", "questionnaire"}:
                    gaps.append("No SOC 2 report, certificate or returned questionnaire attached")
            return gaps
        soc2 = (v.get("assurance") or "").startswith("soc2")
        if tier in ("critical", "high"):
            if "report" not in kinds:
                gaps.append("No SOC 2 report or ISO certificate attached to this review")
            if "questionnaire" not in kinds:
                gaps.append("Our questionnaire was not returned")
        elif tier == "moderate" and not kinds & {"report", "questionnaire"}:
            gaps.append("No report, certificate or returned questionnaire attached")
        if tier in ("critical", "high") and soc2:
            if not v.get("cuecs"):
                gaps.append("No CUECs recorded from the SOC 2 report")
        if any(c.get("status") == "not_mapped" for c in v.get("cuecs") or []):
            gaps.append("Some CUECs are not mapped to our controls")
        if v.get("contract_terms") != "yes":
            gaps.append("Contract security terms are not confirmed")
        if soc2 or v.get("assurance") == "iso27001":
            if not v.get("period_end"):
                gaps.append("Report period end date is not recorded")
            elif v["period_end"] < add_months(self.today.isoformat(), -12):
                gaps.append("The report period ended more than 12 months ago; ask for a newer report or a bridge letter")
        if len(r.get("answers") or {}) < len(QUESTIONS):
            gaps.append("The owner's review questions are not all answered")
        return gaps

    def decide_review(self, actor, vid: str, decision: str, note: str) -> dict:
        """Sign off (approve) or return the open review. Approving with gaps needs a note explaining why
        they are accepted. Approved reviews are frozen with a snapshot of the vendor."""
        self._admin(actor)
        v = self._vendor_row(vid)
        if not v:
            raise self._invalid("Vendor not found")
        r = self.open_review(vid)
        if not r:
            raise self._invalid("There is no open review")
        note = (note or "").strip()[:2000]
        if decision == "return":
            if not note:
                raise self._invalid("Say what is missing so the owner can fix it")
            self.store.update("vendorreviews", vid, r["RowKey"], {"status": "returned", "returned_note": note})
            self.audit(actor, "vendor.review.return", vid, {"controls": ["VEN-02"], "review": r["RowKey"], "note": note[:300]})
            people = {v.get("owner_email"), v.get("backup_email"), r.get("submitted_by")} - {"", None}
            self._notify("vendor", people, actor, self._vendor_mail(
                v, f"Vendor review returned: {v['name']}", f"{actor.name} returned the review: {note}"), ["VEN-02"])
            return self._review(vid, r["RowKey"])
        if decision not in ("approve", "reject"):
            raise self._invalid("Choose sign off or return")
        if decision == "reject" and r["kind"] != "onboarding":
            raise self._invalid("Only a new vendor can be rejected; use offboarding for an existing one")
        others = [e for e in self.active_emails("admin") if e != actor.email]
        submitter = r.get("submitted_by") or r.get("opened_by")
        if submitter == actor.email and others:
            raise self._forbidden("Another admin must sign off a review you submitted (segregation of duties)")
        gaps = self.review_gaps(v, r) if decision == "approve" else []
        if gaps and not note:
            raise self._invalid("This review has open items. Write why they are accepted, or return it to the owner.")
        today = self.today.isoformat()
        snap = {k: x for k, x in v.items() if k not in ("PartitionKey", "RowKey", "legacy") and k not in CONTACT_FIELDS}
        snap["owner_title"] = v.get("owner_title", "")
        self.store.update("vendorreviews", vid, r["RowKey"], {
            "status": "approved", "approved_by": actor.email, "approved_at": _now(), "decision": decision,
            "self_approved": submitter == actor.email, "decision_note": note, "accepted_gaps": gaps, "snapshot": snap})
        updates = {"version": int(v.get("version", 1)) + 1, "updated_by": actor.email, "updated_at": _now()}
        if decision == "reject":
            updates.update(status="rejected", end_date=today)
        elif r["kind"] == "onboarding":
            updates.update(status="active", approved_at=_now(), last_review=today, next_review_override="")
        elif r["kind"] == "annual":
            updates.update(last_review=today, next_review_override="")
        else:
            updates.update(status="offboarded", end_date=today)
        v2 = self.store.update("vendors", "v", vid, updates)
        self._save_version(v2, actor.email, f"{REVIEW_KINDS[r['kind']]} {'rejected' if decision == 'reject' else 'signed off'}")
        self.audit(actor, "vendor.review.approve" if decision == "approve" else "vendor.reject", vid,
                   {"controls": ["VEN-05"] if r["kind"] == "offboarding" else ["VEN-01", "VEN-02"],
                    "review": r["RowKey"], "kind": r["kind"], "gaps": gaps, "self_approved": submitter == actor.email,
                    "status": updates.get("status", v.get("status"))})
        people = {v.get("owner_email"), v.get("backup_email")} - {"", None}
        self._notify("vendor", people, actor, self._vendor_mail(
            v, f"{REVIEW_KINDS[r['kind']]} {'not approved' if decision == 'reject' else 'signed off'}: {v['name']}",
            f"{actor.name} {'did not approve' if decision == 'reject' else 'signed off'} the {REVIEW_KINDS[r['kind']].lower()}."
            + (f" Note: {note}" if note else "")), ["VEN-02"])
        return self._review(vid, r["RowKey"])

    def start_offboarding(self, actor, vid: str, reason: str) -> dict:
        self._admin(actor)
        v = self._vendor_row(vid)
        if not v:
            raise self._invalid("Vendor not found")
        if v.get("status") != "active":
            raise self._invalid("Only an active vendor can be offboarded")
        reason = (reason or "").strip()[:500]
        if not reason:
            raise self._invalid("Say why the vendor is being offboarded")
        r = self.open_review(vid)
        if r:  # an unfinished annual review is closed without sign-off; it stays in the history
            self.store.update("vendorreviews", vid, r["RowKey"], {"status": "approved", "decision": "superseded",
                                                                  "approved_by": actor.email, "approved_at": _now(),
                                                                  "decision_note": "Closed: vendor is being offboarded"})
        v2 = self.store.update("vendors", "v", vid, {"status": "offboarding", "version": int(v.get("version", 1)) + 1,
                                                     "updated_by": actor.email, "updated_at": _now()})
        self._save_version(v2, actor.email, f"Offboarding started: {reason}")
        self.audit(actor, "vendor.offboard.start", vid, {"controls": ["VEN-05"], "reason": reason})
        return self._open_review(actor, vid, "offboarding")

    # ================================================================ questionnaire
    def _q_starter(self) -> dict:
        from grcpal.catalog import load_yaml

        path = self.catalog.base / "catalog/vendor_questionnaire.yaml"
        if not path.exists():
            from grcpal.catalog import STARTER
            path = STARTER / "catalog/vendor_questionnaire.yaml"
        data = load_yaml(path.read_text(encoding="utf-8")) if path.exists() else {}
        sections = [{"id": s["id"], "title": str(s.get("title", ""))[:Q_TITLE],
                     "questions": [{"id": q["id"], "text": str(q.get("text", ""))[:Q_TEXT],
                                    "type": q.get("type") if q.get("type") in Q_TYPES else "text",
                                    "guidance": str(q.get("guidance") or "")[:Q_GUIDE],
                                    "criteria": [c for c in q.get("criteria") or [] if c in self.catalog.criteria]}
                                   for q in s.get("questions") or []]}
                    for s in data.get("sections") or []]
        return {"title": str(data.get("title") or "Vendor security questionnaire")[:Q_TITLE],
                "intro": str(data.get("intro") or "").strip()[:Q_INTRO], "sections": sections}

    @staticmethod
    def _q_next(sections: list[dict], prefix: str) -> int:
        nums = [int(x["id"][2:]) for s in sections for x in ([s] if prefix == "S" else s["questions"])
                if Q_ID_RE.match(x["id"]) and x["id"][0] == prefix]
        return max(nums, default=0) + 1

    def questionnaire_versions(self) -> list[dict]:
        self._q_seed()
        return sorted(self.store.list("questionnaires", "v"), key=lambda r: r["RowKey"], reverse=True)

    def questionnaire_version(self, n: int = 0) -> dict:
        versions = self.questionnaire_versions()
        if not n:
            return versions[0]
        row = self.store.get("questionnaires", "v", f"{int(n):04d}") if 0 < int(n) < 10000 else None
        if not row:
            raise self._invalid("Questionnaire version not found")
        return row

    def _q_seed(self) -> None:
        if self.store.get("questionnaires", "v", "0001"):
            return
        q = self._q_starter()
        self.store.insert("questionnaires", {"PartitionKey": "v", "RowKey": "0001", "version": 1, **q,
                                             "saved_by": "system", "saved_at": _now(), "reason": "Starter questionnaire"})
        self.audit("system", "questionnaire.seed", "v1", {"controls": ["VEN-01"], "questions": sum(
            len(s["questions"]) for s in q["sections"])})

    def questionnaire_draft(self, actor) -> dict:
        """The admin's working copy. It starts as the latest version; nothing changes for anyone else until
        it is saved as a new version."""
        self._admin(actor)
        latest = self.questionnaire_version()
        draft = self.store.get("questionnaires", "d", "draft")
        if not draft:
            draft = {"PartitionKey": "d", "RowKey": "draft", "based_on": latest["version"], "changed": False,
                     **{k: latest[k] for k in ("title", "intro", "sections")}}
            self.store.upsert("questionnaires", draft)
        return draft

    def edit_questionnaire(self, actor, op: str, form: dict) -> dict:
        """One change to the draft: add, edit, move or remove a section or question."""
        draft = self.questionnaire_draft(actor)
        sections = json.loads(json.dumps(draft["sections"]))
        Invalid = self._invalid

        def find_section(sid):
            for i, s in enumerate(sections):
                if s["id"] == sid:
                    return i, s
            raise Invalid("Section not found")

        def find_question(qid):
            for si, s in enumerate(sections):
                for qi, q in enumerate(s["questions"]):
                    if q["id"] == qid:
                        return si, qi, q
            raise Invalid("Question not found")

        def question_fields():
            text = str(form.get("text", "")).strip()
            if not text:
                raise Invalid("Write the question")
            if len(text) > Q_TEXT:
                raise Invalid(f"Questions are limited to {Q_TEXT} characters")
            qtype = str(form.get("type", "text"))
            if qtype not in Q_TYPES:
                raise Invalid("Choose an answer type")
            crit = [c for c in (form.get("criteria") or []) if c]
            unknown = [c for c in crit if c not in self.catalog.criteria]
            if unknown:
                raise Invalid(f"Unknown criterion: {', '.join(unknown)}")
            return {"text": text, "type": qtype, "guidance": str(form.get("guidance", "")).strip()[:Q_GUIDE],
                    "criteria": crit[:10]}

        sid, qid = str(form.get("section", "")), str(form.get("question", ""))
        direction = str(form.get("direction", ""))
        title = str(form.get("title", "")).strip()
        if op == "intro":
            if not title:
                raise Invalid("Give the questionnaire a title")
            draft["title"], draft["intro"] = title[:Q_TITLE], str(form.get("intro", "")).strip()[:Q_INTRO]
        elif op == "add_section":
            if not title:
                raise Invalid("Name the section")
            if len(sections) >= S_MAX:
                raise Invalid(f"A questionnaire can have up to {S_MAX} sections")
            sections.append({"id": f"S-{self._q_next(sections, 'S'):03d}", "title": title[:Q_TITLE], "questions": []})
        elif op == "rename_section":
            _i, s = find_section(sid)
            if not title:
                raise Invalid("Name the section")
            s["title"] = title[:Q_TITLE]
        elif op == "move_section":
            i, s = find_section(sid)
            j = i - 1 if direction == "up" else i + 1
            if 0 <= j < len(sections):
                sections[i], sections[j] = sections[j], sections[i]
        elif op == "delete_section":
            i, s = find_section(sid)
            if s["questions"]:
                raise Invalid("Move or remove the questions in this section first")
            sections.pop(i)
        elif op == "add_question":
            _i, s = find_section(sid)
            if sum(len(x["questions"]) for x in sections) >= Q_MAX:
                raise Invalid(f"A questionnaire can have up to {Q_MAX} questions")
            # Question ids are never reused, even after a question is removed in an earlier version.
            used = [v["sections"] for v in self.store.list("questionnaires", "v")] + [sections]
            n = max(self._q_next(x, "Q") for x in used)
            s["questions"].append({"id": f"Q-{n:03d}", **question_fields()})
        elif op == "edit_question":
            si, qi, q = find_question(qid)
            sections[si]["questions"][qi] = {"id": q["id"], **question_fields()}
        elif op == "move_question":
            si, qi, q = find_question(qid)
            qs = sections[si]["questions"]
            if direction == "up":
                if qi > 0:
                    qs[qi - 1], qs[qi] = qs[qi], qs[qi - 1]
                elif si > 0:  # top of a section: move to the end of the section above
                    sections[si - 1]["questions"].append(qs.pop(qi))
            else:
                if qi < len(qs) - 1:
                    qs[qi + 1], qs[qi] = qs[qi], qs[qi + 1]
                elif si < len(sections) - 1:  # bottom of a section: move to the start of the next one
                    sections[si + 1]["questions"].insert(0, qs.pop(qi))
        elif op == "move_to_section":
            si, qi, q = find_question(qid)
            ti, target = find_section(str(form.get("target", "")))
            if ti != si:
                target["questions"].append(sections[si]["questions"].pop(qi))
        elif op == "delete_question":
            si, qi, q = find_question(qid)
            sections[si]["questions"].pop(qi)
        elif op == "discard":
            latest = self.questionnaire_version()
            self.store.delete("questionnaires", "d", "draft")
            self.audit(actor, "questionnaire.draft.discard", f"v{latest['version']}", {})
            return self.questionnaire_draft(actor)
        else:
            raise Invalid("Unknown change")
        if len(json.dumps(sections)) > Q_BYTES:
            raise Invalid("The questionnaire is too long. Shorten or remove some questions.")
        fields = {"sections": sections, "title": draft["title"], "intro": draft["intro"], "changed": True}
        self.store.update("questionnaires", "d", "draft", fields)
        self.audit(actor, f"questionnaire.draft.{op}", qid or sid or "draft",
                   {"section": sid, "question": qid, "direction": direction, "target": str(form.get("target", ""))})
        return self.store.get("questionnaires", "d", "draft")

    def publish_questionnaire(self, actor, reason: str) -> dict:
        draft = self.questionnaire_draft(actor)
        reason = (reason or "").strip()[:500]
        if not reason:
            raise self._invalid("Say what changed in this version (kept for the auditor)")
        if not draft.get("changed"):
            raise self._invalid("Nothing has changed since the last version")
        if not any(s["questions"] for s in draft["sections"]):
            raise self._invalid("The questionnaire needs at least one question")
        n = self.questionnaire_version()["version"] + 1
        row = {"PartitionKey": "v", "RowKey": f"{n:04d}", "version": n, "title": draft["title"], "intro": draft["intro"],
               "sections": draft["sections"], "saved_by": actor.email, "saved_at": _now(), "reason": reason}
        self.store.insert("questionnaires", row)
        self.store.delete("questionnaires", "d", "draft")
        self.audit(actor, "questionnaire.publish", f"v{n}", {"controls": ["VEN-01"], "version": n, "reason": reason,
                                                             "questions": sum(len(s["questions"]) for s in row["sections"])})
        return row

    def questionnaire_xlsx(self, version: dict, vendor: dict | None = None, due: str = "") -> bytes:
        """The questionnaire as an Excel file: an Instructions sheet and a Questions sheet with locked
        questions, answer and comment columns to fill in, and Yes/No/N/A dropdowns."""
        from grcpal import xlsx

        info = [[(version["title"], xlsx.TITLE)], [""], [("From", xlsx.HEADER), self.org]]
        if vendor:
            info += [[("Vendor", xlsx.HEADER), vendor["name"]], [("Service", xlsx.HEADER), vendor.get("service", "")]]
        if due:
            info.append([("Please return by", xlsx.HEADER), due])
        info += [[("Questionnaire version", xlsx.HEADER), f"v{version['version']} ({version['saved_at'][:10]})"], [""],
                 [(version.get("intro") or "", xlsx.TEXT)], [""],
                 [("How to answer: fill in the Answer and Comments columns on the Questions sheet. For Yes/No "
                   "questions pick Yes, No or N/A from the list. Please keep the question IDs unchanged.", xlsx.TEXT)]]
        rows = [[(h, xlsx.HEADER) for h in ("No.", "ID", "Section", "Question", "Guidance", "Answer", "Comments / evidence")]]
        yesno = []
        for si, s in enumerate(version["sections"], 1):
            for qi, q in enumerate(s["questions"], 1):
                rows.append([f"{si}.{qi}", q["id"], s["title"], q["text"], q.get("guidance", ""),
                             ("", xlsx.ANSWER), ("", xlsx.ANSWER)])
                if q["type"] == "yesno":
                    yesno.append(f"F{len(rows)}")
        sheets = [{"name": "Instructions", "rows": info, "widths": [24, 100]},
                  {"name": "Questions", "rows": rows, "widths": [6, 9, 26, 60, 40, 22, 45], "freeze_row": 1,
                   "protect": True, "lists": [(" ".join(yesno), YES_NO)] if yesno else []}]
        return xlsx.workbook(sheets)

    def send_questionnaire(self, actor, vid: str) -> tuple[str, bytes]:
        """Download the latest questionnaire for one vendor and record on its open review which version was
        sent. Owners and admins only."""
        v = self._vendor_row(vid)
        if not v or not self.can_see_vendor(actor, v):
            raise self._invalid("Vendor not found")
        if not self.can_work_vendor(actor, v):
            raise self._forbidden("Only admins and this vendor's owners can send the questionnaire")
        version = self.questionnaire_version()
        due = (self.today + dt.timedelta(days=30)).isoformat()
        r = self.open_review(vid)
        if not r and v.get("status") == "active":
            r = self._open_review(actor, vid, "annual")
        if r:
            self.store.update("vendorreviews", vid, r["RowKey"], {"questionnaire_version": version["version"],
                                                                  "questionnaire_sent_at": _now()})
        self.audit(actor, "questionnaire.sent", vid, {"controls": ["VEN-02"], "version": version["version"],
                                                      "review": r["RowKey"] if r else ""})
        return (f"{slug(v['name'])}-security-questionnaire-v{version['version']}.xlsx",
                self.questionnaire_xlsx(version, v, due))

    # ================================================================ reminders and calendar
    def _vendor_mail(self, v: dict, subject: str, intro: str) -> dict:
        return {"subject": subject, "title": subject, "intro": intro,
                "fields": [("Vendor", v["name"]), ("Tier", TIERS.get(v.get("tier"), "")),
                           ("Status", STATUSES.get(v.get("status"), ""))],
                "button": ("Open the vendor", self.link(f"/vendors/{v['RowKey']}"))}

    def remind_vendor_reviews(self, actor) -> list[dict]:
        """Email owners and admins about annual reviews due within 30 days (once per due date) or overdue
        (at most once every 12 hours; the scheduled job runs weekly)."""
        out = []
        admins = self.active_emails("admin")
        for v in self.store.list("vendors", "v"):
            view = self._vendor_view(v)
            due = view["next_review"]
            if not due or view["due_in"] is None or view["due_in"] > DUE_SOON_DAYS:
                continue
            if view["open_review"] and view["open_review"]["status"] == "submitted":
                continue
            overdue = view["due_in"] < 0
            key = f"vendor|{v['RowKey']}|{due}|{'overdue' if overdue else 'soon'}"
            if (not overdue and self.store.get("reminders", "r", key)) or (overdue and not self._cooldown_ok(key)):
                continue
            people = {v.get("owner_email"), v.get("backup_email"), *admins} - {"", None}
            subject = (f"Vendor review overdue: {v['name']} (was due {due})" if overdue
                       else f"Vendor review due {due}: {v['name']}")
            sent = self._notify("vendor", people, actor, self._vendor_mail(
                v, subject, "Upload the vendor's latest report or returned questionnaire and answer the review "
                "questions. Security maps the CUECs and signs off."), ["VEN-02"])
            self._mark_sent(key, actor)
            self.audit(actor, "vendor.remind", v["RowKey"], {"controls": ["VEN-02"], "due": due, "recipients": len(sent),
                                                             "overdue": overdue})
            out.append({"vendor": v["name"], "due": due, "overdue": overdue, "sent": sent})
        return out

    def vendor_calendar(self, year: int) -> list[list[dict]]:
        """Annual reviews due in each month of a year (admins see this row on the security calendar)."""
        months: list[list[dict]] = [[] for _ in range(12)]
        for v in self.store.list("vendors", "v"):
            due = self._next_review(v)
            if due and due[:4] == str(year):
                months[int(due[5:7]) - 1].append({"id": v["RowKey"], "name": v["name"], "due": due})
        return months

    # ================================================================ auditor export
    def vendor_export(self, start: str, end: str) -> tuple[dict[str, list[dict]], dict[str, bytes]]:
        """Tables and files for the auditor export. Contact details are never included."""
        def plain(row: dict) -> dict:
            return {k: v for k, v in row.items() if k not in CONTACT_FIELDS and k not in ("PartitionKey", "legacy")}

        vendors = self.store.list("vendors", "v")
        tables: dict[str, list[dict]] = {"vendors": [], "vendor_register_history": [], "vendor_reviews": [],
                                         "vendor_exceptions": [], "vendor_cuecs": [], "vendor_files": [],
                                         "subservice_organizations": [], "questionnaire_versions": []}
        files: dict[str, bytes] = {}
        for v in sorted(vendors, key=lambda x: x["name"].lower()):
            vid = v["RowKey"]
            approved = [r for r in self.vendor_reviews(vid) if r["status"] == "approved"]
            onboarding = next((r for r in approved if r["kind"] == "onboarding"), None)
            row = plain(v)
            row.update(vendor=vid, owner_title=v.get("owner_title", ""), has_internal_owner=bool(v.get("owner_email")),
                       next_review=self._next_review(v), cuecs=len(v.get("cuecs") or []),
                       onboarding_approved_at=(onboarding or {}).get("approved_at", ""),
                       data_shared_before_approval=bool(onboarding and v.get("start_date")
                                                        and v["start_date"] < onboarding["approved_at"][:10]))
            row.pop("RowKey", None)
            tables["vendors"].append(row)
            if v.get("subservice") in ("carved_out", "inclusive"):
                tables["subservice_organizations"].append({
                    "vendor": vid, "name": v["name"], "service": v.get("service", ""),
                    "method": SUBSERVICE[v["subservice"]], "assurance": ASSURANCE.get(v.get("assurance", ""), ""),
                    "report_period_end": v.get("period_end", ""), "last_review": v.get("last_review", "")})
            for ver in self.store.list("vendorversions", vid):
                snap = {k: x for k, x in ver["snapshot"].items() if k not in CONTACT_FIELDS and k != "legacy"}
                tables["vendor_register_history"].append({"vendor": vid, "version": int(ver["RowKey"]), "at": ver["at"],
                                                          "by": ver["by"], "reason": ver["reason"], **snap})
            for c in v.get("cuecs") or []:
                tables["vendor_cuecs"].append({"vendor": vid, "name": v["name"], "source": "current", "review": "",
                                               **{k: c.get(k, "") for k in ("id", "text", "controls", "how", "status", "by", "at")}})
            for r in self.vendor_reviews(vid):
                when = (r.get("approved_at") or r["opened_at"])[:10]
                if not (start <= when <= end or (r["status"] in OPEN_REVIEW and r["opened_at"][:10] <= end)):
                    continue
                tables["vendor_reviews"].append({
                    "vendor": vid, "name": v["name"], "review": r["RowKey"], "kind": r["kind"], "status": r["status"],
                    "decision": r.get("decision", ""), "opened_by": r["opened_by"], "opened_at": r["opened_at"],
                    "submitted_by": r.get("submitted_by", ""), "submitted_at": r.get("submitted_at", ""),
                    "approved_by": r.get("approved_by", ""), "approved_at": r.get("approved_at", ""),
                    "self_approved": r.get("self_approved", False), "accepted_gaps": r.get("accepted_gaps", []),
                    "decision_note": r.get("decision_note", ""), "answers": r.get("answers", {}),
                    "checklist": [{k: i.get(k) for k in ("key", "label", "done", "note", "by", "at")} for i in r.get("checklist") or []],
                    "questionnaire_version": r.get("questionnaire_version", 0), "files": r.get("file_ids", []),
                    "tier_at_signoff": (r.get("snapshot") or {}).get("tier", ""),
                    "assurance_at_signoff": (r.get("snapshot") or {}).get("assurance", ""),
                    "report_period_end_at_signoff": (r.get("snapshot") or {}).get("period_end", ""),
                    "opinion_at_signoff": (r.get("snapshot") or {}).get("opinion", "")})
                for x in r.get("exceptions") or []:
                    tables["vendor_exceptions"].append({"vendor": vid, "name": v["name"], "review": r["RowKey"], **x})
                for c in (r.get("snapshot") or {}).get("cuecs") or []:
                    tables["vendor_cuecs"].append({"vendor": vid, "name": v["name"], "source": "at sign-off",
                                                   "review": r["RowKey"],
                                                   **{k: c.get(k, "") for k in ("id", "text", "controls", "how", "status", "by", "at")}})
            for f in self.store.list("vendorfiles", vid):
                if not start <= f["uploaded_at"][:10] <= end:
                    continue
                path = f"vendor_files/{vid}/{f['RowKey'][:8]}_{f['filename']}"
                tables["vendor_files"].append({"vendor": vid, "review": f["review"], "kind": f["kind"], "file": path,
                                               "sha256": f["sha256"], "size": f["size"], "comment": f["comment"],
                                               "uploaded_by": f["uploaded_by"], "uploaded_at": f["uploaded_at"]})
                source, run = f["evidence_run"].split("/", 1)
                data = self.evidence.read(source, run, f["filename"])
                if data is not None:
                    files[path] = data
        for ver in self.questionnaire_versions():
            for si, s in enumerate(ver["sections"], 1):
                for qi, q in enumerate(s["questions"], 1):
                    tables["questionnaire_versions"].append({
                        "version": ver["version"], "saved_at": ver["saved_at"], "saved_by": ver["saved_by"],
                        "reason": ver["reason"], "number": f"{si}.{qi}", "id": q["id"], "section": s["title"],
                        "question": q["text"], "type": Q_TYPES[q["type"]], "guidance": q.get("guidance", ""),
                        "criteria": q.get("criteria", [])})
        return tables, files

"""Policies page: the approved, in-force documents people must know, and their acknowledgements (SOC 2 CC1.4, CC2.2;
control GOV-04).

Plain model:
- The document library is the draft workspace. A document appears on the Policies page as soon as one of its
  official versions is approved (the approval workflow or an admin's direct approval): nothing is published by hand.
  Sections follow the library's tiers; documents of kind "soc2" (system description, registers, reports) are shown
  as **Registers**: published for reference, never acknowledged.
- Each document says who must acknowledge it: everyone with a GRC-pal account, admins only, or nobody. Policies
  default to everyone; standards, procedures and registers default to nobody. Admins change it per document.
- An acknowledgement records the person, the exact version and the file's SHA-256. A newly approved version needs a
  new acknowledgement; earlier ones stay as history (table `acks`, partition `lib:<document id>`).
- Nobody is emailed by surprise: an admin presses "Ask for acknowledgement", which emails everyone still missing and
  turns on weekly reminders from the nightly job until all have acknowledged.
- Policies written as Markdown in the program repository (catalog/policies) keep working as before, in their own
  section, with their existing acknowledgements.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import re

from grcpal.portal.doclib import GOV_CONTROLS, builtin_catalog
from grcpal.portal.security import csv_cell

ACK_CHOICES = {"all": "Everyone with a GRC-pal account", "admins": "Admins only", "none": "Not needed"}
ACK_CONTROLS = ["GOV-04"]
REMIND_DAYS = 7
REGISTER_KINDS = ("soc2", "register")
SECTIONS_EXTRA = {"registers": ("Registers and reports", "Published for reference. No acknowledgement."),
                  "repository": ("From the program repository", "Markdown policies in catalog/policies.")}
_DID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _controls(raw) -> list[str]:
    if isinstance(raw, list):
        return [str(x) for x in raw]
    return [x for x in re.split(r"[,;\s]+", str(raw or "")) if x]


class PoliciesMixin:
    # ------------------------------------------------------------------ what is published
    def _ack_default(self, d: dict) -> str:
        if d.get("kind") in REGISTER_KINDS:
            return "none"
        return "all" if d.get("kind") == "policy" else "none"

    def _published_from_library(self, user) -> list[dict]:
        out = []
        lib = self.library(user)
        for d in lib["docs"]:
            if not d["current"]:
                continue
            primary = next((v for v in d["current"] if not v.get("variant")), d["current"][0])
            register = d.get("kind") in REGISTER_KINDS
            ack = "none" if register else (d.get("ack") or self._ack_default(d))
            out.append({"id": d["id"], "source": "library", "href": f"/policies/doc/{d['id']}",
                        "title": d["title"], "number": d["number"], "folder": d["folder"],
                        "section": "registers" if register else d["folder"], "kind": d.get("kind", "other"),
                        "version": primary["label"], "vid": primary["RowKey"], "sha256": primary["sha256"],
                        "filename": primary["filename"], "approved_at": primary.get("approved_at", ""),
                        "approved_by": primary.get("approved_by", ""), "variants": d["current"],
                        "owner": d["owner_name"], "approver": d["approver_name"], "next_review": d.get("next_review", ""),
                        "review_state": d.get("review_state", ""), "controls": _controls(d.get("controls")) or GOV_CONTROLS,
                        "ack": ack, "ack_partition": f"lib:{d['id']}", "ack_version": primary["RowKey"],
                        "ack_requested_at": d.get("ack_requested_at", ""), "summary": d.get("summary", "")})
        return out

    def _published_from_repository(self) -> list[dict]:
        out = []
        for p in self.catalog.policies:
            out.append({"id": p["id"], "source": "repository", "href": f"/policies/{p['id']}", "title": p["title"],
                        "number": "", "folder": "repository", "section": "repository", "kind": "policy",
                        "version": p["version"], "vid": p["version"], "sha256": p["sha256"], "filename": "",
                        "approved_at": p.get("effective", ""), "approved_by": p.get("approver", ""), "variants": [],
                        "owner": p.get("owner", ""), "approver": p.get("approver", ""),
                        "next_review": p.get("next_review", ""), "review_state": "", "controls": p.get("controls") or [],
                        "ack": "all" if p.get("acknowledge", True) else "none", "ack_partition": p["id"],
                        "ack_version": p["version"], "ack_requested_at": "", "summary": ""})
        return out

    def published_documents(self, user) -> list[dict]:
        """Every published document this person may see, with acknowledgement status."""
        docs = self._published_from_library(user) + self._published_from_repository()
        for d in docs:
            d["status"] = self.ack_status(d)
            d["mine"] = ("done" if user.email in d["status"]["rows"] else
                         ("todo" if user.email in d["status"]["audience"] else "not_needed"))
        return docs

    def policy_sections(self, user) -> list[dict]:
        cat = builtin_catalog()
        names = {f["id"]: (f["name"], f.get("note", "")) for f in cat["folders"]}
        names["other"] = ("Other documents", "Documents your organization added.")
        names.update(SECTIONS_EXTRA)
        docs = self.published_documents(user)
        order = [f["id"] for f in cat["folders"] if f["id"] != "soc2"] + ["other", "registers", "repository"]
        out = []
        for sid in order:
            rows = [d for d in docs if d["section"] == sid]
            if rows:
                title, note = names.get(sid, (sid, ""))
                out.append({"id": sid, "title": title, "note": note,
                            "docs": sorted(rows, key=lambda d: (d["number"] or "~", d["title"].lower()))})
        return out

    def published_document(self, user, did: str) -> dict:
        doc = next((d for d in self._published_from_library(user) if d["id"] == did), None) if _DID.match(did or "") else None
        if not doc:
            raise self._invalid("Document not found, or it has no approved version yet")
        doc["status"] = self.ack_status(doc)
        return doc

    # ------------------------------------------------------------------ acknowledgements
    def _ack_audience(self, ack: str) -> list[str]:
        if ack == "all":
            return self.active_emails("admin", "contributor")
        if ack == "admins":
            return self.active_emails("admin")
        return []

    def ack_status(self, doc: dict) -> dict:
        prefix = f"{doc['ack_version']}|"
        rows = {r["RowKey"].split("|", 1)[1]: r for r in self.store.list("acks", doc["ack_partition"])
                if r["RowKey"].startswith(prefix)}
        audience = self._ack_audience(doc["ack"])
        return {"audience": audience, "acked": sorted(e for e in rows if e in audience),
                "missing": [e for e in audience if e not in rows], "rows": rows}

    def acknowledge_document(self, user, did: str, vid: str, read: bool) -> dict:
        if user.is_auditor:
            raise self._forbidden("Auditors do not acknowledge policies")
        doc = self.published_document(user, did)
        if doc["ack"] == "none":
            raise self._invalid("This document does not need an acknowledgement")
        if user.email not in doc["status"]["audience"]:
            raise self._invalid("You are not asked to acknowledge this document")
        if vid != doc["vid"]:
            raise self._invalid("A newer version was approved meanwhile. Open the page again and read the new version")
        if not read:
            raise self._invalid("Tick the box to confirm you have read this version")
        key = f"{doc['ack_version']}|{user.email}"
        existing = self.store.get("acks", doc["ack_partition"], key)
        if existing:
            return existing
        row = {"PartitionKey": doc["ack_partition"], "RowKey": key, "email": user.email, "version": doc["version"],
               "vid": doc["vid"], "sha256": doc["sha256"], "title": doc["title"][:200], "at": _now()}
        self.store.insert("acks", row)
        self.audit(user, "policy.ack", did, {"controls": sorted(set(ACK_CONTROLS + doc["controls"])),
                                            "version": doc["version"], "sha256": doc["sha256"], "source": "library"})
        return row

    def set_document_ack(self, actor, did: str, ack: str) -> None:
        self._need_admin(actor, "change who acknowledges a document")
        if ack not in ACK_CHOICES:
            raise self._invalid("Choose who must acknowledge it")
        doc = self.published_document(actor, did)
        if doc["kind"] in REGISTER_KINDS and ack != "none":
            raise self._invalid("Registers and reports are published for reference and are not acknowledged")
        if doc["ack"] == ack:
            return
        row = self.store.get("docs", "d", did)
        if row:
            self.store.update("docs", "d", did, {"ack": ack})
        else:
            self.store.insert("docs", {"PartitionKey": "d", "RowKey": did, "ack": ack})
        self.audit(actor, "policy.ack_audience", did, {"controls": ACK_CONTROLS, "from": doc["ack"], "to": ack})

    def request_acknowledgement(self, actor, did: str) -> dict:
        """Email everyone who has not acknowledged this version yet, and turn on weekly reminders."""
        self._need_admin(actor, "ask for acknowledgements")
        doc = self.published_document(actor, did)
        if doc["ack"] == "none":
            raise self._invalid("Choose who must acknowledge this document first")
        missing = doc["status"]["missing"]
        if not missing:
            raise self._invalid("Everyone has acknowledged this version")
        sent = self._ack_mail(doc, missing, actor, first=True)
        self.store.update("docs", "d", did, {"ack_requested_at": _now(), "ack_requested_by": actor.email}) \
            if self.store.get("docs", "d", did) else \
            self.store.insert("docs", {"PartitionKey": "d", "RowKey": did, "ack_requested_at": _now(),
                                       "ack_requested_by": actor.email})
        self.audit(actor, "policy.ack_request", did, {"controls": ACK_CONTROLS, "version": doc["version"],
                                                      "asked": len(sent)})
        return {"sent": sent, "skipped": [e for e in missing if e not in sent]}

    def _ack_mail(self, doc: dict, emails: list[str], actor, first: bool) -> list[str]:
        from grcpal.portal import notify

        sent = []
        for e in emails:
            key = f"polack:{doc['ack_partition']}|{doc['vid']}|{e}"
            row = self.store.get("reminders", "r", key)
            if not first and row and self._days_since(row["last_sent"]) < REMIND_DAYS:
                continue
            if self._notify("policy", [e], actor, notify.document_ack(self, doc, first), doc["controls"],
                            include_actor=True):
                self._mark_sent(key, actor)
                sent.append(e)
        return sent

    def send_policy_ack_reminders(self, actor) -> list[dict]:
        """Daily job: weekly reminders for documents an admin asked people to acknowledge."""
        out = []
        for doc in self._published_from_library(actor):
            if doc["ack"] == "none" or not doc["ack_requested_at"]:
                continue
            missing = self.ack_status(doc)["missing"]
            if not missing:
                continue
            sent = self._ack_mail(doc, missing, actor, first=False)
            if sent:
                self.audit(actor, "policy.ack_remind", doc["id"], {"controls": ACK_CONTROLS, "version": doc["version"],
                                                                   "reminded": len(sent)})
                out.append({"doc": doc["id"], "reminded": len(sent)})
        return out

    def documents_to_acknowledge(self, user) -> list[dict]:
        """For My work: published documents this person still has to acknowledge."""
        if user.is_auditor:
            return []
        return [d for d in self.published_documents(user) if d["mine"] == "todo"]

    # ------------------------------------------------------------------ report for auditors
    def acknowledgement_report(self, user) -> bytes:
        """Every published document requiring acknowledgement, every person asked, acknowledged or not, with version,
        file SHA-256 and time. Admins and auditors."""
        if not user.sees_everything:
            raise self._forbidden("Only admins and auditors can download the acknowledgement report")
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["document", "number", "source", "version", "sha256", "approved_at", "person", "status",
                    "acknowledged_at"])
        count = 0
        for d in self.published_documents(user):
            if d["ack"] == "none":
                continue
            for e in d["status"]["audience"]:
                r = d["status"]["rows"].get(e)
                w.writerow([csv_cell(x) for x in (d["title"], d["number"], d["source"], d["version"], d["sha256"],
                                                  d["approved_at"], e, "acknowledged" if r else "missing",
                                                  (r or {}).get("at", ""))])
                count += 1
        self.audit(user, "policy.ack_report", "policies", {"controls": ACK_CONTROLS, "rows": count})
        return buf.getvalue().encode("utf-8")

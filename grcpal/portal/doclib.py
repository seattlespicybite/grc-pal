"""Document library: the policy hierarchy (policies, standards, procedures, SOC 2 documents) as a file repository.

Plain model:
- The catalog of built-in documents and their Word templates ships with GRC-pal (`starter/doctemplates/`).
  Nothing is copied into the database up front. A document only gets a row when an admin edits it, so new
  built-in templates appear after an upgrade without any migration. Admins can also add their own documents.
- Every document has two kinds of files, both kept write-once in the evidence store with a SHA-256:
  * Template versions: the built-in template, or one an admin uploaded instead. The newest upload is the active
    template; "Restore built-in" records that choice as a new entry, so history is never lost.
  * Official versions: the company's own approved document. Each has a version number (major or minor, per the
    document control rules), an optional product/variant label, and a status. Files never change; only the
    status moves: draft, in review, approved, superseded (automatic when a newer version of the same variant is
    approved) or archived.
- Who sees what: admins change everything. Auditors read everything, read-only. Control owners see only approved
  official versions (the published copy), never templates or drafts.
- Approval needs a different admin than the uploader, unless there is no other active admin (then it is marked
  self-approved for the auditor). Every write is in the hash-chained audit log.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
import uuid
from functools import lru_cache
from pathlib import Path

import yaml

STARTER = Path(__file__).resolve().parent.parent / "starter" / "doctemplates"
DOC_EXTENSIONS = {".docx", ".pdf", ".xlsx", ".pptx"}
CLASSIFICATIONS = ["Public", "Internal", "Confidential", "Restricted"]
STATUSES = {"draft": "Draft", "in_review": "In review", "approved": "Approved", "superseded": "Superseded",
            "archived": "Archived"}
CHANGES = {"major": "Major (a commitment changed)", "minor": "Minor (wording or formatting)"}
KINDS = {"policy": "Policy", "standard": "Standard", "procedure": "Procedure / plan", "soc2": "SOC 2 document",
         "other": "Other"}
ROLE_NAMES = {"security-lead": "Security lead", "hr-lead": "HR lead", "it-lead": "IT lead",
              "engineering-lead": "Engineering lead", "legal-lead": "Legal lead", "executive-sponsor": "Executive sponsor"}
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
_VID = re.compile(r"^\d{8}T\d{12}-[0-9a-f]{8}$")
GOV_CONTROLS = ["GOV-01"]


def _new_vid() -> str:
    """Sortable id: microsecond timestamp plus a random part, so versions list in upload order."""
    return f"{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%S%f}-{uuid.uuid4().hex[:8]}"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


@lru_cache(maxsize=1)
def builtin_catalog() -> dict:
    data = yaml.safe_load((STARTER / "catalog.yaml").read_text(encoding="utf-8")) or {}
    docs = {d["id"]: d for d in data.get("docs", [])}
    return {"folders": data.get("folders", []), "docs": docs}


def builtin_template(did: str) -> tuple[str, bytes] | None:
    d = builtin_catalog()["docs"].get(did)
    path = STARTER / "files" / (d or {}).get("file", "")
    if not d or not path.is_file():
        return None
    return d["file"], path.read_bytes()


@lru_cache(maxsize=None)
def _builtin_facts(did: str) -> tuple[str, int, str]:
    name, data = builtin_template(did)
    return name, len(data), hashlib.sha256(data).hexdigest()


def bump(labels: list[str], change: str) -> str:
    """Next version label for one document and variant: 1.0 first, then major (2.0) or minor (1.1)."""
    best = (0, 0)
    for lab in labels:
        m = re.match(r"^(\d+)\.(\d+)$", lab or "")
        if m:
            best = max(best, (int(m.group(1)), int(m.group(2))))
    if best == (0, 0):
        return "1.0"
    return f"{best[0] + 1}.0" if change == "major" else f"{best[0]}.{best[1] + 1}"


class DocLibMixin:
    # ------------------------------------------------------------------ reading
    def _doc_rows(self) -> dict[str, dict]:
        return {r["RowKey"]: r for r in self.store.list("docs", "d")}

    def _all_versions(self) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for v in self.store.list("docversions"):
            out.setdefault(v["PartitionKey"], []).append(v)
        for rows in out.values():
            rows.sort(key=lambda v: v["RowKey"], reverse=True)
        return out

    @staticmethod
    def _active_template(versions: list[dict]) -> dict | None:
        """The newest template entry that is a real upload; a built-in marker (or none) means the shipped file."""
        for v in versions:  # newest first
            if v["kind"] == "template":
                return None if v.get("builtin") else v
        return None

    def _merge_doc(self, did: str, base: dict | None, row: dict | None, versions: list[dict]) -> dict:
        d = {"id": did, "number": "", "folder": "other", "kind": "other", "title": did, "owner": "", "approver": "",
             "soc2": "", "iso": "", "controls": "", "summary": "", "parent": "", "custom": False, "classification": "",
             "next_review": "", "updated_at": "", "updated_by": ""}
        d.update(base or {})
        d.update({k: v for k, v in (row or {}).items() if k not in ("PartitionKey", "RowKey")})
        d["builtin_title"] = (base or {}).get("title", "")
        d["owner_name"] = ROLE_NAMES.get(d["owner"], d["owner"])
        d["approver_name"] = ROLE_NAMES.get(d["approver"], d["approver"])
        official = [v for v in versions if v["kind"] == "official"]
        approved = [v for v in official if v["status"] == "approved"]
        seen, current = set(), []
        for v in approved:  # newest first: keep the newest approved version of each variant
            if v.get("variant", "") not in seen:
                seen.add(v.get("variant", ""))
                current.append(v)
        d["current"], d["official_count"] = current, len(official)
        d["pending"] = sum(1 for v in official if v["status"] in ("draft", "in_review"))
        custom_tpl = self._active_template(versions)
        d["template_source"] = "Custom" if custom_tpl else ("Built-in" if base else "None")
        d["has_template"] = bool(custom_tpl or base)
        stamps = [v["uploaded_at"] for v in versions] + [d.get("updated_at") or ""]
        d["last_change"] = max(stamps) if stamps else ""
        due = d.get("next_review") or ""
        today = self.today
        d["review_state"] = ""
        if due and current:
            try:
                days = (dt.date.fromisoformat(due) - today).days
                d["review_state"] = "overdue" if days < 0 else ("soon" if days <= 60 else "ok")
            except ValueError:
                pass
        return d

    def library(self, user, folder: str = "", q: str = "") -> dict:
        """Folders with counts and the documents this user may see."""
        cat, rows, versions = builtin_catalog(), self._doc_rows(), self._all_versions()
        ids = list(cat["docs"]) + [i for i in rows if i not in cat["docs"]]
        docs = []
        for did in ids:
            d = self._merge_doc(did, cat["docs"].get(did), rows.get(did), versions.get(did, []))
            if not user.sees_everything and not d["current"]:
                continue  # staff only see documents that have an approved official version
            docs.append(d)
        docs.sort(key=lambda d: (d["folder"], d["number"] or "~", d["title"].lower()))
        folders = [{**f, "count": sum(1 for d in docs if d["folder"] == f["id"])} for f in cat["folders"]]
        other = [d for d in docs if d["folder"] not in {f["id"] for f in cat["folders"]}]
        if other or any(r.get("custom") for r in rows.values()):
            folders.append({"id": "other", "name": "Other documents", "note": "Documents your organization added.",
                            "count": len(other)})
        needle = (q or "").strip().lower()
        shown = [d for d in docs if (not folder or d["folder"] == folder)
                 and (not needle or needle in f"{d['number']} {d['title']} {d['owner_name']} {d['summary']}".lower())]
        return {"folders": folders, "docs": shown, "total": len(docs)}

    def library_files(self, user, folder: str = "", q: str = "") -> list[dict]:
        """Flat file list (the Explorer 'details' view): every visible file with its document. Admins and auditors
        also see each document's active template, so the list is useful before anything has been uploaded."""
        lib = self.library(user, folder, q)
        versions = self._all_versions()
        out, templates = [], []
        for d in lib["docs"]:
            rows = versions.get(d["id"], [])
            for v in rows:
                if v["kind"] == "official" and (user.sees_everything or v["status"] == "approved"):
                    out.append({**v, "doc": d})
            if user.sees_everything and d["has_template"]:
                active = self._active_template(rows)
                if active:
                    templates.append({**active, "RowKey": "template", "PartitionKey": d["id"], "label": "", "variant": "",
                                      "status": "template", "doc": d})
                else:
                    name, size, digest = _builtin_facts(d["id"])
                    templates.append({"PartitionKey": d["id"], "RowKey": "template", "kind": "template", "filename": name,
                                      "size": size, "sha256": digest, "label": "", "variant": "", "status": "template",
                                      "uploaded_by": "Built-in", "uploaded_at": "", "doc": d})
        out.sort(key=lambda v: v["uploaded_at"], reverse=True)
        return out + sorted(templates, key=lambda v: (v["doc"]["number"] or "~", v["doc"]["title"]))

    def library_doc(self, user, did: str) -> dict:
        cat, rows = builtin_catalog(), self._doc_rows()
        if did not in cat["docs"] and did not in rows:
            raise self._invalid("Document not found")
        versions = self._all_versions().get(did, [])
        d = self._merge_doc(did, cat["docs"].get(did), rows.get(did), versions)
        if not user.sees_everything and not d["current"]:
            raise self._invalid("Document not found")  # staff never learn about unpublished documents
        d["parent_doc"] = cat["docs"].get(d.get("parent", ""))
        d["children"] = [c for c in cat["docs"].values() if c.get("parent") == did]
        return d

    def doc_versions(self, user, did: str) -> dict:
        """Official versions (newest first) and template history, as far as this user may see them."""
        self.library_doc(user, did)
        rows = self._all_versions().get(did, [])
        official = [v for v in rows if v["kind"] == "official" and (user.sees_everything or v["status"] == "approved")]
        templates = [v for v in rows if v["kind"] == "template"] if user.sees_everything else []
        return {"official": official, "templates": templates, "active_template": self._active_template(rows)}

    # ------------------------------------------------------------------ files
    def _store_file(self, actor, did: str, kind: str, filename: str, data: bytes, comment: str) -> dict:
        from grcpal.portal.security import safe_filename, validate_upload

        name = safe_filename(filename)
        if "." + name.rsplit(".", 1)[-1].lower() not in DOC_EXTENSIONS:
            raise self._invalid(f"Use one of: {', '.join(sorted(DOC_EXTENSIONS))}")
        error = validate_upload(name, data)
        if error:
            raise self._invalid(error)
        vid = _new_vid()
        run = self.evidence.new_run("doclib_upload", GOV_CONTROLS, {"uploaded_by": actor.email, "document": did,
                                                                   "kind": kind, "comment": (comment or "")[:2000]})
        taken = set(self.evidence.list_runs("doclib_upload"))
        while run.prefix.split("/", 1)[1] in taken:  # one folder per second, so two uploads never share a manifest
            run.started += dt.timedelta(seconds=1)
        stored = f"{vid[-8:]}_{name}"
        run.add_bytes(stored, data)
        manifest = run.finish([])
        return {"PartitionKey": did, "RowKey": vid, "kind": kind, "filename": name, "stored_name": stored,
                "evidence_run": run.prefix, "sha256": manifest["files"][0]["sha256"], "size": len(data),
                "comment": (comment or "").strip()[:2000], "uploaded_by": actor.email, "uploaded_at": _now()}

    def _need_admin(self, actor, what: str = "change the document library") -> None:
        if not actor.is_admin:
            raise self._forbidden(f"Only admins can {what}")

    def _doc_exists(self, did: str) -> None:
        if did not in builtin_catalog()["docs"] and not self.store.get("docs", "d", did):
            raise self._invalid("Document not found")

    def upload_official(self, actor, did: str, filename: str, data: bytes, variant: str, change: str,
                        comment: str) -> dict:
        self._need_admin(actor, "upload documents")
        self._doc_exists(did)
        if change not in CHANGES:
            raise self._invalid("Say whether this is a major or a minor change")
        variant = " ".join((variant or "").split())[:60]
        same = [v["label"] for v in self.store.list("docversions", did)
                if v["kind"] == "official" and v.get("variant", "") == variant]
        row = self._store_file(actor, did, "official", filename, data, comment)
        row.update(label=bump(same, change), variant=variant, change=change, status="draft", approved_by="",
                   approved_at="", self_approved=False)
        self.store.insert("docversions", row)
        self.audit(actor, "doclib.upload", did, {"controls": GOV_CONTROLS, "version": row["label"], "variant": variant,
                                                 "change": change, "file": row["filename"], "sha256": row["sha256"],
                                                 "run": row["evidence_run"]})
        return row

    def upload_template(self, actor, did: str, filename: str, data: bytes, comment: str) -> dict:
        self._need_admin(actor, "replace templates")
        self._doc_exists(did)
        row = self._store_file(actor, did, "template", filename, data, comment)
        row["builtin"] = False
        self.store.insert("docversions", row)
        self.audit(actor, "doclib.template.replace", did, {"controls": GOV_CONTROLS, "file": row["filename"],
                                                           "sha256": row["sha256"], "run": row["evidence_run"]})
        return row

    def restore_builtin_template(self, actor, did: str) -> dict:
        self._need_admin(actor, "replace templates")
        if not builtin_template(did):
            raise self._invalid("This document has no built-in template")
        vid = _new_vid()
        row = {"PartitionKey": did, "RowKey": vid, "kind": "template", "builtin": True, "filename": "(built-in template)",
               "stored_name": "", "evidence_run": "", "sha256": "", "size": 0, "comment": "Restored the built-in template",
               "uploaded_by": actor.email, "uploaded_at": _now()}
        self.store.insert("docversions", row)
        self.audit(actor, "doclib.template.restore", did, {"controls": GOV_CONTROLS})
        return row

    def doc_file(self, user, did: str, vid: str) -> tuple[str, bytes]:
        """A stored version file. `vid` is a version id, or "template" for the active template."""
        d = self.library_doc(user, did)
        if vid == "template":
            if not user.sees_everything:
                raise self._invalid("File not found")
            active = self._active_template(self._all_versions().get(did, []))
            if not active:
                got = builtin_template(did)
                if not got:
                    raise self._invalid("This document has no template")
                if not user.is_admin:
                    self.audit(user, "doclib.download", did, {"file": got[0], "kind": "template"})
                return got
            v = active
        else:
            v = self.store.get("docversions", did, vid) if _VID.match(vid or "") else None
            if not v or v.get("builtin") or (not user.sees_everything and not (v["kind"] == "official" and v["status"] == "approved")):
                raise self._invalid("File not found")
        source, run = v["evidence_run"].split("/", 1)
        data = self.evidence.read(source, run, v["stored_name"])
        if data is None:
            raise self._invalid("File not found in evidence storage")
        if not user.is_admin:
            self.audit(user, "doclib.download", did, {"file": v["filename"], "sha256": v["sha256"], "kind": v["kind"],
                                                      "title": d["title"][:80]})
        return v["filename"], data

    # ------------------------------------------------------------------ document details
    def edit_doc(self, actor, did: str, fields: dict) -> dict:
        """Change the title and details of a document. The document number never changes."""
        self._need_admin(actor, "edit documents")
        self._doc_exists(did)
        d = self.library_doc(actor, did)
        clean = {}
        if "title" in fields:
            title = " ".join(str(fields["title"] or "").split())
            if not 3 <= len(title) <= 160:
                raise self._invalid("The title must be 3 to 160 characters")
            clean["title"] = title
        for key, limit in (("owner", 80), ("approver", 80)):
            if key in fields:
                clean[key] = " ".join(str(fields[key] or "").split())[:limit]
        if "classification" in fields:
            cls = str(fields["classification"] or "")
            if cls and cls not in CLASSIFICATIONS:
                raise self._invalid("Choose one of the classifications offered")
            clean["classification"] = cls
        if "next_review" in fields:
            nr = str(fields["next_review"] or "").strip()
            if nr:
                try:
                    dt.date.fromisoformat(nr)
                except ValueError:
                    raise self._invalid("Write the review date as YYYY-MM-DD") from None
            clean["next_review"] = nr
        shown = {"owner": d["owner_name"], "approver": d["approver_name"]}  # a role id is shown by its name
        changed = {k: v for k, v in clean.items() if (shown.get(k, d.get(k)) or "") != v}
        if not changed:
            return d
        stamp = {"updated_by": actor.email, "updated_at": _now()}
        row = self.store.get("docs", "d", did)
        if row:
            self.store.update("docs", "d", did, {**changed, **stamp})
        else:
            self.store.insert("docs", {"PartitionKey": "d", "RowKey": did, **changed, **stamp})
        self.audit(actor, "doclib.edit", did, {"controls": GOV_CONTROLS,
                                               "before": {k: d.get(k, "") for k in changed}, "after": changed})
        return self.library_doc(actor, did)

    def add_doc(self, actor, folder: str, number: str, title: str, kind: str = "other") -> dict:
        self._need_admin(actor, "add documents")
        cat = builtin_catalog()
        if folder not in {f["id"] for f in cat["folders"]} | {"other"}:
            raise self._invalid("Choose a folder")
        title = " ".join((title or "").split())
        number = " ".join((number or "").split())[:20]
        if not 3 <= len(title) <= 160:
            raise self._invalid("The title must be 3 to 160 characters")
        if kind not in KINDS:
            kind = "other"
        slug = re.sub(r"[^a-z0-9]+", "-", (number or title).lower()).strip("-")[:24] or "doc"
        did = f"x-{slug}-{uuid.uuid4().hex[:6]}"
        if not _ID.match(did):
            raise self._invalid("Could not make an id for this document")
        row = {"PartitionKey": "d", "RowKey": did, "custom": True, "folder": folder, "number": number, "title": title,
               "kind": kind, "owner": "", "approver": "", "updated_by": actor.email, "updated_at": _now()}
        self.store.insert("docs", row)
        self.audit(actor, "doclib.add", did, {"controls": GOV_CONTROLS, "folder": folder, "number": number, "title": title})
        return self.library_doc(actor, did)

    # ------------------------------------------------------------------ status
    def set_version_status(self, actor, did: str, vid: str, status: str, note: str = "") -> dict:
        """Move an official version through draft, in review, approved or archived. Files never change."""
        self._need_admin(actor, "change the status of a document version")
        v = self.store.get("docversions", did, vid) if _VID.match(vid or "") else None
        if not v or v["kind"] != "official":
            raise self._invalid("Version not found")
        if status not in ("draft", "in_review", "approved", "archived"):
            raise self._invalid("Choose a status")
        old, note = v["status"], (note or "").strip()[:1000]
        allowed = {"draft": {"in_review", "approved", "archived"}, "in_review": {"draft", "approved", "archived"},
                   "approved": {"archived"}, "superseded": {"archived"}, "archived": {"draft"}}
        if status not in allowed.get(old, set()):
            raise self._invalid(f"A {STATUSES[old].lower()} version cannot become {STATUSES[status].lower()}")
        if status in ("draft", "archived") and old != "draft" and not note:
            raise self._invalid("Write a short reason")
        fields = {"status": status, "status_note": note}
        superseded = []
        if status == "approved":
            others = [e for e in self.active_emails("admin") if e != actor.email]
            if v["uploaded_by"] == actor.email and others:
                raise self._forbidden("Another admin must approve a version you uploaded (segregation of duties)")
            fields.update(approved_by=actor.email, approved_at=_now(), self_approved=v["uploaded_by"] == actor.email)
            for other in self.store.list("docversions", did):
                if (other["kind"] == "official" and other["status"] == "approved" and other["RowKey"] != vid
                        and other.get("variant", "") == v.get("variant", "")):
                    self.store.update("docversions", did, other["RowKey"], {"status": "superseded", "superseded_by": v["label"]})
                    superseded.append(other["label"])
        self.store.update("docversions", did, vid, fields)
        self.audit(actor, f"doclib.status.{status}", did, {"controls": GOV_CONTROLS, "version": v["label"],
                                                           "variant": v.get("variant", ""), "from": old, "sha256": v["sha256"],
                                                           "superseded": superseded, "note": note[:300],
                                                           "self_approved": fields.get("self_approved", False)})
        return self.store.get("docversions", did, vid)

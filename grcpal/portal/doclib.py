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
- Trash: deleting a document or removing an old template only hides it (it moves to the Trash page, where an
  admin can restore it). Files stay in the write-once evidence store, so nothing an auditor relies on is ever
  destroyed, and every delete and restore is in the audit log.
- Owner and approver are people (active admins or control owners, by email); the built-in catalog starts with
  a role name until an admin picks a person. The document number shown to people can be edited (it must stay
  unique); the internal id never changes, so versions, acknowledgments and the audit log keep pointing at it.
- A version number is suggested on upload (major 2.0, minor 1.1) and can be typed to match the file. It can be
  corrected while the version is a draft or in review, and is locked once approved.
- Approval, the formal way: an admin presses "Send for approval"; the document's named approver (a person, never
  the uploader or the sender) gets an email and an item in My work, opens the review page, confirms they read the
  version and approves, or denies with a reason. The item closes only when the decision is recorded. Admins can
  withdraw or reassign a request; a reminder goes out every 7 days while it waits.
- Approval, the backup way: an admin approves directly (for example a copy signed inside the document). It still
  needs a different admin than the uploader unless there is no other active admin (then it is marked
  self-approved), and it is recorded as a direct approval so the auditor can tell the two apart.
- Every decision is in the hash-chained audit log and is also written to the write-once evidence store
  (`doclib_approval`, control GOV-01).
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
STATUSES = {"draft": "Draft", "in_review": "Waiting for approval", "approved": "Approved", "superseded": "Superseded",
            "archived": "Archived"}
CHANGES = {"major": "Major (a commitment changed)", "minor": "Minor (wording or formatting)"}
KINDS = {"policy": "Policy", "standard": "Standard", "procedure": "Procedure / plan", "soc2": "SOC 2 document",
         "other": "Other"}
ROLE_NAMES = {"security-lead": "Security lead", "hr-lead": "HR lead", "it-lead": "IT lead",
              "engineering-lead": "Engineering lead", "legal-lead": "Legal lead", "executive-sponsor": "Executive sponsor"}
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
_VID = re.compile(r"^\d{8}T\d{12}-[0-9a-f]{8}$")
_LABEL = re.compile(r"^\d{1,4}(\.\d{1,4}){1,2}$")
_NUMBER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,19}$")
GOV_CONTROLS = ["GOV-01"]
REMIND_DAYS = 7


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
        m = re.match(r"^(\d+)\.(\d+)(?:\.\d+)?$", lab or "")
        if m:
            best = max(best, (int(m.group(1)), int(m.group(2))))
    if best == (0, 0):
        return "1.0"
    return f"{best[0] + 1}.0" if change == "major" else f"{best[0]}.{best[1] + 1}"


def clean_label(raw: str) -> str:
    """A version number typed by a person: "v2.1" or "2.1" becomes "2.1". Two or three numbers only."""
    s = (raw or "").strip()
    if s[:1] in ("v", "V"):
        s = s[1:].strip()
    if not _LABEL.match(s):
        raise ValueError("Write the version as numbers like 1.0, 2.1 or 2.1.3")
    return s


class _Everyone:
    """Read-only viewpoint used for library-wide checks (such as unique numbers); never used for permissions."""
    sees_everything = True


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
        """The newest template entry that is a real upload; a built-in marker (or none) means the shipped file.
        Templates moved to the Trash are skipped."""
        for v in versions:  # newest first
            if v["kind"] == "template" and not v.get("removed_at"):
                return None if v.get("builtin") else v
        return None

    def doc_people(self) -> dict[str, dict]:
        """People who can own or approve a document: active admins and control owners (never auditors)."""
        return {u["RowKey"]: u for u in self.users() if u.get("active", True) and u["role"] in ("admin", "contributor")}

    @staticmethod
    def _who(value: str, people: dict[str, dict]) -> str:
        """How an owner or approver value is shown: a person's name, a built-in role name, or the text as stored."""
        if value in people:
            return people[value].get("name") or value
        return ROLE_NAMES.get(value, value)

    def _merge_doc(self, did: str, base: dict | None, row: dict | None, versions: list[dict],
                   people: dict[str, dict] | None = None) -> dict:
        d = {"id": did, "number": "", "folder": "other", "kind": "other", "title": did, "owner": "", "approver": "",
             "soc2": "", "iso": "", "controls": "", "summary": "", "parent": "", "custom": False, "classification": "",
             "next_review": "", "updated_at": "", "updated_by": ""}
        d.update(base or {})
        d.update({k: v for k, v in (row or {}).items() if k not in ("PartitionKey", "RowKey")})
        d["builtin_title"] = (base or {}).get("title", "")
        people = self.doc_people() if people is None else people
        d["owner_name"], d["approver_name"] = self._who(d["owner"], people), self._who(d["approver"], people)
        d["owner_is_person"], d["approver_is_person"] = d["owner"] in people, d["approver"] in people
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
        cat, rows, versions, people = builtin_catalog(), self._doc_rows(), self._all_versions(), self.doc_people()
        ids = list(cat["docs"]) + [i for i in rows if i not in cat["docs"]]
        docs = []
        for did in ids:
            if (rows.get(did) or {}).get("deleted_at"):
                continue  # in the Trash
            d = self._merge_doc(did, cat["docs"].get(did), rows.get(did), versions.get(did, []), people)
            if not user.sees_everything and not d["current"]:
                continue  # staff only see documents that have an approved official version
            docs.append(d)
        docs.sort(key=lambda d: (d["folder"], d["number"] or "~", d["title"].lower()))
        folders = [{**f, "count": sum(1 for d in docs if d["folder"] == f["id"])} for f in cat["folders"]]
        other = [d for d in docs if d["folder"] not in {f["id"] for f in cat["folders"]}]
        if other or any(r.get("custom") and not r.get("deleted_at") for r in rows.values()):
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
        if (rows.get(did) or {}).get("deleted_at"):
            raise self._invalid("Document not found")  # in the Trash: restore it first
        versions = self._all_versions().get(did, [])
        d = self._merge_doc(did, cat["docs"].get(did), rows.get(did), versions)
        if not user.sees_everything and not d["current"] and not self._waiting_for(user, versions):
            raise self._invalid("Document not found")  # staff never learn about unpublished documents
        d["parent_doc"] = cat["docs"].get(d.get("parent", ""))
        d["children"] = [c for c in cat["docs"].values() if c.get("parent") == did]
        return d

    def doc_versions(self, user, did: str) -> dict:
        """Official versions (newest first) and template history, as far as this user may see them."""
        self.library_doc(user, did)
        rows = self._all_versions().get(did, [])
        official = [v for v in rows if v["kind"] == "official" and (user.sees_everything or v["status"] == "approved"
                                                                    or self._waiting_for(user, [v]))]
        everything = user.sees_everything
        templates = [v for v in rows if v["kind"] == "template" and not v.get("removed_at")] if everything else []
        active = self._active_template(rows)
        builtin = None
        if everything and builtin_template(did):
            name, size, digest = _builtin_facts(did)
            builtin = {"filename": name, "size": size, "sha256": digest, "active": active is None}
        labels = [v["label"] for v in rows if v["kind"] == "official" and not v.get("variant")]
        return {"official": official, "templates": templates, "active_template": active, "builtin": builtin,
                "uploads": [v for v in templates if not v.get("builtin")],
                "removed": [v for v in rows if v["kind"] == "template" and v.get("removed_at")] if everything else [],
                "next": {"major": bump(labels, "major"), "minor": bump(labels, "minor")}}

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
                        comment: str, label: str = "") -> dict:
        self._need_admin(actor, "upload documents")
        self._doc_exists(did)
        if change not in CHANGES:
            raise self._invalid("Say whether this is a major or a minor change")
        variant = " ".join((variant or "").split())[:60]
        same = [v["label"] for v in self.store.list("docversions", did)
                if v["kind"] == "official" and v.get("variant", "") == variant]
        typed = bool((label or "").strip())
        if typed:
            label = self._label(label, same)
        row = self._store_file(actor, did, "official", filename, data, comment)
        row.update(label=label if typed else bump(same, change), variant=variant, change=change, status="draft", approved_by="",
                   approved_at="", self_approved=False)
        self.store.insert("docversions", row)
        self.audit(actor, "doclib.upload", did, {"controls": GOV_CONTROLS, "version": row["label"], "variant": variant,
                                                 "change": change, "file": row["filename"], "sha256": row["sha256"],
                                                 "run": row["evidence_run"], "numbered": "typed" if typed else "auto"})
        return row

    def _label(self, raw: str, taken: list[str]) -> str:
        try:
            label = clean_label(raw)
        except ValueError as exc:
            raise self._invalid(str(exc)) from None
        if label in taken:
            raise self._invalid(f"Version {label} already exists for this document")
        return label

    def set_version_label(self, actor, did: str, vid: str, label: str) -> dict:
        """Correct the version number of a draft or in-review version. Approved versions are locked: the number is
        part of the approval record and the audit log."""
        self._need_admin(actor, "change version numbers")
        v = self.store.get("docversions", did, vid) if _VID.match(vid or "") else None
        if not v or v["kind"] != "official":
            raise self._invalid("Version not found")
        if v["status"] not in ("draft", "in_review"):
            raise self._invalid("The number of an approved version is locked; upload a new version instead")
        taken = [o["label"] for o in self.store.list("docversions", did) if o["kind"] == "official"
                 and o.get("variant", "") == v.get("variant", "") and o["RowKey"] != vid]
        label = self._label(label, taken)
        if label == v["label"]:
            return v
        self.store.update("docversions", did, vid, {"label": label})
        self.audit(actor, "doclib.version.label", did, {"controls": GOV_CONTROLS, "from": v["label"], "to": label,
                                                         "variant": v.get("variant", ""), "sha256": v["sha256"]})
        return self.store.get("docversions", did, vid)

    def upload_template(self, actor, did: str, filename: str, data: bytes, comment: str) -> dict:
        self._need_admin(actor, "replace templates")
        self._doc_exists(did)
        row = self._store_file(actor, did, "template", filename, data, comment)
        row["builtin"] = False
        self.store.insert("docversions", row)
        self.audit(actor, "doclib.template.replace", did, {"controls": GOV_CONTROLS, "file": row["filename"],
                                                           "sha256": row["sha256"], "run": row["evidence_run"]})
        return row

    def rename_template(self, actor, did: str, vid: str, name: str) -> dict:
        """Change the file name a template downloads as. The stored file and its SHA-256 never change."""
        from grcpal.portal.security import safe_filename

        self._need_admin(actor, "rename templates")
        v = self.store.get("docversions", did, vid) if _VID.match(vid or "") else None
        if not v or v["kind"] != "template" or v.get("builtin") or v.get("removed_at"):
            raise self._invalid("Template not found")
        ext = "." + v["filename"].rsplit(".", 1)[-1].lower()
        raw = " ".join((name or "").split())
        if raw and not raw.lower().endswith(ext):
            if "." + raw.rsplit(".", 1)[-1].lower() in DOC_EXTENSIONS:
                raise self._invalid(f"Keep the {ext} ending; the file itself does not change")
            raw += ext
        new = safe_filename(raw) if raw else ""
        if not 1 <= len(new) - len(ext) or len(new) > 120:
            raise self._invalid("The name must be 1 to 120 characters")
        if new == v["filename"]:
            return v
        self.store.update("docversions", did, vid, {"filename": new,
                                                    "original_filename": v.get("original_filename") or v["filename"]})
        self.audit(actor, "doclib.template.rename", did, {"controls": GOV_CONTROLS, "from": v["filename"], "to": new,
                                                          "sha256": v["sha256"]})
        return self.store.get("docversions", did, vid)

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
            visible = v and (user.sees_everything or (v["kind"] == "official" and v["status"] == "approved")
                             or self._waiting_for(user, [v]))
            if not v or v.get("builtin") or not visible:
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
        """Change the details of a document: title, number, description, owner, approver, classification, next
        review. The internal id never changes. Owner and approver must be active people (or the value they already
        have, such as a built-in role name, left as it is)."""
        self._need_admin(actor, "edit documents")
        self._doc_exists(did)
        d = self.library_doc(actor, did)
        clean = {}
        if "title" in fields:
            title = " ".join(str(fields["title"] or "").split())
            if not 3 <= len(title) <= 160:
                raise self._invalid("The title must be 3 to 160 characters")
            clean["title"] = title
        if "number" in fields:
            clean["number"] = self._number(str(fields["number"] or ""), did)
        people = self.doc_people()
        for key, what in (("owner", "owner"), ("approver", "approver")):
            if key in fields:
                value = str(fields[key] or "").strip()
                if value and value != d.get(key, "") and value not in people:
                    raise self._invalid(f"Choose the {what} from the list of active people")
                clean[key] = value
        if "summary" in fields:
            summary = str(fields["summary"] or "").replace("\r\n", "\n").strip()
            if len(summary) > 1000:
                raise self._invalid("The description can be at most 1000 characters")
            clean["summary"] = summary
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
        changed = {k: v for k, v in clean.items() if (d.get(k) or "") != v}
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

    def _number(self, raw: str, did: str = "") -> str:
        """A document number people see (P-05, ISP): letters, digits, space . _ / -, unique in the library.
        Numbers of documents in the Trash stay reserved, so restoring one never creates a clash."""
        number = " ".join(raw.split())
        if not number:
            return ""
        if not _NUMBER.match(number):
            raise self._invalid("The number can have up to 20 letters, digits, spaces and . _ / -")
        cat, rows = builtin_catalog(), self._doc_rows()
        for other in list(cat["docs"]) + [i for i in rows if i not in cat["docs"]]:
            if other == did:
                continue
            row = rows.get(other) or {}
            merged = {**(cat["docs"].get(other) or {}), **row}
            if (merged.get("number") or "").lower() == number.lower():
                where = " (in the Trash)" if row.get("deleted_at") else ""
                raise self._invalid(f"{merged['number']} is already used by {merged.get('title', other)}{where}")
        return number

    # ------------------------------------------------------------------ register
    def document_register(self, user) -> list[dict]:
        """The master list of documents an auditor asks for: one row per document with its owner, approver,
        current version, status and review date. Admins and auditors only."""
        if not user.sees_everything:
            raise self._forbidden("Only admins and auditors can see the document register")
        lib = self.library(user)
        folders = {f["id"]: f["name"] for f in lib["folders"]}
        out = []
        for d in lib["docs"]:
            if d["current"]:
                state = "Approved"
            elif d["pending"]:
                state = "Draft or in review"
            else:
                state = "No version yet"
            out.append({**d, "folder_name": folders.get(d["folder"], d["folder"]), "state": state,
                        "versions": ", ".join(f"v{c['label']}" + (f" ({c['variant']})" if c.get("variant") else "")
                                              for c in d["current"])})
        return out

    def register_xlsx(self, user) -> bytes:
        """The register as an Excel file. Every export is in the audit log."""
        from grcpal import xlsx

        rows = self.document_register(user)
        head = ["Number", "Title", "Folder", "Type", "Owner", "Approver", "Current version", "Status",
                "Pending drafts", "Classification", "Next review", "Last change"]
        table = [[(h, xlsx.HEADER) for h in head]]
        for d in rows:
            table.append([d["number"], d["title"], d["folder_name"], KINDS.get(d["kind"], "Other"), d["owner_name"],
                          d["approver_name"], d["versions"], d["state"], str(d["pending"]), d["classification"],
                          d["next_review"], (d["last_change"] or "")[:10]])
        self.audit(user, "doclib.register.export", "register", {"controls": GOV_CONTROLS, "documents": len(rows)})
        return xlsx.workbook([{"name": "Document register", "rows": table, "freeze_row": 1,
                               "widths": [10, 44, 28, 16, 22, 22, 16, 18, 10, 14, 12, 12]}])

    def add_doc(self, actor, folder: str, number: str, title: str, kind: str = "other") -> dict:
        self._need_admin(actor, "add documents")
        cat = builtin_catalog()
        if folder not in {f["id"] for f in cat["folders"]} | {"other"}:
            raise self._invalid("Choose a folder")
        title = " ".join((title or "").split())
        number = self._number(number or "")
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

    # ------------------------------------------------------------------ trash
    def trash_docs(self, actor, ids: list[str], reason: str = "") -> list[str]:
        """Move documents to the Trash. They disappear from the library for everyone; their files stay in the
        write-once evidence store, and an admin can restore them from the Trash page."""
        self._need_admin(actor, "delete documents")
        ids = list(dict.fromkeys(i for i in ids if i))
        if not ids:
            raise self._invalid("Tick at least one document to delete")
        if len(ids) > 200:
            raise self._invalid("Delete at most 200 documents at a time")
        rows, done = self._doc_rows(), []
        for did in ids:
            d = self.library_doc(actor, did)  # also refuses unknown ids and ones already in the Trash
            stamp = {"deleted_at": _now(), "deleted_by": actor.email, "deleted_reason": (reason or "").strip()[:500]}
            if did in rows:
                self.store.update("docs", "d", did, stamp)
            else:
                self.store.insert("docs", {"PartitionKey": "d", "RowKey": did, **stamp})
            self.audit(actor, "doclib.delete", did, {"controls": GOV_CONTROLS, "title": d["title"][:160],
                                                     "number": d["number"], "approved_versions": len(d["current"]),
                                                     "reason": stamp["deleted_reason"]})
            done.append(did)
        return done

    def restore_doc(self, actor, did: str) -> dict:
        self._need_admin(actor, "restore documents")
        row = self.store.get("docs", "d", did) if _ID.match(did or "") or did in builtin_catalog()["docs"] else None
        if not row or not row.get("deleted_at"):
            raise self._invalid("That document is not in the Trash")
        self.store.update("docs", "d", did, {"deleted_at": "", "deleted_by": "", "deleted_reason": ""})
        self.audit(actor, "doclib.restore", did, {"controls": GOV_CONTROLS, "deleted_at": row["deleted_at"]})
        return self.library_doc(actor, did)

    def remove_template(self, actor, did: str, vid: str) -> dict:
        """Take an old template out of the list (to the Trash). The active one falls back to the next newest."""
        self._need_admin(actor, "remove templates")
        self.library_doc(actor, did)
        v = self.store.get("docversions", did, vid) if _VID.match(vid or "") else None
        if not v or v["kind"] != "template" or v.get("removed_at"):
            raise self._invalid("Template not found")
        self.store.update("docversions", did, vid, {"removed_at": _now(), "removed_by": actor.email})
        self.audit(actor, "doclib.template.remove", did, {"controls": GOV_CONTROLS, "file": v["filename"],
                                                          "sha256": v.get("sha256", "")})
        return v

    def restore_template(self, actor, did: str, vid: str) -> dict:
        self._need_admin(actor, "restore templates")
        v = self.store.get("docversions", did, vid) if _VID.match(vid or "") else None
        if not v or v["kind"] != "template" or not v.get("removed_at"):
            raise self._invalid("That template is not in the Trash")
        self.store.update("docversions", did, vid, {"removed_at": "", "removed_by": ""})
        self.audit(actor, "doclib.template.restore_from_trash", did, {"controls": GOV_CONTROLS, "file": v["filename"]})
        return v

    def library_trash(self, user) -> dict:
        """What is in the Trash: deleted documents and removed templates (admins and auditors)."""
        if not user.sees_everything:
            raise self._forbidden("Only admins and auditors can see the Trash")
        cat, rows, versions = builtin_catalog(), self._doc_rows(), self._all_versions()
        docs = []
        for did, row in rows.items():
            if row.get("deleted_at"):
                d = self._merge_doc(did, cat["docs"].get(did), row, versions.get(did, []))
                docs.append(d)
        templates = []
        for did, rs in versions.items():
            if (rows.get(did) or {}).get("deleted_at"):
                continue  # shown with its document
            for v in rs:
                if v["kind"] == "template" and v.get("removed_at"):
                    base = cat["docs"].get(did) or rows.get(did) or {}
                    templates.append({**v, "doc_title": base.get("title", did), "doc_number": base.get("number", "")})
        docs.sort(key=lambda d: d["deleted_at"], reverse=True)
        templates.sort(key=lambda v: v["removed_at"], reverse=True)
        return {"docs": docs, "templates": templates}

    # ------------------------------------------------------------------ status
    def set_version_status(self, actor, did: str, vid: str, status: str, note: str = "") -> dict:
        """Admin changes: approve directly (the backup to the approval workflow), return to draft, archive, restore.
        "Waiting for approval" is only reached through request_approval. Files never change."""
        self._need_admin(actor, "change the status of a document version")
        v = self.store.get("docversions", did, vid) if _VID.match(vid or "") else None
        if not v or v["kind"] != "official":
            raise self._invalid("Version not found")
        if status == "in_review":
            raise self._invalid("Use Send for approval: it needs the document's approver")
        if status not in ("draft", "approved", "archived"):
            raise self._invalid("Choose a status")
        old, note = v["status"], (note or "").strip()[:1000]
        allowed = {"draft": {"approved", "archived"}, "in_review": {"draft", "approved", "archived"},
                   "approved": {"archived"}, "superseded": {"archived"}, "archived": {"draft"}}
        if status not in allowed.get(old, set()):
            raise self._invalid(f"A {STATUSES[old].lower()} version cannot become {STATUSES[status].lower()}")
        if status in ("draft", "archived") and old != "draft" and not note:
            raise self._invalid("Write a short reason")
        if status == "approved":
            others = [e for e in self.active_emails("admin") if e != actor.email]
            if v["uploaded_by"] == actor.email and others:
                raise self._forbidden("Another admin must approve a version you uploaded (segregation of duties)")
            return self._approve(actor, did, v, "direct", note, self_approved=v["uploaded_by"] == actor.email)
        waiting = old == "in_review" and v.get("approval_approver")
        self.store.update("docversions", did, vid, {"status": status, "status_note": note})
        self.audit(actor, f"doclib.status.{status}", did, {"controls": GOV_CONTROLS, "version": v["label"],
                                                           "variant": v.get("variant", ""), "from": old,
                                                           "sha256": v["sha256"], "note": note[:300]})
        if waiting:
            self._approval_mail("closed", v["approval_approver"], actor, did, v, note)
        return self.store.get("docversions", did, vid)

    def _approve(self, actor, did: str, v: dict, method: str, note: str, self_approved: bool = False,
                 read_confirmed: bool = False) -> dict:
        """Record an approval (workflow or direct): supersede the earlier approved version of the same variant,
        audit it, keep a write-once evidence record, tell the people involved."""
        vid, old = v["RowKey"], v["status"]
        fields = {"status": "approved", "status_note": note, "approved_by": actor.email, "approved_at": _now(),
                  "self_approved": self_approved, "approval_method": method, "decision_note": note,
                  "read_confirmed": read_confirmed}
        superseded = []
        for other in self.store.list("docversions", did):
            if (other["kind"] == "official" and other["status"] == "approved" and other["RowKey"] != vid
                    and other.get("variant", "") == v.get("variant", "")):
                self.store.update("docversions", did, other["RowKey"], {"status": "superseded", "superseded_by": v["label"]})
                superseded.append(other["label"])
        self.store.update("docversions", did, vid, fields)
        detail = {"controls": GOV_CONTROLS, "version": v["label"], "variant": v.get("variant", ""), "from": old,
                  "sha256": v["sha256"], "superseded": superseded, "note": note[:300], "method": method,
                  "self_approved": self_approved, "uploaded_by": v["uploaded_by"],
                  "named_approver": v.get("approval_approver", ""), "read_confirmed": read_confirmed}
        self.audit(actor, "doclib.status.approved", did, detail)
        self._approval_evidence(actor, did, v, "approved", detail)
        waiting_on = v.get("approval_approver", "") if old == "in_review" else ""
        if waiting_on and waiting_on != actor.email:
            self._approval_mail("closed", waiting_on, actor, did, v, note or "Approved directly by an admin")
        self._approval_mail("approved", [v["uploaded_by"], v.get("approval_requested_by", "")], actor, did, v, note)
        return self.store.get("docversions", did, vid)

    # ------------------------------------------------------------------ approval workflow
    @staticmethod
    def _waiting_for(user, versions: list[dict]) -> bool:
        """True when one of these versions is waiting for this user's approval."""
        return any(v.get("kind") == "official" and v.get("status") == "in_review"
                   and v.get("approval_approver") == user.email for v in versions)

    def _pending_version(self, did: str, vid: str) -> dict:
        v = self.store.get("docversions", did, vid) if _VID.match(vid or "") else None
        if not v or v["kind"] != "official":
            raise self._invalid("Version not found")
        return v

    def _check_approver(self, email: str, v: dict, actor) -> str:
        email = (email or "").strip().lower()
        if email not in self.doc_people():
            raise self._invalid("Set the document's approver to an active person first (Details > Edit)")
        if email in (v["uploaded_by"], actor.email):
            raise self._invalid("The approver cannot be the person who uploaded or sends the version")
        return email

    def request_approval(self, actor, did: str, vid: str, note: str = "") -> dict:
        """Send a draft to the document's named approver: email, My work item, audit."""
        self._need_admin(actor, "send documents for approval")
        d = self.library_doc(actor, did)
        v = self._pending_version(did, vid)
        if v["status"] != "draft":
            raise self._invalid("Only a draft can be sent for approval")
        approver = self._check_approver(d.get("approver", ""), v, actor)
        note = (note or "").strip()[:1000]
        fields = {"status": "in_review", "status_note": "", "approval_approver": approver, "approval_requested_by": actor.email,
                  "approval_requested_at": _now(), "approval_reminded_at": "", "approval_note": note}
        self.store.update("docversions", did, vid, fields)
        self.audit(actor, "doclib.approval.request", did, {"controls": GOV_CONTROLS, "version": v["label"],
                                                           "variant": v.get("variant", ""), "approver": approver,
                                                           "sha256": v["sha256"], "note": note[:300]})
        v = self.store.get("docversions", did, vid)
        self._approval_mail("request", approver, actor, did, v, note)
        return v

    def decide_approval(self, user, did: str, vid: str, decision: str, note: str = "", read: bool = False) -> dict:
        """The named approver approves (after confirming they read it) or denies (with a reason)."""
        v = self._pending_version(did, vid)
        if v["status"] != "in_review" or not v.get("approval_approver"):
            raise self._invalid("This version is not waiting for approval any more")
        if v["approval_approver"] != user.email or user.is_auditor:
            raise self._forbidden("Only the approver named on this request can decide it")
        if user.email in (v["uploaded_by"], v.get("approval_requested_by")):
            raise self._forbidden("You cannot approve a version you uploaded or sent (segregation of duties)")
        note = (note or "").strip()[:1000]
        if decision == "approve":
            if not read:
                raise self._invalid(f"Confirm that you have read version {v['label']}")
            return self._approve(user, did, v, "workflow", note, read_confirmed=True)
        if decision != "deny":
            raise self._invalid("Choose approve or deny")
        if not note:
            raise self._invalid("Write why you deny it, so the author knows what to change")
        self.store.update("docversions", did, vid, {"status": "draft", "status_note": note, "decision_note": note,
                                                    "denied_by": user.email, "denied_at": _now()})
        detail = {"controls": GOV_CONTROLS, "version": v["label"], "variant": v.get("variant", ""),
                  "sha256": v["sha256"], "note": note[:300]}
        self.audit(user, "doclib.approval.deny", did, detail)
        self._approval_evidence(user, did, v, "denied", detail)
        self._approval_mail("denied", [v["uploaded_by"], v.get("approval_requested_by", "")], user, did, v, note)
        return self.store.get("docversions", did, vid)

    def withdraw_approval(self, actor, did: str, vid: str, note: str = "") -> dict:
        self._need_admin(actor, "withdraw approval requests")
        v = self._pending_version(did, vid)
        if v["status"] != "in_review":
            raise self._invalid("This version is not waiting for approval")
        note = (note or "").strip()[:1000] or "Withdrawn by an admin"
        self.store.update("docversions", did, vid, {"status": "draft", "status_note": note})
        self.audit(actor, "doclib.approval.withdraw", did, {"controls": GOV_CONTROLS, "version": v["label"],
                                                            "approver": v.get("approval_approver", ""), "note": note[:300]})
        if v.get("approval_approver"):
            self._approval_mail("closed", v["approval_approver"], actor, did, v, note)
        return self.store.get("docversions", did, vid)

    def reassign_approval(self, actor, did: str, vid: str, approver: str) -> dict:
        self._need_admin(actor, "reassign approval requests")
        v = self._pending_version(did, vid)
        if v["status"] != "in_review":
            raise self._invalid("This version is not waiting for approval")
        new = self._check_approver(approver, v, actor)
        old = v.get("approval_approver", "")
        if new == old:
            return v
        self.store.update("docversions", did, vid, {"approval_approver": new, "approval_requested_at": _now(),
                                                    "approval_reminded_at": ""})
        self.audit(actor, "doclib.approval.reassign", did, {"controls": GOV_CONTROLS, "version": v["label"],
                                                            "from": old, "to": new})
        v = self.store.get("docversions", did, vid)
        if old:
            self._approval_mail("closed", old, actor, did, v, f"Reassigned to {self._who(new, self.doc_people())}")
        self._approval_mail("request", new, actor, did, v, v.get("approval_note", ""))
        return v

    def approval_view(self, user, did: str, vid: str) -> dict:
        """What the review page shows: the document, this version and the current approved version of the same
        variant (to compare). Admins and auditors see any request; anyone else only one addressed to them."""
        d = self.library_doc(user, did)
        v = self._pending_version(did, vid)
        if not user.sees_everything and v.get("approval_approver") != user.email:
            raise self._invalid("Version not found")
        current = next((c for c in d["current"] if c.get("variant", "") == v.get("variant", "") and c["RowKey"] != vid), None)
        people = self.doc_people()
        return {"d": d, "v": v, "current": current, "approver_name": self._who(v.get("approval_approver", ""), people),
                "can_decide": (v["status"] == "in_review" and v.get("approval_approver") == user.email
                               and not user.is_auditor and user.email not in (v["uploaded_by"], v.get("approval_requested_by")))}

    def pending_approvals(self, user) -> dict:
        """For My work: versions waiting for this user, and (for admins) every request still waiting."""
        cat, rows, people = builtin_catalog(), self._doc_rows(), self.doc_people()
        mine, waiting = [], []
        for did, versions in self._all_versions().items():
            if (rows.get(did) or {}).get("deleted_at"):
                continue
            for v in versions:
                if v["kind"] != "official" or v["status"] != "in_review" or not v.get("approval_approver"):
                    continue
                base = {**(cat["docs"].get(did) or {}), **(rows.get(did) or {})}
                item = {**v, "doc_id": did, "doc_title": base.get("title", did), "doc_number": base.get("number", ""),
                        "approver_name": self._who(v["approval_approver"], people),
                        "days": self._days_since(v.get("approval_requested_at", ""))}
                if v["approval_approver"] == user.email:
                    mine.append(item)
                elif user.is_admin:
                    waiting.append(item)
        key = lambda x: x.get("approval_requested_at", "")  # noqa: E731
        return {"mine": sorted(mine, key=key), "waiting": sorted(waiting, key=key)}

    def _days_since(self, stamp: str) -> int:
        try:
            return max(0, (self.today - dt.date.fromisoformat(stamp[:10])).days)
        except ValueError:
            return 0

    def send_approval_reminders(self, actor) -> list[dict]:
        """Daily (after the scheduled collection): remind approvers of requests waiting REMIND_DAYS or more,
        at most once every REMIND_DAYS days per request."""
        out = []
        for did, versions in self._all_versions().items():
            if (self.store.get("docs", "d", did) or {}).get("deleted_at"):
                continue
            for v in versions:
                if v["kind"] != "official" or v["status"] != "in_review" or not v.get("approval_approver"):
                    continue
                last = v.get("approval_reminded_at") or v.get("approval_requested_at", "")
                if self._days_since(last) < REMIND_DAYS:
                    continue
                self.store.update("docversions", did, v["RowKey"], {"approval_reminded_at": self.today.isoformat()})
                sent = self._approval_mail("reminder", v["approval_approver"], actor, did, v, v.get("approval_note", ""))
                self.audit(actor, "doclib.approval.remind", did, {"controls": GOV_CONTROLS, "version": v["label"],
                                                                  "approver": v["approval_approver"],
                                                                  "waiting_days": self._days_since(v.get("approval_requested_at", ""))})
                out.append({"doc": did, "version": v["label"], "sent": sent})
        return out

    def _approval_evidence(self, actor, did: str, v: dict, decision: str, detail: dict) -> None:
        """A small write-once record of the decision next to the file it is about."""
        run = self.evidence.new_run("doclib_approval", GOV_CONTROLS, {"document": did, "decision": decision,
                                                                     "by": actor.email})
        taken = set(self.evidence.list_runs("doclib_approval"))
        while run.prefix.split("/", 1)[1] in taken:
            run.started += dt.timedelta(seconds=1)
        run.add("decision", {"document": did, "file": v["filename"], "decision": decision, "by": actor.email,
                                  "at": _now(), **{k: x for k, x in detail.items() if k != "controls"}})
        run.finish([])

    def _approval_mail(self, kind: str, to, actor, did: str, v: dict, note: str) -> list[str]:
        from grcpal.portal import notify

        d = {**(builtin_catalog()["docs"].get(did) or {}), **(self.store.get("docs", "d", did) or {})}
        recipients = [to] if isinstance(to, str) else list(to)
        content = notify.doc_approval(self, kind, d.get("number", ""), d.get("title", did), did, v, note, actor)
        return self._notify("doc_approval", [r for r in recipients if r], actor, content, GOV_CONTROLS)


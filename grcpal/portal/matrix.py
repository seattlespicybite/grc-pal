"""Control matrix: export the whole control set to a spreadsheet, edit it in bulk, import it back; and a
read-only report (print to PDF, or Word).

Two different files on purpose:
- The data file (.xlsx) is a strict template that round-trips. Its look never changes, so it never breaks
  the import. A hidden "About" sheet records the organization, the export time and a fingerprint of every
  control, so the import can refuse files from another organization and spot rows that changed in GRC-pal
  after the export (conflicts).
- The report is for people (leadership, auditors). It can change its look freely; it is never imported.

Import rules (every rule and permission check lives here; routes only parse forms):
- Only the control library owner imports. Admins and auditors download. Control owners see neither.
- Two steps: upload -> preview (nothing changes) -> apply. Apply re-reads the stored file and refuses if
  anything changed since the preview.
- Each changed row goes through the same functions as the edit forms (`save_control_definition`,
  `save_custom_control`), so the same validation, version history and audit entries apply. Every row is
  validated (dry run) before the first write, so a business-rule failure cannot stop an import half way.
- Rows missing from the file are left alone. Nothing is ever deleted; custom controls can be retired by
  setting Status to "retired". Built-in controls cannot be retired.
- The uploaded file and the result are kept as write-once evidence (`control_matrix_import`,
  `control_matrix_apply`), so an auditor can see exactly what was imported, by whom, why, and what changed.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import secrets

from grcpal import frameworks as fw_mod
from grcpal import xlsx

FORMAT = "grcpal-control-matrix"
TEMPLATE_VERSION = "1"
SOURCE_IMPORT = "control_matrix_import"
SOURCE_APPLY = "control_matrix_apply"
EVIDENCE_CONTROLS = ["GOV-01"]
PENDING_HOURS = 24
DATA_SHEET, HELP_SHEET, META_SHEET = "Controls", "How to edit", "About"
STATUSES = ("active", "retired")

# (key, header). Headers are how the import finds columns, so users may reorder columns or add their own.
EDIT_COLS = [("id", "Control ID"), ("title", "Title"), ("description", "Description (how it operates)"),
             ("owner", "Owner role"), ("owner_emails", "Owner emails"), ("frequency", "Frequency"),
             ("type", "Type (read only)"), ("status", "Status")]
INFO_COLS = [("pof", "Points of focus (read only)"), ("evidence", "Evidence (read only)"),
             ("source", "Source (read only)")]
FIELD_LABELS = {"title": "Title", "description": "Description", "owner": "Owner role", "owner_emails": "Owner emails",
                "frequency": "Frequency", "status": "Status"}
_FW_HEADER = re.compile(r"\[([a-z0-9][a-z0-9-]{0,39})\]\s*$")
_SPLIT = re.compile(r"[;,\n]+")
_EMAIL_SPLIT = re.compile(r"[;,\s]+")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _ids(text: str) -> list[str]:
    return list(dict.fromkeys(x.strip() for x in _SPLIT.split(text or "") if x.strip()))


def _emails(text: str) -> list[str]:
    return sorted({x.strip().lower() for x in _EMAIL_SPLIT.split(text or "") if x.strip()})


def _hash(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def fw_label(fw) -> str:
    short = fw.name.split(" (")[0].split(":")[0]
    return f"{short}{' criteria' if fw.id == 'soc2' else ''} [{fw.id}]"


class MatrixMixin:
    # ================================================================ access
    def _matrix_reader(self, user) -> None:
        if not user.sees_everything:
            raise self._forbidden("Only admins and auditors can download the control matrix")

    # ================================================================ the controls, as the matrix shows them
    def _pof_by_control(self) -> dict[str, list[tuple[str, str]]]:
        out: dict[str, list[tuple[str, str]]] = {}
        for crit in sorted(self.base_catalog.points_of_focus):
            for p in self.base_catalog.points_of_focus.get(crit) or []:
                for cid in p.get("controls") or []:
                    out.setdefault(cid, []).append((str(p.get("id", "")), str(p.get("point", ""))))
        return out

    def _custom_state(self, row: dict) -> dict:
        return {k: row.get(k) for k in ("title", "description", "owner", "owner_emails", "frequency", "mappings",
                                         "evidence", "links", "status")}

    def matrix_controls(self) -> list[dict]:
        """Every active control (built in and custom) with the fields the matrix shows, in catalog order."""
        in_use = self.frameworks_in_use
        pof = self._pof_by_control()
        out = []
        for c in self.catalog.controls:
            cid = c["id"]
            if c.get("custom"):
                row = self.custom_control(cid) or {}
                maps = {fid: list((row.get("mappings") or {}).get(fid, [])) for fid in in_use}
                stamp = _hash(self._custom_state(row))
                text = {"title": row.get("title", ""), "description": row.get("description", ""),
                        "owner": row.get("owner", ""), "owner_emails": list(row.get("owner_emails") or [])}
            else:
                d = self.control_definition(cid)
                maps = d["mappings"]
                stamp = _hash(d)
                text = {k: d[k] for k in ("title", "description", "owner", "owner_emails")}
            out.append({"id": cid, **text, "frequency": c.get("frequency", ""), "type": c.get("type", ""),
                        "status": "active", "mappings": maps, "custom": bool(c.get("custom")),
                        "pof": pof.get(cid, []), "evidence": [str(e.get("artifact", "")) for e in c.get("evidence") or []],
                        "stamp": stamp[:20], "edited": c.get("edited")})
        return out

    # ================================================================ data file (export)
    def matrix_xlsx(self, user) -> bytes:
        """The round-trip data file. Admins and auditors; every download is in the audit log."""
        self._matrix_reader(user)
        in_use = self.frameworks_in_use
        rows = self.matrix_controls()
        head = [label for _, label in EDIT_COLS] + [fw_label(fw) for fw in in_use.values()] + \
               [label for _, label in INFO_COLS]
        table = [[(h, xlsx.HEADER) for h in head]]
        for r in rows:
            table.append([(r["id"], xlsx.LOCKED), (r["title"], xlsx.ANSWER), (r["description"], xlsx.ANSWER),
                          (r["owner"], xlsx.ANSWER), ("; ".join(r["owner_emails"]), xlsx.ANSWER),
                          (r["frequency"], xlsx.ANSWER if r["custom"] else xlsx.LOCKED), (r["type"], xlsx.LOCKED),
                          (r["status"], xlsx.ANSWER)]
                         + [("; ".join(r["mappings"].get(fid, [])), xlsx.ANSWER) for fid in in_use]
                         # IDs only and one line per cell, so rows stay short; the report has the full text
                         + [("; ".join(i for i, _ in r["pof"]), xlsx.LOCKED),
                            ("; ".join(r["evidence"]), xlsx.LOCKED),
                            ("Custom" if r["custom"] else "Built-in", xlsx.LOCKED)])
        last = len(rows) + 200  # room for new rows
        freq_col, status_col = xlsx.col_letter(6), xlsx.col_letter(8)
        widths = [12, 40, 70, 18, 30, 12, 12, 10] + [26] * len(in_use) + [44, 44, 12]
        now = _now()
        meta = [[("Key", xlsx.HEADER), ("Value", xlsx.HEADER), ("Fingerprint", xlsx.HEADER)],
                ["format", FORMAT], ["template_version", TEMPLATE_VERSION], ["tenant", self.store.tenant],
                ["organization", self.org], ["exported_at", now], ["exported_by", user.email],
                ["frameworks", ";".join(in_use)]]
        meta += [["stamp", r["id"], r["stamp"]] for r in rows]
        help_rows = [[("How to edit this control matrix", xlsx.TITLE)], [""]] + [[(t, xlsx.TEXT)] for t in (
            "1. Edit the white cells on the Controls sheet. Grey columns marked (read only) are ignored on import.",
            "2. One row is one control. Do not change the Control ID of an existing control.",
            "3. Separate several framework requirements or owner emails with a semicolon, e.g. CC6.1; CC6.2.",
            "4. Owner role must be a role from roles.yaml; Owner emails become Control owners in GRC-pal.",
            "5. To add a custom control, add a row with a new Control ID (capital letters, digits, dots, hyphens).",
            "6. To retire a custom control, set Status to retired. Built-in controls cannot be retired.",
            "7. Rows you delete from this file are NOT deleted in GRC-pal. Nothing is ever deleted by an import.",
            "8. Frequency can be changed for custom controls only. Do not type formulas.",
            "9. Upload the file on the Control matrix page. You will see every change before anything is saved.",
            f"Exported {now[:16].replace('T', ' ')} UTC by {user.email} for {self.org}.")]
        self.audit(user, "control.matrix.export", "control-matrix",
                   {"controls": [r["id"] for r in rows][:500], "count": len(rows), "frameworks": list(in_use)})
        return xlsx.workbook([
            {"name": DATA_SHEET, "rows": table, "freeze_row": 1, "widths": widths,
             "lists": [(f"{freq_col}2:{freq_col}{last}", ["continuous", "daily", "weekly", "monthly", "quarterly",
                                                          "annual", "event"]),
                       (f"{status_col}2:{status_col}{last}", list(STATUSES))]},
            {"name": HELP_SHEET, "rows": help_rows, "widths": [110]},
            {"name": META_SHEET, "rows": meta, "widths": [18, 40, 24], "hidden": True}])

    # ================================================================ import: read and compare
    def _matrix_plan(self, actor, data: bytes) -> dict:
        """Read an uploaded data file and work out every change, without saving anything."""
        from grcpal.portal.service import Invalid  # imported here: service imports this module
        try:
            sheets = xlsx.read_values(data)
        except xlsx.ReadError as exc:
            raise self._invalid(str(exc)) from exc
        meta_rows = sheets.get(META_SHEET)
        if meta_rows is None or DATA_SHEET not in sheets:
            raise self._invalid("This is not a GRC-pal control matrix file. Download the data file from the "
                                "Control matrix page, edit it, and upload that file (keep the sheet names).")
        meta, stamps = {}, {}
        for r in meta_rows[1:]:
            r = (r + ["", "", ""])[:3]
            if r[0] == "stamp":
                stamps[r[1].strip().upper()] = r[2].strip()
            elif r[0]:
                meta[r[0].strip()] = r[1].strip()
        if meta.get("format") != FORMAT:
            raise self._invalid("This is not a GRC-pal control matrix file.")
        if meta.get("template_version") != TEMPLATE_VERSION:
            raise self._invalid("This file was made by a different version of GRC-pal. Download a fresh data file.")
        if meta.get("tenant") != self.store.tenant:
            raise self._invalid("This file was exported from a different organization in GRC-pal. Download the "
                                "data file from this organization and edit that one.")
        rows = sheets[DATA_SHEET]
        if not rows:
            raise self._invalid("The Controls sheet is empty.")
        header = [h.strip() for h in rows[0]]
        cols: dict[str, int] = {}
        labels = {label.lower(): key for key, label in EDIT_COLS}
        for i, h in enumerate(header):
            m = _FW_HEADER.search(h)
            if m:
                cols[f"fw:{m.group(1)}"] = i
            elif h.lower() in labels:
                cols[labels[h.lower()]] = i
        in_use = self.frameworks_in_use
        need = ["id", "title", "description", "owner", "owner_emails", "frequency", "status"] + \
               [f"fw:{f}" for f in in_use]
        missing = [k for k in need if k not in cols]
        if missing:
            names = dict(EDIT_COLS) | {f"fw:{f}": fw_label(fw) for f, fw in in_use.items()}
            raise self._invalid("Columns missing from the Controls sheet: " + ", ".join(names[k] for k in missing)
                                + ". Download a fresh data file (frameworks switched on may have changed).")
        warnings: list[str] = []
        off = sorted(k[3:] for k in cols if k.startswith("fw:") and k[3:] not in in_use)
        if off:
            warnings.append(f"Columns for frameworks not switched on are ignored: {', '.join(off)}.")

        current = {c["id"]: c for c in self.matrix_controls()}
        retired = {r["RowKey"] for r in self.custom_controls() if r.get("status") == "retired"}
        labels_fw = {f"map:{f}": fw.name.split(" (")[0].split(":")[0] for f, fw in in_use.items()}
        changes, errors, seen = [], [], set()
        unchanged = 0
        for n, raw in enumerate(rows[1:], 2):
            cell = {k: (raw[i].strip() if i < len(raw) else "") for k, i in cols.items()}
            if not any(cell.values()):
                continue
            cid = cell["id"].upper()
            where = f"Row {n} ({cid or 'no ID'})"
            if not cid:
                errors.append(f"Row {n}: Control ID is empty.")
                continue
            if cid in seen:
                errors.append(f"{where}: this Control ID appears more than once in the file.")
                continue
            seen.add(cid)
            status = (cell["status"] or "active").lower()
            if status not in STATUSES:
                errors.append(f"{where}: Status must be active or retired.")
                continue
            if cid in retired:
                errors.append(f"{where}: this custom control is retired. Restore it in GRC-pal first.")
                continue
            new = {"title": cell["title"], "description": cell["description"], "owner": cell["owner"],
                   "owner_emails": _emails(cell["owner_emails"]),
                   "mappings": {f: _ids(cell[f"fw:{f}"]) for f in in_use}}
            cur = current.get(cid)
            if cur is None:
                if status == "retired":
                    errors.append(f"{where}: a new control cannot be created as retired.")
                    continue
                freq = (cell["frequency"] or "annual").lower()
                old_shown = dict.fromkeys(self._shown(new, freq), "")
                action = "create"
            else:
                if cur["custom"]:
                    freq = (cell["frequency"] or cur["frequency"]).lower()
                else:
                    if cell["frequency"] and cell["frequency"].lower() != cur["frequency"]:
                        warnings.append(f"{where}: Frequency of built-in controls cannot be changed by import; ignored.")
                    freq = cur["frequency"]
                old_shown = self._shown(cur, cur["frequency"])
                action = "update"
                if status == "retired":
                    if not cur["custom"]:
                        errors.append(f"{where}: built-in controls cannot be retired.")
                        continue
                    action = "retire"
            new_shown = self._shown(new, freq)
            diff = [{"key": k, "field": FIELD_LABELS.get(k) or labels_fw.get(k, k), "old": old_shown.get(k, ""),
                     "new": v} for k, v in new_shown.items() if old_shown.get(k, "") != v]
            if action == "retire":
                diff = [{"key": "status", "field": "Status", "old": "active", "new": "retired"}]
            elif action == "update" and not diff:
                unchanged += 1
                continue
            if action != "create" and stamps.get(cid) != cur["stamp"]:
                by = (cur.get("edited") or {}).get("by")
                errors.append(f"{where}: this control was changed in GRC-pal after the file was exported"
                              + (f" (by {by})" if by else "") + ". Download a fresh file and make your edit again.")
                continue
            try:
                if action == "create":
                    self.save_custom_control(actor, self._custom_form(new, freq, None, cid), dry_run=True)
                elif action == "update" and cur["custom"]:
                    self.save_custom_control(actor, self._custom_form(new, freq, cid), existing_id=cid, dry_run=True)
                elif action == "update":
                    self.save_control_definition(actor, cid, self._builtin_form(cid, new), dry_run=True)
            except Invalid as exc:
                errors.append(f"{where}: {exc}")
                continue
            changes.append({"id": cid, "action": action, "title": new["title"] or (cur or {}).get("title", ""),
                            "custom": action == "create" or bool(cur and cur["custom"]), "fields": diff,
                            "data": {**new, "frequency": freq}})
        # Coverage after the whole import: in-scope SOC 2 criteria that lose their last control.
        gaps = []
        if "soc2" in in_use and changes:
            final = {cid: list(c["mappings"].get("soc2", [])) for cid, c in current.items()}
            for ch in changes:
                if ch["action"] == "retire":
                    final.pop(ch["id"], None)
                else:
                    final[ch["id"]] = ch["data"]["mappings"].get("soc2", [])
            covered_now = {x for ids in (c["mappings"].get("soc2", []) for c in current.values()) for x in ids}
            covered_after = {x for ids in final.values() for x in ids}
            gaps = [c for c in self.catalog.in_scope_criteria if c in covered_now and c not in covered_after]
        plan_hash = _hash(changes)[:24]
        return {"changes": changes, "errors": errors, "warnings": warnings, "gaps": gaps, "unchanged": unchanged,
                "plan_hash": plan_hash, "exported_at": meta.get("exported_at", ""),
                "exported_by": meta.get("exported_by", "")}

    @staticmethod
    def _shown(c: dict, frequency: str) -> dict:
        """The editable fields as text, to compare and to show in the preview."""
        out = {"title": c["title"], "description": (c.get("description") or "").strip(), "owner": c.get("owner", ""),
               "owner_emails": "; ".join(c.get("owner_emails") or []), "frequency": frequency}
        for fid, ids in sorted((c.get("mappings") or {}).items()):
            out[f"map:{fid}"] = "; ".join(ids)
        return out

    def _builtin_form(self, cid: str, new: dict) -> dict:
        d = self.control_definition(cid)
        form = {"title": new["title"], "description": new["description"], "owner": new["owner"],
                "owner_emails": ", ".join(new["owner_emails"]),
                "extra_evidence": "\n".join(d["extra_evidence"]),  # not in the file: keep as it is
                "reason": "Control matrix import (preview)", "confirm_uncovered": "yes"}
        for fid, ids in new["mappings"].items():
            form[f"map_{fid}"] = ", ".join(ids)
        return form

    def _custom_form(self, new: dict, frequency: str, cid: str | None, create_id: str = "") -> dict:
        row = (self.custom_control(cid) if cid else None) or {}
        form = {"id": create_id, "title": new["title"], "description": new["description"],
                "owner": new["owner"], "owner_emails": ", ".join(new["owner_emails"]), "frequency": frequency,
                # evidence wanted and links are not in the file: keep them as they are
                "evidence_wanted": "\n".join(e["artifact"] for e in row.get("evidence") or [] if e.get("via") == "upload"),
                "links": "\n".join(f"{x.get('name', '')}|{x.get('url', '')}" for x in row.get("links") or [])}
        for fid, ids in new["mappings"].items():
            form[f"map_{fid}"] = ", ".join(ids)
        return form

    # ================================================================ import: preview, apply, discard
    def matrix_preview(self, actor, filename: str, data: bytes) -> dict:
        """Step 1: read the file and show every change. Nothing in the control set changes. A clean file is
        kept as write-once evidence so step 2 applies exactly what was previewed."""
        self._library(actor)
        if not (filename or "").lower().endswith(".xlsx"):
            raise self._invalid("Upload the control matrix as an .xlsx file.")
        plan = self._matrix_plan(actor, data)
        sha = hashlib.sha256(data).hexdigest()
        result = {**plan, "import_id": "", "file_name": filename[-120:], "file_sha256": sha}
        if plan["errors"] or not plan["changes"]:
            self.audit(actor, "control.matrix.preview", "control-matrix",
                       {"controls": [], "file_sha256": sha, "errors": len(plan["errors"]), "changes": len(plan["changes"])})
            return result
        import_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
        run = self.evidence.new_run(SOURCE_IMPORT, EVIDENCE_CONTROLS,
                                    {"import_id": import_id, "uploaded_by": actor.email, "file_name": filename[-120:],
                                     "file_sha256": sha, "purpose": "Control matrix import file, as uploaded for preview"})
        run.add_bytes(f"upload-{import_id}.xlsx", data)
        run.add(f"preview-{import_id}", {"changes": plan["changes"], "warnings": plan["warnings"], "gaps": plan["gaps"],
                                         "plan_hash": plan["plan_hash"]})
        run.finish([])
        self.store.upsert("matriximports", {"PartitionKey": "i", "RowKey": import_id, "run": run.prefix.split("/", 1)[1],
                                            "file_name": filename[-120:], "file_sha256": sha, "by": actor.email,
                                            "at": _now(), "status": "pending", "plan_hash": plan["plan_hash"],
                                            "summary": {"changes": len(plan["changes"]), "gaps": plan["gaps"]}})
        self.audit(actor, "control.matrix.preview", import_id,
                   {"controls": [c["id"] for c in plan["changes"]][:500], "file_sha256": sha,
                    "changes": len(plan["changes"]), "errors": 0})
        result["import_id"] = import_id
        return result

    def _pending_import(self, actor, import_id: str) -> dict:
        row = self.store.get("matriximports", "i", import_id or "")
        if not row or row.get("by") != actor.email:
            raise self._invalid("Import not found. Upload the file again.")
        if row.get("status") != "pending":
            raise self._invalid(f"This import is already {row.get('status')}. Upload the file again to make new changes.")
        age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(row["at"])
        if age > dt.timedelta(hours=PENDING_HOURS):
            raise self._invalid(f"This preview is older than {PENDING_HOURS} hours. Upload the file again.")
        return row

    def matrix_import(self, import_id: str) -> dict | None:
        return self.store.get("matriximports", "i", import_id or "")

    def matrix_imports(self, limit: int = 20) -> list[dict]:
        return sorted(self.store.list("matriximports", "i"), key=lambda r: r["RowKey"], reverse=True)[:limit]

    def matrix_discard(self, actor, import_id: str) -> None:
        self._library(actor)
        self._pending_import(actor, import_id)
        self.store.update("matriximports", "i", import_id, {"status": "discarded", "closed_at": _now()})
        self.audit(actor, "control.matrix.discard", import_id, {"controls": []})

    def matrix_apply(self, actor, import_id: str, plan_hash: str, reason: str, accept_gaps: bool = False) -> dict:
        """Step 2: apply exactly the previewed changes. Library owner only; a reason is required."""
        self._library(actor)
        row = self._pending_import(actor, import_id)
        reason = (reason or "").strip()
        if len(reason) < 10:
            raise self._invalid("Say why you are importing these changes (at least 10 characters); auditors will read it")
        data = self.evidence.read(SOURCE_IMPORT, row["run"], f"upload-{import_id}.xlsx")
        if data is None or hashlib.sha256(data).hexdigest() != row["file_sha256"]:
            raise self._invalid("The uploaded file could not be read back from evidence. Upload it again.")
        plan = self._matrix_plan(actor, data)
        if plan["errors"] or plan["plan_hash"] != row["plan_hash"] or plan_hash != row["plan_hash"]:
            self.store.update("matriximports", "i", import_id, {"status": "stale", "closed_at": _now()})
            raise self._invalid("Controls changed in GRC-pal since the preview, so these changes were not applied. "
                                "Download a fresh data file and import again.")
        if plan["gaps"] and not accept_gaps:
            raise self._invalid(f"This import leaves {', '.join(plan['gaps'])} with no control. Tick the box to "
                                "confirm you accept the gap, or fix the file.")
        # Pure additions first and removals last, so mappings never pass through a gap they do not end in.
        order = {"create": 0, "update": 1, "retire": 2}

        def removed(ch):
            return sum(len(set(_ids(f["old"])) - set(_ids(f["new"]))) for f in ch["fields"] if f["key"].startswith("map:"))

        changes = sorted(plan["changes"], key=lambda c: (order[c["action"]], removed(c)))
        why = f"Control matrix import {import_id}: {reason}"[:1000]
        applied, failed = [], None
        for ch in changes:
            new, cid = ch["data"], ch["id"]
            try:
                if ch["action"] == "create":
                    self.save_custom_control(actor, self._custom_form(new, new["frequency"], None, cid))
                elif ch["action"] == "retire":
                    self.retire_custom_control(actor, cid, why)
                elif ch["custom"]:
                    self.save_custom_control(actor, self._custom_form(new, new["frequency"], cid), existing_id=cid)
                else:
                    form = self._builtin_form(cid, new)
                    form["reason"] = why
                    self.save_control_definition(actor, cid, form)
                applied.append({k: v for k, v in ch.items() if k != "data"})
            except Exception as exc:  # noqa: BLE001 - storage failure mid-way: record honestly, stop
                failed = {"id": cid, "error": str(exc)[:300]}
                break
        status = "applied" if failed is None else "partial"
        run = self.evidence.new_run(SOURCE_APPLY, EVIDENCE_CONTROLS,
                                    {"import_id": import_id, "applied_by": actor.email, "file_sha256": row["file_sha256"],
                                     "reason": reason[:1000], "accepted_gaps": plan["gaps"] if accept_gaps else []})
        run.add(f"result-{import_id}", {"status": status, "applied": applied, "failed": failed,
                                        "import_file": f"{SOURCE_IMPORT}/{row['run']}/upload-{import_id}.xlsx"})
        run.finish([] if failed is None else [{"key": failed["id"], "title": "Import stopped", "severity": "high",
                                                "detail": failed}], status="ok" if failed is None else "error")
        self.store.update("matriximports", "i", import_id, {"status": status, "closed_at": _now(), "reason": reason[:1000],
                                                            "summary": {"changes": len(applied), "gaps": plan["gaps"],
                                                                        "failed": failed}})
        self.audit(actor, "control.matrix.import", import_id,
                   {"controls": [c["id"] for c in applied][:500], "file_sha256": row["file_sha256"],
                    "created": sum(c["action"] == "create" for c in applied),
                    "updated": sum(c["action"] == "update" for c in applied),
                    "retired": sum(c["action"] == "retire" for c in applied), "reason": reason[:300],
                    "accepted_gaps": plan["gaps"] if accept_gaps else None, "failed": failed})
        self._changed()
        return {"status": status, "applied": applied, "failed": failed}

    # ================================================================ report (read only)
    def matrix_report(self, user, fmt: str = "html") -> dict:
        """Everything the report shows. Admins and auditors; every report is in the audit log."""
        self._matrix_reader(user)
        in_use = self.frameworks_in_use
        controls = self.matrix_controls()
        roles = self.base_catalog.roles
        xref = []
        for fid, fw in in_use.items():
            cov = fw_mod.coverage(self.catalog.controls, fw)
            reqs = [{"id": rid, "title": r.get("title", ""), "group": r.get("group", ""), "controls": cov.get(rid, [])}
                    for rid, r in fw.requirements.items()]
            if fid == "soc2":
                scope = set(self.catalog.in_scope_criteria)
                reqs = [r for r in reqs if r["id"] in scope]
            xref.append({"id": fid, "name": fw.name, "requirements": reqs,
                         "uncovered": sum(1 for r in reqs if not r["controls"])})
        self.audit(user, "control.matrix.report", "control-matrix", {"controls": [], "format": fmt, "count": len(controls)})
        return {"org": self.org, "generated": _now(), "generated_by": user.email, "frameworks": in_use,
                "controls": controls, "xref": xref,
                "role_names": {k: (v.get("title") or v.get("name") or k) if isinstance(v, dict) else k
                               for k, v in roles.items()}}

    def matrix_docx(self, user) -> bytes:
        from grcpal import wordfile

        r = self.matrix_report(user, "docx")
        doc = wordfile.Document()
        doc.title(f"Control matrix: {r['org']}")
        doc.para(f"Generated {r['generated'][:16].replace('T', ' ')} UTC by {r['generated_by']}. "
                 f"Frameworks: {', '.join(fw.name for fw in r['frameworks'].values())}. {len(r['controls'])} controls.")
        doc.heading("Summary", 1)
        doc.table(["Framework", "Requirements in scope", "With no control"],
                  [[x["name"], str(len(x["requirements"])), str(x["uncovered"])] for x in r["xref"]])
        doc.heading("Controls", 1)
        for c in r["controls"]:
            doc.heading(f"{c['id']}  {c['title']}", 2)
            doc.para((c["description"] or "").strip() or "No description.")
            facts = [["Owner", ", ".join(x for x in [r["role_names"].get(c["owner"], c["owner"])] + c["owner_emails"] if x)],
                     ["Frequency", c["frequency"]], ["Type", c["type"]],
                     ["Source", "Custom" if c["custom"] else "Built-in"]]
            facts += [[fw.name.split(" (")[0], "; ".join(c["mappings"].get(fid, [])) or "-"]
                      for fid, fw in r["frameworks"].items()]
            if c["pof"]:
                facts.append(["Points of focus", "\n".join(f"{i} {t}" for i, t in c["pof"])])
            if c["evidence"]:
                facts.append(["Evidence", "\n".join(c["evidence"])])
            doc.table(None, facts, widths=(25, 75))
        for x in r["xref"]:
            doc.page_break()
            doc.heading(f"Cross-reference: {x['name']}", 1)
            doc.table(["Requirement", "Title", "Controls"],
                      [[q["id"], q["title"], ", ".join(q["controls"]) or "No control"] for q in x["requirements"]],
                      widths=(16, 54, 30))
        return doc.save()

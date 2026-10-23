"""Bulk vendor import from a CSV file. It only ever adds vendors: nothing in the register is changed or deleted.

How it works:
1. An admin uploads a CSV (the template is at /vendors/import/template.csv). The file is stored write-once in
   the evidence store (source `vendor_import`), so the auditor can see where the vendor population came from.
2. GRC-pal compares every row with the register (the "delta"):
   - new: not in the register; can be added;
   - existing: same name or a shared domain; the differences are shown for information, never applied;
   - similar: a name close to a vendor already in the register; added only if the admin ticks it;
   - problem: something to fix in the file (no name, unknown tier, bad email, listed twice); skipped.
   Vendors in the register that are not in the file are listed for information and never touched.
3. The admin ticks the rows to add. Applying reads the stored file again and recomputes the delta, so only rows
   that are still new (or similar) and were ticked are added. The browser sends row numbers, nothing else.
   Imported vendors are Active and never reviewed (they are already in use); their first reviews can be spread
   over the next 12 months, critical vendors first, so they do not all fall due in the same week.
"""
from __future__ import annotations

import csv
import datetime as dt
import difflib
import hashlib
import io
import re
import uuid

from grcpal.portal import vendors as vmod

MAX_BYTES, MAX_ROWS, PREVIEW_DAYS = 1_000_000, 500, 7
# Template columns, in order, with the help shown on the import page.
COLUMNS = [
    ("name", "Vendor name (required)"),
    ("service", "What they do for us"),
    ("tier", "critical, high, moderate or low (required)"),
    ("data_access", "What they can reach, separated by ; from: " + "; ".join(vmod.DATA_ACCESS)),
    ("domains", "Website or email domains, separated by ; (for example contoso.com)"),
    ("subservice", "Subservice organization for our SOC 2: no, carved_out or inclusive"),
    ("owner_name", "Internal owner's name"), ("owner_title", "Internal owner's title"),
    ("owner_email", "Internal owner's email (if it belongs to a GRC-pal user, they will see this vendor)"),
    ("owner_phone", "Internal owner's phone"),
    ("backup_name", "Backup contact's name"), ("backup_title", "Backup contact's title"),
    ("backup_email", "Backup contact's email"),
    ("ext_name", "Vendor contract contact's name"), ("ext_title", "Vendor contact's title"),
    ("ext_email", "Vendor contact's email"), ("ext_phone", "Vendor contact's phone"),
    ("support_text", "How to open a support ticket"), ("support_url", "Support link (https://)"),
    ("docs_text", "How to request their SOC 2 report, certificate or a questionnaire"),
    ("docs_url", "Trust page link (https://)"),
    ("contract_terms", "Security terms in the contract: yes, partial, no, na or empty"),
    ("dpa", "Data processing agreement signed: yes, partial, no, na or empty"),
    ("contract_note", "Contract note (renewal date, notice period)"),
    ("assurance", "soc2_type2, soc2_type1, iso27001, questionnaire, other, none or empty"),
    ("period_end", "Report period end or certificate expiry (YYYY-MM-DD)"),
    ("notes", "Anything else"),
]
FIELDS = [c for c, _ in COLUMNS]
ALIASES = {"vendor": "name", "vendor_name": "name", "supplier": "name", "website": "domains", "domain": "domains",
           "owner": "owner_name", "internal_owner": "owner_name", "risk_tier": "tier", "criticality": "tier",
           "description": "service", "contact_email": "ext_email", "contact_name": "ext_name"}
SUFFIXES = {"inc", "incorporated", "llc", "ltd", "limited", "corp", "corporation", "co", "company", "gmbh", "sa",
            "sas", "srl", "bv", "nv", "plc", "pty", "pvt", "private", "ag", "oy", "ab", "as", "kk", "llp", "lp", "the"}
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
YES = {"yes", "y", "true", "1", "carved_out", "carved out", "carve-out", "carve out"}
TIER_RANK = {"critical": 0, "high": 1, "moderate": 2, "low": 3}


class ImportProblem(ValueError):
    """The file as a whole cannot be used; the message says what to fix."""


def _header(name: str) -> str:
    key = re.sub(r"[\s\-]+", "_", (name or "").strip().strip("*").strip().lower())
    return ALIASES.get(key, key)


def norm_name(name: str) -> str:
    """Name for matching: lower case, no brackets or punctuation, no legal suffix ("Contoso, Inc." -> "contoso")."""
    s = re.sub(r"\(.*?\)", " ", (name or "").lower()).replace("&", " and ")
    words = re.sub(r"[^a-z0-9]+", " ", s).split()
    while len(words) > 1 and words[-1] in SUFFIXES:
        words.pop()
    while len(words) > 1 and words[0] == "the":
        words.pop(0)
    return " ".join(words)


def clean_domains(value) -> tuple[list[str], list[str]]:
    """Domains from text or a list ("https://www.contoso.com/x; billing@contoso.co.uk"): (good, rejected)."""
    items = value if isinstance(value, list) else re.split(r"[;,\s]+", str(value or ""))
    good, bad = [], []
    for item in items:
        d = str(item).strip().lower()
        if not d:
            continue
        d = d.split("@")[-1]
        d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0]
        d = d[4:] if d.startswith("www.") else d
        if DOMAIN_RE.match(d):
            if d not in good:
                good.append(d)
        else:
            bad.append(str(item).strip()[:60])
    return good[:10], bad


def _decode(data: bytes) -> str:
    if b"\x00" in data:
        raise ImportProblem("This is not a text file. Save the spreadsheet as CSV UTF-8 and upload that.")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImportProblem("The file must be UTF-8 text. In Excel choose File > Save As > "
                            "'CSV UTF-8 (Comma delimited)'.") from exc


def parse(data: bytes) -> tuple[list[dict], list[str]]:
    """Rows as {row (line number), values (column -> text)} and the names of ignored columns."""
    if not data.strip():
        raise ImportProblem("The file is empty")
    if len(data) > MAX_BYTES:
        raise ImportProblem(f"The file is larger than {MAX_BYTES // 1_000_000} MB; split it into smaller files")
    text = _decode(data)
    first = text.split("\n", 1)[0]
    delimiter = max(",;\t", key=first.count) if any(d in first for d in ",;\t") else ","
    try:
        reader = csv.reader(io.StringIO(text), delimiter=delimiter)
        header = [_header(h) for h in next(reader, [])]
        if "name" not in header:
            raise ImportProblem("The first row must be the column names, including 'name'. Download the template.")
        if "tier" not in header:
            raise ImportProblem("The file needs a 'tier' column (critical, high, moderate or low)")
        if len(header) != len(set(h for h in header if h)) + header.count(""):
            raise ImportProblem("A column name appears twice in the first row")
        rows = []
        for line_no, cells in enumerate(reader, start=2):
            if not any(c.strip() for c in cells):
                continue
            if len(rows) >= MAX_ROWS:
                raise ImportProblem(f"The file has more than {MAX_ROWS} vendors; split it into smaller files")
            values = {h: c.strip() for h, c in zip(header, cells) if h in FIELDS}
            rows.append({"row": line_no, "values": values})
    except csv.Error as exc:
        raise ImportProblem(f"The file is not a valid CSV: {exc}") from exc
    if not rows:
        raise ImportProblem("The file has column names but no vendors")
    ignored = [h for h in header if h and h not in FIELDS]
    return rows, ignored


def _choice(value: str, options: dict, aliases: dict | None = None) -> str:
    v = (value or "").strip().lower()
    if v in options:
        return v
    if aliases and v in aliases:
        return aliases[v]
    for key, label in options.items():
        if label and v == label.lower():
            return key
    return value  # left as typed, so validation names the bad value


def template_csv() -> bytes:
    buf = io.StringIO()
    csv.writer(buf).writerow(FIELDS)
    return ("﻿" + buf.getvalue()).encode("utf-8")  # the BOM makes Excel open it as UTF-8


class VendorImportMixin:
    """CSV import for the Portal. Admins only; every step is audited."""

    def _import_form(self, values: dict) -> tuple[dict, list[str]]:
        """Turn one row's text into vendor fields, plus warnings for values that were ignored."""
        warnings = []
        form = {k: v for k, v in values.items() if k in FIELDS and k not in ("data_access", "domains")}
        form["tier"] = (values.get("tier") or "").strip().lower()
        form["subservice"] = ("carved_out" if (values.get("subservice") or "").strip().lower() in YES
                              else _choice(values.get("subservice") or "no", vmod.SUBSERVICE,
                                           {"no": "no", "n": "no", "false": "no", "0": "no", "": "no"}))
        contract_aliases = {"": "unknown", "partly": "partial", "n/a": "na", "y": "yes", "n": "no", "true": "yes",
                            "false": "no"}
        for key in ("contract_terms", "dpa"):
            form[key] = _choice(values.get(key, ""), vmod.CONTRACT, contract_aliases)
        form["assurance"] = _choice(values.get("assurance", ""), vmod.ASSURANCE,
                                    {"soc 2 type 2": "soc2_type2", "soc2": "soc2_type2", "soc 2": "soc2_type2",
                                     "soc 2 type 1": "soc2_type1", "iso": "iso27001", "iso 27001": "iso27001"})
        wanted = [x.strip() for x in re.split(r"[;,]", values.get("data_access", "")) if x.strip()]
        by_lower = {d.lower(): d for d in vmod.DATA_ACCESS}
        form["data_access"] = [by_lower[x.lower()] for x in wanted if x.lower() in by_lower]
        unknown = [x for x in wanted if x.lower() not in by_lower]
        if unknown:
            warnings.append(f"Data access not recognised and left out: {', '.join(unknown)[:200]}")
        domains, bad = clean_domains(values.get("domains", ""))
        form["domains"] = domains
        if bad:
            warnings.append(f"Not a domain, left out: {', '.join(bad)}")
        return form, warnings

    def _import_delta(self, data: bytes) -> dict:
        rows, ignored = parse(data)
        register = [v for v in self.store.list("vendors", "v")]
        by_name = {norm_name(v["name"]): v for v in register}
        by_domain = {d: v for v in register for d in v.get("domains") or []}
        users = {u["RowKey"] for u in self.users() if u.get("active", True)}
        seen: dict[str, int] = {}
        matched: set[str] = set()
        out = []
        fields = [f for f in vmod.DETAIL_FIELDS + vmod.CONTACT_FIELDS if f != "next_review_override"]
        for r in rows:
            item = {"row": r["row"], "name": r["values"].get("name", "")[:120], "status": "new", "reason": "",
                    "warnings": [], "diffs": [], "match": "", "match_name": ""}
            out.append(item)
            form, item["warnings"] = self._import_form(r["values"])
            try:
                if not form.get("name"):
                    raise self._invalid("The vendor name is empty")
                if not form.get("tier"):
                    raise self._invalid("The tier is empty (critical, high, moderate or low)")
                clean = self._clean_vendor(form, fields)
            except Exception as exc:  # noqa: BLE001 - Invalid from validation; shown to the admin
                item.update(status="problem", reason=str(exc))
                continue
            item["vendor"] = clean
            key = norm_name(clean["name"])
            if key in seen:
                item.update(status="problem", reason=f"Listed twice in the file (also on row {seen[key]})")
                continue
            seen[key] = r["row"]
            hit = by_name.get(key) or next((by_domain[d] for d in clean.get("domains") or [] if d in by_domain), None)
            if hit:
                matched.add(hit["RowKey"])
                item.update(status="existing", match=hit["RowKey"], match_name=hit["name"])
                for f in fields:
                    if f in r["values"] and r["values"][f].strip() and clean.get(f) not in (None, "", []) \
                            and clean.get(f) != hit.get(f) and f != "name":
                        item["diffs"].append({"field": f, "file": clean.get(f), "register": hit.get(f, "")})
                continue
            close = [v for v in register if key and (
                difflib.SequenceMatcher(None, key, norm_name(v["name"])).ratio() >= 0.8
                or (len(key) >= 4 and len(norm_name(v["name"])) >= 4
                    and (key in norm_name(v["name"]) or norm_name(v["name"]) in key)))]
            if close:
                item.update(status="similar", match=close[0]["RowKey"], match_name=close[0]["name"])
            for f in ("owner_email", "backup_email"):
                if clean.get(f) and clean[f] in users:
                    item["warnings"].append(f"{clean[f]} is a GRC-pal user and will see this vendor")
        missing = [{"RowKey": v["RowKey"], "name": v["name"], "status": v.get("status", "")} for v in register
                   if v["RowKey"] not in matched and v.get("status") not in ("offboarded", "rejected")]
        counts = {s: sum(1 for i in out if i["status"] == s) for s in ("new", "existing", "similar", "problem")}
        return {"rows": out, "missing": sorted(missing, key=lambda m: m["name"].lower()), "ignored": ignored,
                "counts": counts}

    # ---------------------------------------------------------------- steps
    def vendor_import_upload(self, actor, filename: str, data: bytes) -> dict:
        """Check and store the file, and return the import record. Nothing is added yet."""
        self._admin(actor)
        from grcpal.portal.security import safe_filename

        name = safe_filename(filename or "vendors.csv")
        if not name.lower().endswith(".csv"):
            raise self._invalid("Upload a .csv file. In Excel choose File > Save As > 'CSV UTF-8 (Comma delimited)'.")
        try:
            delta = self._import_delta(data)
        except ImportProblem as exc:
            raise self._invalid(str(exc)) from exc
        sha = hashlib.sha256(data).hexdigest()
        run = self.evidence.new_run("vendor_import", ["VEN-01"], {"uploaded_by": actor.email, "file": name})
        run.add_bytes(name, data)
        run.finish([])
        token = uuid.uuid4().hex
        row = {"PartitionKey": "i", "RowKey": token, "filename": name, "sha256": sha, "evidence_run": run.prefix,
               "by": actor.email, "at": vmod._now(), "status": "preview", "import_counts": delta["counts"],
               "added_ids": [], "applied_at": "", "spread": False}
        self.store.insert("vendorimports", row)
        self.audit(actor, "vendor.import.preview", token, {"controls": ["VEN-01"], "file": name, "sha256": sha,
                                                          "run": run.prefix, **delta["counts"]})
        return row

    def vendor_imports(self) -> list[dict]:
        return sorted(self.store.list("vendorimports", "i"), key=lambda r: r["at"], reverse=True)[:20]

    def vendor_import(self, actor, token: str) -> tuple[dict, dict | None]:
        """The import record and, while it can still be applied, the delta recomputed from the stored file."""
        self._admin(actor)
        rec = self.store.get("vendorimports", "i", token) if re.match(r"^[0-9a-f]{32}$", token or "") else None
        if not rec:
            raise self._invalid("Import not found")
        if rec["status"] != "preview":
            return rec, None
        if rec["at"][:10] < (self.today - dt.timedelta(days=PREVIEW_DAYS)).isoformat():
            raise self._invalid(f"This preview is older than {PREVIEW_DAYS} days. Upload the file again.")
        source, run = rec["evidence_run"].split("/", 1)
        data = self.evidence.read(source, run, rec["filename"])
        if data is None or hashlib.sha256(data).hexdigest() != rec["sha256"]:
            raise self._invalid("The stored file is missing or changed. Upload it again.")
        return rec, self._import_delta(data)

    def vendor_import_apply(self, actor, token: str, picked: list[int], spread: bool) -> list[dict]:
        """Add the ticked rows that are still new or similar. Nothing else is changed."""
        rec, delta = self.vendor_import(actor, token)
        if delta is None:
            raise self._invalid("This import was already applied or discarded")
        wanted = set(picked)
        chosen = [i for i in delta["rows"] if i["row"] in wanted and i["status"] in ("new", "similar")]
        if not chosen:
            raise self._invalid("Tick at least one new vendor to add")
        chosen.sort(key=lambda i: (TIER_RANK.get(i["vendor"]["tier"], 9), i["vendor"]["name"].lower()))
        today, n = self.today, len(chosen)
        now, added = vmod._now(), []
        names = {norm_name(v["name"]) for v in self.store.list("vendors", "v")}
        for pos, item in enumerate(chosen):
            clean = item["vendor"]
            if norm_name(clean["name"]) in names:  # added since the preview: never create a second copy
                continue
            names.add(norm_name(clean["name"]))
            due = (today + dt.timedelta(days=30 + (round(pos * 335 / (n - 1)) if n > 1 else 0))).isoformat() if spread else ""
            base, k = vmod.slug(clean["name"]), 2
            vid = base if base not in vmod.RESERVED else f"{base}-vendor"
            while self.store.get("vendors", "v", vid):
                vid, k = f"{base}-{k}", k + 1
            row = {"PartitionKey": "v", "RowKey": vid, "status": "active", "subservice": "no", "data_access": [],
                   "domains": [], "contract_terms": "unknown", "dpa": "unknown", "assurance": "", "opinion": "",
                   "cuecs": [], "last_review": "", "approved_at": "", "end_date": "", "legacy": {}, "version": 1,
                   "imported_from": f"{rec['filename']} ({rec['sha256'][:12]}, row {item['row']})",
                   "created_by": actor.email, "created_at": now, "updated_by": actor.email, "updated_at": now,
                   **clean, "next_review_override": due}
            self.store.insert("vendors", row)
            self._save_version(row, actor.email, f"Imported from {rec['filename']}, row {item['row']}"
                               + (f"; first review planned for {due}" if due else ""))
            self.audit(actor, "vendor.create", vid, {"controls": ["VEN-01"], "name": row["name"], "tier": row["tier"],
                                                     "status": "active", "import": token, "row": item["row"]})
            added.append(row)
        self.store.update("vendorimports", "i", token, {"status": "applied", "applied_at": vmod._now(),
                                                         "added_ids": [r["RowKey"] for r in added], "spread": bool(spread)})
        self.audit(actor, "vendor.import.apply", token, {"controls": ["VEN-01"], "file": rec["filename"],
                                                        "sha256": rec["sha256"], "added": len(added),
                                                        "rows": [i["row"] for i in chosen], "spread": bool(spread)})
        return added

    def vendor_import_discard(self, actor, token: str) -> None:
        rec, delta = self.vendor_import(actor, token)
        if delta is None:
            raise self._invalid("This import was already applied or discarded")
        self.store.update("vendorimports", "i", token, {"status": "discarded", "applied_at": vmod._now()})
        self.audit(actor, "vendor.import.discard", token, {"file": rec["filename"]})

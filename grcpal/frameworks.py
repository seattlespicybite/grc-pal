"""Frameworks: SOC 2, ISO 27001 and any other standard, behind one model.

A framework is a list of requirements (id, title, group). Controls map to requirements of any number of
frameworks, so one control can satisfy SOC 2 CC6.1, ISO 27001 A.5.15 and a customer's own standard at the
same time. Sources, merged in this order:
  * built in: SOC 2 from catalog/criteria.yaml;
  * files: frameworks/*.yaml in the starter kit and in your program repository;
  * custom: created on the Frameworks page (stored per tenant).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from grcpal.catalog import load_yaml

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,39}$")
STARTER_DIR = Path(__file__).parent / "starter" / "frameworks"


@dataclass
class Framework:
    id: str
    name: str
    version: str = ""
    description: str = ""
    requirements: dict = field(default_factory=dict)   # id -> {"title", "group"}
    source: str = "file"
    control_field: str = ""                             # legacy field on controls (criteria, iso27001)

    def groups(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for rid, r in self.requirements.items():
            out.setdefault(r.get("group") or "Requirements", []).append(rid)
        return out


def _from_doc(doc: dict, source: str) -> Framework:
    reqs = {}
    for r in doc.get("requirements") or []:
        reqs[str(r["id"])] = {"title": str(r.get("title", "")), "group": str(r.get("group", ""))}
    return Framework(id=doc["id"], name=doc.get("name", doc["id"]), version=str(doc.get("version", "")),
                     description=doc.get("description", ""), requirements=reqs, source=source,
                     control_field=doc.get("control_field", ""))


def soc2(catalog) -> Framework:
    names = {"security": "Security (common criteria)", "availability": "Availability", "confidentiality": "Confidentiality",
             "processing_integrity": "Processing Integrity", "privacy": "Privacy"}
    reqs = {cid: {"title": c["title"], "group": names.get(c["category"], c["category"])} for cid, c in catalog.criteria.items()}
    return Framework("soc2", "SOC 2 (Trust Services Criteria)", "2017, revised points of focus 2022",
                     "AICPA Trust Services Criteria for Security, Availability, Confidentiality, Processing Integrity "
                     "and Privacy.", reqs, "built-in", "criteria")


def load(catalog, custom: list[dict] | None = None) -> dict[str, Framework]:
    out = {"soc2": soc2(catalog)}
    folders = [STARTER_DIR]
    base = Path(catalog.base) / "frameworks"
    if base.resolve() != STARTER_DIR.resolve():
        folders.append(base)
    for folder in folders:
        if folder.is_dir():
            for f in sorted(folder.glob("*.yaml")):
                doc = load_yaml(f.read_text(encoding="utf-8"))
                if doc.get("id") and ID_RE.match(doc["id"]) and doc["id"] != "soc2":
                    out[doc["id"]] = _from_doc(doc, "file")
    for row in custom or []:
        if row.get("active", True) and row["RowKey"] not in out:
            out[row["RowKey"]] = _from_doc({"id": row["RowKey"], **row}, "custom")
    return out


def requirements_of(control: dict, fw: Framework) -> list[str]:
    mapped = list((control.get("mappings") or {}).get(fw.id, []))
    if fw.control_field:
        mapped += [x for x in control.get(fw.control_field, []) or [] if x not in mapped]
    return [str(x) for x in mapped]


def coverage(controls: list[dict], fw: Framework) -> dict[str, list[str]]:
    cov: dict[str, list[str]] = {rid: [] for rid in fw.requirements}
    for c in controls:
        for rid in requirements_of(c, fw):
            cov.setdefault(rid, []).append(c["id"])
    return cov


def parse_requirements(text: str) -> list[dict]:
    """Lines of 'ID | title | group' (group optional) from the custom framework form."""
    out = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if parts and parts[0]:
            out.append({"id": parts[0][:40], "title": (parts[1] if len(parts) > 1 else "")[:200],
                        "group": (parts[2] if len(parts) > 2 else "")[:80]})
    return out

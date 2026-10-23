"""SOC 2 view helpers: criteria grouped into families, criterion order, and how each control is evidenced.

Pure functions over the catalog and settings, so pages and tests share one definition.
"""
from __future__ import annotations

import re

FAMILY_NAMES = {
    "CC1": "Control environment", "CC2": "Communication and information", "CC3": "Risk assessment",
    "CC4": "Monitoring activities", "CC5": "Control activities", "CC6": "Logical and physical access",
    "CC7": "System operations", "CC8": "Change management", "CC9": "Risk mitigation",
    "A1": "Availability", "C1": "Confidentiality", "PI1": "Processing integrity", "P": "Privacy",
}
CATEGORY_ORDER = ("security", "availability", "confidentiality", "processing_integrity", "privacy")
STATUSES = ("ok", "accepted", "findings", "attention", "not_started")

# Collector name prefix -> where the data comes from, in words people use
SOURCE_LABELS = (
    ("entra_", "Entra ID"), ("conditional_access", "Entra ID"), ("leaver_", "HR export + Entra ID"),
    ("intune_", "Intune"), ("azure_", "Azure"), ("github_", "GitHub"), ("issues_", "GitHub issues"),
    ("aws_", "AWS"), ("gcp_", "Google Cloud"), ("portal_", "GRC-pal"), ("catalog_", "GRC-pal"),
)
TYPE_LABELS = {"automated": "Automatic", "hybrid": "Hybrid", "manual": "Manual"}


def family_of(criterion_id: str) -> str:
    """CC6.1 -> CC6, A1.2 -> A1, PI1.3 -> PI1, P4.2 -> P (privacy is one family)."""
    head = criterion_id.split(".")[0]
    return "P" if re.fullmatch(r"P\d+", head) else head


def ordered_criteria(catalog, in_scope_only: bool = True) -> list[str]:
    """Criteria in reading order (CC1.1 ... CC9.2, A1, C1, PI1, P), optionally only those in scope."""
    keep = set(catalog.in_scope_criteria) if in_scope_only else set(catalog.criteria)
    by_cat = {c: [] for c in CATEGORY_ORDER}
    for cid, crit in catalog.criteria.items():
        if cid in keep:
            by_cat.setdefault(crit["category"], []).append(cid)
    return [cid for cat in by_cat.values() for cid in cat]


def neighbours(items: list[str], current: str) -> tuple[str | None, str | None, int]:
    """(previous, next, 1-based position) of current in items; position 0 when it is not there."""
    if current not in items:
        return None, None, 0
    i = items.index(current)
    return (items[i - 1] if i else None), (items[i + 1] if i + 1 < len(items) else None), i + 1


def families(catalog, status: dict[str, str]) -> list[dict]:
    """Every family with its criteria, controls and status counts. Out-of-scope categories are marked."""
    in_scope = set(catalog.in_scope_criteria)
    cov = catalog.coverage()
    out: dict[str, dict] = {}
    for cid in ordered_criteria(catalog, in_scope_only=False):
        crit = catalog.criteria[cid]
        fam = out.setdefault(family_of(cid), {"id": family_of(cid), "name": FAMILY_NAMES.get(family_of(cid), family_of(cid)),
                                              "category": crit["category"], "criteria": [], "controls": set(),
                                              "in_scope": False})
        ctls = cov.get(cid, [])
        statuses = [status.get(c, "not_started") for c in ctls]
        fam["criteria"].append({"id": cid, "title": crit["title"], "controls": len(ctls), "status": worst(statuses)})
        fam["controls"].update(ctls)
        fam["in_scope"] = fam["in_scope"] or cid in in_scope
    for fam in out.values():
        counts = {s: 0 for s in STATUSES}
        for c in fam["controls"]:
            s = status.get(c, "not_started")
            counts[s if s in counts else "not_started"] += 1
        fam["counts"], fam["total"] = counts, len(fam["controls"])
    return list(out.values())


def worst(statuses: list[str]) -> str:
    """One status for a group of controls: the most urgent one wins; no controls means not started."""
    for s in ("attention", "findings", "not_started", "accepted", "ok"):
        if s in statuses:
            return s
    return "not_started"


def evidenced_by(control: dict, skip_sources: set[str]) -> dict:
    """How a control is evidenced for this client: type plus the connected sources. Sources that are switched
    off (for example AWS when only Azure is used) are left out and listed separately."""
    sources, hidden, manual = [], [], []
    for ev in control.get("evidence", []):
        kind, _, name = str(ev.get("via", "upload")).partition(":")
        if kind == "collector":
            label = next((lbl for prefix, lbl in SOURCE_LABELS if name.startswith(prefix)), name)
            (hidden if name in skip_sources else sources).append(label)
        elif kind == "tool":
            sources.append({"prowler": "Prowler scan", "maester": "Maester tests", "testssl": "TLS scan"}.get(name, name))
        elif kind == "check":
            sources.append("Custom check")
        elif kind == "task":
            manual.append("Recurring task")
        elif kind == "git":
            manual.append("Document in repository")
        elif kind != "link":
            manual.append("Upload")
    uniq = lambda xs: list(dict.fromkeys(xs))  # noqa: E731
    sources, manual = uniq(sources), uniq(manual)
    kind = catalog_kind = control.get("type", "manual")
    reason = ""
    if kind != "manual" and not sources:
        kind = "manual"   # nothing automatic is connected for this client
        reason = (f"{TYPE_LABELS.get(catalog_kind, catalog_kind)} in the control library; shown as Manual because "
                  "none of its automatic sources are connected for this organization")
    elif kind == "manual" and sources:
        kind = "hybrid"   # an admin added an automated check to a manual control
        reason = "Manual in the control library; shown as Hybrid because an automated check was added to it"
    return {"type": kind, "label": TYPE_LABELS.get(kind, kind.title()), "sources": sources, "manual": manual,
            "hidden": [h for h in uniq(hidden) if h not in sources], "reason": reason}


AUTOMATIC_VIA = ("collector", "tool", "check")
TYPE_HELP = {"automated": "Evidence is collected by GRC-pal on a schedule; people only act on findings",
             "hybrid": "Part of the evidence is collected automatically, part is done and recorded by people",
             "manual": "Evidence is produced by people: uploads, recurring tasks, meetings, documents"}


def split_evidence(items: list[dict]) -> dict:
    """Group a control's evidence status rows into what GRC-pal collects itself and what people do."""
    out = {"automatic": [], "manual": []}
    for i in items:
        out["automatic" if str(i.get("via", "")).partition(":")[0] in AUTOMATIC_VIA else "manual"].append(i)
    return out

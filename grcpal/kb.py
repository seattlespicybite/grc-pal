"""Knowledge base: plain-language evidence guidance for each SOC 2 criterion and point of focus.

One YAML file per criterion (kb/CC6.1.yaml) in the starter kit; a program repository can replace an article
with its own file of the same name. Articles are data, not code: plain text only (no HTML or Markdown), so a
page can show them without any sanitizer and the AI assistant can read them later.

Article format:
    criterion: CC6.1
    title: Logical access security
    status: draft | reviewed          # reviewed = checked by a person named in reviewed_by
    reviewed_by: ""
    last_reviewed: ""                 # YYYY-MM-DD
    summary: what the criterion asks for, in plain words
    auditor_approach: [how auditors usually test it]
    points:
      - id: CC6.1-PF01
        what_auditor_tests: text
        evidence_standard: [what good evidence must show]
        good_examples: [concrete artifacts]
        common_mistakes: [what leads to exceptions]
        frequency: how often, and sample sizes to expect

Articles are our own words, never the AICPA criterion or point-of-focus text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from grcpal.catalog import load_yaml

STARTER_DIR = Path(__file__).parent / "starter" / "kb"
STATUSES = ("draft", "reviewed")
LIST_FIELDS = ("evidence_standard", "good_examples", "common_mistakes")
CRITERION_RE = re.compile(r"^[A-Z]{1,2}\d+\.\d+$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass
class Article:
    criterion: str
    title: str
    status: str = "draft"
    reviewed_by: str = ""
    last_reviewed: str = ""
    summary: str = ""
    auditor_approach: list[str] = field(default_factory=list)
    points: list[dict] = field(default_factory=list)
    source: str = "starter"

    def point(self, point_id: str) -> dict | None:
        return next((p for p in self.points if p["id"] == point_id), None)


def _texts(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    return [str(v).strip() for v in value if str(v).strip()]


def _from_doc(doc: dict, source: str) -> Article:
    points = []
    for p in doc.get("points") or []:
        points.append({"id": str(p.get("id", "")), "what_auditor_tests": str(p.get("what_auditor_tests") or "").strip(),
                       "frequency": str(p.get("frequency") or "").strip(),
                       **{k: _texts(p.get(k)) for k in LIST_FIELDS}})
    return Article(criterion=str(doc.get("criterion", "")), title=str(doc.get("title") or "").strip(),
                   status=str(doc.get("status") or "draft"), reviewed_by=str(doc.get("reviewed_by") or ""),
                   last_reviewed=str(doc.get("last_reviewed") or ""), summary=str(doc.get("summary") or "").strip(),
                   auditor_approach=_texts(doc.get("auditor_approach")), points=points, source=source)


def load(base: Path | str | None = None) -> dict[str, Article]:
    """Starter articles, then any in <program repo>/kb/ (same file name replaces the starter article)."""
    out: dict[str, Article] = {}
    folders = [STARTER_DIR]
    if base is not None:
        mine = Path(base) / "kb"
        if mine.resolve() != STARTER_DIR.resolve():
            folders.append(mine)
    for folder in folders:
        if not folder.is_dir():
            continue
        for f in sorted(folder.glob("*.yaml")):
            doc = load_yaml(f.read_text(encoding="utf-8")) or {}
            crit = str(doc.get("criterion", ""))
            if CRITERION_RE.match(crit) and f.stem == crit:
                out[crit] = _from_doc(doc, "starter" if folder == STARTER_DIR else "program")
    return out


def validate(catalog, articles: dict[str, Article]) -> list[str]:
    """Problems that would make an article misleading: unknown ids, wrong status, empty guidance."""
    problems = []
    for crit, a in sorted(articles.items()):
        if crit not in catalog.criteria:
            problems.append(f"{crit}: not a criterion in this catalog")
            continue
        if a.status not in STATUSES:
            problems.append(f"{crit}: status must be one of {', '.join(STATUSES)}")
        if a.status == "reviewed" and not (a.reviewed_by and DATE_RE.match(a.last_reviewed)):
            problems.append(f"{crit}: a reviewed article needs reviewed_by and last_reviewed (YYYY-MM-DD)")
        if not a.title or not a.summary:
            problems.append(f"{crit}: title and summary are required")
        known = {p["id"] for p in catalog.points_of_focus.get(crit, [])}
        seen = set()
        for p in a.points:
            if p["id"] not in known:
                problems.append(f"{crit}: {p['id'] or '(no id)'} is not a point of focus of {crit}")
            if p["id"] in seen:
                problems.append(f"{crit}: {p['id']} appears twice")
            seen.add(p["id"])
            if not (p["what_auditor_tests"] and p["evidence_standard"] and p["good_examples"]):
                problems.append(f"{crit}: {p['id']} needs what_auditor_tests, evidence_standard and good_examples")
    return problems


def missing_points(catalog, articles: dict[str, Article], criteria: list[str]) -> list[str]:
    """Points of focus of the given criteria that have no guidance section yet."""
    out = []
    for crit in criteria:
        a = articles.get(crit)
        have = {p["id"] for p in a.points} if a else set()
        out += [p["id"] for p in catalog.points_of_focus.get(crit, []) if p["id"] not in have]
    return out

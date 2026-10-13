"""Load and validate the control catalog, registers and tasks."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

FREQUENCIES = {"continuous", "daily", "weekly", "monthly", "quarterly", "annual", "event"}
TYPES = {"automated", "hybrid", "manual"}
KNOWN_TOOLS = {"prowler", "maester", "testssl", "trivy"}
REQUIRED = ("id", "title", "description", "criteria", "owner", "frequency", "type", "evidence")
POF_STATUSES = {"covered", "partial", "gap", "n/a"}
STARTER = Path(__file__).parent / "starter"


def load_policies(folder: Path) -> list[dict]:
    import hashlib

    out = []
    if not folder.is_dir():
        return out
    for path in sorted(folder.glob("*.md")):
        if path.stem.upper() in ("README", "TEMPLATE"):
            continue
        text = path.read_text(encoding="utf-8")
        meta, body = {}, text
        if text.startswith("---"):
            _, header, body = text.split("---", 2)
            meta = yaml.safe_load(header) or {}
        out.append({"id": path.stem, "title": meta.get("title", path.stem), "owner": meta.get("owner", ""),
                    "approver": meta.get("approver", ""), "controls": meta.get("controls", []) or [],
                    "version": str(meta.get("version", "1.0")), "effective": str(meta.get("effective", "")),
                    "next_review": str(meta.get("next_review", "")), "acknowledge": meta.get("acknowledge", True),
                    "body": body.strip(), "sha256": hashlib.sha256(text.encode()).hexdigest()})
    return out


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@dataclass
class Catalog:
    base: Path
    criteria: dict
    categories: dict
    scope: dict
    roles: dict
    controls: list[dict]
    tasks: dict
    risks: list[dict]
    vendors: list[dict]
    exceptions: list[dict]
    points_of_focus: dict

    @classmethod
    def load(cls, base: str | Path | None = None) -> "Catalog":
        base = Path(base) if base else STARTER
        crit = _load(base / "catalog/criteria.yaml")
        return cls(
            base=base,
            criteria=crit["criteria"],
            categories=crit["categories"],
            scope=_load(base / "catalog/scope.yaml"),
            roles=_load(base / "catalog/roles.yaml")["roles"],
            controls=_load(base / "catalog/controls.yaml")["controls"],
            tasks=_load(base / "catalog/tasks.yaml")["tasks"],
            risks=_load(base / "registers/risks.yaml").get("risks", []) or [],
            vendors=_load(base / "registers/vendors.yaml").get("vendors", []) or [],
            exceptions=_load(base / "registers/exceptions.yaml").get("exceptions", []) or [],
            points_of_focus=(_load(base / "catalog/points_of_focus.yaml").get("points_of_focus", {}) or {})
            if (base / "catalog/points_of_focus.yaml").exists() else {},
        )

    @property
    def in_scope_criteria(self) -> list[str]:
        cats = set(self.scope.get("in_scope_categories", [])) | {"security"}
        return [cid for cid, c in self.criteria.items() if c["category"] in cats]

    @property
    def checks(self) -> list[dict]:
        """Checks defined as code in catalog/checks.yaml (HTTP, TLS and command checks)."""
        if getattr(self, "_checks", None) is None:
            path = self.base / "catalog/checks.yaml"
            self._checks = [dict(c, source="repository") for c in ((_load(path).get("checks") or []) if path.exists() else [])]
        return self._checks

    @property
    def policies(self) -> list[dict]:
        """Markdown policies in policies/ with a YAML front matter header (see TEMPLATE.md)."""
        if getattr(self, "_policies", None) is None:
            self._policies = load_policies(self.base / "policies")
        return self._policies

    def policy(self, pid: str) -> dict | None:
        return next((p for p in self.policies if p["id"] == pid), None)

    def control(self, cid: str) -> dict | None:
        return next((c for c in self.controls if c["id"] == cid), None)

    def coverage(self) -> dict[str, list[str]]:
        cov: dict[str, list[str]] = {cid: [] for cid in self.criteria}
        for ctl in self.controls:
            for crit in ctl.get("criteria", []):
                cov.setdefault(crit, []).append(ctl["id"])
        return cov

    def sources(self, kind: str) -> dict[str, list[str]]:
        """Map collector/tool/task name -> control IDs that rely on it."""
        out: dict[str, list[str]] = {}
        for ctl in self.controls:
            for ev in ctl.get("evidence", []):
                via = str(ev.get("via", ""))
                if via.startswith(f"{kind}:"):
                    out.setdefault(via.split(":", 1)[1], []).append(ctl["id"])
        return out


def validate(cat: Catalog, collectors: set[str]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()

    for ctl in cat.controls:
        cid = ctl.get("id", "<missing id>")
        for key in REQUIRED:
            if not ctl.get(key):
                errors.append(f"{cid}: missing '{key}'")
        if cid in seen:
            errors.append(f"{cid}: duplicate control id")
        seen.add(cid)
        for crit in ctl.get("criteria", []):
            if crit not in cat.criteria:
                errors.append(f"{cid}: unknown criterion {crit}")
        if ctl.get("owner") not in cat.roles:
            errors.append(f"{cid}: owner '{ctl.get('owner')}' not in roles.yaml")
        if ctl.get("frequency") not in FREQUENCIES:
            errors.append(f"{cid}: invalid frequency '{ctl.get('frequency')}'")
        if ctl.get("type") not in TYPES:
            errors.append(f"{cid}: invalid type '{ctl.get('type')}'")
        for ev in ctl.get("evidence", []):
            via = str(ev.get("via", ""))
            kind, _, name = via.partition(":")
            if via == "event":
                continue
            if kind == "collector" and name not in collectors:
                errors.append(f"{cid}: collector '{name}' does not exist")
            elif kind == "task" and name not in cat.tasks:
                errors.append(f"{cid}: task '{name}' not defined in tasks.yaml")
            elif kind == "tool" and name not in KNOWN_TOOLS:
                errors.append(f"{cid}: unknown tool '{name}'")
            elif kind == "check" and name not in {c.get("id") for c in cat.checks}:
                errors.append(f"{cid}: check '{name}' not defined in catalog/checks.yaml")
            elif kind == "git":
                if not (cat.base / name).exists():
                    warnings.append(f"{cid}: git path '{name}' does not exist yet")
            elif kind not in {"collector", "task", "tool", "git"}:
                errors.append(f"{cid}: invalid evidence via '{via}'")

    cov = cat.coverage()
    for crit in cat.in_scope_criteria:
        if not cov.get(crit):
            errors.append(f"in-scope criterion {crit} has no control")
    for crit, ctls in cov.items():
        if crit not in cat.in_scope_criteria and not ctls:
            warnings.append(f"deferred criterion {crit} has no control")

    for name, task in cat.tasks.items():
        for role_key in ("owner", "approver"):
            if task.get(role_key) not in cat.roles:
                errors.append(f"task {name}: {role_key} '{task.get(role_key)}' not in roles.yaml")
        if not set(task.get("months", [])) <= set(range(1, 13)):
            errors.append(f"task {name}: months must be 1-12")
    used_tasks = set(cat.sources("task"))
    for name in cat.tasks:
        if name not in used_tasks:
            warnings.append(f"task {name} is not referenced by any control")

    for risk in cat.risks:
        rid = risk.get("id")
        for ctl in risk.get("controls", []):
            if ctl not in seen:
                errors.append(f"risk {rid}: unknown control {ctl}")
        if risk.get("owner") not in cat.roles:
            errors.append(f"risk {rid}: owner '{risk.get('owner')}' not in roles.yaml")
        if not risk.get("controls") and risk.get("treatment") == "mitigate":
            errors.append(f"risk {rid}: mitigated risk must map to controls")

    for exc in cat.exceptions:
        if exc.get("control") not in seen:
            errors.append(f"exception {exc.get('id')}: unknown control {exc.get('control')}")

    for role, info in cat.roles.items():
        if info.get("person") in (None, "TBD"):
            warnings.append(f"role {role} has no named person")

    for crit, points in cat.points_of_focus.items():
        if crit not in cat.criteria:
            errors.append(f"points of focus: unknown criterion {crit}")
            continue
        for pt in points:
            pid, status = pt.get("id"), pt.get("status")
            if status not in POF_STATUSES:
                errors.append(f"{pid}: invalid status '{status}'")
            for cid in pt.get("controls", []):
                ctl = cat.control(cid)
                if ctl is None:
                    errors.append(f"{pid}: unknown control {cid}")
                elif crit not in ctl.get("criteria", []):
                    errors.append(f"{pid}: control {cid} does not list criterion {crit}")
            if status in ("covered", "partial") and not pt.get("controls"):
                errors.append(f"{pid}: status '{status}' needs at least one control")
            if status in ("gap", "partial"):
                warnings.append(f"{pid} {status}: {pt.get('note') or pt.get('point')}")
    from grcpal.checks import CHECK_TYPES, ID_RE

    check_ids: set[str] = set()
    for chk in cat.checks:
        cid = chk.get("id", "<missing id>")
        if not ID_RE.match(str(cid)) or cid in check_ids:
            errors.append(f"checks.yaml: invalid or duplicate check id '{cid}'")
        check_ids.add(cid)
        if chk.get("type") not in CHECK_TYPES:
            errors.append(f"checks.yaml {cid}: type must be one of {', '.join(CHECK_TYPES)}")
        if chk.get("control") not in seen:
            errors.append(f"checks.yaml {cid}: control '{chk.get('control')}' does not exist")
        need = {"http": "url", "tls": "host", "command": "run"}.get(chk.get("type"))
        if need and not chk.get(need):
            errors.append(f"checks.yaml {cid}: '{need}' is required")
    for crit in cat.in_scope_criteria:
        if cat.points_of_focus and crit not in cat.points_of_focus:
            warnings.append(f"in-scope criterion {crit} has no points of focus mapped")

    return errors, warnings

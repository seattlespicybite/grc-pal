"""Integrations: credentials, connection tests and the registry the Configuration page uses.

Adding a provider:
  1. add a Section to grcpal.settings.SCHEMA (fields with help text);
  2. add a module here with credential/session helpers and validate(settings, ctx) -> Result;
  3. register it in VALIDATORS below and write collectors in grcpal/collectors with PLATFORM set
     to the section id.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    hint: str = ""


@dataclass
class Result:
    checks: list = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str = "", hint: str = "") -> bool:
        self.checks.append(Check(name, ok, detail[:500], hint))
        return ok

    def run(self, name: str, fn, hint: str = "") -> object:
        try:
            value = fn()
        except Exception as exc:  # noqa: BLE001 - every failure becomes a readable check result
            self.add(name, False, _clean(exc), hint)
            return None
        self.add(name, True, value if isinstance(value, str) else "")
        return value

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    def as_dict(self) -> dict:
        passed = sum(c.ok for c in self.checks)
        return {"ok": self.ok, "summary": f"{passed} of {len(self.checks)} checks passed",
                "at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
                "checks": [c.__dict__ for c in self.checks]}


def _clean(exc: Exception) -> str:
    text = f"{type(exc).__name__}: {exc}"
    for marker in ("Bearer ", "AKIA", "github_pat_", "sk-ant-"):
        if marker in text:
            text = text.split(marker)[0] + marker + "[redacted]"
    return text[:400]


class TestContext:
    """What a validator may use besides settings: the portal (storage, mailer) and the person testing."""

    def __init__(self, portal=None, actor=None):
        self.portal, self.actor = portal, actor


def validators() -> dict:
    from grcpal.integrations import ai_check, aws, email_check, gcp, github, microsoft, sources

    return {"microsoft": microsoft.validate, "azure": microsoft.validate_azure, "aws": aws.validate,
            "gcp": gcp.validate, "github": github.validate, "email": email_check.validate,
            "ai": ai_check.validate, "sources": sources.validate}


def validate(section_id: str, settings, ctx: TestContext) -> dict:
    fn = validators().get(section_id)
    result = Result()
    if fn is None:
        result.add("No connection test for this section", True)
        return result.as_dict()
    try:
        fn(settings, ctx, result)
    except Exception as exc:  # noqa: BLE001
        result.add("Connection test", False, _clean(exc))
    if not result.checks:
        result.add("Nothing to test with the current values", False, hint="Fill in the fields above first.")
    return result.as_dict()

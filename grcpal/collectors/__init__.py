"""Evidence collectors.

Each module defines:
    PLATFORM   scope.yaml platform key it depends on (or None)
    DESCRIPTION one line
    run(ctx, run) -> list[dict]   adds artifacts to the run, returns findings
A finding is {"key": stable id, "title": str, "severity": low|medium|high, "detail": dict}.
"""
from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass, field
from importlib import import_module

NAMES = [
    "catalog_validate",
    "entra_users",
    "entra_mfa",
    "entra_roles",
    "entra_apps",
    "conditional_access",
    "leaver_reconcile",
    "intune_devices",
    "azure_inventory",
    "azure_rbac",
    "azure_policy_compliance",
    "azure_backup",
    "github_changes",
    "github_branch_protection",
    "github_vulns",
    "issues_export",
    "portal_audit",
    "aws_iam",
    "aws_cloudtrail",
    "aws_s3",
    "aws_security_services",
    "gcp_iam",
    "gcp_logging",
    "gcp_storage",
    "gcp_firewall",
]

# Collector PLATFORM -> (settings flag that turns it on, scope.yaml platforms key for older catalogs)
PLATFORMS = {
    "identity": ("GRCPAL_MS_ENABLED", "identity"),
    "productivity": ("GRCPAL_MS_ENABLED", "productivity"),
    "endpoints": ("GRCPAL_MS_ENABLED", "endpoints"),
    "cloud": ("GRCPAL_AZURE_ENABLED", "cloud"),
    "source_control": ("GRCPAL_GITHUB_ENABLED", "source_control"),
    "aws": ("GRCPAL_AWS_ENABLED", None),
    "gcp": ("GRCPAL_GCP_ENABLED", None),
}


def platform_enabled(mod, catalog, settings=None) -> bool:
    """A collector runs when its platform is turned on in settings (saved or environment), or, for the original
    platforms, when catalog/scope.yaml lists it and no setting says otherwise."""
    if not mod.PLATFORM:
        return True
    flag, scope_key = PLATFORMS.get(mod.PLATFORM, (None, mod.PLATFORM))
    if settings is not None and flag and settings.source(flag) != "default":
        return settings.flag(flag)
    if scope_key:
        return bool(catalog.scope.get("platforms", {}).get(scope_key))
    return bool(settings is not None and flag and settings.flag(flag))


def disabled_sources(catalog, settings=None) -> set[str]:
    """Collector names whose platform is off; the health report shows them as not applicable."""
    out = set()
    for name in NAMES:
        mod = get(name)
        if mod.PLATFORM and not platform_enabled(mod, catalog, settings):
            out.add(name)
    return out


def get(name: str):
    if name not in NAMES:
        raise KeyError(f"unknown collector {name}")
    return import_module(f"grcpal.collectors.{name}")


@dataclass
class Context:
    clients: object
    catalog: object
    today: dt.date = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc).date())
    window_days: int = int(os.getenv("GRCPAL_WINDOW_DAYS", "31"))
    settings: object = None          # grcpal.settings.Settings; None = environment variables only
    inbox: object = None             # callable(name) -> bytes | None, reads the storage inbox container
    _sessions: dict = field(default_factory=dict)

    def setting(self, key: str, default: str = "") -> str:
        if self.settings is not None:
            return self.settings.get(key, default)
        return os.getenv(key, default)

    def setting_list(self, key: str) -> list[str]:
        return [x.strip() for x in self.setting(key).replace(",", "\n").splitlines() if x.strip()]

    def aws(self, region: str | None = None):
        from grcpal.integrations import aws

        key = f"aws:{region}"
        if key not in self._sessions:
            self._sessions[key] = aws.session(self._settings(), region)
        return self._sessions[key]

    def gcp(self):
        from grcpal.integrations import gcp

        if "gcp" not in self._sessions:
            self._sessions["gcp"] = gcp.session(self._settings())
        return self._sessions["gcp"]

    def _settings(self):
        from grcpal.settings import Settings

        return self.settings if self.settings is not None else Settings()

    def read_input(self, path: str) -> bytes:
        """Local file, or inbox/<name> from the storage account's inbox container."""
        from pathlib import Path

        local = Path(path)
        if local.exists():
            return local.read_bytes()
        if path.startswith("inbox/") and self.inbox is not None:
            data = self.inbox(path.split("/", 1)[1])
            if data is not None:
                return data
        raise FileNotFoundError(f"input file not found: {path}")

    @property
    def repos(self) -> list[str]:
        """Repositories whose changes are in scope, e.g. "acme/app,acme/infra"."""
        return self.setting_list("GRCPAL_REPOS")

    @property
    def grc_repo(self) -> str:
        repo = self.setting("GRCPAL_GRC_REPO") or os.getenv("GITHUB_REPOSITORY")
        if not repo:
            raise RuntimeError("Set GRCPAL_GRC_REPO or GITHUB_REPOSITORY")
        return repo


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def days_since(value: str | None, today: dt.date) -> int | None:
    t = parse_time(value)
    return None if t is None else (today - t.date()).days

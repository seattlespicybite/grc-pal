"""Instance configuration: what GRC-pal connects to and how.

Settings are declared once in SCHEMA (sections of fields with help text). The Configuration page,
the setup wizard, the validators and the collectors all read this one definition, so adding an
integration means adding a section here plus a validator in grcpal.integrations.

Where values come from, in order:
  1. saved on the Configuration page (stored per tenant in the `config` table);
  2. the environment variable with the same name (set by the deployment);
  3. the field default.

Secrets are encrypted with AES-256-GCM before they are stored. The key comes from
GRCPAL_ENCRYPTION_KEY (a Container Apps secret in Azure). Ciphertext is bound to the tenant and
field name, so a value copied to another field or tenant does not decrypt. Saved secrets are never
sent back to the browser, written to logs or put in the audit trail.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import secrets as pysecrets
from dataclasses import dataclass
from pathlib import Path


# ====================================================================== schema
@dataclass(frozen=True)
class Field:
    key: str
    label: str
    help: str
    kind: str = "text"          # text | secret | list | select | bool | url | number | textarea
    options: tuple = ()
    default: str = ""
    placeholder: str = ""
    required_when: str = ""     # "KEY=value": only required when another field has that value
    show_when: str = ""         # "KEY=value[|value]": only shown when another field matches
    advanced: bool = False

    @property
    def secret(self) -> bool:
        return self.kind == "secret"


@dataclass(frozen=True)
class Section:
    id: str
    title: str
    summary: str
    guide: str
    fields: tuple
    enable_key: str = ""        # bool field that turns the integration on
    category: str = "integration"
    testable: bool = True


YES_NO = ("true", "false")

SCHEMA: tuple[Section, ...] = (
    Section(
        "organization", "Organization", "Name shown in the portal and emails.",
        "These settings describe your organization. Scope (which SOC 2 categories are in the audit) lives in "
        "catalog/scope.yaml in your program repository, because scope changes need an approved pull request.",
        (
            Field("GRCPAL_ORG_NAME", "Organization name", "Shown in the sidebar, emails and exports. Leave empty to use "
                  "the name in catalog/scope.yaml.", placeholder="Acme Inc"),
            Field("GRCPAL_SUPPORT_CONTACT", "Support contact", "Email or link people can use when they need help with "
                  "GRC-pal. Shown on error and access-denied pages.", placeholder="security@acme.example"),
            Field("GRCPAL_FRAMEWORKS", "Frameworks in use", "Framework IDs this organization is working on, one per "
                  "line (for example soc2). Leave empty for SOC 2 only. Admins can also turn frameworks on "
                  "and off on the Frameworks page. With one framework, the portal shows only that framework.",
                  kind="list", placeholder="soc2"),
        ), category="general", testable=False),
    Section(
        "microsoft", "Microsoft Entra ID and Microsoft 365", "Users, MFA, roles, apps, Conditional Access, Intune devices.",
        "GRC-pal reads your directory with Microsoft Graph, read-only. Best: run in Azure and use the managed identity "
        "(no secret). Otherwise create an app registration with application permissions User.Read.All, "
        "AuditLog.Read.All, RoleManagement.Read.Directory, Application.Read.All, Policy.Read.All and "
        "DeviceManagementManagedDevices.Read.All, grant admin consent, and enter a client secret here. "
        "The test checks each permission separately.",
        (
            Field("GRCPAL_MS_ENABLED", "Collect from Microsoft Entra ID and Microsoft 365", "Turn off if you do not use "
                  "Microsoft 365.", kind="bool", default="true"),
            Field("GRCPAL_MS_TENANT_ID", "Directory (tenant) ID", "Entra admin center > Overview > Tenant ID. A GUID.",
                  placeholder="00000000-0000-0000-0000-000000000000"),
            Field("GRCPAL_MS_AUTH", "How GRC-pal signs in", "Managed identity: no secret, works when GRC-pal runs in "
                  "Azure. Client secret: an app registration's ID and secret. Default chain: whatever is available "
                  "(environment, managed identity, az login on your computer).", kind="select",
                  options=("managed_identity", "client_secret", "default"), default="default"),
            Field("GRCPAL_MS_CLIENT_ID", "Client (application) ID", "For client secret: the app registration's "
                  "Application (client) ID. For managed identity: the identity's client ID if it is user-assigned.",
                  show_when="GRCPAL_MS_AUTH=client_secret|managed_identity",
                  required_when="GRCPAL_MS_AUTH=client_secret"),
            Field("GRCPAL_MS_CLIENT_SECRET", "Client secret", "App registration > Certificates & secrets > New client "
                  "secret. Copy the Value (not the ID). Set a reminder to rotate it before it expires.",
                  kind="secret", show_when="GRCPAL_MS_AUTH=client_secret", required_when="GRCPAL_MS_AUTH=client_secret"),
        ), enable_key="GRCPAL_MS_ENABLED"),
    Section(
        "azure", "Microsoft Azure", "Resources, RBAC, Azure Policy compliance, backups.",
        "Uses the same identity as Microsoft Entra ID above. Give it the Reader role at the management group or on "
        "each subscription in scope (deploy/azure/grant-permissions.ps1 does this). Assign the built-in Azure "
        "Policy initiative \"SOC 2 Type 2\" in audit mode to get compliance evidence.",
        (
            Field("GRCPAL_AZURE_ENABLED", "Collect from Azure", "Turn off if you have no Azure subscriptions in scope.",
                  kind="bool", default="true"),
            Field("GRCPAL_SUBSCRIPTIONS", "Subscriptions in scope", "One subscription ID per line. Leave empty to include "
                  "every subscription the identity can read.", kind="list"),
            Field("GRCPAL_POLICY_ASSIGNMENT", "Azure Policy assignment name", "Name of the SOC 2 initiative assignment "
                  "(Azure Policy > Assignments). Optional.", placeholder="soc2-audit"),
        ), enable_key="GRCPAL_AZURE_ENABLED"),
    Section(
        "aws", "Amazon Web Services", "IAM and MFA, CloudTrail, S3 public access and encryption, GuardDuty, Config.",
        "GRC-pal needs read-only access: attach the AWS managed policies SecurityAudit and ViewOnlyAccess to a role or "
        "user. Prefer a role: either GitHub OIDC (when collectors run in GitHub Actions) or web identity from the "
        "Azure managed identity. Access keys work but must be rotated. Requires the AWS extra: "
        "pip install \"grc-pal[aws]\".",
        (
            Field("GRCPAL_AWS_ENABLED", "Collect from AWS", "Turn on when you have AWS accounts in scope.", kind="bool",
                  default="false"),
            Field("GRCPAL_AWS_AUTH", "How GRC-pal signs in", "Access key: an IAM user's key pair. Assume role: start "
                  "from the default credentials (environment, instance role, GitHub OIDC) and assume the role below. "
                  "Azure identity: exchange the Azure managed identity token for the role (no secret).",
                  kind="select", options=("access_key", "assume_role", "azure_web_identity", "default"),
                  default="default"),
            Field("GRCPAL_AWS_ACCESS_KEY_ID", "Access key ID", "IAM > Users > Security credentials. Starts with AKIA.",
                  show_when="GRCPAL_AWS_AUTH=access_key", required_when="GRCPAL_AWS_AUTH=access_key"),
            Field("GRCPAL_AWS_SECRET_ACCESS_KEY", "Secret access key", "Shown once when the key is created.",
                  kind="secret", show_when="GRCPAL_AWS_AUTH=access_key", required_when="GRCPAL_AWS_AUTH=access_key"),
            Field("GRCPAL_AWS_ROLE_ARN", "Role ARN", "The read-only role to assume, e.g. "
                  "arn:aws:iam::123456789012:role/grc-pal-reader.", show_when="GRCPAL_AWS_AUTH=assume_role|azure_web_identity",
                  required_when="GRCPAL_AWS_AUTH=azure_web_identity"),
            Field("GRCPAL_AWS_EXTERNAL_ID", "External ID", "Optional extra check in the role's trust policy.",
                  show_when="GRCPAL_AWS_AUTH=assume_role", advanced=True),
            Field("GRCPAL_AWS_WEB_IDENTITY_AUDIENCE", "Token audience", "Application ID URI of the Entra app that AWS "
                  "trusts as an OIDC provider (Azure identity option).", placeholder="api://grc-pal-aws",
                  show_when="GRCPAL_AWS_AUTH=azure_web_identity", required_when="GRCPAL_AWS_AUTH=azure_web_identity"),
            Field("GRCPAL_AWS_REGIONS", "Regions", "One region per line. Regional services (GuardDuty, Config, EBS "
                  "encryption) are checked in each.", kind="list", default="us-east-1"),
        ), enable_key="GRCPAL_AWS_ENABLED"),
    Section(
        "gcp", "Google Cloud", "IAM roles and keys, audit logging, Cloud Storage public access, firewall rules.",
        "Grant a service account the roles Security Reviewer (roles/iam.securityReviewer), Logs Viewer and Browser at "
        "the organization or on each project. Prefer Workload Identity Federation (no key): paste the credential "
        "configuration JSON that gcloud generates. A service account key JSON also works. Requires the GCP extra: "
        "pip install \"grc-pal[gcp]\".",
        (
            Field("GRCPAL_GCP_ENABLED", "Collect from Google Cloud", "Turn on when you have Google Cloud projects in scope.",
                  kind="bool", default="false"),
            Field("GRCPAL_GCP_AUTH", "How GRC-pal signs in", "Workload identity: credential configuration JSON from "
                  "gcloud iam workload-identity-pools create-cred-config. Key: a service account key JSON. "
                  "Default: application default credentials.", kind="select",
                  options=("workload_identity", "service_account_key", "default"), default="default"),
            Field("GRCPAL_GCP_CREDENTIALS_JSON", "Credential JSON", "Paste the whole JSON file. Stored encrypted.",
                  kind="secret", show_when="GRCPAL_GCP_AUTH=workload_identity|service_account_key",
                  required_when="GRCPAL_GCP_AUTH=service_account_key"),
            Field("GRCPAL_GCP_PROJECTS", "Projects in scope", "One project ID per line (not the number).", kind="list"),
            Field("GRCPAL_GCP_ORGANIZATION_ID", "Organization ID", "Optional, numeric. Enables organization-level IAM "
                  "checks.", advanced=True),
        ), enable_key="GRCPAL_GCP_ENABLED"),
    Section(
        "github", "GitHub", "Pull request reviews, branch protection, Dependabot alerts, issues.",
        "Create a fine-grained personal access token or GitHub App token with read access to the repositories in "
        "scope: Contents, Pull requests, Administration (read, for rules), Dependabot alerts, and Issues write on "
        "your program repository (for deficiency issues).",
        (
            Field("GRCPAL_GITHUB_ENABLED", "Collect from GitHub", "Turn off if your code is elsewhere.", kind="bool",
                  default="true"),
            Field("GRCPAL_GITHUB_TOKEN", "Access token", "Fine-grained token, read-only on the repositories below. "
                  "Starts with github_pat_.", kind="secret"),
            Field("GRCPAL_REPOS", "Repositories in scope", "One owner/repo per line: the code that runs your "
                  "product and infrastructure.", kind="list", placeholder="acme/app"),
            Field("GRCPAL_GRC_REPO", "Program repository", "owner/repo of your GRC-pal program repository, where "
                  "deficiency issues are opened.", placeholder="acme/acme-grc"),
            Field("GRCPAL_GITHUB_API_URL", "API URL", "Only for GitHub Enterprise Server.",
                  default="https://api.github.com", advanced=True),
        ), enable_key="GRCPAL_GITHUB_ENABLED"),
    Section(
        "sources", "HR feed and documentation", "Leavers export, endpoints to test, links to documents kept elsewhere.",
        "Some evidence lives outside connected systems. Point GRC-pal at it here; custom controls can link to these "
        "documents and pull them as evidence.",
        (
            Field("GRCPAL_HR_LEAVERS_CSV", "HR leavers export", "Path of the CSV (email,termination_date) that HR drops in "
                  "the inbox container. Used to check access removal for leavers.", default="inbox/hr_leavers.csv"),
            Field("GRCPAL_TLS_TARGETS", "Public endpoints", "One hostname per line. Checked weekly for TLS version and "
                  "certificate expiry.", kind="list", placeholder="app.acme.example"),
            Field("GRCPAL_DOC_LINKS", "Documentation sources", "One per line as Name | URL, e.g. \"Employee handbook | "
                  "https://acme.sharepoint.com/...\". Shown as evidence references and available to custom controls.",
                  kind="textarea"),
        ), category="general", testable=True),
    Section(
        "email", "Email", "Notifications and reminders.",
        "Microsoft 365: use a shared mailbox and send through Microsoft Graph with the managed identity (no secret; "
        "see docs/deploy-azure.md for the one Exchange command). Any other provider: SMTP with TLS. The test sends "
        "a message to you.",
        (
            Field("GRCPAL_MAIL_BACKEND", "Send email with", "Console shows emails on the outbox page without sending "
                  "(for trials).", kind="select", options=("console", "smtp", "graph", "off"), default="console"),
            Field("GRCPAL_MAIL_FROM", "Sender address", "The mailbox emails come from. For Graph, the shared mailbox "
                  "the identity may send as.", placeholder="grc@acme.example"),
            Field("GRCPAL_SMTP_HOST", "SMTP server", "Host name of your mail provider's SMTP relay.",
                  show_when="GRCPAL_MAIL_BACKEND=smtp", required_when="GRCPAL_MAIL_BACKEND=smtp"),
            Field("GRCPAL_SMTP_PORT", "SMTP port", "587 for STARTTLS, 465 for SSL.", kind="number", default="587",
                  show_when="GRCPAL_MAIL_BACKEND=smtp"),
            Field("GRCPAL_SMTP_USER", "SMTP user name", "Leave empty if the relay does not need sign-in.",
                  show_when="GRCPAL_MAIL_BACKEND=smtp"),
            Field("GRCPAL_SMTP_PASSWORD", "SMTP password", "Or an app password.", kind="secret",
                  show_when="GRCPAL_MAIL_BACKEND=smtp"),
            Field("GRCPAL_SMTP_TLS", "Encryption", "Use none only for a local test server.", kind="select",
                  options=("starttls", "ssl", "none"), default="starttls", show_when="GRCPAL_MAIL_BACKEND=smtp"),
        ), category="general"),
    Section(
        "ai", "AI assistant", "Evidence review and mock audits with Claude or a model you run.",
        "AI review sends a control's definition and an evidence summary to the provider you choose. Nothing is sent "
        "until an admin presses a review button. Results are suggestions: a person accepts or dismisses each one, "
        "and both the request and the answer are kept as evidence. Check that your provider's terms allow this data. "
        "Self-hosted models (Ollama, vLLM, LM Studio) keep everything on your network.",
        (
            Field("GRCPAL_AI_PROVIDER", "Provider", "anthropic: Claude API. openai_compatible: any service with an "
                  "OpenAI-style chat endpoint, including Ollama, vLLM, LM Studio, Azure OpenAI and OpenAI. demo: offline "
                  "rule-based reviewer for trying the feature.", kind="select",
                  options=("off", "anthropic", "openai_compatible", "demo"), default="off"),
            Field("GRCPAL_AI_MODEL", "Model", "Claude: e.g. claude-sonnet-5-5 (balanced) or claude-opus-5-5 (most capable). "
                  "Ollama: e.g. llama3.1:70b.", placeholder="claude-sonnet-5-5",
                  show_when="GRCPAL_AI_PROVIDER=anthropic|openai_compatible",
                  required_when="GRCPAL_AI_PROVIDER=openai_compatible"),
            Field("GRCPAL_AI_API_KEY", "API key", "Claude: create a key in the Claude Console. Self-hosted models may "
                  "not need one.", kind="secret", show_when="GRCPAL_AI_PROVIDER=anthropic|openai_compatible",
                  required_when="GRCPAL_AI_PROVIDER=anthropic"),
            Field("GRCPAL_AI_BASE_URL", "Endpoint URL", "Claude: leave empty. Ollama: http://ollama:11434/v1. "
                  "Azure OpenAI: https://<resource>.openai.azure.com/openai/v1.", kind="url",
                  show_when="GRCPAL_AI_PROVIDER=anthropic|openai_compatible",
                  required_when="GRCPAL_AI_PROVIDER=openai_compatible"),
            Field("GRCPAL_AI_SEND_FILES", "Send file contents", "Off: only metadata and collector summaries are sent. "
                  "On: uploaded files (text, CSV, PDF, screenshots) are included, up to the limits below.", kind="bool",
                  default="false", show_when="GRCPAL_AI_PROVIDER=anthropic|openai_compatible|demo"),
            Field("GRCPAL_AI_REDACT_EMAILS", "Mask email addresses", "Replace email addresses with stable tokens "
                  "before sending.", kind="bool", default="true",
                  show_when="GRCPAL_AI_PROVIDER=anthropic|openai_compatible|demo"),
            Field("GRCPAL_AI_MAX_TOKENS", "Maximum answer length (tokens)", "Upper limit per review.", kind="number",
                  default="4000", advanced=True),
            Field("GRCPAL_AI_DAILY_LIMIT", "Daily request limit", "Stops runaway costs. Each control review is one "
                  "request; a full mock audit uses one per control plus one.", kind="number", default="200",
                  advanced=True),
            Field("GRCPAL_AI_DATA_ACK", "Data use confirmed", "Confirm your provider's terms permit sending this "
                  "evidence and that it is not used for training.", kind="bool", default="false",
                  show_when="GRCPAL_AI_PROVIDER=anthropic|openai_compatible"),
        ), category="general"),
)

OPTION_LABELS = {
    "managed_identity": "Managed identity (no secret)", "client_secret": "App registration with a client secret",
    "default": "Default credential chain", "access_key": "IAM user access key", "assume_role": "Assume a role",
    "azure_web_identity": "Azure managed identity to an AWS role (no secret)",
    "workload_identity": "Workload Identity Federation (no key)", "service_account_key": "Service account key",
    "console": "Console outbox (testing, nothing is sent)", "smtp": "SMTP server", "graph": "Microsoft 365 (Graph API)",
    "off": "Off", "anthropic": "Claude (Anthropic API)",
    "openai_compatible": "OpenAI-compatible (Ollama, vLLM, LM Studio, Azure OpenAI, OpenAI)",
    "demo": "Demo reviewer (offline rules, no AI)", "starttls": "STARTTLS (port 587)", "ssl": "SSL/TLS (port 465)",
    "none": "None (local test servers only)",
}

SECTIONS = {s.id: s for s in SCHEMA}
FIELDS = {f.key: f for s in SCHEMA for f in s.fields}


def section_of(key: str) -> Section:
    return next(s for s in SCHEMA if any(f.key == key for f in s.fields))


def _matches(rule: str, values: dict) -> bool:
    if not rule:
        return True
    key, _, allowed = rule.partition("=")
    return str(values.get(key, FIELDS[key].default if key in FIELDS else "")) in allowed.split("|")


def visible(f: Field, values: dict) -> bool:
    return _matches(f.show_when, values)


def required(f: Field, values: dict) -> bool:
    return bool(f.required_when) and _matches(f.required_when, values)


# ====================================================================== encryption
class SecretBox:
    """AES-256-GCM with a per-value random nonce; associated data binds a value to tenant and field."""

    def __init__(self, key: bytes):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self._aes = AESGCM(hashlib.sha256(key).digest())

    def seal(self, plaintext: str, aad: str) -> str:
        nonce = pysecrets.token_bytes(12)
        ct = self._aes.encrypt(nonce, plaintext.encode(), aad.encode())
        return "v1:" + base64.b64encode(nonce + ct).decode()

    def open(self, token: str, aad: str) -> str:
        if not token.startswith("v1:"):
            raise ValueError("unknown secret format")
        raw = base64.b64decode(token[3:])
        return self._aes.decrypt(raw[:12], raw[12:], aad.encode()).decode()


class NoKey(Exception):
    pass


def secret_box() -> SecretBox:
    """Key from GRCPAL_ENCRYPTION_KEY. Outside production a key file is created (mode 0600) on first use."""
    key = os.getenv("GRCPAL_ENCRYPTION_KEY")
    if key:
        return SecretBox(key.encode())
    if os.getenv("GRCPAL_ENV", "").lower() == "production":
        raise NoKey("GRCPAL_ENCRYPTION_KEY is not set, so secrets cannot be stored. Re-run deploy.sh or set the "
                    "Container Apps secret.")
    path = Path(os.getenv("GRCPAL_KEY_FILE", ".grcpal.key"))
    if not path.exists():
        path.write_text(pysecrets.token_hex(32))
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return SecretBox(path.read_text().strip().encode())


# ====================================================================== store and resolution
def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


class Settings:
    """Resolved settings for one tenant. Read-only view; use SettingsStore to change them."""

    def __init__(self, values: dict | None = None, secrets: dict | None = None, box_fn=secret_box,
                 tenant: str = "default", env: bool = True):
        self._values, self._secrets = values or {}, secrets or {}
        self._box_fn, self.tenant, self._env = box_fn, tenant, env

    def source(self, key: str) -> str:
        if key in self._values and self._values[key] not in ("", None):
            return "saved"
        if key in self._secrets:
            return "saved"
        if self._env and os.getenv(key):
            return "environment"
        return "default"

    def get(self, key: str, default: str | None = None) -> str:
        f = FIELDS.get(key)
        if f and f.secret:
            return self.secret(key) or (default or "")
        value = self._values.get(key)
        if value in (None, ""):
            value = os.getenv(key, "") if self._env else ""
        if value in (None, ""):
            value = default if default is not None else (f.default if f else "")
        return str(value)

    def secret(self, key: str) -> str:
        token = self._secrets.get(key, {}).get("enc") if isinstance(self._secrets.get(key), dict) else None
        if token:
            return self._box_fn().open(token, f"{self.tenant}|{key}")
        return os.getenv(key, "") if self._env else ""

    def has_secret(self, key: str) -> bool:
        return bool(self._secrets.get(key)) or (self._env and bool(os.getenv(key)))

    def secret_info(self, key: str) -> dict:
        return {k: v for k, v in (self._secrets.get(key) or {}).items() if k != "enc"}

    def flag(self, key: str) -> bool:
        return self.get(key).lower() in ("true", "1", "yes", "on")

    def list(self, key: str) -> list[str]:
        raw = self.get(key).replace(",", "\n")
        return [x.strip() for x in raw.splitlines() if x.strip()]

    def number(self, key: str) -> int:
        try:
            return int(self.get(key))
        except ValueError:
            return int(FIELDS[key].default or 0)

    def doc_links(self) -> list[tuple[str, str]]:
        out = []
        for line in self.get("GRCPAL_DOC_LINKS").splitlines():
            name, _, url = line.partition("|")
            if url.strip().startswith(("https://", "http://")):
                out.append((name.strip() or url.strip(), url.strip()))
        return out

    def values(self) -> dict:
        return {k: self.get(k) for k, f in FIELDS.items() if not f.secret}

    def overlay(self, values: dict, secrets: dict) -> "Settings":
        """A copy with unsaved form values applied (secrets given in plaintext), for testing before saving."""
        box = self._box_fn
        sealed = dict(self._secrets)
        if secrets:
            b = box()
            for k, v in secrets.items():
                sealed[k] = {"enc": b.seal(v, f"{self.tenant}|{k}")}
        return Settings({**self._values, **values}, sealed, box, self.tenant, self._env)


class SettingsStore:
    """Per-tenant persistence. Rows: PK "cfg", RK = section id, fields values (dict) and secrets (dict)."""

    def __init__(self, store, tenant: str = "default", box_fn=secret_box):
        self.store, self.tenant, self._box_fn = store, tenant, box_fn
        self._cache: Settings | None = None

    def _rows(self) -> dict:
        return {r["RowKey"]: r for r in self.store.list("config", "cfg")}

    def load(self) -> Settings:
        if self._cache is None:
            values, secrets = {}, {}
            for row in self._rows().values():
                values.update(row.get("values") or {})
                secrets.update(row.get("secrets") or {})
            self._cache = Settings(values, secrets, self._box_fn, self.tenant)
        return self._cache

    def row(self, section: str) -> dict:
        return self.store.get("config", "cfg", section) or {}

    def save(self, section_id: str, form: dict, actor: str) -> tuple[list[str], list[str]]:
        """Validate and persist one section. Returns (changed keys, errors). Secret fields: a blank input keeps
        the saved value; the special value "__clear__" removes it."""
        section = SECTIONS[section_id]
        current = self.row(section_id)
        values = dict(current.get("values") or {})
        secrets = dict(current.get("secrets") or {})
        merged_view = {**self.load().values(), **values}
        changed, errors = [], []
        for f in section.fields:
            if f.secret:
                raw = form.get(f.key, "")
                if raw == "__clear__":
                    if f.key in secrets:
                        secrets.pop(f.key)
                        changed.append(f.key)
                elif raw.strip():
                    secrets[f.key] = {"enc": self._box_fn().seal(raw.strip(), f"{self.tenant}|{f.key}"),
                                      "set_at": _now(), "set_by": actor}
                    changed.append(f.key)
                continue
            if f.kind == "bool":
                new = "true" if form.get(f.key) in ("true", "on", "1") else "false"
            else:
                new = (form.get(f.key) or "").strip()
                if f.kind == "list":
                    new = "\n".join(x.strip() for x in new.replace(",", "\n").splitlines() if x.strip())
            if f.kind == "number" and new and not new.isdigit():
                errors.append(f"{f.label} must be a number")
                continue
            if f.kind == "select" and new and new not in f.options:
                errors.append(f"{f.label}: choose one of {', '.join(f.options)}")
                continue
            if f.kind == "url" and new and not new.startswith(("https://", "http://")):
                errors.append(f"{f.label} must start with https://")
                continue
            if len(new) > 8000:
                errors.append(f"{f.label} is too long")
                continue
            if values.get(f.key, "") != new:
                values[f.key] = new
                changed.append(f.key)
            merged_view[f.key] = new
        for f in section.fields:
            if required(f, merged_view):
                has = (f.key in secrets or os.getenv(f.key)) if f.secret else (merged_view.get(f.key) or os.getenv(f.key))
                if not has:
                    errors.append(f"{f.label} is required for this option")
        if errors:
            return [], errors
        self.store.upsert("config", {"PartitionKey": "cfg", "RowKey": section_id, "values": values, "secrets": secrets,
                                     "updated_at": _now(), "updated_by": actor,
                                     "last_test": current.get("last_test") or {}})
        self._cache = None
        return changed, []

    def seal_secret(self, field: str, plaintext: str) -> str:
        """Encrypt a secret that is not a Configuration field (for example one application's API token). The
        value is bound to this tenant and to `field`, so it cannot be moved to another tenant or field."""
        return self._box_fn().seal(plaintext, f"{self.tenant}|{field}")

    def open_secret(self, field: str, token: str) -> str:
        return self._box_fn().open(token, f"{self.tenant}|{field}") if token else ""

    def record_test(self, section_id: str, result: dict) -> None:
        row = self.row(section_id) or {"PartitionKey": "cfg", "RowKey": section_id, "values": {}, "secrets": {}}
        row["last_test"] = {k: result[k] for k in ("ok", "summary", "at") if k in result}
        self.store.upsert("config", row)
        self._cache = None

    def state(self, key: str, default=None):
        row = self.store.get("config", "state", key)
        return json.loads(row["json"]) if row else default

    def set_state(self, key: str, value) -> None:
        self.store.upsert("config", {"PartitionKey": "state", "RowKey": key, "json": json.dumps(value)})


def section_status(store: SettingsStore, settings: Settings, section: Section) -> str:
    """not_configured | disabled | configured | ok | failed"""
    if section.enable_key and not settings.flag(section.enable_key):
        return "disabled"
    row = store.row(section.id)
    test = (row or {}).get("last_test") or {}
    if test:
        return "ok" if test.get("ok") else "failed"
    configured = any(settings.source(f.key) != "default" for f in section.fields if f.key != section.enable_key)
    return "configured" if configured else "not_configured"

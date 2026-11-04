"""Remediation tickets: open one Jira issue or GitHub issue per application after an access review.

GRC-pal never disables or changes an account itself. A ticket asks the people who run the application to make
the change; an admin then confirms it in GRC-pal (or the next account pull shows it). Settings live in
Configuration > Remediation tickets.

Safety:
  * Jira's address is admin-configured, so calls go through checks.safe_request (public addresses only unless
    GRCPAL_JIRA_ALLOW_PRIVATE=1 for Jira Data Center on your own network; redirects to another host drop the token).
    Changing the Jira address clears the saved token (settings.ENDPOINT_SECRETS).
  * GitHub uses the existing GitHub token and client (grcpal.clients), which applies the same guard.
  * Text from reviewers is put in tickets as plain text: no @mentions (they would notify people), no Jira markup.
"""
from __future__ import annotations

import base64
import json
import re

from grcpal import checks

SYSTEMS = ("off", "jira", "github")
_JIRA_KEY = re.compile(r"^[A-Z][A-Z0-9_]{1,19}$")
_REPO = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_MENTION = re.compile(r"(?<![\w.+-])@")


class TicketError(Exception):
    """A ticket could not be created. The message is safe to show to an admin (no secrets)."""


def system(settings) -> str:
    value = (settings.get("GRCPAL_TICKETS_SYSTEM") or "off").strip().lower()
    return value if value in SYSTEMS else "off"


def plain(text: str, limit: int = 500) -> str:
    """One line of reviewer text, safe in a Jira or GitHub issue: no control characters, no mentions or markup."""
    text = _CONTROL.sub(" ", str(text or "")).replace("\n", " ").replace("\r", " ")
    text = _MENTION.sub("@\u200b", text)            # GitHub @mention or team mention; email addresses stay intact
    for ch in "[]{}|":                                # Jira wiki markup: links, user mentions, tables, macros
        text = text.replace(ch, "\\" + ch)
    return text.strip()[:limit]


def problems(settings) -> list[str]:
    kind = system(settings)
    if kind == "jira":
        out = []
        url = (settings.get("GRCPAL_JIRA_URL") or "").strip()
        if not url.startswith("https://"):
            out.append("Jira address must start with https://")
        if not _JIRA_KEY.match((settings.get("GRCPAL_JIRA_PROJECT") or "").strip()):
            out.append("Jira project key must be capital letters and digits, for example IT")
        if not settings.secret("GRCPAL_JIRA_TOKEN"):
            out.append("Jira API token is missing")
        return out
    if kind == "github":
        out = []
        if not _REPO.match(repo(settings)):
            out.append("Repository must be owner/repo")
        if not settings.secret("GRCPAL_GITHUB_TOKEN"):
            out.append("The GitHub token (Configuration > GitHub) is missing")
        return out
    return ["Remediation tickets are turned off"]


def repo(settings) -> str:
    return (settings.get("GRCPAL_TICKETS_REPO") or settings.get("GRCPAL_GRC_REPO") or "").strip()


# ====================================================================== Jira
def _jira_headers(settings) -> dict:
    token = settings.secret("GRCPAL_JIRA_TOKEN")
    email = (settings.get("GRCPAL_JIRA_EMAIL") or "").strip()
    if email:  # Jira Cloud: email + API token
        auth = "Basic " + base64.b64encode(f"{email}:{token}".encode()).decode()
    else:      # Jira Data Center / Server: personal access token
        auth = f"Bearer {token}"
    return {"Authorization": auth, "Accept": "application/json", "Content-Type": "application/json"}


def _jira(settings, method: str, path: str, body: dict | None = None, request_fn=None):
    base = (settings.get("GRCPAL_JIRA_URL") or "").strip().rstrip("/")
    fn = request_fn or checks.safe_request
    return fn(method, base + path, headers=_jira_headers(settings),
              body=json.dumps(body) if body is not None else None, timeout=20,
              allow_private=checks.private_allowed("GRCPAL_JIRA_ALLOW_PRIVATE"), user_agent="GRC-pal/1")


def jira_create(settings, title: str, lines: list[str], request_fn=None) -> dict:
    base = (settings.get("GRCPAL_JIRA_URL") or "").strip().rstrip("/")
    body = {"fields": {"project": {"key": settings.get("GRCPAL_JIRA_PROJECT").strip()},
                       "issuetype": {"name": (settings.get("GRCPAL_JIRA_ISSUE_TYPE") or "Task").strip()},
                       "summary": title[:250], "description": "\n".join(lines)[:30000],
                       "labels": ["access-review", "grc-pal"]}}
    # API v2 takes a plain-text description and works on both Jira Cloud and Jira Data Center.
    r = _jira(settings, "POST", "/rest/api/2/issue", body, request_fn)
    if r.status_code not in (200, 201):
        raise TicketError(f"Jira refused the ticket (HTTP {r.status_code}): {_jira_error(r)}")
    key = str((r.json() or {}).get("key") or "")
    if not key:
        raise TicketError("Jira did not return an issue key")
    return {"system": "jira", "key": key, "url": f"{base}/browse/{key}"}


def _jira_error(r) -> str:
    try:
        data = r.json() or {}
        msgs = list(data.get("errorMessages") or []) + [f"{k}: {v}" for k, v in (data.get("errors") or {}).items()]
        return "; ".join(str(m) for m in msgs)[:300] or "no detail"
    except ValueError:
        return "no detail"


# ====================================================================== GitHub Issues
def github_create(settings, title: str, lines: list[str], clients=None) -> dict:
    from grcpal.clients import ApiError, Clients

    gh = clients or Clients(settings)
    try:
        issue = gh.gh_post(f"/repos/{repo(settings)}/issues", {"title": title[:250], "body": "\n".join(lines)[:60000]})
    except ApiError as exc:
        raise TicketError(f"GitHub refused the issue (HTTP {exc.status}). The token needs Issues: write on "
                          f"{repo(settings)}") from exc
    if not issue or not issue.get("number"):
        raise TicketError("GitHub did not return an issue number")
    return {"system": "github", "key": f"#{issue['number']}", "url": str(issue.get("html_url") or "")}


def create(settings, title: str, lines: list[str], request_fn=None, clients=None) -> dict:
    found = problems(settings)
    if found:
        raise TicketError("; ".join(found))
    if system(settings) == "jira":
        return jira_create(settings, title, lines, request_fn)
    return github_create(settings, title, lines, clients)


# ====================================================================== connection test
def validate(settings, ctx, result, request_fn=None, clients=None) -> None:
    kind = system(settings)
    if kind == "off":
        result.add("Remediation tickets are turned off", True)
        return
    for p in problems(settings):
        result.add("Settings", False, p)
    if problems(settings):
        return
    if kind == "jira":
        key = settings.get("GRCPAL_JIRA_PROJECT").strip()

        def me() -> str:
            r = _jira(settings, "GET", "/rest/api/2/myself", request_fn=request_fn)
            if r.status_code != 200:
                raise TicketError(f"HTTP {r.status_code}: check the address, email and API token")
            return f"signed in as {(r.json() or {}).get('displayName', 'the token owner')}"

        def project() -> str:
            r = _jira(settings, "GET", f"/rest/api/2/project/{key}", request_fn=request_fn)
            if r.status_code != 200:
                raise TicketError(f"HTTP {r.status_code}: the project does not exist or the account cannot see it")
            return f"project {key} found"

        if result.run("Jira sign-in", me):
            result.run(f"Jira project {key}", project, hint="The account needs Create issues in this project.")
        return
    from grcpal.clients import Clients

    gh = clients or Clients(settings)

    def can_open() -> str:
        info = gh.gh_get(f"/repos/{repo(settings)}") or {}
        perms = info.get("permissions") or {}
        if not (perms.get("push") or perms.get("triage") or perms.get("maintain") or perms.get("admin")):
            raise TicketError("the token cannot open issues there (needs Issues: write)")
        return f"issues can be opened in {repo(settings)}"

    result.run("GitHub repository", can_open, hint="Give the fine-grained token Issues: read and write on this repository.")

"""GitHub: token and repository access test. Requests go through checks.safe_request (see clients.gh_request)."""
from __future__ import annotations

from grcpal.checks import Blocked
from grcpal.clients import gh_request


def headers(settings) -> dict:
    token = settings.secret("GRCPAL_GITHUB_TOKEN") or settings.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("No GitHub token configured")
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"}


def validate(settings, ctx, result) -> None:
    if not settings.flag("GRCPAL_GITHUB_ENABLED"):
        result.add("GitHub collection is turned off", True)
        return
    api = settings.get("GRCPAL_GITHUB_API_URL").rstrip("/")
    try:
        hdrs = headers(settings)
    except ValueError as exc:
        result.add("Token", False, str(exc), "Create a fine-grained token and paste it above.")
        return
    try:
        r = gh_request("GET", f"{api}/rate_limit", hdrs, timeout=20)
    except Blocked as exc:
        result.add("API URL", False, f"Blocked: {exc}",
                   "Use a public GitHub API address. GitHub Enterprise Server on a private network needs "
                   "GRCPAL_GITHUB_ALLOW_PRIVATE=1 in the deployment environment.")
        return
    if not result.add("Token accepted", r.status_code == 200, f"HTTP {r.status_code}",
                      "The token is invalid or expired. Create a new one."):
        return
    remaining = r.json().get("resources", {}).get("core", {}).get("remaining")
    result.add("API rate limit", True, f"{remaining} requests left this hour")
    repos = settings.list("GRCPAL_REPOS")
    if not repos:
        result.add("Repositories in scope", False, "none listed", "Add at least one owner/repo.")
    for repo in repos:
        rr = gh_request("GET", f"{api}/repos/{repo}", hdrs, timeout=20)
        result.add(f"Read {repo}", rr.status_code == 200, f"HTTP {rr.status_code}",
                   "Give the token read access to this repository (Contents, Pull requests, Administration read).")
    grc = settings.get("GRCPAL_GRC_REPO")
    if grc:
        rr = gh_request("GET", f"{api}/repos/{grc}", hdrs, timeout=20)
        can_push = rr.status_code == 200 and (rr.json().get("permissions") or {}).get("push", False)
        result.add(f"Open issues in {grc}", can_push, "write access" if can_push else f"HTTP {rr.status_code}, no write",
                   "Give the token Issues: read and write on the program repository.")

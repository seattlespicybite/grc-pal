"""API clients for Microsoft Graph, Azure Resource Graph and GitHub.

Authentication:
  * Microsoft: azure-identity DefaultAzureCredential. In GitHub Actions use OIDC workload
    identity federation (no stored secrets); locally `az login` works; in Azure Automation
    or Functions a managed identity works.
  * GitHub: GITHUB_TOKEN environment variable (the Actions token or a fine-grained PAT).
All calls are read-only except GitHub issue creation used by tasks and deficiency tracking.

GitHub calls go through checks.safe_request because the API URL can be changed on the Configuration page: public
addresses only, redirects re-checked, the token dropped on a cross-host redirect. GitHub Enterprise Server on a
private network needs GRCPAL_GITHUB_ALLOW_PRIVATE=1 in the environment. Graph and Azure Resource Manager use fixed
Microsoft hosts and keep the requests session.
"""
from __future__ import annotations

import json as jsonlib
import os
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

import requests

from grcpal import checks

GRAPH = "https://graph.microsoft.com/v1.0"
ARM = "https://management.azure.com"
GITHUB = "https://api.github.com"
_RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


def gh_request(method: str, url: str, headers: dict, *, params: dict | None = None, json: Any = None,
               timeout: float = 60) -> checks.Response:
    """One GitHub API request through the outbound guard."""
    if params:
        url += ("&" if urlsplit(url).query else "?") + urlencode(params)
    hdrs = dict(headers)
    body = None
    if json is not None:
        body = jsonlib.dumps(json)
        hdrs.setdefault("Content-Type", "application/json")
    return checks.safe_request(method, url, headers=hdrs, body=body, timeout=timeout, max_bytes=MAX_RESPONSE_BYTES,
                               user_agent="GRC-pal/1", allow_private=checks.private_allowed("GRCPAL_GITHUB_ALLOW_PRIVATE"))


class ApiError(RuntimeError):
    def __init__(self, status: int, url: str, body: str):
        super().__init__(f"HTTP {status} for {url}: {body[:300]}")
        self.status = status


class Clients:
    def __init__(self, settings=None) -> None:
        """settings: grcpal.settings.Settings. Without it, credentials come from the environment."""
        self.session = requests.Session()
        self.settings = settings
        self._credential = None
        self._tokens: dict[str, tuple[str, float]] = {}
        # Provenance for evidence: one entry per list call (API, request, record count, identity, request id).
        # The CLI copies it into each run's manifest so auditors can test completeness and accuracy.
        self.queries: list[dict] = []

    def _record(self, api: str, request: str, records: int, pages: int, resp=None, **extra) -> None:
        headers = getattr(resp, "headers", None) or {}
        rid = headers.get("request-id") or headers.get("x-ms-request-id") or headers.get("x-github-request-id")
        entry = {"api": api, "request": request[:500], "records": records, "pages": pages,
                 "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **extra}
        if rid:
            entry["request_id"] = rid
        if api in ("microsoft-graph", "azure-resource-graph") and self.settings is not None:
            entry["identity"] = {k: v for k, v in (("tenant_id", self.settings.get("GRCPAL_MS_TENANT_ID")),
                                                   ("client_id", self.settings.get("GRCPAL_MS_CLIENT_ID")),
                                                   ("auth", self.settings.get("GRCPAL_MS_AUTH"))) if v}
        self.queries.append(entry)

    # ---------------- auth ----------------
    def _azure_token(self, scope: str) -> str:
        cached = self._tokens.get(scope)
        if cached and cached[1] - 120 > time.time():
            return cached[0]
        if self._credential is None:
            if self.settings is not None:
                from grcpal.integrations.microsoft import credential

                self._credential = credential(self.settings)
            else:
                from azure.identity import DefaultAzureCredential

                self._credential = DefaultAzureCredential()
        tok = self._credential.get_token(scope)
        self._tokens[scope] = (tok.token, tok.expires_on)
        return tok.token

    @property
    def github_api(self) -> str:
        if self.settings is not None:
            return self.settings.get("GRCPAL_GITHUB_API_URL", GITHUB).rstrip("/")
        return GITHUB

    def _github_headers(self) -> dict[str, str]:
        token = (self.settings.secret("GRCPAL_GITHUB_TOKEN") if self.settings is not None else "") \
            or os.getenv("GRCPAL_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN")
        if not token:
            raise RuntimeError("No GitHub token: set it under Configuration > GitHub (or GITHUB_TOKEN)")
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    # ---------------- transport ----------------
    def _request(self, method: str, url: str, *, headers: dict, params=None, json=None,
                 allow_404: bool = False) -> requests.Response | None:
        for attempt in range(6):
            resp = self.session.request(method, url, headers=headers, params=params, json=json, timeout=60)
            if resp.status_code in _RETRY_STATUS:
                wait = float(resp.headers.get("Retry-After", 2 ** attempt))
                time.sleep(min(wait, 60))
                continue
            if allow_404 and resp.status_code == 404:
                return None
            if resp.status_code >= 400:
                raise ApiError(resp.status_code, url, resp.text)
            return resp
        raise ApiError(resp.status_code, url, "retries exhausted")

    def _gh(self, method: str, url: str, *, params=None, json=None, allow_404: bool = False) -> checks.Response | None:
        headers = self._github_headers()
        for attempt in range(6):
            resp = gh_request(method, url, headers, params=params, json=json)
            if resp.status in _RETRY_STATUS:
                try:
                    wait = float(resp.headers.get("retry-after", 2 ** attempt))
                except ValueError:
                    wait = 2 ** attempt
                time.sleep(min(wait, 60))
                continue
            if allow_404 and resp.status == 404:
                return None
            if resp.status >= 400:
                raise ApiError(resp.status, url, resp.text())
            if resp.truncated:
                raise ApiError(resp.status, url, f"response too large (over {MAX_RESPONSE_BYTES} bytes)")
            return resp
        raise ApiError(resp.status, url, "retries exhausted")

    # ---------------- Microsoft Graph ----------------
    def graph_list(self, path: str, params: dict | None = None, headers: dict | None = None) -> list[dict]:
        url = path if path.startswith("http") else GRAPH + path
        hdrs = {"Authorization": f"Bearer {self._azure_token('https://graph.microsoft.com/.default')}"}
        hdrs.update(headers or {})
        items: list[dict] = []
        request, pages, first = path + ("?" + "&".join(f"{k}={v}" for k, v in params.items()) if params else ""), 0, None
        while url:
            resp = self._request("GET", url, headers=hdrs, params=params)
            first, pages = first or resp, pages + 1
            data = resp.json()
            items.extend(data.get("value", []))
            url, params = data.get("@odata.nextLink"), None
        self._record("microsoft-graph", request, len(items), pages, first)
        return items

    # ---------------- Azure Resource Graph ----------------
    def arg_query(self, query: str, subscriptions: list[str] | None = None) -> list[dict]:
        url = f"{ARM}/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
        hdrs = {"Authorization": f"Bearer {self._azure_token('https://management.azure.com/.default')}"}
        subs = subscriptions or (self.settings.list("GRCPAL_SUBSCRIPTIONS") if self.settings is not None
                                 else [s for s in os.getenv("GRCPAL_SUBSCRIPTIONS", "").split(",") if s])
        rows: list[dict] = []
        skip, pages, first = None, 0, None
        while True:
            body: dict[str, Any] = {"query": query, "options": {"$top": 1000}}
            if subs:
                body["subscriptions"] = subs
            if skip:
                body["options"]["$skipToken"] = skip
            resp = self._request("POST", url, headers=hdrs, json=body)
            first, pages = first or resp, pages + 1
            data = resp.json()
            rows.extend(data.get("data", []))
            skip = data.get("$skipToken")
            if not skip:
                self._record("azure-resource-graph", " ".join(query.split()), len(rows), pages, first,
                             subscriptions=subs or "all visible")
                return rows

    # ---------------- GitHub ----------------
    def gh_list(self, path: str, params: dict | None = None, max_pages: int = 50, complete: bool = False) -> list[dict]:
        """All pages up to max_pages. complete=True raises instead of silently stopping when more pages remain
        (used where a partial list would be wrong evidence, such as access review populations)."""
        url = path if path.startswith("http") else self.github_api + path
        params = dict(params or {}, per_page=100)
        items: list[dict] = []
        first = None
        for page in range(1, max_pages + 1):
            resp = self._gh("GET", url, params=params)
            first = first or resp
            data = resp.json()
            items.extend(data if isinstance(data, list) else data.get("items", []))
            nxt = resp.links.get("next", {}).get("url")
            if not nxt:
                self._record("github", path, len(items), page, first)
                return items
            url, params = nxt, None
        if complete:
            raise RuntimeError(f"More than {max_pages} pages from {path}; refusing an incomplete list")
        self._record("github", path, len(items), max_pages, first, truncated=True)
        return items

    def gh_get(self, path: str, allow_404: bool = False) -> dict | None:
        resp = self._gh("GET", self.github_api + path, allow_404=allow_404)
        return None if resp is None else resp.json()

    def gh_post(self, path: str, body: dict, ok_statuses: tuple[int, ...] = ()) -> dict | None:
        try:
            resp = self._gh("POST", self.github_api + path, json=body)
            return resp.json()
        except ApiError as err:
            if err.status in ok_statuses:
                return None
            raise

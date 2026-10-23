"""Outbound endpoint controls (hardening batch B3, finding F-11).

The AI provider, GitHub and Microsoft Graph calls go through the same guard as custom checks
(`checks.safe_request`): public addresses only, every redirect re-checked, credentials dropped when a redirect
leaves the original host. Changing an endpoint on the Configuration page clears that section's secret unless a
new one is entered in the same save, and every Configuration change is audited and emailed to all admins.
"""
from __future__ import annotations

import json

import pytest
import requests

from grcpal import checks, clients
from grcpal.ai import providers
from grcpal.integrations import github as gh_integration
from grcpal.integrations import microsoft as ms_integration
from grcpal.portal.service import Invalid
from grcpal.settings import Settings
from test_portal import ADMIN, ADMIN2, make_portal


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail loudly if anything bypasses the guard with plain `requests`, and never touch the network."""
    def refuse(*a, **k):
        raise AssertionError(f"unguarded outbound request: {a[:2]}")

    for name in ("get", "post", "put", "patch", "delete", "request"):
        monkeypatch.setattr(requests, name, refuse)
    monkeypatch.setattr(requests.Session, "request", refuse)
    for var in ("GRCPAL_CHECKS_ALLOW_PRIVATE", "GRCPAL_AI_ALLOW_PRIVATE", "GRCPAL_GITHUB_ALLOW_PRIVATE",
                "GRCPAL_SMTP_PASSWORD", "GRCPAL_AI_API_KEY", "GRCPAL_GITHUB_TOKEN", "GITHUB_TOKEN", "GRCPAL_ENV",
                "GRCPAL_AI_BASE_URL", "GRCPAL_GITHUB_API_URL", "GRCPAL_SMTP_HOST", "GRCPAL_ENCRYPTION_KEY"):
        monkeypatch.delenv(var, raising=False)


class Wire:
    """Stands in for the pinned connections in checks.py and records what would have been sent."""

    def __init__(self, monkeypatch, replies=None, addresses=None):
        self.sent: list[dict] = []
        self.replies = list(replies or [])
        wire = self
        real_resolve = checks.resolve_public

        def resolve(host, port, allow_private=None):
            if addresses and host in addresses:
                ip = addresses[host]
                if ip != "public":
                    return real_resolve(ip, port, allow_private)
                return "93.184.216.34"
            return real_resolve(host, port, allow_private)

        class Resp:
            def __init__(self, status, headers, body):
                self.status, self._headers, self._body = status, headers, body

            def getheaders(self):
                return list(self._headers.items())

            def read(self, n=None):
                return self._body

        class Conn:
            def __init__(self, host, address, port, timeout, context=None):
                self.host, self.address, self.port = host, address, port

            def request(self, method, path, body=None, headers=None):
                wire.sent.append({"method": method, "host": self.host, "address": self.address, "path": path,
                                  "headers": dict(headers or {}), "body": body})

            def getresponse(self):
                status, headers, body = wire.replies.pop(0) if wire.replies else (200, {}, b"{}")
                return Resp(status, headers, body)

            def close(self):
                pass

        monkeypatch.setattr(checks, "resolve_public", resolve)
        monkeypatch.setattr(checks, "_PinnedHTTPS", Conn)
        monkeypatch.setattr(checks, "_PinnedHTTP", Conn)


def _json(data) -> tuple:
    return (200, {"Content-Type": "application/json"}, json.dumps(data).encode())


OK_CHAT = _json({"choices": [{"message": {"content": "OK"}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}})


# ================================================================ AI provider
@pytest.mark.parametrize("base", ["http://169.254.169.254/latest", "http://127.0.0.1:11434/v1", "http://10.0.0.5/v1",
                                  "http://[::1]:8080/v1", "file:///etc/passwd"])
def test_ai_provider_refuses_internal_endpoints(monkeypatch, base):
    wire = Wire(monkeypatch)
    with pytest.raises(providers.ProviderError, match="blocked|non-public|only http"):
        providers.OpenAICompatibleProvider("m", "sk-secret", base).complete("sys", [{"type": "text", "text": "hi"}])
    assert wire.sent == []


def test_ai_provider_private_endpoint_needs_explicit_opt_in(monkeypatch):
    wire = Wire(monkeypatch, [OK_CHAT])
    monkeypatch.setenv("GRCPAL_CHECKS_ALLOW_PRIVATE", "1")    # the checks switch does not open AI calls
    with pytest.raises(providers.ProviderError):
        providers.OpenAICompatibleProvider("llama3.1", "", "http://10.0.0.5:11434/v1").complete(
            "sys", [{"type": "text", "text": "hi"}])
    monkeypatch.setenv("GRCPAL_AI_ALLOW_PRIVATE", "1")
    c = providers.OpenAICompatibleProvider("llama3.1", "", "http://10.0.0.5:11434/v1").complete(
        "sys", [{"type": "text", "text": "hi"}])
    assert c.text == "OK" and wire.sent[0]["address"] == "10.0.0.5" and wire.sent[0]["path"] == "/v1/chat/completions"


def test_ai_opt_in_never_opens_cloud_metadata(monkeypatch):
    wire = Wire(monkeypatch)
    monkeypatch.setenv("GRCPAL_AI_ALLOW_PRIVATE", "1")
    with pytest.raises(providers.ProviderError, match="link-local"):
        providers.OpenAICompatibleProvider("m", "", "http://169.254.169.254/v1").complete(
            "sys", [{"type": "text", "text": "hi"}])
    assert wire.sent == []


def test_ai_provider_redirect_to_metadata_is_blocked(monkeypatch):
    wire = Wire(monkeypatch, [(307, {"Location": "http://169.254.169.254/latest/meta-data/"}, b"")],
                {"llm.example.com": "public"})
    with pytest.raises(providers.ProviderError, match="non-public"):
        providers.OpenAICompatibleProvider("m", "sk-secret", "https://llm.example.com/v1").complete(
            "sys", [{"type": "text", "text": "hi"}])
    assert len(wire.sent) == 1


def test_ai_provider_request_shape_and_retry_through_guard(monkeypatch):
    monkeypatch.setattr(providers.time, "sleep", lambda s: None)
    reply = _json({"content": [{"type": "text", "text": "fine"}], "model": "claude-sonnet-5-5",
                   "usage": {"input_tokens": 3, "output_tokens": 2}})
    wire = Wire(monkeypatch, [(529, {"Retry-After": "1"}, b"busy"), reply], {"api.anthropic.com": "public"})
    c = providers.AnthropicProvider("", "sk-ant-test").complete("sys", [{"type": "text", "text": "hi"}], 100)
    assert c.text == "fine" and c.input_tokens == 3 and len(wire.sent) == 2
    first = wire.sent[0]
    assert first["host"] == "api.anthropic.com" and first["path"] == "/v1/messages"
    assert first["headers"]["x-api-key"] == "sk-ant-test" and json.loads(first["body"])["system"] == "sys"


def test_ai_provider_error_text_is_reported(monkeypatch):
    Wire(monkeypatch, [(401, {}, b'{"error": "bad key"}')], {"api.anthropic.com": "public"})
    with pytest.raises(providers.ProviderError, match="HTTP 401: .*bad key"):
        providers.AnthropicProvider("", "sk-ant-test").complete("sys", [{"type": "text", "text": "hi"}])


# ================================================================ redirects and credentials
def test_cross_host_redirect_drops_credentials_same_host_keeps_them(monkeypatch):
    wire = Wire(monkeypatch, [(301, {"Location": "/v2/x"}, b""), (302, {"Location": "https://other.example.net/y"}, b""),
                              (200, {}, b"ok")], {"api.example.com": "public", "other.example.net": "public"})
    checks.safe_request("GET", "https://api.example.com/v1/x",
                        headers={"Authorization": "Bearer t0p", "X-Api-Key": "k", "Accept": "application/json"})
    assert [s["host"] for s in wire.sent] == ["api.example.com", "api.example.com", "other.example.net"]
    assert wire.sent[1]["headers"]["Authorization"] == "Bearer t0p"
    last = wire.sent[2]["headers"]
    assert "Authorization" not in last and "X-Api-Key" not in last and last["Accept"] == "application/json"


# ================================================================ GitHub
class _GhSettings(Settings):
    def secret(self, key):
        return "ghp_secret" if key == "GRCPAL_GITHUB_TOKEN" else ""


class FakeResult:
    def __init__(self):
        self.checks = []

    def add(self, name, ok, detail="", hint=""):
        self.checks.append((name, ok, detail))
        return ok

    def run(self, name, fn, hint=""):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            self.checks.append((name, False, str(exc)))
            return None


@pytest.mark.parametrize("api", ["http://169.254.169.254", "http://127.0.0.1:8080/api/v3", "http://10.9.8.7"])
def test_github_connection_test_refuses_internal_api_url(monkeypatch, api):
    wire = Wire(monkeypatch)
    s = _GhSettings({"GRCPAL_GITHUB_ENABLED": "true", "GRCPAL_GITHUB_API_URL": api, "GRCPAL_REPOS": "acme/app"}, env=False)
    result = FakeResult()
    gh_integration.validate(s, None, result)
    assert wire.sent == []
    assert result.checks and not result.checks[0][1] and "blocked" in result.checks[0][2].lower()


def test_github_connection_test_works_through_guard(monkeypatch):
    wire = Wire(monkeypatch, [_json({"resources": {"core": {"remaining": 4999}}}), _json({"full_name": "acme/app"})],
                {"api.github.com": "public"})
    s = _GhSettings({"GRCPAL_GITHUB_ENABLED": "true", "GRCPAL_REPOS": "acme/app"}, env=False)
    result = FakeResult()
    gh_integration.validate(s, None, result)
    assert all(ok for _, ok, _ in result.checks), result.checks
    assert [w["path"] for w in wire.sent] == ["/rate_limit", "/repos/acme/app"]
    assert wire.sent[0]["headers"]["Authorization"] == "Bearer ghp_secret"


def test_github_enterprise_on_private_network_needs_opt_in(monkeypatch):
    wire = Wire(monkeypatch, [_json({"login": "bot"})])
    c = clients.Clients(_GhSettings({"GRCPAL_GITHUB_API_URL": "http://10.9.8.7/api/v3"}, env=False))
    with pytest.raises(checks.Blocked):
        c.gh_get("/user")
    assert wire.sent == []
    monkeypatch.setenv("GRCPAL_GITHUB_ALLOW_PRIVATE", "1")
    assert c.gh_get("/user") == {"login": "bot"} and wire.sent[0]["path"] == "/api/v3/user"


def test_github_collector_client_pagination_and_post_through_guard(monkeypatch):
    page1 = (200, {"Link": '<https://api.github.com/orgs/acme/members?page=2>; rel="next"'}, b'[{"login": "a"}]')
    page2 = (200, {}, b'[{"login": "b"}]')
    wire = Wire(monkeypatch, [page1, page2, (201, {}, b'{"number": 7}'), (404, {}, b"nope")],
                {"api.github.com": "public"})
    c = clients.Clients(_GhSettings({}, env=False))
    assert [m["login"] for m in c.gh_list("/orgs/acme/members", {"role": "all"})] == ["a", "b"]
    assert wire.sent[0]["path"] == "/orgs/acme/members?role=all&per_page=100"
    assert wire.sent[1]["path"] == "/orgs/acme/members?page=2"
    assert c.gh_post("/repos/acme/grc/issues", {"title": "t"}) == {"number": 7}
    assert json.loads(wire.sent[2]["body"]) == {"title": "t"} and wire.sent[2]["method"] == "POST"
    assert c.gh_get("/repos/acme/gone", allow_404=True) is None


def test_github_collector_client_refuses_truncated_pages(monkeypatch):
    monkeypatch.setattr(clients, "MAX_RESPONSE_BYTES", 10)
    Wire(monkeypatch, [(200, {}, b'[{"login": "a-very-long-name"}]')], {"api.github.com": "public"})
    with pytest.raises(clients.ApiError, match="too large"):
        clients.Clients(_GhSettings({}, env=False)).gh_get("/orgs/acme")


# ================================================================ Microsoft Graph
def test_graph_connection_probe_goes_through_guard(monkeypatch):
    wire = Wire(monkeypatch, [(200, {}, b"{}")], {"graph.microsoft.com": "public"})
    r = ms_integration._get("https://graph.microsoft.com/v1.0/users?$top=1", "tok")
    assert r.status_code == 200 and wire.sent[0]["headers"]["Authorization"] == "Bearer tok"
    with pytest.raises(checks.Blocked):
        ms_integration._get("http://169.254.169.254/metadata/identity", "tok")


# ================================================================ Configuration page: endpoint changes
@pytest.fixture()
def portal(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_KEY_FILE", str(tmp_path / "key"))
    monkeypatch.setenv("GRCPAL_JOBS_SYNC", "1")
    return make_portal(tmp_path)


def _ai(base, key="", provider="openai_compatible"):
    return {"GRCPAL_AI_PROVIDER": provider, "GRCPAL_AI_MODEL": "m", "GRCPAL_AI_BASE_URL": base, "GRCPAL_AI_API_KEY": key}


def test_changing_ai_endpoint_without_new_key_clears_old_key_and_it_is_not_sent(portal, monkeypatch):
    portal.save_settings(ADMIN, "ai", _ai("https://llm.example.com/v1", "sk-old"))
    assert portal.settings.secret("GRCPAL_AI_API_KEY") == "sk-old"
    portal.save_settings(ADMIN, "ai", _ai("https://llm.example.com/v1/"))          # same endpoint: key kept
    assert portal.settings.secret("GRCPAL_AI_API_KEY") == "sk-old"
    changed = portal.save_settings(ADMIN, "ai", _ai("https://collector.example.net/v1"))
    assert "GRCPAL_AI_API_KEY" in changed and portal.settings.secret("GRCPAL_AI_API_KEY") == ""
    wire = Wire(monkeypatch, [OK_CHAT], {"collector.example.net": "public"})
    providers.from_settings(portal.settings).complete("sys", [{"type": "text", "text": "hi"}])
    assert "sk-old" not in repr(wire.sent) and "Authorization" not in wire.sent[0]["headers"]
    entry = [r for r in portal.log.records() if r["action"] == "config.save"][-1]
    assert entry["detail"]["secrets_cleared"] == ["GRCPAL_AI_API_KEY"] and "sk-old" not in json.dumps(entry)


def test_changing_ai_endpoint_with_new_key_keeps_the_new_key(portal):
    portal.save_settings(ADMIN, "ai", _ai("https://llm.example.com/v1", "sk-old"))
    portal.save_settings(ADMIN, "ai", _ai("https://llm2.example.com/v1", "sk-new"))
    assert portal.settings.secret("GRCPAL_AI_API_KEY") == "sk-new"


def test_claude_endpoint_change_asks_for_the_key_again(portal):
    portal.save_settings(ADMIN, "ai", _ai("", "sk-ant-old", "anthropic"))
    with pytest.raises(Invalid, match="enter it again"):
        portal.save_settings(ADMIN, "ai", _ai("https://proxy.example.net", "", "anthropic"))
    assert portal.settings.secret("GRCPAL_AI_API_KEY") == "sk-ant-old"            # nothing saved on error


def test_changing_github_api_url_clears_token(portal):
    base = {"GRCPAL_GITHUB_ENABLED": "true", "GRCPAL_REPOS": "acme/app"}
    portal.save_settings(ADMIN, "github", {**base, "GRCPAL_GITHUB_TOKEN": "github_pat_old"})
    portal.save_settings(ADMIN, "github", {**base, "GRCPAL_GITHUB_API_URL": "https://api.github.com"})   # default
    assert portal.settings.secret("GRCPAL_GITHUB_TOKEN") == "github_pat_old"
    portal.save_settings(ADMIN, "github", {**base, "GRCPAL_GITHUB_API_URL": "https://ghe.example.net/api/v3"})
    assert portal.settings.secret("GRCPAL_GITHUB_TOKEN") == ""


def _smtp(host, password=""):
    return {"GRCPAL_MAIL_BACKEND": "smtp", "GRCPAL_MAIL_FROM": "grc@example.com", "GRCPAL_SMTP_HOST": host,
            "GRCPAL_SMTP_PORT": "587", "GRCPAL_SMTP_USER": "grc", "GRCPAL_SMTP_PASSWORD": password,
            "GRCPAL_SMTP_TLS": "starttls"}


def test_changing_smtp_host_blocks_a_deployment_password(portal, monkeypatch):
    """On Azure the SMTP password comes from a Container Apps secret (environment), which the portal cannot clear.
    A new SMTP host must not receive it until someone enters a password for that host."""
    monkeypatch.setenv("GRCPAL_SMTP_HOST", "smtp.example.com")      # deploy.sh/Bicep set host and password together
    monkeypatch.setenv("GRCPAL_SMTP_PASSWORD", "env-pw")
    portal.save_settings(ADMIN, "email", _smtp("smtp.example.com"))
    assert portal.settings.secret("GRCPAL_SMTP_PASSWORD") == "env-pw"
    portal.save_settings(ADMIN, "email", _smtp("smtp.example.net"))
    s = portal.settings
    assert s.secret("GRCPAL_SMTP_PASSWORD") == "" and not s.has_secret("GRCPAL_SMTP_PASSWORD")
    portal.save_settings(ADMIN, "email", {**_smtp("smtp.example.net"), "GRCPAL_SMTP_PASSWORD": "__clear__"})
    assert portal.settings.secret("GRCPAL_SMTP_PASSWORD") == ""                    # "remove" cannot re-open it
    portal.save_settings(ADMIN, "email", _smtp("smtp.example.com"))                # back to the original host
    assert portal.settings.secret("GRCPAL_SMTP_PASSWORD") == "env-pw"
    portal.save_settings(ADMIN, "email", _smtp("smtp.example.net", "typed-pw"))
    assert portal.settings.secret("GRCPAL_SMTP_PASSWORD") == "typed-pw"


def test_test_without_saving_does_not_send_saved_key_to_a_new_endpoint(portal, monkeypatch):
    portal.save_settings(ADMIN, "ai", _ai("https://llm.example.com/v1", "sk-old"))
    wire = Wire(monkeypatch, [OK_CHAT, OK_CHAT], {"collector.example.net": "public", "llm.example.com": "public"})
    portal.test_settings(ADMIN, "ai", _ai("https://collector.example.net/v1"))
    assert wire.sent and "sk-old" not in repr(wire.sent)
    portal.test_settings(ADMIN, "ai", _ai("https://llm.example.com/v1"))           # unchanged endpoint: key used
    assert wire.sent[-1]["headers"]["Authorization"] == "Bearer sk-old"


def test_configuration_change_is_emailed_to_every_admin(portal):
    portal.mailer.outbox.clear()
    portal.save_settings(ADMIN, "ai", _ai("https://llm.example.com/v1", "sk-old"))
    portal.save_settings(ADMIN, "ai", _ai("https://collector.example.net/v1"))
    mails = [m for m in portal.mailer.outbox if m.kind == "config_change"]
    assert {m.to for m in mails} == {ADMIN.email, ADMIN2.email}                     # the actor too
    latest = [m for m in mails if m.to == ADMIN2.email][0]
    lines = [ln.strip() for ln in latest.text.splitlines()]      # whole-line match: shows old -> new address
    assert "AI assistant" in latest.subject
    assert "- Endpoint URL: https://llm.example.com/v1 -> https://collector.example.net/v1" in lines
    assert "API key" in latest.text and "sk-old" not in latest.text + latest.html
    assert portal.save_settings(ADMIN, "ai", _ai("https://collector.example.net/v1")) == []
    assert len([m for m in portal.mailer.outbox if m.kind == "config_change"]) == len(mails)   # no change, no email

"""Custom evidence checks: HTTP requests, TLS certificates and (from the program repository only) commands.

HTTP and TLS checks can be created by admins in the portal. They run with these protections:
  * only http and https URLs; at most 3 redirects, each one re-checked;
  * the host name is resolved once and every address must be public: loopback, private, link-local
    (including cloud metadata such as 169.254.169.254), multicast and reserved ranges are refused, and
    the connection is pinned to the checked address so DNS rebinding cannot swap it;
  * time limit, response size limit, and secret header values stored encrypted and redacted in evidence.
GRCPAL_CHECKS_ALLOW_PRIVATE=1 lifts the address rule for self-hosted, internal-only deployments.

Command checks run a program and test its output. They can only be defined in catalog/checks.yaml in the
program repository (so every change is a reviewed pull request) and only the command line runs them
(`grcpal checks run`, the collect job, CI). The web portal never executes commands.
"""
from __future__ import annotations

import datetime as dt
import http.client
import ipaddress
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

MAX_BYTES = 2 * 1024 * 1024
METHODS = ("GET", "HEAD", "POST", "OPTIONS")
ASSERTION_KINDS = ("status", "contains", "not_contains", "regex", "json_path", "header", "max_ms")
CHECK_TYPES = ("http", "tls", "command")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,47}$")


class Blocked(Exception):
    pass


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes
    ms: int
    url: str
    address: str
    truncated: bool = False

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def _allow_private() -> bool:
    return os.getenv("GRCPAL_CHECKS_ALLOW_PRIVATE") == "1"


def resolve_public(host: str, port: int) -> str:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise Blocked(f"cannot resolve {host}") from exc
    addresses = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not _allow_private() and (not ip.is_global or ip.is_multicast):
            raise Blocked(f"{host} resolves to a non-public address ({ip}); requests to internal networks and "
                          "cloud metadata are blocked")
        addresses.append(str(ip))
    if not addresses:
        raise Blocked(f"cannot resolve {host}")
    return addresses[0]


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, port, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._address = address

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, address, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self):
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


def safe_request(method: str, url: str, headers: dict | None = None, body: str | bytes | None = None,
                 timeout: float = 15, max_bytes: int = MAX_BYTES, redirects: int = 3) -> Response:
    method = method.upper()
    if method not in METHODS:
        raise Blocked(f"method {method} is not allowed; use {', '.join(METHODS)}")
    started = time.perf_counter()
    for _ in range(redirects + 1):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise Blocked("only http:// and https:// URLs are allowed")
        if parts.username or parts.password:
            raise Blocked("put credentials in a header, not in the URL")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        address = resolve_public(parts.hostname, port)
        if parts.scheme == "https":
            conn = _PinnedHTTPS(parts.hostname, address, port, timeout, ssl.create_default_context())
        else:
            conn = _PinnedHTTP(parts.hostname, address, port, timeout)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        hdrs = {"User-Agent": "GRC-pal-check/1", "Accept": "*/*", **(headers or {})}
        data = body.encode() if isinstance(body, str) else body
        try:
            conn.request(method, path, body=data, headers=hdrs)
            resp = conn.getresponse()
            payload = resp.read(max_bytes + 1) if method != "HEAD" else b""
            rheaders = {k.lower(): v for k, v in resp.getheaders()}
        finally:
            conn.close()
        if resp.status in (301, 302, 303, 307, 308) and rheaders.get("location"):
            url = urljoin(url, rheaders["location"])
            if resp.status == 303:
                method, body = "GET", None
            continue
        return Response(resp.status, rheaders, payload[:max_bytes], int((time.perf_counter() - started) * 1000), url,
                        address, len(payload) > max_bytes)
    raise Blocked("too many redirects")


# ---------------------------------------------------------------- assertions
def json_path(data, path: str):
    """Dotted path with list indexes: items[0].enabled, meta.count. Raises KeyError when missing."""
    current = data
    for token in re.findall(r"[^.\[\]]+|\[\d+\]", path):
        if token.startswith("["):
            current = current[int(token[1:-1])]
        else:
            if not isinstance(current, dict) or token not in current:
                raise KeyError(path)
            current = current[token]
    return current


OPERATORS = ("exists", "equals", "not_equals", "contains", "matches", "lt", "gt", "le", "ge")
_ALIASES = {"gte": "ge", "lte": "le", "eq": "equals", "ne": "not_equals", "==": "equals", "!=": "not_equals",
            ">": "gt", "<": "lt", ">=": "ge", "<=": "le", "regex": "matches"}


def _compare(actual, op: str, expected: str) -> bool:
    op = _ALIASES.get(op, op)
    if op == "not_equals":
        return not _compare(actual, "equals", expected)
    if op == "matches":
        return re.search(str(expected), str(actual)) is not None
    if op == "exists":
        return True
    if op == "equals":
        return str(actual).lower() == str(expected).lower() if isinstance(actual, bool) else str(actual) == str(expected)
    if op == "contains":
        return str(expected) in (json.dumps(actual) if isinstance(actual, (list, dict)) else str(actual))
    if op in ("lt", "gt", "le", "ge"):
        a, b = float(actual), float(expected)
        return {"lt": a < b, "gt": a > b, "le": a <= b, "ge": a >= b}[op]
    raise ValueError(f"unknown operator {op}")


def status_ok(status: int, expect: str) -> bool:
    expect = (expect or "200-399").strip()
    for part in expect.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            if int(lo) <= status <= int(hi):
                return True
        elif part and int(part) == status:
            return True
    return False


def evaluate(assertions: list[dict], *, status: int | None = None, text: str = "", headers: dict | None = None,
             ms: int | None = None) -> list[str]:
    """Return the list of failed assertions as readable sentences (empty = pass)."""
    failures = []
    parsed = None
    for a in assertions or []:
        kind, path, op, value = a.get("kind"), a.get("path", ""), a.get("op", "equals"), a.get("value", "")
        try:
            if kind == "status" and status is not None and not status_ok(status, value):
                failures.append(f"status {status} is not {value}")
            elif kind == "contains" and value not in text:
                failures.append(f"response does not contain '{value}'")
            elif kind == "not_contains" and value in text:
                failures.append(f"response contains '{value}'")
            elif kind == "regex" and not re.search(value, text):
                failures.append(f"response does not match /{value}/")
            elif kind == "header":
                actual = (headers or {}).get(path.lower())
                if actual is None or not _compare(actual, op, value):
                    failures.append(f"header {path} is {actual!r}, expected {op} {value!r}")
            elif kind == "max_ms" and ms is not None and ms > int(value):
                failures.append(f"took {ms} ms, more than {value} ms")
            elif kind == "json_path":
                if parsed is None:
                    parsed = json.loads(text)
                try:
                    actual = json_path(parsed, path)
                except (KeyError, IndexError, TypeError):
                    failures.append(f"{path} is missing")
                    continue
                if not _compare(actual, op, value):
                    failures.append(f"{path} is {actual!r}, expected {op} {value!r}")
        except (ValueError, re.error) as exc:
            failures.append(f"assertion {kind} {path} could not be evaluated: {exc}")
    return failures


# ---------------------------------------------------------------- runners
@dataclass
class CheckResult:
    ok: bool
    failures: list = field(default_factory=list)
    summary: str = ""
    request: dict = field(default_factory=dict)
    response: dict = field(default_factory=dict)
    body: bytes = b""
    at: str = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat())


def _redact(headers: dict, secret_names: set) -> dict:
    return {k: ("[redacted]" if k in secret_names or k.lower() in ("authorization", "cookie", "x-api-key") else v)
            for k, v in headers.items()}


def run_http(cfg: dict, headers: dict, secret_names: set | None = None, requester=safe_request) -> CheckResult:
    secret_names = secret_names or set()
    req = {"method": cfg.get("method", "GET"), "url": cfg["url"], "headers": _redact(headers, secret_names),
           "body": (cfg.get("body") or "")[:2000]}
    try:
        r = requester(req["method"], cfg["url"], headers=headers, body=cfg.get("body") or None,
                      timeout=float(cfg.get("timeout") or 15))
    except Exception as exc:  # noqa: BLE001
        return CheckResult(False, [f"request failed: {type(exc).__name__}: {exc}"], "request failed", req)
    assertions = [{"kind": "status", "value": cfg.get("expect_status") or "200-399"}, *(cfg.get("assertions") or [])]
    failures = evaluate(assertions, status=r.status, text=r.text(), headers=r.headers, ms=r.ms)
    keep = {k: v for k, v in r.headers.items() if k in ("content-type", "date", "server", "strict-transport-security",
                                                        "content-security-policy", "x-frame-options", "location")}
    resp = {"status": r.status, "ms": r.ms, "final_url": r.url, "address": r.address, "headers": keep,
            "bytes": len(r.body), "truncated": r.truncated, "excerpt": r.text()[:1500]}
    summary = f"HTTP {r.status} in {r.ms} ms" + (f", {len(failures)} assertion(s) failed" if failures else ", all assertions passed")
    return CheckResult(not failures, failures, summary, req, resp, r.body if cfg.get("store_response") else b"")


def tls_info(host: str, port: int = 443, timeout: float = 10) -> dict:
    address = resolve_public(host, port)
    ctx = ssl.create_default_context()
    with socket.create_connection((address, port), timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            version = tls.version()
    expires = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    return {"host": host, "address": address, "tls_version": version, "expires": expires.isoformat(),
            "days_left": (expires - dt.datetime.now(dt.timezone.utc)).days,
            "issuer": issuer.get("organizationName") or issuer.get("commonName", "")}


def run_tls(cfg: dict, probe=tls_info) -> CheckResult:
    host, port = cfg["host"], int(cfg.get("port") or 443)
    req = {"host": host, "port": port}
    try:
        info = probe(host, port)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(False, [f"TLS connection failed: {type(exc).__name__}: {exc}"], "connection failed", req)
    failures = []
    min_days = int(cfg.get("min_days") or 21)
    if info["days_left"] < min_days:
        failures.append(f"certificate expires in {info['days_left']} days (minimum {min_days})")
    if info["tls_version"] not in ("TLSv1.2", "TLSv1.3"):
        failures.append(f"negotiated {info['tls_version']}; TLS 1.2 or later is required")
    return CheckResult(not failures, failures, f"{info['tls_version']}, certificate valid {info['days_left']} more days",
                       req, info)


def run_command(cfg: dict, allow_commands: bool = False) -> CheckResult:
    if not allow_commands:
        raise PermissionError("command checks run only from the command line (grcpal checks run), never in the portal")
    argv = shlex.split(cfg["run"])
    req = {"run": cfg["run"], "timeout": int(cfg.get("timeout") or 120)}
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TZ") or k.startswith("GRCPAL_CHECK_")}
    try:
        p = subprocess.run(argv, capture_output=True, timeout=req["timeout"], env=env, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CheckResult(False, [f"command failed to run: {exc}"], "did not run", req)
    out = p.stdout[:MAX_BYTES].decode("utf-8", "replace")
    failures = [] if p.returncode == int(cfg.get("expect_exit", 0)) else [f"exit code {p.returncode}"]
    failures += evaluate(cfg.get("assertions") or [], text=out)
    resp = {"exit_code": p.returncode, "stdout_excerpt": out[:1500], "stderr_excerpt": p.stderr[:800].decode("utf-8", "replace")}
    return CheckResult(not failures, failures, f"exit {p.returncode}" + (", passed" if not failures else ", failed"),
                       req, resp, p.stdout[:MAX_BYTES] if cfg.get("store_response") else b"")


def store_result(evidence, check: dict, result: CheckResult) -> str:
    """Write a check result to the write-once evidence store; returns the run prefix."""
    run = evidence.new_run(f"check-{check['id']}", [check["control"]], {"check": check["id"], "type": check["type"],
                                                                         "description": check.get("title", "")})
    run.add("request", result.request)
    run.add("result", {"ok": result.ok, "summary": result.summary, "failures": result.failures,
                       "response": result.response, "at": result.at})
    if result.body:
        ctype = (result.response.get("headers") or {}).get("content-type", "")
        ext = ".json" if "json" in ctype else ".csv" if "csv" in ctype else ".txt"
        run.add_bytes(f"response{ext}", result.body)
    findings = [{"key": f"{check['id']}:{i}", "severity": check.get("severity", "medium"), "title": f"{check['id']}: {f}",
                 "detail": {}} for i, f in enumerate(result.failures)]
    run.finish(findings)
    return run.prefix

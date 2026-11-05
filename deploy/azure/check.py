"""Post-deploy check for a GRC-pal instance on Azure (run by deploy/azure/check.sh and at the end of deploy.sh).

Standard library only; talks to Azure through the `az` CLI and to the portal through `curl`, so it runs in
Azure Cloud Shell as is. It reads only configuration: no secrets are fetched or printed.

Each check prints PASS, WARN or FAIL with the fix. Exit code 1 when anything FAILs.
With --fix it repairs the one thing that is safe to repair automatically: a missing sign-in redirect address
(the step an interrupted deploy.sh skips).
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import subprocess
import sys
import time

LOGIN_HOST = "login.microsoftonline.com"


class Report:
    def __init__(self) -> None:
        self.failed = 0
        self.warned = 0

    def line(self, status: str, text: str, fix: str = "") -> None:
        if status == "FAIL":
            self.failed += 1
        elif status == "WARN":
            self.warned += 1
        print(f"  {status:<5} {text}")
        if fix:
            print(f"        fix: {fix}")


def az_json(*args: str):
    r = subprocess.run(["az", *args, "-o", "json"], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout or "null")
    except ValueError:
        return None


def az_run(*args: str) -> bool:
    return subprocess.run(["az", *args, "-o", "none"], capture_output=True, text=True).returncode == 0


def http(url: str, *headers: str) -> tuple[str, str]:
    """Status code and redirect target of one request, without following redirects."""
    cmd = ["curl", "-s", "-o", "/dev/null", "--max-time", "60", "-w", "%{http_code} %{redirect_url}"]
    for h in headers:
        cmd += ["-H", h]
    r = subprocess.run(cmd + [url], capture_output=True, text=True)
    code, _, target = (r.stdout.strip() + " ").partition(" ")
    return code or "000", target.strip()


def response_headers(url: str) -> str:
    r = subprocess.run(["curl", "-sI", "--max-time", "60", url], capture_output=True, text=True)
    return r.stdout


def refused(code: str, target: str) -> bool:
    """The sign-in edge refused the request: a redirect to Microsoft sign-in or a plain 401/403."""
    return (code in ("301", "302", "303", "307") and LOGIN_HOST in target) or code in ("401", "403")


def check_app(rep: Report, rg: str, app: str) -> dict | None:
    print("Portal")
    ca = az_json("containerapp", "show", "-g", rg, "-n", app)
    if not ca:
        rep.line("FAIL", f"no container app {app} in {rg}", "run deploy.sh with the same --name (safe to repeat)")
        return None
    props = ca.get("properties", {})
    ingress = props.get("configuration", {}).get("ingress") or {}
    image = (props.get("template", {}).get("containers") or [{}])[0].get("image", "?")
    rep.line("PASS", f"image {image}")
    if not ingress.get("external") or not ingress.get("fqdn"):
        rep.line("FAIL", "the portal has no public address (ingress)", "run deploy.sh with the same --name")
        return None
    return ca


def check_revisions(rep: Report, rg: str, app: str) -> None:
    revs = az_json("containerapp", "revision", "list", "-g", rg, "-n", app) or []
    active = [r for r in revs if r.get("properties", {}).get("active")]
    serving = [r for r in active if (r["properties"].get("trafficWeight") or 0) > 0]
    if not serving:
        rep.line("FAIL", "no revision receives traffic",
                 f"az containerapp ingress traffic set -g {rg} -n {app} --revision-weight latest=100")
    for r in serving:
        p = r["properties"]
        health, state = p.get("healthState") or "None", p.get("runningState") or "?"
        if health == "Healthy":
            rep.line("PASS", f"{r['name']} serves {p.get('trafficWeight')}% of traffic and is healthy ({state})")
        else:
            rep.line("FAIL", f"{r['name']} serves {p.get('trafficWeight')}% of traffic but is {health} ({state})",
                     f"logs: az containerapp logs show -g {rg} -n {app} --revision {r['name']} --tail 50")
    for r in active:
        p = r["properties"]
        if r in serving or p.get("healthState") == "Healthy":
            continue
        rep.line("WARN", f"{r['name']} is still active but {p.get('healthState') or 'None'} and receives no traffic",
                 f"az containerapp revision deactivate -g {rg} -n {app} --revision {r['name']}")


def check_sign_in(rep: Report, rg: str, app: str, name: str, fqdn: str, fix: bool) -> None:
    print("Sign-in (Entra ID)")
    auth = az_json("containerapp", "auth", "show", "-g", rg, "-n", app) or {}
    cfg = auth.get("properties", auth)
    enabled = (cfg.get("platform") or {}).get("enabled")
    action = (cfg.get("globalValidation") or {}).get("unauthenticatedClientAction")
    client_id = (((cfg.get("identityProviders") or {}).get("azureActiveDirectory") or {}).get("registration")
                 or {}).get("clientId")
    if enabled and action == "RedirectToLoginPage":
        rep.line("PASS", "Microsoft sign-in is required for every page except /healthz")
    else:
        rep.line("FAIL", f"Microsoft sign-in is not enforced (enabled={enabled}, unauthenticated={action})",
                 "run deploy.sh with the same --name; never turn sign-in off by hand (break-glass: breakglass.sh)")

    apps = az_json("ad", "app", "list", "--display-name", f"GRC-pal ({name})") or []
    reg = next((a for a in apps if a.get("appId") == client_id), apps[0] if apps else None)
    if not reg:
        rep.line("FAIL", f"no app registration 'GRC-pal ({name})'", "run deploy.sh with the same --name")
        return
    if client_id and reg.get("appId") != client_id:
        rep.line("FAIL", f"the portal signs in with a different app registration than 'GRC-pal ({name})'",
                 "run deploy.sh with the same --name")
    redirect = f"https://{fqdn}/.auth/login/aad/callback"
    uris = (reg.get("web") or {}).get("redirectUris") or []
    if redirect in uris:
        rep.line("PASS", "sign-in redirect address is registered")
    elif fix and az_run("ad", "app", "update", "--id", reg["appId"], "--web-redirect-uris", redirect):
        rep.line("PASS", "sign-in redirect address was missing and is now registered (--fix)")
    else:
        rep.line("FAIL", "sign-in redirect address is missing (sign-in fails with AADSTS500113)",
                 f"re-run with --fix, or: az ad app update --id {reg['appId']} --web-redirect-uris {redirect}")

    ends = [c.get("endDateTime") for c in reg.get("passwordCredentials") or [] if c.get("endDateTime")]
    if not ends:
        rep.line("FAIL", "the sign-in client secret is missing", "run deploy.sh with the same --name")
    else:
        end = max(dt.datetime.fromisoformat(e.replace("Z", "+00:00")) for e in ends)
        days = (end - dt.datetime.now(dt.timezone.utc)).days
        if days < 0:
            rep.line("FAIL", f"the sign-in client secret expired on {end.date()}", "run deploy.sh to rotate it")
        elif days < 30:
            rep.line("WARN", f"the sign-in client secret expires in {days} days ({end.date()})",
                     "run deploy.sh to rotate it")
        else:
            rep.line("PASS", f"sign-in client secret valid until {end.date()}")

    sp = az_json("ad", "sp", "show", "--id", reg["appId"]) or {}
    if sp.get("appRoleAssignmentRequired"):
        rep.line("PASS", "only people assigned to the app can sign in")
    else:
        rep.line("WARN", "anyone in your directory can get a sign-in token (GRC-pal still refuses people it does "
                 "not know)", "assign yourself, then re-run deploy.sh with --require-assignment "
                 "(docs/deploy-azure.md, Step 3b)")


def check_edge(rep: Report, url: str, waits: int) -> None:
    print("Internet-facing checks")
    code = "000"
    for attempt in range(waits):  # the portal scales to zero: the first request may wait for it to start
        code, _ = http(f"{url}/healthz")
        if code == "200":
            break
        if attempt + 1 < waits:
            time.sleep(15)
    if code == "200":
        rep.line("PASS", "/healthz answers 200")
    else:
        rep.line("FAIL", f"/healthz answers {code} (the portal is not running or not reachable)",
                 "see the Portal section above, then the container logs")
        return
    forged = json.dumps({"claims": [{"typ": "preferred_username", "val": "admin@example.com"}]})
    principal = base64.b64encode(forged.encode()).decode()
    probes = [("V-1 forged identity header", "/", (f"X-MS-CLIENT-PRINCIPAL: {principal}", "Accept: text/html")),
              ("V-3 development sign-in", "/dev/login", ("Accept: text/html",)),
              ("V-3 password sign-in", "/login", ("Accept: text/html",))]
    for label, path, headers in probes:
        code, target = http(url + path, *headers)
        if refused(code, target):
            rep.line("PASS", f"{label}: refused ({code})")
        else:
            rep.line("FAIL", f"{label}: answered {code} {target}".rstrip(),
                     "stop and check the sign-in settings: an unauthenticated request got through")
    head = response_headers(f"{url}/healthz").lower()
    missing = [h for h in ("content-security-policy", "strict-transport-security") if h + ":" not in head]
    if missing:
        rep.line("WARN", f"security headers missing on /healthz: {', '.join(missing)}")
    else:
        rep.line("PASS", "security headers present (CSP, HSTS)")
    if any(line.startswith("server:") for line in head.splitlines()):
        rep.line("WARN", "the response names the web server (Server header)")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="check.sh", description="Check a GRC-pal instance on Azure after deploying.")
    ap.add_argument("--name", required=True, help="instance name used with deploy.sh")
    ap.add_argument("--fix", action="store_true", help="register a missing sign-in redirect address")
    ap.add_argument("--waits", type=int, default=6, help=argparse.SUPPRESS)  # tries for /healthz, 15 s apart
    a = ap.parse_args(argv)
    rg, app = f"rg-grcpal-{a.name}", f"grcpal-{a.name}"[:32]
    rep = Report()
    print(f"Checking GRC-pal instance '{a.name}' ({rg})")
    ca = check_app(rep, rg, app)
    if ca:
        check_revisions(rep, rg, app)
        fqdn = ca["properties"]["configuration"]["ingress"]["fqdn"]
        check_sign_in(rep, rg, app, a.name, fqdn, a.fix)
        check_edge(rep, f"https://{fqdn}", max(1, a.waits))
        print(f"\nPortal: https://{fqdn}")
    print(f"\n{rep.failed} failed, {rep.warned} warnings")
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""NET-01 (Google Cloud): firewall rules that open SSH, RDP or all ports to the internet.

Permissions: compute.firewalls.list (roles/compute.securityAdmin read or roles/iam.securityReviewer).
"""
PLATFORM = "gcp"
DESCRIPTION = "Google Cloud VPC firewall rules open to 0.0.0.0/0 on administrative ports"
COMPUTE = "https://compute.googleapis.com/compute/v1"
RISKY = {"22", "3389"}


def _ports(allowed: list) -> set:
    out = set()
    for a in allowed:
        if a.get("IPProtocol") in ("all",):
            out.add("all")
        for p in a.get("ports", []) or (["all"] if a.get("IPProtocol") in ("tcp", "udp") else []):
            out.add(p)
    return out


def _covers(ports: set, target: str) -> bool:
    for p in ports:
        if p == "all" or p == target:
            return True
        if "-" in p:
            lo, hi = p.split("-")
            if int(lo) <= int(target) <= int(hi):
                return True
    return False


def run(ctx, run):
    s = ctx.gcp()
    rows, findings = [], []
    for pid in ctx.setting_list("GRCPAL_GCP_PROJECTS"):
        r = s.get(f"{COMPUTE}/projects/{pid}/global/firewalls", timeout=30)
        r.raise_for_status()
        for fw in r.json().get("items", []):
            if fw.get("direction", "INGRESS") != "INGRESS" or fw.get("disabled"):
                continue
            open_world = "0.0.0.0/0" in fw.get("sourceRanges", [])
            ports = _ports(fw.get("allowed", []))
            rows.append({"project": pid, "rule": fw["name"], "network": fw.get("network", "").rsplit("/", 1)[-1],
                         "open_to_internet": open_world, "ports": ",".join(sorted(ports))})
            if open_world and (any(_covers(ports, t) for t in RISKY)):
                findings.append({"key": f"open-admin:{pid}:{fw['name']}", "severity": "high",
                                 "title": f"{pid}: firewall rule {fw['name']} opens SSH/RDP to the internet", "detail": {}})
    run.add("firewall_rules", rows)
    return findings

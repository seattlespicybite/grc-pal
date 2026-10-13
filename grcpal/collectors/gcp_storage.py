"""CRY-01, DAT-01 (Google Cloud): Cloud Storage public access prevention, uniform access and public IAM.

Permissions: storage.buckets.list, storage.buckets.getIamPolicy.
"""
PLATFORM = "gcp"
DESCRIPTION = "Google Cloud Storage: public access prevention, uniform bucket-level access, public buckets"
STORAGE = "https://storage.googleapis.com/storage/v1"


def run(ctx, run):
    s = ctx.gcp()
    rows, findings = [], []
    for pid in ctx.setting_list("GRCPAL_GCP_PROJECTS"):
        r = s.get(f"{STORAGE}/b?project={pid}", timeout=30)
        r.raise_for_status()
        for b in r.json().get("items", []):
            cfg = b.get("iamConfiguration", {})
            pol = s.get(f"{STORAGE}/b/{b['name']}/iam", timeout=30)
            members = {m for x in (pol.json().get("bindings", []) if pol.ok else []) for m in x.get("members", [])}
            public = bool(members & {"allUsers", "allAuthenticatedUsers"})
            row = {"project": pid, "bucket": b["name"], "public_access_prevention": cfg.get("publicAccessPrevention", "inherited"),
                   "uniform_access": cfg.get("uniformBucketLevelAccess", {}).get("enabled", False),
                   "public": public, "cmek": bool(b.get("encryption", {}).get("defaultKmsKeyName"))}
            rows.append(row)
            if public:
                findings.append({"key": f"public:{b['name']}", "severity": "high",
                                 "title": f"Cloud Storage bucket {b['name']} is public", "detail": {}})
            elif row["public_access_prevention"] != "enforced":
                findings.append({"key": f"pap:{b['name']}", "severity": "low",
                                 "title": f"Bucket {b['name']}: public access prevention not enforced", "detail": {}})
    run.add("buckets", rows)
    return findings

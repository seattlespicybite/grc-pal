"""Google Cloud: credentials and connection test. Needs the optional extra: pip install "grc-pal[gcp]"."""
from __future__ import annotations

import json

SCOPES = ["https://www.googleapis.com/auth/cloud-platform.read-only"]
CRM = "https://cloudresourcemanager.googleapis.com/v1"


def credentials(settings):
    try:
        import google.auth
        from google.oauth2 import service_account
    except ImportError as exc:
        raise RuntimeError('Google Cloud support is not installed. Run: pip install "grc-pal[gcp]" (the container '
                           "image includes it).") from exc
    auth = settings.get("GRCPAL_GCP_AUTH")
    raw = settings.secret("GRCPAL_GCP_CREDENTIALS_JSON")
    if auth in ("service_account_key", "workload_identity") and raw:
        info = json.loads(raw)
        if info.get("type") == "service_account":
            return service_account.Credentials.from_service_account_info(info, scopes=SCOPES)
        creds, _ = google.auth.load_credentials_from_dict(info, scopes=SCOPES)
        return creds
    creds, _ = google.auth.default(scopes=SCOPES)
    return creds


def session(settings):
    from google.auth.transport.requests import AuthorizedSession

    return AuthorizedSession(credentials(settings))


def validate(settings, ctx, result) -> None:
    if not settings.flag("GRCPAL_GCP_ENABLED"):
        result.add("Google Cloud collection is turned off", True)
        return
    raw = settings.secret("GRCPAL_GCP_CREDENTIALS_JSON")
    if raw:
        if not result.run("Credential JSON is valid", lambda: json.loads(raw).get("type", "?")):
            return
    sess = result.run("Load credentials", lambda: session(settings),
                      "Paste the full JSON, or use application default credentials.")
    if sess is None:
        return
    projects = settings.list("GRCPAL_GCP_PROJECTS")
    if not projects:
        result.add("Projects in scope", False, "none listed", "Add at least one project ID.")
    for pid in projects:
        r = sess.get(f"{CRM}/projects/{pid}", timeout=20)
        if not result.add(f"Read project {pid}", r.status_code == 200, f"HTTP {r.status_code}",
                          "Grant roles/iam.securityReviewer and roles/browser on the project or organization."):
            continue
        r = sess.post(f"{CRM}/projects/{pid}:getIamPolicy", json={}, timeout=20)
        result.add(f"Read IAM policy of {pid}", r.status_code == 200, f"HTTP {r.status_code}",
                   "Grant roles/iam.securityReviewer.")
        r = sess.get(f"https://storage.googleapis.com/storage/v1/b?project={pid}&maxResults=1", timeout=20)
        result.add(f"List buckets in {pid}", r.status_code == 200, f"HTTP {r.status_code}",
                   "Grant roles/storage.legacyBucketReader or Viewer, or enable the Cloud Storage API.")

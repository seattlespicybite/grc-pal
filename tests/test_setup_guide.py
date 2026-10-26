"""Setup guide: the program-setup steps added after 0.1.0 (audit period, owners, backups, updates, alerts,
access reviews, vendors, calendar and library), their readiness checks, and the Microsoft certificate option."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from test_portal import ADMIN, ADMIN2, CONTRIB, HR, as_, csrf, make_portal

from grcpal import cli
from grcpal.integrations import microsoft
from grcpal.portal.app import create_app
from grcpal.portal.routes_extra import STEP_IDS

NEW_STEPS = ("cycle", "owners", "backups", "updates", "alerts", "access_reviews", "vendors", "calendar_library")


@pytest.fixture()
def site(tmp_path, monkeypatch):
    monkeypatch.setenv("GRCPAL_AUTH_MODE", "dev")
    monkeypatch.setenv("GRCPAL_ENV", "dev")
    monkeypatch.setenv("GRCPAL_JOBS_SYNC", "1")
    monkeypatch.setenv("GRCPAL_KEY_FILE", str(tmp_path / "key"))
    for var in ("GRCPAL_TENANT", "GRCPAL_TABLES_URL", "GRCPAL_PUBLIC_URL", "GRCPAL_SQLITE", "GRCPAL_BACKUP_DIR",
                "GRCPAL_BACKUP_DIR_2", "GRCPAL_BACKUP_KEY", "GRCPAL_UPDATE_REQUESTS", "GRCPAL_UPDATE_STATE",
                "GRCPAL_EVIDENCE_ACCOUNT_URL", "GRCPAL_ENCRYPTION_KEY"):
        monkeypatch.delenv(var, raising=False)
    portal = make_portal(tmp_path)
    return portal, TestClient(create_app(portal), base_url="https://grc.example.com"), tmp_path


def item(ready: dict, name_part: str) -> dict:
    return next(i for i in ready["checks"] if name_part.lower() in i["name"].lower())


# ---------------------------------------------------------------- the guide lists every step
def test_new_steps_are_in_the_guide_in_order():
    pos = [STEP_IDS.index(s) for s in NEW_STEPS]
    assert pos == sorted(pos)
    assert STEP_IDS.index("access") < pos[0] and pos[-1] < STEP_IDS.index("collect")


@pytest.mark.parametrize("step", NEW_STEPS)
def test_each_new_step_renders_with_strict_csp_for_admins_only(site, step):
    portal, client, _ = site
    page = as_(client, ADMIN).get(f"/setup/{step}")
    assert page.status_code == 200, page.text[:400]
    assert 'style="' not in page.text and "<script>" not in page.text and "onclick" not in page.text
    assert as_(client, CONTRIB).get(f"/setup/{step}").status_code == 403


def test_summary_lists_program_setup(site):
    _, client, _ = site
    page = as_(client, ADMIN).get("/setup/finish")
    assert "Program setup" in page.text and "Audit period" in page.text and "Backups" in page.text


def test_readiness_is_admin_only(site):
    portal, _, _ = site
    from grcpal.portal.service import Forbidden
    with pytest.raises(Forbidden):
        portal.setup_readiness(CONTRIB, "backups")


# ---------------------------------------------------------------- audit period
def test_cycle_ready_only_after_an_admin_sets_the_period(site):
    portal, _, _ = site
    assert portal.setup_readiness(ADMIN, "cycle")["ready"] is False
    portal.edit_cycle(ADMIN, "2027 Type 2 window", "2026-11-01", "2027-10-31")
    ready = portal.setup_readiness(ADMIN, "cycle")
    assert ready["ready"] is True and "2026-11-01" in item(ready, "audit period")["detail"]


# ---------------------------------------------------------------- owners
def test_owners_counts_controls_without_an_owner_and_needs_a_library_owner(site):
    portal, _, _ = site
    ready = portal.setup_readiness(ADMIN, "owners")
    owners = item(ready, "owner")
    assert owners["ok"] is False and "without" in owners["detail"]
    assert item(ready, "library owner")["ok"] is True       # the first admin holds it by default
    assert ready["ready"] is False


# ---------------------------------------------------------------- backups
def test_backups_not_ready_without_a_backup_and_kit(site):
    portal, _, _ = site
    ready = portal.setup_readiness(ADMIN, "backups")
    assert ready["ready"] is False and item(ready, "recent backup")["ok"] is False


def test_backups_location_problem_is_shown(site, monkeypatch):
    portal, _, _ = site
    monkeypatch.setattr(type(portal), "backups_blocker", lambda self: "No backup location is configured.")
    ready = portal.setup_readiness(ADMIN, "backups")
    assert item(ready, "location")["ok"] is False and "GRCPAL_BACKUP_DIR" in item(ready, "location")["hint"]


def test_backups_ready_after_location_backup_and_recovery_kit(site, monkeypatch):
    portal, _, tmp = site
    monkeypatch.setenv("GRCPAL_BACKUP_DIR", str(tmp / "backups"))
    monkeypatch.setenv("GRCPAL_BACKUP_KEY_FILE", str(tmp / "keys" / "backup.key"))
    ready = portal.setup_readiness(ADMIN, "backups")
    assert item(ready, "location")["ok"] and not item(ready, "recent backup")["ok"]
    assert not item(ready, "recovery kit")["ok"]
    assert portal.backup_now(ADMIN, "local")["status"] == "done"
    portal.audit(ADMIN, "backup.kit_export", "backups", {})      # what the CLI or the Backups page records
    ready = portal.setup_readiness(ADMIN, "backups")
    assert item(ready, "recent backup")["ok"] and item(ready, "recovery kit")["ok"] and ready["ready"]


# ---------------------------------------------------------------- updates
def test_updates_on_a_vm_need_a_chosen_policy(site, monkeypatch):
    portal, _, tmp = site
    (tmp / "requests").mkdir()
    (tmp / "state").mkdir()
    monkeypatch.setenv("GRCPAL_UPDATE_REQUESTS", str(tmp / "requests"))
    monkeypatch.setenv("GRCPAL_UPDATE_STATE", str(tmp / "state"))
    assert portal.setup_readiness(ADMIN, "updates")["ready"] is False
    (tmp / "state" / "policy.json").write_text(json.dumps({"auto_patch": True, "online": False}))
    ready = portal.setup_readiness(ADMIN, "updates")
    assert ready["ready"] is True and "automatic" in item(ready, "policy")["detail"].lower()


def test_updates_elsewhere_explain_where_they_come_from(site):
    portal, _, _ = site
    ready = portal.setup_readiness(ADMIN, "updates")
    assert ready["checks"] and "install" in ready["checks"][0]["hint"].lower()


# ---------------------------------------------------------------- alerts
def test_alerts_need_working_email_and_an_admin_receiving_them(site):
    portal, _, _ = site
    ready = portal.setup_readiness(ADMIN, "alerts")
    assert item(ready, "email")["ok"] is False
    assert item(ready, "failure alerts")["ok"] is True       # on by default for admins
    portal.set_notify_prefs(ADMIN, False, [])
    portal.set_notify_prefs(ADMIN2, False, [])
    assert item(portal.setup_readiness(ADMIN, "alerts"), "failure alerts")["ok"] is False


# ---------------------------------------------------------------- access reviews and vendors
def test_access_reviews_need_a_tested_application(site):
    portal, _, _ = site
    assert portal.setup_readiness(ADMIN, "access_reviews")["ready"] is False
    app = portal.add_access_app(ADMIN, "GRC-pal", "grcpal")
    ready = portal.setup_readiness(ADMIN, "access_reviews")
    assert item(ready, "applications")["ok"] and not item(ready, "tested")["ok"]
    portal.test_access_app(ADMIN, app["RowKey"])
    assert portal.setup_readiness(ADMIN, "access_reviews")["ready"] is True


def test_vendors_need_at_least_one_vendor(site):
    portal, _, _ = site
    assert portal.setup_readiness(ADMIN, "vendors")["ready"] is False
    portal.store.insert("vendors", {"PartitionKey": "v", "RowKey": "v1", "name": "Example Cloud"})
    assert portal.setup_readiness(ADMIN, "vendors")["ready"] is True


def test_calendar_and_library_are_recommendations_only(site):
    portal, _, _ = site
    ready = portal.setup_readiness(ADMIN, "calendar_library")
    assert ready["checks"] and all(i.get("optional") for i in ready["checks"])


# ---------------------------------------------------------------- wizard status follows readiness
def test_step_status_follows_readiness_and_skip(site):
    portal, client, _ = site
    as_(client, ADMIN)
    page = client.get("/setup/cycle")
    assert "To do" in page.text
    portal.edit_cycle(ADMIN, "FY2027", "2026-11-01", "2027-10-31")
    nav = client.get("/setup/cycle").text
    assert 'href="/setup/cycle"' in nav and "Done" in nav.split('href="/setup/cycle"')[1].split("</a>")[0]
    t = csrf(client, "/setup/vendors")
    r = client.post("/setup/vendors", data={"csrf": t, "action": "skip"}, follow_redirects=False)
    assert r.status_code == 303
    nav = client.get("/setup/vendors").text
    assert "Skipped" in nav.split('href="/setup/vendors"')[1].split("</a>")[0]
    # Continue on a step that is not ready moves on but does not mark it done
    r = client.post("/setup/owners", data={"csrf": t, "action": "next"}, follow_redirects=False)
    assert r.headers["location"] == "/setup/backups"
    nav = client.get("/setup/owners").text
    assert "To do" in nav.split('href="/setup/owners"')[1].split("</a>")[0]


# ---------------------------------------------------------------- Microsoft: certificate and permissions
def _cert_pem():
    return cli._make_ms_certificate("GRC-pal monitoring", days=30)


def test_ms_cert_command_writes_private_key_and_public_certificate(tmp_path, capsys):
    out = tmp_path / "grcpal-ms"
    assert cli.main(["ms-cert", "--out", str(out)]) == 0
    key_file, cer_file = out.with_suffix(".pem"), out.with_suffix(".cer")
    assert "PRIVATE KEY" in key_file.read_text() and "CERTIFICATE" in key_file.read_text()
    assert oct(key_file.stat().st_mode & 0o777) == "0o600"
    assert "PRIVATE KEY" not in cer_file.read_text()
    assert "Thumbprint" in capsys.readouterr().out


def test_certificate_pasted_on_one_line_is_rebuilt():
    pem = _cert_pem()
    flat = pem.replace("\n", " ")
    rebuilt = microsoft.normalize_pem(flat)
    assert rebuilt.count("-----BEGIN") == 2 and "\n" in rebuilt
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography import x509
    load_pem_private_key(rebuilt.encode(), password=None)
    x509.load_pem_x509_certificate(rebuilt.encode())


def test_certificate_credential_is_used(monkeypatch):
    pem = _cert_pem()
    seen = {}

    class FakeCert:
        def __init__(self, tenant, client, certificate_data=None, **kw):
            seen.update(tenant=tenant, client=client, data=certificate_data)

    from azure import identity
    monkeypatch.setattr(identity, "CertificateCredential", FakeCert)

    class S:
        values = {"GRCPAL_MS_AUTH": "certificate", "GRCPAL_MS_TENANT_ID": "tid", "GRCPAL_MS_CLIENT_ID": "cid"}

        def get(self, k):
            return self.values.get(k, "")

        def secret(self, k):
            return pem.replace("\n", " ") if k == "GRCPAL_MS_CERTIFICATE" else ""

    microsoft.credential(S())
    assert seen["tenant"] == "tid" and seen["client"] == "cid" and b"BEGIN CERTIFICATE" in seen["data"]


def test_certificate_auth_requires_the_certificate(site):
    portal, _, _ = site
    from grcpal.portal.service import Invalid
    with pytest.raises(Invalid):
        portal.save_settings(ADMIN, "microsoft", {"GRCPAL_MS_ENABLED": "true", "GRCPAL_MS_AUTH": "certificate",
                                                  "GRCPAL_MS_TENANT_ID": "00000000-0000-0000-0000-000000000000",
                                                  "GRCPAL_MS_CLIENT_ID": "11111111-1111-1111-1111-111111111111"})


def test_connection_test_checks_group_membership_permission():
    assert "GroupMember.Read.All" in [p for p, _ in microsoft.GRAPH_PROBES]


def test_hr_owner_sees_no_setup(site):
    _, client, _ = site
    assert as_(client, HR).get("/setup/backups").status_code == 403

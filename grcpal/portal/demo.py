"""Demo data so a new user can click through GRC-pal in under a minute.

Loaded by `grcpal serve --demo` (GRCPAL_DEMO=1) into an empty store only. It creates a closed
previous cycle with approved evidence, a carried-forward active cycle with work in progress,
comments, a returned upload, an override and policy acknowledgments. Never use in production.
"""
from __future__ import annotations

import datetime as dt
import struct
import zlib

from grcpal.portal.auth import User
from grcpal.portal.mailer import NullMailer

ADMIN = User("alex.admin@example.com", "Alex Admin", "admin")
ADMIN2 = User("sam.security@example.com", "Sam Security", "admin")
HR = User("harper.hr@example.com", "Harper HR", "contributor")
IT = User("ivan.it@example.com", "Ivan IT", "contributor")
ENG = User("erin.eng@example.com", "Erin Engineering", "contributor")
AUDITOR = User("casey@cpa-firm.example", "Casey (external auditor)", "auditor")
PEOPLE = (ADMIN, ADMIN2, HR, IT, ENG, AUDITOR)
OWNERS = {"security-lead": ADMIN2.email, "hr-lead": HR.email, "it-lead": IT.email, "engineering-lead": ENG.email,
          "executive-sponsor": ADMIN.email, "system-owners": [IT.email, ENG.email]}


def _png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + b"\x0f\x8b\x8d" * 8 for _ in range(8))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def _pdf(title: str) -> bytes:
    return f"%PDF-1.4\n% GRC-pal demo evidence: {title}\n%%EOF\n".encode()


def seed(portal) -> bool:
    if portal.users():
        return False
    for role, email in OWNERS.items():
        if role in portal.catalog.roles:
            portal.catalog.roles[role]["email"] = email
    for u in PEOPLE:
        portal._create_user(u.email, u.name, u.role, "demo", "demo-seed")
    portal.store.update("users", "u", ADMIN.email, {"library_owner": True})  # Alex can change control definitions

    real_mailer, portal.mailer = portal.mailer, NullMailer("demo@localhost", sync=True)
    today = portal.today
    active = portal.active_cycle()
    portal.store.update("cycles", "c", active["RowKey"], {"name": f"FY{today.year - 1}",
                                                          "start": (today - dt.timedelta(days=380)).isoformat(),
                                                          "end": (today - dt.timedelta(days=15)).isoformat()})
    portal._today = today - dt.timedelta(days=200)
    last = {}
    for cid, who, note in [("HR-01", HR, "Hire list for the period reconciled with background-check completion dates."),
                           ("HR-02", HR, "Training completion export from the LMS."),
                           ("IAM-03", IT, "Quarterly access review sign-off for production systems."),
                           ("BCP-03", ENG, "Backup restore test with measured RTO and RPO."),
                           ("CHG-01", ENG, "Pull request review settings and a sample of merged changes.")]:
        a = portal.create_assignment(ADMIN, "control", cid, who.email, [], (portal.today + dt.timedelta(days=20)).isoformat(), note)
        name = {"HR-02": "training-completion.csv", "IAM-03": "access-review-signoff.png"}.get(cid, f"{cid.lower()}-evidence.pdf")
        data = {"HR-02": b"name,course,completed\nHarper,Security awareness,2025-03-02\nIvan,Security awareness,2025-03-05\n",
                "IAM-03": _png()}.get(cid, _pdf(cid))
        u = portal.upload(who, name, data, note, assignment_id=a["RowKey"])
        portal.add_comment(who, "Uploaded. This covers the full period.", upload_id=u["RowKey"])
        portal.review(ADMIN2, u["RowKey"], "approve", "Complete population, matches the period.")
        last[cid] = a
    portal._today = today

    cycle = portal.start_cycle(ADMIN, f"FY{today.year}", (today - dt.timedelta(days=14)).isoformat(),
                               (today + dt.timedelta(days=350)).isoformat(), carry_forward=True)
    portal.mailer = real_mailer
    work = {a["controls"][0]: a for a in portal.assignments(cycle=cycle["RowKey"])}
    u = portal.upload(HR, "background-checks-q3.pdf", _pdf("HR-01 Q3"), "Q3 hires with check dates",
                      assignment_id=work["HR-01"]["RowKey"])
    portal.add_comment(ADMIN2, "Thanks. Does this include the two contractors who started in August?", upload_id=u["RowKey"])
    portal.add_comment(HR, "Yes, rows 14 and 15. Contractors go through the same vendor.", upload_id=u["RowKey"])
    r = portal.upload(ENG, "restore-test.txt", b"Restore test 2026-09-30: database restored in 42 minutes.\n",
                      "Restore test notes", assignment_id=work["BCP-03"]["RowKey"])
    portal.review(ADMIN, r["RowKey"], "return", "Please add the RPO measurement and who approved the test.")
    portal.upload(IT, "access-review-q3.png", _png(), "Screenshot of the Q3 access review completion",
                  assignment_id=work["IAM-03"]["RowKey"])
    portal.create_override(ADMIN, "END-02", "Mobile devices are not used to access company data; MDM policy blocks "
                           "enrollment of personal phones. Confirmed with IT on the scoping call.",
                           (today + dt.timedelta(days=180)).isoformat(), "Scoping notes, ticket IT-142")
    for pol in portal.catalog.policies:
        for who in (ADMIN, HR, ENG):
            portal.acknowledge(who, pol["id"])

    # Newer features: offline AI reviewer, a custom control for two frameworks, and a sample review.
    portal.save_settings(ADMIN, "organization", {"GRCPAL_ORG_NAME": "Example Co (demo)",
                                                 "GRCPAL_SUPPORT_CONTACT": "security@example.com"})
    portal.save_settings(ADMIN, "ai", {"GRCPAL_AI_PROVIDER": "demo", "GRCPAL_AI_REDACT_EMAILS": "true",
                                       "GRCPAL_AI_MAX_TOKENS": "4000", "GRCPAL_AI_DAILY_LIMIT": "200"})
    portal.save_custom_control(ADMIN, {
        "id": "CUS-01", "title": "Critical vendors' SOC 2 reports reviewed every year",
        "description": "Security reviews each critical vendor's latest SOC 2 report, notes exceptions and confirms our "
                       "complementary user entity controls (CUECs) are in place.",
        "frequency": "annual", "owner_emails": ADMIN2.email,
        "map_soc2": "CC9.2", "map_iso27001": "A.5.19 A.5.22",
        "links": "Vendor inventory | https://example.com/vendors\nCUEC checklist | https://example.com/cuecs",
        "evidence_wanted": "Review notes for each critical vendor's SOC 2 report\nList of CUECs with owner confirmation"})
    portal.upload(ADMIN2, "vendor-soc2-review-2026.csv",
                  b"vendor,report_period,exceptions,cuecs_confirmed\nMicrosoft,2025-10-01..2026-09-30,0,yes\n"
                  b"GitHub,2025-07-01..2026-06-30,1,yes\n", "Annual vendor SOC 2 review", control_id="CUS-01",
                  approval_note="Reviewed and approved by the security lead in the vendor review meeting")
    # Implementation notes: how each control is met here, kept for the next person and the auditor.
    for cid, text in [
        ("IAM-02", "Covered by Information Security Policy section 6 (Access control).\nMFA is enforced by the "
                   "Entra ID Conditional Access policy 'Require MFA - all users'; break-glass accounts are excluded "
                   "and reviewed quarterly under IAM-05."),
        ("BCP-03", "Satisfied by the annual disaster recovery test held every November. The engineering lead "
                   "restores the production database to a clean subscription and records recovery time against "
                   "the 4-hour RTO in the DR test report (Business Continuity Plan section 4)."),
        ("GOV-01", "Policies live in /policies. The executive sponsor approves the annual review through a pull "
                   "request in January; the merged PR is the approval evidence.")]:
        portal.save_control_note(ADMIN, cid, text)
    portal.events.warning("collector", "Collector entra_mfa skipped: Microsoft Entra ID is not connected in the demo",
                          actor="demo-seed", collector="entra_mfa")
    from grcpal import report

    data = report.build(portal.catalog, portal.evidence, portal.today, portal=portal.report_inputs())
    portal.ai_review(ADMIN, "HR-01", next((c for c in data["controls"] if c["id"] == "HR-01"), None))
    _vendors(portal)
    return True


def _vendors(portal) -> None:
    """Vendors in every state: imported, signed off with CUECs, waiting for sign-off, onboarding, offboarding."""
    real_mailer, portal.mailer = portal.mailer, NullMailer("demo@localhost", sync=True)
    today = portal.today
    portal.import_vendors(ADMIN)
    contacts = {"owner_name": "Ivan IT", "owner_title": "IT lead", "owner_email": IT.email, "owner_phone": "+1 555 0100",
                "backup_name": "Sam Security", "backup_title": "Security engineer", "backup_email": ADMIN2.email,
                "ext_name": "Jordan Pike", "ext_title": "Customer success manager", "ext_email": "jordan@backup.example.com",
                "support_text": "Email support@backup.example.com or call the 24/7 line in the contract.\n"
                                "P1 = a restore that fails. The account number is on the invoice.",
                "support_url": "https://support.backup.example.com",
                "docs_text": "Ask Jordan for the SOC 2 report; it is sent under NDA within 5 business days.",
                "docs_url": "https://trust.backup.example.com"}
    v = portal.create_vendor(ADMIN, {"name": "Contoso Backup", "service": "Offsite backup of production databases",
                                     "tier": "critical", "data_access": ["Customer data"], "subservice": "inclusive",
                                     "contract_terms": "yes", "dpa": "yes", "contract_note": "Renews 2027-06-30",
                                     "assurance": "soc2_type2", "period_start": (today - dt.timedelta(days=470)).isoformat(),
                                     "period_end": (today - dt.timedelta(days=105)).isoformat(), "opinion": "qualified",
                                     "start_date": (today - dt.timedelta(days=330)).isoformat(), **contacts})
    vid = v["RowKey"]
    portal.add_vendor_file(IT, vid, "contoso-backup-soc2-type2.pdf", _pdf("Contoso Backup SOC 2"), "report", "SOC 2 Type 2")
    for key in ("risk", "assurance", "contract"):
        portal.update_checklist(IT, vid, key, True, "Checked during onboarding")
    portal.save_cuec(ADMIN, vid, "new", {"text": "Customers verify backups by restoring sample data.",
                                         "controls": ["BCP-03"], "how": "Annual restore test (DR test report)",
                                         "status": "met"})
    portal.save_cuec(ADMIN, vid, "new", {"text": "Customers restrict who can delete backup sets.", "controls": [],
                                         "how": "", "status": "not_mapped"})
    portal.save_assurance(IT, vid, "independent", {})
    portal.decide_review(ADMIN2, vid, "approve", "Qualified opinion (restore testing) accepted: we run our own test.")
    portal.store.update("vendors", "v", vid, {"last_review": (today - dt.timedelta(days=345)).isoformat()})
    payroll = portal.create_vendor(ADMIN, {"name": "Northwind Payroll", "service": "Payroll and benefits", "tier": "high",
                                           "data_access": ["Employee data", "Financial data"], "contract_terms": "yes",
                                           "assurance": "soc2_type2", "period_end": (today - dt.timedelta(days=60)).isoformat(),
                                           "owner_name": "Harper HR", "owner_title": "HR lead", "owner_email": HR.email})
    portal.add_vendor_file(ADMIN, payroll["RowKey"], "northwind-soc2.pdf", _pdf("Northwind SOC 2"), "report", "")
    for key in ("risk", "assurance", "contract"):
        portal.update_checklist(ADMIN, payroll["RowKey"], key, True, "Checked")
    portal.save_assurance(ADMIN, payroll["RowKey"], "independent", {})
    portal.decide_review(ADMIN2, payroll["RowKey"], "approve", "")
    portal.store.update("vendors", "v", payroll["RowKey"], {"last_review": (today - dt.timedelta(days=380)).isoformat()})
    portal.start_annual_review(HR, payroll["RowKey"])
    portal.add_vendor_file(HR, payroll["RowKey"], "northwind-soc2-2026.pdf", _pdf("Northwind SOC 2 2026"), "report", "")
    portal.save_review_answers(HR, payroll["RowKey"], {"covers_service": "yes", "exceptions": "no", "concerns": "na",
                                                       "data_change": "no"}, submit=True)
    portal.create_vendor(ENG, {"name": "Tailspin Mail", "service": "Transactional email", "tier": "high",
                               "data_access": ["Customer data"], "notes": "Sends password-reset and receipt emails."})
    old = portal.create_vendor(ADMIN, {"name": "Litware Translation", "service": "Document translation", "tier": "moderate",
                                       "data_access": ["Customer data"], "owner_email": ENG.email, "owner_name": "Erin"})
    for key in ("risk", "assurance", "contract"):
        portal.update_checklist(ADMIN, old["RowKey"], key, True, "Checked")
    portal.add_vendor_file(ADMIN, old["RowKey"], "litware-questionnaire.xlsx",
                           portal.questionnaire_xlsx(portal.questionnaire_version(), old), "questionnaire", "")
    portal.save_assurance(ADMIN, old["RowKey"], "self", {})
    portal.decide_review(ADMIN2, old["RowKey"], "approve", "Contract terms checked by Legal.")
    portal.start_offboarding(ADMIN, old["RowKey"], "Moved translation in-house")
    portal.update_checklist(ADMIN, old["RowKey"], "access", True, "SSO app removed in Entra ID")
    # A two-person payroll contractor without SOC 2 or ISO: essentials questionnaire with proof, baseline controls,
    # one control not met, and the business owner's written risk acceptance until the next review.
    small = portal.create_vendor(ADMIN, {
        "name": "Tamarind Payroll Services", "service": "Payroll processing for two client entities", "tier": "critical",
        "data_access": ["Employee data", "Financial data"], "domains": "tamarind-payroll.example",
        "contract_terms": "yes", "dpa": "yes", "assurance": "questionnaire",
        "owner_name": "Harper HR", "owner_title": "HR lead", "owner_email": HR.email,
        "ext_name": "Ade Okafor", "ext_title": "Founder", "ext_email": "ade@tamarind-payroll.example",
        "docs_text": "No SOC 2 or ISO. Send our essentials questionnaire to Ade; he answers within a week."})
    sid = small["RowKey"]
    portal.add_vendor_file(HR, sid, "tamarind-essentials.xlsx", portal.send_questionnaire(HR, sid, "essentials")[1],
                           "questionnaire", "Returned essentials questionnaire")
    portal.add_vendor_file(HR, sid, "tamarind-mfa.png", _png(), "proof", "Google Workspace 2-step verification enforced")
    for key in ("risk", "assurance", "contract"):
        portal.update_checklist(HR, sid, key, True, "Checked")
    base = {k: {"status": "met", "note": ""} for k in ("mfa", "accounts", "devices", "least_data", "no_copies",
                                                        "breach_notice", "subcontractors", "deletion", "location",
                                                        "sanctions")}
    base.update(our_systems={"status": "compensated", "note": "They work only in our M365 tenant with accounts we own"},
                backups={"status": "na", "note": "No data kept on their side"},
                continuity={"status": "not_met", "note": "Two people; no backup provider named yet"})
    portal.save_assurance(HR, sid, "evidence", base)
    portal.add_vendor_file(ADMIN, sid, "acceptance-harper.eml",
                           b"From: harper.hr@example.com\nSubject: Tamarind risk\n\nI accept the continuity risk until "
                           b"the next review. We keep the payroll data in our tenant.\n", "acceptance", "")
    portal.record_acceptance(ADMIN, sid, {"owner_name": "Harper HR", "owner_title": "HR lead",
                                          "reason": "Key-person risk (two-person company). Payroll data stays in our "
                                                    "tenant, so we can switch provider.",
                                          "expires": (today + dt.timedelta(days=170)).isoformat()})
    portal.decide_review(ADMIN2, sid, "approve", "")
    portal.mailer = real_mailer

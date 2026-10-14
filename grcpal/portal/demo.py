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
                  b"GitHub,2025-07-01..2026-06-30,1,yes\n", "Annual vendor SOC 2 review", control_id="CUS-01")
    portal.events.warning("collector", "Collector entra_mfa skipped: Microsoft Entra ID is not connected in the demo",
                          actor="demo-seed", collector="entra_mfa")
    from grcpal import report

    data = report.build(portal.catalog, portal.evidence, portal.today, portal=portal.report_inputs())
    portal.ai_review(ADMIN, "HR-01", next((c for c in data["controls"] if c["id"] == "HR-01"), None))
    return True

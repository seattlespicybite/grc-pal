"""The authorization expectation table: for every route, which roles may call it.

tests/test_authz.py reads this table, lists app.routes in the dev and local sign-in modes, and checks both
directions: a route that is missing from the table fails the suite, and so does a table entry for a route that
does not exist. NEW ROUTES MUST BE ADDED HERE (see CONTRIBUTING.md).

How to read it
  * EXPECT[(method, path)] is the set of roles that may call the route. Every other role must be refused.
  * Roles: anonymous (no sign-in), admin, owner (a Control owner who owns control A, a vendor, an access-review
    assignment and is a document approver), contributor (a Control owner with nothing assigned), auditor,
    expired_auditor (access end date passed), disabled_admin (an admin whose account is switched off).
  * PARAMS maps each {placeholder} in a path to an attribute of the test world (tests/authz_world.py).
  * FORMS gives, for a POST, a valid form so the test can show that an allowed role really gets through.
  * XFAIL / DOWNLOAD_XFAIL list known gaps (strict: a gap that is fixed must be removed from the list).
"""
from __future__ import annotations

A = frozenset({"admin"})
AU = frozenset({"admin", "auditor"})                                  # staff who see everything
STAFF = frozenset({"admin", "owner", "contributor"})                  # may use the portal, cannot read all
EVERYONE = frozenset({"admin", "owner", "contributor", "auditor"})    # any signed-in, active person
LIB_OWNER = A                                                         # the control library owner is an admin

# Sign-in, sign-out and health: reachable without an identity by design.
PUBLIC = {
    ("GET", "/healthz"), ("GET", "/dev/login"), ("POST", "/dev/login"), ("GET", "/dev/logout"),
    ("GET", "/login"), ("POST", "/login"), ("POST", "/logout"),
    ("GET", "/account/forgot"), ("POST", "/account/forgot"),
    ("GET", "/account/password/{token}"),    # old link format: redirects to the form below, sets nothing
    # choosing a password from an emailed link: the link's token (then a short-lived cookie) is the identity
    ("POST", "/account/password/open"), ("GET", "/account/password"), ("POST", "/account/password"),
}

# {placeholder} -> world attribute, per route template. Control A is the owner's, control B belongs to someone else.
PARAMS: dict[str, dict[str, str]] = {
    "/controls/{control_id}": {"control_id": "ctl_a"},
    "/controls/{control_id}/upload": {"control_id": "ctl_a"},
    "/controls/{control_id}/note": {"control_id": "ctl_a"},
    "/controls/{control_id}/remind": {"control_id": "ctl_a"},
    "/criteria/{crit_id}": {"crit_id": "crit"},
    "/assignments/{assignment_id}": {"assignment_id": "assign_a"},
    "/assignments/{assignment_id}/edit": {"assignment_id": "assign_extra"},
    "/assignments/{assignment_id}/cancel": {"assignment_id": "assign_extra"},
    "/assignments/{assignment_id}/upload": {"assignment_id": "assign_a"},
    "/assignments/{assignment_id}/remind": {"assignment_id": "assign_extra"},
    "/uploads/{upload_id}/review": {"upload_id": "upload_pending"},
    "/uploads/{upload_id}/download": {"upload_id": "upload_a"},
    "/evidence/{source}/{run}": {"source": "ev_source", "run": "ev_run"},
    "/evidence/{source}/{run}/{filename}": {"source": "ev_source", "run": "ev_run", "filename": "ev_file"},
    "/overrides/{override_id}/revoke": {"override_id": "override_revoke"},
    "/users/{email}/link": {"email": "user_target"},
    "/users/{email}/until": {"email": "auditor_email"},
    "/users/{email}/role": {"email": "user_target"},
    "/users/{email}/library-owner": {"email": "admin2_email"},
    "/users/{email}/identity": {"email": "user_target"},
    "/users/{email}/active": {"email": "user_target"},
    "/users/{email}/mfa": {"email": "user_target"},
    "/cycles/{cycle_id}/export": {"cycle_id": "cycle_closed"},
    "/policies/{policy_id}": {"policy_id": "policy"},
    "/policies/{policy_id}/ack": {"policy_id": "policy"},
    "/policies/{policy_id}/remind": {"policy_id": "policy"},
    "/settings/{section_id}": {"section_id": "section"},
    "/setup/{step_id}": {"step_id": "step"},
    "/jobs/{job_id}": {"job_id": "job"},
    "/kb/{crit_id}": {"crit_id": "crit"},
    "/frameworks/{fid}": {"fid": "framework_off"},
    "/frameworks/{fid}/use": {"fid": "framework_off"},
    "/controls/{cid}/definition": {"cid": "ctl_a"},
    "/controls/{cid}/definition/reset": {"cid": "ctl_edited"},
    "/controls/{cid}/edit": {"cid": "custom"},
    "/controls/{cid}/retire": {"cid": "custom"},
    "/controls/{cid}/checks": {"cid": "ctl_a"},
    "/checks/{check_id}/run": {"check_id": "check"},
    "/checks/{check_id}/delete": {"check_id": "check"},
    "/controls/{cid}/ai-review": {"cid": "ctl_a"},
    "/controls/{cid}/ai/{rid}/disposition": {"cid": "ctl_a", "rid": "ai_review"},
    "/ai/audits/{audit_id}": {"audit_id": "ai_audit"},
    "/ai/audits/{audit_id}/report.html": {"audit_id": "ai_audit"},
    "/calendar/o/{key}": {"key": "occurrence"},
    "/calendar/o/{key}/add": {"key": "occ_new"},
    "/calendar/a/{aid}": {"aid": "activity"},
    "/calendar/a/{aid}/move": {"aid": "activity"},
    "/calendar/a/{aid}/status": {"aid": "activity"},
    "/calendar/auto/{source}": {"source": "auto_source"},
    "/library/{did}": {"did": "doc"},
    "/library/{did}/edit": {"did": "doc"},
    "/library/{did}/official": {"did": "doc"},
    "/library/{did}/template": {"did": "doc"},
    "/library/{did}/versions/{vid}/status": {"did": "doc", "vid": "ver_draft"},
    "/library/{did}/versions/{vid}/label": {"did": "doc", "vid": "ver_draft"},
    "/library/{did}/versions/{vid}/approval": {"did": "doc", "vid": "ver_review"},
    "/library/{did}/review/{vid}": {"did": "doc", "vid": "ver_review"},
    "/library/{did}/files/{vid}": {"did": "doc", "vid": "ver_draft"},
    "/vendors/import/{token}": {"token": "vendor_import"},
    "/vendors/import/{token}/apply": {"token": "vendor_import"},
    "/vendors/import/{token}/discard": {"token": "vendor_import"},
    "/vendors/{vid}": {"vid": "vendor_a"},
    "/vendors/{vid}/edit": {"vid": "vendor_a"},
    "/vendors/{vid}/contacts": {"vid": "vendor_a"},
    "/vendors/{vid}/review/start": {"vid": "vendor_c"},
    "/vendors/{vid}/files": {"vid": "vendor_a"},
    "/vendors/{vid}/files/{fid}": {"vid": "vendor_a", "fid": "vendor_file_a"},
    "/vendors/{vid}/review/answers": {"vid": "vendor_d"},
    "/vendors/{vid}/review/exception": {"vid": "vendor_a"},
    "/vendors/{vid}/review/checklist": {"vid": "vendor_a"},
    "/vendors/{vid}/review/decide": {"vid": "vendor_a"},
    "/vendors/{vid}/cuecs": {"vid": "vendor_a"},
    "/vendors/{vid}/review/assurance": {"vid": "vendor_a"},
    "/vendors/{vid}/review/acceptance": {"vid": "vendor_a"},
    "/vendors/{vid}/signin-check": {"vid": "vendor_a"},
    "/vendors/{vid}/offboard": {"vid": "vendor_c"},
    "/vendors/{vid}/questionnaire": {"vid": "vendor_a"},
    "/access-reviews/apps/{aid}": {"aid": "access_app"},
    "/access-reviews/apps/{aid}/identities": {"aid": "access_app"},
    "/access-reviews/apps/{aid}/test": {"aid": "access_app"},
    "/access-reviews/{cid}": {"cid": "campaign_a"},
    "/access-reviews/{cid}/decide": {"cid": "campaign_a"},
    "/access-reviews/{cid}/signoff": {"cid": "campaign_c"},
    "/access-reviews/{cid}/reopen": {"cid": "campaign_d"},
    "/access-reviews/{cid}/assign": {"cid": "campaign_a"},
    "/access-reviews/{cid}/confirm": {"cid": "campaign_e"},
    "/access-reviews/{cid}/close": {"cid": "campaign_f"},
    "/access-reviews/{cid}/export.csv": {"cid": "campaign_a"},
    "/matrix/import/{import_id}/apply": {"import_id": "matrix_import"},
    "/matrix/import/{import_id}/discard": {"import_id": "matrix_import"},
}


PDF = b"%PDF-1.4\n% authz test file\n%%EOF\n"
DUE = "2026-11-20"


def pdf(name="evidence.pdf"):
    return {"file": (name, PDF, "application/pdf")}


def _definition(w):
    d = w.portal.control_definition(w.ctl_a)
    return {"reason": "Clarifying the title for the authz suite.", "title": d["title"] + " (clearer)",
            "owner": d["owner"], "owner_emails": ", ".join(d["owner_emails"]), "description": d["description"],
            **{f"map_{fid}": " ".join(ids) for fid, ids in d["mappings"].items()}}


def _custom(w, cid):
    return {"id": cid, "title": "Another custom control", "description": "Made by the authz suite.",
            "frequency": "annual", "owner_emails": w.who["admin"].email, "map_soc2": "CC9.2",
            "evidence_wanted": "A test file"}


def _vendor_form(w):
    return {"name": "Brand New Vendor", "service": "Test service", "tier": "moderate", "data_access": "Customer data"}


def _decisions(w):
    return {f"d_{w.entry_a}": "keep", f"c_{w.entry_a}": "looks right"}


# A form is a dict (or a function of the world returning one). A "__files__" key holds uploads.
FORMS: dict[tuple[str, str], object] = {
    ("POST", "/controls/{control_id}/upload"): lambda w: {
        "comment": "Evidence for the authz suite", "approval_note": "Reviewed by the uploader; complete.",
        "__files__": pdf()},
    ("POST", "/controls/{control_id}/note"): {"text": "How this control is met, written by the authz suite."},
    ("POST", "/controls/{control_id}/remind"): {"note": "Please send the evidence."},
    ("POST", "/assignments"): lambda w: {
        "target_type": "control", "target_id": "IAM-04", "assignee": w.other_owner.email, "contributors": "",
        "due": DUE, "instructions": "Please upload the evidence", "return_to": "/work"},
    ("POST", "/assignments/{assignment_id}/edit"): lambda w: {
        "assignee": w.other_owner.email, "contributors": "", "due": DUE, "instructions": "Changed instructions"},
    ("POST", "/assignments/{assignment_id}/cancel"): {"reason": "No longer needed for this test"},
    ("POST", "/assignments/{assignment_id}/upload"): lambda w: {
        "comment": "Evidence for the authz suite", "approval_note": "Reviewed by the uploader; complete.",
        "__files__": pdf()},
    ("POST", "/assignments/{assignment_id}/remind"): {"note": "Please send the evidence."},
    ("POST", "/comments"): lambda w: {"body": "A comment from the authz suite", "assignment_id": w.assign_a,
                                      "upload_id": "", "control_id": "", "return_to": "/work"},
    ("POST", "/uploads/{upload_id}/review"): {"decision": "approve", "note": "Complete and matches the period.",
                                              "return_to": "/reviews"},
    ("POST", "/overrides"): {"control": "IAM-04", "justification": "This control does not apply to the test system.",
                             "expires": "2027-03-01", "evidence_ref": "ticket 1"},
    ("POST", "/overrides/{override_id}/revoke"): {"reason": "The exception is no longer needed."},
    ("POST", "/users"): {"email": "new.person@example.com", "name": "New Person", "role": "contributor",
                         "access_until": ""},
    ("POST", "/users/{email}/link"): {},
    ("POST", "/users/{email}/until"): {"access_until": "2027-01-31"},
    ("POST", "/users/{email}/role"): {"role": "auditor", "access_until": "2027-01-31"},
    ("POST", "/users/{email}/library-owner"): {},
    ("POST", "/users/{email}/identity"): {},
    ("POST", "/users/{email}/active"): {"active": "0"},
    ("POST", "/users/{email}/mfa"): {},
    ("POST", "/account/mfa/start"): {},
    ("POST", "/account/mfa/confirm"): {"code": "000000"},
    ("POST", "/account/mfa/off"): {"password": "not-the-password"},
    ("POST", "/cycles"): {"name": "FY2099", "start": "2026-10-13", "end": "2027-10-12", "carry_forward": "1"},
    ("POST", "/cycles/current"): lambda w: {"name": "Renamed cycle", "start": w.portal.active_cycle()["start"],
                                            "end": w.portal.active_cycle()["end"]},
    ("POST", "/policies/{policy_id}/ack"): {},
    ("POST", "/policies/{policy_id}/remind"): {},
    ("POST", "/settings/{section_id}"): {"GRCPAL_ORG_NAME": "Authz Test Org", "action": "save"},
    ("POST", "/collect"): {"return_to": "/settings"},
    ("POST", "/setup/{step_id}"): {"action": "skip"},
    ("POST", "/frameworks/{fid}/use"): {"on": "true"},
    ("POST", "/frameworks/new"): {"fid": "authz-fw", "name": "Authz framework", "version": "1", "description": "x",
                                  "requirements": "R-1 | First requirement | Group"},
    ("POST", "/controls/new"): lambda w: _custom(w, "CUS-NEW"),
    ("POST", "/controls/{cid}/definition"): _definition,
    ("POST", "/controls/{cid}/definition/reset"): {"reason": "Back to the starter wording for the test."},
    ("POST", "/controls/{cid}/edit"): lambda w: {**_custom(w, w.custom), "title": "Edited custom control"},
    ("POST", "/controls/{cid}/retire"): {"reason": "Retired for the authz suite."},
    ("POST", "/controls/{cid}/checks"): {"id": "chk-new", "type": "http", "url": "https://example.com/up",
                                         "schedule": "manual", "method": "GET", "expect_status": "200-399"},
    ("POST", "/checks/{check_id}/run"): {"return_to": "/controls"},
    ("POST", "/checks/{check_id}/delete"): {"return_to": "/controls"},
    ("POST", "/controls/{cid}/ai-review"): {},
    ("POST", "/controls/{cid}/ai/{rid}/disposition"): {"decision": "accepted", "note": "Agreed."},
    ("POST", "/ai/audits"): {"framework": "soc2", "limit": "2"},
    ("POST", "/calendar/o/{key}/add"): {"return_to": "/calendar"},
    ("POST", "/calendar/o/{key}"): {"status": "performed", "completed_on": "2026-10-10", "note": "Done by the suite",
                                    "move_to": "", "return_to": "/calendar"},
    ("POST", "/calendar/order"): lambda w: {"kind": "manual", "ids": ",".join(reversed(
        [a["id"] for a in w.portal.calendar_activities() if a["kind"] == "manual"][:3])), "return_to": "/calendar"},
    ("POST", "/calendar/a/{aid}/move"): {"direction": "down", "return_to": "/calendar"},
    ("POST", "/calendar/a/{aid}"): lambda w: {
        "title": "Renamed activity", "kind": "manual", "due_day": "15", "owner": "",
        "instructions": "Do the thing", "source": "", "months": ["3", "9"], "controls": [w.ctl_a]},
    ("POST", "/calendar/a/{aid}/status"): {"action": "retire", "reason": "Not needed any more."},
    ("POST", "/calendar/notifications"): {"alerts": "1", "digests": ["weekly"]},
    ("POST", "/backups/now"): {"destination": ""},
    ("POST", "/backups/schedule"): {"enabled": "on", "hour": "3"},
    ("POST", "/backups/verify"): {"destination": "", "name": "none.grcbak"},
    ("POST", "/backups/download"): {"destination": "", "name": "none.grcbak"},
    ("POST", "/backups/kit"): {},
    ("POST", "/backups/restore"): {"destination": "", "name": "none.grcbak", "confirm": "RESTORE"},
    ("POST", "/updates/approve"): {"version": "99.0.0"},
    ("POST", "/updates/policy"): {"auto_patch": "on", "online": ""},
    ("POST", "/updates/check"): {},
    ("POST", "/updates/verify"): {},
    ("POST", "/library/add"): {"folder": "other", "number": "N-9", "title": "Another test document", "kind": "policy"},
    ("POST", "/library/trash"): lambda w: {"ids": w.doc_to_trash, "reason": "No longer needed"},
    ("POST", "/library/trash/restore"): lambda w: {"doc": w.doc_trashed},
    ("POST", "/library/{did}/edit"): {"title": "A better title for the test", "summary": "Summary"},
    ("POST", "/library/{did}/official"): {"variant": "", "change": "minor", "comment": "Another draft",
                                          "label": "", "__files__": pdf("policy.pdf")},
    ("POST", "/library/{did}/template"): {"comment": "New template", "__files__": pdf("template.pdf")},
    ("POST", "/library/{did}/versions/{vid}/status"): {"status": "archived", "note": "Not needed"},
    ("POST", "/library/{did}/versions/{vid}/label"): {"label": "2.5"},
    ("POST", "/library/{did}/versions/{vid}/approval"): {"action": "withdraw", "note": "Changed my mind"},
    ("POST", "/library/{did}/review/{vid}"): {"decision": "approve", "read": "1", "note": ""},
    ("POST", "/vendors/import"): {},
    ("POST", "/vendors/import/upload"): lambda w: {"__files__": {"file": (
        "vendors.csv", b"name,service,tier\r\nUploaded Vendor,Some service,moderate\r\n", "text/csv")}},
    ("POST", "/vendors/import/{token}/apply"): lambda w: {
        "row": [str(r["row"]) for r in w.portal.vendor_import(w.who["admin"], w.vendor_import)[1]["rows"]],
        "spread": ""},
    ("POST", "/vendors/import/{token}/discard"): {},
    ("POST", "/vendors/new"): _vendor_form,
    ("POST", "/vendors/questionnaire/edit"): {"op": "discard", "q": "full"},
    ("POST", "/vendors/questionnaire/publish"): {"reason": "A new version", "q": "full"},
    ("POST", "/vendors/{vid}/edit"): {"name": "Renamed Vendor", "service": "Changed service", "tier": "high",
                                      "data_access": "Customer data", "reason": "The scope changed."},
    ("POST", "/vendors/{vid}/contacts"): {"ext_name": "New Contact", "ext_email": "contact@vendor.example"},
    ("POST", "/vendors/{vid}/review/start"): {},
    ("POST", "/vendors/{vid}/files"): {"kind": "report", "comment": "Their report", "__files__": pdf("report.pdf")},
    ("POST", "/vendors/{vid}/review/answers"): {"action": "save", "covers_service": "yes"},
    ("POST", "/vendors/{vid}/review/exception"): {"text": "A qualified opinion", "impact": "Low",
                                                  "response": "Accepted"},
    ("POST", "/vendors/{vid}/review/checklist"): {"key": "risk", "done": "1", "note": "Checked"},
    ("POST", "/vendors/{vid}/review/decide"): {"decision": "return", "note": "Please attach the report"},
    ("POST", "/vendors/{vid}/cuecs"): {"cuec": "new", "text": "Customers restrict who can delete backups.",
                                       "how": "", "status": "not_mapped"},
    ("POST", "/vendors/{vid}/review/assurance"): {"level": "independent"},
    ("POST", "/vendors/{vid}/review/acceptance"): {"owner_name": "Owner", "owner_title": "Lead",
                                                   "reason": "Accepted for the test.", "expires": "2027-03-01"},
    ("POST", "/vendors/{vid}/signin-check"): {},
    ("POST", "/vendors/{vid}/offboard"): {"reason": "Moved in-house"},
    ("POST", "/vendors/{vid}/questionnaire"): {"q": "full"},
    ("POST", "/access-reviews/new"): lambda w: {"name": "New review", "due": DUE, "__files__": {"accounts": (
        "accounts.csv", b"app,account_id,email,name,status,role,last_login,mfa,is_service_account,manager_email\r\n"
        b"GitHub,x1,x1@example.com,X One,active,member,2026-10-01,yes,no," + w.owner.email.encode() + b"\r\n",
        "text/csv")}},
    ("POST", "/access-reviews/apps/new"): {"name": "Another application", "kind": "csv", "owner_email": "",
                                           "preset": ""},
    ("POST", "/access-reviews/apps/{aid}"): {"name": "Renamed application", "active": "on"},
    ("POST", "/access-reviews/apps/{aid}/identities"): {"__files__": {"identities": (
        "ids.csv", b"account_id,email\r\nx1,x1@example.com\r\n", "text/csv")}},
    ("POST", "/access-reviews/apps/{aid}/test"): {},
    ("POST", "/access-reviews/{cid}/decide"): _decisions,
    ("POST", "/access-reviews/{cid}/signoff"): {},
    ("POST", "/access-reviews/{cid}/reopen"): lambda w: {"reviewer": w.owner.email},
    ("POST", "/access-reviews/{cid}/assign"): lambda w: {"entry": w.entry_a, "reviewer": w.other_owner.email},
    ("POST", "/access-reviews/{cid}/confirm"): lambda w: {"entry": w.entry_e, "note": "Removed in the app"},
    ("POST", "/access-reviews/{cid}/close"): {"note": ""},
    ("POST", "/matrix/import"): lambda w: {"__files__": {"file": ("matrix.xlsx", w.matrix_file, "application/octet-stream")}},
    ("POST", "/matrix/import/{import_id}/apply"): lambda w: {
        "plan": w.matrix_plan, "reason": "Applying the previewed change in the authz suite.", "accept_gaps": ""},
    ("POST", "/matrix/import/{import_id}/discard"): {},
}

# ---------------------------------------------------------------------------------------------- who may call what
# Each group is "the roles", then "the routes" (METHOD path). Read a route's line to learn its rule; the rule itself
# is enforced in service.py / features.py (hidden buttons are not authorization, CLAUDE.md rule 1).
OWNER_OF = frozenset({"admin", "owner"})                      # the object's own owner, or an admin
OWNER_OR_READER = frozenset({"admin", "owner", "auditor"})    # an admin, the object's owner, or an auditor (read only)
OWNER_ONLY = frozenset({"owner"})                             # a named person: reviewer, approver. Not even an admin.

_GROUPS: list[tuple[frozenset, str]] = [
    # --- admins only (the control library owner is an admin; the library-owner-only routes are tested separately)
    (A, """GET /backups | GET /calendar | GET /calendar.csv | GET /calendar/a/new | GET /calendar/a/{aid}
           GET /calendar/auto/{source} | GET /calendar/notifications | GET /calendar/o/{key}
           GET /controls/new | GET /controls/{cid}/definition | GET /controls/{cid}/edit | GET /dev/outbox
           GET /frameworks/new | GET /reviews | GET /settings | GET /settings/{section_id} | GET /setup
           GET /setup/{step_id} | GET /updates | GET /updates/progress | GET /users | GET /vendors/import
           GET /vendors/import/template.csv | GET /vendors/import/{token} | GET /vendors/{vid}/edit
           POST /access-reviews/apps/new | POST /access-reviews/apps/{aid} | POST /access-reviews/apps/{aid}/identities
           POST /access-reviews/apps/{aid}/test | POST /access-reviews/new | POST /access-reviews/{cid}/assign
           POST /access-reviews/{cid}/close | POST /access-reviews/{cid}/confirm | POST /access-reviews/{cid}/reopen
           POST /ai/audits | POST /assignments | POST /assignments/{assignment_id}/cancel
           POST /assignments/{assignment_id}/edit | POST /assignments/{assignment_id}/remind
           POST /backups/download | POST /backups/kit | POST /backups/now | POST /backups/restore
           POST /backups/schedule | POST /backups/verify | POST /calendar/a/{aid} | POST /calendar/a/{aid}/move
           POST /calendar/a/{aid}/status | POST /calendar/notifications | POST /calendar/o/{key}
           POST /calendar/o/{key}/add | POST /calendar/order | POST /checks/{check_id}/delete
           POST /checks/{check_id}/run | POST /collect | POST /controls/new | POST /controls/{cid}/ai-review
           POST /controls/{cid}/ai/{rid}/disposition | POST /controls/{cid}/checks | POST /controls/{cid}/definition
           POST /controls/{cid}/definition/reset | POST /controls/{cid}/edit | POST /controls/{cid}/retire
           POST /controls/{control_id}/remind | POST /cycles | POST /cycles/current | POST /frameworks/new
           POST /frameworks/{fid}/use | POST /library/add | POST /library/trash | POST /library/trash/restore
           POST /library/{did}/edit | POST /library/{did}/official | POST /library/{did}/template
           POST /library/{did}/versions/{vid}/approval | POST /library/{did}/versions/{vid}/label
           POST /library/{did}/versions/{vid}/status | POST /matrix/import | POST /matrix/import/{import_id}/apply
           POST /matrix/import/{import_id}/discard | POST /overrides | POST /overrides/{override_id}/revoke
           POST /policies/{policy_id}/remind | POST /settings/{section_id} | POST /setup/{step_id}
           POST /updates/approve | POST /updates/check | POST /updates/policy | POST /updates/verify
           POST /uploads/{upload_id}/review | POST /users | POST /users/{email}/active | POST /users/{email}/identity
           POST /users/{email}/library-owner | POST /users/{email}/link | POST /users/{email}/mfa
           POST /users/{email}/role
           POST /users/{email}/until | POST /vendors/import | POST /vendors/import/upload
           POST /vendors/import/{token}/apply | POST /vendors/import/{token}/discard
           POST /vendors/questionnaire/edit | POST /vendors/questionnaire/publish | POST /vendors/{vid}/cuecs
           POST /vendors/{vid}/edit | POST /vendors/{vid}/offboard | POST /vendors/{vid}/review/acceptance
           POST /vendors/{vid}/review/decide | POST /vendors/{vid}/review/exception
           POST /vendors/{vid}/review/start"""),
    # --- admins and auditors (auditors read everything, change nothing)
    (AU, """GET /access-reviews/apps | GET /access-reviews/apps/{aid} | GET /access-reviews/{cid}/export.csv | GET /ai
            GET /ai/audits/{audit_id} | GET /ai/audits/{audit_id}/report.html | GET /audit | GET /criteria
            GET /criteria/{crit_id} | GET /cycles | GET /cycles/{cycle_id}/export | GET /evidence
            GET /evidence-signing-key.pem | GET /evidence/{source}/{run} | GET /evidence/{source}/{run}/{filename}
            GET /frameworks | GET /frameworks/{fid} | GET /jobs | GET /jobs/{job_id} | GET /library/register.xlsx
            GET /library/trash | GET /library/{did}/files/{vid} | GET /logs | GET /logs.csv | GET /matrix
            GET /matrix/data.xlsx | GET /matrix/report | GET /matrix/report.docx | GET /overrides | GET /users.csv"""),
    # --- everyone who is signed in and active (what they see is filtered to what is theirs)
    (EVERYONE, """GET / | GET /access-reviews | GET /access-reviews/template.csv | GET /controls | GET /kb
                  GET /kb/{crit_id} | GET /library | GET /policies | GET /policies/{policy_id} | GET /vendors
                  GET /vendors/questionnaire | GET /vendors/questionnaire.xlsx | GET /view | GET /work"""),
    # --- one object: its owner or assignee, an admin, an auditor. Anyone else gets 404 (rule 7)
    (OWNER_OR_READER, """GET /access-reviews/{cid} | GET /assignments/{assignment_id} | GET /controls/{control_id}
                         GET /library/{did} | GET /library/{did}/review/{vid} | GET /uploads/{upload_id}/download
                         GET /vendors/{vid} | GET /vendors/{vid}/files/{fid}"""),
    # --- an admin or the owner of that object
    (OWNER_OF, """POST /assignments/{assignment_id}/upload | POST /comments | POST /controls/{control_id}/note
                  POST /controls/{control_id}/upload | POST /vendors/{vid}/contacts | POST /vendors/{vid}/files
                  POST /vendors/{vid}/questionnaire | POST /vendors/{vid}/review/answers
                  POST /vendors/{vid}/review/assurance | POST /vendors/{vid}/review/checklist
                  POST /vendors/{vid}/signin-check"""),
    # --- named people. An admin who is not named is refused
    (OWNER_ONLY, """POST /access-reviews/{cid}/decide | POST /access-reviews/{cid}/signoff
                    POST /library/{did}/review/{vid}"""),
    # --- each signed-in person's own account security (two-step sign-in). Auditors too: it changes only
    # their own sign-in, never the organization's data (see SELF_SERVICE)
    (EVERYONE, """GET /account/mfa | POST /account/mfa/start | POST /account/mfa/confirm | POST /account/mfa/off"""),
    # --- any active person who writes (not auditors)
    (STAFF, """GET /vendors/new | POST /policies/{policy_id}/ack | POST /vendors/new"""),
]
EXPECT: dict[tuple[str, str], frozenset] = {}
for _roles, _text in _GROUPS:
    for _item in _text.replace("\n", "|").split("|"):
        _item = " ".join(_item.split())
        if _item:
            _method, _path = _item.split(" ", 1)
            assert (_method, _path) not in EXPECT, f"{_method} {_path} is listed twice"
            EXPECT[(_method, _path)] = _roles

# POSTs whose success changes no row we can see (a missing set-up, an action already done, an answer that needs
# a file first). The test then checks that the allowed role gets a different answer than a refused role does.
NO_WRITE: set[tuple[str, str]] = {
    ("POST", "/backups/download"), ("POST", "/backups/kit"), ("POST", "/backups/now"), ("POST", "/backups/restore"),
    ("POST", "/backups/schedule"), ("POST", "/backups/verify"),          # this test store holds two organizations
    ("POST", "/updates/approve"), ("POST", "/updates/policy"),           # no updater in the test
    ("POST", "/policies/{policy_id}/ack"),                               # the demo people acknowledged already
    ("POST", "/vendors/{vid}/signin-check"),                             # needs Microsoft Entra ID
    ("POST", "/vendors/questionnaire/publish"),                          # nothing to publish without edits
    ("POST", "/vendors/{vid}/review/acceptance"),                        # needs the owner's signed note first
    ("POST", "/users/{email}/mfa"),                                      # the target has no two-step sign-in to remove
    ("POST", "/account/mfa/confirm"), ("POST", "/account/mfa/off"),      # a wrong code / password changes nothing
    ("POST", "/account/mfa/start"),                                      # the test people have no password or key
}

# POSTs that change only the caller's own sign-in (not organization data), so auditors may use them too
SELF_SERVICE = {("POST", "/account/mfa/start"), ("POST", "/account/mfa/confirm"), ("POST", "/account/mfa/off")}

# Known gaps, strict: the test must fail while the gap exists, and a fixed gap must be removed from here.
XFAIL: dict[tuple[str, str], str] = {}
DOWNLOAD_XFAIL: dict[tuple[str, str], str] = {}

# IDs that are the same in every organization (starter catalog, fixed names). Routes with only these IDs cannot say
# anything about two organizations; routes with at least one other ID are used in the two-organization test.
SHARED = frozenset({"ctl_a", "ctl_b", "ctl_edited", "crit", "section", "step", "framework", "framework_off", "policy",
                    "auto_source", "activity", "occurrence", "occ_new", "ev_source", "cycle_closed", "cycle_active"})
# POSTs without an ID in the path whose form carries another organization's IDs
CROSS_FORMS = {("POST", "/comments"), ("POST", "/library/trash"), ("POST", "/library/trash/restore")}

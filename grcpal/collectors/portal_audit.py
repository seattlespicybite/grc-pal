"""Portal records exported to write-once evidence (daily).

Covers the human side of controls managed in the portal: users and roles, cycles, requests,
uploads with review decisions, comments, overrides, policy acknowledgments and the audit log,
plus a verification of the audit log's hash chain. Exporting daily anchors the chain: records
already in locked storage cannot be rewritten later. Skips cleanly when the portal is not deployed.
"""
import os

PLATFORM = None
DESCRIPTION = "Export portal users, requests, uploads, comments, overrides, acknowledgments and the verified audit log"


def enabled() -> bool:
    return bool(os.getenv("GRCPAL_TABLES_URL"))


def run(ctx, run):
    store = getattr(ctx, "portal_store", None)
    if store is None and enabled():
        from grcpal.portal.store import from_env

        store = from_env()
    if store is None:
        run.add("status", {"portal": "not configured"})
        return []
    from grcpal.portal.auditlog import AuditLog

    log = AuditLog(store)
    verification = log.verify()
    run.add("audit_chain_verification", verification)
    run.add("audit_log", log.records())
    for table, pk in (("users", "u"), ("cycles", "c"), ("assignments", "a"), ("uploads", "u"), ("comments", "m"),
                      ("overrides", "o")):
        run.add(table, store.list(table, pk))
    run.add("policy_acknowledgments", [r for r in store.list("acks") if r.get("version")])
    findings = []
    if not verification["ok"]:
        findings.append({"key": "audit-chain", "severity": "high", "title": "Portal audit log failed integrity "
                         f"verification: {'; '.join(verification['problems'][:5])}", "detail": verification})
    today = ctx.today.isoformat()
    active = {c["RowKey"] for c in store.list("cycles", "c") if c.get("status") == "active"}
    findings += [{"key": f"overdue:{a['RowKey']}", "severity": "medium",
                  "title": f"Portal request overdue since {a['due']}: {a['label'].splitlines()[0]} ({a['assignee']})",
                  "detail": {}}
                 for a in store.list("assignments", "a")
                 if a.get("cycle") in active and a["status"] in ("open", "returned") and a["due"] < today]
    return findings

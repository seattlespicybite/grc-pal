"""CHG-01, CHG-05, CRY-03: effective branch rules on each repo's default branch.

Uses the "rules for a branch" endpoint, which returns rules from both rulesets and
classic protection where visible, and works with read access.
"""
PLATFORM = "source_control"
DESCRIPTION = "Export effective default-branch rules and flag missing PR or check requirements"


def run(ctx, run):
    rows, findings = [], []
    for repo in ctx.repos:
        default = ctx.clients.gh_get(f"/repos/{repo}")["default_branch"]
        rules = ctx.clients.gh_list(f"/repos/{repo}/rules/branches/{default}")
        types = {r.get("type") for r in rules}
        pr_rule = next((r for r in rules if r.get("type") == "pull_request"), {})
        checks_rule = next((r for r in rules if r.get("type") == "required_status_checks"), {})
        approvals = (pr_rule.get("parameters") or {}).get("required_approving_review_count", 0)
        checks = [c.get("context") for c in (checks_rule.get("parameters") or {}).get("required_status_checks", [])]
        row = {"repo": repo, "branch": default, "rule_types": ",".join(sorted(t for t in types if t)),
               "required_approvals": approvals, "required_checks": ",".join(checks),
               "blocks_force_push": "non_fast_forward" in types, "blocks_deletion": "deletion" in types}
        rows.append(row)
        if approvals < 1:
            findings.append({"key": f"no-pr-rule:{repo}", "severity": "high",
                             "title": f"{repo}:{default} does not require an approving review", "detail": {}})
        if not checks:
            findings.append({"key": f"no-checks:{repo}", "severity": "medium",
                             "title": f"{repo}:{default} has no required status checks", "detail": {}})
        if not row["blocks_force_push"]:
            findings.append({"key": f"force-push:{repo}", "severity": "medium",
                             "title": f"{repo}:{default} allows force pushes", "detail": {}})
    run.add("branch_rules", rows)
    return findings

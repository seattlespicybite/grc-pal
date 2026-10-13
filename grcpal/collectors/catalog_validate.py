"""GOV-09: catalog validation and criteria coverage."""
from grcpal.catalog import validate
from grcpal.collectors import NAMES

PLATFORM = None
DESCRIPTION = "Validate the control catalog and record criteria coverage"


def run(ctx, run):
    cat = ctx.catalog
    errors, warnings = validate(cat, set(NAMES))
    coverage = cat.coverage()
    in_scope = set(cat.in_scope_criteria)
    run.add("coverage", [
        {"criterion": crit, "title": cat.criteria[crit]["title"], "category": cat.criteria[crit]["category"],
         "in_scope": crit in in_scope, "controls": ",".join(ctls)}
        for crit, ctls in coverage.items()
    ])
    run.add("validation", {"errors": errors, "warnings": warnings,
                           "controls": len(cat.controls), "in_scope_criteria": len(in_scope)})
    return [{"key": f"catalog:{i}", "title": e, "severity": "high", "detail": {}} for i, e in enumerate(errors)]

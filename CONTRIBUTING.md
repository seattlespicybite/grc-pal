# Contributing to GRC-pal

Thank you for helping. GRC-pal is used to produce audit evidence, so correctness and security
matter more than speed.

## Set up

```bash
git clone https://github.com/seattlespicybite/grc-pal && cd grc-pal
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q
grcpal serve --demo          # http://localhost:8000
```

## Ground rules

- **Discuss first** for anything larger than a bug fix: open an issue describing the problem, the
  control or criterion involved, and what evidence the change would produce.
- **Every write goes through `grcpal/portal/service.py`**, checks the user's role there, and is
  recorded with `self.audit(...)`. Hiding a button is not authorization.
- **Never bypass `TenantStore`.** Application code must not use a backend store directly.
- **Strict CSP:** no inline `<script>`, `style=` or event handlers in templates. Put behavior in
  `static/app.js` (progressive enhancement only) and styles in `static/app.css`.
- **Tests with the change:** permissions (who can and cannot), tenant isolation where data is
  touched, and the audit record.
- **New routes:** add them to `tests/authz_matrix.py` (who may call the route, its `{ids}`, and for a POST a
  valid form). `tests/test_authz.py` fails until you do.
- **No real organization data** in code, tests, fixtures or screenshots. Use `example.com`.
- **New collectors:** add `grcpal/collectors/<name>.py` with `PLATFORM`, `DESCRIPTION` and
  `run(ctx, run)`, register it in `collectors/__init__.py`, and add a test with canned API data.
  Collectors must be read-only against the source system.
- Keep dependencies few. Every new dependency needs a reason in the pull request.

## Style

Python 3.11+, type hints where they help, `pyflakes` clean. Plain, short user-facing text.

## Licensing of contributions

GRC-pal is licensed under AGPL-3.0-or-later. By submitting a contribution you agree that it is
licensed under the same terms and that you have the right to submit it. The maintainer may ask
contributors to sign a contributor license agreement before larger contributions are merged, so
the project can also be offered under other license terms in the future.

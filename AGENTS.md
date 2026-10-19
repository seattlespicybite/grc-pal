# Instructions for AI coding agents

This file is read by Jules, Codex and other agents that look for `AGENTS.md`. Gemini CLI reads
`GEMINI.md`, which points here.

**[CLAUDE.md](CLAUDE.md) is the single source of truth.** Read it before any change and follow it exactly:
the file map, which tests to run, and the "Rules that must not be broken". Its name is historical; the
rules apply to every agent and every person. Do not copy its content into this file or into GEMINI.md;
copies drift apart.

Extra rules when several AI tools work on this repo:

1. One task per branch, one pull request per task. Never push to `main`; the owner merges.
2. Do not edit `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` or `.github/` unless the task asks for it.
3. Do not add or upgrade dependencies (`pyproject.toml`) unless the task asks for it; say why in the PR.
4. Never weaken or delete a test to make it pass. Fix the code, or say in the PR why the test is wrong.
5. Hiding a button is not authorization: every write is checked and audit-logged in `service.py` or
   `features.py`. UI-only work must not change those files.
6. Before opening the PR: `python -m pytest -q` green and `python -m pyflakes grcpal tests` clean.
   Put the result line in the PR description, plus what changed and anything left undone.

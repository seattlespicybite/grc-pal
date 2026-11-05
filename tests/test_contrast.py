"""Colour contrast of the design tokens (B-060 / D-01): WCAG 2.2 AA, 4.5:1 for normal text.

Reads the tokens that win in app.css (the last `:root` block for light mode, the last dark-mode block) and checks
text colours on the page, on cards and on their own status-chip tint (`.pill` = 10% of the colour over the card).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

CSS = (Path(__file__).resolve().parents[1] / "grcpal/portal/static/app.css").read_text()
AA = 4.5


def _tokens(dark: bool) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in re.finditer(r"(@media \(prefers-color-scheme: dark\) \{\s*)?:root \{([^}]*)\}", CSS):
        if bool(m.group(1)) == dark:
            out.update(dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})", m.group(2))))
    return out


def _rgb(h: str) -> list[float]:
    return [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]


def _lum(c: list[float]) -> float:
    c = [x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def _ratio(a: list[float], b: list[float]) -> float:
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _tint(colour: list[float], over: list[float], share: float = 0.10) -> list[float]:
    return [colour[i] * share + over[i] * (1 - share) for i in range(3)]


@pytest.mark.parametrize("dark", [False, True], ids=["light", "dark"])
def test_text_and_status_colours_meet_wcag_aa(dark):
    t = {k: _rgb(v) for k, v in _tokens(dark).items()}
    failures = []
    for fg in ("text", "muted", "accent"):
        for bg in ("bg", "surface", "surface-2"):
            if (r := _ratio(t[fg], t[bg])) < AA:
                failures.append(f"--{fg} on --{bg}: {r:.2f}")
    for fg in ("ok", "warn", "bad", "info", "idle", "accent"):
        for bg in ("bg", "surface"):
            if (r := _ratio(t[fg], _tint(t[fg], t[bg]))) < AA:
                failures.append(f"--{fg} chip on --{bg}: {r:.2f}")
    if (r := _ratio(t["accent-ink"], t["accent"])) < AA:
        failures.append(f"button text on --accent: {r:.2f}")
    assert not failures, failures


def test_links_inside_sentences_are_underlined():
    assert re.search(r"p a:not\(\.btn\)[^{]*\{\s*text-decoration: underline", CSS)

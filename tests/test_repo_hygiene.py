"""Leftovers from resolving merge conflicts in GitHub's web editor: marker lines or bare branch names."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARKER = re.compile(r"^(<<<<<<<|=======$|>>>>>>>|(main|feature/\S+|release/\S+|security/\S+|fix/\S+)$)")


def test_no_merge_leftovers_in_docs():
    for path in [ROOT / "CHANGELOG.md", ROOT / "README.md", ROOT / "CLAUDE.md", *sorted((ROOT / "docs").glob("*.md"))]:
        bad = [n for n, line in enumerate(path.read_text().splitlines(), 1) if MARKER.match(line)]
        assert not bad, f"{path.name}: merge leftovers on lines {bad}"

"""Guard against half-resolved merges: leftover conflict markers break JavaScript, Python and docs silently."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARKER = re.compile(r"^(<{7}( .*)?|={7}|>{7}( .*)?)$")
TEXT = {".py", ".js", ".css", ".html", ".yaml", ".yml", ".json", ".sh", ".bicep", ".toml", ".md", ".txt", ".ps1"}


def _tracked_files():
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        return [ROOT / f for f in out.splitlines()]
    except (OSError, subprocess.CalledProcessError):  # not a git checkout (for example an sdist)
        return [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]


def test_no_merge_conflict_markers():
    found = []
    for path in _tracked_files():
        if path.suffix not in TEXT or not path.is_file():
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if MARKER.match(line):
                found.append(f"{path.relative_to(ROOT)}:{n}: {line[:40]}")
    assert not found, "merge conflict markers left in:\n" + "\n".join(found)

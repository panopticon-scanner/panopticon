"""Language-keyed scanner selection and its bounded prune disclosure.

One walk observes two surfaces: ordinary source selects scanners, while source
under the historical #1138 prune only explains why a language-keyed scanner was
not selected. Dependency/cache trees and dot directories stay unobserved.
"""
import os


EXTENSIONS = {".py": "python", ".go": "go",
              ".js": "javascript", ".jsx": "javascript",
              ".ts": "typescript", ".tsx": "typescript"}
LANGUAGE_TOOLS = {"python": "bandit", "go": "gosec"}
SKIP_REASON = "present only under pruned directories"
SKIP_REASONS = frozenset({SKIP_REASON})
SKIP_FIELDS = frozenset({"language", "tool", "reason"})
SKIPS_MAX = len(LANGUAGE_TOOLS)

# Selection-neutral noise. Dot directories are also rejected generically below;
# spelling the three security-sensitive roots makes that invariant visible.
NOISE_DIRS = frozenset({
    ".git", ".panopticon", ".worktrees", ".venv", "venv", "node_modules",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    "tmp", "site-packages",
})
# #1138's selection prune. Discovery still reviews these names, so a language
# found only here is a single-axis gap and earns the disclosure this module emits.
SELECTION_PRUNE = frozenset({
    "vendor", "third_party", "third-party", "testdata", "fixtures",
    "examples", "example", "dist", "build", "target", "docs",
})


def valid_skip_row(row):
    """Whether *row* is one controlled language/tool/reason statement."""
    return (isinstance(row, dict) and set(row) == SKIP_FIELDS
            and isinstance(row.get("language"), str)
            and isinstance(row.get("tool"), str)
            and LANGUAGE_TOOLS.get(row["language"]) == row["tool"]
            and row.get("reason") in SKIP_REASONS)


def display_skip_rows(value):
    """Valid rows from a report, bounded again for standalone renderers."""
    if not isinstance(value, list):
        return []
    return [row for row in value[:SKIPS_MAX] if valid_skip_row(row)]


def detect(target):
    """Return ``(selected languages, pruned-only scanner rows)`` in one walk."""
    found: set[str] = set()
    pruned: set[str] = set()
    want = set(EXTENSIONS.values())
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [name for name in dirnames
                       if name not in NOISE_DIRS and not name.startswith(".")]
        relative = os.path.relpath(dirpath, target)
        parts = () if relative == "." else relative.split(os.sep)
        bucket = pruned if SELECTION_PRUNE.intersection(parts) else found
        for filename in filenames:
            language = EXTENSIONS.get(os.path.splitext(filename)[1].lower())
            if language:
                bucket.add(language)
                if found == want:
                    return sorted(found), []
    rows = [{"language": language, "tool": LANGUAGE_TOOLS[language],
             "reason": SKIP_REASON}
            for language in sorted(pruned - found) if language in LANGUAGE_TOOLS]
    assert len(rows) <= len(LANGUAGE_TOOLS) == SKIPS_MAX
    return sorted(found), rows

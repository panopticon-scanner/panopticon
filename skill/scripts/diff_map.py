"""Delta-review support (#449): turn a base ref + working tree into a per-file
changed-line-range map, and classify findings against it. Stdlib only; pure
functions plus thin git/gh subprocess wrappers.
"""
import re

_NEWFILE_RE = re.compile(r"^\+\+\+ (?:b/)?(.*?)\s*$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(text):
    """{path: [(start, end), ...]} of changed NEW-side line ranges.

    `+++ b/<path>` opens a file (kept as a key even with no ranges, so a
    lineless finding on a changed file can fail-open in classify()); a
    `+++ /dev/null` target (deleted file) is skipped. `@@ -a,b +c,d @@` gives
    new-side range (c, c+d-1); d==0 (pure deletion) adds nothing.
    """
    result = {}
    path = None
    for line in text.splitlines():
        m = _NEWFILE_RE.match(line)
        if m:
            path = None if m.group(1) == "/dev/null" else m.group(1)
            if path is not None:
                result.setdefault(path, [])
            continue
        if path is None:
            continue
        h = _HUNK_RE.match(line)
        if h:
            start = int(h.group(1))
            count = int(h.group(2)) if h.group(2) is not None else 1
            if count > 0:
                result[path].append((start, start + count - 1))
    return result

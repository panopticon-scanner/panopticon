"""Delta-review support (#449): turn a base ref + working tree into a per-file
changed-line-range map, and classify findings against it. Stdlib only; pure
functions plus thin git/gh subprocess wrappers.
"""
import re
import subprocess
import os

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


def _run_git(repo, args, timeout=60):
    return subprocess.run(["git", "-C", repo, *args],
                          capture_output=True, text=True, timeout=timeout)


def hunk_map(repo, base):
    """Changed new-side line ranges per file (merge-base vs working tree),
    including untracked non-ignored files as whole-file ranges. {} on failure."""
    try:
        mb = _run_git(repo, ["merge-base", "HEAD", base])
    except Exception:
        return {}
    if mb.returncode != 0 or not mb.stdout.strip():
        return {}
    base_sha = mb.stdout.strip()
    try:
        diff = _run_git(repo, ["diff", "--unified=0", "--no-color",
                               "--find-renames", base_sha])
    except Exception:
        return {}
    if diff.returncode != 0:
        return {}
    result = parse_unified_diff(diff.stdout)
    # `git diff` omits untracked files; add them as whole-file ranges.
    try:
        others = _run_git(repo, ["ls-files", "--others", "--exclude-standard"])
    except Exception:
        others = None
    if others is not None and others.returncode == 0:
        for rel in others.stdout.splitlines():
            rel = rel.strip()
            if not rel:
                continue
            full = os.path.join(repo, rel)
            try:
                with open(full, "rb") as fh:
                    n = sum(1 for _ in fh)
            except OSError:
                continue
            result[rel] = [(1, max(n, 1))]
    return result

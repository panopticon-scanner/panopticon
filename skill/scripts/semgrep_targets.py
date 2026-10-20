"""The files Semgrep skipped for size, listed on the host (#3193).

Semgrep skips every regular file over `--max-target-bytes` and says nothing in
its SARIF, so a payload parked in a 1.1 MB file loses every Semgrep finding in
silence. Measured with the pinned 1.179.0, the vendored rules and the adapter's
argv (`--x-ls-long`):

- the size check applies to every kind of file (no language filter: with this
  rule set every small file is selected, random binary included), AFTER the
  argv's `--exclude` patterns, and a file of exactly the limit is scanned;
- a symlink is never selected, to a file or a directory, inside or out;
- the target's `.semgrepignore`/`.gitignore` are off on the argv, so the
  argv's `--exclude` values are the whole exclusion policy.

So the walk below lists the regular files over the limit, reached without
following a symlink, minus those the argv's patterns exclude. Asking Semgrep
(`--x-ls-long`) instead costs a second container and ~20 s of rule loading,
needs an internal flag, and splits a file name holding a newline.

The matcher FAILS CLOSED (coordinator ruling): it drops a path only on a
pattern form `tests/test_semgrep_targets.py` pins against Semgrep's own answer.
Any other form keeps its candidates listed -- over-disclosure costs a
certification, under-disclosure hides a payload.

The listing is stamped on the capture (`STAMP_KEY`) the way #1335 stamps the
scanned-file count, so it travels with the artifact and a re-ingest reads the
same facts; `tools.legacy_sarif` turns it into partial file coverage.
"""
from __future__ import annotations

import json
import os
import re
from fnmatch import fnmatchcase

from scripts.tolerant_json import depth_checked

STAMP_KEY = "panopticon_size_skipped"
MAX_LISTED = 100
# A bound on the walk itself. A tree past it is stamped incomplete, which the
# ingest reads as partial: a listing cut short never reads as "nothing skipped".
MAX_ENTRIES = 1_000_000

# Glob syntax the differential did not measure. `*` is the only wildcard a
# measured form uses; `**` is measured only as a trailing `/**`.
_UNMEASURED = re.compile(r"[?\[\]!\\{}]")


def _form(pattern):
    """(parts, anchored, dir_only, inside_only) for a measured form, else None."""
    if not isinstance(pattern, str) or not pattern or _UNMEASURED.search(pattern):
        return None
    inside_only = pattern.endswith("/**")
    core = pattern[:-3] if inside_only else pattern
    dir_only = core.endswith("/")
    anchored = core.startswith("/") or inside_only
    parts = core.strip("/").split("/")
    if any(part in ("", ".", "..") or "**" in part for part in parts):
        return None
    return parts, anchored or len(parts) > 1, dir_only, inside_only


def pattern_drops(pattern, rel, is_dir):
    """Whether `--exclude=pattern` takes the path `rel` (a tuple of components
    from the scan root) out of Semgrep's scope: True or False, or None for a
    form outside the measured set, which the caller treats as "keep"."""
    form = _form(pattern)
    if form is None:
        return None
    parts, anchored, dir_only, inside_only = form
    if not anchored:
        # One component, matched at any depth, gitignore style.
        return any(fnmatchcase(name, parts[0])
                   and not (dir_only and i == len(rel) - 1 and not is_dir)
                   for i, name in enumerate(rel))
    k = len(parts)
    if len(rel) < k or not all(fnmatchcase(rel[i], parts[i]) for i in range(k)):
        return False
    if inside_only:
        return len(rel) > k
    return not (dir_only and len(rel) == k and not is_dir)


def excluded(rel, is_dir, patterns):
    return any(pattern_drops(pattern, rel, is_dir) is True for pattern in patterns)


def argv_excludes(cmd):
    return [arg.split("=", 1)[1] for arg in cmd if arg.startswith("--exclude=")]


def oversized(root, patterns, limit, max_entries=MAX_ENTRIES):
    """The listing: {"limit", "count", "files" (at most MAX_LISTED, sorted),
    "complete"}. `complete` is False when the walk hit `max_entries` or could
    not read a directory, so the count is a lower bound."""
    found, complete, seen = [], True, 0
    stack: list[tuple[str, tuple[str, ...]]] = [(root, ())]
    while stack:
        directory, rel = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            complete = False
            continue
        for entry in entries:
            seen += 1
            if seen > max_entries:
                complete, stack = False, []
                break
            path = rel + (entry.name,)
            try:
                if entry.is_dir(follow_symlinks=False):
                    if not excluded(path, True, patterns):
                        stack.append((entry.path, path))
                elif (entry.is_file(follow_symlinks=False)
                      and entry.stat(follow_symlinks=False).st_size > limit
                      and not excluded(path, False, patterns)):
                    found.append("/".join(path))
            except OSError:
                complete = False
    found.sort()
    return {"limit": limit, "count": len(found), "files": found[:MAX_LISTED],
            "complete": complete}


def stamp(payload, listing):
    """`payload` with `listing` at runs[0].properties[STAMP_KEY]. Output that is
    not a SARIF document with a run object is returned untouched: the ingest
    already reports it, and without the stamp it reads as partial anyway."""
    try:
        doc = json.loads(depth_checked(payload))
        run = doc["runs"][0]
        if not isinstance(run, dict):
            return payload
    except (ValueError, KeyError, IndexError, TypeError):
        return payload
    properties = run.get("properties")
    if not isinstance(properties, dict):
        properties = run["properties"] = {}
    properties[STAMP_KEY] = listing
    return json.dumps(doc).encode("utf-8")


# Semgrep's own default, for an argv that does not state the limit.
SEMGREP_DEFAULT_MAX_TARGET_BYTES = 1_000_000


def argv_limit(cmd):
    """The `--max-target-bytes=N` the launched argv states, else Semgrep's default."""
    for arg in cmd:
        value = arg[len("--max-target-bytes="):] if arg.startswith("--max-target-bytes=") else ""
        if value.isdigit():
            return int(value)
    return SEMGREP_DEFAULT_MAX_TARGET_BYTES


def stamper(tool, root, cmd):
    """The capture-time stamp for a Semgrep run over `root` with the launched
    `cmd` (its excludes and its limit), or None for any other tool. The walk
    runs when the capture lands."""
    if tool != "semgrep":
        return None
    patterns, limit = argv_excludes(cmd), argv_limit(cmd)
    return lambda payload: stamp(payload, oversized(root, patterns, limit))

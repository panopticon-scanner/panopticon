"""Semgrep target gaps and explicit Dockerfile-variant targets (#3193, #3579).

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

Semgrep 1.183.0's ``--scan-unknown-extensions`` applies only to files named
directly on the command line. Its directory walk does not apply Dockerfile
rules to names such as ``Dockerfile.prod``. The host therefore keeps the
ordinary full-rules ``/src`` scan and runs each Dockerfile-like variant as an
explicit ``/src/...`` target in a second, Dockerfile-rules-only pass. A capture
stamp records the variants covered by that exact second argv; ingestion can
never mistake an omitted explicit target for complete Dockerfile-rule coverage.
"""
from __future__ import annotations

import json
import os
import re
from fnmatch import fnmatchcase

from scripts.tolerant_json import depth_checked

STAMP_KEY = "panopticon_size_skipped"
DOCKERFILE_STAMP_KEY = "panopticon_dockerfile_coverage"
SCAN_UNKNOWN_EXTENSIONS = "--scan-unknown-extensions"
DOCKERFILE_RULES_CONFIG = "/opt/semgrep-rules/dockerfile"
SCANNED_FILES_KEY = "panopticon_scanned_files"
MAX_LISTED = 100
# A bound on the walk itself. A tree past it is stamped incomplete, which the
# ingest reads as partial: a listing cut short never reads as "nothing skipped".
MAX_ENTRIES = 1_000_000

# Keep the scanner argv safely below ordinary exec limits even in a hostile
# repository. Variants beyond either bound remain in the capture's uncovered
# count, so an argv ceiling costs certification rather than hiding input.
MAX_DOCKERFILE_TARGETS = 1_000
MAX_DOCKERFILE_ARG_BYTES = 64 * 1024

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
            # #3246: iterated LAZILY under the entry cap -- `list(...)` first read
            # a whole directory into memory however far past the cap it ran.
            with os.scandir(directory) as entries:
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
        except OSError:                      # the open, or a read mid-directory
            complete = False
    found.sort()
    return {"limit": limit, "count": len(found), "files": found[:MAX_LISTED],
            "complete": complete}


def _is_dockerfile_variant(name):
    """Whether ``name`` needs forced Dockerfile-language selection.

    ``Containerfile*`` includes the plain name. The pinned Semgrep does not
    discover it as Dockerfile input, and forcing it is harmless if a later pin
    learns the name because merged results are deduplicated.
    """
    return (name.startswith("Dockerfile.")
            or name.endswith(".Dockerfile")
            or name.endswith(".dockerfile")
            or name.startswith("Containerfile"))


def _dockerfile_variants(root, patterns, max_entries=MAX_ENTRIES):
    """Return ``([(relative path, size)], complete)`` without following links.

    The traversal and exclusion semantics mirror :func:`oversized`: a target
    excluded from Semgrep's ordinary tree is not silently re-admitted by the
    explicit-target repair, and an unreadable or bounded walk is disclosed.
    """
    found: list[tuple[str, int]] = []
    complete, seen = True, 0
    stack: list[tuple[str, tuple[str, ...]]] = [(root, ())]
    while stack:
        directory, rel = stack.pop()
        try:
            with os.scandir(directory) as entries:
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
                              and _is_dockerfile_variant(entry.name)
                              and not excluded(path, False, patterns)):
                            found.append(("/".join(path),
                                          entry.stat(follow_symlinks=False).st_size))
                    except OSError:
                        complete = False
        except OSError:
            complete = False
    found.sort()
    return found, complete


def _container_target(rel):
    return "/src/" + rel


def with_dockerfile_targets(tool, cmd, root):
    """Build a Dockerfile-only Semgrep command for the forced variants.

    The main command stays untouched and scans the ordinary tree with the full
    ruleset. This second command replaces its config with the vendored
    Dockerfile subtree and replaces the directory target with explicit variant
    paths. Using the full config here makes every configured language parser
    inspect each forced file (#3579's real-image round produced six spurious
    syntax errors). Every inserted name is rooted under ``/src/``, so a hostile
    filename cannot become an option.
    """
    if tool != "semgrep":
        return cmd
    variants, _complete = _dockerfile_variants(root, argv_excludes(cmd))
    limit = argv_limit(cmd)
    targets: list[str] = []
    used = 0
    for rel, size in variants:
        target = _container_target(rel)
        cost = len(os.fsencode(target)) + 1
        if (size > limit or len(targets) >= MAX_DOCKERFILE_TARGETS
                or used + cost > MAX_DOCKERFILE_ARG_BYTES):
            continue
        targets.append(target)
        used += cost
    if not targets:
        return cmd
    try:
        at = cmd.index("/src")
        config_at = cmd.index("--config") + 1
    except ValueError:
        return cmd
    dockerfile_cmd = list(cmd)
    dockerfile_cmd[config_at] = DOCKERFILE_RULES_CONFIG
    return (dockerfile_cmd[:at] + [SCAN_UNKNOWN_EXTENSIONS] + targets
            + dockerfile_cmd[at + 1:])


def dockerfile_coverage(root, cmd, max_entries=MAX_ENTRIES):
    """Coverage stamp for Dockerfile-like variants under the launched ``cmd``."""
    variants, complete = _dockerfile_variants(
        root, argv_excludes(cmd), max_entries=max_entries)
    direct = set(cmd) if SCAN_UNKNOWN_EXTENSIONS in cmd else set()
    limit = argv_limit(cmd)
    analyzed = [rel for rel, size in variants
                if size <= limit and _container_target(rel) in direct]
    analyzed_set = set(analyzed)
    uncovered = [rel for rel, _size in variants if rel not in analyzed_set]
    return {"count": len(variants), "analyzed": len(analyzed),
            "unanalyzed": len(uncovered), "files": uncovered[:MAX_LISTED],
            "complete": complete}


def stamp(payload, listing, dockerfile_listing=None):
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
    if dockerfile_listing is not None:
        properties[DOCKERFILE_STAMP_KEY] = dockerfile_listing
    return json.dumps(doc).encode("utf-8")


def _result_identity(result):
    """A stable finding identity across the tree and Dockerfile-only passes."""
    if not isinstance(result, dict):
        return None
    try:
        physical = result["locations"][0]["physicalLocation"]
        uri = physical["artifactLocation"]["uri"]
        region = physical.get("region") or {}
    except (KeyError, IndexError, TypeError, AttributeError):
        return None
    message = result.get("message")
    text = message.get("text") if isinstance(message, dict) else message
    path = str(uri).removeprefix("file://").removeprefix("/src/").lstrip("/")
    return (result.get("ruleId"), path, region.get("startLine"),
            region.get("startColumn"), region.get("endLine"),
            region.get("endColumn"), text)


def merge_sarif(primary, dockerfile):
    """Combine two Semgrep SARIF documents, deduplicating native-name hits.

    Both inputs retain their own run, rule and notification records. Only a
    result with the same rule, normalized path, region and message is removed;
    a genuinely different finding is never folded away. The scanned-file
    witness is summed when every run carries one, otherwise removed rather
    than publishing a lower bound as an exact count.
    """
    try:
        doc = json.loads(depth_checked(primary))
        extra = json.loads(depth_checked(dockerfile))
        runs = doc["runs"]
        extra_runs = extra["runs"]
        if not (isinstance(doc, dict) and isinstance(extra, dict)
                and isinstance(runs, list) and runs
                and isinstance(extra_runs, list) and extra_runs
                and all(isinstance(run, dict) for run in runs + extra_runs)):
            return None
    except (ValueError, KeyError, TypeError):
        return None

    seen = set()
    for run in runs:
        results = run.get("results")
        for result in results if isinstance(results, list) else ():
            identity = _result_identity(result)
            if identity is not None:
                seen.add(identity)
    for run in extra_runs:
        results = run.get("results")
        if isinstance(results, list):
            kept = []
            for result in results:
                identity = _result_identity(result)
                if identity is not None and identity in seen:
                    continue
                kept.append(result)
                if identity is not None:
                    seen.add(identity)
            run["results"] = kept
    runs.extend(extra_runs)

    counts: list[int] = []
    for run in runs:
        properties = run.get("properties")
        count = properties.get(SCANNED_FILES_KEY) if isinstance(properties, dict) else None
        if type(count) is not int or count < 0:
            counts = []
            break
        counts.append(count)
    first_properties = runs[0].setdefault("properties", {})
    if isinstance(first_properties, dict):
        if len(counts) == len(runs):
            first_properties[SCANNED_FILES_KEY] = sum(counts)
        else:
            first_properties.pop(SCANNED_FILES_KEY, None)
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
    return lambda payload: stamp(
        payload, oversized(root, patterns, limit), dockerfile_coverage(root, cmd))

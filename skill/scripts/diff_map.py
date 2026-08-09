"""Delta-review support (#449): turn a base ref + working tree into a per-file
changed-line-range map, and classify findings against it. Stdlib only; pure
functions plus thin git/gh subprocess wrappers.
"""
import re
import subprocess
import os
import json as _json
import tempfile

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


def diff_anchors(repo, base):
    """Resolve the three commit anchors the delta artifact records.

    {base_commit, delta_start, delta_end}: the base ref's tip, the
    merge-base(base, HEAD) fork point, and HEAD. Any field is None if git can't
    resolve it (in practice the orchestrator has already refused an unresolvable
    base, so all three are populated).
    """
    def _rev(ref):
        try:
            r = _run_git(repo, ["rev-parse", "--verify", "-q", ref])
        except Exception:
            return None
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
    delta_start = None
    if base:
        try:
            mb = _run_git(repo, ["merge-base", "HEAD", base])
            if mb.returncode == 0 and mb.stdout.strip():
                delta_start = mb.stdout.strip()
        except Exception:
            delta_start = None
    return {"base_commit": _rev(base + "^{commit}") if base else None,
            "delta_start": delta_start,
            "delta_end": _rev("HEAD")}


def _distance_to_range(ls, le, s, e):
    """Minimum distance from finding [ls, le] to range [s, e] (0 if overlapping)."""
    if ls <= e and le >= s:
        return 0
    return min(abs(ls - s), abs(ls - e), abs(le - s), abs(le - e))


def classify(finding, hmap, tolerance=5):
    """{on_diff, hunk, distance} for a finding vs the hunk map (see module docstring)."""
    loc = finding.get("location") or {}
    path = loc.get("file")
    if path not in hmap:
        return {"on_diff": False, "hunk": None, "distance": None}
    ranges = hmap[path]
    ls = loc.get("line_start")
    if ls is None:
        return {"on_diff": True, "hunk": None, "distance": None}   # fail-open
    le = loc.get("line_end") or ls
    best = None
    for (s, e) in ranges:
        if le >= s - tolerance and ls <= e + tolerance:            # within window or overlap
            dist = _distance_to_range(ls, le, s, e)
            if best is None or dist < best[1]:
                best = ((s, e), dist)
    if best is not None:
        return {"on_diff": True, "hunk": [best[0][0], best[0][1]], "distance": best[1]}
    if not ranges:
        return {"on_diff": True, "hunk": None, "distance": None}   # changed file, no ranges, lined finding: fail-open
    nearest = min(_distance_to_range(ls, le, s, e) for (s, e) in ranges)
    return {"on_diff": False, "hunk": None, "distance": nearest}


def _mk_worktree_dir(pr_number):
    return tempfile.mkdtemp(prefix="panopticon-pr%d-" % pr_number)


def acquire_pr(pr_number, repo=".", runner=subprocess.run):
    """Fetch a PR head into a throwaway worktree and return its base branch.

    Never mutates the caller's checkout — all work lands in the new worktree
    (the blast radius). Raises RuntimeError (loud) on any step's failure.
    """
    def _run(argv):
        r = runner(argv, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("panopticon --pr: `%s` failed: %s"
                               % (" ".join(argv), (r.stderr or "").strip()))
        return r.stdout

    view = _run(["gh", "pr", "view", str(pr_number), "--json", "baseRefName"])
    base = (_json.loads(view) or {}).get("baseRefName")
    if not base:
        raise RuntimeError("panopticon --pr: could not read base branch for PR %d" % pr_number)
    _run(["git", "-C", repo, "fetch", "origin", "refs/pull/%d/head" % pr_number])
    head_sha = _run(["git", "-C", repo, "rev-parse", "FETCH_HEAD"]).strip()
    wt = _mk_worktree_dir(pr_number)
    _run(["git", "-C", repo, "worktree", "add", "--detach", wt, "FETCH_HEAD"])
    return {"worktree": wt, "base": base, "head_sha": head_sha}


def release_worktree(path, repo=".", runner=subprocess.run):
    """Remove a worktree; tolerant if it is already gone."""
    try:
        runner(["git", "-C", repo, "worktree", "remove", "--force", path],
               capture_output=True, text=True)
    except Exception:
        pass

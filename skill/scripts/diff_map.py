"""Delta-review support (#449): turn a base ref + working tree into a per-file
changed-line-range map, and classify findings against it. Stdlib only; pure
functions plus thin git/gh subprocess wrappers.
"""
import re
import subprocess
import os
import json as _json
import tempfile
import uuid
import hashlib

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


class DiffMapError(Exception):
    """A delta-map computation failed in a way that must NOT silently degrade to
    an empty (and therefore vacuous-PASS) hunk map — the caller fails loud
    instead of scoping the on-diff gate to nothing (#5.0-08)."""


def hunk_map(repo, base):
    """Changed new-side line ranges per file (merge-base vs working tree),
    including untracked non-ignored files as whole-file ranges.

    Returns {} when the base is unresolvable (an upstream loud-fail already
    guards this). RAISES DiffMapError when the diff itself fails after a valid
    base — a git-diff failure must not fall through to an empty map that passes
    the delta gate vacuously (#5.0-08)."""
    try:
        mb = _run_git(repo, ["merge-base", "HEAD", base])
    except Exception:
        return {}
    if mb.returncode != 0 or not mb.stdout.strip():
        return {}
    base_sha = mb.stdout.strip()
    # Pin diff formatting so a user's gitconfig (diff.mnemonicPrefix=true, a
    # diff.external driver, quotepath escaping) can't reshape the `+++ b/<path>`
    # headers parse_unified_diff keys on — which would yield an empty map and a
    # vacuous PASS (#5.0-08).
    try:
        diff = _run_git(repo, ["-c", "diff.mnemonicPrefix=false",
                               "-c", "core.quotepath=false", "diff",
                               "--unified=0", "--no-color", "--find-renames",
                               "--src-prefix=a/", "--dst-prefix=b/", base_sha])
    except Exception as e:
        raise DiffMapError("git diff against %s failed: %s" % (base_sha, e))
    if diff.returncode != 0:
        raise DiffMapError("git diff against %s failed (rc=%s): %s"
                           % (base_sha, diff.returncode, (diff.stderr or "").strip()))
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


def _worktree_dir(repo, pr_number):
    """Deterministic per-(repo, PR) worktree path (owner steer: deterministic
    wherever possible) so acquire_pr is idempotent and a driver --pr run is
    resumable — re-acquisition returns the SAME tree, never leaks a fresh one.
    Under the system temp dir, keyed by the repo's physical path + PR number.

    realpath (#947 FIXME-1): on macOS mkdtemp/tempdir roots live under
    /var/folders/..., a symlink into /private/var/...; record the physical
    path so every consumer (guard allowlist, reconcile, cwd-derived paths)
    agrees.
    """
    key = hashlib.sha256(os.path.realpath(repo).encode("utf-8")).hexdigest()[:12]
    return os.path.realpath(os.path.join(tempfile.gettempdir(),
                                         "panopticon-pr-%d-%s" % (pr_number, key)))


def acquire_pr(pr_number, repo=".", runner=subprocess.run):
    """Fetch a PR head into a DETERMINISTIC throwaway worktree and return its
    base branch. Idempotent: if the deterministic worktree already exists and
    is registered (per `git worktree list`), REUSE it (no re-fetch, stays at
    its pinned head) so a driver --pr run resumes in the same tree; else
    fetch the PR head + create it.

    Never mutates the caller's checkout — all work lands in the worktree (the
    blast radius). Raises RuntimeError (loud) on any step's failure.
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

    wt = _worktree_dir(repo, pr_number)
    # `git worktree list` (no --porcelain) prints one line per worktree:
    # "<path>  <sha> [<branch>]" or "<path>  <sha> (detached HEAD)" — column
    # widths vary with the longest path, so match on the first whitespace-
    # split token rather than a fixed-width slice (verified against real
    # `git worktree list` output, not assumed from the porcelain format).
    listing = runner(["git", "-C", repo, "worktree", "list"],
                     capture_output=True, text=True)
    if listing.returncode == 0 and any(
            line.split()[:1] == [wt]
            for line in listing.stdout.splitlines() if line.strip()):
        head_sha = _run(["git", "-C", wt, "rev-parse", "HEAD"]).strip()
        return {"worktree": wt, "base": base, "head_sha": head_sha}   # reuse (resume)

    fetch_ref = "refs/panopticon/pr-%d-%s" % (pr_number, uuid.uuid4().hex)
    _run(["git", "-C", repo, "fetch", "--no-write-fetch-head", "origin",
          "refs/pull/%d/head:%s" % (pr_number, fetch_ref)])
    head_sha = _run(["git", "-C", repo, "rev-parse", fetch_ref]).strip()
    try:
        _run(["git", "-C", repo, "worktree", "add", "--detach", wt, head_sha])
    finally:
        try:
            _run(["git", "-C", repo, "update-ref", "-d", fetch_ref])
        except RuntimeError:
            pass
    return {"worktree": wt, "base": base, "head_sha": head_sha}


def release_worktree(path, repo=".", runner=subprocess.run):
    """Remove a worktree; tolerant if it is already gone."""
    try:
        runner(["git", "-C", repo, "worktree", "remove", "--force", path],
               capture_output=True, text=True)
    except Exception:
        pass

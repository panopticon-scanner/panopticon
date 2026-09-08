"""Phase 7 -- validate: the working-tree baseline, delta and worktree finalization."""
import glob as _glob
import hashlib
import json
import os
import shutil
import subprocess
import sys

import scripts.diff_map as diff_map
import scripts.run_manifest as run_manifest
from . import engine
from . import runio


# #run9 OPS-E1A: sentinel written when the run-start baseline probe FAILS
# (timeout/error/unexpected non-zero) -- distinct from a legitimately non-git
# target (no baseline at all). _tree_delta turns this into a fail-CLOSED integrity
# violation at validate, so a DoS'd/hung git probe can no longer silently disable
# the redteam clean-tree guard by reading as a clean tree that was never verified.
_TREE_BASELINE_PROBE_FAILED = "#panopticon:baseline-probe-failed\n"

def _write_probe_failed_baseline(baseline):
    os.makedirs(os.path.dirname(baseline), exist_ok=True)
    with runio._open_w_nofollow(baseline) as fh:
        fh.write(_TREE_BASELINE_PROBE_FAILED)
    return baseline

# #1514 (Codex BR-04): the baseline used to be raw porcelain status, and the
# delta was set subtraction over those records. A file that was ALREADY dirty at
# run start (` M app.py`) could be rewritten arbitrarily during the run and its
# status record never changed -- delta empty, tree_clean true. Pre-existing edits
# are the normal starting state for a coding-agent review, so that was the common
# path, not a corner. v2 records a content digest per baselined path alongside
# the status text, which is what makes "same status, different bytes" visible.
_BASELINE_SCHEMA = 2

# An untracked directory is one porcelain record but arbitrarily many files.
# Digesting without a bound would let a large untracked tree stall every run at
# start; exceeding it marks the baseline unestablished rather than quietly
# skipping files, so the failure is loud and fails CLOSED at validate.
_MAX_BASELINE_FILES = 20000


def _file_entry(path):
    """Content identity for one path: symlink target, file digest + exec bit,
    or absence. Mode is reduced to the executable bit because that is the only
    permission git itself tracks."""
    if os.path.islink(path):
        return {"type": "symlink", "target": os.readlink(path)}
    if not os.path.exists(path):
        return {"type": "absent"}
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return {"type": "file", "sha": h.hexdigest(),
            "exec": bool(os.stat(path).st_mode & 0o111)}


def _dir_entry(path, budget):
    """Content identity for an untracked DIRECTORY -- one digest over every
    file's relative path and content, so an edit anywhere inside it shows up."""
    h = hashlib.sha256()
    for root, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files):
            budget[0] -= 1
            if budget[0] < 0:
                return {"type": "truncated"}
            full = os.path.join(root, name)
            rel = os.path.relpath(full, path)
            entry = _file_entry(full)
            h.update(rel.encode("utf-8", "surrogateescape"))
            h.update(json.dumps(entry, sort_keys=True).encode("utf-8"))
    return {"type": "dir", "sha": h.hexdigest()}


def _entry_for(review_root, rel, budget):
    full = os.path.join(review_root, rel)
    if os.path.isdir(full) and not os.path.islink(full):
        return _dir_entry(full, budget)
    budget[0] -= 1
    if budget[0] < 0:
        return {"type": "truncated"}
    return _file_entry(full)


def _content_entries(review_root, status_output):
    """{path: entry} for every OUTSIDE-.panopticon path the status names.

    Only baselined paths need digests: a change to any file that was CLEAN at
    run start produces a NEW status record, which record subtraction already
    catches. The hole was exactly the paths whose record cannot change because
    it is already there.

    Ignored files are out of scope BY POLICY: `git status` without --ignored
    never reports them, so they are neither baselined nor audited. Build outputs
    and caches churn during any real run, and a scanner that never writes them
    is not what this guard exists to prove.
    """
    budget = [_MAX_BASELINE_FILES]
    entries = {}
    for _xy, paths in _porcelain_z_records(status_output):
        for rel in paths:
            rel = rel.rstrip("/")
            if not rel or not _outside_panopticon(rel) or rel in entries:
                continue
            entries[rel] = _entry_for(review_root, rel, budget)
    return entries


def capture_tree_baseline(review_root, runner=subprocess.run):
    """Snapshot the clean-tree baseline once (run start). Returns None (no
    baseline) for a legitimately non-git target -- the guard is N/A. A git-status
    PROBE FAILURE (timeout/error/unexpected non-zero) is NOT the same as non-git:
    it records a sentinel (loudly) so validate fails CLOSED rather than silently
    certifying a tree it never established a reference for (#run9 OPS-E1A)."""
    baseline = runio._pano(review_root, "tree-baseline.txt")
    if os.path.exists(baseline):
        return baseline
    try:
        proc = runner(["git", "-C", review_root, "status", "--porcelain", "-z"],
                      capture_output=True, text=True, timeout=15)
    except (subprocess.SubprocessError, OSError) as exc:
        print("driver: clean-tree baseline probe FAILED (%s); the integrity guard "
              "will fail closed at validate" % exc, file=sys.stderr, flush=True)
        return _write_probe_failed_baseline(baseline)
    if proc.returncode != 0:
        if "not a git repository" in (proc.stderr or "").lower():
            return None                              # non-git target: guard is N/A
        print("driver: clean-tree baseline probe exited %s (%s); the integrity guard "
              "will fail closed at validate"
              % (proc.returncode, (proc.stderr or "").strip()[:200]),
              file=sys.stderr, flush=True)
        return _write_probe_failed_baseline(baseline)
    entries = _content_entries(review_root, proc.stdout)
    truncated = any(e.get("type") == "truncated" for e in entries.values())
    if truncated:
        print("driver: clean-tree baseline exceeded %d files while digesting "
              "already-dirty/untracked paths; content equality cannot be "
              "established and the integrity guard will fail closed at validate"
              % _MAX_BASELINE_FILES, file=sys.stderr, flush=True)
    os.makedirs(os.path.dirname(baseline), exist_ok=True)
    with runio._open_w_nofollow(baseline) as fh:
        json.dump({"schema_version": _BASELINE_SCHEMA, "status": proc.stdout,
                   "entries": entries, "truncated": truncated}, fh,
                  sort_keys=True)
    return baseline

def _porcelain_z_records(output):
    """Parse `git status --porcelain -z` into a set of (XY, paths) records. Paths
    are RAW -- `-z` disables core.quotePath, so a non-ASCII name is emitted
    verbatim between NULs instead of C-quoted (`".panopticon/\\303\\251.py"`),
    which the old line-split mis-flagged. A rename/copy (X in R/C) carries BOTH
    endpoints: the entry's own (new) path plus the NUL-separated original path
    that immediately follows it (#1033/SEC-1)."""
    tokens = output.split("\0")
    records = set()
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if not tok:
            i += 1
            continue
        xy, path = tok[:2], tok[3:]
        if xy[:1] in ("R", "C") and i + 1 < len(tokens):
            records.add((xy, (path, tokens[i + 1])))   # (new, original)
            i += 2
        else:
            records.add((xy, (path,)))
            i += 1
    return records

def _outside_panopticon(path):
    """First path component is not `.panopticon` (a real boundary check:
    '.panopticon-evil.py' is NOT under .panopticon/)."""
    return path.split("/", 1)[0] != ".panopticon"

def _tree_delta(review_root, runner):
    """NEW porcelain records (vs. baseline) that touch a path outside
    .panopticon/. Empty when there is no baseline (non-git) — nothing to compare.
    A rename is checked on BOTH endpoints (#1033/SEC-1): a rename moving a real
    file INTO .panopticon/ still changed the outside tree via its source, which
    the old destination-only check silently missed."""
    try:
        with open(runio._pano(review_root, "tree-baseline.txt"), encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return []                                    # no baseline (non-git) -> nothing to compare
    if raw == _TREE_BASELINE_PROBE_FAILED:
        # #run9 OPS-E1A: the run-start baseline probe failed, so no clean-tree
        # reference exists -- the tree CANNOT be certified clean. Fail closed.
        return ["clean-tree baseline was never captured (git-status probe failed "
                "at run start); tree integrity cannot be certified"]
    # #1514: a v1 baseline is raw porcelain text with no digests. Resuming across
    # the upgrade must say so rather than silently certify on a check it cannot
    # perform -- the same fail-closed rule the probe-failure sentinel follows.
    try:
        snapshot = json.loads(raw)
        if not isinstance(snapshot, dict):
            raise ValueError("not an object")
    except ValueError:
        return ["clean-tree baseline predates content digests (schema v1); "
                "content equality not established, so tree integrity cannot "
                "be certified"]
    if snapshot.get("schema_version") != _BASELINE_SCHEMA:
        return ["clean-tree baseline schema_version %r is not %d; content "
                "equality not established, so tree integrity cannot be certified"
                % (snapshot.get("schema_version"), _BASELINE_SCHEMA)]
    if snapshot.get("truncated"):
        return ["clean-tree baseline was truncated at %d files; content equality "
                "not established, so tree integrity cannot be certified"
                % _MAX_BASELINE_FILES]
    baseline = _porcelain_z_records(snapshot.get("status") or "")
    try:
        proc = runner(["git", "-C", review_root, "status", "--porcelain", "-z"],
                      capture_output=True, text=True, timeout=15)
        if proc.returncode != 0:
            # #run9 OPS-E1A: a baseline exists but the verification probe failed --
            # we can't confirm the tree is unchanged, so fail closed, never []-clean.
            return ["clean-tree verification git-status exited %s; tree integrity "
                    "cannot be certified" % proc.returncode]
    except (subprocess.SubprocessError, OSError) as exc:
        return ["clean-tree verification git-status failed (%s); tree integrity "
                "cannot be certified" % exc]
    new = _porcelain_z_records(proc.stdout) - baseline
    delta = sorted("%s %s" % (xy, " -> ".join(paths)) for xy, paths in new
                   if any(_outside_panopticon(p) for p in paths))
    # #1514: the record set answers "did any file's STATUS change". It cannot see
    # a rewrite of a file that was already dirty (record unchanged) or a revert
    # of one (record disappears, and subtraction only looks at NEW records). Both
    # are reviewer side effects on user content, so compare the digests too.
    recorded = snapshot.get("entries")
    if isinstance(recorded, dict):
        budget = [_MAX_BASELINE_FILES]
        for rel, was in sorted(recorded.items()):
            try:
                now = _entry_for(review_root, rel, budget)
            except OSError as exc:
                delta.append("%s content unreadable at validate (%s); tree "
                             "integrity cannot be certified" % (rel, exc))
                continue
            if now.get("type") == "truncated":
                delta.append("%s content equality not established (baseline "
                             "budget exhausted)" % rel)
            elif now != was:
                delta.append("CONTENT %s (%s -> %s)"
                             % (rel, was.get("type"), now.get("type"))
                             if now.get("type") != was.get("type")
                             else "CONTENT %s" % rel)
    return delta

def validate_done(review_root, manifest):
    data = runio._load_json(runio._pano(review_root, "validate.json"))
    return (isinstance(data, dict) and data.get("run_id") == manifest.get("run_id")
            and data.get("tree_clean") is True)

def validate_execute(review_root, manifest, runner=subprocess.run):
    delta = _tree_delta(review_root, runner)
    # The PR worktree (when review_root IS the worktree) is released by run()
    # AFTER the run completes, NOT here: releasing mid-machine would delete the
    # review root (report.json + manifest) and break cursor derivation. (Ruling A)
    runio._write_json(runio._pano(review_root, "validate.json"),
                {"schema_version": 1, "run_id": manifest["run_id"],
                 "tree_clean": not delta, "unexpected_changes": delta})
    if delta:
        raise runio.DriverError("validate: reviewer side effects outside .panopticon/: "
                          + "; ".join(delta[:10]))
    return engine.PhaseResult(kind="advanced", message="validate: clean tree")

def _finalize_worktree(review_root, manifest):
    """On a completed --pr run, review_root IS the disposable worktree. Surface
    report.json to the caller's target .panopticon/ BEFORE releasing the worktree
    so the deliverable survives disposal (spec §4: no leak + report available).
    Best-effort surface; release is tolerant. No-op when there is no worktree."""
    worktree = manifest.get("worktree")
    if not worktree:
        return
    target = manifest.get("target") or review_root
    tag = run_manifest.run_tag(manifest)
    src_dir = os.path.join(review_root, ".panopticon")
    dst_dir = os.path.join(target, ".panopticon")
    # §5.1: surface the durable, top-level, tag-named outputs (report + optional
    # split part + html) so the caller's report is complete and self-consistent even
    # when split, then re-link report.json there. Falls back to a flat report.json
    # copy if there is no tag (no manifest — should not happen post-run).
    # #run7 OPS-E1A: surface EVERY durable tag-named artifact, not just part2 --
    # a split report (run-7 produced 4 parts + discarded + x0x) otherwise loses
    # part3+ on worktree release.
    if tag:
        names = sorted(os.path.basename(p) for p in
                       _glob.glob(os.path.join(src_dir, f"{tag}-report*.json")))
        names.append(f"{tag}-report.json.html")
    else:
        names = ["report.json"]
    failed = []
    for name in names:
        src, dst = os.path.join(src_dir, name), os.path.join(dst_dir, name)
        if os.path.realpath(src) == os.path.realpath(dst) or not os.path.isfile(src):
            continue
        try:
            os.makedirs(dst_dir, exist_ok=True)
            shutil.copyfile(src, dst)
        except OSError as e:
            failed.append((name, e))   # #run7 OPS-E1A: no longer silently swallowed
    if tag and os.path.isfile(os.path.join(dst_dir, f"{tag}-report.json")):
        try:
            runio._relink(os.path.join(dst_dir, "report.json"), f"{tag}-report.json")
            if os.path.isfile(os.path.join(dst_dir, f"{tag}-report.json.html")):
                runio._relink(os.path.join(dst_dir, "report.json.html"),
                        f"{tag}-report.json.html")
        except OSError:
            pass
    # #run7 OPS-E1A: the worktree is the ONLY other copy of the report. If ANY
    # artifact failed to surface, releasing it (git worktree remove --force) would
    # destroy the deliverable irrecoverably while run() still returns
    # status:complete. Keep the worktree and fail LOUD instead of silent loss.
    if failed:
        detail = "; ".join("%s (%s)" % (n, e) for n, e in failed)
        print("driver: FAILED to surface %d report artifact(s) to %s: %s -- KEEPING "
              "the worktree %s so the deliverable is recoverable (copy the report out, "
              "then `git -C %s worktree remove --force %s`)."
              % (len(failed), dst_dir, detail, worktree, target, worktree),
              file=sys.stderr, flush=True)
        return
    diff_map.release_worktree(worktree, repo=target)

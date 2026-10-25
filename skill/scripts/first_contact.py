"""First contact: one readiness assessment of the target, before any phase
writes (#3271, the #3173 audit's G2).

Until this step each artifact defended itself, and nothing halted on a target
that tracks or pre-plants `.panopticon/`: on a non-git target a planted
`run-manifest.json` naming the predictable extraction path was accepted as our
own prior run, flags and all. This sweep halts, loudly and with a fixed
reason, on clear hostility:

  H1  `.panopticon/` is tracked in the target's git index;
  H2  `.panopticon/` holds anything but no `owner.json` carrying this
      machine's stamp (`run_stamp`) -- planted, copied from elsewhere, or
      left by a pre-stamp run (owner ruling D1: move it aside or `--reset`).
      First contact writes that mark into a new or empty `.panopticon/`, so
      every directory a run of ours started carries it;
  H3  a symlink under `.panopticon/` other than the run's own links;
  H4  a regular file whose link count is greater than its in-tree name count,
      i.e. hard-linked to something outside the target. `.git/` is not counted
      (ruling A1): `git clone /local/path` hard-links its objects by default,
      and those are the operator's own repository, not a read lever;
  H5  something the sweep cannot read, which fails closed.

The whole-tree walk (H4) runs once per run, when its manifest is new: the
manifest records `first_contact`, and a resume of a stamped run skips it --
except under `driver setup`, whose directory grant covers the whole tree, which
walks on every invocation (#3271 B1, G-b). The cheap half -- H1 to H3 -- runs
on every invocation. What H4 does not count, no grant reads: a directory grant
never covers `<root>/.git` (G-a).

Every message is one line; a target-authored name in it is JSON-quoted
(control characters escaped) and bounded.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time

import scripts.build_disclosure as build_disclosure
import scripts.run_stamp as run_stamp
import scripts.safe_git as safe_git
import scripts.safe_write as safe_write

PANO = ".panopticon"
H1 = (".panopticon/ is tracked in the target's git index; panopticon never commits its "
      "artifact directory -- remove it from the index (git rm -r --cached .panopticon) or "
      "review a clean clone")
H2 = (".panopticon/ was not created by a panopticon run on this machine (its run stamp does "
      "not verify); move it aside (mv .panopticon .panopticon.old) or pass --reset, and re-run")
H3 = (".panopticon/%s is a symlink, and the artifact directory holds none but the run's own "
      "links; remove it and re-run")
H4 = ("%s is hard-linked outside the target (st_nlink=%d, %d in-tree names); review a copy "
      "without hard links (a plain cp)")
H5 = "the target cannot be assessed at first contact: %s: %s"
MORE = " (and %d more)"
PRIOR_HOST = build_disclosure.PRIOR_RUN
_MANIFESTS = ("run-manifest.json", "setup-manifest.json")
# The directory's ownership mark: written at first contact into a new or empty
# `.panopticon/`, stamped with this machine's key (`run_stamp`).
OWNER = "owner.json"
# The links our own runs make (`runio._relink`, `phases/synthesize`), and the
# staging name `_relink` replaces onto each.
_OWN_LINKS = re.compile(r"(?:runs/latest|report\.json|report\.json\.html)(?:\.relink-\d+\.tmp)?\Z")
_MAX_NAME = 200


class FirstContactHalt(ValueError):
    """The target failed first contact; the run halts with this one line."""


def _quote(rel):
    return json.dumps(rel)[1:-1][:_MAX_NAME]


def _tracked(review_root, runner):
    """(a git work tree?, any path under `.panopticon/` in its index?). Through
    `safe_git.probe`: a trusted git, with the target's own config (fsmonitor,
    hooks) suppressed. No trusted git, or a launch that fails, halts H5 on one
    line -- never a traceback, and never a stderr the target wrote."""
    try:
        proc = safe_git.probe(review_root, ["ls-files", "-z", "--", PANO],
                              runner=runner or subprocess.run, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise FirstContactHalt(H5 % ("git ls-files", type(exc).__name__)) from None
    if proc.returncode == 0:
        return True, bool((proc.stdout or "").strip("\0"))
    if proc.returncode == 128 and "not a git repository" in (proc.stderr or ""):
        return False, False
    raise FirstContactHalt(H5 % ("git ls-files", "exit %s" % proc.returncode))


# #3271 F0: present, but not a document any reader may trust.
UNREADABLE = object()


def _load(path):
    """The parsed object at `path`, None when nothing is there, or UNREADABLE:
    oversize, not a regular file, unreadable, not JSON, too deep, or not an
    object. Read through `load_manifest`'s own reader, so the document
    verified here is the one a resume then acts on."""
    try:
        doc = safe_write.read_manifest_json(path)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return UNREADABLE
    return doc if isinstance(doc, dict) else UNREADABLE


def _walk_errors(exc):
    raise FirstContactHalt(H5 % (_quote(getattr(exc, "filename", "") or "?"),
                                 exc.strerror or type(exc).__name__))


def _stray_links(pano):
    """Every symlink under `.panopticon/` that is not one of the run's own:
    a relative link, of an allowed name, resolving inside `.panopticon/`."""
    real = os.path.realpath(pano)
    stray = []
    for here, dirs, files in os.walk(pano, onerror=_walk_errors):
        for name in dirs + files:
            path = os.path.join(here, name)
            if not os.path.islink(path):
                continue
            rel = os.path.relpath(path, pano).replace(os.sep, "/")
            target = os.readlink(path)
            inside = os.path.commonpath([real, os.path.realpath(path)]) == real
            if not (_OWN_LINKS.match(rel) and not os.path.isabs(target) and inside):
                stray.append(rel)
    return sorted(stray)


def _outside_links(review_root, git=False):
    """[(rel, nlink, names)] for every regular file whose link count is greater
    than its in-tree name count. One walk, lstat only. Only a work tree's OWN
    `.git/` is pruned (review C2): a `vendor/.git/`, or a `.git/` shipped in a
    tarball, is target content like any other."""
    seen: dict = {}
    files = 0
    for here, dirs, names in os.walk(review_root, onerror=_walk_errors):
        if git and here == review_root:
            dirs[:] = [d for d in dirs if d != ".git"]
        for name in names:
            path = os.path.join(here, name)
            try:
                info = os.lstat(path)
            except OSError as exc:
                raise FirstContactHalt(H5 % (_quote(os.path.relpath(path, review_root)),
                                             exc.strerror or type(exc).__name__)) from None
            files += 1
            if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                row = seen.setdefault((info.st_dev, info.st_ino), [info.st_nlink, []])
                row[1].append(os.path.relpath(path, review_root).replace(os.sep, "/"))
    found = sorted((sorted(names)[0], nlink, len(names))
                   for nlink, names in seen.values() if nlink > len(names))
    return found, files


def _halt(rows, template):
    first = template % rows[0]
    raise FirstContactHalt(first + (MORE % (len(rows) - 1) if len(rows) > 1 else ""))


def _move_aside(pano):
    aside = "%s.unverified-%s" % (pano, time.strftime("%Y%m%dT%H%M%S", time.gmtime()))
    os.rename(pano, aside)
    print("driver: moved the unverified .panopticon/ aside to %s (--reset)"
          % os.path.basename(aside), file=sys.stderr, flush=True)


def _write_owner(pano, review_root):
    """Mark a new or empty `.panopticon/` as this machine's: a no-follow create
    of the directory and an exclusive, no-follow create of `owner.json`
    carrying the stamp. The one writer of the mark, for the driver's first
    contact and the standalone entries alike (#3273 P1). FileExistsError when
    anything is there by now -- a link, a file, an entry, the mark itself --
    so a directory that appeared after its assessment is never marked over."""
    try:
        os.mkdir(pano, 0o755)        # never follows a link at `pano`
    except FileExistsError:
        if os.path.islink(pano) or not os.path.isdir(pano) or os.listdir(pano):
            raise
    marker = {"run_id": secrets.token_hex(16), "review_root": os.path.abspath(review_root)}
    marker["stamp"] = run_stamp.sign(marker)
    fd = os.open(os.path.join(pano, OWNER),
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(marker, fh)


def _nothing_to_trust(pano):
    """Absent, or a real directory with nothing in it."""
    if not os.path.lexists(pano):
        return True
    try:
        return not os.path.islink(pano) and os.path.isdir(pano) and not os.listdir(pano)
    except OSError:
        return False             # the full assessment halts on it (H5)


def assess_artifacts(review_root, *, reset=False, runner=None, read_only=False):
    """H1-H3 for `review_root`'s `.panopticon/`, and its ownership: a new or
    empty one is marked ours (`owner.json`, stamped), a non-empty one must
    already carry this machine's mark. Returns {manifest name: its parsed
    contents} for the manifests present. `reset` moves an unverified
    `.panopticon/` aside instead of halting on H2 or H3 (never on H1).

    `read_only` is the standalone entries' assessment (#3273 P1): the same
    halts, but no mark and no key are written -- a new or empty `.panopticon/`
    passes as it is, and on a machine with no key nothing non-empty can verify
    (H2). `assess_standalone` marks afterwards, only where the entry writes."""
    keyless = None
    try:
        run_stamp.key(create=not read_only)
    except run_stamp.KeyUnavailable as exc:
        if not (read_only and not os.path.lexists(
                os.path.join(run_stamp.state_dir(), run_stamp.KEY_NAME))):
            raise FirstContactHalt(H5 % ("run stamp", exc)) from None
        keyless = exc
    pano = os.path.join(review_root, PANO)
    if read_only and _nothing_to_trust(pano):
        return {"git": None}      # no launch: an absent or empty directory vouches for nothing
    git, tracked = _tracked(review_root, runner)
    if tracked:
        raise FirstContactHalt(H1)
    if os.path.lexists(pano) and (os.path.islink(pano) or not os.path.isdir(pano)):
        if not reset:
            raise FirstContactHalt(H3 % "" if os.path.islink(pano)
                                   else H5 % (PANO, "not a directory"))
        _move_aside(pano)
    try:
        empty = not os.path.lexists(pano) or not os.listdir(pano)
    except OSError as exc:
        raise FirstContactHalt(H5 % (PANO, exc.strerror or type(exc).__name__)) from None
    if empty:
        if not read_only:        # emptied since `_nothing_to_trust`: still never marked here
            _write_owner(pano, review_root)
        return {"git": git}
    if keyless is not None:
        raise FirstContactHalt(H2)
    owner = _load(os.path.join(pano, OWNER))
    # Signed here AND for this tree: a real mark copied from another checkout
    # carries a valid stamp over ITS review_root, not this one.
    unverified = not (run_stamp.verifies(owner) and isinstance(owner, dict)
                      and owner.get("review_root") == os.path.abspath(review_root))
    manifests = {n: _load(os.path.join(pano, n)) for n in _MANIFESTS}
    # Review C1: the mark proves the DIRECTORY; a manifest a resume trusts must
    # prove itself too, so one planted into a directory of ours does not pass.
    # F0: one that is there but cannot be read whole (UNREADABLE, which no
    # stamp verifies) proves nothing either; only an ABSENT one is no manifest.
    unverified = unverified or any(m is not None and not _bound(m, owner, review_root)
                                   for m in manifests.values())
    stray = _stray_links(pano)
    if unverified or stray:
        if not reset:
            if unverified:
                raise FirstContactHalt(H2)
            _halt([(_quote(rel),) for rel in stray], H3)
        _move_aside(pano)
        _write_owner(pano, review_root)
        return {"git": git}
    return dict(manifests, git=git)


def _bound(manifest, owner, review_root):
    return (run_stamp.verifies(manifest) and manifest.get("owner") == owner.get("run_id")
            and manifest.get("review_root") == os.path.abspath(review_root))


def bind(review_root, manifest):
    """Stamp a new run or setup `manifest` to this tree's `owner.json`, so a
    later first contact can tell it from one planted beside the mark."""
    owner = _load(os.path.join(review_root, PANO, OWNER))
    owner = owner if isinstance(owner, dict) else {}
    manifest["owner"] = owner.get("run_id")
    manifest["stamp"] = run_stamp.sign(manifest)
    return manifest


def assess_loop(args, resolved):
    """`driver loop`'s first contact (#3271 B2), in `driver loop` and `driver
    loop --setup` alike: H1-H3 on the review root and, under --pr, on the
    operator's checkout, BEFORE the loop reads a manifest, a dispatch request
    or a crash record, and before it deletes anything a crash record names.
    Each iteration's `driver.run` / `run_setup_flow` then makes the whole
    contact, H4 included. A halt releases a --pr worktree, as `driver.run`'s does."""
    review_root, worktree = resolved[0], resolved[1]
    reset = getattr(args, "reset", False)
    try:
        for root in ((args.target,) if getattr(args, "pr", None) else ()) + (review_root,):
            assess_artifacts(root, reset=reset)
    except FirstContactHalt:
        if worktree:
            import scripts.diff_map as diff_map
            diff_map.release_worktree(worktree, repo=args.target)
        raise


def _owning_roots(path):
    """The trees whose `.panopticon/` holds `path`, as spelled and as resolved:
    a symlink cannot route a run artifact into an unassessed `.panopticon/`."""
    roots = []
    for spelled in (os.path.abspath(path), os.path.realpath(path)):
        head = spelled
        while True:
            parent, name = os.path.split(head)
            if name == PANO:
                roots.append(parent)
                break
            if parent == head:
                break
            head = parent
    return roots


def _mark_or_reassess(root, runner):
    """Mark `root`'s absent or empty `.panopticon/` through `_write_owner`; when
    something appeared there since its assessment, assess it again instead
    (it halts unless it is now ours). Twice at most."""
    pano = os.path.join(root, PANO)
    for _ in range(2):
        try:
            _write_owner(pano, root)
            return
        except FileExistsError:
            assess_artifacts(root, runner=runner, read_only=True)
            if not _nothing_to_trust(pano):
                return               # it verified as ours
    raise FirstContactHalt(H5 % (PANO, "it kept changing while it was being marked"))


def assess_standalone(cwd, read_paths, write_paths=(), *, root_hints=(), runner=None):
    """A direct `synthesize.py` / `discovery.py`'s first contact (#3273 P1):
    H1-H3 and the ownership mark, read-only, on `cwd` (None: discovery, which
    reads no cwd artifact) and on every tree whose
    `.panopticon/` holds one of `read_paths` or `write_paths`, before the
    entry reads or writes any of them. A tree whose `.panopticon/` was absent
    or empty and that this invocation writes into is then marked ours, by the
    driver's own writer (ruling R1); one it only reads is left unmarked. The
    driver's children pass: their parent made the whole contact. No H4 walk:
    neither entry grants an agent a read. `run_tools.py` stays markless.

    The mark binds the tree as the driver SPELLED it (`abspath`), and
    `getcwd()` is resolved (`/tmp` vs `/private/tmp`), so each tree is
    assessed under an unresolved spelling when one is found (a `root_hints`
    entry -- --root, $PWD -- naming the cwd, or an artifact path), and as
    resolved only otherwise."""
    found = [os.path.abspath(h) for h in root_hints
             if h and cwd and os.path.realpath(h) == os.path.realpath(cwd)]
    written = set()
    for paths, writes in ((read_paths, False), (write_paths, True)):
        for path in paths:
            for root in _owning_roots(path) if path else ():
                found.append(root)
                if writes:
                    written.add(os.path.realpath(root))
    if cwd:
        found.append(cwd)
    roots: list = []
    for unresolved_only in (True, False):
        for root in found:
            if unresolved_only and root == os.path.realpath(root):
                continue
            if all(os.path.realpath(root) != os.path.realpath(r) for r in roots):
                roots.append(root)
    for root in roots:
        assess_artifacts(root, runner=runner, read_only=True)
        if (os.path.realpath(root) in written
                and _nothing_to_trust(os.path.join(root, PANO))):
            _mark_or_reassess(root, runner)


def assess(review_root, manifest_name, *, reset=False, host=None, other_roots=(), runner=None,
           walk_every_time=False):
    """The whole first contact for the run whose manifest is `manifest_name`:
    H1-H3 on `review_root` (and on each of `other_roots` -- the operator's own
    checkout under --pr, which the run copies its report into), then, unless
    that stamped manifest is resuming, the one H4 walk. Returns the record a
    NEW manifest carries as `first_contact`, or None on a resume.

    `walk_every_time` (#3271 B1, ruling G-b) is `driver setup`'s: its scan
    holds the one directory grant over the whole tree, so the H4 walk runs on
    every setup invocation, a resume included, not once per run."""
    for root in other_roots:
        assess_artifacts(root, reset=reset, runner=runner)
    ours = assess_artifacts(review_root, reset=reset, runner=runner)
    prior = ours.get(manifest_name)
    resuming = isinstance(prior, dict) and isinstance(prior.get("first_contact"), dict) and not reset
    if resuming and not walk_every_time:
        return None
    found, files = _outside_links(review_root, git=ours.get("git", False))
    if found:
        _halt([(_quote(rel), nlink, names) for rel, nlink, names in found], H4)
    if resuming:
        return None
    record = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "files": files}
    if isinstance(prior, dict) and host and prior.get("host") not in (None, host):
        # Owner ruling D2: a stamped run by ANOTHER host is ours; say so.
        run_id = str(prior.get("run_id") or "")[:8]
        record["prior_run"] = {"host": str(prior["host"])[:32], "run_id": run_id}
        print("driver: " + PRIOR_HOST % (record["prior_run"]["host"], run_id),
              file=sys.stderr, flush=True)
    return record

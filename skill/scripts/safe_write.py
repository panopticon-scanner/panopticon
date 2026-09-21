#!/usr/bin/env python3
"""The no-follow `.panopticon` artifact open, and nothing else. Stdlib-only.

`.panopticon/` lives INSIDE the reviewed tree, so under redteam every artifact
path is a name an untrusted target can pre-commit as a symlink to any file the
invoking user can write. A plain `open(path, "w")` follows that link and
clobbers the victim; `os.makedirs` traverses a symlinked intermediate
directory the same way. These three functions are the answer, and they are the
ONLY spelling of it on the driver side.

They started in `phases/runio` (#1095, #run9 SEC-X0X) and moved down here
whole in #1735, because the module that needed them next could not reach them:
`run_manifest._rewrite` stages the manifest at `<manifest>.tmp` with a plain
write, and `run_manifest` may not import `phases` -- `phases/*` imports
`run_manifest`, and layout rule 3 (tests/test_layout.py) keeps that arrow
pointing one way. `synth/*` may not reach `phases` either. A leaf module that
imports nothing of ours is reachable from all three sides, so the guard is
written once rather than copied per caller (the copy is what #1735 was: the
sibling guard hooks carry their own O_EXCL|O_NOFOLLOW write -- deliberately,
since a hook subprocess has no package on sys.path -- and `_rewrite` was
simply never brought along).

`phases/runio` binds all three under its own private names, as aliases of
THESE objects (tests/test_safe_write.py pins the identity). A test patches the
runio alias, not the name here: every existing caller reaches the primitive
through `runio`, so a patch applied here would leave all of them running the
real one.

No makedirs in `open_w_nofollow`: a caller that must create the parent calls
`confine_artifact_path` FIRST and then makedirs, which is the order
`runio._write_json` and `open_a_nofollow` below already use -- confining after
the makedirs would mean the traversal had already happened.
"""
import os


def confine_artifact_path(path):
    """Reject a `.panopticon` artifact path whose REAL location escapes the real
    `.panopticon` via a symlinked component (#run9 SEC-X0X). plan_contract.
    artifact_root() vets only the TOP-LEVEL `.panopticon` (once, at run start) and
    open_w_nofollow's O_NOFOLLOW only the FINAL component, so a hostile target can
    plant an INTERMEDIATE symlink (`.panopticon/runs -> /elsewhere`) that a write
    would traverse. Anchor on the path's own `.panopticon` segment and require the
    realpath (which resolves any symlinked intermediate dir) to stay inside the
    real root. A planted `runs` link resolves outside and is rejected; a legit
    not-yet-created path resolves lexically against its real parent and passes, and
    the intentional `runs/latest` link (which points WITHIN `.panopticon`) passes.
    A path with no `.panopticon` segment is not an artifact path and is left be."""
    apath = os.path.abspath(path)
    parts = apath.split(os.sep)
    if ".panopticon" not in parts:
        return
    root = os.sep.join(parts[:parts.index(".panopticon") + 1]) or os.sep
    real_root = os.path.realpath(root)
    real = os.path.realpath(apath)
    if not (real == real_root or real.startswith(real_root + os.sep)):
        raise ValueError(
            "artifact path escapes .panopticon via a symlinked component: %r" % path)


def open_w_nofollow(path):
    """Open `path` for writing, refusing to follow a symlink at the final path
    component. A target repo (untrusted under redteam) can pre-commit a
    `.panopticon` artifact path as a symlink to a file the invoking user can
    write (a dotfile, authorized_keys, ...); plain open() would follow it and
    clobber that target. O_NOFOLLOW makes the open fail on a symlink; we then
    replace the link with a fresh regular file instead of writing through it
    (#1095 -- mirrors run_manifest's exclusive-create precedent).

    #run9 SEC-X0X: O_NOFOLLOW guards only the FINAL component, so confine the whole
    resolved path to the real `.panopticon` first -- an intermediate symlinked dir
    (`.panopticon/runs -> /elsewhere`) would otherwise carry this write outside.

    Safe for a STAGING path too, and #1735 is why it has to be used for one: a
    `<artifact>.tmp` sitting in the reviewed tree is as plantable as the
    artifact, and more quietly so -- the `os.replace` that follows renames the
    LINK over the artifact, so a run that never noticed also loses the anchor."""
    confine_artifact_path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError:
        if os.path.islink(path):
            os.unlink(path)                       # neutralize the link, never follow it
            fd = os.open(path, flags, 0o644)
        else:
            raise
    return os.fdopen(fd, "w", encoding="utf-8")


def open_a_nofollow(path):
    """Open `path` for APPENDING, refusing to follow a symlink at the final
    path component -- the O_APPEND analogue of `open_w_nofollow` (#1095,
    plan 6 review round 1) for a caller that must ADD a line without ever
    truncating what is already there (Ledger.record's dispatch-ledger.jsonl,
    one line per launch). Folds the confine-then-makedirs sequence
    `runio._write_json` applies around `open_w_nofollow` INTO this call, so a
    caller needs neither a separate `confine_artifact_path` nor its own
    `os.makedirs` -- `Ledger.record` no longer carries either."""
    confine_artifact_path(path)               # SEC-X0X: before makedirs, which would
    os.makedirs(os.path.dirname(path), exist_ok=True)   # otherwise follow a symlinked dir
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError:
        if os.path.islink(path):
            os.unlink(path)                       # neutralize the link, never follow it
            fd = os.open(path, flags, 0o644)
        else:
            raise
    return os.fdopen(fd, "a", encoding="utf-8")

#!/usr/bin/env python3
"""Bounded no-follow reads plus `.panopticon` artifact writes and publication.

`.panopticon/` lives INSIDE the reviewed tree, so under redteam every artifact
path is a name an untrusted target can pre-commit as a symlink to any file the
invoking user can write. A plain `open(path, "w")` follows that link and
clobbers the victim; `os.makedirs` traverses a symlinked intermediate
directory the same way. The three guards below own this defence on the driver
side; `publish_texts` uses them for staged report publication.

They started in `phases/runio` (#1095, #run9 SEC-X0X) and moved down here
whole in #1735, because the module that needed them next could not reach them:
`run_manifest._rewrite` stages the manifest at `<manifest>.tmp` with a plain
write, and `run_manifest` may not import `phases` -- `phases/*` imports
`run_manifest`, and layout rule 3 (tests/test_layout.py) keeps that arrow
pointing one way. `synth/*` may not reach `phases` either. This module depends
only on stdlib and the stdlib-only `claim_scope`, so it is reachable from all
three sides. The guard is
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

`read_regular_bytes` is the one descriptor-checked reader for verdicts, run
metadata, and evidence-scope source files. It owns the no-follow, nonblocking,
regular-file, and byte-limit checks; callers own confinement and presentation.
"""
import errno
import os
import stat
from typing import TYPE_CHECKING

if TYPE_CHECKING or __package__:
    from scripts import claim_scope
else:  # flat consumers put skill/scripts itself on sys.path
    import claim_scope


class ReadLimitExceeded(ValueError):
    """A regular file exceeded the caller's explicit byte boundary."""


class NonRegularFileError(OSError):
    """The opened leaf is not a regular file and no bytes were consumed."""


class ArtifactPathError(OSError):
    """A named refusal to write, publish, or remove an artifact path."""

    def __init__(self, action, path, cause):
        self.action = action
        self.path = os.fspath(path)
        self.cause = cause
        detail = (str(cause).splitlines() or [type(cause).__name__])[0]
        super().__init__("cannot %s artifact %r: %s" %
                         (action, self.path, detail or type(cause).__name__))


def read_failure_reason(error):
    """Classify the stage that rejected a bounded artifact read.

    Byte decoding and document parsing failures are ``unparseable``; filesystem
    failures remain ``unreadable``, and the explicit byte cap is ``oversized``.
    """
    if isinstance(error, ReadLimitExceeded):
        kind = "oversized"
    elif isinstance(error, OSError):
        kind = "unreadable"
    else:
        kind = "unparseable"
    detail = (str(error).splitlines() or [type(error).__name__])[0]
    return "%s: %s" % (kind, detail or type(error).__name__)


def read_regular_bytes(path, limit):
    """Read at most ``limit`` bytes from a regular, non-symlink leaf.

    The descriptor check closes the size and file-type races around a prior
    ``stat``. ``O_NONBLOCK`` keeps a special file from hanging before the
    descriptor type is rejected. ``NonRegularFileError`` and
    ``ReadLimitExceeded`` distinguish policy refusals; other ``OSError``
    instances retain the operating system's I/O outcome. Callers retain
    decoding and presentation policy.
    """
    if type(limit) is not int or limit <= 0:
        raise ValueError("read limit must be a positive integer")
    flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NonRegularFileError(errno.EINVAL, "not a regular file")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(limit + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(raw) > limit:
        raise ReadLimitExceeded("over the %d-byte read limit; skipped unparsed" % limit)
    return raw


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
    review_root = claim_scope.review_root_of_artifact_path(apath)
    if review_root is None:
        return
    root = os.path.join(review_root, ".panopticon")
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


def remove_artifact(path):
    """Remove an artifact leaf without following it or an escaping parent.

    Confine the parent rather than the leaf so a planted final symlink can be
    unlinked safely. Missing artifacts are already in the requested state.
    """
    try:
        confine_artifact_path(os.path.dirname(os.path.abspath(path)))
        try:
            os.unlink(path)
        except FileNotFoundError:
            return
    except OSError as exc:
        raise ArtifactPathError("remove", path, exc) from None


def write_text(path, text):
    """Write one text artifact without following a planted path component."""
    try:
        confine_artifact_path(path)
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        with open_w_nofollow(path) as stream:
            stream.write(text)
    except OSError as exc:
        raise ArtifactPathError("write", path, exc) from None


def publish_texts(targets):
    """Stage `(final_path, temp_path, text)` entries, then publish in reverse.

    Callers put the main report first so its sibling pointers go live last.
    Every write must finish before any destination is replaced. Each replace
    is atomic; the set is not a transaction, so a failed replace can leave
    earlier siblings published. Return final paths in the supplied order.

    Stage names and serialization belong to the caller. Cleanup includes the
    currently failing write or close and planted leaf links. Confine parents
    before creating directories or tracking cleanup: removing a temporary
    through an escaping intermediate link would itself modify another tree.
    """
    staged = []
    try:
        for final, temp, text in targets:
            try:
                parent = os.path.dirname(os.path.abspath(temp))
                confine_artifact_path(parent)
                os.makedirs(parent, exist_ok=True)
                staged.append((temp, final))
                with open_w_nofollow(temp) as stream:
                    stream.write(text)
            except OSError as exc:
                raise ArtifactPathError("stage", final, exc) from None
        for temp, final in reversed(staged):
            try:
                os.replace(temp, final)
            except OSError as exc:
                raise ArtifactPathError("publish", final, exc) from None
    finally:
        for temp, _ in staged:
            if os.path.lexists(temp):
                try:
                    os.remove(temp)
                except OSError:
                    pass
    return [final for _, final in staged]

#!/usr/bin/env python3
"""Bounded no-follow reads plus `.panopticon` artifact writes and publication.

`.panopticon/` lives INSIDE the reviewed tree, so under redteam every artifact
path is a name an untrusted target can pre-commit as a symlink to any file the
invoking user can write. A plain `open(path, "w")` follows that link and
clobbers the victim; `os.makedirs` traverses a symlinked intermediate
directory the same way. The guards below own this defence on the driver
side; `publish_texts` uses the exclusive staging guard for report publication.

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

import json

if TYPE_CHECKING or __package__:
    from scripts import claim_scope, tolerant_json
else:  # flat consumers put skill/scripts itself on sys.path
    import claim_scope
    import tolerant_json

# #3271 F0: the most a run or setup manifest (or `owner.json`) may weigh. ONE
# number for the checker and every consumer: first contact once read 1 MiB
# while `load_manifest` read the whole file, so a manifest padded past the cap
# went unverified there and was then parsed and resumed here.
MANIFEST_MAX_BYTES = 1 << 20


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


class UnsafeStagingPathError(ValueError):
    """A fixed staging name was occupied by a leaf we cannot safely replace."""

    def __init__(self, path, detail):
        self.path = os.fspath(path)
        super().__init__("refusing occupied staging path %r: %s" % (self.path, detail))


class ArtifactSymlinkError(ValueError):
    """A final artifact leaf is a symlink and must remain untouched (#3269)."""

    def __init__(self, path):
        self.path = os.fspath(path)
        super().__init__("refusing artifact-path symlink %r" % self.path)


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


def read_manifest_json(path):
    """The one reader of a document first contact vouches for (#3271 F0): a
    regular non-symlink leaf of at most MANIFEST_MAX_BYTES, depth-checked and
    parsed whole. `FileNotFoundError` means nothing is at `path`; any other
    `OSError` or `ValueError` means something IS there that no reader may
    trust -- a FIFO is refused before a byte is read, never blocked on."""
    raw = read_regular_bytes(path, MANIFEST_MAX_BYTES)
    return json.loads(tolerant_json.depth_checked(raw.decode("utf-8")))


def confine_artifact_path(path):
    """Reject a `.panopticon` artifact path whose REAL location escapes the real
    `.panopticon` via a symlinked component (#run9 SEC-X0X). First contact
    (#3271) vets `.panopticon` once per invocation, at its start, and
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


def _replace_nonartifact_symlink(path):
    """Unlink a final symlink only for a caller-chosen non-artifact output.

    Artifact symlinks are a hostile-tree signal and get one loud refusal. The
    historical replacement behavior remains for explicit output paths outside
    `.panopticon`, where replacing the leaf without following it is the API.
    """
    if not os.path.islink(path):
        return False
    if claim_scope.review_root_of_artifact_path(os.path.abspath(path)) is not None:
        raise ArtifactSymlinkError(path)
    os.unlink(path)
    return True


def open_w_nofollow(path):
    """Open `path` for writing, refusing to follow a symlink at the final path
    component. A target repo (untrusted under redteam) can pre-commit a
    `.panopticon` artifact path as a symlink to a file the invoking user can
    write (a dotfile, authorized_keys, ...); plain open() would follow it and
    clobber that target. O_NOFOLLOW makes the open fail on a symlink. At an
    artifact path that is one loud refusal (#3269 G9); a caller-chosen output
    outside `.panopticon` retains #1095's safe replace-without-following API.

    #run9 SEC-X0X: O_NOFOLLOW guards only the FINAL component, so confine the whole
    resolved path to the real `.panopticon` first -- an intermediate symlinked dir
    (`.panopticon/runs -> /elsewhere`) would otherwise carry this write outside.

    Fixed staging paths use `open_staging_nofollow` instead: their names must be
    created exclusively, while a final artifact legitimately already exists."""
    confine_artifact_path(path)
    # O_NONBLOCK keeps an existing FIFO from waiting forever for a reader. The
    # descriptor check rejects every non-regular leaf that can still be opened
    # (for example a FIFO that already has a reader) before any bytes are sent.
    # #3235: no O_TRUNC -- a hard link is refused BEFORE anything is truncated.
    flags = (os.O_WRONLY | os.O_CREAT
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, flags, 0o644)
    except OSError:
        if _replace_nonartifact_symlink(path):
            fd = os.open(path, flags, 0o644)
        else:
            raise
    try:
        _refuse_unless_sole_regular(fd)
        os.ftruncate(fd, 0)
    except Exception:
        os.close(fd)
        raise
    return os.fdopen(fd, "w", encoding="utf-8")


def _refuse_unless_sole_regular(fd):
    """A regular file with ONE name (#3235). A second link is another path to the same bytes,
    and writing through it changes a file outside the artifact this call was asked for."""
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise NonRegularFileError(errno.EINVAL, "not a regular file")
    if info.st_nlink != 1:
        raise NonRegularFileError(errno.EMLINK, "refusing a file with %d hard links"
                                  % info.st_nlink)


def open_staging_nofollow(path):
    """Create a fixed staging leaf exclusively, reusing only a safe leftover.

    #2093: O_NOFOLLOW alone still opens and truncates a hard link, while opening
    a FIFO can block. O_EXCL refuses every occupied name before either can happen;
    O_NONBLOCK is retained as a second bounded-open guard. A singly-linked regular
    file is an orphan from our own interrupted stage and may be unlinked first.
    Symlinks, special files, and multiply-linked regular files are refused.
    """
    confine_artifact_path(path)
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))

    def create():
        return os.open(path, flags, 0o644)

    collisions = (errno.EEXIST, errno.ELOOP)
    try:
        fd = create()
    except OSError as exc:
        if exc.errno not in collisions:
            raise
        try:
            found = os.lstat(path)
        except FileNotFoundError:
            found = None
        if found is not None:
            if not stat.S_ISREG(found.st_mode) or found.st_nlink != 1:
                raise UnsafeStagingPathError(
                    path, "leaf is not a singly-linked regular file") from None
            os.unlink(path)
        try:
            fd = create()
        except OSError as retry:
            if retry.errno in collisions:
                raise UnsafeStagingPathError(
                    path, "leaf changed while the stale stage was replaced") from None
            raise
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise UnsafeStagingPathError(
                path, "created leaf is not a singly-linked regular file")
        return os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise


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
        if _replace_nonartifact_symlink(path):
            fd = os.open(path, flags, 0o644)
        else:
            raise
    try:
        _refuse_unless_sole_regular(fd)
    except Exception:
        os.close(fd)
        raise
    return os.fdopen(fd, "a", encoding="utf-8")


def open_lock_nofollow(path):
    """A persistent lock file, opened for appending, never through a link and never blocked on a
    pipe (#3256). It outlives the run, so it is not created exclusively; it must be regular."""
    confine_artifact_path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), 0o644)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("the lock is not a regular file: %s" % path)
    except BaseException:
        os.close(fd)
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
    """Write text with path refusals normalized, but encoding errors intact."""
    try:
        try:
            confine_artifact_path(path)
        except ValueError as exc:
            raise ArtifactPathError("write", path, exc) from None
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        try:
            stream = open_w_nofollow(path)
        except ValueError as exc:
            raise ArtifactPathError("write", path, exc) from None
        with stream:
            stream.write(text)
    except ArtifactPathError:
        raise
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
                with open_staging_nofollow(temp) as stream:
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

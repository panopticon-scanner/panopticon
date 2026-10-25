"""The run stamp: proof that a `.panopticon/` was started by panopticon on THIS
machine (#3271, the #3173 audit's G2).

A target can plant or commit anything inside the reviewed tree, so nothing in
the tree can say "this is ours". The stamp is an HMAC-SHA256 over a record's
`run_id` and `review_root`, keyed by 32 random bytes that live on the operator
side and never enter a target: a planted `.panopticon/owner.json` cannot carry
a valid one, and a real one copied from another checkout fails on its
`review_root`. The run and setup manifests carry one too, over their own
run_id and review_root and the `owner.json` run_id they were written under, so
a manifest planted into a directory that IS ours (a tarball re-extracted over
a scanned checkout) does not verify either.

The key lives under `$PANOPTICON_STATE_DIR` (default `~/.local/state/panopticon`,
shared with #3272's probe cache). The directory is 0700 and the key 0600. It is
created through an exclusive temp file and `os.link`, so two first runs racing
on a new machine agree on one key and no reader ever sees a partial one. A key
that is a symlink, not a regular file, the wrong size, or readable by group or
other is refused: a key nobody can trust signs nothing, and the run halts
rather than running unstamped (owner ruling D3, 2026-10-24).

Stdlib only.
"""
from __future__ import annotations

import errno
import hashlib
import hmac
import os
import secrets
import stat

KEY_NAME = "run-stamp.key"
KEY_BYTES = 32
_KEY_CACHE: dict = {}


class KeyUnavailable(ValueError):
    """The stamp key cannot be created or trusted; the run halts (H5)."""


def state_dir():
    """The operator-side state directory, never inside a target."""
    override = os.environ.get("PANOPTICON_STATE_DIR")
    if override:
        return os.path.abspath(override)
    return os.path.join(os.path.expanduser("~"), ".local", "state", "panopticon")


def _ensure_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise KeyUnavailable("%s is not a real directory" % path)
    if info.st_uid != os.getuid():
        raise KeyUnavailable("%s is owned by another user" % path)
    if info.st_mode & 0o077:
        os.chmod(path, 0o700)


def _read(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise KeyUnavailable("%s is not a regular file" % path)
        if info.st_mode & 0o077:
            raise KeyUnavailable("%s is readable by group or other" % path)
        if info.st_uid != os.getuid():
            raise KeyUnavailable("%s is owned by another user" % path)
        data = os.read(fd, KEY_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) != KEY_BYTES:
        raise KeyUnavailable("%s is not a %d-byte key" % (path, KEY_BYTES))
    return data


def _create(directory, path):
    """Write a fresh key under a private name, then link it into place: the link
    is exclusive, so the first run wins and every other reads the winner's."""
    tmp = os.path.join(directory, ".%s.%s.tmp" % (KEY_NAME, secrets.token_hex(8)))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, secrets.token_bytes(KEY_BYTES))
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(tmp, path)
    except FileExistsError:
        pass
    finally:
        os.unlink(tmp)


def key(create=True):
    """This machine's stamp key, created on first use; KeyUnavailable otherwise.
    `create=False` reads an existing key only, and an absent one is
    KeyUnavailable (a standalone entry writes no key, #3273 P1)."""
    directory = state_dir()
    path = os.path.join(directory, KEY_NAME)
    cached = _KEY_CACHE.get(path)
    if cached is not None:
        return cached
    try:
        if not create:
            data = _read(path)
        else:
            _ensure_dir(directory)
            try:
                data = _read(path)
            except FileNotFoundError:
                _create(directory, path)
                data = _read(path)
    except KeyUnavailable as exc:
        raise KeyUnavailable("run-stamp key: %s" % exc) from None
    except OSError as exc:
        reason = "a symlink" if exc.errno == errno.ELOOP else (exc.strerror or type(exc).__name__)
        raise KeyUnavailable("run-stamp key %s: %s" % (path, reason)) from None
    _KEY_CACHE[path] = data
    return data


def _message(manifest):
    # `owner` binds a manifest to the directory mark it was written under
    # (#3271 review C1); the mark itself has none, and signs "".
    return ("panopticon-run-stamp-1\0%s\0%s\0%s" % (
        manifest.get("run_id"), manifest.get("review_root"),
        manifest.get("owner") or "")).encode("utf-8", "surrogateescape")


def sign(manifest):
    """The stamp for `manifest` (hex)."""
    return hmac.new(key(), _message(manifest), hashlib.sha256).hexdigest()


def verifies(manifest):
    """Whether the record `manifest` carries this machine's stamp for its own
    run_id and review_root. False for anything else, never a raise on a bad shape; a key
    that cannot be read raises KeyUnavailable (the caller halts)."""
    if not isinstance(manifest, dict):
        return False
    stamp, run_id, root = manifest.get("stamp"), manifest.get("run_id"), manifest.get("review_root")
    if not (isinstance(stamp, str) and isinstance(run_id, str) and isinstance(root, str)):
        return False
    try:
        return hmac.compare_digest(stamp.encode("ascii"), sign(manifest).encode("ascii"))
    except (UnicodeEncodeError, ValueError):
        return False         # a lone surrogate or a non-ASCII stamp is no stamp of ours

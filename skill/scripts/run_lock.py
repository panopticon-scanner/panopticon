"""The run lock: one driver at a time on a review root (#3779).

`driver run`, `driver loop` and `driver setup` each read `.panopticon/`, decide, and
write. Two of them on one root decide on what the other is changing: a second driver's
`--reset` deleted the run folder under the first, and an older driver that woke after
a newer run finished set that run's report aside.

The lock is `flock` on one file per review root, held by the process for the whole
verb. The kernel lets it go when the last holder exits, so a killed driver leaves no
stale lock and nothing here guesses whether a pid is alive to decide anything.

The file lives in the operator's state directory (`run_stamp.state_dir`), named by the
SHA-256 of the root's real path: a target cannot plant, hold or delete it, first
contact has nothing new to judge, and `--reset` does not touch it. The file is never
removed, so its name always means the same inode.

A phase child (`phases/child._run_child`) is handed the descriptor. It is the same
open file, so a synthesis child that outlives a killed driver still holds the root,
and a retry is refused until that child exits. Nothing else is handed it: the
descriptor is close-on-exec in the driver, and `_bootstrap.py` makes it close-on-exec
again in the child, so no scanner, shell or reviewer agent either of them starts
holds the root.

What the file SAYS (pid, verb, start, the phase child now running) is for the next
driver's refusal and for nothing else. It is read back type by type, never printed
as written.

Not covered: `driver persist` and `driver readiness` take no lock, and two state
directories (two machines, or two users, on one shared tree) do not exclude each
other.

Stdlib only.
"""
from __future__ import annotations

import contextlib
import datetime
import errno
import fcntl
import hashlib
import json
import os
import re
import socket
import stat
import threading
from typing import Any, TypeGuard

from scripts import run_stamp

LOCKS_DIR = "locks"
#: The variable a phase child reads its inherited descriptor's number from.
FD_ENV = "PANOPTICON_RUN_LOCK_FD"
VERBS = ("run", "loop", "setup")

_SINCE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_PHASE = re.compile(r"[a-z]{1,20}")
_HOST = re.compile(r"[A-Za-z0-9._-]{1,255}")
_RECORD_MAX = 4096

#: lock path -> [descriptor, how many holds deep, what the file says]
_HELD: dict = {}
_GUARD = threading.RLock()

_AGAIN = "wait for it to finish, or stop it, then run again"
_UNUSABLE = ("the run lock cannot be used: %s. `driver run`, `loop` and `setup` hold one "
             "lock file per review root under the state directory; point "
             "PANOPTICON_STATE_DIR at a directory you own on a local filesystem")


class Refused(ValueError):
    """The review root cannot be taken: another process holds it, or the lock itself
    cannot be used. The message is the whole status."""


def lock_path(review_root):
    """The lock file for `review_root`, by its real path: a link to a root is that root."""
    real = os.path.realpath(review_root)
    return os.path.join(run_stamp.state_dir(), LOCKS_DIR,
                        hashlib.sha256(os.fsencode(real)).hexdigest() + ".lock")


@contextlib.contextmanager
def hold(review_root, verb):
    """Hold `review_root` for `verb`, or raise `Refused`.

    A hold inside a hold, in one process, passes: `driver loop` holds the root and
    calls `driver.run` in-process. The root is let go when the outermost one ends."""
    path = lock_path(review_root)
    with _GUARD:
        entry = _HELD.get(path)
        if entry is None:
            said = {"pid": os.getpid(), "verb": verb, "host": socket.gethostname(),
                    "since": datetime.datetime.now(datetime.timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "review_root": os.path.realpath(review_root)}
            entry = _HELD[path] = [_take(path), 0, said]
            _say(entry)
        entry[1] += 1
    try:
        yield
    finally:
        with _GUARD:
            entry[1] -= 1
            if not entry[1]:
                del _HELD[path]
                _let_go(entry[0])


def descriptor(review_root):
    """The descriptor this process holds `review_root` by, or None when it holds none."""
    with _GUARD:
        entry = _HELD.get(lock_path(review_root))
        return None if entry is None else entry[0]


def note_child(review_root, pid=None, phase=None):
    """Say which phase child is running, or (no pid) that none is. A process holding no
    lock says nothing."""
    with _GUARD:
        entry = _HELD.get(lock_path(review_root))
        if entry is None:
            return
        entry[2].pop("child", None)
        if pid is not None:
            entry[2]["child"] = {"pid": pid, "phase": phase}
        _say(entry)


def _take(path):
    """An open, locked descriptor on `path`, or `Refused`. Close-on-exec, as every
    descriptor Python opens is: only a child handed it by name inherits it."""
    directory = os.path.dirname(path)
    try:
        for folder in (os.path.dirname(directory), directory):
            run_stamp._ensure_dir(folder)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except (OSError, run_stamp.KeyUnavailable) as exc:
        raise Refused(_UNUSABLE % _reason(path, exc)) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Refused(_UNUSABLE % ("%s is not a regular file" % path))
        if info.st_uid != os.getuid():
            raise Refused(_UNUSABLE % ("%s is owned by another user" % path))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused(_held_by(fd, path)) from exc
        except OSError as exc:
            raise Refused(_UNUSABLE % ("the filesystem holding %s refused the lock (%s)"
                                       % (path, exc.strerror or errno.errorcode.get(
                                           exc.errno or 0, "error")))) from exc
    except BaseException:
        os.close(fd)
        raise
    return fd


def _reason(path, exc):
    if isinstance(exc, OSError):
        return "%s: %s" % (exc.filename or path, exc.strerror or exc)
    return str(exc)


def _say(entry):
    """Write what the next driver's refusal reads. Best-effort: a record that cannot be
    written (a full disk) costs that message its detail, never the holder its run."""
    data = json.dumps(entry[2], sort_keys=True).encode("utf-8")
    try:
        os.ftruncate(entry[0], 0)
        os.pwrite(entry[0], data, 0)
    except OSError:
        pass


def _let_go(fd):
    """Close, and no more. `flock(LOCK_UN)` would unlock the open file itself, and so
    take the lock away from a phase child still holding the same one."""
    try:
        os.ftruncate(fd, 0)
    except OSError:
        pass
    finally:
        os.close(fd)


def _whole(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _running(pid):
    """Whether `pid` names a process here. For the refusal's wording only."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except (OSError, OverflowError):
        return True                       # refused, so something is there to refuse
    return True


def _held_by(fd, path):
    """The refusal for a root another process holds, from what its lock file says.
    Every field is taken by type and shape; anything else is not repeated."""
    unreadable = ("another process holds this review root, and its lock file says nothing "
                  "readable about it: `lsof %s` names it; %s" % (path, _AGAIN))
    try:
        said = json.loads(os.pread(fd, _RECORD_MAX, 0).decode("utf-8"))
    except (OSError, ValueError):
        return unreadable
    if not isinstance(said, dict):
        return unreadable
    pid, verb, since, host = (said.get(key) for key in ("pid", "verb", "since", "host"))
    if not (_whole(pid) and verb in VERBS and isinstance(since, str)
            and _SINCE.fullmatch(since) and isinstance(host, str)):
        return unreadable
    if host != socket.gethostname():      # a pid from another machine means nothing here
        if not _HOST.fullmatch(host):
            return unreadable
        return ("another driver is running on this review root (pid %d on %s, `driver %s`, "
                "since %s): %s" % (pid, host, verb, since, _AGAIN))
    if _running(pid):
        return ("another driver is running on this review root (pid %d, `driver %s`, "
                "since %s): %s" % (pid, verb, since, _AGAIN))
    gone = "a driver that is no longer running (pid %d, `driver %s`, since %s)" % (
        pid, verb, since)
    left = said.get("child")
    child, phase = (left.get(key) for key in ("pid", "phase")) if isinstance(left, dict) \
        else (None, None)
    if _whole(child) and isinstance(phase, str) and _PHASE.fullmatch(phase):
        return ("a %s child (pid %d) left by %s still holds this review root: wait for it "
                "to exit, or stop it (`kill %d`), then run again" % (phase, child, gone, child))
    return ("a process left by %s still holds this review root: `lsof %s` names it; "
            "wait for it to exit, or stop it, then run again" % (gone, path))

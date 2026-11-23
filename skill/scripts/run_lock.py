"""The run lock: one driver at a time on a review root (#3779).

`driver run`, `driver loop` and `driver setup` each read `.panopticon/`, decide, and
write. Two of them on one root decide on what the other is changing: a second driver's
`--reset` deleted the run folder under the first, and an older driver that woke after
a newer run finished set that run's report aside.

The lock is `flock` on one file per review root, held by the process for the whole
verb. The kernel lets it go when the last holder exits, so a killed driver leaves no
stale lock and nothing here guesses whether a pid is alive to decide anything.

The file lives in the operator's state directory (`run_stamp.state_dir`): a target
cannot plant, hold or delete it, first contact has nothing new to judge, and `--reset`
does not touch it. It is named by the root DIRECTORY's device and inode numbers, not by
its path. A path has more than one spelling (a link, `..`, and on a case-insensitive
volume `nongit/Proj` and `NONGIT/proj`, which `realpath` leaves apart), and two
spellings of one `.panopticon/` must be one lock. The numbers only have to agree
between processes running at the same time, which is all a lock compares. The file is
never removed, so its name always means the same inode. The state directory must be
writable: the stamp key can be read from a read-only one, the lock cannot be made there.

A phase child (`phases/child._run_child`) is handed the descriptor. It is the same
open file, so a synthesis child that outlives a killed driver still holds the root,
and a retry is refused until that child exits. Nothing else is handed it: the
descriptor is close-on-exec in the driver, and `_bootstrap.py` makes it close-on-exec
again in the child, so no scanner, shell or reviewer agent either of them starts
holds the root.

What the file SAYS (pid, verb, start, the phase child now running) is for the next
driver's refusal and for nothing else. It is read back type by type, never printed
as written, and written as one write of one size, so a driver reading while the holder
writes sees the old record or the new one.

Not covered: `driver persist`, `driver readiness` and `driver migrate-config` take no
lock, nor does an entry script run by hand (`synthesize.py`, `discovery.py`,
`devtools/replay_report.py`). Two state directories (two machines, or two users, on one
shared tree) do not exclude each other. A lock file deleted or replaced while it is
held lets a second driver in, and so does replacing the root directory itself.

Stdlib only.
"""
from __future__ import annotations

import contextlib
import datetime
import errno
import fcntl
import json
import os
import re
import shlex
import socket
import stat
import threading
from typing import Any, TypeGuard

from scripts import run_stamp

LOCKS_DIR = "locks"
#: The variable a phase child reads its inherited descriptor's number from.
FD_ENV = "PANOPTICON_RUN_LOCK_FD"
VERBS = ("run", "loop", "setup")

_SINCE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", re.ASCII)
_PHASE = re.compile(r"[a-z]{1,20}")
_HOST = re.compile(r"[A-Za-z0-9._-]{1,255}")
_RECORD_MAX = 4096
#: Every record is written at this size, padded: one write, never a truncate first.
_RECORD_SIZE = 1024

#: lock path -> [descriptor, how many holds deep, what the file says, who holds it]
_HELD: dict = {}
#: a root's path as it was given to `hold` -> its lock path, while that lock is held.
_GIVEN: dict = {}
#: Held for every change to the two tables above. A process may hold several roots on
#: several threads, and a release that iterates a table another thread is writing to
#: raises before it closes its descriptor.
_TABLE = threading.Lock()

_AGAIN = "wait for it to finish, or stop it, then run again"
_UNUSABLE = ("the run lock cannot be used: %s. `driver run`, `loop` and `setup` hold one "
             "lock file per review root under the state directory; point "
             "PANOPTICON_STATE_DIR at a directory you own and can write, on a local filesystem")


class Refused(ValueError):
    """The review root cannot be taken: another process holds it, or the lock itself
    cannot be used. The message is the whole status."""


def lock_path(review_root):
    """The lock file for the directory `review_root` names, by its device and inode: one
    directory, one lock, however its path is spelled. `OSError` when it cannot be looked at."""
    info = os.stat(review_root)
    return os.path.join(run_stamp.state_dir(), LOCKS_DIR,
                        "%x-%x.lock" % (info.st_dev, info.st_ino))


def _me():
    """Who holds: this process, on this thread. A hold inside a hold is the same one."""
    return (os.getpid(), threading.get_ident())


def _held(review_root):
    """This process's entry for `review_root`, or None when it holds none.

    By the path as it was given to `hold`, with no second look at the root: a look that
    fails must not read as "not held" and start a child without the lock its driver
    holds. Any other spelling is looked at, and that `OSError` is the caller's."""
    if not _HELD:
        return None
    path = _GIVEN.get(os.path.abspath(review_root))
    return _HELD.get(lock_path(review_root) if path is None else path)


@contextlib.contextmanager
def hold(review_root, verb):
    """Hold `review_root` for `verb`, or raise `Refused`.

    A hold inside a hold, in one process and on one thread, passes: `driver loop` holds
    the root and calls `driver.run` in-process. The root is let go when the outermost
    one ends. From any other thread, or from a forked process that inherited this
    table, the root is held by another driver.

    The descriptor is closed whatever happens to the table on the way out."""
    try:
        path = lock_path(review_root)
    except OSError as exc:
        raise Refused("the review root cannot be locked: %s" % _reason(review_root, exc)) from exc
    given = os.path.abspath(review_root)
    with _TABLE:
        entry = _HELD.get(path)
        if entry is not None and entry[3] != _me():
            raise Refused(_held_by(entry[0], path))
        if entry is None:
            said = {"pid": os.getpid(), "verb": verb, "host": socket.gethostname(),
                    "since": datetime.datetime.now(datetime.timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:%SZ")}
            entry = [_take(path), 0, said, _me()]
            _HELD[path] = entry
            _say(entry)
        entry[1] += 1
        _GIVEN[given] = path
    try:
        yield
    finally:
        entry[1] -= 1
        try:
            with _TABLE:
                if not entry[1]:
                    _HELD.pop(path, None)
                    for spelled in [key for key, value in _GIVEN.items() if value == path]:
                        _GIVEN.pop(spelled, None)
        finally:
            if not entry[1]:
                _let_go(entry[0])


def descriptor(review_root):
    """The descriptor this process holds `review_root` by, or None when it holds none.
    `Refused` when that cannot be told: the caller starts no child on a guess."""
    try:
        entry = _held(review_root)
    except OSError as exc:
        raise Refused("the run lock for %s could not be checked: %s"
                      % (review_root, exc.strerror or exc)) from exc
    return None if entry is None else entry[0]


def note_child(review_root, pid=None, phase=None):
    """Say which phase child is running, or (no pid) that none is. Best-effort, like the
    record itself: a process holding no lock, or a root that cannot be matched to one,
    says nothing."""
    try:
        entry = _held(review_root)
    except OSError:
        return
    if entry is None:
        return
    entry[2].pop("child", None)
    if pid is not None:
        entry[2]["child"] = {"pid": pid, "phase": phase}
    _say(entry)


def _take(path):
    """An open, locked descriptor on `path`, or `Refused`. Close-on-exec, as every
    descriptor Python opens is: only a child handed it by name inherits it.

    Never 0, 1 or 2. A driver started with a standard stream closed is given that number
    by `os.open`, and a child's own redirection then replaces it: the child was handed a
    pipe for a lock. Moved above them before it is locked."""
    directory = os.path.dirname(path)
    try:
        for folder in (os.path.dirname(directory), directory):
            run_stamp._ensure_dir(folder)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        if fd <= 2:
            low = fd
            try:
                fd = fcntl.fcntl(low, fcntl.F_DUPFD_CLOEXEC, 3)
            finally:
                os.close(low)
    except (OSError, run_stamp.KeyUnavailable) as exc:
        raise Refused(_UNUSABLE % _reason(path, exc)) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Refused(_UNUSABLE % ("%s is not a regular file" % path))
        if info.st_uid != os.getuid():
            raise Refused(_UNUSABLE % ("%s is owned by another user" % path))
        if info.st_nlink != 1:            # a hard link: the record would be written over it
            raise Refused(_UNUSABLE % ("%s has more than one name" % path))
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
    """Write what the next driver's refusal reads: one write, always `_RECORD_SIZE`
    bytes (JSON, then spaces), so a reader sees the record before or the record after
    and never an empty or half-replaced file. A record too long for that says nothing.
    Best-effort: a record that cannot be written (a full disk) costs that message its
    detail, never the holder its run. The file is then emptied, so the next driver's
    refusal does not name a pid out of an earlier holder's record."""
    data = json.dumps(entry[2], sort_keys=True).encode("utf-8")
    if len(data) > _RECORD_SIZE:
        data = b""
    try:
        os.pwrite(entry[0], data.ljust(_RECORD_SIZE), 0)
    except OSError:
        try:                              # never the record of whoever held it before
            os.ftruncate(entry[0], 0)
        except OSError:
            pass


def _let_go(fd):
    """Close, and no more. `flock(LOCK_UN)` would unlock the open file itself, and so
    take the lock away from a phase child still holding the same one. Best-effort: the
    verb has finished, and a close that fails must not turn its status into a traceback."""
    for release in (lambda: os.ftruncate(fd, 0), lambda: os.close(fd)):
        try:
            release()
        except OSError:
            pass


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
                  "readable about it: `lsof %s` names it; %s" % (shlex.quote(path), _AGAIN))
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
    left = said.get("child")
    child, phase = (left.get(key) for key in ("pid", "phase")) if isinstance(left, dict) \
        else (None, None)
    # Named only while it runs: a record update that failed leaves the child before it.
    kid: int | None = None
    if (_whole(child) and isinstance(phase, str) and _PHASE.fullmatch(phase)
            and _running(child)):
        kid = child
    if _running(pid):
        its = "; its %s child is pid %d" % (phase, kid) if kid is not None else ""
        return ("another driver is running on this review root (pid %d, `driver %s`, "
                "since %s%s): %s" % (pid, verb, since, its, _AGAIN))
    gone = "a driver that is no longer running (pid %d, `driver %s`, since %s)" % (
        pid, verb, since)
    if kid is not None:
        return ("a %s child (pid %d) left by %s still holds this review root: wait for it "
                "to exit, or stop it (`kill %d`), then run again" % (phase, kid, gone, kid))
    return ("a process left by %s still holds this review root: `lsof %s` names it; "
            "wait for it to exit, or stop it, then run again" % (gone, shlex.quote(path)))

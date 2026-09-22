"""One kill path, for every child this repo spawns (#1575).

Two existed. `phases/child.py` ended a timed-out PHASE child by signalling its
whole process group; `runners/base.py` ended a registered HOST child by
calling `terminate()` and then `kill()` on the handle. A tree has whichever
guarantee the caller happened to use, so the weaker one was the real one: a
host CLI that spawns its own workers -- every one of the three shipped
families does -- outlived both a family-side timeout and an operator's Ctrl-C,
because the signal reached the direct pid only.

So the group kill lives HERE, in one stdlib-only module that neither package
owns, and both sides call it. `runners/` may not import `scripts.phases`
(tests/test_layout.py rule 3), which is why this is a top-level module rather
than a fourth function in `phases/child.py`.

Three entry points, because the two callers need different shapes of the same
thing:

* `kill_group(proc, grace)` -- the whole sequence for ONE child: SIGTERM to
  its group, `grace` to exit, then SIGKILL. What a timeout wants.
* `end_group(proc, sig)` + `reaped(proc, timeout)` -- the same sequence taken
  apart, so a caller with SEVERAL children can signal them all before waiting
  on any of them. What an interrupt wants: `HostRunner.terminate_children`
  bounds a Ctrl-C by ONE shared grace window, not one window per child.

Nothing here raises. Every one of these calls is made on a path that is
already handling a failure -- a deadline that passed, an operator who pressed
Ctrl-C -- and an exception out of the kill would replace a bounded stop with
a traceback.
"""
import os
import signal

# How long a group is given to exit on SIGTERM before SIGKILL. Short on
# purpose: the deadline that brought us here has already passed. Moved
# verbatim from `phases/child.py:_KILL_GRACE`, semantics included.
KILL_GRACE = 2.0


def _pgid(proc):
    """`proc`'s process group id, or None when there is no group to signal.

    None covers three cases that the caller must treat identically: a handle
    with no `pid` at all (what `HostRunner.register_child` accepts, and what
    the suite's fakes are), a child already reaped, and a platform without
    process groups.
    """
    try:
        return os.getpgid(proc.pid)
    except (AttributeError, OSError):
        return None


def end_group(proc, sig):
    """Send `sig` to `proc`'s whole process group, and wait for nothing.

    The child is spawned with `start_new_session=True` by both callers, so its
    pid IS its group id and one `killpg` reaches every process it started --
    the scanner's workers, the host CLI's helpers -- rather than the one pid
    at the root of the tree.

    With no group to reach, it falls back to the HANDLE: `terminate()` for a
    SIGTERM, `kill()` for a SIGKILL. That fallback is what a non-POSIX
    platform gets, and it is also the pre-#1575 behaviour of
    `HostRunner.terminate_children` -- a bare handle keeps exactly the
    treatment it had, rather than being skipped for want of a pid.
    """
    pgid = _pgid(proc)
    if pgid is not None:
        try:
            os.killpg(pgid, sig)
            return
        except (AttributeError, OSError):    # gone between getpgid and killpg
            return
    handler = proc.kill if sig == signal.SIGKILL else proc.terminate
    try:
        handler()
    except (OSError, ValueError):            # already gone, or a closed handle
        pass


def reaped(proc, timeout):
    """True once `proc` has exited, waiting at most `timeout` seconds for it.

    False means "still running, or a handle that cannot answer" -- the caller
    escalates either way, so the two are deliberately one answer. `timeout` is
    clamped at zero: a shared deadline that has already passed is a poll, not
    a negative wait (which `Popen.wait` reads as "forever").
    """
    try:
        proc.wait(timeout=max(0.0, float(timeout)))
        return True
    except Exception:            # noqa: BLE001 - TimeoutExpired, or a deaf handle
        return False


def kill_group(proc, grace=KILL_GRACE):
    """End a child's whole PROCESS GROUP: SIGTERM, `grace`, then SIGKILL.

    `proc.kill()` reaches the direct child only. A phase child that forked a
    worker -- `run_tools.py` launching a scanner, a scanner launching its own
    workers -- left that worker alive holding the stdout pipe it inherited, so
    the reader never saw EOF and the descendant went on running after the
    driver had already reported the phase timed out. That is not "no timeout";
    it is a nominal deadline that bounds one process out of a tree.

    SIGTERM first, so a scanner can flush and unlink its temp files, then
    SIGKILL once the grace window passes. A group that is already gone is
    success, not an error.

    Returns whether the child was reaped. The final wait is BOUNDED rather
    than unconditional: a descendant that escaped the group (one that called
    `setsid` itself) cannot be signalled, and a caller on a deadline path must
    not be made to wait for it for ever. An unreaped child is left to
    `Popen.__del__`, which is a warning; an unbounded wait was the hang.
    """
    for sig in (signal.SIGTERM, signal.SIGKILL):
        end_group(proc, sig)
        if reaped(proc, grace):
            return True
    return reaped(proc, grace)

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
* `group_id(proc)` + `end_group(proc, sig, pgid)` + `reaped(proc, timeout)` --
  the same sequence taken apart, so a caller with SEVERAL children can retain
  their groups, signal them all, then wait. What an interrupt wants:
  `HostRunner.terminate_children` bounds a Ctrl-C by ONE shared grace window,
  not one window per child.

Nothing in that kill path raises. Every one of these calls is made on a path
that is already handling a failure -- a deadline that passed, an operator who
pressed Ctrl-C -- and an exception out of the kill would replace a bounded
stop with a traceback.

And one way INTO that path, for the signal that used to skip it (#2199):
`sigterm_as_interrupt(main)` runs the driver's CLI with a SIGTERM raised as
the interrupt a Ctrl-C raises, so a supervisor's stop reaches the same kills.
"""
import os
import signal
import sys
import time

# How long a group is given to exit on SIGTERM before SIGKILL. Short on
# purpose: the deadline that brought us here has already passed. Moved
# verbatim from `phases/child.py:_KILL_GRACE`, semantics included.
KILL_GRACE = 2.0


def _pgid(proc):
    """`proc`'s process group id, or None when there is no group to signal
    -- in which case the caller signals the HANDLE instead.

    None covers four cases that the caller must treat identically:

    * a handle with no `pid` at all (what `HostRunner.register_child` accepts,
      and what the suite's fakes are), or a platform without process groups;
    * a child this process has already REAPED. Its pid went back to the OS,
      and pids are handed out in order, so that number may already name
      somebody else's session leader -- `killpg` on it would end their whole
      tree. `Popen.send_signal` has always been immune (it returns early once
      `returncode` is set) and the group kill has to make the same check
      BEFORE it asks the OS what group that pid is in. The window is real:
      `launch` reaps in `communicate` and unregisters a moment later, and an
      interrupt can arrive in between;
    * a child in OUR OWN process group -- anything registered by a caller
      that did not pass `start_new_session=True`. `killpg` there is a signal
      to the driver itself and to every sibling sharing its group; measured
      while writing this guard, it SIGTERMed the test runner.

    `returncode` is read with `getattr`: a registered handle need not be a
    `Popen`, and one that does not carry the attribute has no pid of ours to
    protect.
    """
    if getattr(proc, "returncode", None) is not None:
        return None                        # reaped: the pid may be somebody else's
    try:
        pid = proc.pid
        pgid = os.getpgid(pid)
    except AttributeError:
        return None
    except OSError:
        # Darwin reports ESRCH for an unreaped session leader after it exits,
        # even while descendants keep the group alive. The caller created the
        # session, so its retained pid is the group id until it is reaped.
        try:
            pgid = pid
            os.killpg(pgid, 0)
        except (AttributeError, OSError, TypeError, ValueError):
            return None
    try:
        if pgid == os.getpgid(0):
            return None                    # our own group: signal the handle
    except (AttributeError, OSError):      # pragma: no cover - no process groups
        return None
    return pgid


def _end_group(proc, sig, pgid):
    """Send one signal, retaining an already validated group id when supplied."""
    if pgid is not None:
        try:
            os.killpg(pgid, sig)
            return True
        except ProcessLookupError:
            return False
        except (AttributeError, OSError):
            pass
    handler = proc.kill if sig == signal.SIGKILL else proc.terminate
    try:
        handler()
    except (OSError, ValueError):
        pass
    return False


def _group_exists(pgid):
    """Whether a retained process group still has a signalable member."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except (AttributeError, OSError):
        return True
    return True


def _leader_exited_unreaped(proc):
    """Observe an exited child without releasing its pid or process-group id."""
    waitid = getattr(os, "waitid", None)
    if waitid is None:
        return False
    try:
        result = waitid(
            getattr(os, "P_PID"), proc.pid,
            getattr(os, "WEXITED") | getattr(os, "WNOHANG")
            | getattr(os, "WNOWAIT"))
    except (AttributeError, ChildProcessError, OSError, TypeError, ValueError):
        return False
    return bool(result and getattr(result, "si_pid", 0))


def group_id(proc):
    """Return `proc`'s validated group id for a caller that must retain it."""
    return _pgid(proc)


def end_group(proc, sig, pgid=None):
    """Send `sig` to `proc`'s retained or current group, and wait for nothing.

    The child is spawned with `start_new_session=True` by both callers, so its
    pid IS its group id and one `killpg` reaches every process it started --
    the scanner's workers, the host CLI's helpers -- rather than the one pid
    at the root of the tree.

    With no group to reach -- see `_pgid` for the four ways that happens --
    it falls back to the HANDLE: `terminate()` for a SIGTERM, `kill()` for a
    SIGKILL. That fallback is what a non-POSIX platform gets, and it is also
    the pre-#1575 behaviour of `HostRunner.terminate_children` -- a bare
    handle keeps exactly the treatment it had, rather than being skipped for
    want of a pid -- and it is recycle-safe, because `Popen.send_signal`
    refuses a handle whose `returncode` is set.
    """
    _end_group(proc, sig, pgid if pgid is not None else _pgid(proc))


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

    SIGTERM first, so a scanner can flush and unlink its temp files. SIGKILL
    follows when the GROUP's grace passes, or immediately when its leader has
    already exited. The leader stays unreaped until that decision: its pid
    cannot be recycled, and the retained group id still reaches a descendant
    that ignored SIGTERM.

    Returns whether the child was reaped. The final wait is BOUNDED rather
    than unconditional: a descendant that escaped the group (one that called
    `setsid` itself) cannot be signalled, and a caller on a deadline path must
    not be made to wait for it for ever. An unreaped child is left to
    `Popen.__del__`, which is a warning; an unbounded wait was the hang.
    """
    try:
        grace = max(0.0, float(grace))
    except (TypeError, ValueError):
        grace = 0.0
    pgid = _pgid(proc)
    group_signalled = _end_group(proc, signal.SIGTERM, pgid)
    if pgid is not None and group_signalled:
        deadline = time.monotonic() + grace
        while (_group_exists(pgid) and not _leader_exited_unreaped(proc)
               and time.monotonic() < deadline):
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        retained = pgid if getattr(proc, "returncode", None) is None else None
        if _group_exists(pgid):
            _end_group(proc, signal.SIGKILL, retained)
        return reaped(proc, grace)
    if reaped(proc, grace):
        return True
    end_group(proc, signal.SIGKILL)
    return reaped(proc, grace)


class Terminated(KeyboardInterrupt):
    """A SIGTERM, raised as the interrupt a Ctrl-C raises (#2199).

    A subclass, so every handler that routes a Ctrl-C routes this unchanged:
    `_run_child`'s group kill, `iter_batch`'s `terminate_children`,
    `orchestrate.loop`'s rollback and teardown. Its own type, so that
    `sigterm_as_interrupt` can tell it from a real Ctrl-C when it escapes.
    """


def sigterm_as_interrupt(main):
    """Run `main()` with a SIGTERM raising `Terminated` in the main thread,
    and return what `main` returns (#2199).

    At the default disposition a SIGTERM -- a supervisor's stop, a CI
    cancel, a plain `kill` -- ended the driver without running one `except`
    or `finally`. The phase child and the runner children lead their own
    sessions, so no signal to the driver's group reached them, and they were
    left running. Raised as the interrupt instead, a SIGTERM takes the path a
    Ctrl-C takes, and that path ends them first.

    Only the FIRST SIGTERM raises. Every later one is absorbed until `main`
    returns: the kills that path is waiting on escalate to SIGKILL only after
    `reaped`, which catches `Exception` and not an interrupt, so a second
    raise would cut them short and leave a child that ignores SIGTERM
    running. SIGKILL still stops the driver outright, and a Ctrl-C still
    raises every time. Once `main` returns, the disposition it replaced is
    back, so a SIGTERM during the interpreter's own exit does what it always
    did.

    A `Terminated` that escapes `main` stops here, with one line on stderr --
    `driver: stopped by SIGTERM` -- and 143 (128 + SIGTERM) as the status.
    Left to the interpreter it would not leave the same way on every
    supported Python: an escaping KeyboardInterrupt SUBCLASS exits 1 with a
    traceback before 3.14 and dies by SIGINT from 3.14 on. Where
    `orchestrate.loop` catches the interrupt, it still rolls back and
    returns its own status; this is for the interrupts nothing caught. A
    real Ctrl-C -- `KeyboardInterrupt` itself -- is not caught here and
    escapes exactly as before.

    Installed only over the DEFAULT disposition, Python's own rule for
    SIGINT: a parent that set SIGTERM to be ignored meant it, and a handler
    already there is somebody else's. `driver.py` calls this from its
    `__main__` block and never at import, because the suite imports the
    driver and must keep its default dispositions.
    """
    if signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL:
        return main()
    raised: list[int] = []

    def interrupt(signum, frame):
        if not raised:
            raised.append(signum)
            raise Terminated("SIGTERM")

    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        return main()
    except Terminated:
        print("driver: stopped by SIGTERM", file=sys.stderr, flush=True)
        return 128 + signal.SIGTERM
    finally:
        signal.signal(signal.SIGTERM, previous)

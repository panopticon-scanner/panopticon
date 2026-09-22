"""The runner seam's children: how a family starts one, and how one is ended.

Split out of `runners/base.py` (which owns the rest of the seam contract) when
the group-aware launch would have pushed that module past the 700-line ratchet
`tests/test_layout.py` holds it to. One subject, one module: a host CLI is
spawned HERE, registered HERE while it runs, and ended HERE -- by the same
`scripts.procgroup` kill path `phases/child.py` uses for the driver's own
children.

`ChildProcesses` is a mixin rather than a second base class with state of its
own, and everything it keeps lives in `self.__dict__` under one key: a family
(and several fakes in this suite) may define its own `__init__` without
chaining to `HostRunner`'s, and a registry that exists only when somebody
remembered to call `super()` is a registry that silently holds nothing on the
one host that needed it.

#1575. Before this, the three shipped families each called `subprocess.run`
directly. That is a blocking call which hands back no handle at all, so:

* nothing was registered, and `terminate_children` was a no-op for every
  shipped host -- an operator's Ctrl-C reached a child only because the
  terminal SIGINTs the whole foreground process group, and a child that had
  left that group (or a run driven from anything but a terminal) was missed;
* the entry timeout killed the DIRECT pid. Every one of these CLIs spawns its
  own workers, so the workers went on running -- and charging -- after the
  entry had been ledgered as timed out.
"""
import signal
import subprocess
import time

import scripts.procgroup as procgroup

# How long a timed-out launch's group is given to drain its pipes once it has
# been killed, before the launcher gives up and reports what it has.
#
# The second `communicate()` after the kill is what recovers the partial
# output `subprocess.run` recovers internally -- but a descendant that escaped
# the group (one that called `setsid` itself) still holds the write end of the
# pipes, so EOF never arrives and that second call would block for ever. Short,
# because the entry deadline has already passed and the head of the stream is
# the whole of the diagnostic.
PARTIAL_OUTPUT_GRACE = 2.0


class ChildProcesses:
    """Launching, registering and ending one host CLI's children."""

    # #1662: how long a terminated child is given to exit before it is killed,
    # and the bound on how long an INTERRUPTED batch waits for the workers
    # that were holding those children. Short on purpose -- a Ctrl-C means
    # stop, and the operator is watching a terminal.
    INTERRUPT_GRACE = 5.0

    def launcher(self, *candidates):
        """The callable a launch goes through: the first of `candidates` that
        is not None, and otherwise this runner's own `launch`.

        The ONE place the seam's resolution order is written down, so the
        three families spell it identically. Each of them passes what it has,
        in priority order: an injected `runner=` (a fake, in every test that
        does not mean to spawn anything), then the module's `DEFAULT_RUNNER`
        -- which tests/conftest.py swaps for a refusal across the whole suite,
        and which ships as None precisely so that an un-injected runner in a
        REAL run falls through to the last candidate: `launch`.

        Kept as a method rather than a module function because the fallback is
        bound to THIS instance: `launch` registers its child on the runner
        whose `terminate_children` an interrupt will call.
        """
        for candidate in candidates:
            if candidate is not None:
                return candidate
        return self.launch

    def launch(self, argv, *, input=None, cwd=None, env=None, timeout=None,
               text=True, capture_output=True):
        """Run `argv` to completion and return its `CompletedProcess`.

        The seam's own launcher: `subprocess.run`-SHAPED on purpose, keyword
        for keyword, because it stands in for `subprocess.run` at every family
        launch site and at every fake those sites are tested with. What it
        adds is the three things `subprocess.run` cannot do:

        * `start_new_session=True`, so the child leads its own process group
          and one signal reaches everything it started;
        * `register_child` BEFORE the wait and `unregister_child` after it, so
          an interrupt arriving mid-launch can reach this child -- and so a
          child that has already finished is NOT signalled later at a pid the
          OS may by then have handed to somebody else;
        * `procgroup.kill_group` on the timeout, which is the whole point:
          `subprocess.run` kills the direct pid and leaves the workers.

        The `TimeoutExpired` it raises is the one every family's existing
        `except subprocess.TimeoutExpired` clause already reads -- same type,
        carrying the same partial `output`/`stderr` (D10 ruling 5) -- so no
        family's failure path changes. It is RE-RAISED rather than passed
        through because the partial streams are recovered after the kill: on
        POSIX `communicate` populates the first exception with whatever it had
        read as UNDECODED bytes, and a second `communicate()` once the group
        is dead returns the complete, decoded streams instead.

        `capture_output` exists for signature parity and must be true: both
        streams are always piped, because the parsers downstream read both and
        an un-piped stream would go to the operator's terminal mid-run.
        """
        if not capture_output:
            raise ValueError("HostRunner.launch always captures both streams")
        proc = subprocess.Popen(                       # noqa: S603 - argv, never a shell
            argv, cwd=cwd, env=env,
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=text, start_new_session=True)
        self.register_child(proc)
        try:
            try:
                out, err = proc.communicate(input, timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                procgroup.kill_group(proc)
                out, err = self._drain(proc, exc)
                raise subprocess.TimeoutExpired(
                    argv, timeout, output=out, stderr=err) from None
        finally:
            self.unregister_child(proc)
        return subprocess.CompletedProcess(argv, proc.returncode, out, err)

    @staticmethod
    def _drain(proc, timed_out):
        """What the killed child had printed, as completely as it can be had.

        `communicate()` accumulates across calls, so the second one returns
        the first one's partial read plus whatever arrived before the kill --
        decoded, which the exception's own `stdout`/`stderr` are not. If even
        that cannot finish (a descendant outside the group is holding the
        pipes), the undecoded partials the first exception carries are the
        answer: `base.partial_output` and `base.stderr_head` both accept
        bytes, and a truncated diagnostic beats none.
        """
        try:
            return proc.communicate(timeout=PARTIAL_OUTPUT_GRACE)
        except Exception:            # noqa: BLE001 - a second timeout, or closed pipes
            return timed_out.stdout, timed_out.stderr

    def register_child(self, proc):
        """Record a live child, so a Ctrl-C can end it (#1662).

        `proc` is anything `subprocess.Popen`-shaped -- `pid`, `terminate()`,
        `kill()`, `wait(timeout=)` are all this seam uses, and a handle
        without a `pid` still gets the terminate/kill path (`procgroup`).

        Stored on the INSTANCE dict lazily rather than in `__init__` for the
        reason in this module's docstring. `setdefault` and `append` are each
        atomic under the GIL, which is all the synchronising a list appended
        to from the pool's workers and read from the main thread needs.
        """
        self.__dict__.setdefault("_children", []).append(proc)

    def unregister_child(self, proc):
        """Forget a child that has finished, for the same reason
        `terminate_children` empties the registry as it reads it: a pid the
        OS has reused must never be signalled by this run's interrupt path.

        Silent when the child is not there -- an interrupt may already have
        taken the whole registry, and the launch that is returning must not
        turn that race into an exception on its way out.
        """
        children = self.__dict__.get("_children")
        if not children:
            return
        try:
            children.remove(proc)
        except ValueError:           # already emptied by terminate_children
            pass

    def terminate_children(self, grace=None):
        """End every child this runner still has in flight -- SIGTERM to each
        one's whole PROCESS GROUP, then SIGKILL to whatever has not exited
        within `grace` -- and return the children it acted on (#1662).

        Called by `iter_batch` on the interrupt path, before the loop tears
        the guard files down. It installs NO signal handler and replaces none:
        `runners/kimi.py` chains a SIGTERM secret-stripper onto whatever was
        already registered, and an interrupt path that installed its own would
        unlink that chain. The registry is EMPTIED as it is read, so a second
        call is a no-op rather than a second kill at a pid the OS may since
        have reused.

        #1575: the GROUP, not the handle. A host CLI spawns its own workers,
        so `terminate()` on the pid the runner holds left them running. The
        two phases are kept apart -- every child is signalled before any child
        is waited on -- so `grace` stays ONE shared window for the batch, which
        is what `INTERRUPT_GRACE` promises; `procgroup.kill_group` would spend
        it once per child.
        """
        grace = self.INTERRUPT_GRACE if grace is None else grace
        children = list(self.__dict__.get("_children") or ())
        self.__dict__["_children"] = []
        for proc in children:
            procgroup.end_group(proc, signal.SIGTERM)
        deadline = time.monotonic() + max(0.0, float(grace))
        for proc in children:
            if not procgroup.reaped(proc, deadline - time.monotonic()):
                procgroup.end_group(proc, signal.SIGKILL)
        return children

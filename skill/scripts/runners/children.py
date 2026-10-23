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
import locale
import os
import signal
import subprocess
import threading
import time

import scripts.executable as executable
import scripts.procgroup as procgroup
import scripts.tools.base as tools_base

# How long a timed-out launch's group is given to drain its pipes once it has
# been killed, before the launcher gives up and reports what it has.
#
# The readers are given this long after the kill to collect the partial output
# `subprocess.run` recovers internally -- but a descendant that escaped the
# group (one that called `setsid` itself) still holds the write end of the
# pipes, so EOF never arrives and an unbounded wait would block for ever. Short,
# because the entry deadline has already passed and the head of the stream is
# the whole of the diagnostic.
PARTIAL_OUTPUT_GRACE = 2.0

# #3246: what a launch keeps of a host CLI's streams -- the scanner runner's own
# two caps, not a second pair. Codex `exec --json` and Kimi `stream-json` echo
# tool results, so a hostile target can steer a reviewer into printing whole
# files; 8 launches run at once, and `communicate()` kept every byte of each.
STDOUT_CAP = tools_base.MAX_TOOL_OUTPUT_BYTES
STDERR_CAP = tools_base.MAX_TOOL_STDERR_BYTES


class HostOutputExceeded(RuntimeError):
    """A host CLI printed more than `STDOUT_CAP` bytes on stdout (#3246).

    Raised AFTER its group is ended. Every family's `except Exception` turns it
    into a failed entry, so the retained prefix is never parsed as a reply; it
    rides on `output` (and the stderr tail on `stderr`) for a caller that wants
    the evidence."""

    def __init__(self, argv, cap, output=None, stderr=None):
        super().__init__("%s printed more than %d bytes on stdout; the launch was "
                         "stopped and its reply refused" % (os.path.basename(str(argv[0])), cap))
        self.output, self.stderr = output, stderr


def _feed(stream, data):
    """Write the prompt and close stdin. A CLI that exits or closes stdin early
    is not an error here (EPIPE): its exit code and stdout decide (#3246)."""
    try:
        view = memoryview(data or b"")
        while view:                          # a raw pipe may take part of a write
            view = view[stream.write(view) or 0:]
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            pass


class _Capture:
    """`communicate`, bounded (#3246): stdin fed on a thread, stderr drained to
    a tail on a thread (`tools_base.drain_stderr_async`), stdout read up to the
    cap on a thread (`tools_base.read_capped`) -- and the WAIT stays on the
    caller's thread with a deadline, as `communicate`'s did, so no timer exists
    that could fire late at a recycled group."""

    def __init__(self, proc, data):
        self.proc, self.chunks, self.capped = proc, [], False
        self.feeder = None
        if proc.stdin is not None:
            self.feeder = threading.Thread(target=_feed, args=(proc.stdin, data), daemon=True)
            self.feeder.start()
        self.join_stderr = tools_base.drain_stderr_async(proc, cap=STDERR_CAP)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        try:
            self.capped = tools_base.read_capped(self.proc.stdout, STDOUT_CAP, self.chunks)
        except (OSError, ValueError):       # the pipe was closed under us
            pass

    def wait(self, timeout):
        """"done", "capped" or "timeout"; on "done" the child has exited."""
        deadline = None if timeout is None else time.monotonic() + timeout
        self.reader.join(timeout)
        if self.reader.is_alive():
            return "timeout"
        if self.capped:
            return "capped"
        try:
            self.proc.wait(None if deadline is None else max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            return "timeout"
        return "done"

    def streams(self, grace):
        """(stdout bytes, stderr tail bytes), waiting at most `grace` for each."""
        self.reader.join(grace)
        return b"".join(list(self.chunks)), self.join_stderr(grace)


def _text(data, encoding, errors="strict"):
    """Decode as `Popen(text=True)` does: the locale encoding, universal newlines."""
    return data.decode(encoding, errors).replace("\r\n", "\n").replace("\r", "\n")


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

        Any OTHER exception out of the wait ends the group too, and then
        propagates untouched -- `subprocess.run`'s own bare
        `except BaseException: process.kill(); raise`, with the group kill in
        place of the pid kill. The three pipes are closed in the `finally`
        whichever way the launch ended; see the note there for why that is
        written out rather than delegated to `with proc:`.

        The `TimeoutExpired` it raises is the one every family's existing
        `except subprocess.TimeoutExpired` clause already reads -- same type,
        carrying the same partial `output`/`stderr` (D10 ruling 5) -- so no
        family's failure path changes. The partial streams are collected after
        the kill, decoded with `errors="replace"` (a cut can split a character).

        #3246: the wait is `_Capture`, `communicate` bounded. stdout past
        `STDOUT_CAP` ends the group and raises `HostOutputExceeded`, which every
        family's `except Exception` turns into a failed entry; stderr keeps its
        last `STDERR_CAP` bytes.

        `capture_output` exists for signature parity and must be true: both
        streams are always piped, because the parsers downstream read both and
        an un-piped stream would go to the operator's terminal mid-run.
        """
        if not capture_output:
            raise ValueError("HostRunner.launch always captures both streams")
        requested_argv = list(argv)
        child_env = executable.sanitize_startup_environment(
            os.environ if env is None else env)
        # `review_root` is bound by every family in prepare(). Probes can run
        # before prepare, so their explicit cwd (or this process's cwd) is the
        # conservative root rather than silently dropping provenance checks.
        review_root = (getattr(self, "review_root", None) or cwd or os.getcwd())
        resolved = executable.resolve(requested_argv[0], review_root,
                                      child_env.get("PATH", ""))
        child_env["PATH"] = resolved.path_env
        launch_argv = [resolved.path] + requested_argv[1:]
        encoding = locale.getpreferredencoding(False)
        data = input.encode(encoding) if text and isinstance(input, str) else input
        proc = subprocess.Popen(                       # noqa: S603 - argv, never a shell
            launch_argv, cwd=cwd, env=child_env,
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            # Unbuffered: closing a RAW pipe in the `finally` takes no lock, so a
            # reader still blocked on it (a descendant outside the group holds
            # the write end) cannot hang the launch; its next read sees it closed.
            bufsize=0)
        try:
            # Inside the try (#3250): a registration refused because the runner
            # is shutting down has already ended the child, and its pipes still
            # go back in the `finally` below.
            self.register_child(proc)
            try:
                capture = _Capture(proc, data)
                outcome = capture.wait(timeout)
                if outcome != "done":
                    procgroup.kill_group(proc)
                    out, err = capture.streams(PARTIAL_OUTPUT_GRACE)
                    if outcome == "capped":
                        raise HostOutputExceeded(requested_argv, STDOUT_CAP, out, err)
                    if text:
                        out, err = _text(out, encoding, "replace"), _text(err, encoding, "replace")
                    raise subprocess.TimeoutExpired(requested_argv, timeout, output=out, stderr=err)
                out, err = capture.streams(PARTIAL_OUTPUT_GRACE)
                if text:
                    out, err = _text(out, encoding), _text(err, encoding)
            except (subprocess.TimeoutExpired, HostOutputExceeded):
                raise
            except BaseException:
                # The timeout is not the only way out. A Ctrl-C on one of
                # the MAIN-THREAD launches (`prove_output_schema_shape`,
                # `probes/common._cli_help`, codex_host's catalog and
                # surface probes), a MemoryError, a bug in this method:
                # each one used to leave a host CLI and its whole worker
                # tree running, with nobody holding a handle to it.
                # `subprocess.run` has had this clause since it was
                # written; it is the reason `run` never leaked a child.
                procgroup.kill_group(proc)
                raise
        finally:
            self.unregister_child(proc)
            # The three descriptors go back however this ended -- a loop that
            # leaks three per failed entry runs out of them. Explicitly, and
            # NOT by running the launch inside `with proc:`: `Popen.__exit__`
            # closes these same three and then makes a bare, UNBOUNDED
            # `self.wait()` for every exit but `KeyboardInterrupt`. That wait
            # lands immediately after `kill_group`, whose own final wait is
            # bounded precisely because a child can survive the kill
            # (uninterruptible I/O; EPERM from a child that changed
            # privilege) -- so the context manager turned a bounded entry
            # timeout into a driver that never returns. Measured at 8 s and
            # still going. Zombies are not the price: `_Capture.wait` reaps on
            # the way out of the success path, and `kill_group`'s bounded
            # `reaped()` does it on every failure path.
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:         # already closed by a reader
                        pass
        return subprocess.CompletedProcess(requested_argv, proc.returncode, out, err)

    def register_child(self, proc):
        """Record a live child, so a Ctrl-C can end it (#1662).

        `proc` is anything `subprocess.Popen`-shaped -- `pid`, `terminate()`,
        `kill()`, `wait(timeout=)` are all this seam uses, and a handle
        without a `pid` still gets the terminate/kill path (`procgroup`).

        Stored on the INSTANCE dict lazily rather than in `__init__` for the
        reason in this module's docstring.

        #3250: under the registry lock, and REFUSED once `terminate_children`
        has run. Without the lock an append could land on the list
        `terminate_children` had just copied and was about to replace, and a
        worker whose `Popen` returned after the terminate registered into the
        fresh list nobody would read: either way a child outlived the guards.
        A refused child is ended here (`procgroup.kill_group`) and the launch
        fails the normal way, with a RuntimeError.

        APPEND, then check: kimi's SIGTERM stripper calls `terminate_children`
        from a signal handler on the main thread, which also launches -- so the
        lock is re-entrant, and a terminate that runs in the middle of this
        either finds the child in the list it takes or leaves `closed` set for
        the check. Removal is if-present: that terminate has swapped the list.
        """
        with self._registry_lock():
            self.__dict__.setdefault("_children", []).append(proc)
            closed = self.__dict__.get("_children_closed", False)
            if closed:
                self.__dict__["_children"] = [c for c in self.__dict__["_children"]
                                              if c is not proc]
        if closed:
            procgroup.kill_group(proc)
            raise RuntimeError("runner is shutting down; launch refused")

    def _registry_lock(self):
        """The one lock over `_children` and `_children_closed`, created lazily
        on the instance dict; `dict.setdefault` is atomic, so two first callers
        cannot make two locks. Re-entrant, for the signal path above."""
        return self.__dict__.setdefault("_children_lock", threading.RLock())

    def unregister_child(self, proc):
        """Forget a child that has finished, for the same reason
        `terminate_children` empties the registry as it reads it: a pid the
        OS has reused must never be signalled by this run's interrupt path.

        Silent when the child is not there -- an interrupt may already have
        taken the whole registry, and the launch that is returning must not
        turn that race into an exception on its way out.
        """
        with self._registry_lock():
            children = self.__dict__.get("_children")
            if not children:
                return
            try:
                children.remove(proc)
            except ValueError:       # already emptied by terminate_children
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

        #3250: it also CLOSES the registry, for good. A run drives one batch
        and launches nothing after its terminate, so every later
        `register_child` is a launch racing the shutdown and is refused.
        """
        grace = self.INTERRUPT_GRACE if grace is None else grace
        with self._registry_lock():           # #3250: closed, then taken, as one step
            self.__dict__["_children_closed"] = True
            children = list(self.__dict__.get("_children") or ())
            self.__dict__["_children"] = []
        groups = [(proc, procgroup.group_id(proc)) for proc in children]
        for proc, pgid in groups:
            procgroup.end_group_retained(proc, signal.SIGTERM, pgid)
        deadline = time.monotonic() + max(0.0, float(grace))
        retained = [(proc, pgid) for proc, pgid in groups if pgid is not None]
        handles = [proc for proc, pgid in groups if pgid is None]
        procgroup.wait_interrupt_grace(retained, deadline)
        for proc, pgid in retained:
            if procgroup.retained_group_exists(proc, pgid):
                procgroup.end_group_retained(proc, signal.SIGKILL, pgid)
        for proc in handles:
            if not procgroup.reaped(proc, deadline - time.monotonic()):
                procgroup.end_group_retained(proc, signal.SIGKILL, None)
        for proc, _pgid in retained:
            procgroup.reaped(proc, 0.0)
        return children

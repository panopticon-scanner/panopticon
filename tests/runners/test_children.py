"""Tests for scripts.runners.children: the seam's own launcher (#1575).

`HostRunner.launch` is the `subprocess.run`-shaped call every family goes
through instead of `subprocess.run` itself. Three things it must do that
`subprocess.run` cannot: put the child in its OWN SESSION, REGISTER it while
it runs so an interrupt can reach it, and end the whole process GROUP when the
entry timeout fires.

Real children throughout -- `sys.executable -c ...`, an absolute interpreter
path with the program on the command line, so the case runs identically under
the PATH shim and under an empty PATH and never needs a host binary. The
memory lesson these tests exist for is that a fake proved nothing about the
headless environment: the defect is a grandchild that outlives its parent's
death, which no `Mock` can exhibit.
"""
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import scripts.procgroup as procgroup
import scripts.runners.base as base
import scripts.runners.children as children

_POSIX = os.name == "posix"

# A child that forks a grandchild, records its pid, and then sleeps past every
# deadline in this file. The grandchild inherits the child's process group --
# nothing calls setsid -- which is exactly the shape a host CLI that spawns
# its own workers has.
_TREE = ("import subprocess, sys, time\n"
         "p = subprocess.Popen([sys.executable, '-c',"
         " 'import time; time.sleep(60)'])\n"
         "open(%r, 'w').write(str(p.pid))\n"
         "sys.stderr.write('working\\n')\n"
         "sys.stderr.flush()\n"
         "sys.stdout.write('started\\n')\n"
         "sys.stdout.flush()\n"
         "time.sleep(60)\n")


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:          # pragma: no cover - alive, not ours
        return True
    return True


def await_death(pid, seconds=3.0):
    """Bounded poll, never a sleep(n)."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not alive(pid):
            return True
        time.sleep(0.05)
    return not alive(pid)


class GrandchildCase(unittest.TestCase):
    """A temp directory, a pid file, and the cleanup that stops a failed
    assertion from leaking a 60-second sleeper into the rest of the suite."""

    def setUp(self):
        if not _POSIX:               # pragma: no cover - the suite runs on POSIX
            self.skipTest("process groups are a POSIX facility")
        self.root = tempfile.mkdtemp(prefix="runner-children-")
        self.addCleanup(self._rmtree)
        self.pidfile = os.path.join(self.root, "grandchild.pid")

    def _rmtree(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def tree_argv(self):
        return [sys.executable, "-c", _TREE % self.pidfile]

    def grandchild(self, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                text = open(self.pidfile, encoding="utf-8").read().strip()
            except OSError:
                text = ""
            if text:
                pid = int(text)
                self.addCleanup(self.kill_pid, pid)
                return pid
            time.sleep(0.05)
        self.fail("the child never recorded its grandchild's pid")

    @staticmethod
    def kill_pid(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


class TestAFinishedLaunchIsWhatSubprocessRunReturned(unittest.TestCase):
    """Ruling 6: no behaviour change for a child that finishes. The families
    read `proc.stdout`, `proc.returncode` and `proc.stderr` off the result and
    hand the first to a parser that a stray newline would break."""

    PROGRAM = ("import sys\n"
               "print('x')\n"
               "sys.stderr.write('y')\n"
               "sys.exit(3)\n")

    def test_stdout_stderr_and_returncode_are_identical(self):
        argv = [sys.executable, "-c", self.PROGRAM]
        expected = subprocess.run(argv, capture_output=True, text=True)  # noqa: S603
        got = base.HostRunner().launch(argv, capture_output=True, text=True)
        self.assertEqual(expected.returncode, got.returncode)
        self.assertEqual(expected.stdout, got.stdout)
        self.assertEqual(expected.stderr, got.stderr)
        self.assertEqual(3, got.returncode)
        self.assertEqual("x\n", got.stdout)
        self.assertEqual("y", got.stderr)

    def test_the_result_is_a_completed_process_naming_its_argv(self):
        argv = [sys.executable, "-c", "pass"]
        got = base.HostRunner().launch(argv)
        self.assertIsInstance(got, subprocess.CompletedProcess)
        self.assertEqual(argv, list(got.args))

    def test_input_reaches_the_child_and_bytes_mode_is_honoured(self):
        argv = [sys.executable, "-c",
                "import sys; sys.stdout.write(sys.stdin.read().upper())"]
        text = base.HostRunner().launch(argv, input="hello", text=True)
        self.assertEqual("HELLO", text.stdout)
        raw = base.HostRunner().launch(argv, input=b"hello", text=False)
        self.assertEqual(b"HELLO", raw.stdout)

    def test_a_child_given_no_input_reads_eof_rather_than_the_parents_stdin(self):
        # DEVNULL, never an inherited terminal: a host CLI that reads stdin
        # when it was given none must not be able to consume the operator's.
        argv = [sys.executable, "-c",
                "import sys; sys.stdout.write(repr(sys.stdin.read()))"]
        self.assertEqual("''", base.HostRunner().launch(argv).stdout)

    def test_cwd_and_env_are_the_child_s(self):
        with tempfile.TemporaryDirectory() as d:
            argv = [sys.executable, "-c",
                    "import os, sys; sys.stdout.write(os.getcwd() + '|' "
                    "+ os.environ.get('PANOPTICON_PROBE', ''))"]
            got = base.HostRunner().launch(
                argv, cwd=d, env={"PANOPTICON_PROBE": "seen", "PATH": os.environ["PATH"]})
            cwd, _sep, probe = got.stdout.partition("|")
            self.assertEqual(os.path.realpath(d), os.path.realpath(cwd))
            self.assertEqual("seen", probe)

    def test_a_spawn_failure_is_an_oserror_the_families_already_catch(self):
        # Every family maps OSError to "could not launch <CLI>"; the Popen
        # must not turn that into something else.
        with self.assertRaises(OSError):
            base.HostRunner().launch([os.path.join(os.sep, "nonexistent-binary-9x")])


class TestTheLaunchLeadsItsOwnSession(GrandchildCase):

    def test_the_child_is_its_own_process_group_leader(self):
        argv = [sys.executable, "-c",
                "import os, sys; sys.stdout.write(str(os.getpgid(0) == os.getpid()))"]
        self.assertEqual("True", base.HostRunner().launch(argv).stdout)


class TestATimeoutEndsTheWholeTree(GrandchildCase):
    """The defect. `subprocess.run`'s timeout kills the direct pid, so a host
    CLI's workers went on running -- and charging -- after the entry had been
    ledgered as timed out."""

    def test_the_grandchild_does_not_outlive_the_timeout(self):
        runner = base.HostRunner()
        with self.assertRaises(subprocess.TimeoutExpired):
            runner.launch(self.tree_argv(), timeout=1)
        pid = self.grandchild()
        self.assertTrue(await_death(pid),
                        "the timeout killed the child and left its worker running")

    def test_the_timeout_carries_the_partial_output_the_families_ledger(self):
        # D10 ruling 5: a killed child's stdout and stderr are the only
        # evidence a timed-out entry ever has. Every family reads them off
        # this exception through `base.partial_output` / `base.stderr_head`.
        runner = base.HostRunner()
        with self.assertRaises(subprocess.TimeoutExpired) as ctx:
            runner.launch(self.tree_argv(), timeout=1)
        self.addCleanup(self.kill_pid, self.grandchild())
        self.assertIn("started", base.partial_output(ctx.exception))
        self.assertIn("working", base.stderr_head(ctx.exception.stderr))
        self.assertEqual(1, ctx.exception.timeout)

    # A generous ceiling on the honest path: the entry timeout (1 s) plus
    # `children.PARTIAL_OUTPUT_GRACE` (2 s) for the drain. Well clear of any
    # real launch, and well under "never".
    HANG_BOUND = 8.0

    def test_a_child_that_survives_the_kill_does_not_hang_the_launch(self):
        """The entry timeout is a BOUND, and everything after the kill has to
        respect it too.

        `kill_group`'s own final wait is bounded on purpose, because a child
        can survive both the group kill and the handle kill -- uninterruptible
        I/O, or a child that changed privilege so the signal comes back EPERM.
        Anything `launch` does AFTER that has to be bounded for the same
        reason. Running the launch inside `with proc:` was not:
        `Popen.__exit__` ends with a bare `self.wait()` for every exit but
        `KeyboardInterrupt` (read off the installed stdlib), and it ran
        immediately after the bounded wait -- turning a one-second entry
        timeout into a driver that never comes back.

        The launch runs on a DAEMON thread so a regression is a failed
        assertion rather than a hung suite.
        """
        self.assertEqual(2.0, children.PARTIAL_OUTPUT_GRACE)   # the bound below
        runner, refused, outcome = base.HostRunner(), [], {}

        def refuses(proc, grace=None):
            """A kill that does not kill: what EPERM or an uninterruptible
            child looks like from here."""
            refused.append(proc)
            return False

        def run():
            try:
                runner.launch(self.tree_argv(), timeout=1)
            except BaseException as exc:      # noqa: BLE001 - recorded, then asserted
                outcome["raised"] = exc

        with mock.patch.object(procgroup, "kill_group", refuses):
            thread = threading.Thread(target=run, daemon=True)
            started = time.monotonic()
            thread.start()
            thread.join(self.HANG_BOUND)
            elapsed = time.monotonic() - started
        if refused:                           # kill it for real, whatever happened
            self.addCleanup(refused[0].wait)
            self.addCleanup(refused[0].kill)
            self.grandchild()                 # registers its own cleanup
        self.assertFalse(
            thread.is_alive(),
            "launch did not return within %.0fs with a child that survived the "
            "kill: the entry timeout is no longer a bound" % self.HANG_BOUND)
        self.assertIsInstance(outcome.get("raised"), subprocess.TimeoutExpired)
        self.assertLess(elapsed, self.HANG_BOUND)

    def test_the_registry_is_empty_once_a_launch_has_returned(self):
        # A finished child must not stay registered: `terminate_children`
        # would later signal a pid the OS has since handed to somebody else.
        runner = base.HostRunner()
        runner.launch([sys.executable, "-c", "pass"])
        self.assertEqual([], runner.__dict__.get("_children") or [])
        with self.assertRaises(subprocess.TimeoutExpired):
            runner.launch(self.tree_argv(), timeout=1)
        self.addCleanup(self.kill_pid, self.grandchild())
        self.assertEqual([], runner.__dict__.get("_children") or [])

    def test_the_child_is_registered_while_it_runs(self):
        seen = []
        runner = base.HostRunner()
        register = runner.register_child

        def watch(proc):
            seen.append(proc)
            return register(proc)

        runner.register_child = watch
        runner.launch([sys.executable, "-c", "pass"])
        self.assertEqual(1, len(seen), "the launch registered no child")
        self.assertIsNotNone(seen[0].pid)


class TestANonTimeoutFailureStillEndsTheTree(GrandchildCase):
    """B2: the timeout is not the only way out of a launch.

    `subprocess.run` had a bare `except BaseException: process.kill(); raise`
    and ran the child inside `with Popen(...)`, so ANY exception out of
    `communicate` -- a Ctrl-C on one of the main-thread launches
    (`loop_batch.prove_output_schema_shape`, `probes/common._cli_help`,
    `codex_host._dump_catalog`, `codex_host._capture_requests`), a
    `MemoryError`, a bug in this method -- ended the child and closed the
    pipes. Handling only `TimeoutExpired` left a host CLI and its whole worker
    tree running, unregistered, with nobody holding a handle to it.
    """

    def _interrupted_by(self, error):
        """Launch a real tree, then raise `error` out of `communicate` once
        the grandchild is up. Returns the grandchild's pid."""
        runner, seen = base.HostRunner(), []

        def interrupted(_proc_self, *_args, **_kwargs):
            seen.append(self.grandchild())      # the tree is really running
            raise error

        with mock.patch.object(subprocess.Popen, "communicate", interrupted):
            with self.assertRaises(type(error)):
                runner.launch(self.tree_argv(), timeout=30)
        self.assertEqual([], runner.__dict__.get("_children") or [],
                         "the failed launch left its child registered")
        return seen[0]

    def test_a_ctrl_c_mid_launch_leaves_nothing_running(self):
        pid = self._interrupted_by(KeyboardInterrupt("Ctrl-C during the launch"))
        self.assertTrue(await_death(pid),
                        "an interrupted launch left the CLI's worker running")

    def test_an_ordinary_exception_mid_launch_leaves_nothing_running(self):
        pid = self._interrupted_by(RuntimeError("something else broke"))
        self.assertTrue(await_death(pid),
                        "a failed launch left the CLI's worker running")

    def test_the_pipes_are_closed_when_a_launch_ends_badly(self):
        # `with Popen(...)`: the fds go back whichever way the launch ends. A
        # loop that leaks three descriptors per failed entry runs out of them.
        runner, held = base.HostRunner(), []

        def interrupted(proc_self, *_args, **_kwargs):
            held.append(proc_self)
            raise RuntimeError("boom")

        with mock.patch.object(subprocess.Popen, "communicate", interrupted):
            with self.assertRaises(RuntimeError):
                runner.launch([sys.executable, "-c", "pass"])
        proc = held[0]
        for name in ("stdout", "stderr"):
            stream = getattr(proc, name)
            self.assertTrue(stream is None or stream.closed,
                            "%s was left open by a failed launch" % name)


class TestTerminateChildrenEndsTheWholeGroup(GrandchildCase):
    """The interrupt half of the same kill path: Ctrl-C must reach a
    registered child's workers, not only the pid the runner is holding."""

    def test_a_registered_group_s_grandchild_dies(self):
        runner = base.HostRunner()
        proc = subprocess.Popen(self.tree_argv(), start_new_session=True,  # noqa: S603
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        runner.register_child(proc)
        pid = self.grandchild()
        self.assertTrue(alive(pid), "the grandchild was never running")
        self.assertEqual([proc], runner.terminate_children(grace=0.5))
        self.assertTrue(await_death(pid),
                        "terminate_children signalled the child only, not its group")

    def test_the_registry_is_emptied_as_it_is_read(self):
        runner = base.HostRunner()
        proc = subprocess.Popen([sys.executable, "-c", "pass"],  # noqa: S603
                                start_new_session=True)
        runner.register_child(proc)
        self.assertEqual([proc], runner.terminate_children(grace=0.5))
        self.assertEqual([], runner.terminate_children(grace=0.5))

    def test_a_reaped_handle_is_not_signalled_at_a_pid_somebody_else_now_owns(self):
        """B1 through the interrupt surface itself. `launch` reaps inside
        `communicate` and unregisters a moment later; an interrupt landing in
        that window used to hand `terminate_children` a handle whose pid the
        OS had already given away.

        The victim is polled through its OWN HANDLE for a bounded window, not
        read once with `os.kill(pid, 0)`: signals are delivered
        asynchronously, so one immediate read reports it alive whether or not
        it was hit, and a dead direct child stays a ZOMBIE that `os.kill`
        still answers for until somebody waits on it. `Popen.poll` is the one
        reading that cannot be fooled by either. (Mutation-checked: deleting
        the `returncode` guard in `procgroup._pgid` turns this red.)
        """
        runner = base.HostRunner()
        reaped = subprocess.Popen([sys.executable, "-c", "pass"],  # noqa: S603
                                  start_new_session=True)
        reaped.wait()
        victim = subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", "import time; time.sleep(60)"],
            start_new_session=True, stdout=subprocess.DEVNULL)
        self.addCleanup(victim.wait)
        self.addCleanup(victim.kill)
        reaped.pid = victim.pid                 # what a recycled pid looks like
        runner.register_child(reaped)
        runner.terminate_children(grace=0.5)
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            self.assertIsNone(
                victim.poll(),
                "a reaped handle's stale pid was signalled: the process that "
                "owns that pid now was ended")
            time.sleep(0.05)

    def test_a_child_in_our_own_group_dies_without_taking_the_runner_with_it(self):
        """I3 end to end: a plain `Popen` -- no new session -- registered and
        terminated. The child dies; this process does not.

        A SIGTERM handler is installed for the length of the test, so a
        regression is ABSORBED and recorded rather than killing the runner --
        which is what makes this case fire-for-real AND mutation-checkable.
        Verified: with the own-group guard deleted from `procgroup._pgid`,
        this fails `Lists differ: [] != [True]` and pytest exits 1 (run inside
        its own session, so the stray SIGTERM cannot reach anything else).
        Without the handler the signal would end the runner instead, which is
        a failure mode that deletes its own evidence."""
        runner, received = base.HostRunner(), []
        before = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, before)
        signal.signal(signal.SIGTERM, lambda *_a: received.append(True))
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],  # noqa: S603
                                stdout=subprocess.DEVNULL)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        self.assertEqual(os.getpgid(proc.pid), os.getpgid(0),
                         "the fixture is wrong: this child made its own group")
        runner.register_child(proc)
        runner.terminate_children(grace=1.0)
        self.assertEqual([], received,
                         "terminate_children SIGTERMed the driver's own group")
        self.assertIsNotNone(proc.poll(), "the child outlived terminate_children")

    def test_unregistering_something_never_registered_is_not_an_error(self):
        runner = base.HostRunner()
        runner.unregister_child(object())            # must not raise
        proc = subprocess.Popen([sys.executable, "-c", "pass"],  # noqa: S603
                                start_new_session=True)
        proc.wait()
        runner.register_child(proc)
        runner.terminate_children(grace=0)
        runner.unregister_child(proc)                # already emptied


if __name__ == "__main__":
    unittest.main()

"""Tests for scripts.procgroup: ONE kill path for every child this repo spawns.

#1575. The driver side (`phases/child.py`) and the family side
(`runners/children.py`) both end a child that has outstayed its deadline, and
they used to do it differently: the driver killed the whole process GROUP, the
runners killed a handle. Two kill paths means the weaker one is the guarantee,
so the group kill moved here and both sides call it.

Every child below is `sys.executable -c ...` -- an absolute interpreter path
and a program on the command line -- so the case runs identically under the
PATH shim and under an empty PATH, and never needs a host binary. The
assertions are about a real process tree, not a mock: the defect this module
exists for (a grandchild outliving the timeout) is invisible to a fake.
"""
import ast
import contextlib
import io
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import scripts.procgroup as procgroup

_POSIX = os.name == "posix"
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# #2199: the stand-in DRIVERS the SIGTERM tests signal. Each is a separate
# interpreter, started in its own session, that runs its `main` the way
# `driver.py`'s `__main__` block runs the real one; argv[1] is the child's
# program and argv[2] the review root. One runs a phase child through the
# real `_run_child`, the other a runner child through the seam's registering
# `launch` from a batch worker, with the batch's wait in the main thread.
_PHASE_DRIVER = """\
import signal, sys
import scripts.phases.child as child
import scripts.procgroup as procgroup


def main():
    child._run_child([sys.executable, "-c", sys.argv[1]], sys.argv[2], "tools", timeout=60)
    return 0


signal.signal(signal.SIGTERM, signal.SIG_DFL)      # a driver started the usual way
sys.exit(procgroup.sigterm_as_interrupt(main))
"""

_RUNNER_DRIVER = """\
import signal, sys
import scripts.procgroup as procgroup
import scripts.runners.base as base


class StandIn(base.HostRunner):
    host = "stand-in"

    def run_entry(self, entry, env):
        return self.launch([sys.executable, "-c", sys.argv[1]], cwd=sys.argv[2], timeout=60)


def main():
    StandIn().run_batch([{"id": "e0"}], 1, lambda entry: {})
    return 0


signal.signal(signal.SIGTERM, signal.SIG_DFL)      # a driver started the usual way
sys.exit(procgroup.sigterm_as_interrupt(main))
"""

# The child both stand-ins start: it forks a worker into its own group,
# records both pids, and outsleeps every deadline here.
_TREE_PIDS = ("import os, subprocess, sys, time\n"
              "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
              "open(%r, 'w').write('%%d %%d' %% (os.getpid(), p.pid))\n"
              "time.sleep(60)\n")


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:          # pragma: no cover - alive, not ours
        return True
    return True


def _await_death(pid, seconds=3.0):
    """Bounded poll, never a sleep(n): the kill is asynchronous."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return not _alive(pid)


class _Handle:
    """A `subprocess.Popen`-SHAPED object with no pid at all.

    The fallback this pins is not hypothetical: `HostRunner.terminate_children`
    is handed whatever a family registered, and tests/runners/test_base.py
    registers exactly this shape. A kill path that assumed a pid would raise
    AttributeError on the interrupt path -- the one path that must not fail.
    """

    def __init__(self, stubborn=False):
        self.stubborn = stubborn
        self.sent = []

    def terminate(self):
        self.sent.append("TERM")

    def kill(self):
        self.sent.append("KILL")

    def wait(self, timeout=None):
        if self.stubborn:
            raise subprocess.TimeoutExpired(["child"], timeout or 0)
        return 0


class _GroupCase(unittest.TestCase):

    def setUp(self):
        if not _POSIX:               # pragma: no cover - the suite runs on POSIX
            self.skipTest("process groups are a POSIX facility")
        self.root = tempfile.mkdtemp(prefix="procgroup-")
        self.addCleanup(self._rmtree)

    def _rmtree(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def _tree(self, pidfile):
        """A child that forks a grandchild, records its pid, and then sleeps.

        The grandchild inherits the child's process group (nothing calls
        setsid), which is the whole point: it is reachable by `killpg` and
        unreachable by `proc.kill()`.
        """
        return (
            "import subprocess, sys, time\n"
            "p = subprocess.Popen([sys.executable, '-c',"
            " 'import time; time.sleep(60)'])\n"
            "open(%r, 'w').write(str(p.pid))\n"
            "sys.stdout.flush()\n"
            "time.sleep(60)\n" % pidfile)

    def _term_resistant_tree(self, pidfile, leader_exits=False):
        """A default-SIGTERM leader whose grandchild ignores that signal."""
        worker = (
            "import os, signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "open(%r, 'w').write(str(os.getpid()))\n"
            "time.sleep(60)\n" % pidfile)
        ending = "" if leader_exits else "time.sleep(60)\n"
        return (
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-c', %r])\n"
            "%s" % (worker, ending))

    def _spawn(self, program):
        proc = subprocess.Popen([sys.executable, "-c", program],
                                start_new_session=True)
        self.addCleanup(self._reap, proc)
        return proc

    def _reap(self, proc):
        """Cleanup for a child that LEADS its own session. Never use it on a
        plain `Popen`: its group id is this process's, and the killpg below
        would then take the test runner down with it (measured, while writing
        `test_a_child_that_shares_our_own_group_is_signalled_by_handle` --
        pytest died with no output at all, which is exactly how invisible the
        defect I3 pins is). `_reap_handle` is the one for those."""
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            pass
        self._reap_handle(proc)

    @staticmethod
    def _reap_handle(proc):
        """Cleanup by HANDLE only -- one pid, whatever group it is in."""
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:            # noqa: BLE001 - cleanup, never a failure
            pass

    def _grandchild_of(self, proc, pidfile):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                text = open(pidfile, encoding="utf-8").read().strip()
            except OSError:
                text = ""
            if text:
                pid = int(text)
                self.addCleanup(self._kill_pid, pid)
                return pid
            time.sleep(0.05)
        self.fail("the child never recorded its grandchild's pid")

    def _kill_pid(self, pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


class TestKillGroupEndsTheWholeTree(_GroupCase):

    def test_the_grandchild_does_not_outlive_the_kill(self):
        pidfile = os.path.join(self.root, "grandchild.pid")
        proc = self._spawn(self._tree(pidfile))
        pid = self._grandchild_of(proc, pidfile)
        self.assertTrue(_alive(pid), "the grandchild was never running")
        procgroup.kill_group(proc, grace=0.5)
        self.assertTrue(_await_death(pid),
                        "kill_group ended the child and left its worker running")
        self.assertIsNotNone(proc.returncode, "the child was not reaped")

    def test_sigkill_reaches_a_resistant_grandchild_after_its_leader_exits(self):
        pidfile = os.path.join(self.root, "resistant-grandchild.pid")
        proc = self._spawn(self._term_resistant_tree(pidfile))
        pid = self._grandchild_of(proc, pidfile)
        self.assertTrue(_alive(pid), "the resistant grandchild was never running")
        procgroup.kill_group(proc, grace=0.2)
        self.assertTrue(_await_death(pid),
                        "the direct child exited before its resistant worker was killed")
        self.assertIsNotNone(proc.returncode, "the child was not reaped")

    def test_an_already_exited_leader_retains_its_live_session_group(self):
        pidfile = os.path.join(self.root, "zombie-leader-grandchild.pid")
        proc = self._spawn(self._term_resistant_tree(pidfile, leader_exits=True))
        pid = self._grandchild_of(proc, pidfile)
        time.sleep(0.1)                  # let the unpolled leader become a zombie
        real_getpgid = procgroup.os.getpgid

        def darwin_getpgid(candidate):
            if candidate == proc.pid:
                raise ProcessLookupError("unreaped leader")
            return real_getpgid(candidate)

        with mock.patch.object(procgroup.os, "getpgid", side_effect=darwin_getpgid):
            procgroup.kill_group(proc, grace=0.2)
        self.assertTrue(_await_death(pid),
                        "the already-exited leader hid its live process group")
        self.assertIsNotNone(proc.returncode, "the child was not reaped")

    def test_a_group_that_is_already_gone_is_success_not_an_error(self):
        proc = subprocess.Popen([sys.executable, "-c", "pass"],
                                start_new_session=True)
        proc.wait()
        procgroup.kill_group(proc, grace=0.1)     # must not raise

    def test_the_default_grace_is_the_module_constant(self):
        """`KILL_GRACE` is the semantics `phases/child.py` shipped with, moved
        rather than re-decided: short on purpose, because the deadline that
        brought us here has already passed."""
        self.assertEqual(2.0, procgroup.KILL_GRACE)


class TestTheHandleFallback(unittest.TestCase):
    """No process group to signal -- a bare handle, or a platform without
    them. SIGTERM then SIGKILL on the handle itself, which is exactly what
    `HostRunner.terminate_children` did before the group kill existed."""

    def test_a_handle_with_no_pid_gets_terminate_then_kill(self):
        stubborn = _Handle(stubborn=True)
        procgroup.kill_group(stubborn, grace=0)
        self.assertEqual(["TERM", "KILL"], stubborn.sent)

    def test_a_handle_that_exits_on_sigterm_is_never_killed(self):
        quick = _Handle()
        procgroup.kill_group(quick, grace=0)
        self.assertEqual(["TERM"], quick.sent)

    def test_end_group_sends_one_signal_and_waits_for_nothing(self):
        """The two-phase form `terminate_children` needs: every child is
        signalled BEFORE anything is waited on, so an interrupt's grace is one
        shared window rather than one window per child."""
        handle = _Handle(stubborn=True)
        procgroup.end_group(handle, signal.SIGTERM)
        self.assertEqual(["TERM"], handle.sent)
        procgroup.end_group(handle, signal.SIGKILL)
        self.assertEqual(["TERM", "KILL"], handle.sent)

    def test_reaped_reports_whether_the_child_is_gone(self):
        self.assertTrue(procgroup.reaped(_Handle(), 0))
        self.assertFalse(procgroup.reaped(_Handle(stubborn=True), 0))

    def test_reaped_is_false_for_a_handle_that_cannot_wait_at_all(self):
        class Deaf:
            def wait(self, timeout=None):
                raise ValueError("no such handle")

        self.assertFalse(procgroup.reaped(Deaf(), 0))


class TestAGroupIsSignalledOnlyWhenItIsSafeTo(_GroupCase):
    """Two ways `killpg` reaches the wrong processes, and the guards for both.

    Neither is reachable through the old handle-only path -- `Popen.terminate`
    short-circuits on a set `returncode`, and it signals one pid rather than a
    group -- so both arrived WITH the group kill and are pinned here.

    Both are asserted on the CALL (`os.killpg` spied) rather than on a
    survivor, because a direct child that dies becomes a ZOMBIE until it is
    waited on, and `os.kill(pid, 0)` still succeeds for one: an
    it-is-still-alive assertion on a direct child passes whether or not the
    signal landed, which is a test that cannot fail. (The grandchild cases
    elsewhere in this file are safe from that -- a grandchild is reparented
    and reaped by init, never left a zombie of ours.)

    Spying is NOT because the I3 case is unobservable when fired for real.
    It is observable, and the end-to-end version in
    tests/runners/test_children.py fires it: that test installs a SIGTERM
    handler, so a regression is absorbed and RECORDED (`[] != [True]`, pytest
    exiting 1) instead of killing the runner. Both halves are
    mutation-checked -- deleting the own-group guard in `procgroup._pgid`
    turns this case and that one red.
    """

    def test_a_reaped_handle_is_never_signalled_at_its_old_pid(self):
        """B1. The pid of a reaped child belongs to the OS again, and pids are
        handed out in order: by the time an interrupt reaches a handle that
        `communicate` already reaped, that number may name somebody else's
        session leader -- and `killpg` on it would end their whole tree.

        `Popen.send_signal` was immune (it returns early once `returncode` is
        set); the group kill has to check the same thing before it asks the OS
        what group that pid is in.
        """
        reaped = subprocess.Popen([sys.executable, "-c", "pass"],  # noqa: S603
                                  start_new_session=True)
        reaped.wait()
        victim = self._spawn("import time; time.sleep(60)")
        reaped.pid = victim.pid              # what a recycled pid looks like
        with mock.patch.object(procgroup.os, "killpg") as killpg:
            procgroup.kill_group(reaped, grace=0.1)
        self.assertEqual([], killpg.call_args_list,
                         "a reaped handle's stale pid was signalled as a group")
        self.assertIsNone(victim.poll(), "the innocent process was ended")

    def test_a_child_that_shares_our_own_group_is_signalled_by_handle(self):
        """I3. A handle registered by something that did NOT start a new
        session has OUR process group id, so `killpg` on it is a SIGTERM to
        the driver itself -- and to every sibling in that group.
        """
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],  # noqa: S603
                                stdout=subprocess.DEVNULL)
        self.addCleanup(self._reap_handle, proc)   # NOT _reap: our own group
        self.assertEqual(os.getpgid(proc.pid), os.getpgid(0),
                         "the fixture is wrong: this child made its own group")
        with mock.patch.object(procgroup.os, "killpg") as killpg:
            ended = procgroup.kill_group(proc, grace=1.0)
        self.assertEqual([], killpg.call_args_list,
                         "end_group signalled the driver's own process group")
        self.assertTrue(ended, "the handle fallback never reached the child")
        self.assertIsNotNone(proc.returncode)


class TestEndGroupReachesTheWholeGroup(_GroupCase):

    def test_one_signal_reaches_the_grandchild_too(self):
        pidfile = os.path.join(self.root, "grandchild.pid")
        proc = self._spawn(self._tree(pidfile))
        pid = self._grandchild_of(proc, pidfile)
        procgroup.end_group(proc, signal.SIGKILL)
        self.assertTrue(_await_death(pid),
                        "end_group signalled the child only, not its group")
        proc.wait(timeout=5)


class TestSigtermAsInterrupt(unittest.TestCase):
    """#2199: the helper itself, in this process. Its handler is only ever
    run by hand -- nothing is sent to the test runner -- and every case starts
    from the default disposition a CLI starts with and puts back what it
    found."""

    def setUp(self):
        self.addCleanup(signal.signal, signal.SIGTERM, signal.getsignal(signal.SIGTERM))
        signal.signal(signal.SIGTERM, signal.SIG_DFL)

    def test_main_runs_under_it_and_the_default_is_back_afterwards(self):
        seen = []

        def main():
            seen.append(signal.getsignal(signal.SIGTERM))
            return 3

        self.assertEqual(3, procgroup.sigterm_as_interrupt(main))
        self.assertTrue(callable(seen[0]), "main ran without the handler")
        self.assertIs(signal.SIG_DFL, signal.getsignal(signal.SIGTERM),
                      "the handler outlived the main it was installed for")

    def test_the_first_sigterm_is_the_interrupt_and_every_later_one_is_absorbed(self):
        later = []

        def main():
            handler = signal.getsignal(signal.SIGTERM)
            with self.assertRaises(KeyboardInterrupt) as caught:
                handler(signal.SIGTERM, None)
            self.assertIsInstance(caught.exception, procgroup.Terminated)
            # Every later SIGTERM lands in the cleanup the first one started,
            # and must not cut it short. Counted OUTSIDE `main`: a later one
            # that raised would leave `main` as the same `Terminated`, and the
            # exit status alone could not tell the two apart.
            for _ in range(2):
                later.append(handler(signal.SIGTERM, None))
            raise caught.exception

        with contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                status = procgroup.sigterm_as_interrupt(main)
            except KeyboardInterrupt as exc:
                # Failed HERE: a KeyboardInterrupt out of a test stops the
                # whole pytest session rather than failing this one case.
                self.fail("the SIGTERM escaped as %r instead of an exit status" % (exc,))
        self.assertEqual([None, None], later, "a later SIGTERM raised instead of being absorbed")
        self.assertEqual(128 + signal.SIGTERM, status)
        self.assertEqual("driver: stopped by SIGTERM\n", err.getvalue())
        self.assertIs(signal.SIG_DFL, signal.getsignal(signal.SIGTERM),
                      "an interrupted main left the handler installed")

    def test_a_real_ctrl_c_escapes_exactly_as_before(self):
        # Only the SIGTERM is turned into an exit status. A KeyboardInterrupt
        # itself is the operator's Ctrl-C and leaves the way it always did.
        def main():
            raise KeyboardInterrupt

        with contextlib.redirect_stderr(io.StringIO()) as err, \
             self.assertRaises(KeyboardInterrupt) as caught:
            procgroup.sigterm_as_interrupt(main)
        self.assertNotIsInstance(caught.exception, procgroup.Terminated)
        self.assertEqual("", err.getvalue())
        self.assertIs(signal.SIG_DFL, signal.getsignal(signal.SIGTERM))

    def test_an_ignored_sigterm_is_left_ignored(self):
        # Python's own rule for SIGINT: a parent that ignored the signal
        # meant it.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        seen = []
        procgroup.sigterm_as_interrupt(lambda: seen.append(signal.getsignal(signal.SIGTERM)))
        self.assertEqual([signal.SIG_IGN], seen)
        self.assertIs(signal.SIG_IGN, signal.getsignal(signal.SIGTERM))

    def test_a_python_handler_already_there_is_left_in_place(self):
        # Somebody else's: `main` runs bare, under THEIR handler, which is
        # still the installed one afterwards. Installed and removed here, in
        # the main thread; no signal is sent.
        def theirs(signum, frame):
            pass

        before = signal.signal(signal.SIGTERM, theirs)
        try:
            seen = []

            def main():
                seen.append(signal.getsignal(signal.SIGTERM))
                return 5

            self.assertEqual(5, procgroup.sigterm_as_interrupt(main))
            self.assertEqual([theirs], seen)
            self.assertIs(theirs, signal.getsignal(signal.SIGTERM))
        finally:
            signal.signal(signal.SIGTERM, before)

    def test_a_handler_installed_from_c_is_left_in_place(self):
        # `signal.getsignal` reports a handler installed from C as None: not
        # the default, so not ours to replace, and nothing is installed.
        with mock.patch.object(procgroup.signal, "getsignal", return_value=None), \
             mock.patch.object(procgroup.signal, "signal") as install:
            self.assertEqual(7, procgroup.sigterm_as_interrupt(lambda: 7))
        install.assert_not_called()


class TestATerminatedDriverEndsItsChildren(_GroupCase):
    """#2199 (COD-869076756; owner ruling 2026-09-27): a SIGTERM to the driver
    -- a supervisor's stop, a CI cancel -- ends its children exactly as a
    Ctrl-C does.

    At the default disposition it ended the driver without one `except` or
    `finally` running, and the phase child and the runner children lead
    their own sessions, so the signal to the driver's group reached none of
    them: they went on running with nobody left to end them. Neither
    stand-in here handles the interrupt the way `orchestrate.loop` does, so
    each one also shows how an unhandled SIGTERM leaves: one line on stderr
    and exit status 143, the same on every supported Python.

    The one signal these tests send goes to a stand-in driver's group, after
    checking that the group is the stand-in's own session and not this
    runner's.
    """

    def _stand_in(self, program, pidfile):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=os.pathsep.join(
            [os.path.join(_REPO, "skill"), os.path.join(_REPO, "skill", "scripts"),
             os.path.join(_REPO, "scripts"), _REPO]))
        proc = subprocess.Popen(  # noqa: S603 - the interpreter, never a shell
            [sys.executable, "-c", program, _TREE_PIDS % pidfile, self.root],
            cwd=self.root, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, start_new_session=True)
        self.addCleanup(self._stop, proc)
        return proc

    @staticmethod
    def _stop(proc):
        # `kill_group` signals a group only while the stand-in is unreaped and
        # leads its own -- never this runner's (see `_pgid`).
        procgroup.kill_group(proc, grace=1.0)
        try:
            proc.communicate(timeout=5)
        except Exception:            # noqa: BLE001 - cleanup, never a failure
            pass

    def _pids(self, proc, pidfile):
        """(child, worker), once the child has recorded both: a bounded poll
        that fails at once, with the stand-in's own words, if it died first."""
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with open(pidfile, encoding="utf-8") as fh:
                    pids = [int(pid) for pid in fh.read().split()]
            except (OSError, ValueError):
                pids = []
            if len(pids) == 2:
                self.addCleanup(self._end_tree, *pids)
                return pids
            if proc.poll() is not None:
                self.fail("the stand-in died before its child started: %s"
                          % proc.communicate()[1].strip())
            time.sleep(0.05)
        self.fail("the stand-in's child never recorded its pids")

    @staticmethod
    def _end_tree(child, worker):
        """Cleanup for a tree the fix did not end. Both pids are in the
        child's group, and each is signalled alone, only while it still is:
        a pid that has died may since name somebody else's process."""
        for pid in (worker, child):
            try:
                if os.getpgid(pid) == child != os.getpgid(0):
                    os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

    def _terminate(self, proc):
        pgid = os.getpgid(proc.pid)
        self.assertEqual(proc.pid, pgid, "the stand-in does not lead its own group")
        self.assertNotEqual(os.getpgid(0), pgid, "refusing to signal this runner's own group")
        os.killpg(pgid, signal.SIGTERM)           # what a supervisor or a CI cancel sends
        return proc.communicate(timeout=30)

    def _assert_stopped_by_sigterm(self, proc, err):
        self.assertEqual(128 + signal.SIGTERM, proc.returncode,
                         "the SIGTERM did not end the stand-in through the interrupt path")
        self.assertEqual("driver: stopped by SIGTERM\n", err)

    def test_a_terminated_driver_ends_its_phase_childs_group(self):
        pidfile = os.path.join(self.root, "tree.pid")
        proc = self._stand_in(_PHASE_DRIVER, pidfile)
        child, worker = self._pids(proc, pidfile)
        _out, err = self._terminate(proc)
        self._assert_stopped_by_sigterm(proc, err)
        self.assertTrue(_await_death(worker), "the phase child's worker outlived the driver")
        self.assertTrue(_await_death(child), "the phase child outlived the driver")

    def test_a_terminated_driver_ends_its_registered_runner_children(self):
        pidfile = os.path.join(self.root, "tree.pid")
        proc = self._stand_in(_RUNNER_DRIVER, pidfile)
        child, worker = self._pids(proc, pidfile)
        _out, err = self._terminate(proc)
        self._assert_stopped_by_sigterm(proc, err)
        self.assertTrue(_await_death(worker), "the runner child's worker outlived the driver")
        self.assertTrue(_await_death(child), "the runner child outlived the driver")


class TestTheDriverCliRunsUnderIt(unittest.TestCase):
    """The ruling covers every verb, so `main` runs under the helper where
    `python3 skill/scripts/driver.py ...` starts -- and nowhere an import
    reaches: the suite imports `driver` and keeps its default dispositions.
    Read off the AST, not the text."""

    def test_the_main_guard_runs_main_under_it_and_nothing_else_does(self):
        path = os.path.join(_REPO, "skill", "scripts", "driver.py")
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), path)
        guards = [node for node in tree.body if isinstance(node, ast.If)
                  and ast.unparse(node.test) == "__name__ == '__main__'"]
        self.assertEqual(1, len(guards), "driver.py has no single __main__ guard")
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and ast.unparse(node.func).endswith("sigterm_as_interrupt")]
        self.assertEqual(1, len(calls), "the driver installs it once, at its entry")
        self.assertIn(calls[0], list(ast.walk(guards[0])),
                      "installed outside the __main__ guard, i.e. at import time")
        self.assertEqual(["main"], [ast.unparse(arg) for arg in calls[0].args])


if __name__ == "__main__":
    unittest.main()

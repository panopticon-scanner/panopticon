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
    survivor, deliberately and for two different reasons. I3 fired for real
    would end this test runner, which proves the point by destroying the
    evidence. And a direct child that dies becomes a ZOMBIE until it is
    waited on, so `os.kill(pid, 0)` still succeeds for it: an
    it-is-still-alive assertion on a direct child passes whether or not the
    signal landed, which is a test that cannot fail. (The grandchild cases
    elsewhere in this file are safe from that -- a grandchild is reparented
    and reaped by init, never left a zombie of ours.)
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


if __name__ == "__main__":
    unittest.main()

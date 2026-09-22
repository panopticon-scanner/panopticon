"""Every shipped family's entry timeout ends the whole process tree (#1575).

One test per family seam, and every one of them drives the REAL launcher --
`HostRunner.launch` -- rather than a fake that raises `TimeoutExpired` on
cue. The fakes in the three family suites prove what `run_entry` does with a
timeout; they cannot prove that a timeout leaves nothing running, because a
`Mock` has no children. That is the whole defect: `subprocess.run`'s timeout
kills the direct pid, so a host CLI's workers went on running -- and charging
-- after the entry had been ledgered as timed out.

No host CLI is started here. Each family's `command()` is replaced with an
argv for `sys.executable`, so the binary under test is the interpreter that is
already running this suite: an absolute path, so the case behaves identically
under the PATH shim and under an empty PATH.
"""
import os
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock

import pytest

import scripts.runners.base as base
import scripts.runners.claude as claude_runner
import scripts.runners.codex as codex_runner
import scripts.runners.kimi as kimi_runner

# This file drives the claude family's own `run_entry` on purpose, which is
# what conftest's refusal fixture asks a test to declare (#1616 item 8). The
# launcher it drives is `Runner.launch`, never a real `claude`.
pytestmark = pytest.mark.claude_runner

_POSIX = os.name == "posix"

# A child that forks a grandchild into its own process group, records the
# grandchild's pid, prints on both streams, and then outsleeps every deadline
# in this file. The shape a host CLI with workers has.
_TREE = ("import subprocess, sys, time\n"
         "p = subprocess.Popen([sys.executable, '-c',"
         " 'import time; time.sleep(60)'])\n"
         "open(%r, 'w').write(str(p.pid))\n"
         "sys.stderr.write('working\\n'); sys.stderr.flush()\n"
         "sys.stdout.write('started\\n'); sys.stdout.flush()\n"
         "time.sleep(60)\n")


class _FamilyCase(unittest.TestCase):
    """One temp root, one pid file, and the cleanup that keeps a failed
    assertion from leaking a 60-second sleeper into the rest of the suite."""

    def setUp(self):
        if not _POSIX:               # pragma: no cover - the suite runs on POSIX
            self.skipTest("process groups are a POSIX facility")
        self.root = tempfile.mkdtemp(prefix="family-procgroup-")
        self.addCleanup(self._rmtree)
        self.pidfile = os.path.join(self.root, "grandchild.pid")

    def _rmtree(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def tree_argv(self, *extra):
        return [sys.executable, "-c", _TREE % self.pidfile, *extra]

    def grandchild(self, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                text = open(self.pidfile, encoding="utf-8").read().strip()
            except OSError:
                text = ""
            if text:
                pid = int(text)
                self.addCleanup(self._kill_pid, pid)
                return pid
            time.sleep(0.05)
        self.fail("the launch never reached the child: no grandchild pid was recorded")

    @staticmethod
    def _kill_pid(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    @staticmethod
    def _alive(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:      # pragma: no cover - alive, not ours
            return True
        return True

    def assert_died(self, pid, seconds=3.0):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and self._alive(pid):
            time.sleep(0.05)
        self.assertFalse(
            self._alive(pid),
            "the entry timeout killed the CLI and left its worker running")

    @staticmethod
    def family_default(module):
        """The family launching the way a RUN launches it: nothing injected,
        the module seam at its shipped value. The autouse guard in
        tests/conftest.py has swapped that value for a refusal, so the
        sentinel is restored here -- no host CLI can start regardless, because
        every `command()` below returns an argv for `sys.executable`."""
        return mock.patch.object(module, "DEFAULT_RUNNER", None)

    def assert_timed_out(self, result):
        """The family's ORDINARY timeout failure -- unchanged by #1575, which
        is the point: `launch` re-raises the same `TimeoutExpired` every
        family's existing except-clause already reads."""
        self.assertFalse(result.ok)
        self.assertIn("timed out", result.error)


class TestTheClaudeFamily(_FamilyCase):

    def test_the_entry_timeout_ends_the_whole_tree(self):
        with self.family_default(claude_runner):
            runner = claude_runner.Runner("claude")
            runner.prepare(self.root, review_root=self.root)
            runner.entry_timeout = 1
            with mock.patch.object(claude_runner.Runner, "command",
                                   return_value=self.tree_argv()):
                result = runner.run_entry({"id": "review-app-SEC", "prompt": "p"}, {})
        self.assert_timed_out(result)
        self.assert_died(self.grandchild())

    def test_the_killed_childs_streams_are_still_ledgered(self):
        # D10 ruling 5 through the new launcher: the partial stdout and the
        # stderr head survive the group kill.
        with self.family_default(claude_runner):
            runner = claude_runner.Runner("claude")
            runner.prepare(self.root, review_root=self.root)
            runner.entry_timeout = 1
            with mock.patch.object(claude_runner.Runner, "command",
                                   return_value=self.tree_argv()):
                result = runner.run_entry({"id": "review-app-SEC", "prompt": "p"}, {})
        self.addCleanup(self._kill_pid, self.grandchild())
        self.assertIn("started", result.text)
        self.assertIn("working", result.stderr)


class TestTheCodexFamily(_FamilyCase):

    def _registered(self):
        """Codex is enforced-only: `prepare` refuses a registration directory
        missing a role shell, so the answer comes from here and never from the
        operator's real ~/.codex/agents."""
        import dataclasses

        from scripts import dispatch, hosts
        directory = os.path.join(self.root, "codex-agents")
        os.makedirs(directory)
        for role_file in dispatch.ROLE_FILES.values():
            name = dispatch.registered_agent_filename("codex", role_file)
            with open(os.path.join(directory, name), "w", encoding="utf-8") as fh:
                fh.write("")
        patch = mock.patch.dict(
            hosts.HOSTS, {"codex": dataclasses.replace(
                hosts.spec("codex"), registration_dir=directory)})
        patch.start()
        self.addCleanup(patch.stop)

    def _argv(self):
        """A `codex_host.command`-shaped argv whose `--cd` scratch is
        registered the way a real launch registers it, so `launch_cwd` -- which
        refuses a directory this process did not allocate -- resolves it."""
        from scripts import codex_host
        scratch = os.path.join(self.root, "codex-cwd")
        runtime = os.path.join(self.root, "codex-runtime")
        os.makedirs(scratch)
        os.makedirs(runtime)
        with codex_host._COMMAND_LOCK:
            codex_host._COMMAND_DIRS[scratch] = (runtime, self.root)
        self.addCleanup(codex_host.cleanup_command, ["--cd", scratch])
        return self.tree_argv("--cd", scratch)

    def test_the_entry_timeout_ends_the_whole_tree(self):
        from scripts import codex_host
        self._registered()
        entry = {"id": "review-app-SEC", "agent": "panopticon-domain-panel",
                 "enforced": True, "model": "fixture-model",
                 "delivery": "return_json", "prompt": "review"}
        overlay = {base.ENV_ENTRY_ID: entry["id"],
                   base.ENV_READ_SCOPE: os.path.join(self.root, "scope.json"),
                   base.ENV_WRITE_ALLOWLIST: os.path.join(self.root, "allow.json")}
        with self.family_default(codex_runner):
            runner = codex_runner.Runner()
            runner.prepare(self.root, self.root)
            runner.entry_timeout = 1
            with mock.patch.object(codex_host, "command", return_value=self._argv()), \
                    mock.patch.object(codex_host, "validate_command"):
                result = runner.run_entry(entry, overlay)
        self.assert_timed_out(result)
        self.assert_died(self.grandchild())


class TestTheKimiFamily(_FamilyCase):

    def _home(self):
        """A minimal real-home fixture, never the operator's own."""
        home = os.path.join(self.root, "real-home")
        os.makedirs(home)
        with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as fh:
            fh.write('default_model = "kimi-code/k3"\n\n'
                     '[models."kimi-code/k3"]\nmodel = "k3"\n\n'
                     '[models."kimi-code/kimi-for-coding"]\n'
                     'model = "kimi-for-coding"\n')
        with open(os.path.join(home, "credentials"), "w", encoding="utf-8") as fh:
            fh.write("fixture")
        return home

    def test_the_entry_timeout_ends_the_whole_tree(self):
        with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": self._home()}), \
                self.family_default(kimi_runner):
            runner = kimi_runner.Runner("kimi")
            runner.prepare(os.path.join(self.root, "run"), review_root=self.root)
            self.addCleanup(runner.teardown, "complete")
            runner.entry_timeout = 1
            entry = {"id": "review-app-SEC", "agent": None, "enforced": False,
                     "model": "secondary", "prompt": "review"}
            with mock.patch.object(kimi_runner.Runner, "command",
                                   return_value=self.tree_argv()):
                result = runner.run_entry(entry, {})
        self.assert_timed_out(result)
        self.assert_died(self.grandchild())


def _resolved(module, **kwargs):
    """What `module`'s family would really launch through, spelled the one way
    that covers all three: an injected runner wins, then the module seam's
    `DEFAULT_RUNNER` (kimi reads it at LAUNCH time on purpose, so the seam
    value has to be in the expression), and otherwise the runner's own
    `launch`."""
    runner = module.Runner(**kwargs)
    return runner.launcher(runner.runner, module.DEFAULT_RUNNER)


class TestEverySeamResolvesToTheBaseLauncher(unittest.TestCase):
    """The seam mechanism itself: `DEFAULT_RUNNER` stays a module attribute
    the suite can swap (tests/test_host_launch_guard.py walks for it), and its
    shipped VALUE is the sentinel that means "this runner's own `launch`"."""

    MODULES = (claude_runner, codex_runner, kimi_runner)

    def test_an_uninjected_runner_launches_through_the_base(self):
        for module in self.MODULES:
            with self.subTest(module=module.__name__):
                with mock.patch.object(module, "DEFAULT_RUNNER", None):
                    self.assertIs(_resolved(module).__func__,
                                  base.HostRunner.launch)

    def test_an_injected_runner_is_still_exactly_what_was_passed(self):
        def fake(*args, **kwargs):
            raise AssertionError("never called")

        for module in self.MODULES:
            with self.subTest(module=module.__name__):
                self.assertIs(fake, _resolved(module, runner=fake))

    def test_the_suite_guard_still_intercepts_every_family(self):
        # The autouse fixture in tests/conftest.py has swapped each module's
        # DEFAULT_RUNNER for a refusal; the sentinel must not let a launch
        # slip past it.
        from scripts import codex_host
        for module in self.MODULES:
            with self.subTest(module=module.__name__):
                with self.assertRaises(codex_host.LaunchRefused):
                    _resolved(module)([module.Runner.CLI, "--version"])

    def test_claude_and_codex_keep_a_callable_launcher_attribute(self):
        # `probes/claude.py` and `probes/common.py` read `runner.runner` and
        # CALL it to interrogate `--help`; `probes/shape.py` wraps it. A bare
        # sentinel left on the instance would have made all three unusable, so
        # these two resolve at CONSTRUCTION, exactly as they did before.
        for module in (claude_runner, codex_runner):
            with self.subTest(module=module.__name__):
                with mock.patch.object(module, "DEFAULT_RUNNER", None):
                    self.assertTrue(callable(module.Runner().runner))

    def test_kimi_still_resolves_its_seam_at_launch_time(self):
        # I3, unchanged: kimi keeps `runner=None` on the instance and reads
        # the module attribute inside the launch body, so a monkeypatch
        # applied after construction is still honoured.
        with mock.patch.object(kimi_runner, "DEFAULT_RUNNER", None):
            self.assertIsNone(kimi_runner.Runner().runner)


if __name__ == "__main__":
    unittest.main()

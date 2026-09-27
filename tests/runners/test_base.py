import importlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import scripts.runners.base as base
import scripts.runners.session as session_runner


class TestRunnerFor(unittest.TestCase):
    def test_session_mode_is_always_available(self):
        r = base.runner_for("gemini", "session")
        self.assertIsInstance(r, session_runner.SessionRunner)
        self.assertEqual(r.mode, "session")

    def test_headless_resolves_the_host_module_or_refuses(self):
        self.assertTrue(base.headless_available("claude"))
        self.assertEqual(base.runner_for("claude", "headless").mode, "headless")
        self.assertFalse(base.headless_available("gemini"))
        with self.assertRaises(ValueError) as cm:
            base.runner_for("gemini", "headless")
        self.assertIn("--mode session", str(cm.exception))

    def test_unknown_mode_is_refused(self):
        with self.assertRaises(ValueError):
            base.runner_for("claude", "batch")


class TestBrokenHeadlessModule(unittest.TestCase):
    """`_headless_module` must tell "no runner for this host" apart from "this
    host's runner is broken", so the test needs a module that fails to import.

    #1616 item 4: it used to write `brokenhost.py` into `skill/scripts/runners/`
    -- the LIVE source tree -- and rely on `addCleanup` to take it away again.
    A crash, a Ctrl-C or a `-x` exit between the two left a stray module in the
    shipped package, where `_seams()` in tests/test_host_launch_guard.py and
    `_package_files()` in tests/test_layout.py would both then find it.

    A temp directory APPENDED TO THE PACKAGE'S `__path__` instead. A package
    path is a list and the import system reads it per lookup, so
    `scripts.runners.brokenhost` resolves out of the temp directory while the
    real package keeps its own files; a plain `sys.path` entry could not do
    this, because `scripts.runners` is already imported and its submodule
    search never consults `sys.path` again. Nothing is written inside the
    repository at any point, so there is nothing a crash can leave behind:
    `mkdtemp` is the only place this test writes, `__pycache__` included.
    """

    def _temp_package_dir(self, name, source):
        """`name` importable from `scripts.runners`, out of a temp directory."""
        import scripts.runners as runners_pkg
        root = tempfile.mkdtemp(prefix="panopticon-runners-")
        self.addCleanup(shutil.rmtree, root, True)
        with open(os.path.join(root, name + ".py"), "w", encoding="utf-8") as fh:
            fh.write(source)
        runners_pkg.__path__.append(root)
        self.addCleanup(lambda: runners_pkg.__path__.remove(root))
        self.addCleanup(sys.modules.pop, "scripts.runners." + name, None)
        # The finder for a directory is cached by path, and this one was
        # created after the last cache build.
        importlib.invalidate_caches()
        return root

    def test_a_broken_runner_module_raises_instead_of_reading_as_absent(self):
        pkg_dir = os.path.dirname(os.path.abspath(base.__file__))
        self.addCleanup(sys.modules.pop, "scripts.runners.does_not_exist_xyz", None)
        self._temp_package_dir("brokenhost",
                               "import scripts.runners.does_not_exist_xyz\n")
        self.assertFalse(os.path.exists(os.path.join(pkg_dir, "brokenhost.py")),
                         "the live runners package holds a test's fixture module")

        with self.assertRaises(ModuleNotFoundError) as cm:
            base.runner_for("brokenhost", "headless")
        self.assertEqual(cm.exception.name, "scripts.runners.does_not_exist_xyz")

        with self.assertRaises(ModuleNotFoundError):
            base.headless_available("brokenhost")

    def test_the_temp_package_is_really_what_the_import_resolves(self):
        # Otherwise the test above could pass on a module that was never
        # found at all -- both halves of it expect an exception.
        root = self._temp_package_dir("workinghost", "class Runner:\n    pass\n")
        self.assertTrue(base.headless_available("workinghost"))
        mod = importlib.import_module("scripts.runners.workinghost")
        self.assertEqual(os.path.dirname(os.path.abspath(mod.__file__)), root)


class TestGuardFileNameConstants(unittest.TestCase):
    """M5 (final review): the allowlist/scope file NAMES have ONE owner here,
    read by module attribute everywhere else. Two readers have to agree on
    them byte-for-byte -- `runners/claude.py`'s `prepare`, which resolves the
    paths the launch is built around, and `orchestrate.Guards`, which writes
    those files and bakes their absolute paths into the hook commands -- and
    they used to spell both strings separately in three places. A rename that
    missed one would arm a hook against a file nothing ever writes:
    fail-closed, so every guarded Read and Write in the fan-out would be
    denied.

    Two READERS, not two writers, since #1616 item 5: `prepare` no longer
    writes host-settings.json at all (`arm` did it again immediately after),
    which is why this test asserts the resolved PATHS on both sides rather
    than the file either of them produced."""

    def test_the_names_are_owned_by_base_and_read_by_attribute(self):
        import tempfile
        from unittest import mock
        import scripts.orchestrate as orchestrate
        import scripts.runners.claude as claude_runner
        self.assertEqual(base.ALLOWLIST_FILE, "write-allowlist.json")
        self.assertEqual(base.SCOPE_FILE, "read-scope.json")
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(base, "ALLOWLIST_FILE", "renamed-allowlist.json"), \
             mock.patch.object(base, "SCOPE_FILE", "renamed-scope.json"):
            runner = claude_runner.Runner("claude")
            runner.prepare(d, review_root=d)
            guards = orchestrate.Guards("headless", run_dir=d)
            for path in (runner.allowlist_path, guards.allowlist_path):
                self.assertEqual(path, os.path.join(d, "renamed-allowlist.json"))
            for path in (runner.scope_path, guards.scope_path):
                self.assertEqual(path, os.path.join(d, "renamed-scope.json"))


class TestLaunchEnv(unittest.TestCase):
    """#1626 I2: ONE env preparation per runner, reachable by the probes.

    `Runner.run_entry` built its child environment inline, so
    `probes.common._cli_advertises` -- which launches the SAME binary to ask
    what it advertises -- had no way to use it and passed no `env` at all.
    The interrogation therefore ran under an environment the runner never
    uses. `launch_env` is that preparation named once; `run_entry` calls it,
    the usage probe calls it, and a family override changes both together.
    """

    def test_the_default_is_the_process_environment_plus_the_overlay(self):
        with mock.patch.dict(os.environ, {"PATH": "/p", "HOME": "/h"}, clear=True):
            self.assertEqual({"PATH": "/p", "HOME": "/h", "E": "1"},
                             base.HostRunner().launch_env({"E": "1"}))

    def test_no_overlay_is_just_the_process_environment(self):
        with mock.patch.dict(os.environ, {"PATH": "/p"}, clear=True):
            self.assertEqual({"PATH": "/p"}, base.HostRunner().launch_env())

    def test_it_is_a_copy_the_caller_may_mutate(self):
        # The probes and the loop both hand the result straight to a
        # subprocess call; returning os.environ itself would let one launch's
        # preparation leak into this process and into every later one.
        env = base.HostRunner().launch_env()
        env["PANOPTICON_ONLY_IN_THE_CHILD"] = "1"
        self.assertNotIn("PANOPTICON_ONLY_IN_THE_CHILD", os.environ)


class TestTheUsageProbesSeamAttributes(unittest.TestCase):
    """#1626 I3: `probes.claude._headless_usage_source` reads three attributes
    off a claiming host's runner -- `CLI`, `ENVELOPE_FLAGS` and `runner` --
    and `HostRunner` declared none of them. A family had to learn they exist
    from an `except Exception` whose detail then named the wrong thing.
    """

    def test_the_contract_declares_the_two_the_usage_probe_reads(self):
        self.assertEqual("", base.HostRunner.CLI)
        self.assertEqual((), base.HostRunner.ENVELOPE_FLAGS)

    def test_a_family_that_leaves_them_empty_inherits_the_empty_defaults(self):
        # The point of declaring them: a runner that says nothing about its
        # CLI reads `unknown` for usage_ledger with a detail saying exactly
        # that, instead of raising AttributeError into a detail about a
        # missing module.
        class Bare(base.HostRunner):
            host = "bare"
        self.assertEqual("", Bare().CLI)
        self.assertEqual((), Bare().ENVELOPE_FLAGS)


class TestAFailedResultKeepsWhatTheLaunchProduced(unittest.TestCase):
    """D10 ruling 5: a timed-out entry is the most expensive kind of failure,
    and it used to be the one that kept nothing -- `usage={}` and the partial
    stdout discarded inside the `except`."""

    def test_failed_defaults_to_no_usage_and_no_text(self):
        res = base.RunResult.failed("e1", "boom")
        self.assertEqual(({}, "", False), (res.usage, res.text, res.ok))

    def test_failed_carries_the_usage_and_partial_output_it_is_given(self):
        res = base.RunResult.failed("e1", "timed out after 5s",
                                    usage={"input_tokens": 9}, text="partial")
        self.assertEqual({"input_tokens": 9}, res.usage)
        self.assertEqual("partial", res.text)
        self.assertFalse(res.ok)

    def test_partial_output_reads_a_killed_childs_stdout_however_it_arrives(self):
        # TimeoutExpired carries stdout UNDECODED even from a text-mode launch
        # (CPython translates newlines only after communicate() returns, and
        # the timeout raises before that), so bytes is the normal case.
        cases = {b"half a line": "half a line", "half a line": "half a line",
                 None: "", b"": "", b"\xff bad": "� bad"}
        for stdout, expected in cases.items():
            with self.subTest(stdout=stdout):
                exc = subprocess.TimeoutExpired(["x"], 1, output=stdout)
                self.assertEqual(expected, base.partial_output(exc))

"""#1422: an environment that is MEANT to run the live-tool tests must not be
allowed to pass by skipping them.

Every adapter integration test guards itself on a precondition -- the fixture is
vendored, the toolchain is installed, the adapter is registered. Outside the
image none of those hold, so the tests skip, which is correct on a dev machine
and on the standard runner. The failure mode is that it is ALSO what happens in
the environment built to run them: a green tick over zero executed assertions.

#1410 fixed exactly one test that way (`PANOPTICON_REQUIRE_INTEGRATION=1` turns
its unmet preconditions into failures) and left the pattern local to that file.
This module makes it the rule rather than the exception, and pins it so the next
integration test cannot quietly reintroduce a silent skip.
"""
import os
import re
import unittest
from unittest import mock

import yaml

from conftest import REPO_ROOT
import _test_helpers as helpers

TOOLS_TESTS = os.path.join(REPO_ROOT, "tests", "tools")

# A skip that is NOT a coverage loss opts out in the source, on the line itself,
# so the exemption travels with the code instead of living in a list here that
# drifts from it.
_EXEMPT = "strict-skip-exempt:"
_SKIP_CALL = re.compile(r"\.skipTest\(")


class TestRequireIntegrationFlag(unittest.TestCase):
    def test_reads_the_environment_at_call_time(self):
        # NOT a module-level constant: `_REQUIRE_INTEGRATION = os.environ...`
        # evaluated at import means the variable is fixed before any test can
        # set it, so the behaviour is untestable without reloading the module
        # and un-settable by a fixture. Read it when asked.
        with mock.patch.dict(os.environ, {helpers.REQUIRE_INTEGRATION_ENV: "1"}):
            self.assertTrue(helpers.require_integration())
        with mock.patch.dict(os.environ,
                             {helpers.REQUIRE_INTEGRATION_ENV: "0"}):
            self.assertFalse(helpers.require_integration())
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(helpers.require_integration())

    def test_only_the_exact_opt_in_counts(self):
        # "true"/"yes"/"" must not switch on a mode that turns skips into
        # failures -- an ambiguous value should leave the safe behaviour.
        for value in ("true", "yes", "", "2"):
            with mock.patch.dict(os.environ,
                                 {helpers.REQUIRE_INTEGRATION_ENV: value}):
                self.assertFalse(helpers.require_integration(), value)


class TestSkipOrFail(unittest.TestCase):
    def test_strict_mode_turns_an_unmet_precondition_into_a_failure(self):
        case = unittest.TestCase()
        with mock.patch.object(helpers, "require_integration", return_value=True):
            with self.assertRaises(AssertionError) as caught:
                helpers.skip_or_fail(case, "cargo not installed")
        self.assertIn("cargo not installed", str(caught.exception))
        self.assertIn(helpers.REQUIRE_INTEGRATION_ENV, str(caught.exception),
                      "the failure must name the flag that made it a failure")

    def test_otherwise_it_stays_a_clean_skip(self):
        case = unittest.TestCase()
        with mock.patch.object(helpers, "require_integration", return_value=False):
            with self.assertRaises(unittest.SkipTest):
                helpers.skip_or_fail(case, "cargo not installed")


class TestAssertAdapterFindsHonoursTheFlag(unittest.TestCase):
    """The single chokepoint every fixture-backed test already goes through
    (#1422: 'teach assert_adapter_finds to honor it too')."""

    def test_missing_fixture_fails_when_integration_is_required(self):
        with mock.patch.object(helpers, "require_integration", return_value=True):
            with self.assertRaises(AssertionError) as caught:
                helpers.assert_adapter_finds(self, "brakeman", "no-such-fixture")
        self.assertIn("no-such-fixture", str(caught.exception))

    def test_missing_fixture_skips_when_it_is_not(self):
        with mock.patch.object(helpers, "require_integration", return_value=False):
            with self.assertRaises(unittest.SkipTest):
                helpers.assert_adapter_finds(self, "brakeman", "no-such-fixture")


class TestNoSilentSkipsRemain(unittest.TestCase):
    """The durable half. Without this, the next integration test added is one
    bare `self.skipTest(...)` away from being invisible again."""

    def _skip_sites(self):
        sites = []
        for name in sorted(os.listdir(TOOLS_TESTS)):
            if not name.endswith(".py"):
                continue
            path = os.path.join(TOOLS_TESTS, name)
            with open(path, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
            for n, line in enumerate(lines, 1):
                if not _SKIP_CALL.search(line):
                    continue
                context = line + (lines[n - 2] if n >= 2 else "")
                if _EXEMPT in context:
                    continue
                sites.append("%s:%d %s" % (name, n, line.strip()))
        return sites

    def test_every_precondition_skip_goes_through_skip_or_fail(self):
        self.assertEqual(
            [], self._skip_sites(),
            "a bare skipTest in an adapter test is invisible in the very "
            "environment built to run it. Use _test_helpers.skip_or_fail, or "
            "mark the line `# %s <why this one is not a coverage loss>`:\n%s"
            % (_EXEMPT, "\n".join(self._skip_sites())))

    def test_the_scanner_actually_reads_the_directory(self):
        # Guards the guard: a glob that matched nothing would report a clean
        # pass over an unread directory.
        names = [n for n in os.listdir(TOOLS_TESTS) if n.endswith(".py")]
        self.assertGreater(len(names), 15, "tools test scan found almost "
                                           "nothing; the scanner is broken")


class TestThereIsSomewhereTheyAreRequiredToRun(unittest.TestCase):
    """The other half of #1422. Strict mode is only worth having if some
    environment actually sets it; otherwise every adapter test still skips
    everywhere and the flag is decoration."""

    def setUp(self):
        path = os.path.join(REPO_ROOT, ".github", "workflows",
                            "adapter-integration.yml")
        self.assertTrue(os.path.isfile(path), "no adapter-integration workflow")
        with open(path, encoding="utf-8") as fh:
            self.wf = yaml.safe_load(fh.read())
        self.steps = self.wf["jobs"]["integration"]["steps"]
        self.run_step = next(
            (s for s in self.steps if "pytest" in (s.get("run") or "")), None)
        self.assertIsNotNone(self.run_step, "no step runs pytest")

    def test_the_job_requires_integration(self):
        self.assertIn("PANOPTICON_REQUIRE_INTEGRATION=1", self.run_step["run"],
                      "the job does not set the flag, so every adapter test "
                      "would skip and the job would pass having run nothing")

    def test_it_runs_inside_the_fixtures_image(self):
        run = self.run_step["run"]
        self.assertIn("panopticon-fixtures", run)
        self.assertIn("FIXTURE_ROOT=/opt/panopticon-fixtures", run,
                      "without FIXTURE_ROOT the image-only fixtures are "
                      "invisible and strict mode fails on all of them")

    def test_it_runs_the_whole_tools_tree_not_an_integration_glob(self):
        # test_brakeman.py's railsgoat probe -- the one that caught the stale
        # CWE map -- is an integration test living in a unit-test file. A
        # `test_*_integration.py` selector would scope around it.
        self.assertIn("tests/tools/", self.run_step["run"])
        self.assertNotIn("_integration.py", self.run_step["run"])

    def test_it_is_scheduled_not_only_manual(self):
        on = self.wf.get(True, {})
        self.assertTrue((on or {}).get("schedule"),
                        "a dispatch-only job is one nobody remembers to run")
        self.assertIn("workflow_dispatch", on)

    def test_it_does_not_substitute_a_degraded_image(self):
        # security.yml deliberately falls back to a local build with a warning;
        # here that would report red for an infrastructure reason dressed as a
        # regression, so the pull must fail loud instead.
        pull = next(s for s in self.steps
                    if "docker pull" in (s.get("run") or ""))
        self.assertIn("::error::", pull["run"])
        self.assertIn("exit 1", pull["run"])
        self.assertNotIn("docker build -t panopticon-tools", pull["run"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

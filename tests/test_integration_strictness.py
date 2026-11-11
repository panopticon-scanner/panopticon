"""Runtime contracts for the strict integration-test opt-in."""
import os
import unittest
from unittest import mock

import tests._test_helpers as helpers


class TestRequireIntegrationFlag(unittest.TestCase):
    def test_reads_the_environment_at_call_time(self):
        with mock.patch.dict(os.environ, {helpers.REQUIRE_INTEGRATION_ENV: "1"}):
            self.assertTrue(helpers.require_integration())
        with mock.patch.dict(os.environ, {helpers.REQUIRE_INTEGRATION_ENV: "0"}):
            self.assertFalse(helpers.require_integration())
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(helpers.require_integration())

    def test_only_the_exact_opt_in_counts(self):
        for value in ("true", "yes", "", "2"):
            with self.subTest(value=value), mock.patch.dict(
                    os.environ, {helpers.REQUIRE_INTEGRATION_ENV: value}):
                self.assertFalse(helpers.require_integration())


class TestSkipOrFail(unittest.TestCase):
    def test_strict_mode_turns_an_unmet_precondition_into_a_failure(self):
        case = unittest.TestCase()
        with mock.patch.object(helpers, "require_integration", return_value=True):
            with self.assertRaises(AssertionError) as caught:
                helpers.skip_or_fail(case, "cargo not installed")
        self.assertIn("cargo not installed", str(caught.exception))
        self.assertIn(helpers.REQUIRE_INTEGRATION_ENV, str(caught.exception))

    def test_non_strict_mode_keeps_the_clean_skip(self):
        case = unittest.TestCase()
        with mock.patch.object(helpers, "require_integration", return_value=False):
            with self.assertRaises(unittest.SkipTest):
                helpers.skip_or_fail(case, "cargo not installed")


class TestAssertAdapterFindsHonoursTheFlag(unittest.TestCase):
    def test_missing_fixture_fails_when_integration_is_required(self):
        with mock.patch.object(helpers, "require_integration", return_value=True):
            with self.assertRaises(AssertionError) as caught:
                helpers.assert_adapter_finds(
                    self, "brakeman", "no-such-fixture", matches=lambda finding: False)
        self.assertIn("no-such-fixture", str(caught.exception))

    def test_missing_fixture_skips_when_integration_is_not_required(self):
        with mock.patch.object(helpers, "require_integration", return_value=False):
            with self.assertRaises(unittest.SkipTest):
                helpers.assert_adapter_finds(
                    self, "brakeman", "no-such-fixture", matches=lambda finding: False)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

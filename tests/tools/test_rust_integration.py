import os
import shutil
import subprocess
import unittest
from unittest import mock

from _test_helpers import (REQUIRE_INTEGRATION_ENV,
                           assert_adapter_finds, skip_or_fail)
from .conftest import FIXTURE_ROOT, OK_SCAN_EXIT_CODES

# #run8 TST-F1A: the only END-TO-END cargo-audit RUSTSEC test used to hide behind
# three stacked SOFT skips (cargo absent / `cargo audit` broken / fixture not
# vendored). Because the vulnerable-rust fixture is vendored in-repo and
# cargo-audit ships on no standard runner, the test silently no-ops in every
# automated CI job today, so a real RUSTSEC-detection regression could go
# completely unverified with no failing test to signal it.
#
# PANOPTICON_REQUIRE_INTEGRATION=1 -- set by the environment that IS meant to run
# it (a cargo-audit-equipped, in-image integration run) -- flips each missing
# precondition from a silent skip into a hard FAILURE, so the test can never
# silently pass-by-skipping where it is supposed to execute. Unset (dev machines,
# the standard runner) keeps the clean skip.
#
# #1422 generalised this file's local pattern into _test_helpers.skip_or_fail and
# applied it to every other adapter test, so the duplicate lives there now. The
# flag is also read at CALL time rather than captured at import, which is what
# lets a test set it.


class TestRustIntegration(unittest.TestCase):
    def _skip_or_fail(self, reason):
        skip_or_fail(self, reason)

    def test_cargo_audit_finds_rustsec_advisories(self):
        if not shutil.which("cargo"):
            self._skip_or_fail("cargo not installed")
        proc = subprocess.run(["cargo", "audit", "--version"],
                              capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            self._skip_or_fail(
                "cargo-audit subcommand not installed "
                "(`cargo audit --version` rc %d)" % proc.returncode)
        if not os.path.isdir(os.path.join(FIXTURE_ROOT, "vulnerable-rust")):
            self._skip_or_fail("vulnerable-rust fixture not vendored")
        findings = assert_adapter_finds(
            self, "cargo-audit", "vulnerable-rust", ok_codes=OK_SCAN_EXIT_CODES
        )
        self.assertTrue(
            any(
                any(r.startswith("RUSTSEC-")
                    for r in (f.get("citations") or {}).get("rustsec", []))
                for f in findings
            ),
            "expected RUSTSEC citations",
        )


class TestRustIntegrationStrictModeMeta(unittest.TestCase):
    """The strict-mode toggle itself is the #run8 TST-F1A fix, so exercise it
    directly (needs no cargo/cargo-audit): a missing precondition must FAIL when
    integration is required and SKIP when it is not."""

    def _run_missing_toolchain(self, strict):
        case = TestRustIntegration("test_cargo_audit_finds_rustsec_advisories")
        # Drive the REAL switch -- the environment variable -- rather than a
        # module constant standing in for it. The old form could only work
        # because the flag was captured at import; now that it is read at call
        # time, the test exercises what CI actually sets.
        with mock.patch.dict(os.environ,
                             {REQUIRE_INTEGRATION_ENV: "1" if strict else "0"}), \
             mock.patch.object(shutil, "which", return_value=None):
            case.test_cargo_audit_finds_rustsec_advisories()

    def test_strict_mode_fails_loud_when_toolchain_missing(self):
        with self.assertRaises(AssertionError):
            self._run_missing_toolchain(True)

    def test_non_strict_mode_skips_when_toolchain_missing(self):
        with self.assertRaises(unittest.SkipTest):
            self._run_missing_toolchain(False)


if __name__ == "__main__":
    unittest.main()

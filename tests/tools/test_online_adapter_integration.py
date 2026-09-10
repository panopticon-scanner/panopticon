"""#1528: pip-audit and npm-audit, the two ONLINE_ONLY adapters.

They are held to a SEPARATE opt-in from the rest, and deliberately excluded from
the daily integration job's promise. Both query a live advisory API, so a red run
would as often mean "PyPI was slow" as "the adapter regressed" -- and a CI signal
that cries wolf is worse than one that admits what it does not cover. The
offline substitute (osv-scanner's baked databases) IS covered, by
test_osv_integration.

Run them deliberately with PANOPTICON_REQUIRE_ONLINE_INTEGRATION=1.
"""
import os
import shutil
import unittest

from _test_helpers import assert_adapter_finds
from .conftest import OK_SCAN_EXIT_CODES

_REQUIRE_ONLINE = os.environ.get("PANOPTICON_REQUIRE_ONLINE_INTEGRATION") == "1"


class TestOnlineAdapterIntegration(unittest.TestCase):
    def _gate(self, binary):
        if not _REQUIRE_ONLINE:
            # ONLINE_ONLY adapters query a live advisory API, which is not a
            # regression signal we control. Opting in is
            # PANOPTICON_REQUIRE_ONLINE_INTEGRATION=1, not the integration flag.
            # strict-skip-exempt: live advisory API, separate opt-in
            self.skipTest(
                "set PANOPTICON_REQUIRE_ONLINE_INTEGRATION=1 to run the "
                "network-dependent adapters")
        if not shutil.which(binary):
            self.fail("PANOPTICON_REQUIRE_ONLINE_INTEGRATION=1 but %s is not "
                      "installed" % binary)

    def test_pip_audit_finds_advisories(self):
        self._gate("pip-audit")
        assert_adapter_finds(self, "pip-audit", "vulnerable-python",
                             ok_codes=OK_SCAN_EXIT_CODES)

    def test_npm_audit_finds_advisories(self):
        self._gate("npm")
        assert_adapter_finds(self, "npm-audit", "vulnerable-node",
                             ok_codes=OK_SCAN_EXIT_CODES)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

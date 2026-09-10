"""#1528: osv-scanner had no live-tool coverage -- every test replayed a single
offline-captured OSV_REAL_SAMPLE JSON literal rather than running the binary.

That shape cannot catch the failure that actually happened. #calibration-1: the
image's offline OSV databases were warmed for npm + PyPI only, so on the first
Go/RubyGems target osv-scanner exited 127, produced nothing, and sank
certification. A replayed sample is green in exactly that world.

So this runs the real binary against all three vendored ecosystems. If a future
image warms fewer databases, the ecosystem that lost its DB fails here by name.
"""
import shutil
import unittest

from _test_helpers import assert_adapter_finds, skip_or_fail
from .conftest import OK_SCAN_EXIT_CODES, in_tools_image

# (fixture, the manifest that makes it applicable) -- named so a failure says
# WHICH ecosystem lost coverage, not just "osv-scanner found nothing".
ECOSYSTEMS = (
    ("vulnerable-python", "requirements.txt"),
    ("vulnerable-node", "package-lock.json"),
    ("vulnerable-rust", "Cargo.lock"),
)


class TestOsvScannerIntegration(unittest.TestCase):
    def setUp(self):
        if not in_tools_image():
            skip_or_fail(self, "not running inside panopticon-tools; osv-scanner needs "
                               "the image's baked assets")
        if not shutil.which("osv-scanner"):
            skip_or_fail(self, "osv-scanner not installed on this host")

    def test_finds_advisories_in_every_vendored_ecosystem(self):
        for fixture, manifest in ECOSYSTEMS:
            with self.subTest(ecosystem=fixture, manifest=manifest):
                findings = assert_adapter_finds(
                    self, "osv-scanner", fixture, ok_codes=OK_SCAN_EXIT_CODES)
                self.assertTrue(
                    any((f.get("citations") or {}) or
                        (f.get("tool_evidence") or {}).get("rule_id")
                        for f in findings),
                    "%s findings carry no advisory identifier at all" % fixture)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

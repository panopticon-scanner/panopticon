import os
import unittest

from scripts.tools import ADAPTERS
from tests.tools.conftest import FIXTURE_ROOT


# Guard against a surprising FIXTURE_ROOT value before any test relies on it.
# It is legitimately one of TWO roots: the in-repo default (tests/fixtures,
# where the corpus is not vendored and every test below skips) or the fixtures
# image's baked corpus, which Dockerfile.fixtures sets via
# `ENV FIXTURE_ROOT=/opt/panopticon-fixtures`.
#
# This asserted the first ONLY, so it held exactly when the tests skipped and
# raised at IMPORT time whenever they would actually run -- taking down pytest
# collection for this file and test_csharp_integration.py together. The Java
# and C# adapters were therefore never exercised by any suite, anywhere: the
# only tests that would have proved they work could not be collected in the
# one environment built to run them.
_IN_REPO_ROOT = os.path.join("tests", "fixtures")
_IMAGE_ROOT = "/opt/panopticon-fixtures"
_root = FIXTURE_ROOT.rstrip(os.sep)
assert _root.endswith(_IN_REPO_ROOT) or _root == _IMAGE_ROOT, (
    "unexpected FIXTURE_ROOT %r -- expected the in-repo tests/fixtures or the "
    "fixtures image's /opt/panopticon-fixtures" % FIXTURE_ROOT)


class TestCSharpIntegration(unittest.TestCase):
    def test_roslyn_secguard_finds_aspnet_issues(self):
        target = os.path.join(FIXTURE_ROOT, "AspGoat")
        # Environment-availability gates → legitimate skips (this suite only
        # runs inside the fixtures image, where the adapter and the baked
        # AspGoat fixture exist).
        if "roslyn-secguard" not in ADAPTERS:
            self.skipTest("roslyn-secguard adapter not registered")
        if not os.path.isdir(target):
            self.skipTest("AspGoat fixture not vendored (run inside the fixtures image)")
        # Past the fixture gate we ARE in the integration environment, so the
        # remaining conditions are real failures, not skips (#581): a
        # non-applicable fixture or a tool crash must not masquerade as
        # "skipped" and leave coverage silently empty.
        adapter = ADAPTERS["roslyn-secguard"]
        self.assertTrue(adapter.is_applicable(target),
                        "roslyn-secguard should apply to the AspGoat C# project")
        raw, rc = adapter.invoke(target)
        self.assertIn(rc, (0, 1), f"roslyn-secguard errored (rc {rc}) on AspGoat")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(any(
            f.get("source") == "tool:roslyn-secguard" and
            f.get("tool_evidence", {}).get("rule_id", "").startswith("SCS")
            for f in findings
        ), "expected SCS rule findings")


if __name__ == "__main__":
    unittest.main()

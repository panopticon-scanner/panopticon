import os
import unittest

from scripts.tools import ADAPTERS
from _test_helpers import assert_fixture_root, skip_or_fail
from tests.tools.conftest import FIXTURE_ROOT


assert_fixture_root(FIXTURE_ROOT)


class TestCSharpIntegration(unittest.TestCase):
    def test_roslyn_secguard_finds_aspnet_issues(self):
        target = os.path.join(FIXTURE_ROOT, "AspGoat")
        # Environment-availability gates → legitimate skips (this suite only
        # runs inside the fixtures image, where the adapter and the baked
        # AspGoat fixture exist).
        if "roslyn-secguard" not in ADAPTERS:
            skip_or_fail(self, "roslyn-secguard adapter not registered")
        if not os.path.isdir(target):
            skip_or_fail(self, "AspGoat fixture not vendored "
                         "(run inside the fixtures image)")
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

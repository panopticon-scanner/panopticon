import unittest
from unittest import mock

import scripts.tools.spotbugs as sb

SPOTBUGS_SAMPLE = b"""<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6" sequence="0" timestamp="0" analysisTimestamp="0" release="">
  <BugInstance type="SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE" priority="1" category="SECURITY">
    <Class classname="com.example.App">
      <SourceLine sourcepath="com/example/App.java" start="42"/>
    </Class>
  </BugInstance>
</BugCollection>
"""


class TestSpotBugsAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        findings = sb.SpotBugsAdapter().parse(SPOTBUGS_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:spotbugs")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["location"]["file"], "com/example/App.java")
        self.assertEqual(f["location"]["line_start"], 42)
        self.assertIn("CWE-89", f["citations"]["cwe"])

    def test_is_applicable_when_pom_present(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("pom.xml")):
            self.assertTrue(sb.SpotBugsAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_false_without_pom(self):
        with mock.patch("os.path.exists", return_value=False):
            self.assertFalse(sb.SpotBugsAdapter().is_applicable("/tmp/fake"))

    def test_parse_includes_provenance(self):
        findings = sb.SpotBugsAdapter().parse(SPOTBUGS_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["provenance"]["discovered_by"], "tool:spotbugs")
        self.assertEqual(findings[0]["provenance"]["confirmation_status"], "TOOL")

    def test_parse_empty_output_returns_no_findings(self):
        findings = sb.SpotBugsAdapter().parse(b"", "g1")
        self.assertEqual(findings, [])

    def test_parse_multiple_bug_instances(self):
        sample = b"""<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6" sequence="0" timestamp="0" analysisTimestamp="0" release="">
  <BugInstance type="SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE" priority="1" category="SECURITY">
    <Class classname="com.example.App">
      <SourceLine sourcepath="com/example/App.java" start="42"/>
    </Class>
  </BugInstance>
  <BugInstance type="XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER" priority="2" category="SECURITY">
    <Class classname="com.example.Servlet">
      <SourceLine sourcepath="com/example/Servlet.java" start="88"/>
    </Class>
  </BugInstance>
</BugCollection>
"""
        findings = sb.SpotBugsAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["location"]["line_start"], 42)
        self.assertEqual(findings[1]["severity"], "MEDIUM")
        self.assertEqual(findings[1]["location"]["file"], "com/example/Servlet.java")
        self.assertEqual(findings[1]["location"]["line_start"], 88)

    def test_parse_bug_instance_without_cwe_mapping(self):
        sample = b"""<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6" sequence="0" timestamp="0" analysisTimestamp="0" release="">
  <BugInstance type="UNKNOWN_CUSTOM_BUG_TYPE" priority="2" category="CORRECTNESS">
    <Class classname="com.example.Util">
      <SourceLine sourcepath="com/example/Util.java" start="10"/>
    </Class>
  </BugInstance>
</BugCollection>
"""
        findings = sb.SpotBugsAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "UNKNOWN_CUSTOM_BUG_TYPE")
        self.assertNotIn("citations", findings[0])


if __name__ == "__main__":
    unittest.main()


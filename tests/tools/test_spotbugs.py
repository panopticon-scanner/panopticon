import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
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

    def test_parse_empty_output_returns_no_findings(self):
        findings = sb.SpotBugsAdapter().parse(b"", "g1")
        self.assertEqual(findings, [])

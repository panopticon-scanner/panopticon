import contextlib
import io
import os
import unittest
from _test_helpers import first, only
from unittest import mock
from xml.etree.ElementTree import ParseError

import scripts.tools.spotbugs as sb

SPOTBUGS_SAMPLE = b"""<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6" sequence="0" timestamp="0" analysisTimestamp="0" release="">
  <BugInstance type="SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE" rank="7" priority="1" category="SECURITY">
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
        self.assertEqual(f["severity"], "HIGH")        # rank 7 -> Scary -> HIGH
        self.assertEqual(f["confidence"], "CERTAIN")   # priority 1 -> high confidence
        self.assertEqual(f["location"]["file"], "com/example/App.java")
        self.assertEqual(f["location"]["line_start"], 42)
        self.assertIn("CWE-89", f["citations"]["cwe"])

    def test_is_applicable_when_pom_and_compiled_classes_present(self):
        # #run7 COD-C2A: SpotBugs needs compiled bytecode, so applicability
        # requires a manifest AND a target/classes (or build/classes) dir.
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("pom.xml")), \
             mock.patch("os.path.isdir",
                        side_effect=lambda p: p.endswith(os.path.join("target", "classes"))):
            self.assertTrue(sb.SpotBugsAdapter().is_applicable("/tmp/fake"))

    def test_not_applicable_with_manifest_but_no_compiled_classes(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("pom.xml")), \
             mock.patch("os.path.isdir", return_value=False):
            self.assertFalse(sb.SpotBugsAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_false_without_pom(self):
        with mock.patch("os.path.exists", return_value=False):
            self.assertFalse(sb.SpotBugsAdapter().is_applicable("/tmp/fake"))

    def test_parse_includes_provenance(self):
        findings = sb.SpotBugsAdapter().parse(SPOTBUGS_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(first(findings)["provenance"]["discovered_by"], "tool:spotbugs")
        self.assertEqual(first(findings)["provenance"]["confirmation_status"], "TOOL")

    def test_parse_empty_output_returns_no_findings(self):
        findings = sb.SpotBugsAdapter().parse(b"", "g1")
        self.assertEqual(findings, [])

    def test_parse_multiple_bug_instances(self):
        sample = b"""<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6" sequence="0" timestamp="0" analysisTimestamp="0" release="">
  <BugInstance type="SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE" rank="4" priority="1" category="SECURITY">
    <Class classname="com.example.App">
      <SourceLine sourcepath="com/example/App.java" start="42"/>
    </Class>
  </BugInstance>
  <BugInstance type="XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER" rank="11" priority="2" category="SECURITY">
    <Class classname="com.example.Servlet">
      <SourceLine sourcepath="com/example/Servlet.java" start="88"/>
    </Class>
  </BugInstance>
  <BugInstance type="WEAK_TRUST_MANAGER" rank="18" priority="3" category="SECURITY">
    <Class classname="com.example.Trust">
      <SourceLine sourcepath="com/example/Trust.java" start="100"/>
    </Class>
  </BugInstance>
</BugCollection>
"""
        findings = sb.SpotBugsAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 3)
        # severity tracks rank, confidence tracks priority -- independently.
        self.assertEqual(findings[0]["severity"], "CRITICAL")   # rank 4
        self.assertEqual(findings[0]["confidence"], "CERTAIN")  # priority 1
        self.assertEqual(findings[0]["location"]["line_start"], 42)
        self.assertEqual(findings[1]["severity"], "MEDIUM")     # rank 11
        self.assertEqual(findings[1]["confidence"], "LIKELY")   # priority 2
        self.assertEqual(findings[1]["location"]["file"], "com/example/Servlet.java")
        self.assertEqual(findings[1]["location"]["line_start"], 88)
        self.assertEqual(findings[2]["severity"], "LOW")        # rank 18
        self.assertEqual(findings[2]["confidence"], "POSSIBLE") # priority 3

    def test_severity_and_confidence_are_decoupled(self):
        # COD-C1A #1408: a high-CONFIDENCE (priority 1) but low-SEVERITY (rank 19)
        # bug must NOT be relabelled HIGH severity, and a genuinely severe
        # (rank 1) but less-certain (priority 3) bug must NOT be buried as LOW.
        sample = b"""<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6" sequence="0" timestamp="0" analysisTimestamp="0" release="">
  <BugInstance type="STYLE_NIT" rank="19" priority="1" category="STYLE">
    <Class classname="com.example.A"><SourceLine sourcepath="com/example/A.java" start="1"/></Class>
  </BugInstance>
  <BugInstance type="COMMAND_INJECTION" rank="1" priority="3" category="SECURITY">
    <Class classname="com.example.B"><SourceLine sourcepath="com/example/B.java" start="2"/></Class>
  </BugInstance>
</BugCollection>
"""
        a, b = sb.SpotBugsAdapter().parse(sample, "g1")
        self.assertEqual((a["severity"], a["confidence"]), ("LOW", "CERTAIN"))
        self.assertEqual((b["severity"], b["confidence"]), ("CRITICAL", "POSSIBLE"))

    def test_missing_rank_and_priority_fall_back_neutrally(self):
        # No rank -> neutral MEDIUM (never borrow the confidence signal); no
        # priority -> conservative POSSIBLE, matching the brakeman default.
        sample = b"""<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6" sequence="0" timestamp="0" analysisTimestamp="0" release="">
  <BugInstance type="COMMAND_INJECTION" category="SECURITY">
    <Class classname="com.example.C"><SourceLine sourcepath="com/example/C.java" start="3"/></Class>
  </BugInstance>
</BugCollection>
"""
        f = only(sb.SpotBugsAdapter().parse(sample, "g1"))
        self.assertEqual(f["severity"], "MEDIUM")
        self.assertEqual(f["confidence"], "POSSIBLE")

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

    def test_parse_bug_instance_without_source_line(self):
        # ARC-A4A: SpotBugsAdapter.DROP_IF_NO_LOCATION is False, so a finding
        # with no <SourceLine> is kept with a synthesized path. SpotBugs sometimes
        # omits SourceLine entirely; the adapter must still emit a finding
        # (#1196), and #run7 COD-C3A: derive location.file from the
        # <Class classname> so it stays matchable by the delta/--pr gate instead
        # of an empty, unscopable path.
        sample = b"""<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6" sequence="0" timestamp="0" analysisTimestamp="0" release="">
  <BugInstance type="COMMAND_INJECTION" priority="1" category="SECURITY">
    <Class classname="com.example.App"/>
  </BugInstance>
</BugCollection>
"""
        findings = sb.SpotBugsAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["location"]["file"], "com/example/App.java")
        self.assertEqual(findings[0]["location"]["line_start"], 1)
        self.assertIn("CWE-78", findings[0]["citations"]["cwe"])

    def test_parse_malformed_xml_raises(self):
        # Malformed tool output should surface as a parse error rather than be
        # silently swallowed (#1196).
        with self.assertRaises(ParseError):
            sb.SpotBugsAdapter().parse(b"<not-xml", "g1")


class TestHardenedXmlParser(unittest.TestCase):
    def test_defusedxml_is_preferred_over_stdlib(self):
        # Regression: adding the offline prefix trim mangled the
        # try/except import, leaving `import xml.etree.ElementTree as ET`
        # running UNCONDITIONALLY at module level -- so ET was the
        # unhardened stdlib parser even though defusedxml is installed in
        # the image. Tool output is untrusted (target-controlled strings),
        # and the trim makes MORE of it reach the parser, so the hardened
        # parser matters more after that change, not less.
        import importlib.util
        if importlib.util.find_spec("defusedxml") is None:
            self.skipTest("defusedxml not installed on this host")
        self.assertIn("defusedxml", sb.ET.__name__,
                      "spotbugs must parse untrusted XML with defusedxml when "
                      "it is available; the stdlib parser is the fallback only")

    def test_the_import_is_a_guarded_fallback_not_an_override(self):
        # Assert the SHAPE, so a future edit cannot silently re-flatten it:
        # the stdlib import must live inside the except branch.
        import inspect
        src = inspect.getsource(sb)
        head = src[:src.index("from .base import")]
        self.assertIn("except ImportError:\n    import xml.etree.ElementTree", head,
                      "the stdlib XML import must stay INSIDE the ImportError "
                      "fallback, not run unconditionally")


class TestOfflineLogPrefix(unittest.TestCase):
    """#calibration-6: spotbugs output is unparseable under `--network none`.

    spotbugs runs on a JVM. With no DNS it cannot resolve the container
    hostname, so log4j writes `ERROR Could not determine local host name ...
    UnknownHostException` to STDOUT ahead of the report, and `ET.fromstring`
    dies with `syntax error: line 1, column 0` -- losing the entire Java axis.

    Measured: online the XML starts at byte 0 and parses; offline it does not.
    The fixture suite passed only because it ran WITH network, which is the
    third time an environment difference between fixtures and real scans hid a
    broken scanner (gosec #1457, roslyn #1469, this).
    """

    XML = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
           b'<BugCollection version="4.8.6">'
           b'<BugInstance type="SQL_INJECTION" priority="1">'
           b'<Class classname="com.x.A"/>'
           b'<SourceLine sourcepath="com/x/A.java" start="7"/>'
           b'</BugInstance></BugCollection>')
    NOISE = (b'2026-09-02T00:07:08Z main ERROR Could not determine local host '
             b'name java.net.UnknownHostException: a1e47b6b3be5\n'
             b'\tat java.base/java.net.InetAddress.getLocalHost\n')

    def test_log_prefixed_output_still_parses(self):
        a = sb.SpotBugsAdapter()
        clean = a.parse(self.XML, "g1")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            prefixed = a.parse(self.NOISE + self.XML, "g1")
        self.assertEqual(len(prefixed), len(clean), "log prefix cost us findings")
        self.assertEqual(len(prefixed), 1)
        self.assertIn("stripped", err.getvalue(),
                      "stripping a prefix should be disclosed, not silent")

    def test_clean_output_is_untouched(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            out = sb.SpotBugsAdapter().parse(self.XML, "g1")
        self.assertEqual(len(out), 1)
        self.assertEqual(err.getvalue(), "",
                         "no prefix to strip -> no note")

    def test_noise_with_no_report_still_fails(self):
        # A trim must not turn "the scanner produced no report" into "the
        # scanner found nothing" -- that is the silent-zero class this whole
        # series exists to stamp out. No XML at all is a FAILURE.
        with self.assertRaises(ParseError):
            sb.SpotBugsAdapter().parse(self.NOISE, "g1")

    def test_a_stray_angle_bracket_is_not_mistaken_for_the_report(self):
        # Anchored to the document start, not to any '<'.
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            out = sb.SpotBugsAdapter().parse(
                b"WARN generic<T> in log line\n" + self.XML, "g1")
        self.assertEqual(len(out), 1)



if __name__ == "__main__":
    unittest.main()


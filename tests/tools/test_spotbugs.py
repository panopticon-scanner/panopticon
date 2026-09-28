import contextlib
import io
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from tests._test_helpers import first, only
from unittest import mock
from xml.etree.ElementTree import ParseError

import scripts.tools.base as base
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
    def test_invoke_uses_compiled_classes_plugin_xml_and_isolated_cwd(self):
        with self.subTest("compiled target"):
            from tempfile import TemporaryDirectory
            with TemporaryDirectory() as root:
                target = Path(root)
                classes = target / "target" / "classes"
                classes.mkdir(parents=True)
                home = target / "installed spotbugs"
                scratch = target / "isolated cwd"
                scratch.mkdir()
                captured = {}

                def fake_run(argv, **kwargs):
                    captured.update(argv=argv, kwargs=kwargs)
                    return b"<BugCollection/>", 0

                with mock.patch.dict(os.environ, {"SPOTBUGS_HOME": str(home)}), \
                     mock.patch.object(sb, "scratch_cwd", return_value=contextlib.nullcontext(str(scratch))) as isolated, \
                     mock.patch.object(sb, "run_tool", side_effect=fake_run):
                    result = sb.SpotBugsAdapter().invoke(str(target))
                isolated.assert_called_once_with("spotbugs-cwd-")
                self.assertEqual(result, (b"<BugCollection/>", 0))
                self.assertEqual(captured["argv"], [
                    str(home / "bin" / "spotbugs"), "-textui", "-xml", "-pluginList",
                    str(home / "plugin" / "findsecbugs-plugin.jar"), str(classes),
                ])
                self.assertEqual(captured["kwargs"], {"timeout": 600, "cwd": str(scratch)})

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


class TestTheBugsOwnSourceLine(unittest.TestCase):
    """#2188: a BugInstance's line is its OWN <SourceLine>, not its class's.

    SpotBugs nests a <SourceLine> inside the enclosing <Class> (the class's
    whole span, so its `start` is the class's first line) and another inside
    each <Method>, then emits the bug's own as a DIRECT child. `.//SourceLine`
    returns the first in DOCUMENT order, which is always the class's -- so on
    the pinned golden all three findings landed on line 11 of a class that
    spans 11-75, about 54 lines from the code each is about.
    """

    GOLDEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "goldens", "tool-raw", "spotbugs.raw")

    # The golden's shape, trimmed: class span, method span, then the bug's own.
    NESTED = b"""<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6">
  <BugInstance type="COMMAND_INJECTION" rank="12" priority="2">
    <Class classname="org.dummy.Holder">
      <SourceLine classname="org.dummy.Holder" start="11" end="75" sourcepath="org/dummy/Holder.java"/>
    </Class>
    <Method classname="org.dummy.Holder" name="readObject">
      <SourceLine classname="org.dummy.Holder" start="46" end="75" sourcepath="org/dummy/Holder.java"/>
    </Method>
    <SourceLine classname="org.dummy.Holder" start="65" end="65" sourcepath="org/dummy/Holder.java"/>
  </BugInstance>
</BugCollection>
"""

    def test_the_bugs_own_source_line_beats_the_class_and_method_spans(self):
        f = only(sb.SpotBugsAdapter().parse(self.NESTED, "g1"))
        self.assertEqual(65, f["location"]["line_start"])
        self.assertEqual("org/dummy/Holder.java", f["location"]["file"])

    def test_a_bug_with_only_a_class_source_line_falls_back_to_it(self):
        # The class's span is still better than nothing: it names the file and
        # the class's first line, which is what SpotBugs itself offers here.
        sample = b"""<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6">
  <BugInstance type="COMMAND_INJECTION" rank="12" priority="2">
    <Class classname="org.dummy.Holder">
      <SourceLine classname="org.dummy.Holder" start="11" end="75" sourcepath="org/dummy/Holder.java"/>
    </Class>
  </BugInstance>
</BugCollection>
"""
        f = only(sb.SpotBugsAdapter().parse(sample, "g1"))
        self.assertEqual(11, f["location"]["line_start"])
        self.assertEqual("org/dummy/Holder.java", f["location"]["file"])

    def test_a_called_methods_source_line_is_never_the_bugs(self):
        # DM_DEFAULT_ENCODING in the golden carries a <Method role="METHOD_CALLED">
        # for java.io.InputStreamReader, whose SourceLine names a JDK file that
        # is in no repository at all. Only the bug's own direct child counts.
        sample = b"""<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6">
  <BugInstance type="DM_DEFAULT_ENCODING" rank="19" priority="1">
    <Class classname="org.dummy.Holder">
      <SourceLine classname="org.dummy.Holder" start="11" end="75" sourcepath="org/dummy/Holder.java"/>
    </Class>
    <Method classname="java.io.InputStreamReader" name="&lt;init&gt;" role="METHOD_CALLED">
      <SourceLine classname="java.io.InputStreamReader" start="88" end="91" sourcepath="java/io/InputStreamReader.java"/>
    </Method>
    <SourceLine classname="org.dummy.Holder" start="66" end="66" sourcepath="org/dummy/Holder.java"/>
  </BugInstance>
</BugCollection>
"""
        f = only(sb.SpotBugsAdapter().parse(sample, "g1"))
        self.assertEqual("org/dummy/Holder.java", f["location"]["file"])
        self.assertEqual(66, f["location"]["line_start"])

    def test_the_goldens_three_findings_land_on_their_own_lines(self):
        # Real captured output, so this is the claim that actually matters:
        # 65, 69 and 66 are what the three BugInstances' own SourceLines say.
        with open(self.GOLDEN, "rb") as fh:
            raw = fh.read()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            findings = sb.SpotBugsAdapter().parse(raw, "g1")
        self.assertEqual(
            [("COMMAND_INJECTION", 65), ("CRLF_INJECTION_LOGS", 69),
             ("DM_DEFAULT_ENCODING", 66)],
            [(f["title"], f["location"]["line_start"]) for f in findings])


class TestTheStartLineIsAlwaysSchemaLegal(unittest.TestCase):
    """Review finding 3: `report-schema.json` gives `location.line_start`
    `minimum: 1`, and the normalization contract's `TestFindingsSurviveIntoAReport`
    proves tool findings really are validated against it -- so ONE unusable
    `SourceLine start` must not invalidate the whole report.

    `-1` is not a hostile value: it is SpotBugs' own `SourceLineAnnotation`
    sentinel for an unknown line, which a class compiled without line-number
    debug info (or a synthetic location) produces. `0` slips past a `>= 0`
    assertion and fails the schema the same way. `abc` used to raise
    `ValueError` out of `parse`, and `ingest_tools`' tolerant `except Exception`
    turns that into "unparseable" and loses the ENTIRE spotbugs document.
    """

    @staticmethod
    def _report(start):
        attribute = "" if start is None else ' start="%s"' % start
        return ('<?xml version="1.0" encoding="UTF-8"?>\n'
                '<BugCollection version="4.8.6">'
                '<BugInstance type="COMMAND_INJECTION" rank="12" priority="2">'
                '<Class classname="org.dummy.Holder"/>'
                '<SourceLine classname="org.dummy.Holder"'
                ' sourcepath="org/dummy/Holder.java"%s/>'
                '</BugInstance></BugCollection>' % attribute).encode()

    def _line_start(self, start):
        finding = only(sb.SpotBugsAdapter().parse(self._report(start), "g1"))
        return finding["location"]["line_start"]

    def test_spotbugs_own_unknown_line_sentinel_clamps_to_one(self):
        self.assertEqual(1, self._line_start("-1"))

    def test_a_zero_start_clamps_to_one(self):
        self.assertEqual(1, self._line_start("0"))

    def test_an_unparseable_start_clamps_to_one_instead_of_raising(self):
        # The whole-document loss is the cost of raising here, so this must not
        # be an `assertRaises`.
        self.assertEqual(1, self._line_start("abc"))

    def test_an_absent_start_is_one(self):
        self.assertEqual(1, self._line_start(None))

    def test_a_real_start_is_untouched(self):
        self.assertEqual(65, self._line_start("65"))


class TestSourcePathResolvesAgainstTheTargetRoot(unittest.TestCase):
    """ARC-284455831: `sourcepath` is SOURCE-ROOT relative, not repo-relative.

    SpotBugs reports `org/dummy/.../VulnerableTaskHolder.java` -- the package
    path -- while the file in a Maven or Gradle layout is at
    `src/main/java/org/dummy/.../VulnerableTaskHolder.java`. The delta/`--pr`
    gate and the advisor's read grant both resolve `location.file` against the
    repo root, so the package path places nothing. The target root reaches
    `parse` through `base.target_root_cv`, the way pip-audit's `_located_at`
    takes it.
    """

    SOURCEPATH = "org/dummy/insecure/framework/VulnerableTaskHolder.java"

    @staticmethod
    def _report(sourcepath, classname="org.dummy.insecure.framework.VulnerableTaskHolder"):
        return ('<?xml version="1.0" encoding="UTF-8"?>\n'
                '<BugCollection version="4.8.6">'
                '<BugInstance type="COMMAND_INJECTION" rank="12" priority="2">'
                '<Class classname="%s"/>'
                '<SourceLine classname="%s" start="65" end="65" sourcepath="%s"/>'
                '</BugInstance></BugCollection>'
                % (classname, classname, sourcepath)).encode()

    def _pin_root(self, root):
        token = base.target_root_cv.set(root)
        self.addCleanup(base.target_root_cv.reset, token)

    @staticmethod
    def _write(root, *relatives):
        for relative in relatives:
            full = os.path.join(root, *relative.split("/"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write("// source\n")

    def _parse_one(self, sourcepath, **kwargs):
        return only(sb.SpotBugsAdapter().parse(self._report(sourcepath, **kwargs), "g1"))

    def test_a_maven_source_root_makes_the_location_repo_relative(self):
        with TemporaryDirectory() as root:
            self._write(root, "src/main/java/" + self.SOURCEPATH)
            self._pin_root(root)
            f = self._parse_one(self.SOURCEPATH)
        self.assertEqual("src/main/java/" + self.SOURCEPATH, f["location"]["file"])
        self.assertNotIn("path_resolution", f["tool_evidence"])

    def test_every_conventional_source_root_is_probed(self):
        for prefix in ("src/main/java", "src/test/java", "src", ""):
            with self.subTest(source_root=prefix or "<target root>"):
                relative = ("%s/%s" % (prefix, self.SOURCEPATH)) if prefix else self.SOURCEPATH
                with TemporaryDirectory() as root:
                    self._write(root, relative)
                    self._pin_root(root)
                    f = self._parse_one(self.SOURCEPATH)
                self.assertEqual(relative, f["location"]["file"])
                self.assertNotIn("path_resolution", f["tool_evidence"])

    def test_the_first_matching_source_root_wins(self):
        # A project with both trees: main is the one SpotBugs analyzed, and
        # probing in a fixed order is what keeps the answer deterministic.
        with TemporaryDirectory() as root:
            self._write(root, "src/test/java/" + self.SOURCEPATH,
                        "src/main/java/" + self.SOURCEPATH)
            self._pin_root(root)
            f = self._parse_one(self.SOURCEPATH)
        self.assertEqual("src/main/java/" + self.SOURCEPATH, f["location"]["file"])

    def test_a_directory_of_the_same_name_is_not_a_match(self):
        # `isfile`, not `exists`: a package directory that happens to share the
        # name would otherwise "resolve" to something no diff hunk can hold.
        with TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "src", "main", "java",
                                     *self.SOURCEPATH.split("/")))
            self._pin_root(root)
            f = self._parse_one(self.SOURCEPATH)
        self.assertEqual(self.SOURCEPATH, f["location"]["file"])
        self.assertEqual("unresolved", f["tool_evidence"]["path_resolution"])

    def test_an_unmatched_sourcepath_is_kept_and_disclosed(self):
        with TemporaryDirectory() as root:
            self._pin_root(root)
            f = self._parse_one(self.SOURCEPATH)
        self.assertEqual(self.SOURCEPATH, f["location"]["file"])
        self.assertEqual("unresolved", f["tool_evidence"]["path_resolution"])

    def test_no_target_root_keeps_the_sourcepath_and_discloses(self):
        # The CI gate parses captured bytes with no tree in reach; the finding
        # must still be emitted, and must say why it cannot be placed.
        f = self._parse_one(self.SOURCEPATH)
        self.assertEqual(self.SOURCEPATH, f["location"]["file"])
        self.assertEqual("unresolved", f["tool_evidence"]["path_resolution"])

    def test_a_resolved_path_carries_no_disclosure(self):
        with TemporaryDirectory() as root:
            self._write(root, "src/" + self.SOURCEPATH)
            self._pin_root(root)
            f = self._parse_one(self.SOURCEPATH)
        self.assertEqual("src/" + self.SOURCEPATH, f["location"]["file"])
        self.assertEqual({"rule_id": "COMMAND_INJECTION"}, f["tool_evidence"])

    def test_a_hostile_sourcepath_never_escapes_the_root(self):
        # `sourcepath` comes from the TARGET's own bytecode debug info, and
        # `location.file` steers the advisor's read grant (#1096), so an
        # escaping path is refused outright rather than published.
        hostile = ("../../../../../../etc/passwd", "/etc/passwd",
                   "src/../../outside.java")
        for sourcepath in hostile:
            with self.subTest(sourcepath=sourcepath):
                with TemporaryDirectory() as root:
                    self._pin_root(root)
                    f = self._parse_one(sourcepath, classname="")
                self.assertEqual("", f["location"]["file"])
                self.assertEqual("unresolved", f["tool_evidence"]["path_resolution"])

    def test_a_hostile_sourcepath_still_leaves_the_classname_fallback(self):
        with TemporaryDirectory() as root:
            self._pin_root(root)
            f = self._parse_one("/etc/passwd")
        self.assertEqual("org/dummy/insecure/framework/VulnerableTaskHolder.java",
                         f["location"]["file"])
        self.assertEqual("unresolved", f["tool_evidence"]["path_resolution"])

    def test_a_symlinked_package_is_not_followed_out_of_the_root(self):
        # An in-tree symlink whose lexical path stays under the root but whose
        # target does not: the #run7 ARC-F2A shape, refused by realpath.
        #
        # The symlink points at `outside` ITSELF, so the probe path really does
        # resolve to a readable file -- asserted below before the parse, which
        # is what stops this test going vacuous. A link to `outside/dummy`
        # would double the `dummy` segment, leave the probe path absent, and
        # pass on `lexists` alone with the confinement check never called.
        with TemporaryDirectory() as outside, TemporaryDirectory() as root:
            self._write(outside, "dummy/insecure/framework/VulnerableTaskHolder.java")
            os.makedirs(os.path.join(root, "src", "main", "java"))
            os.symlink(outside, os.path.join(root, "src", "main", "java", "org"))
            self.assertTrue(
                os.path.isfile(os.path.join(root, "src", "main", "java",
                                            *self.SOURCEPATH.split("/"))),
                "the escaping path must resolve to a readable file, or this "
                "test proves absence rather than refusal")
            self._pin_root(root)
            f = self._parse_one(self.SOURCEPATH)
        self.assertEqual(self.SOURCEPATH, f["location"]["file"])
        self.assertEqual("unresolved", f["tool_evidence"]["path_resolution"])

    def test_a_dangling_symlink_is_not_a_match(self):
        with TemporaryDirectory() as root:
            full = os.path.join(root, "src", "main", "java", *self.SOURCEPATH.split("/"))
            os.makedirs(os.path.dirname(full))
            os.symlink(os.path.join(root, "gone.java"), full)
            self._pin_root(root)
            f = self._parse_one(self.SOURCEPATH)
        self.assertEqual(self.SOURCEPATH, f["location"]["file"])
        self.assertEqual("unresolved", f["tool_evidence"]["path_resolution"])

    def test_the_classname_fallback_resolves_the_same_way(self):
        # #run7 COD-C3A derived a path from <Class classname> so a SourceLine-less
        # finding stayed matchable. A package path is not a repo path, so the
        # derivation only delivers that once it has been resolved too.
        sample = b"""<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6">
  <BugInstance type="COMMAND_INJECTION" priority="1">
    <Class classname="com.example.App"/>
  </BugInstance>
</BugCollection>
"""
        with TemporaryDirectory() as root:
            self._write(root, "src/main/java/com/example/App.java")
            self._pin_root(root)
            f = only(sb.SpotBugsAdapter().parse(sample, "g1"))
        self.assertEqual("src/main/java/com/example/App.java", f["location"]["file"])
        self.assertEqual(1, f["location"]["line_start"])
        self.assertNotIn("path_resolution", f["tool_evidence"])


class TestHardenedXmlParser(unittest.TestCase):
    @staticmethod
    def _entity_report(declaration):
        return ('<?xml version="1.0"?>\n<!DOCTYPE BugCollection [' + declaration + ']>'
                '<BugCollection><BugInstance type="&probe;" priority="1">'
                '<Class classname="example.Probe"/></BugInstance></BugCollection>').encode()

    def test_required_hardened_parser_rejects_internal_entities(self):
        # defusedxml is a declared runtime dependency: its absence is a failure,
        # not a skipped security assertion. Stdlib expands this tiny inert value.
        from defusedxml.common import EntitiesForbidden
        self.assertEqual(len(sb.SpotBugsAdapter().parse(SPOTBUGS_SAMPLE, "g1")), 1)
        payload = self._entity_report('<!ENTITY probe "INERT_ENTITY_SENTINEL">')
        with self.assertRaises(EntitiesForbidden):
            sb.SpotBugsAdapter().parse(payload, "g1")

    def _assert_external_entities_refused_without_io(self, adapter, error):
        import socket
        import urllib.request
        for uri in ("file:///nonexistent-panopticon-entity-probe", "https://example.invalid/entity"):
            payload = self._entity_report('<!ENTITY probe SYSTEM "' + uri + '">')
            with self.subTest(uri=uri), \
                    mock.patch("builtins.open", side_effect=AssertionError("unexpected file read")) as opened, \
                    mock.patch.object(socket, "socket", side_effect=AssertionError("unexpected network")) as network, \
                    mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("unexpected HTTP")) as http:
                with self.assertRaises(error):
                    adapter.parse(payload, "g1")
                opened.assert_not_called()
                network.assert_not_called()
                http.assert_not_called()

    def test_hardened_parser_refuses_external_entities_without_io(self):
        from defusedxml.common import EntitiesForbidden
        self._assert_external_entities_refused_without_io(sb.SpotBugsAdapter(), EntitiesForbidden)

    def test_missing_dependency_fallback_parses_benign_xml_and_refuses_external_entities(self):
        # Fresh isolated module namespace; do not rebind the imported adapter
        # used by other tests. This documents the current fallback, not a claim
        # that it offers defusedxml's internal-entity protection.
        import builtins
        import importlib.util
        original_import = builtins.__import__

        def without_defusedxml(name, *args, **kwargs):
            if name.startswith("defusedxml"):
                raise ImportError("forced missing optional import")
            return original_import(name, *args, **kwargs)

        spec = importlib.util.spec_from_file_location("scripts.tools._spotbugs_fallback_test", sb.__file__)
        fallback = importlib.util.module_from_spec(spec)
        with mock.patch.object(builtins, "__import__", side_effect=without_defusedxml):
            spec.loader.exec_module(fallback)
        adapter = fallback.SpotBugsAdapter()
        finding = only(adapter.parse(SPOTBUGS_SAMPLE, "g1"))
        self.assertEqual(finding["title"], "SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE")
        self._assert_external_entities_refused_without_io(adapter, ParseError)


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

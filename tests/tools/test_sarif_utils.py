"""#2234 (ARC-1496429894 sub-defect): the pin the mirror comment asked for.

`scripts/tools/sarif_utils.py` hand-mirrors the orchestrator's test-fixture
corpus definition -- `FIXTURE_DIR_BASENAMES`, `FIXTURE_PARENT_DIRS` and the
predicate over them -- because the module exists to break the import cycle back
to `ingest_tools` and cannot reach `discovery`. The mirror carried a comment
saying "update both places together" and nothing else: a grep for either name
over `tests/` returned zero hits, so the only guard on the #434 parity was the
comment.

Drift is silent and one-sided. The agentic review path prunes a fixture corpus
in standard mode (`discovery.prune_fixture_files`); the tool scanners walk the
whole repo and report real fixture paths, and `ingest_tools` prunes them here.
A basename added on one side only means the tool axis keeps reporting planted
fixture vulnerabilities that the review axis drops -- run-3 measured 67 such
findings, 11 of them CRITICAL, all planted noise.

So both halves are pinned: the two frozensets, value for value, and the two
PREDICATES over them, on a table of paths that covers each rule (a corpus
basename, a `fixtures` dir under each kind of test parent, ordinary source, and
a test file that is NOT a fixture).
"""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import scripts.discovery as discovery
import scripts.ingest_tools as ingest
import scripts.security_gate as gate
import scripts.tools.sarif_utils as su
from scripts.synth import findings as findings_mod, plan, report, tool_axis
from tests._test_helpers import only


def _discovery_says(path):
    """`discovery`'s verdict on a FILE path, composed the way discovery asks it.

    The two predicates take different arguments. `su._is_fixture_path` takes the
    file and walks its own ancestors; `discovery._is_fixture_dir` answers about
    ONE directory, and `discovery.prune_fixture_files` is what walks the
    ancestors (`_ancestor_dirs`). Composing those two here asks the same
    question of the same definition, so a disagreement is drift and not a
    difference of calling convention.
    """
    return any(discovery._is_fixture_dir(d) for d in discovery._ancestor_dirs(path))


class TestFixtureCorpusMirror(unittest.TestCase):
    def test_corpus_basenames_mirror_discovery(self):
        self.assertEqual(
            su._FIXTURE_DIR_BASENAMES, discovery.FIXTURE_DIR_BASENAMES,
            "sarif_utils mirrors discovery's fixture-corpus basenames; they "
            "have drifted")

    def test_corpus_parent_dirs_mirror_discovery(self):
        self.assertEqual(
            su._FIXTURE_PARENT_DIRS, discovery.FIXTURE_PARENT_DIRS,
            "sarif_utils mirrors discovery's fixture-corpus parent dirs; they "
            "have drifted")

    def test_both_predicates_agree_on_the_corpus(self):
        for path, fixture in (("tests/fixtures/x.py", True),
                              ("testdata/x.py", True),
                              ("spec/fixtures/x.py", True),
                              ("src/x.py", False),
                              ("tests/x_test.py", False)):
            with self.subTest(path=path):
                self.assertEqual(su._is_fixture_path(path), fixture)
                self.assertEqual(_discovery_says(path), fixture)

    def test_the_comparison_reports_a_divergence(self):
        # The guard is only as good as its detector: prove it fires. With
        # `spec` dropped from discovery's parent dirs, `spec/fixtures/x.py` is a
        # fixture to the tool path and ordinary code to the agentic path --
        # exactly the one-sided drift the mirror comment warns about, and the
        # table above goes red on it.
        with mock.patch.object(discovery, "FIXTURE_PARENT_DIRS",
                               frozenset({"tests", "test"})):
            self.assertTrue(su._is_fixture_path("spec/fixtures/x.py"))
            self.assertFalse(_discovery_says("spec/fixtures/x.py"))


def _native_capture(tool):
    """Small valid native records; every malformed variant changes these shapes."""
    if tool == "osv-scanner":
        return {"results": [{"source": {"path": "/src/app.lock"}, "packages": [{
            "package": {"name": "dep", "version": "1", "ecosystem": "PyPI"},
            "vulnerabilities": [{"id": "CVE-2026-12345", "summary": "advisory",
                                 "database_specific": {"severity": "HIGH"}}],
        }]}]}
    return {"runs": [{"results": [{
        "ruleId": "SCS0002", "level": "error", "message": {"text": "SQL injection"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "app.cs"}, "region": {"startLine": 3}}}],
    }]}]}


class TestMalformedNativeCaptures(unittest.TestCase):
    """#2105: exercise ingestion and consumers, with no scanner subprocesses."""

    def _ingest(self, tool, payload):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / (tool + ".json")).write_text(json.dumps(payload))
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                findings, dispositions = ingest.ingest_dir_detailed(directory, "g1")
        return findings, dispositions[tool], stderr.getvalue()

    def test_valid_empty_captures_are_complete_and_quiet(self):
        for tool, payload in (("osv-scanner", {"results": []}),
                              ("roslyn-secguard", {"runs": []}),
                              ("roslyn-secguard", {"runs": [{"results": []}]})):
            with self.subTest(tool=tool, payload=payload):
                findings, disposition, diagnostic = self._ingest(tool, payload)
                self.assertEqual(findings, [])
                self.assertEqual(disposition["status"], "empty")
                self.assertEqual(disposition["file_coverage"]["status"], "complete")
                self.assertEqual(disposition["file_coverage"]["malformed_records"], 0)
                self.assertEqual(diagnostic, "")

    def test_invalid_envelopes_are_failed_captures(self):
        for tool, key in (("osv-scanner", "results"), ("roslyn-secguard", "runs")):
            for payload in (None, [], {}, {key: {}}, {key: "private capture"}, {key: None}):
                with self.subTest(tool=tool, payload=payload):
                    findings, disposition, diagnostic = self._ingest(tool, payload)
                    self.assertEqual(findings, [])
                    self.assertEqual(disposition["status"], "failed")
                    self.assertIn("unparseable", disposition["reason"])
                    self.assertIn("ingest error", diagnostic)
                    self.assertNotIn("private capture", diagnostic)

    def test_issue_reproductions_are_partial_instead_of_silent_empty(self):
        cases = (
            ("osv-scanner", {"results": [{"source": {"path": "/src/x.lock"},
                "packages": [None, {"package": {"name": "p"},
                                    "vulnerabilities": [None]}]}]}, 1, 0),
            ("roslyn-secguard", {"runs": ["not-a-dict", None]}, 0, 2),
        )
        for tool, payload, files, unlocated in cases:
            with self.subTest(tool=tool):
                findings, disposition, diagnostic = self._ingest(tool, payload)
                facts = disposition["file_coverage"]
                self.assertEqual(findings, [])
                self.assertEqual(disposition["status"], "empty")
                self.assertEqual(facts["status"], "partial")
                self.assertEqual(facts["parsed_files"], 0)
                self.assertEqual(facts["unparsed_files"], files)
                self.assertEqual(facts["malformed_records"], 2)
                self.assertEqual(facts["unlocated_records"], unlocated)
                self.assertIn(tool + ": partial capture: 2 malformed record(s)", diagnostic)
                self.assertNotIn("not-a-dict", diagnostic)
                dispositions = {tool: disposition}
                published = report.build_report(report.ReportInputs(
                    run=report.RunConfig(target="t", fail_on="high", timestamp="2026-09-28T00:00:00Z"),
                    findings=findings_mod.FindingSet(findings=findings),
                    plan=plan.PlanInputs(scout_requested=[tool]),
                    tools=tool_axis.ToolAxis(
                        tools_ran=tool_axis.tools_ran_from_dispositions(dispositions),
                        dispositions=dispositions),
                ))
                self.assertEqual(published["meta"]["coverage"]["tools_file_partial"][tool], facts)
                self.assertFalse(published["summary"]["coverage_certified"])
                self.assertIn(tool, published["summary"]["coverage_note"])

    def test_malformed_siblings_preserve_high_findings_and_delta_eligibility(self):
        for tool, key in (("osv-scanner", "results"), ("roslyn-secguard", "runs")):
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as directory:
                payload = _native_capture(tool)
                expected, _, _ = self._ingest(tool, payload)
                payload[key] = [None, *payload[key], "private scanner text"]
                findings, disposition, diagnostic = self._ingest(tool, payload)
                self.assertEqual(findings, expected)
                self.assertEqual(only(findings)["severity"], "HIGH")
                self.assertEqual(disposition["status"], "ok")
                facts = disposition["file_coverage"]
                self.assertEqual(facts["status"], "partial")
                self.assertEqual((facts["parsed_files"], facts["unparsed_files"]), (1, 0))
                self.assertEqual(facts["unlocated_records"], 2)
                self.assertNotIn("private scanner text", diagnostic + json.dumps(disposition))
                manifest = {"selected": [tool], "produced": [tool], "missing": []}
                self.assertEqual(ingest.lost_required_coverage(manifest, {tool: disposition}), {})
                captures = Path(directory) / "captures"
                captures.mkdir()
                (captures / (tool + ".json")).write_text(json.dumps(payload))
                manifest_path = Path(directory) / "manifest.json"
                manifest_path.write_text(json.dumps(manifest))
                argv = ["--tools-dir", str(captures), "--manifest", str(manifest_path)]
                for baseline, expected_rc in ((False, 1), (True, 0)):
                    out, err = io.StringIO(), io.StringIO()
                    args = argv + (["--baseline-dir", str(captures),
                                    "--baseline-manifest", str(manifest_path)] if baseline else [])
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        rc = gate.main(args)
                    self.assertEqual(rc, expected_rc, err.getvalue() + out.getvalue())
                    self.assertIn("partial file coverage", err.getvalue())
                    self.assertNotIn("baseline unusable", err.getvalue())

    def test_partial_facts_and_diagnostics_are_bounded_without_inventing_files(self):
        tool = "osv-scanner"
        payload = {"results": [{"source": {"path": "/src/" + str(i) + "x" * 400 + "\n.lock"},
                                "packages": [None, None]} for i in range(125)] + [None] * 150}
        findings, disposition, diagnostic = self._ingest(tool, payload)
        facts = disposition["file_coverage"]
        self.assertEqual(findings, [])
        self.assertEqual((facts["malformed_records"], facts["unlocated_records"]), (400, 150))
        self.assertEqual((facts["parsed_files"], facts["unparsed_files"]), (0, 125))
        self.assertEqual(len(facts["files"]), 100)
        self.assertEqual(facts["files_omitted"], 25)
        self.assertEqual(len(facts["records"]), 100)
        self.assertEqual(facts["records_omitted"], 300)
        self.assertTrue(all(len(row["file"]) <= 240 and "\n" not in row["file"]
                            for row in facts["files"]))
        self.assertEqual(len(diagnostic.splitlines()), 1)
        self.assertLess(len(diagnostic), 300)
        self.assertNotIn("xxxx", diagnostic)

    def test_nested_osv_corruption_keeps_usable_records(self):
        good = only(_native_capture("osv-scanner")["results"])
        good_package = only(good["packages"])
        cases = [
            {"source": {"path": "/src/bad.lock"}, "packages": bad}
            for bad in (None, {}, "private scanner text")
        ] + [
            {"source": {"path": "/src/bad.lock"}, "packages": [bad]}
            for bad in (None, [], {"package": []}, {**good_package, "vulnerabilities": None},
                        {**good_package, "vulnerabilities": {}},
                        {**good_package, "vulnerabilities": [None, {}]})
        ]
        for bad in cases:
            with self.subTest(bad=bad):
                findings, disposition, diagnostic = self._ingest(
                    "osv-scanner", {"results": [bad, good]})
                self.assertEqual(len(findings), 1)
                self.assertEqual(only(findings)["location"]["file"], "app.lock")
                self.assertEqual(disposition["status"], "ok")
                facts = disposition["file_coverage"]
                self.assertEqual((facts["parsed_files"], facts["unparsed_files"]), (1, 1))
                self.assertEqual(facts["files"], [{"file": "bad.lock", "reason": "parse_error"}])
                self.assertIn("partial capture", diagnostic)

    def test_nested_roslyn_corruption_keeps_usable_records(self):
        good = only(only(_native_capture("roslyn-secguard")["runs"])["results"])
        cases = ([{"results": value} for value in (None, {}, "private scanner text")]
                 + [{"results": [value, good]} for value in (
                     None, [], "private scanner text", {"ruleId": None},
                     {**good, "locations": {}}, {**good, "locations": "invalid"},
                     {**good, "locations": [None]},
                     {**good, "locations": [{"physicalLocation": "invalid"}]},
                     {**good, "locations": [{"physicalLocation": {"artifactLocation": []}}]},
                 )])
        for bad in cases:
            with self.subTest(bad=bad):
                payload = {"runs": [bad, {"results": [good]}]}
                findings, disposition, diagnostic = self._ingest("roslyn-secguard", payload)
                self.assertTrue(findings)
                self.assertTrue(all(f["tool_evidence"]["rule_id"] == "SCS0002" for f in findings))
                self.assertEqual(disposition["status"], "ok")
                self.assertEqual(disposition["file_coverage"]["status"], "partial")
                self.assertIn("partial capture", diagnostic)
                self.assertNotIn("private scanner text", diagnostic)

    def test_a_bad_record_does_not_erase_findings_from_the_same_file(self):
        for tool in ("osv-scanner", "roslyn-secguard"):
            payload = _native_capture(tool)
            if tool == "osv-scanner":
                only(only(payload["results"])["packages"])["vulnerabilities"].append(None)
            else:
                results = only(payload["runs"])["results"]
                results.append({**only(results), "ruleId": None})
            with self.subTest(tool=tool):
                findings, disposition, _ = self._ingest(tool, payload)
                self.assertEqual(len(findings), 1)
                facts = disposition["file_coverage"]
                self.assertEqual((facts["parsed_files"], facts["unparsed_files"]), (0, 1))
                self.assertEqual(facts["unlocated_records"], 0)


if __name__ == "__main__":
    unittest.main()

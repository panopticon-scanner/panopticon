import contextlib, io, os, json, tempfile, unittest
from unittest.mock import patch

import scripts.ingest_tools as it
import json as _json
import scripts.evidence as ev
import scripts.tools as tools_mod

SARIF = {
  "runs": [{
    "tool": {"driver": {"name": "semgrep", "rules": [
      {"id": "sql-injection", "properties": {"tags": ["CWE-89", "OWASP-A03"]}}]}},
    "results": [{
      "ruleId": "sql-injection", "level": "error",
      "message": {"text": "SQL injection"},
      "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "app/db.py"},
        "region": {"startLine": 42}}}]}]}]
}


class TestIngest(unittest.TestCase):
    def test_sarif_to_findings(self):
        out = it.sarif_to_findings(SARIF, "semgrep", "g1", "SG")
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual(f["source"], "tool:semgrep")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["confidence"], "CERTAIN")
        self.assertEqual(f["location"], {"file": "app/db.py", "line_start": 42})
        self.assertEqual(f["_group"], "g1")
        self.assertTrue(f["id"].startswith("SG-"))
        self.assertIn("CWE-89", f["citations"]["cwe"])

    def test_ingest_dir_tolerant(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "w") as fh:
                json.dump(SARIF, fh)
            with open(os.path.join(d, "broken.sarif"), "w") as fh:
                fh.write("{not json")
            out = it.ingest_dir(d, "g1")
            self.assertEqual(len(out), 1)

    def test_ingest_dir_skips_non_sarif_json_with_diagnostic(self):
        # Files without a registered adapter are skipped with a diagnostic.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "custom.json"), "w") as fh:
                json.dump({"findings": [{"id": "X-1"}]}, fh)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                out = it.ingest_dir(d, "g1")
            self.assertEqual(out, [])
            self.assertIn("custom.json", stderr.getvalue())
            self.assertIn("no adapter registered", stderr.getvalue())

    def test_ingest_dir_detailed_rejects_oversized_file(self):
        # #run7 OPS-D1A: a *.sarif/*.json above the byte cap is failed-closed,
        # not slurped whole into memory. (cap patched small to keep the test cheap)
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "wb") as fh:
                fh.write(b"x" * 400)
            stderr = io.StringIO()
            with mock.patch.object(it, "MAX_TOOL_OUTPUT_BYTES", 100):
                with contextlib.redirect_stderr(stderr):
                    findings, disp = it.ingest_dir_detailed(d, "g1")
        self.assertEqual(findings, [])
        self.assertEqual(disp["semgrep"]["status"], "failed")
        self.assertIn("oversize", disp["semgrep"]["reason"])
        self.assertIn("exceeds", stderr.getvalue())

    def test_sarif_uri_normalized_to_repo_relative(self):
        sarif = _sarif_fixture("file:///src/db/engine.py")
        out = it.sarif_to_findings(sarif, "semgrep", "g1", "SG")
        self.assertEqual(out[0]["location"]["file"], "db/engine.py")

    def test_ingest_dir_tolerant_of_structural_garbage(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "w") as fh:
                json.dump({"runs": [None]}, fh)
            with open(os.path.join(d, "trivy.sarif"), "w") as fh:
                json.dump({"runs": [{"results": [None]}]}, fh)
            self.assertEqual(it.ingest_dir(d, "g1"), [])  # skipped, no raise

    def test_sarif_bad_result_does_not_drop_siblings(self):
        sarif = _sarif_fixture("a.py")
        sarif["runs"][0]["results"].insert(0, 123)  # 123 is a malformed (non-dict) result
        out = it.sarif_to_findings(sarif, "semgrep", "g1", "SG")
        self.assertEqual(len(out), 1)      # the good result survives the bad sibling

    def test_sarif_mid_parse_exception_does_not_drop_siblings(self):
        # The result is dict-shaped (passes the isinstance guard) but its nested
        # "physicalLocation" is a string, not a dict -> .get() raises AttributeError
        # mid-processing. Without a per-result try/except this crashes the whole
        # function, discarding findings already collected for earlier results.
        sarif = _sarif_fixture("a.py")
        bad = {"ruleId":"bad","level":"warning","message":{"text":"m"},
               "locations":[{"physicalLocation": "not-a-dict"}]}
        sarif["runs"][0]["results"].append(bad)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            out = it.sarif_to_findings(sarif, "semgrep", "g1", "SG")
        self.assertEqual(len(out), 1)      # good survives; bad is skipped, not fatal
        self.assertIn("sarif_utils: skipping result bad:", stderr.getvalue())

    def test_ingest_dir_logs_skipped_file_to_stderr(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "broken.sarif"), "w") as fh:
                fh.write("{not json")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                out = it.ingest_dir(d, "g1")
            self.assertEqual(out, [])
            self.assertIn("broken.sarif", stderr.getvalue())

    def test_norm_uri_variants(self):
        self.assertEqual(it._norm_uri("file:///src/db/engine.py"), "db/engine.py")
        self.assertEqual(it._norm_uri("src/main.py"), "src/main.py")          # top-level src/ preserved
        self.assertEqual(it._norm_uri("backend/src/handlers/db.py"), "backend/src/handlers/db.py")
        self.assertEqual(it._norm_uri("app/db.py"), "app/db.py")
        self.assertEqual(it._norm_uri("/abs/x.py"), "abs/x.py")
        self.assertIsNone(it._norm_uri(None))

    def test_ingest_dir_survives_deeply_nested_json(self):
        with tempfile.TemporaryDirectory() as d:
            payload = "[" * 20000 + "]" * 20000
            with open(os.path.join(d, "semgrep.sarif"), "w") as fh:
                fh.write(payload)
            self.assertEqual(it.ingest_dir(d, "g1"), [])   # skipped, no RecursionError

    def test_ingest_filters_bandit_b101_and_test_paths(self):
        b101 = _sarif_fixture("tests/test_x.py")
        b101["runs"][0]["tool"]["driver"]["name"] = "bandit"
        b101["runs"][0]["results"][0].update(
            {"ruleId": "B101", "level": "note", "message": {"text": "assert used"}})
        b608 = _sarif_fixture("db/x.py")
        b608["runs"][0]["tool"]["driver"]["name"] = "bandit"
        b608["runs"][0]["results"][0].update(
            {"ruleId": "B608", "level": "warning", "message": {"text": "sql"}})
        sarif = {"runs": [{"tool": {"driver": {"name": "bandit", "rules": []}},
                           "results": b101["runs"][0]["results"] + b608["runs"][0]["results"]}]}
        out = it.sarif_to_findings(sarif, "bandit", "g1", "BN")
        ids = [f["category"] for f in out]
        self.assertNotIn("B101", ids)      # assert-noise dropped
        self.assertIn("B608", ids)         # real finding kept

    def test_sarif_findings_carry_first_class_rule_id(self):
        # #467: the SARIF path must set tool_evidence.rule_id like the
        # dependency adapters do -- provenance.confirmation_reasoning keeps
        # carrying it only as the back-compat fallback for old artifacts.
        out = it.sarif_to_findings(SARIF, "semgrep", "g1", "SG")
        f = out[0]
        self.assertEqual(f["tool_evidence"]["rule_id"], "sql-injection")
        self.assertEqual(ev.tool_rule_id(f), "sql-injection")

    def test_noise_rules_suppress_low_value_bandit_but_keep_backstop(self):
        # B404/B110/B112 are blunt heuristics -> suppressed on any codebase.
        # B603/B607 stay a tool-layer backstop for panel-less runs -> kept.
        def _res(rule):
            return {"ruleId": rule, "level": "warning", "message": {"text": rule},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "skill/scripts/orchestrator.py"},
                        "region": {"startLine": 9}}}]}
        sarif = {"runs": [{"tool": {"driver": {"name": "bandit", "rules": []}},
                           "results": [_res(r) for r in
                                       ("B404", "B110", "B112", "B603", "B607")]}]}
        ids = [f["category"] for f in it.sarif_to_findings(sarif, "bandit", "g1", "BN")]
        for suppressed in ("B404", "B110", "B112"):
            self.assertNotIn(suppressed, ids)
        for kept in ("B603", "B607"):
            self.assertIn(kept, ids)

    def test_ingest_preserves_nonnoise_bandit_under_test_path(self):
        # Non-noise bandit rules (e.g. B608) located in test paths are preserved (#1120)
        sarif = _sarif_fixture("tests/test_x.py")
        sarif["runs"][0]["tool"]["driver"]["name"] = "bandit"
        sarif["runs"][0]["results"][0]["ruleId"] = "B608"
        findings = it.sarif_to_findings(sarif, "bandit", "g1", "BN")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["category"], "B608")

    def test_ingest_real_semgrep_fixture(self):
        # tests/fixtures/ holds a realistic semgrep SARIF (one run, one rule,
        # one result) shaped from real semgrep output, with a container-mount-
        # prefixed artifactLocation.uri ("/src/..."); proves normalization
        # survives real tool output shape, not just hand-built test SARIF.
        here = os.path.dirname(__file__)
        out = it.ingest_dir(os.path.join(here, "fixtures"), "g1")
        self.assertTrue(out)
        for f in out:
            self.assertFalse(f["location"]["file"].startswith("/src"))
            self.assertFalse(f["location"]["file"].startswith("file://"))

    def test_sarif_message_with_control_chars_collapsed_in_title(self):
        sarif = _sarif_fixture("a.py")
        sarif["runs"][0]["results"][0]["message"]["text"] = "line one\nline\ttwo\r\nline three"
        out = it.sarif_to_findings(sarif, "semgrep", "g1", "SG")
        self.assertEqual(out[0]["title"], "line one line two line three")

    def test_ingest_tools_and_legacy_adapter_share_sarif_utils(self):
        # The legacy adapter and ingest_tools must both use the shared SARIF
        # utilities without a circular import between the two modules.
        import scripts.tools.legacy_sarif as ls
        import scripts.tools.sarif_utils as su
        self.assertTrue(hasattr(ls, "LegacySarifAdapter"))
        self.assertIs(it.sarif_to_findings, su.sarif_to_findings)
        self.assertEqual(it.PREFIX, su.PREFIX)


class TestAdapterRouting(unittest.TestCase):
    def test_ingest_routes_json_to_adapter(self):
        raw = json.dumps({"dependencies": [{"name": "x", "version": "1.0", "vulns": []}]})
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pip-audit.json"), "w") as fh:
                fh.write(raw)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                out = it.ingest_dir(d, "g1")
            self.assertEqual(out, [])
            self.assertNotIn("not SARIF", stderr.getvalue())
            self.assertNotIn("no adapter registered", stderr.getvalue())


class TestNonJsonPrefixTolerance(unittest.TestCase):
    """Calibration 2026-08-03: bandit's stdout progress bar preceded its SARIF;
    the trim must not behead array-payload tools (eslint emits a top-level list)."""

    def test_object_payload_with_progress_prefix_is_ingested(self):
        sarif = _sarif_fixture("a.py")
        sarif["runs"][0]["tool"]["driver"]["name"] = "Bandit"
        sarif["runs"][0]["results"] = []
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "bandit.sarif"), "wb") as fh:
                fh.write(b"Working... 100% 0:00:00\n" + json.dumps(sarif).encode())
            findings, disp = it.ingest_dir_detailed(d, "g1")
        self.assertEqual(findings, [])  # parsed cleanly (no results), not an error
        self.assertEqual(disp["bandit"]["status"], "empty")
        self.assertNotIn("not SARIF", disp["bandit"].get("reason", ""))

    def test_array_payload_is_not_trimmed(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "eslint-security.json"), "wb") as fh:
                fh.write(json.dumps([{"filePath": "/src/a.js", "messages": []}]).encode())
            findings, disp = it.ingest_dir_detailed(d, "g1")
        self.assertEqual(findings, [])  # array payload reaches the adapter intact
        self.assertEqual(disp["eslint-security"]["status"], "empty")
        self.assertNotIn("not SARIF", disp["eslint-security"].get("reason", ""))


def _sarif_fixture(path):
    return {"runs": [{"tool": {"driver": {"name": "t", "rules": []}},
                      "results": [{"ruleId": "R1", "level": "warning",
                                   "message": {"text": "m"},
                                   "locations": [{"physicalLocation": {
                                       "artifactLocation": {"uri": path},
                                       "region": {"startLine": 1}}}]}]}]}


class TestExcludeGlobs(unittest.TestCase):
    """F-CAL-2: fixture-noise exclusion is a standard ingest mechanism."""

    def test_excluded_paths_dropped_with_note(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "w") as fh:
                json.dump(_sarif_fixture("tests/fixtures/insecure-js/app.js"), fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                out = it.ingest_dir(d, "g1", exclude_globs=["tests/fixtures/*"])
        self.assertEqual(out, [])
        self.assertIn("excluded 1 finding", err.getvalue())

    def test_non_matching_paths_kept(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "w") as fh:
                json.dump(_sarif_fixture("skill/scripts/dispatch.py"), fh)
            out = it.ingest_dir(d, "g1", exclude_globs=["tests/fixtures/*"],
                                include_fixtures=True)
        self.assertEqual(len(out), 1)


class TestFixturePrune(unittest.TestCase):
    """Tool-path parity with the #434 agentic review prune: standard-mode
    ingestion drops findings located under a test-fixture corpus by default,
    so osv-scanner/trivy CVEs on the intentionally-vulnerable fixtures don't
    dominate a self-scan. Redteam (include_fixtures=True) keeps them."""

    def test_is_fixture_path(self):
        for p in ("tests/fixtures/vulnerable-node/package-lock.json",
                  "test/fixtures/x/main.rs",
                  "spec/fixtures/y.js",
                  "pkg/testdata/seed.json",
                  "app/__fixtures__/case.py"):
            self.assertTrue(it._is_fixture_path(p), p)
        for p in ("skill/scripts/orchestrator.py",
                  "tests/test_orchestrator.py",   # a test FILE is not a fixture corpus
                  "src/fixtures/real.py",         # 'fixtures' but parent not tests/test/spec
                  "package.json"):
            self.assertFalse(it._is_fixture_path(p), p)

    def test_fixture_findings_pruned_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "w") as fh:
                json.dump(_sarif_fixture("tests/fixtures/vulnerable-node/package-lock.json"), fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                out = it.ingest_dir(d, "g1")           # standard mode: no flag
        self.assertEqual(out, [])
        self.assertIn("test-fixture corpus", err.getvalue())

    def test_fixture_findings_kept_with_include_fixtures(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "w") as fh:
                json.dump(_sarif_fixture("tests/fixtures/vulnerable-node/package-lock.json"), fh)
            out = it.ingest_dir(d, "g1", include_fixtures=True)   # redteam
        self.assertEqual(len(out), 1)

    def test_non_fixture_findings_kept_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "w") as fh:
                json.dump(_sarif_fixture("skill/scripts/orchestrator.py"), fh)
            out = it.ingest_dir(d, "g1")
        self.assertEqual(len(out), 1)

    def test_glob_only_exclusion_note_does_not_blame_fixtures(self):
        # Honesty of the stderr note: when include_fixtures=True (prune off) and
        # only an exclude_glob matched, the note must not list "test-fixture
        # corpus" as a reason.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "w") as fh:
                json.dump(_sarif_fixture("vendor/gen.js"), fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                out = it.ingest_dir(d, "g1", exclude_globs=["vendor/*"],
                                    include_fixtures=True)
        self.assertEqual(out, [])
        self.assertIn("excluded 1 finding", err.getvalue())
        self.assertNotIn("test-fixture corpus", err.getvalue())


class TestIngestDispositions(unittest.TestCase):
    def _write(self, d, name, content):
        p = os.path.join(d, name)
        with open(p, "wb") as fh:
            fh.write(content if isinstance(content, bytes)
                     else content.encode("utf-8"))
        return p

    def test_ok_empty_and_failed_are_distinguished(self):
        with tempfile.TemporaryDirectory() as d:
            # bandit SARIF with one result -> ok
            sarif = _sarif_fixture("a.py")
            sarif["runs"][0]["tool"]["driver"]["name"] = "bandit"
            sarif["runs"][0]["tool"]["driver"]["rules"] = [{"id": "B105"}]
            sarif["runs"][0]["results"][0].update(
                {"ruleId": "B105", "level": "error", "message": {"text": "x"}})
            self._write(d, "bandit.sarif", _json.dumps(sarif))
            # valid SARIF, zero results -> empty
            empty = _sarif_fixture("a.py")
            empty["runs"][0]["tool"]["driver"]["name"] = "gitleaks"
            empty["runs"][0]["results"] = []
            self._write(d, "gitleaks.sarif", _json.dumps(empty))
            # 0-byte file -> failed
            self._write(d, "semgrep.sarif", b"")
            # unparseable -> failed
            self._write(d, "trivy.sarif", b"{not json")

            findings, disp = it.ingest_dir_detailed(d, "g1")

        self.assertEqual(disp["bandit"]["status"], "ok")
        self.assertGreaterEqual(disp["bandit"]["findings"], 1)
        self.assertEqual(disp["gitleaks"]["status"], "empty")
        self.assertEqual(disp["gitleaks"]["findings"], 0)
        self.assertEqual(disp["semgrep"]["status"], "failed")
        self.assertIn("empty output file", disp["semgrep"]["reason"])
        self.assertEqual(disp["trivy"]["status"], "failed")
        self.assertIn("unparseable", disp["trivy"]["reason"])

    def test_no_registered_adapter_is_failed(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "notatool.json", b"{}")
            _findings, disp = it.ingest_dir_detailed(d, "g1")
        self.assertEqual(disp["notatool"]["status"], "failed")
        self.assertIn("no registered adapter", disp["notatool"]["reason"])

    def test_empty_message_exception_does_not_crash_disposition_reason(self):
        # An adapter that raises with an EMPTY str(e) (e.g. a bare
        # ValueError("")) must still be tolerated: "".splitlines() == [],
        # so a naive str(e).splitlines()[0] raises IndexError from inside
        # the except handler itself, turning a supposed-to-be-tolerant skip
        # into a hard crash. Registers a real (if fake) adapter into
        # scripts.tools.ADAPTERS rather than mocking ingest_dir_detailed
        # itself, so the real except-handler code under test still runs.

        class _EmptyMessageAdapter:
            def parse(self, raw, group):
                raise ValueError("")

        with tempfile.TemporaryDirectory() as d:
            self._write(d, "emptymsgtool.sarif", b'{"x": 1}')
            with patch.dict(tools_mod.ADAPTERS,
                             {"emptymsgtool": _EmptyMessageAdapter()}):
                findings, disp = it.ingest_dir_detailed(d, "g1")  # must not raise

        self.assertEqual(findings, [])
        self.assertEqual(disp["emptymsgtool"]["status"], "failed")
        self.assertTrue(disp["emptymsgtool"]["reason"].startswith("unparseable:"))

    def test_ingest_dir_wrapper_returns_only_findings(self):
        with tempfile.TemporaryDirectory() as d:
            out = it.ingest_dir(d, "g1")
        self.assertEqual(out, [])  # unchanged contract: a bare list

    def test_ingest_strips_ansi_progress_preamble(self):
        # A tool (e.g. pip-audit's progress spinner) decorates its stdout with
        # ANSI CSI sequences before the JSON. The CSI introducer '\x1b[' must
        # not fool the first-JSON-token scan (its '[' would otherwise win).
        payload = {
            "dependencies": [
                {"name": "requests", "version": "2.0.0",
                 "vulns": [{"id": "PYSEC-0000-1", "description": "x",
                            "fix_versions": ["2.1"],
                            "aliases": ["CVE-0000-0001"]}]},
            ],
            "fixes": [],
        }
        ansi = b"\x1b[?25l\x1b[32m-\x1b[0m Collecting inputs\r\x1b[2K"
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pip-audit.json"), "wb") as fh:
                fh.write(ansi + json.dumps(payload).encode())
            findings = it.ingest_dir(d, "g1", include_fixtures=True)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["citations"]["cve"], ["CVE-0000-0001"])

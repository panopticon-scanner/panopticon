import contextlib, io, os, sys, json, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.ingest_tools as it

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
        # CD-003 regression: valid JSON that isn't SARIF (no 'runs') must be
        # skipped with a diagnostic, not silently dropped.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "custom.json"), "w") as fh:
                json.dump({"findings": [{"id": "X-1"}]}, fh)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                out = it.ingest_dir(d, "g1")
            self.assertEqual(out, [])
            self.assertIn("custom.json", stderr.getvalue())
            self.assertIn("not SARIF", stderr.getvalue())

    def test_sarif_uri_normalized_to_repo_relative(self):
        sarif = {"runs":[{"tool":{"driver":{"name":"semgrep","rules":[]}},
            "results":[{"ruleId":"r","level":"warning","message":{"text":"m"},
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///src/db/engine.py"},
            "region":{"startLine":10}}}]}]}]}
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
        good = {"ruleId":"r","level":"warning","message":{"text":"m"},
                "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":1}}}]}
        sarif = {"runs":[{"tool":{"driver":{"name":"semgrep","rules":[]}},
                 "results":[123, good]}]}   # 123 is a malformed (non-dict) result
        out = it.sarif_to_findings(sarif, "semgrep", "g1", "SG")
        self.assertEqual(len(out), 1)      # the good result survives the bad sibling

    def test_sarif_mid_parse_exception_does_not_drop_siblings(self):
        # The result is dict-shaped (passes the isinstance guard) but its nested
        # "physicalLocation" is a string, not a dict -> .get() raises AttributeError
        # mid-processing. Without a per-result try/except this crashes the whole
        # function, discarding findings already collected for earlier results.
        good = {"ruleId":"r","level":"warning","message":{"text":"m"},
                "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":1}}}]}
        bad = {"ruleId":"bad","level":"warning","message":{"text":"m"},
               "locations":[{"physicalLocation": "not-a-dict"}]}
        sarif = {"runs":[{"tool":{"driver":{"name":"semgrep","rules":[]}},
                 "results":[good, bad]}]}
        out = it.sarif_to_findings(sarif, "semgrep", "g1", "SG")
        self.assertEqual(len(out), 1)      # good survives; bad is skipped, not fatal

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
        sarif = {"runs":[{"tool":{"driver":{"name":"bandit","rules":[]}},
            "results":[
              {"ruleId":"B101","level":"note","message":{"text":"assert used"},
               "locations":[{"physicalLocation":{"artifactLocation":{"uri":"tests/test_x.py"},"region":{"startLine":3}}}]},
              {"ruleId":"B608","level":"warning","message":{"text":"sql"},
               "locations":[{"physicalLocation":{"artifactLocation":{"uri":"db/x.py"},"region":{"startLine":9}}}]}]}]}
        out = it.sarif_to_findings(sarif, "bandit", "g1", "BN")
        ids = [f["category"] for f in out]
        self.assertNotIn("B101", ids)      # assert-noise dropped
        self.assertIn("B608", ids)         # real finding kept

    def test_ingest_filters_nonnoise_bandit_under_test_path(self):
        # Exercises the _is_test_path OR-branch distinctly from NOISE_RULES:
        # a non-noise bandit rule (B608) located in a test file is dropped by
        # design (test-path suppression is bandit-wide, not just B101).
        sarif = {"runs": [{"tool": {"driver": {"name": "bandit", "rules": []}},
            "results": [{"ruleId": "B608", "level": "warning", "message": {"text": "sql"},
              "locations": [{"physicalLocation": {"artifactLocation": {"uri": "tests/test_x.py"},
                             "region": {"startLine": 9}}}]}]}]}
        self.assertEqual(it.sarif_to_findings(sarif, "bandit", "g1", "BN"), [])

    def test_ingest_real_semgrep_fixture(self):
        # tests/fixtures/ holds a trimmed but genuinely-real semgrep SARIF
        # (one run, one rule, one result) with a container-mount-prefixed
        # artifactLocation.uri ("/src/..."); proves normalization survives
        # real tool output, not just hand-built test SARIF.
        here = os.path.dirname(__file__)
        out = it.ingest_dir(os.path.join(here, "fixtures"), "g1")
        self.assertTrue(out)
        for f in out:
            self.assertFalse(f["location"]["file"].startswith("/src"))
            self.assertFalse(f["location"]["file"].startswith("file://"))

    def test_sarif_message_with_control_chars_collapsed_in_title(self):
        sarif = {"runs":[{"tool":{"driver":{"name":"semgrep","rules":[]}},
            "results":[{"ruleId":"r","level":"warning",
            "message":{"text":"line one\nline\ttwo\r\nline three"},
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},
            "region":{"startLine":1}}}]}]}]}
        out = it.sarif_to_findings(sarif, "semgrep", "g1", "SG")
        self.assertEqual(out[0]["title"], "line one line two line three")

    def test_ingest_tools_imports_legacy_adapter(self):
        # ingest_tools.py imports the legacy SARIF adapter at the top level as
        # preparation for Task 7 adapter routing.
        self.assertTrue(hasattr(it.scripts.tools.legacy_sarif, "LegacySarifAdapter"))

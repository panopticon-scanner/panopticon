import contextlib, io, os, json, tempfile, unittest
from unittest.mock import patch

import scripts.ingest_tools as it
from _test_helpers import first, only
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

    def _disposition_for(self, scanned, results):
        sarif = {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}},
                           "results": results}]}
        if scanned is not None:
            sarif["runs"][0]["properties"] = {"panopticon_scanned_files": scanned}
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "w") as fh:
                json.dump(sarif, fh)
            _, disp = it.ingest_dir_detailed(d, "g1")
        return disp["semgrep"]

    def test_scanned_zero_is_noscan_not_empty(self):
        # #1335: 0 files scanned is a silent no-op. Recording it as "empty"
        # credits SEC coverage semgrep never provided (false-clean).
        d = self._disposition_for(0, [])
        self.assertEqual(d["status"], "noscan")
        self.assertEqual(d["findings"], 0)
        self.assertIn("0 files", d.get("reason", ""))

    def test_scanned_some_files_with_no_findings_stays_empty(self):
        # A genuine clean run. Unchanged behaviour.
        self.assertEqual(self._disposition_for(137, [])["status"], "empty")

    def test_no_scanned_signal_stays_empty(self):
        # No annotation (older artifact, non-semgrep tool, unrecognised stderr)
        # must not become noscan -- absence of evidence is not evidence.
        self.assertEqual(self._disposition_for(None, [])["status"], "empty")

    def test_findings_outrank_a_zero_scan_count(self):
        # Contradictory artifact: trust the findings, which are proof of a scan.
        r = SARIF["runs"][0]["results"]
        self.assertEqual(self._disposition_for(0, r)["status"], "ok")

    def test_lost_required_coverage_names_absent_and_unusable_with_reasons(self):
        # #1512 / Codex BR-02: the manifest says a scanner produced bytes; the
        # dispositions say those bytes did not parse. Bytes on disk are not
        # coverage, and the two views have to be reconciled somewhere -- this is
        # the one definition, shared by the CI gate and the report.
        manifest = {"selected": ["bandit", "gitleaks", "npm-audit", "trivy"],
                    "produced": ["bandit", "gitleaks", "trivy"],
                    "missing": ["npm-audit"], "excluded_scope": ["eslint-security"]}
        dispositions = {
            "bandit": {"status": "failed", "findings": 0, "reason": "unparseable: x"},
            "gitleaks": {"status": "ok", "findings": 2},
            "trivy": {"status": "empty", "findings": 0},
        }
        lost = it.lost_required_coverage(manifest, dispositions)
        self.assertEqual(sorted(lost), ["bandit", "npm-audit"])
        self.assertEqual(lost["bandit"]["kind"], "unusable")
        self.assertIn("unparseable", lost["bandit"]["reason"])
        self.assertEqual(lost["npm-audit"]["kind"], "absent")
        self.assertNotIn("eslint-security", lost)   # excluded_scope is never required

    def test_lost_required_coverage_treats_a_selected_tool_with_no_disposition_as_absent(self):
        # An inconsistent manifest (claims produced, nothing ingested) must not
        # read as coverage.
        manifest = {"selected": ["bandit"], "produced": ["bandit"], "missing": [],
                    "excluded_scope": []}
        lost = it.lost_required_coverage(manifest, {})
        self.assertEqual(lost["bandit"]["kind"], "absent")

    def test_lost_required_coverage_does_not_claim_a_noscan_scanner(self):
        # #1335 decided noscan separately: it produced a valid document and is a
        # no-surface signal, disclosed as produced_noscan and NON-gating. Folding
        # it in here would silently re-gate it.
        manifest = {"selected": ["semgrep"], "produced": ["semgrep"], "missing": [],
                    "excluded_scope": []}
        lost = it.lost_required_coverage(
            manifest, {"semgrep": {"status": "noscan", "findings": 0}})
        self.assertEqual(lost, {})

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
        self.assertEqual(first(out)["location"]["file"], "db/engine.py")

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
        f = first(out)
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
        self.assertEqual(first(out)["title"], "line one line two line three")

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

    def test_worktree_findings_pruned_unconditionally(self):
        # run-9 E3: a nested checkout under .worktrees/ is never project source.
        # Dropped in standard mode AND in redteam (include_fixtures=True) -- the
        # prune has no opt-out, so a stray worktree can't feed the tool-verify
        # round the noise run-9 paid 96 advisor dispatches to re-adjudicate.
        for kw in ({}, {"include_fixtures": True}):
            with tempfile.TemporaryDirectory() as d:
                with open(os.path.join(d, "semgrep.sarif"), "w") as fh:
                    json.dump(_sarif_fixture(
                        ".worktrees/a2-streaming/tests/__pycache__/x.pyc"), fh)
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    out = it.ingest_dir(d, "g1", **kw)
                self.assertEqual(out, [], "kw=%r" % kw)
                self.assertIn("not project source", err.getvalue())

    def test_is_run_artifact_path_matches_top_level_only(self):
        for p in (".worktrees/x/a.py", ".git/config", ".worktrees/a2/b.pyc"):
            self.assertTrue(it._is_run_artifact_path(p), p)
        for p in ("skill/scripts/driver.py", "src/.worktrees/x.py",  # not top-level
                  "a/.git/b", "worktrees/x.py", ".gitignore"):
            self.assertFalse(it._is_run_artifact_path(p), p)

    def test_vendored_dependencies_are_not_source(self):
        # #calibration-5 (solidus): eslint-security emitted 623 messages and 592
        # of them (95%) were in `vendor/` -- bundled jQuery and friends, almost
        # all one noisy rule (security/detect-object-injection). Third-party code
        # the project ships but does not author is not the project's to fix, and
        # the DEPENDENCY scanners already cover that surface by version, which is
        # the actionable form. Matched at any depth, like generated bytecode.
        # #1578 moved this class out of `_is_run_artifact_path` into
        # `_vendored_segment`, which returns the NAME that matched so the drop
        # can be disclosed per segment instead of vanishing into an aggregate.
        for p in ("vendor/assets/javascripts/jquery.payment.js",
                  "core/vendor/assets/javascripts/jsuri.js",
                  "node_modules/lodash/lodash.js",
                  "ui/node_modules/x/y.js",
                  "third_party/zlib/deflate.c",
                  "bower_components/a/b.js"):
            self.assertIsNotNone(it._vendored_segment(p), p)

    def test_vendor_matches_only_as_a_path_segment(self):
        # Conservative by design: a project file whose NAME contains "vendor",
        # or a legitimate app directory like `app/models/vendors/`, is real
        # source and must stay reviewable. Only the conventional dependency
        # directories, and only as a full path segment.
        for p in ("app/models/vendor.rb", "lib/vendor_sync.rb",
                  "app/models/vendors/invoice.rb",   # plural: not a dep dir
                  "spec/vendor_spec.rb", "src/node_modules_helper.js"):
            self.assertIsNone(it._vendored_segment(p), p)

    def test_a_vendored_finding_is_dropped_at_ingest(self):
        # End-to-end through the real ingest path, not just the predicate.
        with tempfile.TemporaryDirectory() as d:
            sarif = {"runs": [{"tool": {"driver": {"name": "semgrep"}},
                               "results": [
                {"ruleId": "r1", "level": "error",
                 "message": {"text": "vendored"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "vendor/assets/j.js"},
                     "region": {"startLine": 1}}}]},
                {"ruleId": "r1", "level": "error",
                 "message": {"text": "ours"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "app/models/order.rb"},
                     "region": {"startLine": 2}}}]}]}]}
            with open(os.path.join(d, "semgrep.sarif"), "w", encoding="utf-8") as fh:
                json.dump(sarif, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                out = it.ingest_dir(d, "g1")
            files = [(f.get("location") or {}).get("file") for f in out]
            self.assertEqual(files, ["app/models/order.rb"],
                             "the vendored finding should not survive ingest")
            self.assertIn("vendored dependencies (vendor: 1)", err.getvalue())

    def test_own_artifacts_and_bytecode_are_not_source(self):
        # #run10 D1: 16 of 54 rejected tool findings were located in things that
        # are not project source. `.panopticon/` is the compounding one -- gitleaks
        # flagged a private-key inside a PREVIOUS run's report-discarded.json, so
        # each run re-adjudicated the last run's rejections and the noise grew run
        # over run.
        for p in (".panopticon/claude-redteam-20260825-report-discarded.json",
                  ".panopticon/runs/tag/tools/gitleaks.sarif",
                  "tests/__pycache__/test_redact.cpython-314.pyc",
                  "skill/scripts/__pycache__/driver.cpython-314.pyc",
                  "a/b/c.pyc", "x.pyo"):
            self.assertTrue(it._is_run_artifact_path(p), p)
        # real source with similar-looking names stays reviewable
        for p in ("skill/scripts/redact.py", "docs/panopticon.md",
                  "tests/test_pycache_helper.py", "src/pycache/mod.py"):
            self.assertFalse(it._is_run_artifact_path(p), p)

    def test_own_artifact_findings_are_pruned_unconditionally(self):
        for kw in ({}, {"include_fixtures": True}):
            with tempfile.TemporaryDirectory() as d:
                with open(os.path.join(d, "gitleaks.sarif"), "w") as fh:
                    json.dump(_sarif_fixture(
                        ".panopticon/claude-redteam-20260825-report-discarded.json"), fh)
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    out = it.ingest_dir(d, "g1", **kw)
                self.assertEqual(out, [], "kw=%r" % kw)
                self.assertIn("not project source", err.getvalue())


class TestVendoredSuppressionIsDisclosed(unittest.TestCase):
    """#1578 (SEC-G2B): the vendored-path exclusion earns its keep -- 592 of
    solidus's 623 eslint-security messages sat under `vendor/` -- but the
    PROVENANCE-FREE form of it did not.

    It matched seven conventional directory names as a path segment at any
    depth, with no per-item disclosure and no opt-out in any mode, and
    `security_gate.evaluate` reused the same call with the same defaults, so a
    payload under `app/vendor/` was dropped from the merge-blocking CI gate as
    well as from the report. The only signal was an aggregate stderr line that
    named no file, so a real vendored library and an evasion looked identical.

    The suppression stays (report-side) and becomes accountable: each dropped
    finding is attributed to the SEGMENT that dropped it, the counts reach
    `meta.coverage.tools_suppressed`, and a caller that must not lose a finding
    -- the gate under redteam -- asks for them back through `suppressed_out`.

    The verification of the original finding recorded a correction worth
    keeping: the two tests that were cited as proving unconditionality exercise
    the SIBLING classes (`.worktrees/`, `.panopticon/`). The vendored class
    itself was only ever tested in default mode. That test is here.
    """

    def _ingest(self, path, **kw):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "w", encoding="utf-8") as fh:
                json.dump(_sarif_fixture(path), fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                out, _disp = it.ingest_dir_detailed(d, "g1", **kw)
            return out, err.getvalue()

    def test_vendored_findings_are_pruned_unconditionally(self):
        # The missing test the verification named: the vendored class in BOTH
        # modes, not just the default one.
        for kw in ({}, {"include_fixtures": True}):
            out, err = self._ingest("app/vendor/patched_auth.rb", **kw)
            self.assertEqual(out, [], "kw=%r" % kw)
            self.assertIn("vendor", err)

    def test_each_suppressed_finding_is_attributed_to_its_segment(self):
        suppressed = []
        out, _err = self._ingest("app/vendor/patched_auth.rb",
                                 suppressed_out=suppressed)
        self.assertEqual(out, [])
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(suppressed[0]["suppressed"], "vendor")
        self.assertEqual((suppressed[0]["location"] or {})["file"],
                         "app/vendor/patched_auth.rb")

    def test_the_stderr_note_names_the_segment_and_the_count(self):
        _out, err = self._ingest("lib/third_party/exec_helper.py")
        self.assertIn("third_party", err)
        self.assertIn("1", err)

    def test_the_other_not_source_classes_are_not_counted_as_vendored(self):
        # Precedence is unchanged: a nested checkout / own artifact / bytecode /
        # virtualenv finding is still dropped by its own class, and never lands
        # in the vendored disclosure -- re-gating a PREVIOUS run's discarded
        # report under redteam is the compounding noise run-10 D1 removed.
        suppressed = []
        out, _err = self._ingest(".panopticon/runs/t/vendor/old-report.json",
                                 suppressed_out=suppressed)
        self.assertEqual(out, [])
        self.assertEqual(suppressed, [])

    def test_project_source_is_untouched(self):
        suppressed = []
        out, _err = self._ingest("app/models/order.rb", suppressed_out=suppressed)
        self.assertEqual(len(out), 1)
        self.assertEqual(suppressed, [])
        self.assertNotIn("suppressed", out[0])

    def test_vendored_segment_matches_a_full_segment_only(self):
        self.assertEqual("vendor", it._vendored_segment("app/vendor/j.js"))
        self.assertEqual("node_modules", it._vendored_segment("a/node_modules/b/c.js"))
        for p in ("app/vendors/model.rb", "src/vendor_test.rb", "vendor.js",
                  "app/vendor"):          # the BASENAME never counts
            self.assertIsNone(it._vendored_segment(p), p)


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
        self.assertEqual(first(findings)["citations"]["cve"], ["CVE-0000-0001"])


class TestAdapterFindingCap(unittest.TestCase):
    """#1236 (OPS-D1B): an adapter's parse() emitted every advisory block with
    no result cap. Filed against bundler-audit, but nothing capped ANY adapter,
    and ingest_dir_detailed is where every adapter's parse() is called -- so the
    bound belongs here, once, rather than in the one adapter that got filed.

    Truncation must never be silent: a dropped tool finding nobody is told about
    is indistinguishable from a clean scan.
    """

    def _results(self, n, level="error"):
        return [{"ruleId": "R%04d" % i, "level": level,
                 "message": {"text": "finding %d" % i},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "src/app.py"},
                     "region": {"startLine": i + 1}}}]}
                for i in range(n)]

    def _ingest(self, results, cap):
        sarif = {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}},
                           "results": results}]}
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "w") as fh:
                json.dump(sarif, fh)
            with patch.object(it, "MAX_ADAPTER_FINDINGS", cap), \
                 contextlib.redirect_stderr(io.StringIO()) as err:
                findings, disp = it.ingest_dir_detailed(d, "g1")
        return findings, disp, err.getvalue()

    def test_an_adapter_under_the_cap_is_untouched(self):
        findings, disp, err = self._ingest(self._results(3), cap=10)
        self.assertEqual(len(findings), 3)
        self.assertNotIn("truncated", disp["semgrep"])
        self.assertEqual(err, "")

    def test_an_oversized_adapter_is_capped(self):
        findings, _disp, _err = self._ingest(self._results(25), cap=10)
        self.assertEqual(len(findings), 10)

    def test_the_truncation_is_disclosed_in_the_disposition(self):
        _findings, disp, _err = self._ingest(self._results(25), cap=10)
        self.assertEqual(disp["semgrep"]["truncated"], 15)
        # `findings` stays the RAW count, so a report can read 25 seen / 10 kept.
        self.assertEqual(disp["semgrep"]["findings"], 25)

    def test_the_truncation_is_loud_on_stderr(self):
        _findings, _disp, err = self._ingest(self._results(25), cap=10)
        self.assertIn("semgrep", err)
        self.assertIn("25", err)

    def test_the_cap_keeps_the_most_severe(self):
        # Dropping the one CRITICAL to keep ten notes would be worse than not
        # capping at all.
        results = self._results(20, level="note")
        results.append({"ruleId": "BAD", "level": "error",
                        "message": {"text": "the serious one"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": "src/app.py"},
                            "region": {"startLine": 99}}}]})
        findings, _disp, _err = self._ingest(results, cap=3)
        self.assertIn("the serious one", " ".join(f["title"] for f in findings))

    def test_the_default_cap_is_not_reachable_by_an_ordinary_scan(self):
        # A bound that fires on a normal repo would silently degrade every run.
        self.assertGreaterEqual(it.MAX_ADAPTER_FINDINGS, 1000)

    def test_the_cap_runs_after_the_exclusion_filter(self):
        # #1741: a target that plants noise under an excluded path must not be
        # able to evict real project findings from the cap. Raw yield =
        # MAX_ADAPTER_FINDINGS + 50; the first 100 (highest severity) sit under
        # a fixture-corpus dir and a vendored dir, the rest are real,
        # lower-severity project findings. Capping the RAW list (the old,
        # buggy order) sorts the 100 excluded findings to the front by
        # severity and keeps the first 1900 of the 1950 real ones, silently
        # evicting the last 50 real findings before the filter ever sees them.
        # Filtering first means the excluded 100 never compete for the cap, so
        # all 1950 real findings survive untouched (well under the cap).
        cap = it.MAX_ADAPTER_FINDINGS
        noise = [{"ruleId": "NOISE%04d" % i, "level": "error",
                 "message": {"text": "planted noise %d" % i},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": (
                         "tests/fixtures/corpus/n%d.py" % i if i < 50
                         else "vendor/lib/n%d.py" % i)},
                     "region": {"startLine": i + 1}}}]}
                 for i in range(100)]
        real = self._results(cap + 50 - 100, level="note")
        findings, disp, err = self._ingest(noise + real, cap=cap)
        self.assertEqual(len(findings), len(real))
        self.assertTrue(all(f["title"].startswith("finding ") for f in findings))
        # Raw yield is unaffected by the reorder -- still the adapter's true
        # pre-filter, pre-cap count.
        self.assertEqual(disp["semgrep"]["findings"], len(noise) + len(real))
        # Nothing was capped: the 1950 real findings fit comfortably under the
        # cap once the 100 excluded ones are out of contention.
        self.assertNotIn("truncated", disp["semgrep"])
        # The 100 planted findings are accounted for as excluded, not silently
        # lost to the cap.
        self.assertIn("excluded 100", err)

    def test_the_cap_notice_names_the_post_filter_count(self):
        # #1741: when the exclusion filter removes some of an adapter's raw
        # yield and what remains STILL exceeds the cap, the stderr note and
        # disposition['truncated'] must describe the post-filter total, never
        # the raw (pre-filter) one -- otherwise "kept N of M" names an M that
        # was never really in contention.
        noise = [{"ruleId": "NOISE%d" % i, "level": "error",
                 "message": {"text": "planted noise %d" % i},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "vendor/lib/n%d.py" % i},
                     "region": {"startLine": i + 1}}}]}
                 for i in range(3)]
        real = self._results(10, level="note")
        findings, disp, err = self._ingest(noise + real, cap=5)
        self.assertEqual(len(findings), 5)
        # 13 raw, 3 excluded, 10 survive the filter, 5 of those are kept: the
        # cap dropped 5 (10 - 5), not 8 (13 - 5).
        self.assertEqual(disp["semgrep"]["truncated"], 5)
        self.assertEqual(disp["semgrep"]["findings"], 13)  # raw_count, unchanged
        self.assertIn("10", err)      # the post-filter total the cap saw
        self.assertNotIn("13", err)   # never the pre-filter (raw) total


class TestVirtualenvExclusion(unittest.TestCase):
    """#1638 P09 (D8): a virtualenv is vendored code -- drop it on the tool axis.

    Run-13: 58 bandit findings under `.venv/` survived ingestion and bought 46
    of 128 tool-advisor dispatches (35.9%), returning 2 confirmations against 32
    rejections and 12 not-material. Metadata first (`pyvenv.cfg`, which every
    creator writes -- venv, virtualenv, uv, pipenv, poetry-in-project), the
    conventional names second.
    """

    def _venv(self, root, rel):
        """Plant a real venv marker at <root>/<rel>/pyvenv.cfg."""
        os.makedirs(os.path.join(root, rel), exist_ok=True)
        with open(os.path.join(root, rel, "pyvenv.cfg"), "w", encoding="utf-8") as fh:
            fh.write("home = /usr/bin\nversion = 3.12.0\n")

    def test_conventional_venv_paths_drop_without_any_tree_to_stat(self):
        # The name fallback: ingest reads SARIF paths and may have no target
        # root at all (the CI gate points at a temp dir of artifacts). #1740
        # moved it out of the silent predicate into the DISCLOSED one -- the
        # finding is still dropped, and now it says which name dropped it.
        for p in (".venv/lib/python3.12/site-packages/x.py",
                  "venv/lib/python3.11/site-packages/requests/api.py",
                  "venv/bin/rst2html.py",
                  "tools/.venv/lib/python3.12/site-packages/y.py",
                  "build/site-packages/z.py"):
            self.assertFalse(it._is_run_artifact_path(p), p)
            self.assertIsNotNone(it._venv_name_segment(p), p)

    def test_metadata_marks_a_venv_with_an_unconventional_name(self):
        # `python -m venv env` is as common as `.venv`; only pyvenv.cfg knows.
        with tempfile.TemporaryDirectory() as root:
            self._venv(root, "env")
            p = "env/lib/python3.12/parser.py"
            self.assertFalse(it._is_run_artifact_path(p))          # no root: no claim
            self.assertTrue(it._is_run_artifact_path(p, root))     # marker: venv

    def test_name_fallback_applies_even_when_the_tree_says_nothing(self):
        # D8's accepted trade-off: a `venv/` with no marker is excluded anyway.
        # #1740: excluded from the report, DISCLOSED to the gate -- the tree
        # said nothing, so only the name justifies the drop.
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "venv"))
            self.assertFalse(it._is_run_artifact_path("venv/app.py", root))
            self.assertEqual(it._venv_name_segment("venv/app.py"), "venv")

    def test_the_name_matches_a_segment_never_a_substring(self):
        with tempfile.TemporaryDirectory() as root:
            for p in ("src/venvutils.py", "app/environments/prod.py",
                      "convenience/helpers.py", "venv_tools/build.py",
                      "docs/venv.md", "scripts/make-venv.sh"):
                self.assertFalse(it._is_run_artifact_path(p, root), p)
                self.assertFalse(it._is_run_artifact_path(p), p)

    def test_a_planted_marker_does_not_poison_the_whole_tree(self):
        # The marker is <dir>/pyvenv.cfg and <dir> must be an ANCESTOR of the
        # finding: a fixture file elsewhere cannot mark a sibling as vendored.
        with tempfile.TemporaryDirectory() as root:
            self._venv(root, os.path.join("tests", "fixtures"))
            for p in ("src/app.py", "tests/test_app.py", "skill/scripts/x.py"):
                self.assertFalse(it._is_run_artifact_path(p, root), p)

    def test_the_marker_lookup_never_resolves_outside_the_root(self):
        with tempfile.TemporaryDirectory() as root:
            cache = {}
            self.assertFalse(it._is_run_artifact_path("../outside/x.py", root, cache))
            # Refused before any stat: no directory was ever looked up (the
            # cache's only entry is the resolved root itself).
            self.assertEqual([k for k in cache if isinstance(k, str)], [])

    def test_marker_lookups_are_cached_per_directory(self):
        with tempfile.TemporaryDirectory() as root:
            cache = {"lib": True}          # seeded; nothing on disk
            self.assertTrue(it._is_run_artifact_path("lib/x.py", root, cache))
            fresh = {}
            self._venv(root, "env")
            self.assertTrue(it._is_run_artifact_path("env/a/b.py", root, fresh))
            self.assertTrue(fresh["env"])
            self.assertNotIn("env/a", fresh)         # short-circuits at the hit

    def test_the_root_is_resolved_once_per_ingest_run(self):
        # #1638 P09 F6: `realpath` ran once per FINDING (and again per ancestor
        # inside the marker check). It is memoized in the same per-run cache the
        # directory lookups use, under a key no relative path can collide with.
        with tempfile.TemporaryDirectory() as root:
            self._venv(root, "env")
            cache = {}
            with patch.object(it.os.path, "realpath",
                              side_effect=os.path.realpath) as rp:
                for i in range(5):
                    it._is_run_artifact_path("env/lib/m%d.py" % i, root, cache)
            root_calls = [c for c in rp.call_args_list
                          if c.args and c.args[0] == root]
            self.assertEqual(len(root_calls), 1,
                             "the root was re-resolved per finding: %r"
                             % (rp.call_args_list,))

    def test_both_virtualenv_layouts_drop_on_their_marker(self):
        # stdlib `python -m venv venv` and pipenv/poetry in-project `.venv`.
        with tempfile.TemporaryDirectory() as root:
            self._venv(root, "venv")
            self._venv(root, ".venv")
            self.assertTrue(it._is_run_artifact_path(
                "venv/lib/python3.12/site-packages/urllib3/util/ssl_.py", root))
            self.assertTrue(it._is_run_artifact_path(
                ".venv/lib/python3.12/site-packages/urllib3/util/ssl_.py", root))

    def test_venv_findings_are_dropped_at_ingest_in_every_mode(self):
        # End-to-end: the target root is the parent of the `.panopticon` tree
        # the tools dir lives in, so every ingest site resolves the same root.
        for kw in ({}, {"include_fixtures": True}):
            with tempfile.TemporaryDirectory() as root:
                self._venv(root, "env")
                tools_dir = os.path.join(root, ".panopticon", "runs", "t", "tools")
                os.makedirs(tools_dir)
                with open(os.path.join(tools_dir, "bandit.sarif"), "w") as fh:
                    json.dump(_sarif_fixture("env/lib/python3.12/site.py"), fh)
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    out = it.ingest_dir(tools_dir, "g1", **kw)
                self.assertEqual(out, [], "kw=%r" % kw)
                self.assertIn("virtualenv", err.getvalue())

    def test_an_explicit_target_root_is_honored(self):
        with tempfile.TemporaryDirectory() as root, \
                tempfile.TemporaryDirectory() as tools_dir:
            self._venv(root, "env")
            with open(os.path.join(tools_dir, "bandit.sarif"), "w") as fh:
                json.dump(_sarif_fixture("env/lib/python3.12/site.py"), fh)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(it.ingest_dir(tools_dir, "g1", target_root=root), [])
                kept = it.ingest_dir(tools_dir, "g1")   # no root anywhere: kept
            self.assertEqual([(f.get("location") or {}).get("file") for f in kept],
                             ["env/lib/python3.12/site.py"])

    def test_project_source_beside_a_venv_survives_ingest(self):
        with tempfile.TemporaryDirectory() as root:
            self._venv(root, ".venv")
            tools_dir = os.path.join(root, ".panopticon", "tools")
            os.makedirs(tools_dir)
            sarif = _sarif_fixture(".venv/lib/python3.12/site-packages/dep.py")
            sarif["runs"][0]["results"].append(
                {"ruleId": "r1", "level": "error", "message": {"text": "ours"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "src/app.py"},
                     "region": {"startLine": 2}}}]})
            with open(os.path.join(tools_dir, "bandit.sarif"), "w") as fh:
                json.dump(sarif, fh)
            with contextlib.redirect_stderr(io.StringIO()):
                out = it.ingest_dir(tools_dir, "g1")
            self.assertEqual([(f.get("location") or {}).get("file") for f in out],
                             ["src/app.py"])

    def test_the_root_is_the_nearest_artifact_dir_not_the_outermost(self):
        # A target that itself lives under a `.panopticon` path (a checkout at
        # `/x/.panopticon/repo`) must still resolve to the target, not to `/x`:
        # the tools dir is always `<target>/.panopticon/...`, so the LAST
        # segment is the run's, and an earlier one belongs to the path above it.
        self.assertEqual(
            it._target_root_for("/x/.panopticon/repo/.panopticon/runs/t/tools"),
            "/x/.panopticon/repo")
        self.assertEqual(it._target_root_for("/repo/.panopticon/tools"), "/repo")
        self.assertIsNone(it._target_root_for("/tmp/ci-artifacts/tools"))


class TestRedactedCaptureStillIngests(unittest.TestCase):
    """#1639 P11 ruling 3: the capture-time redaction pass must cost the tool
    axis nothing it uses. Ingest reads `message.text` (title), `ruleId` and
    `locations[].physicalLocation` (rule + location) -- the tool-advisor round
    needs those, never the secret -- so a redacted gitleaks SARIF has to ingest
    exactly as the unredacted one did, minus the credential.

    Gitleaks' OWN sarif writer puts the secret in `region.snippet.text` and
    builds the message from the rule id and the file, but the fixture plants it
    in BOTH: the choke point must not depend on which field a scanner chose,
    and no adapter reads `snippet` today (so this pins the masking, not a
    parse).
    """

    MARKER = "ghp_" + "INGEST" + "B" * 30

    def _sarif(self, secret):
        return {"runs": [{
            "tool": {"driver": {"name": "gitleaks", "rules": [
                {"id": "github-pat", "properties": {"tags": ["CWE-798"]}}]}},
            "results": [{
                "ruleId": "github-pat", "level": "error",
                "message": {"text": "github-pat has detected secret %s" % secret},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "app/settings.py"},
                    "region": {"startLine": 7, "endLine": 7,
                               "snippet": {"text": "TOKEN = '%s'" % secret}}}}],
            }]}]}

    def test_rule_and_location_survive_the_capture_redaction(self):
        import scripts.run_tools as rt
        raw = _json.dumps(self._sarif(self.MARKER)).encode("utf-8")
        redacted = rt._redact_capture("gitleaks", raw)
        self.assertNotIn(self.MARKER.encode(), redacted)

        doc = _json.loads(redacted)
        res = only(first(doc["runs"], "run")["results"], "result")
        phys = only(res["locations"], "location")["physicalLocation"]
        # Structure is untouched: only token-shaped substrings inside strings move.
        self.assertEqual(res["ruleId"], "github-pat")
        self.assertEqual(res["level"], "error")
        self.assertEqual(phys["artifactLocation"]["uri"], "app/settings.py")
        self.assertEqual(phys["region"]["startLine"], 7)
        # Both secret-bearing fields are masked, snippet included.
        self.assertIn("[REDACTED_TOKEN]", res["message"]["text"])
        self.assertIn("[REDACTED_TOKEN]", phys["region"]["snippet"]["text"])

        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "gitleaks.sarif"), "wb") as fh:
                fh.write(redacted)
            with contextlib.redirect_stderr(io.StringIO()):
                out = it.ingest_dir(d, "g1")
        self.assertEqual(len(out), 1, out)
        f = first(out)
        self.assertEqual(f["tool_evidence"]["rule_id"], "github-pat")
        self.assertEqual(f["location"], {"file": "app/settings.py", "line_start": 7})
        self.assertEqual(f["source"], "tool:gitleaks")
        self.assertEqual(f["severity"], "HIGH")
        self.assertIn("CWE-798", f["citations"]["cwe"])
        self.assertIn("[REDACTED_TOKEN]", f["title"])
        self.assertNotIn(self.MARKER, f["title"])

    def test_the_same_finding_ingests_identically_before_redaction(self):
        """Non-vacuity: rule, location, severity and citations above are what
        the UNREDACTED capture yields too, so the assertions pin survival
        rather than describing a finding redaction happened to reshape."""
        import scripts.run_tools as rt
        raw = _json.dumps(self._sarif(self.MARKER)).encode("utf-8")
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "gitleaks.sarif"), "wb") as fh:
                fh.write(raw)
            with contextlib.redirect_stderr(io.StringIO()):
                plain = first(it.ingest_dir(d, "g1"))
            with open(os.path.join(d, "gitleaks.sarif"), "wb") as fh:
                fh.write(rt._redact_capture("gitleaks", raw))
            with contextlib.redirect_stderr(io.StringIO()):
                masked = first(it.ingest_dir(d, "g1"))
        for key in ("tool_evidence", "location", "source", "severity",
                    "citations", "category", "confidence"):
            self.assertEqual(plain[key], masked[key], key)
        self.assertIn(self.MARKER, plain["title"])       # the hole this closes
        self.assertNotIn(self.MARKER, masked["title"])


class TestEveryNameBasedDropIsDisclosed(unittest.TestCase):
    """#1740 (ARC-F2A): #1578 gave ONE name-based drop class a disclosed
    channel; the rest stayed silent.

    `_is_run_artifact_path` dropped any `venv`/`.venv`/`site-packages` segment
    at any depth on the NAME alone -- no `pyvenv.cfg` needed -- and the
    fixture-corpus prune dropped a whole directory tree the same way, both
    invisibly: they fed one aggregate stderr count, never `suppressed_out`, so
    `security_gate --security redteam` re-admitted a payload under
    `app/vendor/` and lost the identical payload under `app/venv/`.

    The split this pins: a drop justified by a NAME travels the disclosed
    channel (per-segment count + `suppressed_out`), and a drop justified by
    EVIDENCE -- a `pyvenv.cfg` marker, the scanner's own artifacts, generated
    bytecode -- stays silent. Operator policy (`exclude_globs`) is neither: it
    is excluded and counted, never handed back.
    """

    def _ingest(self, path, **kw):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "semgrep.sarif"), "w", encoding="utf-8") as fh:
                json.dump(_sarif_fixture(path), fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                out, _disp = it.ingest_dir_detailed(d, "g1", **kw)
            return out, err.getvalue()

    def test_a_name_only_virtualenv_is_suppressed_not_silent(self):
        for path, segment in (("app/venv/patched_auth.py", "venv"),
                              ("tools/.venv/lib/x.py", ".venv"),
                              ("lib/site-packages/requests/api.py", "site-packages")):
            suppressed = []
            out, err = self._ingest(path, suppressed_out=suppressed)
            self.assertEqual(out, [], path)
            self.assertEqual([f["suppressed"] for f in suppressed], [segment], path)
            self.assertIn(segment, err, path)

    def test_a_marker_confirmed_virtualenv_stays_silent(self):
        # Evidence, not a name: `pyvenv.cfg` says the tree really is installed
        # code, so the drop needs no disclosure and the gate never sees it.
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "app", "venv"))
            with open(os.path.join(root, "app", "venv", "pyvenv.cfg"), "w") as fh:
                fh.write("home = /usr/bin\n")
            suppressed = []
            out, err = self._ingest("app/venv/patched_auth.py",
                                    target_root=root, suppressed_out=suppressed)
        self.assertEqual(out, [])
        self.assertEqual(suppressed, [])
        self.assertIn("not project source", err)

    def test_the_fixture_prune_routes_through_the_same_channel(self):
        suppressed = []
        out, err = self._ingest("tests/fixtures/vulnerable-node/app.js",
                                suppressed_out=suppressed)
        self.assertEqual(out, [])
        self.assertEqual([f["suppressed"] for f in suppressed],
                         [it.FIXTURE_SEGMENT])
        self.assertIn("test-fixture corpus", err)

    def test_include_fixtures_keeps_them_instead_of_suppressing_them(self):
        suppressed = []
        out, _err = self._ingest("tests/fixtures/vulnerable-node/app.js",
                                 include_fixtures=True, suppressed_out=suppressed)
        self.assertEqual(len(out), 1)
        self.assertEqual(suppressed, [])

    def test_operator_exclude_globs_are_excluded_and_never_handed_back(self):
        # `--exclude` is operator POLICY, not a guess from a directory name:
        # the operator said this path is out of scope, so it is counted and
        # dropped in every mode -- the gate must not re-admit it.
        suppressed = []
        out, err = self._ingest("ops/deploy.py", exclude_globs=["ops/*"],
                                suppressed_out=suppressed)
        self.assertEqual(out, [])
        self.assertEqual(suppressed, [])
        self.assertIn("excluded 1 finding", err)

    def test_the_evidence_backed_classes_stay_silent(self):
        for path in (".panopticon/runs/t/report-discarded.json",
                     ".worktrees/a2/app/auth.py",
                     ".git/config",
                     "skill/scripts/__pycache__/driver.cpython-314.pyc",
                     "a/b/c.pyo"):
            for kw in ({}, {"include_fixtures": True}):
                suppressed = []
                out, err = self._ingest(path, suppressed_out=suppressed, **kw)
                self.assertEqual(out, [], path)
                self.assertEqual(suppressed, [], path)
                self.assertIn("not project source", err, path)

    def test_the_name_only_venv_predicate_matches_segments_only(self):
        for p in ("app/venv/x.py", "a/.venv/b/c.py", "lib/site-packages/x.py"):
            self.assertIsNotNone(it._venv_name_segment(p), p)
        for p in ("src/venvutils.py", "app/environments/x.py", "venv.py",
                  "app/venv",                       # the BASENAME never counts
                  "src/site_packages/x.py"):
            self.assertIsNone(it._venv_name_segment(p), p)

    def test_every_dropped_finding_is_counted_in_exactly_one_bucket(self):
        # Honesty of the tally: the stderr line's total is the sum of the
        # buckets, and `suppressed_out` holds exactly the suppressed ones.
        parsed = [{"location": {"file": p}} for p in (
            "app/models/order.rb",                     # kept
            "app/vendor/j.js",                         # suppressed: vendored
            "app/venv/x.py",                           # suppressed: venv name
            "lib/site-packages/y.py",                  # suppressed: venv name
            "tests/fixtures/node/app.js",              # suppressed: fixtures
            ".panopticon/old-report.json",             # silent: run artifact
            "a/__pycache__/x.pyc",                     # silent: bytecode
            "ops/deploy.py",                           # excluded: operator glob
        )]
        suppressed_out = []
        kept, gl, ra, suppressed = it._filter_parsed_findings(
            parsed, False, ["ops/*"], None, None, suppressed_out)
        self.assertEqual(len(kept), 1)
        self.assertEqual((gl, ra), (1, 2))
        self.assertEqual(suppressed, {"vendor": 1, "venv": 1,
                                      "site-packages": 1,
                                      it.FIXTURE_SEGMENT: 1})
        self.assertEqual(len(suppressed_out), sum(suppressed.values()))
        self.assertEqual(len(kept) + gl + ra + sum(suppressed.values()),
                         len(parsed))

    def test_each_suppression_names_its_class(self):
        self.assertEqual(it.suppression_class("vendor"), "vendored")
        self.assertEqual(it.suppression_class("node_modules"), "vendored")
        self.assertEqual(it.suppression_class("venv"), "virtualenv-by-name")
        self.assertEqual(it.suppression_class("site-packages"), "virtualenv-by-name")
        self.assertEqual(it.suppression_class(it.FIXTURE_SEGMENT), "fixture-corpus")

    def test_the_stderr_line_names_each_class_with_its_count(self):
        with tempfile.TemporaryDirectory() as d:
            sarif = {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}},
                               "results": [
                {"ruleId": "r1", "level": "error", "message": {"text": "m"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": uri},
                     "region": {"startLine": 1}}}]}
                for uri in ("app/vendor/j.js", "app/venv/x.py",
                            "tests/fixtures/n/app.js")]}]}
            with open(os.path.join(d, "semgrep.sarif"), "w", encoding="utf-8") as fh:
                json.dump(sarif, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                it.ingest_dir(d, "g1")
        text = err.getvalue()
        self.assertIn("excluded 3 finding", text)
        self.assertIn("vendored dependencies (vendor: 1)", text)
        self.assertIn("venv: 1", text)
        self.assertIn("test-fixture corpus", text)

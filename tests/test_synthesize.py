import contextlib
import io
import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
import scripts.synthesize as syn


class TestFindingsFileIntegrity(unittest.TestCase):
    """#936 duplicate out_file + #937 content-vs-filename validation."""

    def test_duplicate_out_files_detected(self):
        plan = [
            {"role": "panel_review", "out_file": ".panopticon/findings-g1-redteam-panel_review.json"},
            {"role": "panel_review", "out_file": ".panopticon/findings-g1-redteam-panel_review.json"},
            {"role": "lens_sweep", "out_file": ".panopticon/findings-g1-code-lens_sweep-style.json"},
        ]
        self.assertEqual(syn.duplicate_out_files(plan),
                         [".panopticon/findings-g1-redteam-panel_review.json"])
        self.assertEqual(syn.duplicate_out_files([]), [])

    def test_expected_from_filename(self):
        self.assertEqual(syn._expected_from_filename(
            "findings-DocumentsIntake-redteam-panel_review.json"), ("redteam", "panel_review"))
        self.assertEqual(syn._expected_from_filename(
            "findings-g1-security-lens_sweep-injection.json"), ("security", "lens_sweep"))
        self.assertIsNone(syn._expected_from_filename("groups.json"))

    def test_mislabeled_when_content_disagrees(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "findings-g1-redteam-panel_review.json")
            with open(good, "w") as fh:
                json.dump({"findings": [{"panel": "redteam", "source_role": "panel_review"}]}, fh)
            # a lens_sweep finding written into a panel_review file = mis-targeted write
            bad = os.path.join(d, "findings-g2-redteam-panel_review.json")
            with open(bad, "w") as fh:
                json.dump({"findings": [{"panel": "security", "source_role": "lens_sweep"}]}, fh)
            self.assertEqual(syn.mislabeled_findings_files([good]), [])
            self.assertEqual(syn.mislabeled_findings_files([bad]), [bad])

    def test_absent_fields_are_not_second_guessed(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-g1-code-panel_review.json")
            with open(p, "w") as fh:
                json.dump({"findings": [{"description": "no role/panel fields"}]}, fh)
            self.assertEqual(syn.mislabeled_findings_files([p]), [])

    def test_mislabeled_file_forces_inconclusive_end_to_end(self):
        # --fail-on high makes the base gate PASS (no high findings); the
        # integrity gap then raises it to INCONCLUSIVE (OFF would be preserved).
        prev = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            p = os.path.join(d, "findings-g1-redteam-panel_review.json")  # panel_review name
            with open(p, "w") as fh:                                       # lens_sweep content
                json.dump({"findings": [{"id": "XX-001", "title": "t", "severity": "LOW",
                    "confidence": "POSSIBLE", "panel": "code", "source_role": "lens_sweep",
                    "category": "x", "location": {"file": "a.py", "line_start": 1}}]}, fh)
            out = os.path.join(d, "report.json")
            try:
                os.chdir(d)
                with contextlib.redirect_stdout(io.StringIO()):
                    syn.main(["--target", "t", "--fail-on", "high", "--out", out, p])
            finally:
                os.chdir(prev)
            report = json.load(open(out))
            self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")
            self.assertFalse(report["summary"]["coverage_certified"])
            self.assertIn(os.path.basename(p),
                          " ".join(report["meta"]["integrity"]["mislabeled_findings_files"]))

    def test_real_tapestry_corpus_is_consistent_when_present(self):
        # If PANOPTICON_TAPESTRY_CORPUS_PATH is set, its reviewer findings files
        # must not trip the mislabel check (they were authored by the real
        # reviewers) — a regression canary against false positives.
        import glob
        base = os.environ.get("PANOPTICON_TAPESTRY_CORPUS_PATH", "")
        if not base:
            self.skipTest("PANOPTICON_TAPESTRY_CORPUS_PATH not set")
        files = glob.glob(os.path.join(base, "findings-*.json"))
        if not files:
            self.skipTest("No findings files found in PANOPTICON_TAPESTRY_CORPUS_PATH")
        self.assertEqual(syn.mislabeled_findings_files(files), [])


@contextlib.contextmanager
def _chdir(path):
    prev = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(prev)


class TestNormalize(unittest.TestCase):
    def test_verdict_maps_to_confidence(self):
        f = syn.normalize_finding({"severity": "high", "verdict": "CONFIRMED",
                                   "panel": "security"})
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["confidence"], "CERTAIN")

    def test_plausible_maps_to_likely(self):
        f = syn.normalize_finding({"verdict": "PLAUSIBLE"})
        self.assertEqual(f["confidence"], "LIKELY")

    def test_unlabeled_defaults_possible(self):
        f = syn.normalize_finding({"severity": "MEDIUM"})
        self.assertEqual(f["confidence"], "POSSIBLE")

    def test_invalid_severity_becomes_info(self):
        f = syn.normalize_finding({"severity": "sorta-bad"})
        self.assertEqual(f["severity"], "INFO")

    def test_normalize_accepts_new_panels(self):
        for panel in ["architecture", "database", "redteam"]:
            f = syn.normalize_finding({"panel": panel, "title": "x", "description": "y"})
            self.assertEqual(f["panel"], panel)

    def test_normalize_defaults_unknown_panel_to_code(self):
        f = syn.normalize_finding({"panel": "unknown", "title": "x"})
        self.assertEqual(f["panel"], "code")

    def test_normalize_omits_empty_lens(self):
        f = syn.normalize_finding({"title": "x"})
        self.assertNotIn("lens", f)

    def test_normalize_preserves_nonempty_lens(self):
        f = syn.normalize_finding({"title": "x", "lens": "injection"})
        self.assertEqual(f["lens"], "injection")

    def test_location_coerced(self):
        f = syn.normalize_finding({"location": {"file": "a.py", "line_start": 10}})
        self.assertEqual(f["location"]["line_end"], 10)


class TestLoad(unittest.TestCase):
    def test_tolerant_json_with_fences(self):
        body = "```json\n{\"findings\": [{\"severity\": \"LOW\"}]}\n```"
        data = syn.load_json_tolerant(body)
        self.assertEqual(len(data["findings"]), 1)

    def test_load_findings_skips_missing(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "findings-x-code.json")
            with open(good, "w") as fh:
                json.dump({"findings": [{"severity": "HIGH", "panel": "code"}]}, fh)
            findings = syn.load_findings([good, os.path.join(d, "missing.json")])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["confidence"], "POSSIBLE")

    def test_load_findings_skips_non_dict_toplevel(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-x-code.json")
            with open(p, "w") as fh:
                fh.write("[1, 2, 3]")
            self.assertEqual(syn.load_findings([p]), [])

    def test_load_findings_skips_non_dict_finding_entries(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-x-code.json")
            with open(p, "w") as fh:
                json.dump({"findings": ["oops", {"severity": "LOW", "panel": "code"}]}, fh)
            out = syn.load_findings([p])
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0]["severity"], "LOW")

    def test_tolerant_json_with_prose_around_object(self):
        # The regex fallback: panel output wrapped in prose (no code fence).
        body = "Sure, here is the JSON:\n{\"findings\": [{\"severity\": \"LOW\"}]}\nHope that helps!"
        self.assertEqual(syn.load_json_tolerant(body), {"findings": [{"severity": "LOW"}]})

    def test_load_findings_skips_invalid_json_and_continues(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "findings-g-code.json")
            good = os.path.join(d, "findings-g-test.json")
            with open(bad, "w") as fh:
                fh.write("{ not valid json ")
            with open(good, "w") as fh:
                json.dump({"findings": [{"severity": "LOW", "panel": "test",
                          "location": {"file": "a.py", "line_start": 1}}]}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                out = syn.load_findings([bad, good])
            self.assertIn("PARSE ERROR", err.getvalue())
            self.assertEqual(len(out), 1)                # good file still processed

    def test_load_findings_skips_non_list_findings_key(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-g-code.json")
            with open(p, "w") as fh:
                json.dump({"findings": "not-a-list"}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                out = syn.load_findings([p])
            self.assertIn("no findings list", err.getvalue())
            self.assertEqual(out, [])


class TestDedupe(unittest.TestCase):
    def test_merges_same_location_and_category(self):
        findings = [
            {"severity": "LOW", "confidence": "POSSIBLE", "category": "injection",
             "location": {"file": "a.rb", "line_start": 10}},
            {"severity": "HIGH", "confidence": "CERTAIN", "category": "injection",
             "location": {"file": "a.rb", "line_start": 10}},
        ]
        out = syn.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "HIGH")

    def test_same_source_distinct_categories_kept_separate(self):
        # Same source (no cross-source corroboration), different categories at
        # the same file+line: these are genuinely distinct findings and must
        # NOT be merged just because they share a locus.
        findings = [
            {"severity": "HIGH", "confidence": "CERTAIN", "category": "injection",
             "location": {"file": "a.rb", "line_start": 10}},
            {"severity": "HIGH", "confidence": "CERTAIN", "category": "structure",
             "location": {"file": "a.rb", "line_start": 10}},
        ]
        self.assertEqual(len(syn.dedupe(findings)), 2)

    def test_two_agent_findings_same_line_both_kept(self):
        # Two agent-sourced findings (different panels/categories) at the same
        # file+line are NOT cross-source corroboration -> kept separate.
        findings = [
            {"severity": "HIGH", "confidence": "LIKELY", "panel": "code",
             "category": "structure", "source": "agent:code-reviewer",
             "location": {"file": "a.py", "line_start": 5}},
            {"severity": "HIGH", "confidence": "LIKELY", "panel": "security",
             "category": "sql-injection", "source": "agent:security-reviewer",
             "location": {"file": "a.py", "line_start": 5}},
        ]
        out = syn.dedupe(findings)
        self.assertEqual(len(out), 2)
        self.assertFalse(any(f.get("reinforced") for f in out))

    def test_keeps_distinct_files(self):
        findings = [
            {"severity": "HIGH", "confidence": "CERTAIN", "category": "injection",
             "location": {"file": "a.rb", "line_start": 10}},
            {"severity": "HIGH", "confidence": "CERTAIN", "category": "injection",
             "location": {"file": "b.rb", "line_start": 10}},
        ]
        self.assertEqual(len(syn.dedupe(findings)), 2)

    def test_no_file_findings_not_merged(self):
        findings = [
            {"severity": "LOW", "confidence": "NOTE", "category": "x", "location": {}},
            {"severity": "LOW", "confidence": "NOTE", "category": "x", "location": {}},
        ]
        self.assertEqual(len(syn.dedupe(findings)), 2)

    def test_no_line_same_category_both_kept(self):
        # CD-001 regression: two distinct issues in the same file that both omit
        # line_start must NOT collapse on file+category alone. Without a concrete
        # line they can't be reliably clustered -> both pass through.
        findings = [
            {"severity": "MEDIUM", "confidence": "LIKELY", "category": "correctness",
             "source": "agent:code-reviewer", "location": {"file": "a.py"}},
            {"severity": "HIGH", "confidence": "CERTAIN", "category": "correctness",
             "source": "agent:code-reviewer", "location": {"file": "a.py"}},
        ]
        self.assertEqual(len(syn.dedupe(findings)), 2)

    def test_reinforce_sourceless_agent_with_tool(self):
        # Production shape: real panel findings carry NO 'source' field; only
        # tool findings do. A tool+agent pair at the same locus must still
        # reinforce (regression for the dead-branch bug where the reinforce
        # condition required a literal 'agent' source token that never existed).
        findings = [
            {"id": "SG-1", "severity": "MEDIUM", "confidence": "CERTAIN", "panel": "security",
             "category": "sqli", "source": "tool:semgrep",
             "location": {"file": "db.py", "line_start": 10},
             "citations": {"cwe": [{"id": "CWE-89", "verified": True}]}},
            {"id": "SE-1", "severity": "HIGH", "confidence": "LIKELY", "panel": "security",
             "category": "novel",                       # no 'source' key -> real agent shape
             "location": {"file": "db.py", "line_start": 10}},
        ]
        out = syn.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].get("reinforced"))
        # confidence is never mutated by the pipeline (amended spec) — the
        # survivor keeps its own original confidence.
        self.assertEqual(out[0].get("confidence"), "LIKELY")
        self.assertIn("citations", out[0])              # tool CWE carried to the survivor

    def test_reinforce_across_type_and_category_mismatch(self):
        findings = [
            {"id":"SE-001","severity":"HIGH","confidence":"LIKELY","panel":"security",
             "category":"novel","source":"agent:security-reviewer",
             "location":{"file":"webapp.py","line_start":151}},
            {"id":"SG-001","severity":"MEDIUM","confidence":"CERTAIN","panel":"security",
             "category":"django-csrf","source":"tool:semgrep",
             "location":{"file":"webapp.py","line_start":"151"},
             "citations":{"cwe":[{"id":"CWE-352","name":"CSRF","verified":True}]}},
        ]
        out = syn.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].get("reinforced"))

    def test_three_findings_at_locus_keeps_unrelated(self):
        # tool + agent corroborate on sql-injection at the same line, plus an
        # UNRELATED agent 'structure' finding on that line -> the unrelated one survives.
        findings = [
            {"id":"TR-001","severity":"HIGH","confidence":"CERTAIN","panel":"security",
             "category":"sql-injection","source":"tool:semgrep",
             "location":{"file":"db.py","line_start":10}},
            {"id":"SE-001","severity":"HIGH","confidence":"LIKELY","panel":"security",
             "category":"sql-injection","source":"agent:security-reviewer",
             "location":{"file":"db.py","line_start":10}},
            {"id":"CD-001","severity":"MEDIUM","confidence":"POSSIBLE","panel":"code",
             "category":"structure","source":"agent:code-reviewer",
             "location":{"file":"db.py","line_start":10}},
        ]
        out = syn.dedupe(findings)
        cats = sorted(f.get("category") for f in out)
        self.assertIn("structure", cats)                 # unrelated finding NOT dropped
        self.assertEqual(len(out), 2)                     # sql-injection (collapsed) + structure
        sql = [f for f in out if f.get("category") == "sql-injection"][0]
        self.assertTrue(sql.get("reinforced"))           # corroboration reinforces even in >2 clusters
        self.assertEqual(sql.get("confidence"), "CERTAIN")


class TestGrading(unittest.TestCase):
    def _f(self, sev):
        return {"severity": sev}

    def test_grade_rule(self):
        self.assertEqual(syn.grade([self._f("CRITICAL")]), "F")
        self.assertEqual(syn.grade([self._f("HIGH")]), "D")
        self.assertEqual(syn.grade([self._f("MEDIUM")]), "C")
        self.assertEqual(syn.grade([self._f("LOW")]), "B")
        self.assertEqual(syn.grade([self._f("INFO")]), "A")
        self.assertEqual(syn.grade([]), "A")

    def test_risk_level(self):
        self.assertEqual(syn.risk_level([self._f("HIGH"), self._f("LOW")]), "HIGH")
        self.assertEqual(syn.risk_level([self._f("INFO")]), "LOW")

    def test_gate_off_when_no_threshold(self):
        self.assertEqual(syn.gate_verdict([self._f("CRITICAL")], None), "OFF")

    def test_gate_fail_at_or_above_threshold(self):
        self.assertEqual(syn.gate_verdict([self._f("HIGH")], "high"), "FAIL")
        self.assertEqual(syn.gate_verdict([self._f("CRITICAL")], "high"), "FAIL")
        self.assertEqual(syn.gate_verdict([self._f("MEDIUM")], "high"), "PASS")

    def test_severity_stats(self):
        stats = syn.severity_stats([self._f("HIGH"), self._f("HIGH"), self._f("LOW")])
        self.assertEqual(stats["high"], 2)
        self.assertEqual(stats["low"], 1)
        self.assertEqual(stats["critical"], 0)


class TestCertify(unittest.TestCase):
    def _crit(self):
        return [{"severity": "CRITICAL", "evidence": {"status": "advisor_confirmed"}}]

    def test_clean_complete_pass_real_grade(self):
        r = syn.certify("A", [], "high", set(), [])
        self.assertEqual(r["gate"], "PASS")
        self.assertEqual(r["overall_grade"], "A")
        self.assertIsNone(r["provisional_grade"])
        self.assertTrue(r["coverage_certified"])
        self.assertIsNone(r["coverage_note"])

    def test_clean_high_value_incomplete_inconclusive(self):
        r = syn.certify("B", [], "high", {"security"}, [])
        self.assertEqual(r["gate"], "INCONCLUSIVE")
        self.assertIsNone(r["overall_grade"])
        self.assertEqual(r["provisional_grade"], "B")
        self.assertFalse(r["coverage_certified"])

    def test_clean_low_value_tail_pass_with_note(self):
        r = syn.certify("B", [], "high", {"test"}, [])
        self.assertEqual(r["gate"], "PASS")
        self.assertIsNone(r["overall_grade"])
        self.assertEqual(r["provisional_grade"], "B")
        self.assertFalse(r["coverage_certified"])
        self.assertIn("test", r["coverage_note"])

    def test_confirmed_fail_beats_inconclusive(self):
        r = syn.certify("F", self._crit(), "high", {"security"}, [])
        self.assertEqual(r["gate"], "FAIL")

    def test_off_preserved_with_gap(self):
        r = syn.certify("B", [], None, {"security"}, [])
        self.assertEqual(r["gate"], "OFF")
        self.assertFalse(r["coverage_certified"])

    def test_requested_absent_tool_inconclusive(self):
        r = syn.certify("A", [], "high", set(), ["semgrep"])
        self.assertEqual(r["gate"], "INCONCLUSIVE")
        self.assertFalse(r["coverage_certified"])


class TestReport(unittest.TestCase):
    def _finding(self, **kw):
        base = {"id": "CD-001", "title": "t", "severity": "LOW", "confidence": "POSSIBLE",
                "panel": "code", "category": "structure",
                "location": {"file": "a.py", "line_start": 3}}
        base.update(kw)
        return base

    def test_build_report_has_grades_and_gate(self):
        # A HIGH finding with no source/verdict is agentic + unverified, and
        # unverified findings are not gate-eligible by default -> grade/gate
        # reflect the (empty) gate-eligible set, not the raw severity.
        findings = [self._finding(severity="HIGH", panel="code")]
        report = syn.build_report(findings, [{"name": "g1", "files": ["a.py"]}],
                                  "src", "high", "2026-07-23T00:00:00Z")
        self.assertEqual(report["summary"]["overall_grade"], "A")
        self.assertEqual(report["summary"]["gate"], "PASS")
        self.assertEqual(report["groups"][0]["panel_grades"]["code"], "A")

    def test_validate_clean_report(self):
        findings = [self._finding()]
        report = syn.build_report(findings, [{"name": "g1", "files": ["a.py"]}],
                                  "src", None, "2026-07-23T00:00:00Z")
        errors, _ = syn.validate_report(report)
        self.assertEqual(errors, [])

    def test_validate_flags_bad_id_and_missing_cvss(self):
        bad = self._finding(id="lowercase", panel="security", severity="CRITICAL")
        report = syn.build_report([bad], [{"name": "g1", "files": ["a.py"]}],
                                  "src", None, "2026-07-23T00:00:00Z")
        errors, _ = syn.validate_report(report)
        self.assertTrue(any("id" in e for e in errors))
        self.assertTrue(any("cvss" in e or "exploit" in e for e in errors))

    def test_validate_flags_duplicate_ids(self):
        report = syn.build_report(
            [self._finding(id="CD-001", title="a", category="x",
                            location={"file": "a", "line_start": 1}),
             self._finding(id="CD-001", title="b", category="y",
                            location={"file": "b", "line_start": 2})],
            [], "t", None, "2026-07-23T00:00:00Z")
        errors, _ = syn.validate_report(report)
        self.assertTrue(any("duplicate" in e.lower() for e in errors))

    def test_build_report_honors_review_type(self):
        report = syn.build_report([], [], "src/app.py", None,
                                   "2026-07-23T00:00:00Z", review_type="file")
        self.assertEqual(report["meta"]["review_type"], "file")

    def test_build_report_includes_security_mode(self):
        report = syn.build_report([], [], "src", None, "2026-07-23T00:00:00Z",
                                  security_mode="redteam")
        self.assertEqual(report["meta"]["security_mode"], "redteam")

    def test_build_report_populates_models_used(self):
        findings = [
            self._finding(
                id="CD-001", panel="code", location={"file": "a.py", "line_start": 1},
                provenance={"discovered_by": "agent:lens_sweep",
                            "confirmation_status": "CONFIRMED",
                            "model": "kimi-k2.7-coding", "model_version": "v1"}),
            self._finding(
                id="CD-002", panel="code", location={"file": "a.py", "line_start": 2},
                provenance={"discovered_by": "agent:panel_review",
                            "confirmation_status": "CONFIRMED",
                            "model": "kimi-k2.7-coding", "model_version": "v1"}),
            self._finding(
                id="CD-003", panel="code", location={"file": "a.py", "line_start": 3},
                provenance={"discovered_by": "agent:lens_sweep",
                            "confirmation_status": "CONFIRMED",
                            "model": "other-model"}),
        ]
        report = syn.build_report(findings, [], "src", None, "2026-07-23T00:00:00Z")
        models = report["meta"]["models_used"]
        self.assertEqual(len(models), 3)
        self.assertIn({"model": "kimi-k2.7-coding", "version": "v1", "role": "lens_sweep"}, models)
        self.assertIn({"model": "kimi-k2.7-coding", "version": "v1", "role": "panel_review"}, models)
        self.assertIn({"model": "other-model", "role": "lens_sweep"}, models)

    def test_main_maps_orchestrator_mode_to_review_type(self):
        with tempfile.TemporaryDirectory() as d:
            gj = os.path.join(d, "groups.json")
            with open(gj, "w") as fh:
                json.dump({"mode": "directory", "groups": [{"name": "g1", "files": ["a.py"]}]}, fh)
            fpath = os.path.join(d, "findings-g1-code.json")
            with open(fpath, "w") as fh:
                json.dump({"findings": [{"id": "CD-001", "title": "x", "severity": "LOW",
                    "confidence": "POSSIBLE", "panel": "code", "category": "structure",
                    "location": {"file": "a.py", "line_start": 1}}]}, fh)
            out = os.path.join(d, "report.json")
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                syn.main(["--target", "src", "--groups", gj, "--out", out, fpath])
            with open(out) as _fh:
                report = json.load(_fh)
            self.assertEqual(report["meta"]["review_type"], "directory")

    def test_main_auto_discovers_panopticon_groups(self):
        # With no --groups flag, synthesize should default to
        # .panopticon/groups.json so the report carries group definitions
        # (groups[].files drives the HTML heatmap and grouped findings).
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "groups.json"), "w") as fh:
                json.dump({"mode": "repo", "security_mode": "standard",
                           "groups": [{"name": "core", "files": ["a.py", "b.py"]}]}, fh)
            fpath = os.path.join(d, "findings-core-code.json")
            with open(fpath, "w") as fh:
                json.dump({"findings": [{"id": "CD-001", "title": "x", "severity": "LOW",
                    "confidence": "POSSIBLE", "panel": "code", "category": "structure",
                    "location": {"file": "a.py", "line_start": 1}}]}, fh)
            out = os.path.join(d, "report.json")
            import io, contextlib
            buf = io.StringIO()
            with _chdir(d), contextlib.redirect_stdout(buf):
                # relative paths so auto-discovery resolves against the cwd
                syn.main(["--target", "src", "--out", "report.json",
                          "findings-core-code.json"])
            with open(out) as _fh:
                report = json.load(_fh)
        names = [g["name"] for g in report["groups"]]
        self.assertIn("core", names)
        core = next(g for g in report["groups"] if g["name"] == "core")
        self.assertEqual(core["files"], ["a.py", "b.py"])

    def test_main_explicit_groups_overrides_auto_discovery(self):
        # An explicit --groups still wins over the .panopticon/groups.json default.
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "groups.json"), "w") as fh:
                json.dump({"groups": [{"name": "auto", "files": ["a.py"]}]}, fh)
            explicit = os.path.join(d, "explicit.json")
            with open(explicit, "w") as fh:
                json.dump({"groups": [{"name": "explicit", "files": ["a.py"]}]}, fh)
            fpath = os.path.join(d, "findings-x-code.json")
            with open(fpath, "w") as fh:
                json.dump({"findings": [{"id": "CD-001", "title": "x", "severity": "LOW",
                    "confidence": "POSSIBLE", "panel": "code", "category": "structure",
                    "location": {"file": "a.py", "line_start": 1}}]}, fh)
            out = os.path.join(d, "report.json")
            import io, contextlib
            buf = io.StringIO()
            with _chdir(d), contextlib.redirect_stdout(buf):
                syn.main(["--target", "src", "--groups", "explicit.json",
                          "--out", "report.json", "findings-x-code.json"])
            with open(out) as _fh:
                report = json.load(_fh)
        self.assertEqual([g["name"] for g in report["groups"]], ["explicit"])

    def test_main_rejects_invalid_fail_on(self):
        with self.assertRaises(SystemExit):
            syn.main(["--target", "src", "--fail-on", "bogus", "x.json"])

    def test_validate_redteam_high_requires_cvss_and_exploit(self):
        bad = self._finding(id="RT-001", panel="redteam", severity="HIGH")
        report = syn.build_report([bad], [{"name": "g1", "files": ["a.py"]}],
                                  "src", None, "2026-07-23T00:00:00Z")
        errors, _ = syn.validate_report(report)
        self.assertTrue(any("cvss" in e for e in errors))
        self.assertTrue(any("exploit" in e for e in errors))

    def test_validate_redteam_critical_filled_is_clean(self):
        good = self._finding(id="RT-001", panel="redteam", severity="CRITICAL",
                             cvss={"score": 9.0}, exploit_scenario="x")
        report = syn.build_report([good], [{"name": "g1", "files": ["a.py"]}],
                                  "src", None, "2026-07-23T00:00:00Z")
        errors, _ = syn.validate_report(report)
        self.assertEqual(errors, [])

    def test_main_severity_filter_excludes_lower(self):
        with tempfile.TemporaryDirectory() as d:
            findings = [
                {"id": "SE-001", "title": "crit", "severity": "CRITICAL",
                 "confidence": "CERTAIN", "panel": "security", "category": "x",
                 "location": {"file": "a", "line_start": 1},
                 "cvss": {"score": 9}, "exploit_scenario": "y"},
                {"id": "CD-001", "title": "low", "severity": "LOW",
                 "confidence": "POSSIBLE", "panel": "code", "category": "z",
                 "location": {"file": "a", "line_start": 2}},
            ]
            p = os.path.join(d, "findings-g1-security.json")
            with open(p, "w") as fh:
                json.dump({"findings": findings}, fh)
            out = os.path.join(d, "report.json")
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = syn.main(["--target", "src", "--severity", "high", "--out", out, p])
            self.assertEqual(rc, 0)  # gate default OFF
            with open(out) as _fh:
                report = json.load(_fh)
            ids = {f["id"] for f in report["findings"]}
            self.assertEqual(ids, {"SE-001"})

    def _tools_dir_with_sarif(self, d):
        # A semgrep SARIF with three results: real code (kept), a fixture-corpus
        # path (dropped by the default prune), and a non-fixture path a
        # --tools-exclude glob can drop independently of the fixture prune.
        sarif = {"runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": [
            {"ruleId": "r1", "level": "error", "message": {"text": "real"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "app/db.py"},
                 "region": {"startLine": 1}}}]},
            {"ruleId": "r2", "level": "error", "message": {"text": "fixture"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "tests/fixtures/vuln.py"},
                 "region": {"startLine": 2}}}]},
            {"ruleId": "r3", "level": "error", "message": {"text": "vendored"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "vendor/gen.js"},
                 "region": {"startLine": 3}}}]},
        ]}]}
        tdir = os.path.join(d, "tools")
        os.makedirs(tdir)
        with open(os.path.join(tdir, "semgrep.sarif"), "w") as fh:
            json.dump(sarif, fh)
        return tdir

    def test_main_tools_exclude_and_fixture_prune_wired_end_to_end(self):
        # #693: --tools-exclude must reach ingest_dir from the CLI. Plus the
        # standard-mode default fixture prune (tool-path parity with #434) and
        # its --include-fixtures (redteam) escape hatch, all wired through main().
        import io, contextlib
        with tempfile.TemporaryDirectory() as d:
            tdir = self._tools_dir_with_sarif(d)
            fpath = os.path.join(d, "findings-g1-code.json")
            with open(fpath, "w") as fh:
                json.dump({"findings": []}, fh)

            def run(extra):
                out = os.path.join(d, "r.json")
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = syn.main(["--target", "src", "--gate-unverified",
                                   "--tools-dir", tdir, "--out", out, *extra, fpath])
                self.assertEqual(rc in (0, 1), True)
                with open(out) as fh:
                    return {f["location"]["file"] for f in json.load(fh)["findings"]}

            # Default: fixture path pruned automatically; non-fixture paths kept.
            self.assertEqual(run([]), {"app/db.py", "vendor/gen.js"})
            # --tools-exclude drops a NON-fixture path via the CLI glob (#693).
            self.assertEqual(run(["--tools-exclude", "vendor/*"]), {"app/db.py"})
            # --include-fixtures (redteam) keeps the fixture-corpus finding.
            self.assertEqual(run(["--include-fixtures"]),
                             {"app/db.py", "tests/fixtures/vuln.py", "vendor/gen.js"})

    def test_main_changes_alias_sets_review_type(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-g1-code.json")
            with open(p, "w") as fh:
                json.dump({"findings": [{"id": "CD-001", "title": "x", "severity": "LOW",
                    "confidence": "POSSIBLE", "panel": "code", "category": "structure",
                    "location": {"file": "a.py", "line_start": 1}}]}, fh)
            out = os.path.join(d, "report.json")
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = syn.main(["--target", "src", "--changes", "--out", out, p])
            self.assertEqual(rc, 0)
            with open(out) as _fh:
                report = json.load(_fh)
            self.assertEqual(report["meta"]["review_type"], "changes")

    def _delta_run(self, d, extra):
        p = os.path.join(d, "findings-g1-code.json")
        with open(p, "w") as fh:
            json.dump({"findings": [{"id": "CD-001", "title": "x", "severity": "LOW",
                "confidence": "POSSIBLE", "panel": "code", "category": "structure",
                "location": {"file": "a.py", "line_start": 1}}]}, fh)
        hunks = os.path.join(d, "diff-hunks.json")
        with open(hunks, "w") as fh:
            json.dump({"base": "main", "base_source": "pr-base",
                       "hunks": {"a.py": [[1, 5]]}}, fh)
        out = os.path.join(d, "report.json")
        import io, contextlib
        errbuf = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(errbuf):
            rc = syn.main(["--target", "src", "--diff-hunks", hunks,
                           "--out", out, *extra, p])
        self.assertEqual(rc, 0)
        return errbuf.getvalue()

    def test_delta_review_without_fail_on_warns_loudly(self):
        # #957: a delta review is gate-first by intent; running one without
        # --fail-on silently yields Gate: OFF. Must warn on stderr.
        with tempfile.TemporaryDirectory() as d:
            err = self._delta_run(d, [])
            self.assertIn("Gate: OFF", err)
            self.assertIn("--fail-on", err)

    def test_delta_review_with_fail_on_does_not_warn(self):
        with tempfile.TemporaryDirectory() as d:
            err = self._delta_run(d, ["--fail-on", "high"])
            self.assertNotIn("Gate: OFF", err)


class TestCliAndSummary(unittest.TestCase):
    def test_render_summary_contains_grade_and_location(self):
        # gate_unverified=True: this test is about render_summary's formatting
        # (location string, FAIL label), not the default gating policy.
        report = syn.build_report(
            [{"id": "CD-001", "title": "SQL injection", "severity": "HIGH",
              "confidence": "CERTAIN", "panel": "security", "category": "injection",
              "location": {"file": "a.rb", "line_start": 42},
              "cvss": {"score": 8.1, "vector": "CVSS:3.1/AV:N"},
              "exploit_scenario": "..."}],
            [{"name": "g1", "files": ["a.rb"]}], "src", "high", "2026-07-23T00:00:00Z",
            gate_unverified=True)
        text = syn.render_summary(report)
        self.assertIn("a.rb:42", text)
        self.assertIn("FAIL", text)

    def test_render_summary_includes_all_panel_grades(self):
        report = syn.build_report(
            [{"id": "CD-001", "title": "t", "severity": "LOW", "confidence": "POSSIBLE",
              "panel": "architecture", "category": "structure",
              "location": {"file": "a.py", "line_start": 1}}],
            [{"name": "g1", "files": ["a.py"]}], "src", None, "2026-07-23T00:00:00Z")
        text = syn.render_summary(report)
        for panel in ["code", "test", "security", "architecture", "database", "redteam"]:
            self.assertIn("%s " % panel, text)

    def test_main_returns_1_on_gate_fail(self):
        with tempfile.TemporaryDirectory() as d:
            fpath = os.path.join(d, "findings-g1-security.json")
            with open(fpath, "w") as fh:
                # tool-sourced: tool_confirmed is gate-eligible by default, so
                # this exercises the CLI FAIL path without needing a verdict.
                # SEC-102: a findings-*.json file is agent-authored, so a
                # self-claimed `source` is stripped at load; --gate-unverified
                # is what exercises the CLI FAIL path now.
                json.dump({"findings": [{"id": "SE-001", "title": "x", "severity": "CRITICAL",
                                         "confidence": "CERTAIN", "panel": "security",
                                         "category": "injection",
                                         "location": {"file": "a.rb", "line_start": 1},
                                         "cvss": {"score": 9.0, "vector": "CVSS:3.1/x"},
                                         "exploit_scenario": "y"}]}, fh)
            out = os.path.join(d, "report.json")
            import io
            import contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = syn.main(["--target", "src", "--fail-on", "high",
                               "--gate-unverified", "--out", out, fpath])
            self.assertEqual(rc, 1)
            self.assertTrue(os.path.isfile(out))

    def test_write_report_split_preserves_findings_without_mutating_input(self):
        findings = [{"id": "CD-%03d" % i, "title": "t" * 40, "severity": "LOW",
                     "confidence": "POSSIBLE", "panel": "code", "category": "structure",
                     "location": {"file": "a.py", "line_start": i}}
                    for i in range(1, 400)]
        report = syn.build_report(findings, [], "src", None, "2026-07-23T00:00:00Z")
        n_before = len(report["findings"])
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            paths = syn.write_report(report, out, max_bytes=1000)
            self.assertEqual(len(paths), 2)
            with open(paths[0]) as _fh:
                main_doc = json.load(_fh)
            with open(paths[1]) as _fh:
                part_doc = json.load(_fh)
            self.assertIn("parts", main_doc["meta"])
            self.assertEqual(len(main_doc["findings"]) + len(part_doc["findings"]), n_before)
            self.assertEqual(len(report["findings"]), n_before)  # caller not mutated

    def test_main_returns_0_when_gate_not_fail(self):
        with tempfile.TemporaryDirectory() as d:
            fpath = os.path.join(d, "findings-g1-code.json")
            with open(fpath, "w") as fh:
                json.dump({"findings": [{"id": "CD-001", "title": "x", "severity": "MEDIUM",
                    "confidence": "POSSIBLE", "panel": "code", "category": "structure",
                    "location": {"file": "a.py", "line_start": 1}}]}, fh)
            out = os.path.join(d, "report.json")
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = syn.main(["--target", "src", "--out", out, fpath])
            self.assertEqual(rc, 0)


class TestReconciliation(unittest.TestCase):
    def test_normalize_backfills_title_category(self):
        f = syn.normalize_finding({"description": "First line.\nSecond", "severity": "LOW"})
        self.assertEqual(f["title"], "First line.")
        self.assertEqual(f["category"], "general")

    def test_normalize_untitled_when_no_description(self):
        f = syn.normalize_finding({"severity": "LOW"})
        self.assertEqual(f["title"], "(untitled)")

    def test_normalize_collapses_multiline_title(self):
        f = syn.normalize_finding({"title": "Package: requests\nInstalled: 2.19.0\nCVE-x",
                                   "severity": "MEDIUM"})
        self.assertEqual(f["title"], "Package: requests Installed: 2.19.0 CVE-x")

    def test_main_survives_malformed_citation_and_writes_report(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-g1-security.json")
            with open(p, "w") as fh:
                json.dump({"findings": [
                    {"id":"SE-001","title":"crit","severity":"CRITICAL","confidence":"CERTAIN",
                     "panel":"security","category":"x","source":"agent:sr",
                     "location":{"file":"a","line_start":1},
                     "cvss":{"score":9.0,"vector":"v"},"exploit_scenario":"e"},
                    {"id":"SE-002","title":"bad","severity":"LOW","confidence":"POSSIBLE",
                     "panel":"security","category":"y","source":"agent:sr",
                     "location":{"file":"b","line_start":2},"citations":{"ssvc":"active"}}]}, fh)
            out = os.path.join(d, "report.json")
            import io, contextlib
            buf = io.StringIO()
            # Isolate cwd: main() discovers .panopticon/scout-*.json relative
            # to cwd, and the repo root's own .panopticon carries self-scan
            # leftovers that would otherwise leak "requested_absent" tools
            # into this fixture's tiny finding set.
            with _chdir(d), contextlib.redirect_stdout(buf):
                rc = syn.main(["--target","t","--fail-on","high","--out",out, p])
            self.assertTrue(os.path.isfile(out))          # report written despite malformed citation
            # Both findings are agentic and carry no verdict -> unverified,
            # which does not gate by default under the two-axis model.
            self.assertEqual(rc, 0)
            with open(out) as _fh:
                report = json.load(_fh)
            self.assertTrue(any(f["id"]=="SE-001" for f in report["findings"]))

    def test_validate_returns_errors_and_warnings(self):
        report = syn.build_report(
            [{"id": "CD-001", "title": "t", "severity": "LOW", "confidence": "POSSIBLE",
              "panel": "code", "category": "general", "location": {}}],
            [], "src", None, "2026-07-23T00:00:00Z")
        errors, warnings = syn.validate_report(report)
        self.assertEqual(errors, [])
        self.assertTrue(any("location" in w for w in warnings))

    def test_tool_security_finding_exempt_from_cvss(self):
        report = syn.build_report(
            [{"id": "TR-001", "title": "t", "severity": "HIGH", "confidence": "CERTAIN",
              "panel": "security", "category": "general", "source": "tool:trivy",
              "location": {"file": "a", "line_start": 1}}],
            [], "src", None, "2026-07-23T00:00:00Z")
        errors, _ = syn.validate_report(report)
        self.assertEqual(errors, [])

    def test_four_digit_tool_id_is_valid(self):
        report = syn.build_report(
            [{"id": "SG-1000", "title": "t", "severity": "LOW", "confidence": "CERTAIN",
              "panel": "security", "category": "x", "source": "tool:semgrep",
              "location": {"file": "a", "line_start": 1}}],
            [], "src", None, "2026-07-23T00:00:00Z")
        errors, _ = syn.validate_report(report)
        self.assertFalse(any("id" in e for e in errors))


class TestGroupTag(unittest.TestCase):
    def test_test_panel_grade_reflects_test_findings(self):
        # a test-panel finding on a path NOT in group files, tagged by _group.
        # gate_unverified=True: this test verifies _group attribution feeds
        # panel_grades, not the default gating policy (the finding is agentic
        # with no verdict, so it would be excluded from grading otherwise).
        findings = [{"id": "TS-001", "title": "weak test", "severity": "HIGH",
                     "confidence": "LIKELY", "panel": "test", "category": "quality",
                     "location": {"file": "spec/foo_spec.rb", "line_start": 3},
                     "_group": "g1"}]
        report = syn.build_report(findings, [{"name": "g1", "files": ["app/foo.rb"]}],
                                  "src", None, "2026-07-23T00:00:00Z", gate_unverified=True)
        self.assertEqual(report["groups"][0]["panel_grades"]["test"], "D")  # not "A"
        # _group scrubbed from emitted findings
        self.assertNotIn("_group", report["findings"][0])

    def test_load_findings_tags_group_from_filename(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-mygroup-code.json")
            with open(p, "w") as fh:
                json.dump({"findings": [{"severity": "LOW", "panel": "code"}]}, fh)
            out = syn.load_findings([p])
            self.assertEqual(out[0]["_group"], "mygroup")

    def test_load_findings_tags_group_from_new_panel_filenames(self):
        with tempfile.TemporaryDirectory() as d:
            for panel in ["architecture", "database", "redteam"]:
                p = os.path.join(d, "findings-mygroup-%s.json" % panel)
                with open(p, "w") as fh:
                    json.dump({"findings": [{"severity": "LOW", "panel": panel}]}, fh)
                out = syn.load_findings([p])
                self.assertEqual(out[0]["_group"], "mygroup")
                self.assertEqual(out[0]["panel"], panel)


class TestPipelineCitations(unittest.TestCase):
    def test_citations_enriched_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "findings-g1-security.json")
            with open(fp, "w") as fh:
                json.dump({"findings": [{"id": "SE-001", "title": "sqli",
                    "severity": "HIGH", "confidence": "CERTAIN", "panel": "security",
                    "category": "injection", "source": "tool:semgrep",
                    "location": {"file": "a.py", "line_start": 1},
                    "citations": {"cwe": ["CWE-89"]}}]}, fh)
            out = os.path.join(d, "report.json")
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                syn.main(["--target", "src", "--out", out, fp])
            with open(out) as _fh:
                report = json.load(_fh)
            cites = report["findings"][0]["citations"]
            self.assertEqual(cites["cwe"][0]["name"][:3], "Imp")
            self.assertIn("A03:2021-Injection", cites["owasp"])


class TestReinforce(unittest.TestCase):
    def test_tool_and_agent_reinforce(self):
        findings = [
            {"id": "SE-001", "severity": "HIGH", "confidence": "LIKELY", "panel": "security",
             "category": "sql-injection", "source": "agent:security-reviewer",
             "location": {"file": "a.py", "line_start": 10}},
            {"id": "SG-001", "severity": "HIGH", "confidence": "CERTAIN", "panel": "security",
             "category": "sql-injection", "source": "tool:semgrep",
             "location": {"file": "a.py", "line_start": 10},
             "citations": {"cwe": [{"id": "CWE-89", "name": "SQLi", "verified": True}]}},
        ]
        out = syn.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].get("reinforced"))
        self.assertEqual(out[0]["confidence"], "CERTAIN")
        self.assertIn("citations", out[0])

    def test_tool_higher_confidence_keeps_agent_cvss_and_exploit(self):
        # PT-002 regression: a tool finding with higher confidence must not
        # discard the agent's cvss/exploit_scenario when it wins as survivor.
        findings = [
            {"id": "SG-001", "title": "SQL injection", "severity": "HIGH",
             "confidence": "CERTAIN", "panel": "security",
             "category": "sql-injection", "source": "tool:semgrep",
             "location": {"file": "a.py", "line_start": 10},
             "citations": {"cwe": [{"id": "CWE-89"}]}},
            {"id": "SE-001", "title": "SQL injection", "severity": "HIGH",
             "confidence": "LIKELY", "panel": "security",
             "category": "sql-injection",
             "location": {"file": "a.py", "line_start": 10},
             "cvss": {"score": 8.1, "vector": "CVSS:3.1/AV:N"},
             "exploit_scenario": "Attacker injects SQL via the search box."},
        ]
        out = syn.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].get("reinforced"))
        self.assertEqual(out[0]["confidence"], "CERTAIN")
        self.assertEqual(out[0]["cvss"]["score"], 8.1)
        self.assertEqual(out[0]["exploit_scenario"],
                         "Attacker injects SQL via the search box.")
        self.assertIn("cwe", out[0].get("citations", {}))

        report = syn.build_report(out, [], "src", None, "2026-07-23T00:00:00Z")
        errors, _ = syn.validate_report(report)
        self.assertEqual(errors, [])

    def test_agent_cvss_preferred_over_tool_cvss(self):
        findings = [
            {"id": "SG-001", "severity": "HIGH", "confidence": "CERTAIN", "panel": "security",
             "category": "sql-injection", "source": "tool:semgrep",
             "location": {"file": "a.py", "line_start": 10},
             "cvss": {"score": 5.0}, "exploit_scenario": "tool scenario",
             "citations": {"cwe": [{"id": "CWE-89"}]}},
            {"id": "SE-001", "severity": "HIGH", "confidence": "LIKELY", "panel": "security",
             "category": "sql-injection",
             "location": {"file": "a.py", "line_start": 10},
             "cvss": {"score": 8.5}, "exploit_scenario": "agent scenario"},
        ]
        out = syn.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["cvss"]["score"], 8.5)
        self.assertEqual(out[0]["exploit_scenario"], "agent scenario")
        self.assertIn("cwe", out[0].get("citations", {}))

    def test_merge_preserves_missing_text_fields(self):
        findings = [
            {"id": "SG-001", "severity": "HIGH", "confidence": "CERTAIN", "panel": "security",
             "category": "sql-injection", "source": "tool:semgrep",
             "location": {"file": "a.py", "line_start": 10},
             "citations": {"cwe": [{"id": "CWE-89"}]},
             "impact": "Data exfiltration", "references": ["https://example.com"]},
            {"id": "SE-001", "severity": "HIGH", "confidence": "LIKELY", "panel": "security",
             "category": "sql-injection",
             "location": {"file": "a.py", "line_start": 10},
             "cvss": {"score": 8.1}, "exploit_scenario": "x",
             "remediation": "Use parameterized queries"},
        ]
        out = syn.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["impact"], "Data exfiltration")
        self.assertEqual(out[0]["references"], ["https://example.com"])
        self.assertEqual(out[0]["remediation"], "Use parameterized queries")
        self.assertEqual(out[0]["cvss"]["score"], 8.1)


class TestToolsDirIntegration(unittest.TestCase):
    def test_tool_findings_merged_and_reinforced(self):
        with tempfile.TemporaryDirectory() as d:
            agent = os.path.join(d, "findings-g1-security.json")
            with open(agent, "w") as fh:
                json.dump({"findings": [{"id": "SE-001", "title": "sqli", "severity": "HIGH",
                    "confidence": "LIKELY", "panel": "security", "category": "sql-injection",
                    "source": "agent:security-reviewer",
                    "location": {"file": "app/db.py", "line_start": 42},
                    "cvss": {"score": 8.1, "vector": "x"}, "exploit_scenario": "y"}]}, fh)
            td = os.path.join(d, "tools"); os.makedirs(td)
            with open(os.path.join(td, "semgrep.sarif"), "w") as fh:
                json.dump({"runs": [{"tool": {"driver": {"name": "semgrep", "rules": [
                    {"id": "sql-injection", "properties": {"tags": ["CWE-89"]}}]}},
                    "results": [{"ruleId": "sql-injection", "level": "error",
                    "message": {"text": "SQL injection"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/db.py"},
                    "region": {"startLine": 42}}}]}]}]}, fh)
            out = os.path.join(d, "report.json")
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                syn.main(["--target", "src", "--tools-dir", td, "--out", out, agent])
            with open(out) as _fh:
                report = json.load(_fh)
            secs = [f for f in report["findings"] if f["panel"] == "security"]
            self.assertEqual(len(secs), 1)          # agent+tool at same locus deduped to one
            self.assertTrue(secs[0].get("reinforced"))
            self.assertIn("cwe", secs[0].get("citations", {}))  # tool CWE-89 carried onto survivor


class TestSummaryCitations(unittest.TestCase):
    def test_summary_shows_cwe_and_provenance(self):
        report = syn.build_report(
            [{"id": "SG-001", "title": "sqli", "severity": "HIGH", "confidence": "CERTAIN",
              "panel": "security", "category": "injection", "source": "tool:semgrep",
              "reinforced": True, "location": {"file": "a.py", "line_start": 1},
              "citations": {"cwe": [{"id": "CWE-89", "name": "SQLi", "verified": True}],
                            "ssvc": {"decision": "Act", "model": "deployer-reduced",
                                     "inputs": {"exploitation": "active", "exposure": "open", "impact": "high"}}}}],
            [], "src", None, "2026-07-23T00:00:00Z")
        text = syn.render_summary(report)
        self.assertIn("CWE-89", text)
        self.assertIn("Act", text)
        # the provenance chip shows the evidence status, not "reinforced". No
        # verdict is supplied here, so P2/#446 means this is tool_reported,
        # not tool_confirmed -- reinforcement alone no longer gates.
        self.assertIn("tool_reported", text)

    def test_summary_shows_panel_label(self):
        report = syn.build_report(
            [{"id": "SE-001", "title": "x", "severity": "HIGH", "confidence": "CERTAIN",
              "panel": "security", "category": "novel", "source": "agent:sr",
              "location": {"file": "a", "line_start": 1},
              "cvss": {"score": 8, "vector": "v"}, "exploit_scenario": "e"}],
            [], "t", None, "2026-07-23T00:00:00Z")
        self.assertIn("security", syn.render_summary(report))


class TestCrossPanelCorroboration(unittest.TestCase):
    """Cross-LENS agreement: the same real issue seen through different panels
    carries DIFFERENT categories by nature (security 'input-validation' vs test
    'test-coverage' vs code 'error-handling'), so it never matches dedupe's
    (file, line, category) key. A separate corroboration pass surfaces that N
    distinct panels independently flagged the same locus, WITHOUT collapsing the
    distinct-lens findings into one."""

    def _f(self, fid, panel, category, line, sev="HIGH", conf="POSSIBLE",
           file="app/resolver.py", **kw):
        base = {"id": fid, "title": fid, "severity": sev, "confidence": conf,
                "panel": panel, "category": category,
                "location": {"file": file, "line_start": line}}
        base.update(kw)
        return base

    def test_different_panels_same_locus_corroborate(self):
        # SEC-701 (security, input-validation) + TST-701 (test, test-coverage)
        # at the SAME file:line, DIFFERENT categories -> corroboration.
        findings = [
            self._f("SEC-701", "security", "input-validation", 42,
                    cvss={"score": 8.1, "vector": "v"}, exploit_scenario="e"),
            self._f("TST-701", "test", "test-coverage", 42),
        ]
        report = syn.build_report(findings, [], "src", None, "2026-07-23T00:00:00Z")
        integ = report["cross_panel"]["integration_findings"]
        self.assertEqual(len(integ), 1)
        entry = integ[0]
        self.assertEqual(entry["location"]["file"], "app/resolver.py")
        self.assertEqual(entry["location"]["line_start"], 42)
        self.assertEqual(sorted(entry["panels"]), ["security", "test"])
        self.assertEqual(sorted(entry["finding_ids"]), ["SEC-701", "TST-701"])
        # both distinct-lens findings survive (NOT collapsed into one)
        self.assertEqual(len(report["findings"]), 2)
        self.assertTrue(all(f.get("corroborated") for f in report["findings"]))

    def test_three_lens_agreement(self):
        # security + test + code all converge on one locus, different categories.
        findings = [
            self._f("SE-1", "security", "input-validation", 151,
                    cvss={"score": 9, "vector": "v"}, exploit_scenario="e"),
            self._f("TS-1", "test", "test-coverage", 151),
            self._f("CD-1", "code", "error-handling", 151),
        ]
        report = syn.build_report(findings, [], "src", None, "2026-07-23T00:00:00Z")
        integ = report["cross_panel"]["integration_findings"]
        self.assertEqual(len(integ), 1)
        self.assertEqual(sorted(integ[0]["panels"]), ["code", "security", "test"])
        self.assertEqual(len(report["findings"]), 3)          # none collapsed

    def test_negative_different_files_do_not_corroborate(self):
        # Two findings, different panels, but at genuinely different loci
        # (different files) -> NO false corroboration.
        findings = [
            self._f("SE-1", "security", "input-validation", 42, file="a.py",
                    cvss={"score": 8, "vector": "v"}, exploit_scenario="e"),
            self._f("TS-1", "test", "test-coverage", 42, file="b.py"),
        ]
        report = syn.build_report(findings, [], "src", None, "2026-07-23T00:00:00Z")
        self.assertEqual(report["cross_panel"]["integration_findings"], [])
        self.assertFalse(any(f.get("corroborated") for f in report["findings"]))

    def test_negative_far_apart_lines_do_not_corroborate(self):
        # Same file, different panels, but lines beyond the proximity window
        # -> genuinely different issues, not corroboration.
        findings = [
            self._f("SE-1", "security", "input-validation", 10,
                    cvss={"score": 8, "vector": "v"}, exploit_scenario="e"),
            self._f("TS-1", "test", "test-coverage", 90),
        ]
        report = syn.build_report(findings, [], "src", None, "2026-07-23T00:00:00Z")
        self.assertEqual(report["cross_panel"]["integration_findings"], [])

    def test_negative_same_panel_not_cross_panel(self):
        # Two SAME-panel findings at one line are within-lens, not cross-panel
        # corroboration (only ONE distinct panel present at the locus).
        findings = [
            self._f("CD-1", "code", "structure", 5),
            self._f("CD-2", "code", "naming", 5),
        ]
        report = syn.build_report(findings, [], "src", None, "2026-07-23T00:00:00Z")
        self.assertEqual(report["cross_panel"]["integration_findings"], [])
        self.assertFalse(any(f.get("corroborated") for f in report["findings"]))

    def test_proximity_window_adjacent_lines(self):
        # Panels citing adjacent lines (function def at 150, vulnerable call at
        # 151) within CORROBORATION_LINE_WINDOW still corroborate.
        self.assertGreaterEqual(syn.CORROBORATION_LINE_WINDOW, 1)
        findings = [
            self._f("SE-1", "security", "input-validation", 150,
                    cvss={"score": 8, "vector": "v"}, exploit_scenario="e"),
            self._f("CD-1", "code", "error-handling", 151),
        ]
        report = syn.build_report(findings, [], "src", None, "2026-07-23T00:00:00Z")
        self.assertEqual(len(report["cross_panel"]["integration_findings"]), 1)

    def test_confidence_not_mutated_by_corroboration(self):
        # Amended spec: confidence is never mutated by the pipeline — it is
        # purely the reviewer's self-assessment. Corroboration still annotates
        # `corroborated`/`corroborated_by` but must leave confidence as-is.
        fs = [
            self._f("SE-1", "security", "input-validation", 7, conf="POSSIBLE"),
            self._f("CD-1", "code", "error-handling", 7, conf="CERTAIN"),
        ]
        integ = syn.cross_panel_corroboration(fs)
        self.assertEqual(len(integ), 1)
        by_id = {f["id"]: f for f in fs}
        self.assertEqual(by_id["SE-1"]["confidence"], "POSSIBLE")
        self.assertEqual(by_id["CD-1"]["confidence"], "CERTAIN")
        self.assertTrue(by_id["SE-1"]["corroborated"])
        self.assertTrue(by_id["CD-1"]["corroborated"])

    def test_integration_entry_records_max_severity(self):
        integ = syn.cross_panel_corroboration([
            self._f("SE-1", "security", "input-validation", 3, sev="CRITICAL"),
            self._f("CD-1", "code", "error-handling", 3, sev="LOW"),
        ])
        self.assertEqual(integ[0]["severity"], "CRITICAL")

    def test_does_not_break_tool_agent_reinforce(self):
        # A tool+agent pair (dedupe collapses -> 1 security finding) plus an
        # independent test finding at the same locus -> the reinforced survivor
        # AND the test finding corroborate cross-panel.
        findings = [
            {"id": "SG-1", "severity": "HIGH", "confidence": "CERTAIN",
             "panel": "security", "category": "sqli", "source": "tool:semgrep",
             "location": {"file": "db.py", "line_start": 10},
             "citations": {"cwe": [{"id": "CWE-89", "verified": True}]}},
            {"id": "SE-1", "severity": "HIGH", "confidence": "LIKELY",
             "panel": "security", "category": "sqli",
             "location": {"file": "db.py", "line_start": 10},
             "cvss": {"score": 8, "vector": "v"}, "exploit_scenario": "e"},
            {"id": "TS-1", "severity": "MEDIUM", "confidence": "POSSIBLE",
             "panel": "test", "category": "test-coverage",
             "location": {"file": "db.py", "line_start": 10}},
        ]
        report = syn.build_report(findings, [], "src", None, "2026-07-23T00:00:00Z")
        secs = [f for f in report["findings"] if f["panel"] == "security"]
        self.assertEqual(len(secs), 1)                      # tool+agent still collapsed
        self.assertTrue(secs[0].get("reinforced"))          # reinforce preserved
        self.assertEqual(len(report["cross_panel"]["integration_findings"]), 1)

    def test_summary_renders_corroboration_section(self):
        findings = [
            self._f("SE-1", "security", "input-validation", 42,
                    cvss={"score": 8, "vector": "v"}, exploit_scenario="e"),
            self._f("TS-1", "test", "test-coverage", 42),
        ]
        report = syn.build_report(findings, [], "src", None, "2026-07-23T00:00:00Z")
        text = syn.render_summary(report)
        self.assertIn("Cross-panel", text)
        self.assertIn("app/resolver.py:42", text)

    def test_schema_defines_integration_finding_items(self):
        ref = os.path.join(os.path.dirname(__file__), os.pardir, "skill", "reference",
                           "report-schema.json")
        with open(ref, encoding="utf-8") as fh:
            schema = json.load(fh)
        items = schema["properties"]["cross_panel"]["properties"]["integration_findings"]["items"]
        self.assertEqual(items["type"], "object")
        self.assertIn("panels", items["properties"])
        self.assertIn("finding_ids", items["properties"])
        # the finding-level corroboration annotations are documented too
        fprops = schema["properties"]["findings"]["items"]["properties"]
        self.assertIn("corroborated", fprops)
        self.assertIn("corroborated_by", fprops)


class TestHtmlOut(unittest.TestCase):
    def test_html_out_writes_file(self):
        with tempfile.TemporaryDirectory() as d:
            out_json = os.path.join(d, "report.json")
            out_html = os.path.join(d, "report.html")
            finding = os.path.join(d, "findings-x-code.json")
            with open(finding, "w") as fh:
                json.dump({"findings": [{"id": "CODE-001", "title": "x", "severity": "LOW",
                                          "panel": "code", "category": "style",
                                          "location": {"file": "a.py", "line_start": 1}}]}, fh)
            rc = syn.main(["--target", "test", "--out", out_json, "--html-out", out_html, finding])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out_html))
            with open(out_html) as fh:
                self.assertIn("<!DOCTYPE html>", fh.read())

    def test_compare_mode_writes_html(self):
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.json")
            b = os.path.join(d, "b.json")
            out = os.path.join(d, "compare.html")
            for path, findings in [(a, []), (b, [{"id": "CODE-001", "title": "x", "severity": "LOW",
                                                   "panel": "code", "category": "style",
                                                   "location": {"file": "a.py", "line_start": 1},
                                                   "evidence": {"status": "unverified", "verified_by": None,
                                                                "reasoning": None, "citation_quality": "none"}}])]:
                with open(path, "w") as fh:
                    json.dump({
                        "meta": {"target": "t", "review_type": "repo", "timestamp": "2026-08-01",
                                 "version": "4.0.0", "security_mode": "standard"},
                        "summary": {"overall_grade": "A", "risk_level": "LOW", "top_issues": [],
                                    "gate": "PASS", "gate_policy": "confirmed_only",
                                    "stats": {"critical": 0, "high": 0, "medium": 0, "low": len(findings), "info": 0},
                                    "evidence_stats": {}},
                        "groups": [], "findings": findings,
                        "cross_panel": {"integration_findings": []},
                    }, fh)
            rc = syn.main(["--compare", a, b, "--html-out", out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))
            with open(out) as fh:
                content = fh.read()
                self.assertIn("new", content)

    def test_compare_missing_file_errors_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            valid = os.path.join(d, "valid.json")
            missing = os.path.join(d, "missing.json")
            out = os.path.join(d, "compare.html")
            with open(valid, "w") as fh:
                json.dump({
                    "meta": {"target": "t", "review_type": "repo", "timestamp": "2026-08-01",
                             "version": "4.0.0", "security_mode": "standard"},
                    "summary": {"overall_grade": "A", "risk_level": "LOW", "top_issues": [],
                                "gate": "PASS", "gate_policy": "confirmed_only",
                                "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                                "evidence_stats": {}},
                    "groups": [], "findings": [],
                    "cross_panel": {"integration_findings": []},
                }, fh)
            with unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as captured:
                rc = syn.main(["--compare", missing, valid, "--html-out", out])
            self.assertNotEqual(rc, 0)
            self.assertIn("cannot read", captured.getvalue())

    def test_compare_invalid_json_errors_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            valid = os.path.join(d, "valid.json")
            invalid = os.path.join(d, "invalid.json")
            out = os.path.join(d, "compare.html")
            with open(valid, "w") as fh:
                json.dump({
                    "meta": {"target": "t", "review_type": "repo", "timestamp": "2026-08-01",
                             "version": "4.0.0", "security_mode": "standard"},
                    "summary": {"overall_grade": "A", "risk_level": "LOW", "top_issues": [],
                                "gate": "PASS", "gate_policy": "confirmed_only",
                                "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                                "evidence_stats": {}},
                    "groups": [], "findings": [],
                    "cross_panel": {"integration_findings": []},
                }, fh)
            with open(invalid, "w") as fh:
                fh.write("not json")
            with unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as captured:
                rc = syn.main(["--compare", invalid, valid, "--html-out", out])
            self.assertNotEqual(rc, 0)
            self.assertIn("invalid JSON", captured.getvalue())

    def test_derive_html_path_is_case_insensitive(self):
        self.assertEqual(syn._derive_html_path("report.json"), "report.json.html")
        self.assertEqual(syn._derive_html_path("report.JSON"), "report.JSON.html")
        self.assertEqual(syn._derive_html_path("report.Json"), "report.Json.html")
        self.assertEqual(syn._derive_html_path("dir"), os.path.join("dir", "report.html"))


class TestInternalFieldCleanup(unittest.TestCase):
    def test_build_report_does_not_leak_internal_fields(self):
        # Two findings, not one: f1's REJECTED verdict moves it OUT of
        # report["findings"] and into report["discarded_claims"], so a
        # single-finding fixture leaves exactly one of the two leak-check
        # loops below vacuous no matter which list the finding lands in.
        # f2 carries no verdict and stays in report["findings"], so both
        # lists are guaranteed non-empty and both loops actually run over
        # real data.
        f1 = {
            "id": "SEC-001", "title": "SQLi", "severity": "HIGH", "confidence": "LIKELY",
            "panel": "security", "category": "injection",
            "provenance": {"discovered_by": "agent:lens_sweep"},
            "location": {"file": "app.py", "line_start": 10},
            "_group": "backend",
            "_repo_root": "/some/path",
        }
        f2 = {
            "id": "SEC-002", "title": "XSS", "severity": "MEDIUM", "confidence": "LIKELY",
            "panel": "security", "category": "xss",
            "provenance": {"discovered_by": "agent:lens_sweep"},
            "location": {"file": "app.py", "line_start": 55},
            "_group": "backend",
            "_repo_root": "/some/path",
        }
        verdicts = {syn.finding_fingerprint(f1):
                    {"finding_id": "SEC-001", "verdict": "REJECTED",
                     "reasoning": "False positive."}}
        report = syn.build_report(
            [f1, f2], [], "src", None, "2026-07-23T00:00:00Z", verdicts=verdicts)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(len(report.get("discarded_claims", [])), 1)
        for finding in report["findings"]:
            self.assertNotIn("_group", finding)
            self.assertNotIn("_repo_root", finding)
        for finding in report.get("discarded_claims", []):
            self.assertNotIn("_group", finding)
            self.assertNotIn("_repo_root", finding)


class TestGroupReMatchesDispatchNames(unittest.TestCase):
    def test_matches_names_actually_produced_by_dispatch(self):
        import scripts.dispatch as dispatch
        profile = {"group": "changes_1", "files": ["a.py"], "depth": "standard",
                   "panels": ["security"],
                   "lenses": {"security": [
                       {"name": "injection", "spawn": True, "priority": 1,
                        "depth_threshold": "shallow"}]}}
        plan = dispatch.build_plan(profile, host="claude")
        self.assertTrue(plan)
        for inv in plan:
            base = os.path.basename(inv["out_file"])
            m = syn.GROUP_RE.match(base)
            self.assertIsNotNone(m, base)
            self.assertEqual(m.group(1), "changes_1", base)

    def test_still_matches_legacy_2x_names(self):
        m = syn.GROUP_RE.match("findings-changes_1-security.json")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "changes_1")


def _agentic(fid="AG-001", sev="HIGH", **kw):
    f = {"id": fid, "title": "finding %s" % fid, "severity": sev,
         "confidence": "POSSIBLE", "panel": "security", "category": "injection",
         "location": {"file": "app.py", "line_start": 10},
         "provenance": {"discovered_by": "agent:panel_review",
                        "confirmation_status": "UNVERIFIED"}}
    f.update(kw)
    return f


class TestEvidenceReport(unittest.TestCase):
    def _report(self, findings, verdicts=None, gate_unverified=False, fail_on="high"):
        return syn.build_report(findings, [], "target", fail_on, "2026-08-03T00:00:00Z",
                                verdicts=verdicts, gate_unverified=gate_unverified)

    def test_unverified_keeps_severity_and_does_not_gate(self):
        report = self._report([_agentic(sev="CRITICAL")])
        f = report["findings"][0]
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertEqual(f["evidence"]["status"], "unverified")
        self.assertEqual(report["summary"]["gate"], "PASS")
        self.assertEqual(report["summary"]["overall_grade"], "A")

    def test_gate_unverified_opts_in(self):
        report = self._report([_agentic(sev="CRITICAL")], gate_unverified=True)
        self.assertEqual(report["summary"]["gate"], "FAIL")
        self.assertEqual(report["summary"]["overall_grade"], "F")
        self.assertEqual(report["summary"]["gate_policy"], "include_unverified")

    def test_confirmed_verdict_gates(self):
        finding = _agentic()
        verdicts = {syn.finding_fingerprint(finding):
                    {"finding_id": "AG-001", "verdict": "CONFIRMED",
                     "reasoning": "verified"}}
        report = self._report([finding], verdicts=verdicts)
        f = report["findings"][0]
        self.assertEqual(f["evidence"]["status"], "advisor_confirmed")
        self.assertEqual(report["summary"]["gate"], "FAIL")
        self.assertEqual(report["summary"]["overall_grade"], "D")

    def test_rejected_moves_to_discarded_with_severity_intact(self):
        finding = _agentic()
        verdicts = {syn.finding_fingerprint(finding):
                    {"finding_id": "AG-001", "verdict": "REJECTED",
                     "reasoning": "not exploitable"}}
        report = self._report([finding], verdicts=verdicts)
        self.assertEqual(report["findings"], [])
        d = report["discarded_claims"][0]
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["evidence"]["status"], "rejected")
        self.assertEqual(d["evidence"]["reasoning"], "not exploitable")
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_needs_more_info_stays_visible_not_gating(self):
        finding = _agentic()
        verdicts = {syn.finding_fingerprint(finding):
                    {"finding_id": "AG-001",
                     "verdict": "NEEDS_MORE_INFO",
                     "reasoning": "need deploy config"}}
        report = self._report([finding], verdicts=verdicts)
        f = report["findings"][0]
        self.assertEqual(f["evidence"]["status"], "needs_more_info")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_tool_finding_without_verdict_is_reported_not_gated(self):
        # P2/#446: this is the load-bearing regression test for the Bandit
        # B105 self-scan incident -- an unverified tool claim must NOT gate a
        # build on its own. It is tool_reported until an advisor confirms it.
        tool = {"id": "TL-001", "title": "sqli", "severity": "HIGH",
                "confidence": "CERTAIN", "panel": "security",
                "category": "injection", "source": "tool:semgrep",
                "location": {"file": "app.py", "line_start": 5},
                "provenance": {"discovered_by": "tool:semgrep",
                               "confirmation_status": "TOOL"}}
        report = self._report([syn.normalize_finding(tool)])
        self.assertEqual(report["findings"][0]["evidence"]["status"],
                         "tool_reported")
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_evidence_stats_counts_everything(self):
        f1 = _agentic()
        # distinct locus for AG-002 so dedupe doesn't collapse it into AG-001
        # (same file/line/category would otherwise keep only the more severe one).
        f2 = _agentic(fid="AG-002", sev="LOW",
                      location={"file": "app.py", "line_start": 99})
        verdicts = {syn.finding_fingerprint(f1):
                    {"finding_id": "AG-001", "verdict": "REJECTED",
                     "reasoning": "r"}}
        report = self._report([f1, f2], verdicts=verdicts)
        stats = report["summary"]["evidence_stats"]
        self.assertEqual(stats["rejected"], 1)
        self.assertEqual(stats["unverified"], 1)

    def test_schema_theater_removed(self):
        report = self._report([_agentic()])
        self.assertNotIn("effort_to_remediate", report["summary"])
        self.assertNotIn("recommendations", report)
        self.assertEqual(report["meta"]["version"], "4.2.0")

    def test_citation_quality_lives_in_evidence(self):
        report = self._report([_agentic(citations={"cwe": ["CWE-89"]})])
        f = report["findings"][0]
        self.assertNotIn("citation_quality", f)
        self.assertIn(f["evidence"]["citation_quality"],
                      ("full", "partial", "minimal", "none"))

    def test_reinforced_tool_agent_merge_without_verdict_does_not_gate(self):
        # P2/#446: a tool HIGH + agent CRITICAL at the same locus reinforce to
        # a single survivor, which is tool-reported by construction (never
        # demoted to mere `corroborated`) -- but reinforcement alone is no
        # longer gate-eligible without an advisor CONFIRMED verdict, same as
        # any other tool claim. Gate stays PASS under --fail-on high.
        tool = {"id": "TL-002", "title": "sqli", "severity": "HIGH",
                "confidence": "CERTAIN", "panel": "security", "category": "injection",
                "source": "tool:semgrep",
                "location": {"file": "app.py", "line_start": 20}}
        agent = {"id": "AG-201", "title": "sqli (agent)", "severity": "CRITICAL",
                 "confidence": "POSSIBLE", "panel": "security", "category": "injection",
                 "location": {"file": "app.py", "line_start": 20}}
        report = self._report([tool, agent])
        self.assertEqual(len(report["findings"]), 1)
        f = report["findings"][0]
        self.assertTrue(f.get("reinforced"))
        self.assertEqual(f["evidence"]["status"], "tool_reported")
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_unknown_queue_id_verdict_ignored(self):
        # A verdict file whose stem doesn't match any current queue_id (e.g.
        # a stale verdict from a prior pass) must not silently vanish -> spec
        # requires a stderr warning naming it, and the report is unaffected.
        verdicts = {"999-UNKNOWN": {"finding_id": "AG-999", "verdict": "CONFIRMED",
                                    "reasoning": "r"}}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            report = self._report([_agentic()], verdicts=verdicts)
        f = report["findings"][0]
        self.assertEqual(f["evidence"]["status"], "unverified")
        self.assertIn("999-UNKNOWN", err.getvalue())


# Expected evidence.status once a verdict genuinely reaches apply_verdict,
# for an _agentic() (non-tool, non-reinforced) finding. Used by
# TestSeverityImmutability to prove its verdicts actually applied -- without
# this, a future queue_id-key regression (like the one fixed by #443) would
# make "severity/confidence unchanged" trivially true again, because nothing
# would have been applied at all.
_VERDICT_STATUS = {"REJECTED": "rejected", "NEEDS_MORE_INFO": "needs_more_info",
                   "CONFIRMED": "advisor_confirmed"}


class TestSeverityImmutability(unittest.TestCase):
    def test_no_path_mutates_severity(self):
        cases = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cases.append((_agentic(fid="AG-%s" % sev[:2], sev=sev), None))
        cases.append((_agentic(fid="AG-101"), {"verdict": "REJECTED", "reasoning": "r"}))
        cases.append((_agentic(fid="AG-102"), {"verdict": "NEEDS_MORE_INFO",
                                               "reasoning": "r"}))
        cases.append((_agentic(fid="AG-103"), {"verdict": "CONFIRMED",
                                               "reasoning": "r"}))
        for finding, verdict in cases:
            original = finding["severity"]
            verdicts = ({syn.finding_fingerprint(finding):
                         dict(verdict, finding_id=finding["id"])}
                        if verdict else None)
            report = syn.build_report([finding], [], "t", "high",
                                      "2026-08-03T00:00:00Z", verdicts=verdicts)
            everywhere = report["findings"] + report["discarded_claims"]
            self.assertEqual(everywhere[0]["severity"], original,
                             "severity mutated for verdict=%r" % verdict)
            if verdict:
                self.assertEqual(
                    everywhere[0]["evidence"]["status"],
                    _VERDICT_STATUS[verdict["verdict"]],
                    "verdict %r did not actually reach apply_verdict" % verdict)

    def test_no_path_mutates_confidence(self):
        # Amended spec: confidence, like severity, is never mutated by the
        # pipeline after normalize_finding — no exceptions (the legacy
        # dedupe/corroboration confidence bumps are removed).
        cases = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cases.append((_agentic(fid="AG-%s" % sev[:2], sev=sev), None))
        cases.append((_agentic(fid="AG-101"), {"verdict": "REJECTED", "reasoning": "r"}))
        cases.append((_agentic(fid="AG-102"), {"verdict": "NEEDS_MORE_INFO",
                                               "reasoning": "r"}))
        cases.append((_agentic(fid="AG-103"), {"verdict": "CONFIRMED",
                                               "reasoning": "r"}))
        for finding, verdict in cases:
            original = finding["confidence"]
            verdicts = ({syn.finding_fingerprint(finding):
                         dict(verdict, finding_id=finding["id"])}
                        if verdict else None)
            report = syn.build_report([finding], [], "t", "high",
                                      "2026-08-03T00:00:00Z", verdicts=verdicts)
            everywhere = report["findings"] + report["discarded_claims"]
            self.assertEqual(everywhere[0]["confidence"], original,
                             "confidence mutated for verdict=%r" % verdict)
            if verdict:
                self.assertEqual(
                    everywhere[0]["evidence"]["status"],
                    _VERDICT_STATUS[verdict["verdict"]],
                    "verdict %r did not actually reach apply_verdict" % verdict)


class TestTwoPassCli(unittest.TestCase):
    def _write_findings(self, d, findings):
        fp = os.path.join(d, ".panopticon", "findings-g1-security-panel_review.json")
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "w") as fh:
            json.dump({"findings": findings}, fh)
        return fp

    def test_pass1_emits_queue_not_report(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = self._write_findings(d, [_agentic()])
            out = os.path.join(d, "report.json")
            rc = syn.main(["--emit-verify-queue", "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertFalse(os.path.exists(out))
            with open(os.path.join(d, ".panopticon", "verify-queue.json")) as fh:
                queue = json.load(fh)
            # queue_id is the finding's content fingerprint (#443), not a
            # position-based "NNN-id".
            self.assertEqual(queue["entries"][0]["queue_id"],
                             syn.finding_fingerprint(queue["entries"][0]["finding"]))

    def test_pass1_empty_queue_falls_through_to_report(self):
        # Post-SEC-102 an agent-authored finding always queues; an empty queue
        # means there was nothing agentic to verify.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = self._write_findings(d, [])
            out = os.path.join(d, "report.json")
            rc = syn.main(["--emit-verify-queue", "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))

    def test_pass2_applies_verdicts(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            finding = _agentic()
            fp = self._write_findings(d, [finding])
            vd = os.path.join(d, ".panopticon", "verdicts")
            os.makedirs(vd)
            qid = syn.finding_fingerprint(finding)
            with open(os.path.join(vd, "%s.json" % qid), "w") as fh:
                json.dump({"finding_id": "AG-001", "verdict": "CONFIRMED",
                           "reasoning": "verified"}, fh)
            out = os.path.join(d, "report.json")
            rc = syn.main(["--verdicts-dir", vd, "--fail-on", "high",
                           "--out", out, fp])
            self.assertEqual(rc, 1)  # gate FAIL -> exit 1
            with open(out) as fh:
                report = json.load(fh)
            self.assertEqual(report["findings"][0]["evidence"]["status"],
                             "advisor_confirmed")
            self.assertEqual(report["summary"]["gate"], "FAIL")

    def test_gate_unverified_flag(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = self._write_findings(d, [_agentic(sev="CRITICAL")])
            out = os.path.join(d, "report.json")
            rc = syn.main(["--gate-unverified", "--fail-on", "critical",
                           "--out", out, fp])
            self.assertEqual(rc, 1)

    def test_pass1_empty_queue_removes_stale_queue_file(self):
        # A queue file left by a PREVIOUS run must not survive a run whose
        # queue is empty this time -> SKILL.md step 7 branches on the file's
        # existence, and a stale file would mislead a re-run into the verify
        # phase.
        # Post-P2 EVERY finding queues -- tool findings included -- so "empty
        # queue this time" means the run produced no findings at all.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = self._write_findings(d, [])
            qpath = os.path.join(d, ".panopticon", "verify-queue.json")
            with open(qpath, "w") as fh:
                json.dump({"version": "4.0.0", "cut_by_max_verify": 0,
                           "entries": [{"queue_id": "000-STALE", "priority": 1,
                                        "finding": {}}]}, fh)
            out = os.path.join(d, "report.json")
            rc = syn.main(["--emit-verify-queue", "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))
            self.assertFalse(os.path.exists(qpath))

    def test_verdicts_dir_empty_but_present_prints_aggregate_note(self):
        # --verdicts-dir pointing at an existing but EMPTY directory must
        # still surface the aggregate "no verdict" note for queued agentic
        # findings -- keying the note on the dict being non-empty silently
        # swallowed this case.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = self._write_findings(d, [_agentic()])
            vd = os.path.join(d, ".panopticon", "verdicts")
            os.makedirs(vd)
            out = os.path.join(d, "report.json")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = syn.main(["--verdicts-dir", vd, "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertIn("no verdict", err.getvalue())

    def test_corrupt_verdict_file_surfaced_in_coverage(self):
        # #938 end-to-end: a verdict file with an unescaped internal quote must
        # route through load_verdicts_detailed into meta.coverage.verdicts.
        # unloadable, not vanish with only a stderr note.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = self._write_findings(d, [_agentic()])
            vd = os.path.join(d, ".panopticon", "verdicts")
            os.makedirs(vd)
            with open(os.path.join(vd, "deadbeefdeadbeef.json"), "w") as fh:
                fh.write('{"verdict": "CONFIRMED", '
                         '"reasoning": "the "eval" call is safe"}')  # unescaped "
            out = os.path.join(d, "report.json")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = syn.main(["--verdicts-dir", vd, "--out", out, fp])
            self.assertEqual(rc, 0)
            with open(out) as fh:
                report = json.load(fh)
            self.assertEqual(
                report["meta"]["coverage"]["verdicts"]["unloadable"], 1)
            self.assertIn("un-loadable", err.getvalue())

    def test_pass1_cli_and_pass2_build_report_agree_on_fingerprints(self):
        # #443: pass 1 (--emit-verify-queue) fed build_verify_queue a bare
        # prepare_findings() list while pass 2 (build_report) aggregated
        # first -- so a tool rule firing twice in one file produced two ids
        # in the queue file but one finding (one fingerprint) in the final
        # report, and an advisor verdict keyed on one of those two ids landed
        # nowhere pass 2 recognized. TestBothPassesAgree (test_verify_queue.py)
        # proves prepare_for_queue is deterministic across two calls on the
        # same input, which would NOT catch a caller left on the old
        # prepare_findings-only path -- so this drives the two REAL CLI passes
        # (main() with and without --emit-verify-queue) over one fixture,
        # ingesting a real SARIF tool file through --tools-dir (load_findings
        # strips a self-asserted 'source' from agent-authored JSON, so a
        # bare findings-*.json fixture can't stand in for a genuine tool
        # hit -- only the ingest_tools path sets it), and compares the
        # resulting id sets directly.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            agent = os.path.join(d, "findings-g1-code.json")
            with open(agent, "w") as fh:
                json.dump({"findings": [
                    {"id": "A-1", "title": "tangled branch", "severity": "MEDIUM",
                     "confidence": "POSSIBLE", "panel": "code", "category": "logic",
                     "location": {"file": "svc.py", "line_start": 7}}]}, fh)
            td = os.path.join(d, "tools")
            os.makedirs(td)
            with open(os.path.join(td, "bandit.sarif"), "w") as fh:
                json.dump({"runs": [{"tool": {"driver": {"name": "bandit", "rules": [
                    {"id": "B105"}]}},
                    "results": [
                        {"ruleId": "B105", "level": "error",
                         "message": {"text": "hardcoded password"},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": "app.py"},
                             "region": {"startLine": 10}}}]},
                        {"ruleId": "B105", "level": "error",
                         "message": {"text": "hardcoded password"},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": "app.py"},
                             "region": {"startLine": 20}}}]},
                    ]}]}, fh)

            queue_out = os.path.join(d, "unused-report.json")
            rc1 = syn.main(["--emit-verify-queue", "--tools-dir", td,
                            "--out", queue_out, agent])
            self.assertEqual(rc1, 0)
            with open(os.path.join(d, ".panopticon", "verify-queue.json")) as fh:
                queue = json.load(fh)
            # queue_id, not a recomputed fingerprint: recomputing from
            # entry["finding"] would strip the -1 collision suffix and make
            # an unaggregated duplicate pair indistinguishable from one
            # aggregated survivor, hiding exactly the bug this guards.
            pass1_qids = {e["queue_id"] for e in queue["entries"]}

            # Verdict the TOOL entry -- the normal pass-2 path now that every
            # finding queues, and the one that used to rot the exported
            # identity. apply_verdict overwrites provenance.
            # confirmation_reasoning, which is exactly where the SARIF
            # adapters park the rule id that finding_fingerprint reads back
            # for a tool finding (evidence.tool_rule_id's fallback). Assigning
            # f["fingerprint"] from a fingerprint recomputed AFTER the verdict
            # loop therefore hashed the advisor's prose: a fresh "stable
            # cross-run identity" every time an advisor re-worded itself.
            tool_entries = [e for e in queue["entries"]
                            if str(e["finding"].get("source", "")).startswith("tool:")]
            self.assertEqual(len(tool_entries), 1)
            tool_qid = tool_entries[0]["queue_id"]
            vd = os.path.join(d, "verdicts")
            os.makedirs(vd)
            with open(os.path.join(vd, "%s.json" % tool_qid), "w") as fh:
                json.dump({"finding_id": tool_entries[0]["finding"].get("id"),
                           "verdict": "CONFIRMED",
                           "reasoning": "Advisor prose, deliberately nothing "
                                        "like the rule id B105."}, fh)

            report_out = os.path.join(d, "report.json")
            rc2 = syn.main(["--tools-dir", td, "--verdicts-dir", vd,
                            "--out", report_out, agent])
            self.assertEqual(rc2, 0)
            with open(report_out) as fh:
                report = json.load(fh)
            emitted = report["findings"] + report["discarded_claims"]
            tool_out = [f for f in emitted
                        if str(f.get("source", "")).startswith("tool:")]
            self.assertEqual(len(tool_out), 1)
            self.assertEqual(tool_out[0]["evidence"]["status"], "tool_confirmed")
            # Applying a verdict must not move the exported identity off the
            # queue id the run already committed to (and that scripts/
            # file_issues.py keys its resume ledger and issue bodies on).
            self.assertEqual(tool_out[0]["fingerprint"], tool_qid)

            pass2_fps = {f["fingerprint"] for f in emitted}
            self.assertTrue(pass1_qids)
            # Exact only because nothing in this fixture collides. Adding a
            # COLLIDING pair would break this for a reason unrelated to #443:
            # the queue ids would be {fp, fp-1} while both findings export
            # fingerprint fp (see the divergence comments in
            # evidence.build_verify_queue and synthesize.build_report).
            self.assertEqual(pass1_qids, pass2_fps)


class TestDedupeRuleIdDiscrimination(unittest.TestCase):
    """Calibration 2026-08-03: distinct advisories at the same manifest locus
    must not collapse to one-per-category (22 real osv findings survived as 3)."""

    def _dep(self, fid, rule, sev="MEDIUM"):
        return {"id": fid, "title": rule, "severity": sev, "confidence": "CERTAIN",
                "panel": "security", "category": "dependency_vulnerability",
                "source": "tool:osv-scanner",
                "location": {"file": "requirements.txt", "line_start": 1},
                "tool_evidence": {"rule_id": rule},
                "provenance": {"discovered_by": "tool:osv-scanner",
                               "confirmation_status": "TOOL"}}

    def test_distinct_rule_ids_all_survive(self):
        findings = [self._dep("OS-001", "GHSA-aaaa"), self._dep("OS-002", "GHSA-bbbb"),
                    self._dep("OS-003", "GHSA-cccc", sev="CRITICAL")]
        out = syn.dedupe(findings)
        self.assertEqual(len(out), 3)
        self.assertEqual({f["tool_evidence"]["rule_id"] for f in out},
                         {"GHSA-aaaa", "GHSA-bbbb", "GHSA-cccc"})

    def test_same_rule_id_still_collapses_to_most_severe(self):
        findings = [self._dep("OS-001", "GHSA-aaaa", sev="MEDIUM"),
                    self._dep("OS-002", "GHSA-aaaa", sev="HIGH"),
                    self._dep("OS-003", "GHSA-bbbb")]
        out = syn.dedupe(findings)
        self.assertEqual(len(out), 2)
        kept = {f["tool_evidence"]["rule_id"]: f["severity"] for f in out}
        self.assertEqual(kept["GHSA-aaaa"], "HIGH")

    def test_tool_agent_reinforce_survives_rule_bucketing(self):
        agent = {"id": "AG-001", "title": "vulnerable dep use", "severity": "HIGH",
                 "confidence": "POSSIBLE", "panel": "security",
                 "category": "dependency_vulnerability",
                 "location": {"file": "requirements.txt", "line_start": 1},
                 "provenance": {"discovered_by": "agent:panel_review",
                                "confirmation_status": "UNVERIFIED"}}
        findings = [self._dep("OS-001", "GHSA-aaaa"), self._dep("OS-002", "GHSA-bbbb"),
                    agent]
        out = syn.dedupe(findings)
        self.assertEqual(len(out), 3)  # two rules + the agent bucket
        self.assertTrue(all(f.get("reinforced") for f in out))


class TestCalibrationFixmes(unittest.TestCase):
    def test_models_used_dedups_inconsistent_versions(self):
        # F-CAL-3: same model+role with three self-reported version spellings -> 1 entry
        fs = []
        for i, ver in enumerate(("claude-haiku-4-5-20251001", "4.5", "20251001")):
            fs.append({"id": "AG-%03d" % i, "title": "t", "severity": "LOW",
                       "confidence": "NOTE", "panel": "code", "category": "style",
                       "location": {"file": "a.py", "line_start": i + 1},
                       "provenance": {"discovered_by": "agent:lens_sweep",
                                      "model": "claude-haiku-4-5-20251001",
                                      "model_version": ver,
                                      "confirmation_status": "UNVERIFIED"}})
        entries = syn._collect_models_used(fs)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["model"], "claude-haiku-4-5-20251001")

    def test_id_re_accepts_real_agent_prefixes(self):
        # F-CAL-4: observed real ids like STRUCT-001 (6 letters) must validate
        for good in ("CD-001", "STRUCT-001", "ABCDEFGH-123"):
            self.assertIsNotNone(syn.ID_RE.match(good), good)
        for bad in ("A-001", "ABCDEFGHI-001", "struct-001", "SEC-01"):
            self.assertIsNone(syn.ID_RE.match(bad), bad)


class TestToolPolicyMode(unittest.TestCase):
    def _write_plan(self, d, flags):
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        plan = [{"role": "panel_review", "enforced": f} for f in flags]
        with open(os.path.join(d, ".panopticon", "dispatch-plan.json"), "w") as fh:
            json.dump(plan, fh)

    def test_all_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            self._write_plan(d, [True, True])
            self.assertEqual(
                syn.derive_tool_policy_mode(os.path.join(d, ".panopticon")),
                "enforced")

    def test_none_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            self._write_plan(d, [False, False])
            self.assertEqual(
                syn.derive_tool_policy_mode(os.path.join(d, ".panopticon")),
                "advisory")

    def test_mixed(self):
        with tempfile.TemporaryDirectory() as d:
            self._write_plan(d, [True, False])
            self.assertEqual(
                syn.derive_tool_policy_mode(os.path.join(d, ".panopticon")),
                "mixed")

    def test_no_plan_files_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(syn.derive_tool_policy_mode(d), "unknown")

    def test_report_meta_carries_mode_and_new_version(self):
        f = _agentic()
        report = syn.build_report([f], [], "t", None, "2026-08-03T00:00:00Z",
                                  tool_policy_mode="mixed")
        self.assertEqual(report["meta"]["coverage"]["tool_policy_mode"], "mixed")
        self.assertEqual(report["meta"]["version"], "4.2.0")


class TestToolsRanFromDispositions(unittest.TestCase):
    def test_failed_excluded_ok_and_empty_included(self):
        dispositions = {
            "bandit": {"status": "ok", "findings": 3},
            "gitleaks": {"status": "empty", "findings": 0},
            "semgrep": {"status": "failed", "findings": 0,
                        "reason": "empty output file"},
        }
        self.assertEqual(syn.tools_ran_from_dispositions(dispositions),
                         {"bandit", "gitleaks"})

    def test_empty_dispositions_yields_empty_set(self):
        self.assertEqual(syn.tools_ran_from_dispositions({}), set())


class TestBuildExecutingTools(unittest.TestCase):
    def _finding(self, **kw):
        base = {"id": "CD-001", "title": "t", "severity": "LOW", "confidence": "POSSIBLE",
                "panel": "code", "category": "structure",
                "location": {"file": "a.py", "line_start": 3}}
        base.update(kw)
        return base

    def test_meta_records_build_executing_tool(self):
        f = self._finding(source="tool:roslyn-secguard")
        report = syn.build_report([f], [], "t", None, "2026-08-03T00:00:00Z")
        self.assertEqual(report["meta"]["coverage"]["build_executing_tools"],
                         ["roslyn-secguard"])

    def test_meta_empty_without_executing_tools(self):
        f = self._finding(source="tool:bandit")
        report = syn.build_report([f], [], "t", None, "2026-08-03T00:00:00Z")
        self.assertEqual(report["meta"]["coverage"]["build_executing_tools"], [])


import scripts.evidence as evidence_mod  # noqa: E402


class TestEvidenceIntegrity(unittest.TestCase):
    """SEC-102: trust must never derive from a field the finding payload sets."""

    def _agent_file(self, d, findings):
        p = os.path.join(d, "findings-g1-security-panel_review.json")
        with open(p, "w") as fh:
            json.dump({"findings": findings}, fh)
        return p

    def test_agent_cannot_forge_tool_source(self):
        forged = {"id": "AG-001", "title": "forged", "severity": "CRITICAL",
                  "confidence": "CERTAIN", "panel": "security", "category": "injection",
                  "source": "tool:bandit",
                  "location": {"file": "a.py", "line_start": 1}}
        with tempfile.TemporaryDirectory() as d:
            loaded = syn.load_findings([self._agent_file(d, [forged])])
        self.assertNotIn("source", loaded[0])
        self.assertFalse(evidence_mod.is_tool_sourced(loaded[0]))

    def test_agent_cannot_forge_reinforced(self):
        forged = {"id": "AG-002", "title": "forged", "severity": "HIGH",
                  "confidence": "CERTAIN", "panel": "security", "category": "injection",
                  "reinforced": True,
                  "location": {"file": "a.py", "line_start": 2}}
        with tempfile.TemporaryDirectory() as d:
            loaded = syn.load_findings([self._agent_file(d, [forged])])
        self.assertNotIn("reinforced", loaded[0])

    def test_forged_finding_still_reaches_the_verify_queue(self):
        forged = {"id": "AG-003", "title": "forged", "severity": "CRITICAL",
                  "confidence": "CERTAIN", "panel": "security", "category": "injection",
                  "source": "tool:bandit", "reinforced": True,
                  "location": {"file": "a.py", "line_start": 3}}
        with tempfile.TemporaryDirectory() as d:
            loaded = syn.load_findings([self._agent_file(d, [forged])])
        entries, _ = evidence_mod.build_verify_queue(loaded)
        self.assertEqual([e["finding"]["id"] for e in entries], ["AG-003"])

    def test_real_tool_findings_keep_their_source(self):
        # ingest_tools output is not agent-authored and must be untouched.
        tool = {"id": "TL-001", "title": "real", "severity": "HIGH",
                "confidence": "CERTAIN", "panel": "security", "category": "injection",
                "source": "tool:semgrep",
                "location": {"file": "a.py", "line_start": 4},
                "provenance": {"discovered_by": "tool:semgrep",
                               "confirmation_status": "TOOL"}}
        f = syn.normalize_finding(dict(tool))
        self.assertTrue(evidence_mod.is_tool_sourced(f))


class TestSchemaErrorsAreNotSilent(unittest.TestCase):
    def test_report_records_schema_error_count(self):
        bad = _agentic(fid="ag-lower")   # id fails ID_RE
        report = syn.build_report([bad], [], "t", None, "2026-08-03T00:00:00Z")
        errors, _ = syn.validate_report(report)
        self.assertTrue(errors)
        syn.attach_schema_status(report, errors)
        self.assertEqual(report["meta"]["schema_errors"], len(errors))

    def test_clean_report_records_zero(self):
        clean = _agentic(panel="code", category="style", severity="LOW")
        report = syn.build_report([clean], [], "t", None, "2026-08-03T00:00:00Z")
        errors, _ = syn.validate_report(report)
        syn.attach_schema_status(report, errors)
        self.assertEqual(report["meta"]["schema_errors"], 0)


class TestFindingFingerprint(unittest.TestCase):
    """Issues need identity that survives across runs and re-wordings."""

    def _f(self, **kw):
        f = {"id": "SG-001", "title": "t", "severity": "MEDIUM", "confidence": "CERTAIN",
             "panel": "security", "category": "injection",
             "location": {"file": "a.py", "line_start": 10}}
        f.update(kw)
        return f

    def test_stable_across_line_moves(self):
        a = syn.finding_fingerprint(self._f())
        b = syn.finding_fingerprint(self._f(location={"file": "a.py", "line_start": 99}))
        self.assertEqual(a, b)

    def test_stable_across_agent_rewording(self):
        # Agent prose varies run to run; identity must not.
        a = syn.finding_fingerprint(self._f(title="Module mixes concerns",
                                            description="one phrasing"))
        b = syn.finding_fingerprint(self._f(title="Module mixes concerns",
                                            description="a totally different phrasing"))
        self.assertEqual(a, b)

    def test_rule_id_discriminates_tool_findings_at_one_locus(self):
        a = syn.finding_fingerprint(self._f(source="tool:semgrep",
                                            tool_evidence={"rule_id": "R-AAA"}))
        b = syn.finding_fingerprint(self._f(source="tool:semgrep",
                                            tool_evidence={"rule_id": "R-BBB"}))
        self.assertNotEqual(a, b)

    def test_different_files_differ(self):
        a = syn.finding_fingerprint(self._f())
        b = syn.finding_fingerprint(self._f(location={"file": "b.py", "line_start": 10}))
        self.assertNotEqual(a, b)

    def test_leading_dot_of_a_dotfile_path_is_not_stripped(self):
        # `.github/workflows/ci.yml` and `github/workflows/ci.yml` are different
        # paths; only a `./` prefix is noise.
        a = syn.finding_fingerprint(self._f(location={"file": ".github/w/ci.yml"}))
        b = syn.finding_fingerprint(self._f(location={"file": "github/w/ci.yml"}))
        self.assertNotEqual(a, b)

    def test_dot_slash_prefix_is_normalized_away(self):
        a = syn.finding_fingerprint(self._f(location={"file": "./a.py"}))
        b = syn.finding_fingerprint(self._f(location={"file": "a.py"}))
        self.assertEqual(a, b)

    def test_report_findings_carry_fingerprints(self):
        report = syn.build_report([_agentic()], [], "t", None, "2026-08-03T00:00:00Z")
        self.assertTrue(report["findings"][0]["fingerprint"])
        self.assertEqual(len(report["findings"][0]["fingerprint"]), 16)


class TestToolFindingAggregation(unittest.TestCase):
    """41 identical rule hits should be one issue with many loci, not 41 issues."""

    def _hit(self, fid, line, rule="ACTIONS-PIN"):
        return {"id": fid, "title": "mutable tag", "severity": "MEDIUM",
                "confidence": "CERTAIN", "panel": "security", "category": "known_vulns",
                "source": "tool:semgrep", "tool_evidence": {"rule_id": rule},
                "location": {"file": ".github/workflows/ci.yml", "line_start": line},
                "provenance": {"discovered_by": "tool:semgrep",
                               "confirmation_status": "TOOL"}}

    def test_same_rule_same_file_collapses_with_loci(self):
        out = syn.aggregate_tool_findings([self._hit("A-001", 13),
                                           self._hit("A-002", 20),
                                           self._hit("A-003", 31)])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["location"]["line_start"], 13)
        self.assertEqual(len(out[0]["additional_loci"]), 2)
        self.assertEqual(out[0]["occurrences"], 3)

    def test_different_rules_stay_separate(self):
        out = syn.aggregate_tool_findings([self._hit("A-001", 13, "R1"),
                                           self._hit("A-002", 20, "R2")])
        self.assertEqual(len(out), 2)

    def test_agent_findings_never_aggregated(self):
        a = {"id": "AG-001", "title": "x", "severity": "LOW", "confidence": "NOTE",
             "panel": "code", "category": "style",
             "location": {"file": "a.py", "line_start": 1}}
        b = dict(a, id="AG-002", location={"file": "a.py", "line_start": 2})
        self.assertEqual(len(syn.aggregate_tool_findings([a, b])), 2)

    def _sarif_hit(self, fid, line, rule="B607", title="Starting a process with a partial executable path"):
        """A SARIF-adapter finding: rule id lands in provenance, NOT tool_evidence."""
        return {"id": fid, "title": title, "severity": "LOW", "confidence": "CERTAIN",
                "panel": "security", "category": rule, "source": "tool:bandit",
                "location": {"file": "skill/scripts/orchestrator.py", "line_start": line},
                "provenance": {"discovered_by": "tool:bandit", "confirmed_by": "tool:bandit",
                               "confirmation_status": "TOOL", "confirmation_reasoning": rule}}

    def test_sarif_adapter_findings_aggregate_by_rule(self):
        # bandit/semgrep go through the SARIF path and emit no tool_evidence at
        # all; the rule id is in provenance.confirmation_reasoning. Keying only
        # on tool_evidence.rule_id silently skipped every SARIF finding, so one
        # rule firing 4x in one file stayed 4 issues instead of 1 with 4 loci.
        out = syn.aggregate_tool_findings([self._sarif_hit("BN-1", 129),
                                           self._sarif_hit("BN-2", 140),
                                           self._sarif_hit("BN-3", 149),
                                           self._sarif_hit("BN-4", 161)])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["occurrences"], 4)
        self.assertEqual(out[0]["location"]["line_start"], 129)
        self.assertEqual(len(out[0]["additional_loci"]), 3)

    def test_sarif_fingerprint_survives_a_tool_message_rewording(self):
        # Identity must key on the rule, not the scanner's prose — otherwise a
        # tool upgrade that rewords its message orphans every existing issue.
        a = syn.finding_fingerprint(self._sarif_hit("BN-1", 129))
        b = syn.finding_fingerprint(self._sarif_hit("BN-1", 129, title="Partial executable path used"))
        self.assertEqual(a, b)

    def test_aggregation_preserves_a_tool_plus_agent_reinforcement(self):
        # Aggregation runs before dedupe, and dedupe reinforces on an EXACT
        # (file, line) match. Collapsing a multi-hit rule to its lowest line
        # would move the tool witness away from the line an agent independently
        # flagged, silently downgrading a tool_confirmed finding.
        agent = {"id": "AG-001", "title": "agent claim", "severity": "HIGH",
                 "confidence": "LIKELY", "panel": "security",
                 "category": "known_vulns",
                 "location": {"file": ".github/workflows/ci.yml",
                              "line_start": 20}}
        aggregated = syn.aggregate_tool_findings(
            [self._hit("A-001", 13), self._hit("A-002", 20),
             self._hit("A-003", 31), agent])
        tool_survivor = [f for f in aggregated if f.get("id", "").startswith("A-")]
        self.assertEqual(len(tool_survivor), 1)
        self.assertEqual(tool_survivor[0]["occurrences"], 3)
        # The survivor sits on the corroborated line, not the lowest one.
        self.assertEqual(tool_survivor[0]["location"]["line_start"], 20)
        deduped, _ = syn.prepare_findings(aggregated)
        self.assertTrue(any(f.get("reinforced") for f in deduped))


class TestShortTitle(unittest.TestCase):
    def test_long_tool_message_gets_a_short_title(self):
        long = ("This Dependabot configuration does not set a cooldown period. "
                "Newly published packages can be malicious or unstable. " + "x" * 400)
        f = syn.normalize_finding({"id": "SG-001", "title": long, "severity": "LOW",
                                   "confidence": "CERTAIN", "panel": "security",
                                   "category": "x",
                                   "location": {"file": "a.yml", "line_start": 1}})
        self.assertLessEqual(len(f["short_title"]), 100)
        self.assertEqual(f["title"], " ".join(long.split()))
        self.assertTrue(f["short_title"].endswith("…"))

    def test_short_title_passes_through_unchanged(self):
        f = syn.normalize_finding({"id": "SG-002", "title": "Short and sweet",
                                   "severity": "LOW", "confidence": "CERTAIN",
                                   "panel": "code", "category": "x",
                                   "location": {"file": "a.py", "line_start": 1}})
        self.assertEqual(f["short_title"], "Short and sweet")


class TestToolsDirSilentSkipGuard(unittest.TestCase):
    def test_warns_when_tools_present_but_not_ingested(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            os.makedirs(os.path.join(d, ".panopticon", "tools"))
            with open(os.path.join(d, ".panopticon", "tools", "semgrep.sarif"), "w") as fh:
                fh.write("{}")
            fp = os.path.join(d, "findings-g1-code-panel_review.json")
            with open(fp, "w") as fh:
                json.dump({"findings": []}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                syn.main(["--target", ".", "--out", os.path.join(d, "r.json"), fp])
        self.assertIn("--tools-dir", err.getvalue())

    def test_no_warning_when_tools_dir_supplied(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            tools = os.path.join(d, ".panopticon", "tools")
            os.makedirs(tools)
            with open(os.path.join(tools, "semgrep.sarif"), "w") as fh:
                fh.write('{"runs":[]}')
            fp = os.path.join(d, "findings-g1-code-panel_review.json")
            with open(fp, "w") as fh:
                json.dump({"findings": []}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                syn.main(["--target", ".", "--tools-dir", tools,
                          "--out", os.path.join(d, "r.json"), fp])
        self.assertNotIn("appears un-ingested", err.getvalue())


class TestToolAxisMeta(unittest.TestCase):
    def _tool(self, fid="T-1", **over):
        f = {"id": fid, "source": "tool:bandit", "severity": "HIGH",
             "panel": "security", "category": "secrets",
             "title": "hardcoded password", "confidence": "LIKELY",
             "description": "d", "location": {"file": "a.py", "line_start": 1},
             "provenance": {"confirmation_reasoning": "B105"}}
        f.update(over)
        return f

    def test_tool_axis_counts_unverified_as_unanswered(self):
        r = syn.build_report([self._tool()], [], "t", None,
                             "2026-08-05T00:00:00Z")
        axis = r["meta"]["coverage"]["tool_axis"]
        self.assertEqual(axis["queued"], 1)
        self.assertEqual(axis["unanswered"], 1)
        self.assertEqual(axis["confirmed"], 0)
        self.assertIsNone(axis["rejection_rate"])

    def test_tool_axis_rejection_rate_when_verdicts_exist(self):
        a, b = self._tool("T-1"), self._tool("T-2",
                                             location={"file": "b.py",
                                                       "line_start": 2})
        prepared, _ = syn.prepare_for_queue([a, b])
        queue, _c = syn.evidence_mod.build_verify_queue(prepared)
        verdicts = {}
        for i, e in enumerate(queue):
            verdicts[e["queue_id"]] = {
                "verdict": "REJECTED" if i == 0 else "CONFIRMED",
                "finding_id": e["finding"]["id"], "reasoning": "r"}
        r = syn.build_report([a, b], [], "t", None, "2026-08-05T00:00:00Z",
                             verdicts=verdicts, verdicts_supplied=True)
        axis = r["meta"]["coverage"]["tool_axis"]
        self.assertEqual((axis["confirmed"], axis["rejected"]), (1, 1))
        self.assertEqual(axis["rejection_rate"], 0.5)

    def test_tool_axis_counts_needs_more_info_and_excludes_it_from_decided(self):
        a, b = self._tool("T-1"), self._tool("T-2",
                                             location={"file": "b.py",
                                                       "line_start": 2})
        prepared, _ = syn.prepare_for_queue([a, b])
        queue, _c = syn.evidence_mod.build_verify_queue(prepared)
        verdicts = {queue[0]["queue_id"]: {
            "verdict": "NEEDS_MORE_INFO",
            "finding_id": queue[0]["finding"]["id"], "reasoning": "r"}}
        r = syn.build_report([a, b], [], "t", None, "2026-08-05T00:00:00Z",
                             verdicts=verdicts, verdicts_supplied=True)
        axis = r["meta"]["coverage"]["tool_axis"]
        self.assertEqual(axis["needs_more_info"], 1)
        self.assertEqual(axis["unanswered"], 1)
        # needs_more_info is neither confirmed nor rejected, so it must not
        # count toward "decided" -- otherwise the rejection rate would be
        # diluted by claims that were never actually resolved either way.
        self.assertIsNone(axis["rejection_rate"])

    def test_tool_axis_counts_reinforced_non_tool_sourced_finding(self):
        # A reinforced (tool+agent same-locus merge) survivor can carry a
        # non-"tool:"-prefixed source, yet build_report's tool_like filter is
        # is_tool_sourced(f) OR f.get("reinforced") -- not is_tool_sourced
        # alone -- so it must still land in the tool axis.
        f = _agentic(reinforced=True)
        r = syn.build_report([f], [], "t", None, "2026-08-05T00:00:00Z")
        axis = r["meta"]["coverage"]["tool_axis"]
        self.assertEqual(axis["queued"], 1)

    def test_build_executing_tools_reports_a_run_with_zero_findings(self):
        r = syn.build_report([], [], "t", None, "2026-08-05T00:00:00Z",
                             tools_ran={"roslyn-secguard", "bandit"})
        self.assertEqual(r["meta"]["coverage"]["build_executing_tools"],
                         ["roslyn-secguard"])

    def test_build_executing_tools_falls_back_without_tools_ran(self):
        r = syn.build_report([self._tool(source="tool:roslyn-secguard")], [],
                             "t", None, "2026-08-05T00:00:00Z")
        self.assertEqual(r["meta"]["coverage"]["build_executing_tools"],
                         ["roslyn-secguard"])


class TestVerdictAccountingMeta(unittest.TestCase):
    """#443's own failure surface, made visible in the artifact.

    A run whose verdicts all fail to match used to still gate on tool findings,
    so the breakage was loud. Under strict gating (P2) that same run yields gate
    PASS, grade A, risk LOW -- the safest-looking output there is -- and CI reads
    the JSON, not stderr. meta.verdicts is the detection.
    """

    def _f(self, fid, title, fname):
        return {"id": fid, "title": title, "severity": "HIGH",
                "confidence": "POSSIBLE", "panel": "code", "category": "logic",
                "description": "d",
                "location": {"file": fname, "line_start": 1}}

    def _queue(self, findings):
        prepared, _ = syn.prepare_for_queue(findings)
        return syn.evidence_mod.build_verify_queue(prepared)[0]

    def test_counts_matched_unknown_and_unanswered(self):
        a = self._f("A-1", "first claim", "a.py")
        b = self._f("A-2", "second claim", "b.py")
        queue = self._queue([a, b])
        self.assertEqual(len(queue), 2)
        answered = queue[0]
        verdicts = {
            answered["queue_id"]: {"verdict": "CONFIRMED", "reasoning": "r",
                                   "finding_id": answered["finding"]["id"]},
            # A stale verdict from a previous run: well-formed, but its id is
            # in no queue this run.
            "deadbeefdeadbeef": {"verdict": "CONFIRMED", "reasoning": "stale",
                                 "finding_id": "GONE-1"},
        }
        r = syn.build_report([a, b], [], "t", None, "2026-08-05T00:00:00Z",
                             verdicts=verdicts, verdicts_supplied=True)
        self.assertEqual(r["meta"]["coverage"]["verdicts"],
                         {"queued": 2, "cut": 0, "supplied": 2, "matched": 1,
                          "unknown": 1, "unanswered": 1, "unloadable": 0})

    def test_unloadable_verdicts_surfaced_in_coverage(self):
        # #938: corrupt verdict files (passed as verdict_unloadable) surface as
        # a count in meta.coverage, so a lost verdict is visible rather than
        # only reflected as a lower `supplied`.
        a = self._f("A-1", "first claim", "a.py")
        self._queue([a])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            r = syn.build_report([a], [], "t", None, "2026-08-05T00:00:00Z",
                                 verdicts={}, verdicts_supplied=True,
                                 verdict_unloadable=[
                                     {"file": "x.json", "reason": "unparseable: ..."},
                                     {"file": "y.json", "reason": "missing/invalid verdict key"}])
        self.assertEqual(r["meta"]["coverage"]["verdicts"]["unloadable"], 2)
        self.assertIn("un-loadable", err.getvalue())

    def test_echo_mismatch_is_dropped_and_counted_as_unanswered(self):
        # match_verdict refuses a verdict that echoes a different finding_id.
        # It is neither matched nor unknown, so supplied - matched - unknown
        # is exactly the echo-rejected count.
        a = self._f("A-1", "first claim", "a.py")
        queue = self._queue([a])
        verdicts = {queue[0]["queue_id"]: {"verdict": "CONFIRMED",
                                           "reasoning": "r",
                                           "finding_id": "SOMEONE-ELSE"}}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            r = syn.build_report([a], [], "t", None, "2026-08-05T00:00:00Z",
                                 verdicts=verdicts, verdicts_supplied=True)
        self.assertEqual(r["meta"]["coverage"]["verdicts"],
                         {"queued": 1, "cut": 0, "supplied": 1, "matched": 0,
                          "unknown": 0, "unanswered": 1, "unloadable": 0})
        self.assertEqual(r["summary"]["gate"], "OFF")  # ...and it looks clean

    def test_unanswered_is_null_when_no_verdicts_were_supplied(self):
        # 0 would read as "nothing went unanswered" for a run that never ran a
        # verify phase; null says "not measured" (as tool_axis.rejection_rate
        # already does).
        r = syn.build_report([self._f("A-1", "first claim", "a.py")], [], "t",
                             None, "2026-08-05T00:00:00Z")
        self.assertEqual(r["meta"]["coverage"]["verdicts"],
                         {"queued": 1, "cut": 0, "supplied": 0, "matched": 0,
                          "unknown": 0, "unanswered": None, "unloadable": 0})


class TestVerdictCutAccounting(unittest.TestCase):
    def _f(self, fid, sev="MEDIUM"):
        return {"id": fid, "severity": sev, "panel": "code",
                "category": "logic", "title": "t-" + fid, "confidence": "POSSIBLE",
                "description": "d", "location": {"file": fid + ".py", "line_start": 1}}

    def test_uncapped_run_reports_cut_zero(self):
        r = syn.build_report([self._f("A"), self._f("B")], [], "t", None,
                             "2026-08-05T00:00:00Z")
        v = r["meta"]["coverage"]["verdicts"]
        self.assertEqual(v["cut"], 0)
        self.assertEqual(v["queued"], 2)

    def test_capped_run_reports_the_cut(self):
        findings = [self._f("A", "CRITICAL"), self._f("B", "HIGH"),
                    self._f("C", "LOW")]
        r = syn.build_report(findings, [], "t", None, "2026-08-05T00:00:00Z",
                             max_verify=1)
        v = r["meta"]["coverage"]["verdicts"]
        self.assertEqual(v["queued"], 1)
        self.assertEqual(v["cut"], 2)


class TestToolPolicyModeUnknown(unittest.TestCase):
    def _plan(self, d, entries):
        import json as _json
        with open(os.path.join(d, "dispatch-plan.json"), "w") as fh:
            _json.dump(entries, fh)

    def test_no_plan_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(syn.derive_tool_policy_mode(d), "unknown")

    def test_plan_with_no_enforced_entries_is_advisory(self):
        with tempfile.TemporaryDirectory() as d:
            self._plan(d, [{"role": "panel_review", "enforced": False}])
            self.assertEqual(syn.derive_tool_policy_mode(d), "advisory")

    def test_all_enforced_is_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            self._plan(d, [{"enforced": True}, {"enforced": True}])
            self.assertEqual(syn.derive_tool_policy_mode(d), "enforced")

    def test_some_enforced_is_mixed(self):
        with tempfile.TemporaryDirectory() as d:
            self._plan(d, [{"enforced": True}, {"enforced": False}])
            self.assertEqual(syn.derive_tool_policy_mode(d), "mixed")


class TestMetaCoverage(unittest.TestCase):
    def _tool(self, fid="T-1"):
        return {"id": fid, "source": "tool:bandit", "severity": "HIGH",
                "panel": "security", "category": "secrets", "title": "x",
                "confidence": "LIKELY", "description": "d",
                "location": {"file": "a.py", "line_start": 1},
                "provenance": {"confirmation_reasoning": "B105"}}

    def test_coverage_block_holds_the_moved_fields(self):
        r = syn.build_report([self._tool()], [], "t", None,
                             "2026-08-05T00:00:00Z",
                             tools_ran={"bandit"}, tool_policy_mode="enforced",
                             tool_dispositions={"bandit": {"status": "ok",
                                                           "findings": 1}})
        cov = r["meta"]["coverage"]
        self.assertEqual(cov["adapters"]["bandit"]["status"], "ok")
        self.assertEqual(cov["tools_ran"], ["bandit"])
        self.assertEqual(cov["tool_policy_mode"], "enforced")
        self.assertIn("tool_axis", cov)
        self.assertIn("verdicts", cov)

    def test_moved_fields_are_gone_from_top_level_meta(self):
        r = syn.build_report([self._tool()], [], "t", None,
                             "2026-08-05T00:00:00Z")
        m = r["meta"]
        for k in ("tool_axis", "verdicts", "tool_policy_mode",
                  "build_executing_tools"):
            self.assertNotIn(k, m)

    def test_coverage_present_on_a_findings_only_run(self):
        r = syn.build_report([{"id": "A", "severity": "LOW", "panel": "code",
                               "category": "logic", "title": "t",
                               "confidence": "POSSIBLE", "description": "d",
                               "location": {"file": "a.py", "line_start": 1}}],
                             [], "t", None, "2026-08-05T00:00:00Z")
        self.assertIn("coverage", r["meta"])
        self.assertEqual(r["meta"]["coverage"]["tool_policy_mode"], "unknown")
        self.assertEqual(r["meta"]["coverage"]["adapters"], {})


class TestCoverageEndToEnd(unittest.TestCase):
    def test_full_coverage_block_is_honest(self):
        tool = {"id": "T-1", "source": "tool:bandit", "severity": "HIGH",
                "panel": "security", "category": "secrets", "title": "x",
                "confidence": "LIKELY", "description": "d",
                "location": {"file": "a.py", "line_start": 1},
                "provenance": {"confirmation_reasoning": "B105"}}
        agent = {"id": "A-1", "severity": "LOW", "panel": "code",
                 "category": "logic", "title": "t", "confidence": "POSSIBLE",
                 "description": "d", "location": {"file": "b.py", "line_start": 2}}
        disp = {"bandit": {"status": "ok", "findings": 1},
                "semgrep": {"status": "failed", "findings": 0,
                            "reason": "empty output file"}}
        r = syn.build_report([tool, agent], [], "t", "high",
                             "2026-08-05T00:00:00Z", max_verify=1,
                             tools_ran={"bandit"}, tool_policy_mode="enforced",
                             tool_dispositions=disp)
        cov = r["meta"]["coverage"]
        # semgrep failed -> not in tools_ran / build_executing_tools
        self.assertNotIn("semgrep", cov["tools_ran"])
        self.assertEqual(cov["adapters"]["semgrep"]["status"], "failed")
        # the cut is disclosed
        self.assertEqual(cov["verdicts"]["cut"], 1)
        self.assertEqual(cov["tool_policy_mode"], "enforced")


class TestFanOutCoverageMeta(unittest.TestCase):
    def _f(self):
        return {"id": "A", "severity": "LOW", "panel": "code", "category": "x",
                "title": "t", "confidence": "POSSIBLE", "description": "d",
                "location": {"file": "a.py", "line_start": 1}}

    def test_fan_out_present_under_coverage(self):
        fo = {"planned": {"code": 2}, "executed": {"code": 1},
              "groups_complete": ["g1"], "groups_partial": ["g2"]}
        r = syn.build_report([self._f()], [], "t", None, "2026-08-07T00:00:00Z",
                             fan_out=fo)
        self.assertEqual(r["meta"]["coverage"]["fan_out"], fo)

    def test_fan_out_null_when_absent(self):
        r = syn.build_report([self._f()], [], "t", None, "2026-08-07T00:00:00Z")
        self.assertIsNone(r["meta"]["coverage"]["fan_out"])


class TestCoverageDivergence(unittest.TestCase):
    GROUPS = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_inconclusive_on_incomplete_high_value_panel(self):
        fan_out = {"planned": {"security": 21, "code": 10},
                   "executed": {"security": 3, "code": 10},
                   "groups_complete": [], "groups_partial": ["g1"]}
        r = syn.build_report([], self.GROUPS, "t", "high", self.TS, fan_out=fan_out)
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")
        self.assertIsNone(r["summary"]["overall_grade"])
        self.assertEqual(r["summary"]["provisional_grade"], "A")
        self.assertEqual(r["meta"]["coverage"]["divergence"]["panels"]["security"],
                         {"planned": 21, "executed": 3})
        self.assertNotIn("code", r["meta"]["coverage"]["divergence"]["panels"])

    def test_tool_requested_absent_is_disclosed_and_inconclusive(self):
        r = syn.build_report([], self.GROUPS, "t", "high", self.TS,
                             tools_ran=["trivy"], scout_requested=["trivy", "semgrep"])
        self.assertEqual(r["meta"]["coverage"]["divergence"]["tools"],
                         {"semgrep": "requested_absent"})
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")

    def test_backward_compat_no_fanout_no_scout(self):
        r = syn.build_report([], self.GROUPS, "t", "high", self.TS)
        self.assertEqual(r["summary"]["overall_grade"], "A")
        self.assertEqual(r["summary"]["gate"], "PASS")
        self.assertTrue(r["summary"]["coverage_certified"])
        self.assertIsNone(r["summary"]["provisional_grade"])
        self.assertEqual(r["meta"]["coverage"]["divergence"], {"panels": {}, "tools": {}})


class TestResumeDisclosure(unittest.TestCase):
    G = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_build_report_emits_resume(self):
        r = syn.build_report([], self.G, "t", "high", self.TS,
                             resume={"fan_out": {"total": 74, "done": 33, "pending": 41},
                                     "verify": {"total": 52, "done": 12, "pending": 40}})
        self.assertEqual(r["meta"]["coverage"]["resume"]["fan_out"]["done"], 33)
        self.assertEqual(r["meta"]["coverage"]["resume"]["verify"]["pending"], 40)

    def test_build_report_resume_defaults_none(self):
        r = syn.build_report([], self.G, "t", "high", self.TS)
        self.assertIsNone(r["meta"]["coverage"]["resume"])

    def test_main_tolerates_non_list_verify_queue_entries(self):
        # A verify-queue.json with a truthy non-list `entries` (e.g. an int)
        # is a valid JSON dict -- it passes main()'s isinstance(dict) load
        # guard -- and used to raise a TypeError deep inside
        # group_runner.resume_stats, aborting the whole run with no report
        # artifact. A malformed queue must never abort a run.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
            with open(os.path.join(d, ".panopticon", "verify-queue.json"), "w") as fh:
                json.dump({"entries": 42}, fh)
            with open(os.path.join(d, ".panopticon", "groups.json"), "w") as fh:
                json.dump({"mode": "repo", "groups": self.G}, fh)
            fpath = os.path.join(d, "findings-g1-code.json")
            with open(fpath, "w") as fh:
                json.dump({"findings": [{"id": "CD-001", "title": "x", "severity": "LOW",
                    "confidence": "POSSIBLE", "panel": "code", "category": "structure",
                    "location": {"file": "a.py", "line_start": 1}}]}, fh)
            out = os.path.join(d, "report.json")
            rc = syn.main(["--out", out, fpath])
            self.assertIsInstance(rc, int)
            self.assertTrue(os.path.exists(out))
            with open(out) as fh:
                report = json.load(fh)
            self.assertEqual(
                report["meta"]["coverage"]["resume"]["verify"]["total"], 0)


class TestMainExitAndScout(unittest.TestCase):
    def test_inconclusive_from_scout_requested_tool_absent_exits_2(self):
        import tempfile, json as _json
        with tempfile.TemporaryDirectory() as d:
            pan = os.path.join(d, ".panopticon")
            os.makedirs(os.path.join(pan, "tools"), exist_ok=True)
            # a scout requested semgrep; no tool output will exist for it
            with open(os.path.join(pan, "scout-g1.json"), "w") as fh:
                _json.dump({"group": "g1", "tools": ["semgrep"], "files": ["a.py"]}, fh)
            with open(os.path.join(pan, "groups.json"), "w") as fh:
                _json.dump({"groups": [{"name": "g1", "files": ["a.py"]}]}, fh)
            findings = os.path.join(pan, "findings-g1-code-panel_review.json")
            with open(findings, "w") as fh:
                _json.dump({"findings": []}, fh)
            cwd = os.getcwd()
            try:
                os.chdir(d)
                rc = syn.main(["--target", "t", "--fail-on", "high",
                              "--out", os.path.join(pan, "report.json"), findings])
            finally:
                os.chdir(cwd)
            self.assertEqual(rc, 2)  # INCONCLUSIVE -> exit 2
            with open(os.path.join(pan, "report.json")) as fh:
                rep = _json.load(fh)
            self.assertEqual(rep["meta"]["coverage"]["divergence"]["tools"],
                             {"semgrep": "requested_absent"})

    def test_malformed_scout_tools_are_tolerated(self):
        """Scout files are agent-authored/untrusted. A non-list `tools` (or a
        list with non-string items) must never abort the run -- see the
        scout-discovery loop's type guard in main()."""
        with tempfile.TemporaryDirectory() as d:
            pan = os.path.join(d, ".panopticon")
            os.makedirs(pan, exist_ok=True)
            with open(os.path.join(pan, "scout-a.json"), "w", encoding="utf-8") as fh:
                json.dump({"group": "a", "tools": 5}, fh)
            with open(os.path.join(pan, "scout-b.json"), "w", encoding="utf-8") as fh:
                json.dump({"group": "b", "tools": "semgrep"}, fh)
            with open(os.path.join(pan, "scout-c.json"), "w", encoding="utf-8") as fh:
                json.dump({"group": "c", "tools": ["trivy", None]}, fh)
            with open(os.path.join(pan, "groups.json"), "w", encoding="utf-8") as fh:
                json.dump({"groups": [{"name": "a", "files": ["x.py"]}]}, fh)
            findings = os.path.join(pan, "findings-a-code-panel_review.json")
            with open(findings, "w", encoding="utf-8") as fh:
                json.dump({"findings": []}, fh)
            out_path = os.path.join(pan, "report.json")
            with _chdir(d):
                rc = syn.main(["--target", "t", "--out", out_path, findings])
            # (a) run completed: no exception, an artifact was written.
            self.assertIsInstance(rc, int)
            self.assertTrue(os.path.isfile(out_path))
            with open(out_path, encoding="utf-8") as fh:
                report = json.load(fh)
            tools_div = report["meta"]["coverage"]["divergence"]["tools"]
            # (b) the one valid list-string requested tool is disclosed absent.
            self.assertIn("trivy", tools_div)
            # (c) the bare-string "semgrep" must never explode per-character.
            self.assertNotIn("s", tools_div)
            self.assertNotIn("e", tools_div)


class TestMultigroupPlanReconcile(unittest.TestCase):
    """C1: the real fan-out workflow writes one dispatch-plan-<group>.json
    PER GROUP, never a single dispatch-plan.json -- main() must glob all of
    them (same pattern as derive_tool_policy_mode) or reconcile never runs
    on the shape it was built for. This is the load-bearing regression test:
    a single-group main() test would still pass with the old single-file
    load in place."""

    def _setup(self, d, decoy):
        pan = os.path.join(d, ".panopticon")
        os.makedirs(pan, exist_ok=True)
        plan_g1 = [{"role": "panel_review", "agent": "panopticon-panel-review",
                    "enforced": True, "group": "g1", "panel": "code",
                    "out_file": ".panopticon/findings-g1-code-panel_review.json"}]
        plan_g2 = [{"role": "panel_review", "agent": "panopticon-panel-review",
                    "enforced": True, "group": "g2", "panel": "code",
                    "out_file": ".panopticon/findings-g2-code-panel_review.json"}]
        with open(os.path.join(pan, "dispatch-plan-g1.json"), "w", encoding="utf-8") as fh:
            json.dump(plan_g1, fh)
        with open(os.path.join(pan, "dispatch-plan-g2.json"), "w", encoding="utf-8") as fh:
            json.dump(plan_g2, fh)
        with open(os.path.join(pan, "groups.json"), "w", encoding="utf-8") as fh:
            json.dump({"groups": [{"name": "g1", "files": ["a.py"]},
                                  {"name": "g2", "files": ["b.py"]}]}, fh)
        with open(os.path.join(pan, "findings-g1-code-panel_review.json"),
                 "w", encoding="utf-8") as fh:
            json.dump({"findings": []}, fh)
        with open(os.path.join(pan, "findings-g2-code-panel_review.json"),
                 "w", encoding="utf-8") as fh:
            json.dump({"findings": []}, fh)
        files = [".panopticon/findings-g1-code-panel_review.json",
                 ".panopticon/findings-g2-code-panel_review.json"]
        if decoy:
            with open(os.path.join(pan, "findings-EVIL.json"), "w", encoding="utf-8") as fh:
                json.dump({"findings": []}, fh)
            files.append(".panopticon/findings-EVIL.json")
        return files

    def test_multigroup_plans_decoy_detected_via_main(self):
        with tempfile.TemporaryDirectory() as d:
            files = self._setup(d, decoy=True)
            with _chdir(d):
                out_path = os.path.join(".panopticon", "report.json")
                rc = syn.main(["--target", "t", "--fail-on", "high",
                              "--out", out_path] + files)
                with open(out_path, encoding="utf-8") as fh:
                    report = json.load(fh)
        self.assertEqual(rc, 2)  # INCONCLUSIVE -> exit 2
        integ = report["meta"]["integrity"]
        self.assertEqual(integ["unexpected_findings_files"],
                         [".panopticon/findings-EVIL.json"])
        self.assertEqual(integ["plans_seen"], 2)
        self.assertNotIn(".panopticon/findings-g1-code-panel_review.json",
                         integ["unexpected_findings_files"])
        self.assertNotIn(".panopticon/findings-g2-code-panel_review.json",
                         integ["unexpected_findings_files"])

    def test_multigroup_plans_clean_via_main(self):
        with tempfile.TemporaryDirectory() as d:
            files = self._setup(d, decoy=False)
            with _chdir(d):
                out_path = os.path.join(".panopticon", "report.json")
                rc = syn.main(["--target", "t", "--fail-on", "high",
                              "--out", out_path] + files)
                with open(out_path, encoding="utf-8") as fh:
                    report = json.load(fh)
        self.assertEqual(rc, 0)
        integ = report["meta"]["integrity"]
        self.assertEqual(integ["unexpected_findings_files"], [])
        self.assertEqual(integ["plans_seen"], 2)


class TestRenderSummaryCoverage(unittest.TestCase):
    def test_inconclusive_summary_names_divergence(self):
        fan_out = {"planned": {"security": 21}, "executed": {"security": 3},
                   "groups_complete": [], "groups_partial": ["g1"]}
        r = syn.build_report([], [{"name": "g1", "files": ["a.py"]}],
                             "t", "high", "2026-01-01T00:00:00Z", fan_out=fan_out)
        text = syn.render_summary(r)
        self.assertIn("INCONCLUSIVE", text)
        self.assertIn("NOT CERTIFIED", text)
        self.assertIn("security", text)
        self.assertIn("provisional", text.lower())


class TestRenderSummaryResume(unittest.TestCase):
    G = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_resume_line_shown_when_pending(self):
        r = syn.build_report([], self.G, "t", "high", self.TS,
                             resume={"fan_out": {"total": 74, "done": 33, "pending": 41},
                                     "verify": {"total": 52, "done": 12, "pending": 40}})
        text = syn.render_summary(r)
        self.assertIn("Resume:", text)
        self.assertIn("33/74", text)
        self.assertIn("12/52", text)

    def test_no_resume_line_when_complete(self):
        r = syn.build_report([], self.G, "t", "high", self.TS,
                             resume={"fan_out": {"total": 74, "done": 74, "pending": 0},
                                     "verify": {"total": 52, "done": 52, "pending": 0}})
        self.assertNotIn("Resume:", syn.render_summary(r))

    def test_no_resume_line_when_resume_absent(self):
        r = syn.build_report([], self.G, "t", "high", self.TS)  # resume=None
        self.assertNotIn("Resume:", syn.render_summary(r))


class TestIntegrity(unittest.TestCase):
    G = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_certify_integrity_not_ok_is_inconclusive(self):
        r = syn.certify("A", [], "high", set(), [], integrity_ok=False)
        self.assertEqual(r["gate"], "INCONCLUSIVE")
        self.assertFalse(r["coverage_certified"])

    def test_certify_integrity_ok_default_unchanged(self):
        r = syn.certify("A", [], "high", set(), [])
        self.assertEqual(r["gate"], "PASS")
        self.assertTrue(r["coverage_certified"])

    def test_certify_integrity_not_ok_fail_still_wins(self):
        # Precedence truth-table (spec requirement): a confirmed CRITICAL
        # finding must still FAIL the gate when integrity is also broken --
        # integrity_ok=False must never downgrade a FAIL to INCONCLUSIVE.
        crit = [{"severity": "CRITICAL", "evidence": {"status": "advisor_confirmed"}}]
        r = syn.certify("F", crit, "high", set(), [], integrity_ok=False)
        self.assertEqual(r["gate"], "FAIL")
        self.assertFalse(r["coverage_certified"])

    def test_certify_integrity_not_ok_off_preserved(self):
        # No --fail-on -> gate is OFF regardless of coverage; integrity_ok
        # must not force it to INCONCLUSIVE.
        r = syn.certify("A", [], None, set(), [], integrity_ok=False)
        self.assertEqual(r["gate"], "OFF")
        self.assertFalse(r["coverage_certified"])

    def test_reconcile_flags_unexpected_and_missing(self):
        plan = [{"role": "panel_review", "out_file": ".panopticon/findings-g1-code-panel_review.json"},
                {"role": "lens_sweep", "out_file": ".panopticon/findings-g1-code-lens_sweep-style.json"}]
        ingested = [".panopticon/findings-g1-code-panel_review.json",
                    ".panopticon/findings-EVIL-decoy.json"]
        unexpected, missing = syn.reconcile_findings_files(plan, ingested)
        self.assertEqual(unexpected, [".panopticon/findings-EVIL-decoy.json"])
        self.assertEqual(missing, [".panopticon/findings-g1-code-lens_sweep-style.json"])

    def test_reconcile_skipped_without_plan(self):
        self.assertEqual(syn.reconcile_findings_files([], ["whatever.json"]), ([], []))
        self.assertEqual(syn.reconcile_findings_files(None, ["x.json"]), ([], []))

    def test_build_report_emits_integrity_and_inconclusive_on_unexpected(self):
        integ = {"unexpected_findings_files": [".panopticon/findings-EVIL.json"],
                 "missing_planned_files": [], "unenforced_acknowledged": False}
        r = syn.build_report([], self.G, "t", "high", self.TS, integrity=integ)
        self.assertEqual(r["meta"]["integrity"], integ)
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")

    def test_build_report_integrity_defaults_empty(self):
        r = syn.build_report([], self.G, "t", "high", self.TS)
        self.assertEqual(r["meta"]["integrity"],
                         {"unexpected_findings_files": [], "missing_planned_files": [],
                          "duplicate_out_files": [], "mislabeled_findings_files": [],
                          "unenforced_acknowledged": False, "plans_seen": 0})
        self.assertEqual(r["summary"]["gate"], "PASS")

    def test_build_report_integrity_non_dict_does_not_raise(self):
        # M10: a truthy non-dict integrity (e.g. a stray list) must fall back
        # to the default rather than raise on the .get() calls below it.
        r = syn.build_report([], self.G, "t", "high", self.TS, integrity=["not", "a", "dict"])
        self.assertEqual(r["meta"]["integrity"],
                         {"unexpected_findings_files": [], "missing_planned_files": [],
                          "duplicate_out_files": [], "mislabeled_findings_files": [],
                          "unenforced_acknowledged": False, "plans_seen": 0})
        self.assertEqual(r["summary"]["gate"], "PASS")

    def test_missing_alone_does_not_force_inconclusive(self):
        integ = {"unexpected_findings_files": [],
                 "missing_planned_files": [".panopticon/findings-g1-x.json"],
                 "unenforced_acknowledged": False}
        r = syn.build_report([], self.G, "t", "high", self.TS, integrity=integ)
        self.assertEqual(r["summary"]["gate"], "PASS")


class TestRenderSummaryIntegrity(unittest.TestCase):
    G = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_integrity_line_on_unexpected(self):
        integ = {"unexpected_findings_files": [".panopticon/findings-EVIL.json"],
                 "missing_planned_files": [], "unenforced_acknowledged": False}
        text = syn.render_summary(syn.build_report([], self.G, "t", "high", self.TS,
                                                   integrity=integ))
        self.assertIn("Integrity:", text)
        self.assertIn("findings-EVIL.json", text)

    def test_no_integrity_line_when_clean(self):
        self.assertNotIn("Integrity:",
                         syn.render_summary(syn.build_report([], self.G, "t", "high", self.TS)))


class TestReadUnenforcedAck(unittest.TestCase):
    """M8: read_unenforced_ack had zero direct test coverage -- exactly where
    I1's real defect lived (a stale/spurious ack silently poisoning every
    later run's meta.integrity.unenforced_acknowledged)."""

    def test_true_when_acknowledged(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ack.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"acknowledged": True, "roles": ["panel_review"]}, fh)
            self.assertTrue(syn.read_unenforced_ack(path))

    def test_false_when_missing(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "does-not-exist.json")
            self.assertFalse(syn.read_unenforced_ack(path))

    def test_false_when_malformed_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ack.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            self.assertFalse(syn.read_unenforced_ack(path))

    def test_false_when_non_dict_payload(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ack.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(["not", "a", "dict"], fh)
            self.assertFalse(syn.read_unenforced_ack(path))


class TestLoadDiffHunks(unittest.TestCase):
    """#449 Task 7: the orchestrator's diff-hunks.json artifact, tuple-ified."""

    def test_loads_and_converts_ranges_to_tuples(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"base": "main", "base_source": "explicit",
                          "diff_context": 5, "files_changed": 1,
                          "hunks": {"a.py": [[10, 12], [20, 20]]}}, fh)
            data = syn.load_diff_hunks(path)
            self.assertEqual(data["base"], "main")
            self.assertEqual(data["hunks"], {"a.py": [(10, 12), (20, 20)]})

    def test_missing_file_returns_empty_dict(self):
        self.assertEqual(syn.load_diff_hunks("/does/not/exist/diff-hunks.json"), {})

    def test_malformed_json_returns_empty_dict(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            self.assertEqual(syn.load_diff_hunks(path), {})

    def test_non_dict_payload_returns_empty_dict(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(["not", "a", "dict"], fh)
            self.assertEqual(syn.load_diff_hunks(path), {})

    def test_missing_hunks_key_defaults_to_empty(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"base": "main"}, fh)
            data = syn.load_diff_hunks(path)
            self.assertEqual(data["hunks"], {})


class TestClassifyFindings(unittest.TestCase):
    """#449 Task 7: classify_findings stamps f['delta'] via diff_map.classify."""

    def test_stamps_delta_on_each_finding(self):
        findings = [
            {"id": "A-1", "location": {"file": "a.py", "line_start": 11}},
            {"id": "A-2", "location": {"file": "a.py", "line_start": 90}},
        ]
        hunks = {"a.py": [(10, 12)]}
        syn.classify_findings(findings, hunks, 5)
        self.assertTrue(findings[0]["delta"]["on_diff"])
        self.assertFalse(findings[1]["delta"]["on_diff"])
        self.assertIn("hunk", findings[0]["delta"])
        self.assertIn("distance", findings[0]["delta"])


class TestDeltaClassify(unittest.TestCase):
    def test_build_report_stamps_delta_when_hunks_present(self):
        findings = [
            {"id": "A-1", "title": "on", "severity": "HIGH", "confidence": "POSSIBLE",
             "panel": "code", "category": "x", "location": {"file": "a.py", "line_start": 11}},
            {"id": "A-2", "title": "off", "severity": "HIGH", "confidence": "POSSIBLE",
             "panel": "code", "category": "x", "location": {"file": "a.py", "line_start": 90}},
        ]
        hunks = {"base": "main", "base_source": "explicit", "diff_context": 5,
                 "files_changed": 1, "hunks": {"a.py": [(10, 12)]}}
        rep = syn.build_report(findings, [{"name": "g1", "files": ["a.py"]}],
                               "t", "high", "2026-01-01T00:00:00Z",
                               diff_hunks=hunks, diff_context=5)
        by = {f["id"]: f["delta"]["on_diff"] for f in rep["findings"]}
        self.assertTrue(by["A-1"]); self.assertFalse(by["A-2"])

    def test_build_report_no_delta_key_when_diff_hunks_omitted(self):
        """Backward compatibility: no diff_hunks kwarg -> no delta stamping at all
        (not even a False/None placeholder) — existing non-delta callers unaffected."""
        findings = [
            {"id": "A-1", "title": "x", "severity": "HIGH", "confidence": "POSSIBLE",
             "panel": "code", "category": "x", "location": {"file": "a.py", "line_start": 11}},
        ]
        rep = syn.build_report(findings, [{"name": "g1", "files": ["a.py"]}],
                               "t", "high", "2026-01-01T00:00:00Z")
        self.assertNotIn("delta", rep["findings"][0])

    def test_build_report_no_delta_when_base_unresolved(self):
        """diff_hunks present but base is None (unresolved) -> delta_mode is False,
        so findings are left unstamped. (Orchestrator Task 5 now fails loudly
        before this artifact shape can occur in practice.)"""
        findings = [
            {"id": "A-1", "title": "x", "severity": "HIGH", "confidence": "POSSIBLE",
             "panel": "code", "category": "x", "location": {"file": "a.py", "line_start": 11}},
        ]
        hunks = {"base": None, "base_source": "unresolved", "diff_context": 5,
                 "files_changed": 0, "hunks": {}}
        rep = syn.build_report(findings, [{"name": "g1", "files": ["a.py"]}],
                               "t", "high", "2026-01-01T00:00:00Z",
                               diff_hunks=hunks, diff_context=5)
        self.assertNotIn("delta", rep["findings"][0])


class TestDeltaGate(unittest.TestCase):
    """#449 Task 8 (rework): on-diff gate/grade scoping, summary.delta,
    coverage.delta with three commit anchors. An unresolvable base is now a
    loud orchestrator failure (Task 5) that never reaches synthesize, so
    delta_mode alone drives these blocks -- no delta_unresolved path."""

    def _findings(self):
        return [
            {"id": "A-1", "title": "on-high", "severity": "HIGH", "confidence": "POSSIBLE",
             "panel": "code", "category": "x", "location": {"file": "a.py", "line_start": 11}},
            {"id": "A-2", "title": "pre-high", "severity": "HIGH", "confidence": "POSSIBLE",
             "panel": "code", "category": "x", "location": {"file": "a.py", "line_start": 90}},
        ]

    def test_gate_scopes_to_on_diff(self):
        hunks = {"base": "main", "base_source": "explicit", "diff_context": 5,
                 "files_changed": 1, "hunks": {"a.py": [(10, 12)]}}
        rep = syn.build_report(self._findings(), [{"name": "g1", "files": ["a.py"]}],
                               "t", "high", "2026-01-01T00:00:00Z", gate_unverified=True,
                               diff_hunks=hunks, diff_context=5, gate_scope="on-diff")
        # only the on-diff HIGH gates
        self.assertEqual(rep["summary"]["delta"]["on_diff"].get("high"), 1)
        self.assertEqual(rep["summary"]["delta"]["pre_existing"].get("high"), 1)
        self.assertEqual(rep["meta"]["coverage"]["delta"]["base"], "main")

    def test_gate_scope_all_gates_everything(self):
        hunks = {"base": "main", "base_source": "explicit", "diff_context": 5,
                 "files_changed": 1, "hunks": {"a.py": [(10, 12)]}}
        rep = syn.build_report(self._findings(), [{"name": "g1", "files": ["a.py"]}],
                               "t", "high", "2026-01-01T00:00:00Z", gate_unverified=True,
                               diff_hunks=hunks, diff_context=5, gate_scope="all")
        self.assertEqual(rep["summary"]["gate"], "FAIL")  # both HIGHs count

    def test_coverage_delta_carries_three_anchors(self):
        hunks = {"base": "main", "base_source": "fallback", "diff_context": 5,
                 "base_commit": "b0", "delta_start": "d0", "delta_end": "d1",
                 "includes_uncommitted": False,
                 "files_changed": 1, "hunks": {"a.py": [(10, 12)]}}
        rep = syn.build_report(self._findings(), [{"name": "g1", "files": ["a.py"]}],
                               "t", "high", "2026-01-01T00:00:00Z", gate_unverified=True,
                               diff_hunks=hunks, diff_context=5)
        d = rep["meta"]["coverage"]["delta"]
        self.assertEqual((d["base_commit"], d["delta_start"], d["delta_end"]),
                         ("b0", "d0", "d1"))
        self.assertIs(d["includes_uncommitted"], False)

    def test_base_less_artifact_is_non_delta_not_inconclusive(self):
        # No delta_unresolved path anymore: a base-less artifact (which the
        # orchestrator no longer produces) is treated as a plain review.
        hunks = {"base": None, "base_source": "unresolved", "diff_context": 5,
                 "files_changed": 0, "hunks": {}}
        rep = syn.build_report(self._findings(), [{"name": "g1", "files": ["a.py"]}],
                               "t", "high", "2026-01-01T00:00:00Z", gate_unverified=True,
                               diff_hunks=hunks, diff_context=5)
        self.assertNotEqual(rep["summary"]["gate"], "INCONCLUSIVE")
        self.assertIsNone(rep["summary"]["delta"])
        self.assertIsNone(rep["meta"]["coverage"]["delta"])


class TestRenderDelta(unittest.TestCase):
    """#449 Task 9: render_summary surfaces summary.delta -- on-diff counts,
    all-severity pre-existing counts, and a loud (advisory, non-gating)
    warning when pre-existing CRITICAL+HIGH > 0."""

    def _report(self, pre):
        return {"meta": {"target": "t"}, "summary": {
            "overall_grade": "B", "risk_level": "MEDIUM", "gate": "PASS",
            "stats": {}, "evidence_stats": {}, "delta": {"on_diff": {"high": 1},
                                   "pre_existing": pre}}, "groups": [], "findings": []}

    def test_warns_on_pre_existing_high(self):
        out = syn.render_summary(self._report({"critical": 0, "high": 2, "medium": 5, "low": 3}))
        self.assertIn("pre-existing", out.lower())
        self.assertIn("2", out)              # HIGH count
        self.assertIn("⚠", out)         # loud warning glyph
        self.assertIn("5", out)              # MEDIUM count still shown

    def test_no_warning_without_high(self):
        out = syn.render_summary(self._report({"critical": 0, "high": 0, "medium": 4, "low": 1}))
        self.assertNotIn("⚠", out)
        self.assertIn("4", out)              # MEDIUM count still shown

    def test_delta_lines_placed_between_evidence_and_groups(self):
        r = self._report({"critical": 1, "high": 0, "medium": 0, "low": 0})
        out = syn.render_summary(r)
        lines = out.split("\n")
        ev_idx = next(i for i, ln in enumerate(lines) if ln.startswith("**Evidence:**"))
        groups_idx = next(i for i, ln in enumerate(lines) if ln == "## Groups")
        ondiff_idx = next(i for i, ln in enumerate(lines) if ln.startswith("**On-diff:**"))
        pre_idx = next(i for i, ln in enumerate(lines) if ln.startswith("**Pre-existing"))
        self.assertTrue(ev_idx < ondiff_idx < pre_idx < groups_idx)

    def test_no_delta_block_when_not_delta_mode(self):
        r = self._report({"critical": 0, "high": 0, "medium": 0, "low": 0})
        r["summary"]["delta"] = None
        out = syn.render_summary(r)
        self.assertNotIn("On-diff", out)
        self.assertNotIn("Pre-existing", out)


class TestScoutToolDisclosure(unittest.TestCase):
    """#471 remainder: a scout returning tools:[] is a silent decline of the
    tool layer -- must be disclosed on stderr and readable from the artifact
    (scout_profiles_seen > 0 with scout_requested [])."""

    def test_scout_declining_tools_is_disclosed(self):
        import io, contextlib
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            os.makedirs(".panopticon")
            with open(os.path.join(".panopticon", "scout-g1.json"), "w") as fh:
                json.dump({"group": "g1", "tools": [], "panels": ["code"]}, fh)
            fp = os.path.join(d, "findings-g1-code.json")
            with open(fp, "w") as fh:
                json.dump({"findings": []}, fh)
            out = os.path.join(d, "r.json")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(err):
                rc = syn.main(["--target", "src", "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertIn("requested NO tools", err.getvalue())
            with open(out) as fh:
                report = json.load(fh)
            cov = report["meta"]["coverage"]
            self.assertEqual(cov["scout_profiles_seen"], 1)
            self.assertEqual(cov["scout_requested"], [])

    def test_no_scout_profiles_no_disclosure(self):
        import io, contextlib
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = os.path.join(d, "findings-g1-code.json")
            with open(fp, "w") as fh:
                json.dump({"findings": []}, fh)
            out = os.path.join(d, "r.json")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(err):
                rc = syn.main(["--target", "src", "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertNotIn("requested NO tools", err.getvalue())
            with open(out) as fh:
                report = json.load(fh)
            self.assertEqual(report["meta"]["coverage"]["scout_profiles_seen"], 0)

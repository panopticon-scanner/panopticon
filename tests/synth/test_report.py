"""Report assembly, validation, and synthesis entry-point contracts."""

import contextlib
import io
import os
import json
import tempfile
import unittest
import scripts.synthesize as syn
import scripts.synth.findings as findings_mod
import scripts.synth.plan as plan_mod
import scripts.synth.report as report_mod
from tests.synth.helpers import DEFAULT_TIMESTAMP, _chdir, _make_finding


class TestReport(unittest.TestCase):

    def test_build_report_has_grades_and_gate(self):
        # A HIGH finding with no source/verdict is agentic + unverified, and
        # unverified findings are not gate-eligible by default -> grade/gate
        # reflect the (empty) gate-eligible set, not the raw severity.
        findings = [_make_finding(severity="HIGH", panel="code")]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on="high", timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        # The letter now comes from health, and "a.py" does not exist here, so
        # there is no LoC to measure -> no grade. The GATE is what this asserts.
        self.assertIsNone(report["summary"]["overall_grade"])
        self.assertEqual(report["summary"]["gate"], "PASS")
        # panel_grades stay the per-panel SEVERITY rollup -- health needs LoC,
        # which is not attributable per panel (one file feeds several).
        self.assertEqual(report["groups"][0]["panel_grades"]["code"], "A")

    def test_validate_clean_report(self):
        findings = [_make_finding()]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        errors, _ = report_mod.validate_report(report)
        self.assertEqual(errors, [])

    def test_validate_flags_bad_id_and_missing_cvss(self):
        bad = _make_finding(id="lowercase", panel="security", severity="CRITICAL")
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=[bad]),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        errors, _ = report_mod.validate_report(report)
        self.assertTrue(any("id" in e for e in errors))
        self.assertTrue(any("cvss" in e or "exploit" in e for e in errors))

    def test_validate_flags_duplicate_ids(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    _make_finding(
                        id="CD-001", title="a", category="x", location={"file": "a", "line_start": 1}
                    ),
                    _make_finding(
                        id="CD-001", title="b", category="y", location={"file": "b", "line_start": 2}
                    ),
                ],
            ),
        ))
        errors, _ = report_mod.validate_report(report)
        self.assertTrue(any("duplicate" in e.lower() for e in errors))

    def test_build_report_honors_review_type(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="src/app.py",
                fail_on=None,
                timestamp=DEFAULT_TIMESTAMP,
                review_type="file",
            ),
            findings=findings_mod.FindingSet(findings=[]),
        ))
        self.assertEqual(report["meta"]["review_type"], "file")

    def test_build_report_includes_security_mode(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="src",
                fail_on=None,
                timestamp=DEFAULT_TIMESTAMP,
                security_mode="redteam",
            ),
            findings=findings_mod.FindingSet(findings=[]),
        ))
        self.assertEqual(report["meta"]["security_mode"], "redteam")

    def test_build_report_populates_models_used(self):
        findings = [
            _make_finding(
                id="CD-001",
                panel="code",
                location={"file": "a.py", "line_start": 1},
                provenance={
                    "discovered_by": "agent:lens_sweep",
                    "confirmation_status": "CONFIRMED",
                    "model": "kimi-k2.7-coding",
                    "model_version": "v1",
                },
            ),
            _make_finding(
                id="CD-002",
                panel="code",
                location={"file": "a.py", "line_start": 2},
                provenance={
                    "discovered_by": "agent:panel_review",
                    "confirmation_status": "CONFIRMED",
                    "model": "kimi-k2.7-coding",
                    "model_version": "v1",
                },
            ),
            _make_finding(
                id="CD-003",
                panel="code",
                location={"file": "a.py", "line_start": 3},
                provenance={
                    "discovered_by": "agent:lens_sweep",
                    "confirmation_status": "CONFIRMED",
                    "model": "other-model",
                },
            ),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        models = report["meta"]["models_used"]
        self.assertEqual(len(models), 3)
        self.assertIn({"model": "kimi-k2.7-coding", "version": "v1", "role": "lens_sweep"}, models)
        self.assertIn(
            {"model": "kimi-k2.7-coding", "version": "v1", "role": "panel_review"}, models
        )
        self.assertIn({"model": "other-model", "role": "lens_sweep"}, models)

    def test_main_maps_orchestrator_mode_to_review_type(self):
        with tempfile.TemporaryDirectory() as d:
            gj = os.path.join(d, "groups.json")
            with open(gj, "w") as fh:
                json.dump({"mode": "directory", "groups": [{"name": "g1", "files": ["a.py"]}]}, fh)
            fpath = os.path.join(d, "findings-g1-code.json")
            with open(fpath, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "CD-001",
                                "title": "x",
                                "severity": "LOW",
                                "confidence": "POSSIBLE",
                                "panel": "code",
                                "category": "structure",
                                "location": {"file": "a.py", "line_start": 1},
                            }
                        ]
                    },
                    fh,
                )
            out = os.path.join(d, "report.json")

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
                json.dump(
                    {
                        "mode": "repo",
                        "security_mode": "standard",
                        "groups": [{"name": "core", "files": ["a.py", "b.py"]}],
                    },
                    fh,
                )
            fpath = os.path.join(d, "findings-core-code.json")
            with open(fpath, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "CD-001",
                                "title": "x",
                                "severity": "LOW",
                                "confidence": "POSSIBLE",
                                "panel": "code",
                                "category": "structure",
                                "location": {"file": "a.py", "line_start": 1},
                            }
                        ]
                    },
                    fh,
                )
            out = os.path.join(d, "report.json")

            buf = io.StringIO()
            with _chdir(d), contextlib.redirect_stdout(buf):
                # relative paths so auto-discovery resolves against the cwd
                syn.main(["--target", "src", "--out", "report.json", "findings-core-code.json"])
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
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "CD-001",
                                "title": "x",
                                "severity": "LOW",
                                "confidence": "POSSIBLE",
                                "panel": "code",
                                "category": "structure",
                                "location": {"file": "a.py", "line_start": 1},
                            }
                        ]
                    },
                    fh,
                )
            out = os.path.join(d, "report.json")

            buf = io.StringIO()
            with _chdir(d), contextlib.redirect_stdout(buf):
                syn.main(
                    [
                        "--target",
                        "src",
                        "--groups",
                        "explicit.json",
                        "--out",
                        "report.json",
                        "findings-x-code.json",
                    ]
                )
            with open(out) as _fh:
                report = json.load(_fh)
        self.assertEqual([g["name"] for g in report["groups"]], ["explicit"])

    def test_main_rejects_invalid_fail_on(self):
        with self.assertRaises(SystemExit):
            syn.main(["--target", "src", "--fail-on", "bogus", "x.json"])

    def test_validate_redteam_high_requires_cvss_and_exploit(self):
        bad = _make_finding(id="RT-001", panel="redteam", severity="HIGH")
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=[bad]),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        errors, _ = report_mod.validate_report(report)
        self.assertTrue(any("cvss" in e for e in errors))
        self.assertTrue(any("exploit" in e for e in errors))

    def test_validate_redteam_critical_filled_is_clean(self):
        good = _make_finding(
            id="RT-001",
            panel="redteam",
            severity="CRITICAL",
            cvss={"score": 9.0},
            exploit_scenario="x",
        )
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=[good]),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        errors, _ = report_mod.validate_report(report)
        self.assertEqual(errors, [])

    def test_main_severity_filter_excludes_lower(self):
        with tempfile.TemporaryDirectory() as d:
            findings = [
                {
                    "id": "SE-001",
                    "title": "crit",
                    "severity": "CRITICAL",
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "x",
                    "location": {"file": "a", "line_start": 1},
                    "cvss": {"score": 9},
                    "exploit_scenario": "y",
                },
                {
                    "id": "CD-001",
                    "title": "low",
                    "severity": "LOW",
                    "confidence": "POSSIBLE",
                    "panel": "code",
                    "category": "z",
                    "location": {"file": "a", "line_start": 2},
                },
            ]
            p = os.path.join(d, "findings-g1-security.json")
            with open(p, "w") as fh:
                json.dump({"findings": findings}, fh)
            out = os.path.join(d, "report.json")

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = syn.main(["--target", "src", "--severity", "high", "--out", out, p])
            self.assertEqual(rc, 0)  # gate default OFF
            with open(out) as _fh:
                report = json.load(_fh)
            # LOW filtered out, CRITICAL kept (assert on title -- ids are now
            # content-derived, #1109).
            self.assertEqual(len(report["findings"]), 1)
            self.assertEqual(report["findings"][0]["title"], "crit")

    def _tools_dir_with_sarif(self, d):
        # A semgrep SARIF with three results: real code (kept), a fixture-corpus
        # path (dropped by the default prune), and a non-fixture path a
        # --tools-exclude glob can drop independently of the fixture prune.
        sarif = {
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "r1",
                            "level": "error",
                            "message": {"text": "real"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app/db.py"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        },
                        {
                            "ruleId": "r2",
                            "level": "error",
                            "message": {"text": "fixture"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "tests/fixtures/vuln.py"},
                                        "region": {"startLine": 2},
                                    }
                                }
                            ],
                        },
                        {
                            "ruleId": "r3",
                            "level": "error",
                            "message": {"text": "generated"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        # #calibration-5: was `vendor/gen.js`, which
                                        # ingest now drops unconditionally as a
                                        # vendored dependency -- so it could no
                                        # longer stand for "a path only the CLI glob
                                        # removes", which is what this test is for.
                                        "artifactLocation": {"uri": "build/gen.js"},
                                        "region": {"startLine": 3},
                                    }
                                }
                            ],
                        },
                    ],
                }
            ]
        }
        tdir = os.path.join(d, "tools")
        os.makedirs(tdir)
        with open(os.path.join(tdir, "semgrep.sarif"), "w") as fh:
            json.dump(sarif, fh)
        return tdir

    def test_main_tools_exclude_and_fixture_prune_wired_end_to_end(self):
        # #693: --tools-exclude must reach ingest_dir from the CLI. Plus the
        # standard-mode default fixture prune (tool-path parity with #434) and
        # its --include-fixtures (redteam) escape hatch, all wired through main().

        with tempfile.TemporaryDirectory() as d:
            tdir = self._tools_dir_with_sarif(d)
            fpath = os.path.join(d, "findings-g1-code.json")
            with open(fpath, "w") as fh:
                json.dump({"findings": []}, fh)

            def run(extra):
                out = os.path.join(d, "r.json")
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = syn.main(
                        [
                            "--target",
                            "src",
                            "--gate-unverified",
                            "--tools-dir",
                            tdir,
                            "--out",
                            out,
                            *extra,
                            fpath,
                        ]
                    )
                self.assertEqual(rc in (0, 1), True)
                with open(out) as fh:
                    return {f["location"]["file"] for f in json.load(fh)["findings"]}

            # Default: fixture path pruned automatically; non-fixture paths kept.
            self.assertEqual(run([]), {"app/db.py", "build/gen.js"})
            # --tools-exclude drops a NON-fixture path via the CLI glob (#693).
            self.assertEqual(run(["--tools-exclude", "build/*"]), {"app/db.py"})
            # --include-fixtures (redteam) keeps the fixture-corpus finding.
            self.assertEqual(
                run(["--include-fixtures"]),
                {"app/db.py", "tests/fixtures/vuln.py", "build/gen.js"},
            )

    def test_main_changes_alias_sets_review_type(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-g1-code.json")
            with open(p, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "CD-001",
                                "title": "x",
                                "severity": "LOW",
                                "confidence": "POSSIBLE",
                                "panel": "code",
                                "category": "structure",
                                "location": {"file": "a.py", "line_start": 1},
                            }
                        ]
                    },
                    fh,
                )
            out = os.path.join(d, "report.json")

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
            json.dump(
                {
                    "findings": [
                        {
                            "id": "CD-001",
                            "title": "x",
                            "severity": "LOW",
                            "confidence": "POSSIBLE",
                            "panel": "code",
                            "category": "structure",
                            "location": {"file": "a.py", "line_start": 1},
                        }
                    ]
                },
                fh,
            )
        hunks = os.path.join(d, "diff-hunks.json")
        with open(hunks, "w") as fh:
            json.dump({"base": "main", "base_source": "pr-base", "hunks": {"a.py": [[1, 5]]}}, fh)
        out = os.path.join(d, "report.json")

        errbuf = io.StringIO()
        with (
            _chdir(d),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(errbuf),
        ):
            rc = syn.main(["--target", "src", "--diff-hunks", hunks, "--out", out, *extra, p])
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

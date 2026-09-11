"""Tests for scripts.synth.report: build_report end to end -- ReportInputs, meta.*
sections, gates and grades as the assembled report shows them.
"""
import contextlib
import io
import os
import json
import tempfile
import unittest

import scripts.synthesize as syn
import scripts.synth.findings as findings_mod
import scripts.synth.codes as codes_mod
import scripts.synth.delta as delta_mod
import scripts.synth.grading as grading_mod
import scripts.synth.plan as plan_mod
import scripts.synth.integrity as integrity_mod
import scripts.synth.cost as cost_mod
import scripts.synth.report as report_mod
import scripts.synth.verdicts as verdicts_mod
import scripts.synth.render as render_mod
import scripts.evidence as evidence_mod
import scripts.hosts as hosts_mod
import scripts.ocrdb as ocrdb
from scripts._version import __version__

from conftest import SKILL_ROOT
from tests.synth.helpers import SPLIT_FILE_MAX_BYTES, DEFAULT_TIMESTAMP, _chdir, _make_finding, _target_with_files, _agentic, _VERDICT_STATUS, _cli_args


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

class TestCliAndSummary(unittest.TestCase):
    def test_render_summary_contains_grade_and_location(self):
        # gate_unverified=True: this test is about render_summary's formatting
        # (location string, FAIL label), not the default gating policy.
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="src",
                fail_on="high",
                timestamp=DEFAULT_TIMESTAMP,
                gate_unverified=True,
            ),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "CD-001",
                        "title": "SQL injection",
                        "severity": "HIGH",
                        "confidence": "CERTAIN",
                        "panel": "security",
                        "category": "injection",
                        "location": {"file": "a.rb", "line_start": 42},
                        "cvss": {"score": 8.1, "vector": "CVSS:3.1/AV:N"},
                        "exploit_scenario": "...",
                    }
                ],
            ),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.rb"]}]),
        ))
        text = render_mod.render_summary(report)
        self.assertIn("a.rb:42", text)
        self.assertIn("FAIL", text)

    def test_render_summary_includes_all_panel_grades(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "CD-001",
                        "title": "t",
                        "severity": "LOW",
                        "confidence": "POSSIBLE",
                        "panel": "architecture",
                        "category": "structure",
                        "location": {"file": "a.py", "line_start": 1},
                    }
                ],
            ),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        text = render_mod.render_summary(report)
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
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "SE-001",
                                "title": "x",
                                "severity": "CRITICAL",
                                "confidence": "CERTAIN",
                                "panel": "security",
                                "category": "injection",
                                "location": {"file": "a.rb", "line_start": 1},
                                "cvss": {"score": 9.0, "vector": "CVSS:3.1/x"},
                                "exploit_scenario": "y",
                            }
                        ]
                    },
                    fh,
                )
            out = os.path.join(d, "report.json")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = syn.main(
                    [
                        "--target",
                        "src",
                        "--fail-on",
                        "high",
                        "--gate-unverified",
                        "--out",
                        out,
                        fpath,
                    ]
                )
            self.assertEqual(rc, 1)
            self.assertTrue(os.path.isfile(out))

    def test_write_report_split_preserves_findings_without_mutating_input(self):
        findings = [
            {
                "id": "CD-%03d" % i,
                "title": "t" * 40,
                "severity": "LOW",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "structure",
                "location": {"file": "a.py", "line_start": i},
            }
            for i in range(1, 400)
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        n_before = len(report["findings"])
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            paths = render_mod.write_report(report, out, max_bytes=SPLIT_FILE_MAX_BYTES)
            self.assertGreaterEqual(len(paths), 2)
            with open(paths[0]) as _fh:
                main_doc = json.load(_fh)
            self.assertIn("parts", main_doc["meta"])
            part_findings_count = 0
            for p in paths[1:]:
                with open(p) as fh:
                    part_findings_count += len(json.load(fh)["findings"])
            self.assertEqual(len(main_doc["findings"]) + part_findings_count, n_before)
            self.assertEqual(len(report["findings"]), n_before)  # caller not mutated

    def test_write_report_atomic_cleans_up_on_error(self):
        findings = [
            {
                "id": "CD-%03d" % i,
                "title": "t" * 40,
                "severity": "LOW",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "structure",
                "location": {"file": "a.py", "line_start": i},
            }
            for i in range(1, 400)
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            # If os.replace fails partway, no incomplete files should be left behind
            with unittest.mock.patch("os.replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    render_mod.write_report(report, out, max_bytes=SPLIT_FILE_MAX_BYTES)
            self.assertFalse(os.path.exists(out))
            # No stray .tmp files left in dir
            self.assertEqual(os.listdir(d), [])

    def test_main_returns_0_when_gate_not_fail(self):
        with tempfile.TemporaryDirectory() as d:
            fpath = os.path.join(d, "findings-g1-code.json")
            with open(fpath, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "CD-001",
                                "title": "x",
                                "severity": "MEDIUM",
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
                rc = syn.main(["--target", "src", "--out", out, fpath])
            self.assertEqual(rc, 0)

class TestSynthesizeLoadsHostCapabilities(unittest.TestCase):
    """synthesize.py's own artifact read: dirname(--groups)/host-capabilities.json,
    beside groups.json (F3a's write location) -- the part of Task 4 that lives
    outside report.py and so isn't exercised by TestHostCapabilitiesMeta at all.
    """

    def _run(self, d, groups_extra_files=(), out_name="report.json"):
        gj = os.path.join(d, "groups.json")
        with open(gj, "w") as fh:
            json.dump({"mode": "repo", "groups": [{"name": "g1", "files": ["a.py"]}]}, fh)
        fpath = os.path.join(d, "findings-g1-code.json")
        with open(fpath, "w") as fh:
            json.dump({"findings": []}, fh)
        for name, content in groups_extra_files:
            with open(os.path.join(d, name), "w") as fh:
                fh.write(content)
        out = os.path.join(d, out_name)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            syn.main(["--target", "src", "--groups", gj, "--out", out, fpath])
        with open(out) as fh:
            return json.load(fh)

    def test_reads_the_artifact_beside_groups_json(self):
        env = {"schema_version": 1, "host": "claude", "probed_at": "T",
              "capabilities": {hosts_mod.TOOL_POLICY_ENFORCED:
                               {"state": hosts_mod.REFUTED, "by": "shadow-shell-scan",
                                "detail": "ships panopticon-scout.md"},
                               hosts_mod.ARTIFACT_WRITE_GUARD:
                               {"state": hosts_mod.PROVEN, "by": "write-guard-armed",
                                "detail": "round-trip denied"}}}
        with tempfile.TemporaryDirectory() as d:
            report = self._run(d, [("host-capabilities.json", json.dumps(env))])
        hc = report["meta"]["host_capabilities"]
        self.assertEqual("claude", hc["host"])
        self.assertEqual(env["capabilities"], hc["capabilities"])

    def test_missing_artifact_reads_as_nobody_looked(self):
        with tempfile.TemporaryDirectory() as d:
            report = self._run(d)
        hc = report["meta"]["host_capabilities"]
        self.assertIsNone(hc["host"])
        self.assertEqual({}, hc["capabilities"])

    def test_corrupt_json_reads_as_nobody_looked_not_a_crash(self):
        # Truncated mid-write is the realistic corruption shape for an
        # artifact another process is writing concurrently.
        with tempfile.TemporaryDirectory() as d:
            report = self._run(d, [("host-capabilities.json", '{"host": "claude", "cap')])
        hc = report["meta"]["host_capabilities"]
        self.assertIsNone(hc["host"])
        self.assertEqual({}, hc["capabilities"])

    def test_a_json_array_artifact_reads_as_nobody_looked_not_a_crash(self):
        # json.load succeeds on any valid JSON document, not just objects --
        # the isinstance guard is what stops a bare array from propagating.
        with tempfile.TemporaryDirectory() as d:
            report = self._run(d, [("host-capabilities.json", "[1, 2, 3]")])
        hc = report["meta"]["host_capabilities"]
        self.assertIsNone(hc["host"])
        self.assertEqual({}, hc["capabilities"])

class TestReconciliation(unittest.TestCase):
    def test_normalize_backfills_title_category(self):
        f = findings_mod.normalize_finding({"description": "First line.\nSecond", "severity": "LOW"})
        self.assertEqual(f["title"], "First line.")
        self.assertEqual(f["category"], "general")

    def test_normalize_untitled_when_no_description(self):
        f = findings_mod.normalize_finding({"severity": "LOW"})
        self.assertEqual(f["title"], "(untitled)")

    def test_normalize_collapses_multiline_title(self):
        f = findings_mod.normalize_finding(
            {"title": "Package: requests\nInstalled: 2.19.0\nCVE-x", "severity": "MEDIUM"}
        )
        self.assertEqual(f["title"], "Package: requests Installed: 2.19.0 CVE-x")

    def test_main_survives_malformed_citation_and_writes_report(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-g1-security.json")
            with open(p, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "SE-001",
                                "title": "crit",
                                "severity": "CRITICAL",
                                "confidence": "CERTAIN",
                                "panel": "security",
                                "category": "x",
                                "source": "agent:sr",
                                "location": {"file": "a", "line_start": 1},
                                "cvss": {"score": 9.0, "vector": "v"},
                                "exploit_scenario": "e",
                            },
                            {
                                "id": "SE-002",
                                "title": "bad",
                                "severity": "LOW",
                                "confidence": "POSSIBLE",
                                "panel": "security",
                                "category": "y",
                                "source": "agent:sr",
                                "location": {"file": "b", "line_start": 2},
                                "citations": {"ssvc": "active"},
                            },
                        ]
                    },
                    fh,
                )
            out = os.path.join(d, "report.json")

            buf = io.StringIO()
            # Isolate cwd: main() discovers .panopticon/scout-*.json relative
            # to cwd, and the repo root's own .panopticon carries self-scan
            # leftovers that would otherwise leak "requested_absent" tools
            # into this fixture's tiny finding set.
            with _chdir(d), contextlib.redirect_stdout(buf):
                rc = syn.main(["--target", "t", "--fail-on", "high", "--out", out, p])
            self.assertTrue(os.path.isfile(out))  # report written despite malformed citation
            # Both findings are agentic and carry no verdict -> unverified,
            # which does not gate by default under the two-axis model.
            self.assertEqual(rc, 0)
            with open(out) as _fh:
                report = json.load(_fh)
            self.assertTrue(any(f["title"] == "crit" for f in report["findings"]))

    def test_validate_returns_errors_and_warnings(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "CD-001",
                        "title": "t",
                        "severity": "LOW",
                        "confidence": "POSSIBLE",
                        "panel": "code",
                        "category": "general",
                        "location": {},
                    }
                ],
            ),
        ))
        errors, warnings = report_mod.validate_report(report)
        self.assertEqual(errors, [])
        self.assertTrue(any("location" in w for w in warnings))

    def test_tool_security_finding_exempt_from_cvss(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "TR-001",
                        "title": "t",
                        "severity": "HIGH",
                        "confidence": "CERTAIN",
                        "panel": "security",
                        "category": "general",
                        "source": "tool:trivy",
                        "location": {"file": "a", "line_start": 1},
                    }
                ],
            ),
        ))
        errors, _ = report_mod.validate_report(report)
        self.assertEqual(errors, [])

    def test_four_digit_tool_id_is_valid(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "SG-1000",
                        "title": "t",
                        "severity": "LOW",
                        "confidence": "CERTAIN",
                        "panel": "security",
                        "category": "x",
                        "source": "tool:semgrep",
                        "location": {"file": "a", "line_start": 1},
                    }
                ],
            ),
        ))
        errors, _ = report_mod.validate_report(report)
        self.assertFalse(any("id" in e for e in errors))

class TestGroupTag(unittest.TestCase):
    def test_test_panel_grade_reflects_test_findings(self):
        # a test-panel finding on a path NOT in group files, tagged by _group.
        # gate_unverified=True: this test verifies _group attribution feeds
        # panel_grades, not the default gating policy (the finding is agentic
        # with no verdict, so it would be excluded from grading otherwise).
        findings = [
            {
                "id": "TS-001",
                "title": "weak test",
                "severity": "HIGH",
                "confidence": "LIKELY",
                "panel": "test",
                "category": "quality",
                "location": {"file": "spec/foo_spec.rb", "line_start": 3},
                "_group": "g1",
            }
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="src",
                fail_on=None,
                timestamp=DEFAULT_TIMESTAMP,
                gate_unverified=True,
            ),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["app/foo.rb"]}]),
        ))
        self.assertEqual(report["groups"][0]["panel_grades"]["test"], "D")  # not "A"
        # _group scrubbed from emitted findings
        self.assertNotIn("_group", report["findings"][0])

class TestGroupParentRollup(unittest.TestCase):
    """Task 6: report group view rolls subgroups up to their parent
    (group -> subgroup -> file drill-down), byte-identical for flat groups."""

    def test_subgroups_roll_up_to_parent(self):
        findings = [
            _make_finding(
                id="CD-001", severity="HIGH", panel="code",
                location={"file": "src/ui/admin/a.py", "line_start": 1},
                _group="UI:Admin",
            ),
            _make_finding(
                id="CD-002", severity="MEDIUM", panel="code",
                location={"file": "src/ui/components/b.py", "line_start": 1},
                _group="UI:Components",
            ),
        ]
        groups_meta = [
            {"name": "UI:Admin", "files": ["src/ui/admin/a.py"], "parent": "UI"},
            {"name": "UI:Components", "files": ["src/ui/components/b.py"], "parent": "UI"},
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="src",
                fail_on=None,
                timestamp=DEFAULT_TIMESTAMP,
                gate_unverified=True,
            ),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan_mod.PlanInputs(groups_meta=groups_meta),
        ))
        names = [g["name"] for g in report["groups"]]
        self.assertEqual(names, ["UI"])
        ui = report["groups"][0]
        # worst of D (HIGH -> Admin) and C (MEDIUM -> Components)
        self.assertEqual(ui["panel_grades"]["code"], "D")
        sub_names = {s["name"] for s in ui["subgroups"]}
        self.assertEqual(sub_names, {"UI:Admin", "UI:Components"})
        admin = next(s for s in ui["subgroups"] if s["name"] == "UI:Admin")
        components = next(s for s in ui["subgroups"] if s["name"] == "UI:Components")
        self.assertEqual(admin["panel_grades"]["code"], "D")
        self.assertEqual(components["panel_grades"]["code"], "C")
        self.assertEqual(admin["files"], ["src/ui/admin/a.py"])
        self.assertEqual(components["files"], ["src/ui/components/b.py"])
        # both subgroups' files are reachable for file-level drill-down
        self.assertIn("src/ui/admin/a.py", ui["files"])
        self.assertIn("src/ui/components/b.py", ui["files"])
        # The overall letter is health-derived and these files do not exist, so
        # it is unmeasurable here; the per-panel severity rollup asserted above
        # is what this test is actually about.
        self.assertIsNone(report["summary"]["overall_grade"])
        self.assertEqual(report["summary"]["gate"], "OFF")

    def test_flat_self_parented_groups_report_unchanged(self):
        # A flat groups.yml (no subgroups): every group self-parents, and the
        # report's group view must be exactly today's shape -- no "subgroups"
        # key, same fields, same values.
        findings = [_make_finding(severity="HIGH", panel="code")]
        groups_meta = [{"name": "g1", "files": ["a.py"]}]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on="high", timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan_mod.PlanInputs(groups_meta=groups_meta),
        ))
        self.assertEqual(len(report["groups"]), 1)
        g = report["groups"][0]
        self.assertEqual(g["name"], "g1")
        self.assertEqual(g["files"], ["a.py"])
        self.assertEqual(set(g), {"name", "files", "panel_grades", "key_findings"})
        self.assertEqual(g["panel_grades"]["code"], "A")

    def test_flat_groups_with_explicit_self_parent_unchanged(self):
        # Same as above but with an explicit parent==name (as discovery now
        # always writes) -- must still take the leaf/self-parented shape.
        findings = [_make_finding(severity="HIGH", panel="code")]
        groups_meta = [{"name": "g1", "files": ["a.py"], "parent": "g1"}]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on="high", timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan_mod.PlanInputs(groups_meta=groups_meta),
        ))
        self.assertEqual(len(report["groups"]), 1)
        g = report["groups"][0]
        self.assertEqual(g["name"], "g1")
        self.assertNotIn("subgroups", g)

    def test_load_findings_tags_group_from_filename(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-mygroup-code.json")
            with open(p, "w") as fh:
                json.dump({"findings": [{"severity": "LOW", "panel": "code"}]}, fh)
            out = findings_mod.load_findings([p])
            self.assertEqual(out[0]["_group"], "mygroup")

    def test_load_findings_tags_group_from_new_panel_filenames(self):
        with tempfile.TemporaryDirectory() as d:
            for panel in ["architecture", "database", "redteam"]:
                p = os.path.join(d, "findings-mygroup-%s.json" % panel)
                with open(p, "w") as fh:
                    json.dump({"findings": [{"severity": "LOW", "panel": panel}]}, fh)
                out = findings_mod.load_findings([p])
                self.assertEqual(out[0]["_group"], "mygroup")
                self.assertEqual(out[0]["panel"], panel)

    def test_load_findings_tags_group_from_domain_suffixed_filenames(self):
        # P4 review cells write findings-<group>-<domain>.json (groups_schema.DOMAINS,
        # e.g. "SEC"), no panel_review/lens_sweep suffix -- GROUP_RE must parse this
        # shape too, or _group tagging silently fails for every matrix cell.
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-Auth-SEC.json")
            with open(p, "w") as fh:
                json.dump(
                    {"findings": [{"severity": "LOW", "domain": "SEC", "code": "SEC-X0X"}]}, fh
                )
            out = findings_mod.load_findings([p])
            self.assertEqual(out[0]["_group"], "Auth")

class TestSummaryCitations(unittest.TestCase):
    def test_summary_shows_cwe_and_provenance(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "SG-001",
                        "title": "sqli",
                        "severity": "HIGH",
                        "confidence": "CERTAIN",
                        "panel": "security",
                        "category": "injection",
                        "source": "tool:semgrep",
                        "reinforced": True,
                        "location": {"file": "a.py", "line_start": 1},
                        "citations": {
                            "cwe": [{"id": "CWE-89", "name": "SQLi", "verified": True}],
                            "ssvc": {
                                "decision": "Act",
                                "model": "deployer-reduced",
                                "inputs": {
                                    "exploitation": "active",
                                    "exposure": "open",
                                    "impact": "high",
                                },
                            },
                        },
                    }
                ],
            ),
        ))
        text = render_mod.render_summary(report)
        self.assertIn("CWE-89", text)
        self.assertIn("Act", text)
        # the provenance chip shows the evidence status, not "reinforced". No
        # verdict is supplied here, so P2/#446 means this is tool_reported,
        # not tool_confirmed -- reinforcement alone no longer gates.
        self.assertIn("tool_reported", text)

    def test_summary_shows_panel_label(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "SE-001",
                        "title": "x",
                        "severity": "HIGH",
                        "confidence": "CERTAIN",
                        "panel": "security",
                        "category": "novel",
                        "source": "agent:sr",
                        "location": {"file": "a", "line_start": 1},
                        "cvss": {"score": 8, "vector": "v"},
                        "exploit_scenario": "e",
                    }
                ],
            ),
        ))
        self.assertIn("security", render_mod.render_summary(report))

class TestCrossPanelCorroboration(unittest.TestCase):
    """Cross-LENS agreement: the same real issue seen through different panels
    carries DIFFERENT categories by nature (security 'input-validation' vs test
    'test-coverage' vs code 'error-handling'), so it never matches dedupe's
    (file, line, category) key. A separate corroboration pass surfaces that N
    distinct panels independently flagged the same locus, WITHOUT collapsing the
    distinct-lens findings into one."""

    def _f(
        self, fid, panel, category, line, sev="HIGH", conf="POSSIBLE", file="app/resolver.py", **kw
    ):
        base = {
            "id": fid,
            "title": fid,
            "severity": sev,
            "confidence": conf,
            "panel": panel,
            "category": category,
            "location": {"file": file, "line_start": line},
        }
        base.update(kw)
        return base

    def test_different_panels_same_locus_corroborate(self):
        # SEC-701 (security, input-validation) + TST-701 (test, test-coverage)
        # at the SAME file:line, DIFFERENT categories -> corroboration.
        findings = [
            self._f(
                "SEC-701",
                "security",
                "input-validation",
                42,
                cvss={"score": 8.1, "vector": "v"},
                exploit_scenario="e",
            ),
            self._f("TST-701", "test", "test-coverage", 42),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
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
            self._f(
                "SE-1",
                "security",
                "input-validation",
                151,
                cvss={"score": 9, "vector": "v"},
                exploit_scenario="e",
            ),
            self._f("TS-1", "test", "test-coverage", 151),
            self._f("CD-1", "code", "error-handling", 151),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        integ = report["cross_panel"]["integration_findings"]
        self.assertEqual(len(integ), 1)
        self.assertEqual(sorted(integ[0]["panels"]), ["code", "security", "test"])
        self.assertEqual(len(report["findings"]), 3)  # none collapsed

    def test_negative_different_files_do_not_corroborate(self):
        # Two findings, different panels, but at genuinely different loci
        # (different files) -> NO false corroboration.
        findings = [
            self._f(
                "SE-1",
                "security",
                "input-validation",
                42,
                file="a.py",
                cvss={"score": 8, "vector": "v"},
                exploit_scenario="e",
            ),
            self._f("TS-1", "test", "test-coverage", 42, file="b.py"),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        self.assertEqual(report["cross_panel"]["integration_findings"], [])
        self.assertFalse(any(f.get("corroborated") for f in report["findings"]))

    def test_negative_far_apart_lines_do_not_corroborate(self):
        # Same file, different panels, but lines beyond the proximity window
        # -> genuinely different issues, not corroboration.
        findings = [
            self._f(
                "SE-1",
                "security",
                "input-validation",
                10,
                cvss={"score": 8, "vector": "v"},
                exploit_scenario="e",
            ),
            self._f("TS-1", "test", "test-coverage", 90),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        self.assertEqual(report["cross_panel"]["integration_findings"], [])

    def test_negative_same_panel_not_cross_panel(self):
        # Two SAME-panel findings at one line are within-lens, not cross-panel
        # corroboration (only ONE distinct panel present at the locus).
        findings = [
            self._f("CD-1", "code", "structure", 5),
            self._f("CD-2", "code", "naming", 5),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        self.assertEqual(report["cross_panel"]["integration_findings"], [])
        self.assertFalse(any(f.get("corroborated") for f in report["findings"]))

    def test_proximity_window_adjacent_lines(self):
        # Panels citing adjacent lines (function def at 150, vulnerable call at
        # 151) within CORROBORATION_LINE_WINDOW still corroborate.
        self.assertGreaterEqual(findings_mod.CORROBORATION_LINE_WINDOW, 1)
        findings = [
            self._f(
                "SE-1",
                "security",
                "input-validation",
                150,
                cvss={"score": 8, "vector": "v"},
                exploit_scenario="e",
            ),
            self._f("CD-1", "code", "error-handling", 151),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        self.assertEqual(len(report["cross_panel"]["integration_findings"]), 1)

    def test_confidence_not_mutated_by_corroboration(self):
        # Amended spec: confidence is never mutated by the pipeline — it is
        # purely the reviewer's self-assessment. Corroboration still annotates
        # `corroborated`/`corroborated_by` but must leave confidence as-is.
        fs = [
            self._f("SE-1", "security", "input-validation", 7, conf="POSSIBLE"),
            self._f("CD-1", "code", "error-handling", 7, conf="CERTAIN"),
        ]
        integ = findings_mod.cross_panel_corroboration(fs)
        self.assertEqual(len(integ), 1)
        by_id = {f["id"]: f for f in fs}
        self.assertEqual(by_id["SE-1"]["confidence"], "POSSIBLE")
        self.assertEqual(by_id["CD-1"]["confidence"], "CERTAIN")
        self.assertTrue(by_id["SE-1"]["corroborated"])
        self.assertTrue(by_id["CD-1"]["corroborated"])

    def test_integration_entry_records_max_severity(self):
        integ = findings_mod.cross_panel_corroboration(
            [
                self._f("SE-1", "security", "input-validation", 3, sev="CRITICAL"),
                self._f("CD-1", "code", "error-handling", 3, sev="LOW"),
            ]
        )
        self.assertEqual(integ[0]["severity"], "CRITICAL")

    def test_does_not_break_tool_agent_reinforce(self):
        # A tool+agent pair (dedupe collapses -> 1 security finding) plus an
        # independent test finding at the same locus -> the reinforced survivor
        # AND the test finding corroborate cross-panel.
        findings = [
            {
                "id": "SG-1",
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "sqli",
                "source": "tool:semgrep",
                "location": {"file": "db.py", "line_start": 10},
                "citations": {"cwe": [{"id": "CWE-89", "verified": True}]},
            },
            {
                "id": "SE-1",
                "severity": "HIGH",
                "confidence": "LIKELY",
                "panel": "security",
                "category": "sqli",
                "location": {"file": "db.py", "line_start": 10},
                "cvss": {"score": 8, "vector": "v"},
                "exploit_scenario": "e",
            },
            {
                "id": "TS-1",
                "severity": "MEDIUM",
                "confidence": "POSSIBLE",
                "panel": "test",
                "category": "test-coverage",
                "location": {"file": "db.py", "line_start": 10},
            },
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        secs = [f for f in report["findings"] if f["panel"] == "security"]
        self.assertEqual(len(secs), 1)  # tool+agent still collapsed
        self.assertTrue(secs[0].get("reinforced"))  # reinforce preserved
        self.assertEqual(len(report["cross_panel"]["integration_findings"]), 1)

    def test_summary_renders_corroboration_section(self):
        findings = [
            self._f(
                "SE-1",
                "security",
                "input-validation",
                42,
                cvss={"score": 8, "vector": "v"},
                exploit_scenario="e",
            ),
            self._f("TS-1", "test", "test-coverage", 42),
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        text = render_mod.render_summary(report)
        self.assertIn("Cross-panel", text)
        self.assertIn("app/resolver.py:42", text)

    def test_schema_defines_integration_finding_items(self):
        ref = os.path.join(SKILL_ROOT, "reference", "report-schema.json")
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
            "id": "SEC-001",
            "title": "SQLi",
            "severity": "HIGH",
            "confidence": "LIKELY",
            "panel": "security",
            "category": "injection",
            "provenance": {"discovered_by": "agent:lens_sweep"},
            "location": {"file": "app.py", "line_start": 10},
            "_group": "backend",
            "_repo_root": "/some/path",
        }
        f2 = {
            "id": "SEC-002",
            "title": "XSS",
            "severity": "MEDIUM",
            "confidence": "LIKELY",
            "panel": "security",
            "category": "xss",
            "provenance": {"discovered_by": "agent:lens_sweep"},
            "location": {"file": "app.py", "line_start": 55},
            "_group": "backend",
            "_repo_root": "/some/path",
        }
        verdicts = {
            evidence_mod.finding_fingerprint(f1): {
                "finding_id": "SEC-001",
                "verdict": "REJECTED",
                "reasoning": "False positive.",
            }
        }
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=[f1, f2], verdicts=verdicts),
        ))
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(len(report.get("discarded_claims", [])), 1)
        for finding in report["findings"]:
            self.assertNotIn("_group", finding)
            self.assertNotIn("_repo_root", finding)
        for finding in report.get("discarded_claims", []):
            self.assertNotIn("_group", finding)
            self.assertNotIn("_repo_root", finding)

class TestHealthLetterGrade(unittest.TestCase):
    """The letter grade, banded over the 0-100 health index.

    Replaces the max-severity rollup, which saturated: one HIGH anywhere was a D
    regardless of codebase size, so ten of the eleven measured runs graded D and
    the eleventh graded F.
    """

    def test_every_band_boundary(self):
        for score, letter in ((100, "S"), (99.99, "A"), (90, "A"), (89.99, "B"),
                              (80, "B"), (79.99, "C"), (70, "C"), (69.99, "D"),
                              (60, "D"), (59.99, "F"), (26, "F"), (25.99, "X"),
                              (0, "X")):
            with self.subTest(score=score):
                self.assertEqual(grading_mod.health_grade(score), letter)

    def test_s_is_reachable_only_at_exactly_100(self):
        # S must mean "no gate-eligible weighted defect at all", not "rounded up
        # from 99.995" -- otherwise it is just a second A.
        self.assertEqual(grading_mod.health_grade(100), "S")
        self.assertEqual(grading_mod.health_grade(99.99), "A")

    def test_unmeasurable_health_has_no_grade(self):
        # None, not X. A run whose paths do not resolve read no code; grading it
        # the floor letter would report a catastrophe it never measured.
        self.assertIsNone(grading_mod.health_grade(None))

    def test_grades_are_monotonic_in_health(self):
        order = ["S", "A", "B", "C", "D", "F", "X"]
        seen = [grading_mod.health_grade(v) for v in range(100, -1, -1)]
        ranks = [order.index(g) for g in seen]
        self.assertEqual(ranks, sorted(ranks), "a lower health scored a better letter")

    def test_the_six_calibration_targets_grade_c_d_f(self):
        # Real measured (total_loc, weighted_defect). Recorded because the bands
        # are a prior, not a fit: no measured codebase has ever reached B, so
        # this is the evidence a future recut would be argued against.
        expected = {"fzf": "F", "gotify": "F", "ripgrep": "F",
                    "express": "D", "btcpayserver": "D", "solidus": "C"}
        measured = {"fzf": (51789, 93341), "gotify": (31277, 52305),
                    "ripgrep": (68932, 72954), "express": (21911, 14512),
                    "btcpayserver": (321482, 183694), "solidus": (251596, 105547)}
        got = {n: grading_mod.health_grade(grading_mod.health_score(*v)) for n, v in measured.items()}
        self.assertEqual(got, expected)

    def test_grade_no_longer_saturates_on_one_high(self):
        # THE regression the change exists to prevent. Two codebases, same single
        # confirmed HIGH, three orders of magnitude apart in size. The old
        # max-severity rollup graded both D; they must now differ.
        def graded(lines):
            groups = [{"name": "g1", "files": ["a.py"]}]
            finding = _agentic(sev="HIGH",
                               location={"file": "a.py", "line_start": 1, "line_end": 4})
            verdicts = {evidence_mod.finding_fingerprint(finding): {
                "finding_id": "AG-001", "verdict": "CONFIRMED", "reasoning": "v"}}
            with _target_with_files(groups, lines=lines) as tgt:
                r = report_mod.build_report(report_mod.ReportInputs(
                    run=report_mod.RunConfig(
                        target=tgt,
                        fail_on="high",
                        timestamp="2026-01-01T00:00:00Z",
                    ),
                    findings=findings_mod.FindingSet(findings=[finding], verdicts=verdicts),
                    plan=plan_mod.PlanInputs(groups_meta=groups),
                ))
            return r["summary"]["overall_grade"]

        small, large = graded(50), graded(50000)
        self.assertNotEqual(small, large)
        # 25 (HIGH) x 4 lines = 100 weighted defect either way.
        self.assertEqual(large, "A")   # ... against 50,000 clean lines -> 99.8
        self.assertEqual(small, "F")   # ... against 50 -> 33.33
        # Not S: S needs ZERO gate-eligible weighted defect, so a confirmed
        # finding of any severity can never reach it however large the codebase.

    def test_a_clean_tree_grades_s_end_to_end(self):
        groups = [{"name": "g1", "files": ["a.py"]}]
        with _target_with_files(groups) as tgt:
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target=tgt,
                    fail_on="high",
                    timestamp="2026-01-01T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=groups),
            ))
        self.assertEqual(r["summary"]["overall_grade"], "S")
        self.assertEqual(r["summary"]["health"]["score"], 100.0)

    def test_grade_and_health_can_never_disagree(self):
        # They are computed from one shared dict; this pins that they stay so.
        groups = [{"name": "g1", "files": ["a.py"]}]
        finding = _agentic(sev="MEDIUM",
                           location={"file": "a.py", "line_start": 1, "line_end": 20})
        verdicts = {evidence_mod.finding_fingerprint(finding): {
            "finding_id": "AG-001", "verdict": "CONFIRMED", "reasoning": "v"}}
        with _target_with_files(groups, lines=200) as tgt:
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target=tgt,
                    fail_on="high",
                    timestamp="2026-01-01T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(findings=[finding], verdicts=verdicts),
                plan=plan_mod.PlanInputs(groups_meta=groups),
            ))
        s = r["summary"]
        self.assertEqual(s["overall_grade"], grading_mod.health_grade(s["health"]["score"]))

class TestEvidenceReport(unittest.TestCase):
    def _report(self, findings, verdicts=None, gate_unverified=False, fail_on="high"):
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="target",
                fail_on=fail_on,
                timestamp="2026-08-03T00:00:00Z",
                gate_unverified=gate_unverified,
            ),
            findings=findings_mod.FindingSet(findings=findings, verdicts=verdicts),
        ))

    def test_summary_carries_the_gate_severity_roles(self):
        # The report must ship the roles, not leave every renderer to re-derive
        # them from fail_on -- which is how the two would drift apart.
        report = self._report([_agentic(sev="HIGH")], fail_on="high")
        roles = report["summary"]["gate_severities"]
        self.assertEqual(roles["fail_on"], "HIGH")
        self.assertEqual(roles["in_play"], ["CRITICAL", "HIGH"])
        # unverified -> not gate-eligible -> in play but NOT contributing, and
        # the gate agrees.
        self.assertEqual(roles["contributing"], [])
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_gate_severity_roles_follow_confirmation(self):
        # Same finding, now confirmed: it becomes gate-eligible, the level turns
        # contributing, and the gate FAILs. The mark tracks the verdict.
        finding = _agentic(sev="HIGH")
        verdicts = {evidence_mod.finding_fingerprint(finding): {
            "finding_id": "AG-001", "verdict": "CONFIRMED", "reasoning": "v"}}
        report = self._report([finding], verdicts=verdicts, fail_on="high")
        self.assertEqual(report["summary"]["gate_severities"]["contributing"], ["HIGH"])
        self.assertEqual(report["summary"]["gate"], "FAIL")

    def test_unverified_keeps_severity_and_does_not_gate(self):
        report = self._report([_agentic(sev="CRITICAL")])
        f = report["findings"][0]
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertEqual(f["evidence"]["status"], "unverified")
        self.assertEqual(report["summary"]["gate"], "PASS")
        self.assertIsNone(report["summary"]["overall_grade"])   # no LoC here

    def test_gate_unverified_opts_in(self):
        report = self._report([_agentic(sev="CRITICAL")], gate_unverified=True)
        self.assertEqual(report["summary"]["gate"], "FAIL")
        self.assertIsNone(report["summary"]["overall_grade"])   # no LoC here
        self.assertEqual(report["summary"]["gate_policy"], "include_unverified")

    def test_confirmed_verdict_gates(self):
        finding = _agentic()
        verdicts = {
            evidence_mod.finding_fingerprint(finding): {
                "finding_id": "AG-001",
                "verdict": "CONFIRMED",
                "reasoning": "verified",
            }
        }
        report = self._report([finding], verdicts=verdicts)
        f = report["findings"][0]
        self.assertEqual(f["evidence"]["status"], "advisor_confirmed")
        self.assertEqual(report["summary"]["gate"], "FAIL")
        self.assertIsNone(report["summary"]["overall_grade"])   # no LoC here

    def test_summary_health_counts_only_gate_eligible(self):
        # #1146: the health denominator is the gate-eligible set (same as the
        # letter). A CONFIRMED HIGH spanning 4 lines -> weighted_defect = 25*4.
        # An UNVERIFIED finding is NOT gate-eligible and must not move it.
        confirmed = _agentic(location={"file": "app.py", "line_start": 10, "line_end": 13})
        unverified = _agentic(
            fid="AG-002", location={"file": "app.py", "line_start": 90, "line_end": 99}
        )
        verdicts = {
            evidence_mod.finding_fingerprint(confirmed): {
                "finding_id": "AG-001",
                "verdict": "CONFIRMED",
                "reasoning": "v",
            }
        }
        health = self._report([confirmed, unverified], verdicts=verdicts)["summary"]["health"]
        self.assertEqual(health["population"], "gate_eligible")
        self.assertEqual(health["weighted_defect"], 100)  # 25 * 4, unverified excluded
        self.assertEqual(health["weights"]["critical"], 125)
        self.assertEqual(health["total_loc"], 0)  # file absent in this fixture
        # No readable LoC is an unmeasurable codebase, NOT a health of zero --
        # otherwise a run whose paths fail to resolve grades X for code it never
        # read. See health_score's note.
        self.assertIsNone(health["score"])

    def test_summary_health_score_null_only_when_nothing_measurable(self):
        # An unverified-only report has an empty gate-eligible set -> no weighted
        # defect. In this fixture the reviewed file does not exist either, so
        # total_loc is 0 too and BOTH inputs are zero -- the one genuinely
        # undefined case. A clean repo with real LoC scores 100 (see
        # test_a_clean_repo_scores_a_perfect_100_not_none).
        health = self._report([_agentic()])["summary"]["health"]
        self.assertEqual(health["weighted_defect"], 0)
        self.assertEqual(health["total_loc"], 0)
        self.assertIsNone(health["score"])

    def test_summary_health_states_its_own_formula(self):
        # The score changed shape once; a report that names the expression it
        # used stays interpretable when it changes again.
        health = self._report([_agentic()])["summary"]["health"]
        self.assertEqual(health["formula"], grading_mod.HEALTH_FORMULA)
        self.assertIn("total_loc", health["formula"])
        self.assertIn("weighted_defect", health["formula"])

    def test_rejected_moves_to_discarded_with_severity_intact(self):
        finding = _agentic()
        verdicts = {
            evidence_mod.finding_fingerprint(finding): {
                "finding_id": "AG-001",
                "verdict": "REJECTED",
                "reasoning": "not exploitable",
            }
        }
        report = self._report([finding], verdicts=verdicts)
        self.assertEqual(report["findings"], [])
        d = report["discarded_claims"][0]
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["evidence"]["status"], "rejected")
        self.assertEqual(d["evidence"]["reasoning"], "not exploitable")
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_needs_more_info_stays_visible_not_gating(self):
        finding = _agentic()
        verdicts = {
            evidence_mod.finding_fingerprint(finding): {
                "finding_id": "AG-001",
                "verdict": "NEEDS_MORE_INFO",
                "reasoning": "need deploy config",
            }
        }
        report = self._report([finding], verdicts=verdicts)
        f = report["findings"][0]
        self.assertEqual(f["evidence"]["status"], "needs_more_info")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_tool_finding_without_verdict_is_reported_not_gated(self):
        # P2/#446: this is the load-bearing regression test for the Bandit
        # B105 self-scan incident -- an unverified tool claim must NOT gate a
        # build on its own. It is tool_reported until an advisor confirms it.
        tool = {
            "id": "TL-001",
            "title": "sqli",
            "severity": "HIGH",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection",
            "source": "tool:semgrep",
            "location": {"file": "app.py", "line_start": 5},
            "provenance": {"discovered_by": "tool:semgrep", "confirmation_status": "TOOL"},
        }
        report = self._report([findings_mod.normalize_finding(tool)])
        self.assertEqual(report["findings"][0]["evidence"]["status"], "tool_reported")
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_evidence_stats_counts_everything(self):
        f1 = _agentic()
        # distinct locus for AG-002 so dedupe doesn't collapse it into AG-001
        # (same file/line/category would otherwise keep only the more severe one).
        f2 = _agentic(fid="AG-002", sev="LOW", location={"file": "app.py", "line_start": 99})
        verdicts = {
            evidence_mod.finding_fingerprint(f1): {
                "finding_id": "AG-001",
                "verdict": "REJECTED",
                "reasoning": "r",
            }
        }
        report = self._report([f1, f2], verdicts=verdicts)
        stats = report["summary"]["evidence_stats"]
        self.assertEqual(stats["rejected"], 1)
        self.assertEqual(stats["unverified"], 1)

    def _split_report(self):
        # f1 gets REJECTED -> discarded; f2 stays active. So `stats` (active)
        # and `evidence_stats` (all) count DIFFERENT populations.
        f1 = _agentic()
        f2 = _agentic(fid="AG-002", sev="LOW", location={"file": "app.py", "line_start": 99})
        verdicts = {
            evidence_mod.finding_fingerprint(f1): {
                "finding_id": "AG-001",
                "verdict": "REJECTED",
                "reasoning": "r",
            }
        }
        return self._report([f1, f2], verdicts=verdicts)

    def test_summary_counts_label_the_two_populations(self):
        # #1059: summary.stats counts ACTIVE (kept) findings while
        # summary.evidence_stats counts ALL findings (kept + discarded), so the
        # two histograms' totals differ with nothing saying which is which --
        # the run-5 self-scan's unlabeled 65-vs-30. A labeled counts block plus
        # explicit population tags make each histogram reconcilable.
        summary = self._split_report()["summary"]
        counts = summary["counts"]
        self.assertEqual(counts["active"], 1)
        self.assertEqual(counts["discarded"], 1)
        self.assertEqual(counts["total"], 2)
        self.assertEqual(summary["stats_population"], "active")
        self.assertEqual(summary["evidence_stats_population"], "all")
        self.assertEqual(sum(summary["stats"].values()), counts["active"])
        self.assertEqual(sum(summary["evidence_stats"].values()), counts["total"])

    def test_summary_counts_reconcile_with_report_arrays(self):
        # counts must equal the ACTUAL report array lengths, not a parallel
        # tally that could drift from what the report emits.
        report = self._split_report()
        self.assertEqual(report["summary"]["counts"]["active"], len(report["findings"]))
        self.assertEqual(report["summary"]["counts"]["discarded"], len(report["discarded_claims"]))
        self.assertEqual(
            report["summary"]["counts"]["total"],
            len(report["findings"]) + len(report["discarded_claims"]),
        )

    def test_schema_theater_removed(self):
        report = self._report([_agentic()])
        self.assertNotIn("effort_to_remediate", report["summary"])
        self.assertNotIn("recommendations", report)
        self.assertEqual(report["meta"]["version"], __version__)

    def test_citation_quality_lives_in_evidence(self):
        report = self._report([_agentic(citations={"cwe": ["CWE-89"]})])
        f = report["findings"][0]
        self.assertNotIn("citation_quality", f)
        self.assertIn(f["evidence"]["citation_quality"], ("full", "partial", "minimal", "none"))

    def test_reinforced_tool_agent_merge_without_verdict_does_not_gate(self):
        # P2/#446: a tool HIGH + agent CRITICAL at the same locus reinforce to
        # a single survivor, which is tool-reported by construction (never
        # demoted to mere `corroborated`) -- but reinforcement alone is no
        # longer gate-eligible without an advisor CONFIRMED verdict, same as
        # any other tool claim. Gate stays PASS under --fail-on high.
        tool = {
            "id": "TL-002",
            "title": "sqli",
            "severity": "HIGH",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection",
            "source": "tool:semgrep",
            "location": {"file": "app.py", "line_start": 20},
        }
        agent = {
            "id": "AG-201",
            "title": "sqli (agent)",
            "severity": "CRITICAL",
            "confidence": "POSSIBLE",
            "panel": "security",
            "category": "injection",
            "location": {"file": "app.py", "line_start": 20},
        }
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
        verdicts = {
            "999-UNKNOWN": {"finding_id": "AG-999", "verdict": "CONFIRMED", "reasoning": "r"}
        }
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            report = self._report([_agentic()], verdicts=verdicts)
        f = report["findings"][0]
        self.assertEqual(f["evidence"]["status"], "unverified")
        self.assertIn("999-UNKNOWN", err.getvalue())

class TestHostCapabilitiesMeta(unittest.TestCase):
    """meta.host_capabilities: 5.1 surface 2 -- the artifact's `capabilities`
    map VERBATIM (state + by + detail), plus the host, so a consumer can diff
    posture across runs without re-deriving it.

    Test-helper note: the plan's brief called for a `self._build(host_capabilities=...)`
    helper that does not exist anywhere in this file. `TestEvidenceReport._report`
    (above) is close but requires `findings` as its first positional and has no
    `host_capabilities` parameter; ~15 other tests already depend on its exact
    signature. Rather than retrofit a parameter only this class needs, this
    class gets its own minimal `_build`, matching the brief's call shape
    (`self._build(host_capabilities=env)`) with an empty findings set --
    meta.host_capabilities does not depend on the findings axis at all.
    """

    def _build(self, host_capabilities):
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="target",
                fail_on="high",
                timestamp="2026-08-03T00:00:00Z",
                host_capabilities=host_capabilities,
            ),
            findings=findings_mod.FindingSet(findings=[]),
        ))

    def test_meta_carries_the_posture_verbatim(self):
        # Mixed on purpose (plan Global Constraints): a surface that
        # hard-codes one capability's shape passes an all-proven or
        # all-unknown fixture and fails to catch it. All five capabilities
        # present, spread across three different states -- proven, refuted,
        # unknown, each on a different capability.
        caps = {
            hosts_mod.TOOL_POLICY_ENFORCED: {"state": hosts_mod.REFUTED,
                                             "by": "shadow-shell-scan",
                                             "detail": "ships panopticon-scout.md"},
            hosts_mod.ARTIFACT_WRITE_GUARD: {"state": hosts_mod.PROVEN,
                                             "by": "write-guard-armed",
                                             "detail": "round-trip denied"},
            hosts_mod.USAGE_LEDGER: {"state": hosts_mod.UNKNOWN,
                                     "by": None,
                                     "detail": "no transcript directory"},
            hosts_mod.READ_SCOPE_CONFINED: {"state": hosts_mod.UNKNOWN,
                                            "by": None,
                                            "detail": "no read-confinement control yet"},
            hosts_mod.MODEL_BINDING: {"state": hosts_mod.UNKNOWN,
                                      "by": None,
                                      "detail": "model=None until F4 binds them"},
        }
        env = {"schema_version": 1, "host": "claude", "probed_at": "T",
               "capabilities": caps}
        report = self._build(host_capabilities=env)
        hc = report["meta"]["host_capabilities"]
        self.assertEqual("claude", hc["host"])
        # verbatim: the REASON survives, not just the verdict -- by/detail
        # included, nothing re-keyed, nothing summarised.
        self.assertEqual(env["capabilities"], hc["capabilities"])

    def test_meta_says_nobody_looked_when_the_artifact_is_absent(self):
        # synthesize.py's own absent/corrupt-artifact branch normalises to
        # {} -- this is what a RunConfig sees when nobody looked.
        report = self._build(host_capabilities={})
        hc = report["meta"]["host_capabilities"]
        self.assertIsNone(hc["host"])
        self.assertEqual({}, hc["capabilities"])

    def test_meta_fails_closed_on_a_non_dict_artifact(self):
        # The artifact is a file on disk and therefore untrusted: a
        # truncated or tampered host-capabilities.json can deserialize to
        # any JSON shape, not just an object. This must render as "nobody
        # looked", never raise mid-synthesis and never fabricate a posture.
        for bad in ([1, 2, 3], "garbage", 5, None):
            with self.subTest(bad=bad):
                report = self._build(host_capabilities=bad)
                hc = report["meta"]["host_capabilities"]
                self.assertIsNone(hc["host"])
                self.assertEqual({}, hc["capabilities"])

    def test_meta_fails_closed_when_capabilities_key_is_not_a_dict(self):
        # Isolates the OTHER arm: `host` is a valid, readable string but
        # `capabilities` is garbage. host_disclosure.host_of() never looks at
        # `capabilities`, so the host name still survives verbatim here --
        # only the unusable capabilities value collapses to {}. Without this
        # test, a single shared guard could look correct while actually only
        # covering the host_of() arm.
        bad = {"host": "claude", "capabilities": "not-a-mapping"}
        report = self._build(host_capabilities=bad)
        hc = report["meta"]["host_capabilities"]
        self.assertEqual("claude", hc["host"])
        self.assertEqual({}, hc["capabilities"])

class TestSeverityImmutability(unittest.TestCase):
    def test_no_path_mutates_severity(self):
        cases = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cases.append((_agentic(fid="AG-%s" % sev[:2], sev=sev), None))
        cases.append((_agentic(fid="AG-101"), {"verdict": "REJECTED", "reasoning": "r"}))
        cases.append((_agentic(fid="AG-102"), {"verdict": "NEEDS_MORE_INFO", "reasoning": "r"}))
        cases.append((_agentic(fid="AG-103"), {"verdict": "CONFIRMED", "reasoning": "r"}))
        for finding, verdict in cases:
            original = finding["severity"]
            verdicts = (
                {evidence_mod.finding_fingerprint(finding): dict(verdict, finding_id=finding["id"])}
                if verdict
                else None
            )
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on="high",
                    timestamp="2026-08-03T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(findings=[finding], verdicts=verdicts),
            ))
            everywhere = report["findings"] + report["discarded_claims"]
            self.assertEqual(
                everywhere[0]["severity"], original, "severity mutated for verdict=%r" % verdict
            )
            if verdict:
                self.assertEqual(
                    everywhere[0]["evidence"]["status"],
                    _VERDICT_STATUS[verdict["verdict"]],
                    "verdict %r did not actually reach apply_verdict" % verdict,
                )

    def test_no_path_mutates_confidence(self):
        # Amended spec: confidence, like severity, is never mutated by the
        # pipeline after normalize_finding — no exceptions (the legacy
        # dedupe/corroboration confidence bumps are removed).
        cases = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cases.append((_agentic(fid="AG-%s" % sev[:2], sev=sev), None))
        cases.append((_agentic(fid="AG-101"), {"verdict": "REJECTED", "reasoning": "r"}))
        cases.append((_agentic(fid="AG-102"), {"verdict": "NEEDS_MORE_INFO", "reasoning": "r"}))
        cases.append((_agentic(fid="AG-103"), {"verdict": "CONFIRMED", "reasoning": "r"}))
        for finding, verdict in cases:
            original = finding["confidence"]
            verdicts = (
                {evidence_mod.finding_fingerprint(finding): dict(verdict, finding_id=finding["id"])}
                if verdict
                else None
            )
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on="high",
                    timestamp="2026-08-03T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(findings=[finding], verdicts=verdicts),
            ))
            everywhere = report["findings"] + report["discarded_claims"]
            self.assertEqual(
                everywhere[0]["confidence"], original, "confidence mutated for verdict=%r" % verdict
            )
            if verdict:
                self.assertEqual(
                    everywhere[0]["evidence"]["status"],
                    _VERDICT_STATUS[verdict["verdict"]],
                    "verdict %r did not actually reach apply_verdict" % verdict,
                )

class TestBuildExecutingTools(unittest.TestCase):

    def test_meta_records_build_executing_tool(self):
        f = _make_finding(source="tool:roslyn-secguard")
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-03T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[f]),
        ))
        self.assertEqual(report["meta"]["coverage"]["build_executing_tools"], ["roslyn-secguard"])

    def test_meta_empty_without_executing_tools(self):
        f = _make_finding(source="tool:bandit")
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-03T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[f]),
        ))
        self.assertEqual(report["meta"]["coverage"]["build_executing_tools"], [])

class TestSchemaErrorsAreNotSilent(unittest.TestCase):
    def test_report_records_schema_error_count(self):
        bad = _agentic(fid="ag-lower")  # id fails ID_RE
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-03T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[bad]),
        ))
        errors, _ = report_mod.validate_report(report)
        self.assertTrue(errors)
        report_mod.attach_schema_status(report, errors)
        self.assertEqual(report["meta"]["schema_errors"], len(errors))

    def test_clean_report_records_zero(self):
        clean = _agentic(panel="code", category="style", severity="LOW")
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-03T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[clean]),
        ))
        errors, _ = report_mod.validate_report(report)
        report_mod.attach_schema_status(report, errors)
        self.assertEqual(report["meta"]["schema_errors"], 0)

class TestFindingFingerprint(unittest.TestCase):
    """Issues need identity that survives across runs and re-wordings."""

    def _f(self, **kw):
        f = {
            "id": "SG-001",
            "title": "t",
            "severity": "MEDIUM",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection",
            "location": {"file": "a.py", "line_start": 10},
        }
        f.update(kw)
        return f

    def test_stable_across_line_moves(self):
        a = evidence_mod.finding_fingerprint(self._f())
        b = evidence_mod.finding_fingerprint(self._f(location={"file": "a.py", "line_start": 99}))
        self.assertEqual(a, b)

    def test_stable_across_agent_rewording(self):
        # Agent prose varies run to run; identity must not.
        a = evidence_mod.finding_fingerprint(
            self._f(title="Module mixes concerns", description="one phrasing")
        )
        b = evidence_mod.finding_fingerprint(
            self._f(title="Module mixes concerns", description="a totally different phrasing")
        )
        self.assertEqual(a, b)

    def test_rule_id_discriminates_tool_findings_at_one_locus(self):
        a = evidence_mod.finding_fingerprint(
            self._f(source="tool:semgrep", tool_evidence={"rule_id": "R-AAA"})
        )
        b = evidence_mod.finding_fingerprint(
            self._f(source="tool:semgrep", tool_evidence={"rule_id": "R-BBB"})
        )
        self.assertNotEqual(a, b)

    def test_different_files_differ(self):
        a = evidence_mod.finding_fingerprint(self._f())
        b = evidence_mod.finding_fingerprint(self._f(location={"file": "b.py", "line_start": 10}))
        self.assertNotEqual(a, b)

    def test_leading_dot_of_a_dotfile_path_is_not_stripped(self):
        # `.github/workflows/ci.yml` and `github/workflows/ci.yml` are different
        # paths; only a `./` prefix is noise.
        a = evidence_mod.finding_fingerprint(self._f(location={"file": ".github/w/ci.yml"}))
        b = evidence_mod.finding_fingerprint(self._f(location={"file": "github/w/ci.yml"}))
        self.assertNotEqual(a, b)

    def test_dot_slash_prefix_is_normalized_away(self):
        a = evidence_mod.finding_fingerprint(self._f(location={"file": "./a.py"}))
        b = evidence_mod.finding_fingerprint(self._f(location={"file": "a.py"}))
        self.assertEqual(a, b)

    def test_report_findings_carry_fingerprints(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-03T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[_agentic()]),
        ))
        self.assertTrue(report["findings"][0]["fingerprint"])
        self.assertEqual(len(report["findings"][0]["fingerprint"]), 16)

class TestToolAxisMeta(unittest.TestCase):
    def _tool(self, fid="T-1", **over):
        f = {
            "id": fid,
            "source": "tool:bandit",
            "severity": "HIGH",
            "panel": "security",
            "category": "secrets",
            "title": "hardcoded password",
            "confidence": "LIKELY",
            "description": "d",
            "location": {"file": "a.py", "line_start": 1},
            "provenance": {"confirmation_reasoning": "B105"},
        }
        f.update(over)
        return f

    def test_tool_axis_counts_unverified_as_unanswered(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._tool()]),
        ))
        axis = r["meta"]["coverage"]["tool_axis"]
        self.assertEqual(axis["queued"], 1)
        self.assertEqual(axis["unanswered"], 1)
        self.assertEqual(axis["confirmed"], 0)
        self.assertIsNone(axis["rejection_rate"])

    def test_tool_axis_rejection_rate_when_verdicts_exist(self):
        a, b = self._tool("T-1"), self._tool("T-2", location={"file": "b.py", "line_start": 2})
        prepared, _ = findings_mod.prepare_for_queue([a, b])
        queue, _c = evidence_mod.build_verify_queue(prepared)
        verdicts = {}
        for i, e in enumerate(queue):
            verdicts[e["queue_id"]] = {
                "verdict": "REJECTED" if i == 0 else "CONFIRMED",
                "finding_id": e["finding"]["id"],
                "reasoning": "r",
            }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[a, b],
                verdicts=verdicts,
                verdicts_supplied=True,
            ),
        ))
        axis = r["meta"]["coverage"]["tool_axis"]
        self.assertEqual((axis["confirmed"], axis["rejected"]), (1, 1))
        self.assertEqual(axis["rejection_rate"], 0.5)

    def test_tool_axis_counts_needs_more_info_and_excludes_it_from_decided(self):
        a, b = self._tool("T-1"), self._tool("T-2", location={"file": "b.py", "line_start": 2})
        prepared, _ = findings_mod.prepare_for_queue([a, b])
        queue, _c = evidence_mod.build_verify_queue(prepared)
        verdicts = {
            queue[0]["queue_id"]: {
                "verdict": "NEEDS_MORE_INFO",
                "finding_id": queue[0]["finding"]["id"],
                "reasoning": "r",
            }
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[a, b],
                verdicts=verdicts,
                verdicts_supplied=True,
            ),
        ))
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
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[f]),
        ))
        axis = r["meta"]["coverage"]["tool_axis"]
        self.assertEqual(axis["queued"], 1)

    def test_build_executing_tools_reports_a_run_with_zero_findings(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[]),
            tools=plan_mod.ToolAxis(tools_ran={"roslyn-secguard", "bandit"}),
        ))
        self.assertEqual(r["meta"]["coverage"]["build_executing_tools"], ["roslyn-secguard"])

    def test_build_executing_tools_falls_back_without_tools_ran(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._tool(source="tool:roslyn-secguard")]),
        ))
        self.assertEqual(r["meta"]["coverage"]["build_executing_tools"], ["roslyn-secguard"])

class TestVerdictAccountingMeta(unittest.TestCase):
    """#443's own failure surface, made visible in the artifact.

    A run whose verdicts all fail to match used to still gate on tool findings,
    so the breakage was loud. Under strict gating (P2) that same run yields gate
    PASS, grade A, risk LOW -- the safest-looking output there is -- and CI reads
    the JSON, not stderr. meta.verdicts is the detection.
    """

    def _f(self, fid, title, fname):
        return {
            "id": fid,
            "title": title,
            "severity": "HIGH",
            "confidence": "POSSIBLE",
            "panel": "code",
            "category": "logic",
            "description": "d",
            "location": {"file": fname, "line_start": 1},
        }

    def _queue(self, findings):
        prepared, _ = findings_mod.prepare_for_queue(findings)
        return evidence_mod.build_verify_queue(prepared)[0]

    def test_counts_matched_unknown_and_unanswered(self):
        a = self._f("A-1", "first claim", "a.py")
        b = self._f("A-2", "second claim", "b.py")
        queue = self._queue([a, b])
        self.assertEqual(len(queue), 2)
        answered = queue[0]
        verdicts = {
            answered["queue_id"]: {
                "verdict": "CONFIRMED",
                "reasoning": "r",
                "finding_id": answered["finding"]["id"],
            },
            # A stale verdict from a previous run: well-formed, but its id is
            # in no queue this run.
            "deadbeefdeadbeef": {
                "verdict": "CONFIRMED",
                "reasoning": "stale",
                "finding_id": "GONE-1",
            },
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[a, b],
                verdicts=verdicts,
                verdicts_supplied=True,
            ),
        ))
        self.assertEqual(
            r["meta"]["coverage"]["verdicts"],
            {
                "queued": 2,
                "cut": 0,
                "supplied": 2,
                "matched": 1,
                "unknown": 1,
                "unanswered": 1,
                "misrouted": 0,
                "unloadable": 0,
            },
        )

    def test_unloadable_verdicts_surfaced_in_coverage(self):
        # #938: corrupt verdict files (passed as verdict_unloadable) surface as
        # a count in meta.coverage, so a lost verdict is visible rather than
        # only reflected as a lower `supplied`.
        a = self._f("A-1", "first claim", "a.py")
        self._queue([a])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on=None,
                    timestamp="2026-08-05T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(
                    findings=[a],
                    verdicts={},
                    verdicts_supplied=True,
                    verdict_unloadable=[
                        {"file": "x.json", "reason": "unparseable: ..."},
                        {"file": "y.json", "reason": "missing/invalid verdict key"},
                    ],
                ),
            ))
        self.assertEqual(r["meta"]["coverage"]["verdicts"]["unloadable"], 2)
        self.assertIn("un-loadable", err.getvalue())
        # a corrupt file is NOT a misrouted one -- different failure, different
        # remedy, so the two counters must not bleed into each other.
        self.assertEqual(r["meta"]["coverage"]["verdicts"]["misrouted"], 0)

    def test_echo_mismatch_is_dropped_and_reported_as_misrouted(self):
        # match_verdict refuses a verdict that echoes a different finding_id.
        # It is neither matched nor unknown, so supplied - matched - unknown
        # is exactly the echo-rejected count.
        #
        # #1475: it is ALSO counted as `misrouted`. The rejection was always
        # correct; what run-6 lacked was any way to tell it apart from a cell
        # no advisor ever answered, since both only moved `unanswered`. This is
        # the run-6 shape exactly: a verdict file present for the cell, naming
        # somebody else's finding.
        a = self._f("A-1", "first claim", "a.py")
        queue = self._queue([a])
        verdicts = {
            queue[0]["queue_id"]: {
                "verdict": "CONFIRMED",
                "reasoning": "r",
                "finding_id": "SOMEONE-ELSE",
            }
        }
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on=None,
                    timestamp="2026-08-05T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(
                    findings=[a],
                    verdicts=verdicts,
                    verdicts_supplied=True,
                ),
            ))
        self.assertEqual(
            r["meta"]["coverage"]["verdicts"],
            {
                "queued": 1,
                "cut": 0,
                "supplied": 1,
                "matched": 0,
                "unknown": 0,
                "unanswered": 1,
                # the whole point: an advisor DID answer, mislabelled -- not a
                # dispatch that never happened.
                "misrouted": 1,
                "unloadable": 0,
            },
        )
        self.assertEqual(r["summary"]["gate"], "OFF")  # ...and it looks clean
        # stderr must say an advisor answered and was mislabelled, not merely
        # that something is unanswered -- that distinction is the fix.
        self.assertIn("mislabelled", err.getvalue())

    def test_run6_shape_misroute_is_distinguishable_from_a_missing_dispatch(self):
        # The two failures that ran-6 collapsed into one number, side by side.
        # Same queue, same `unanswered: 1`, opposite causes and opposite fixes:
        # one needs the advisor re-dispatched, the other needs its answer
        # relabelled. A report that cannot tell them apart sends the operator
        # digging through raw agent transcripts, which is what it cost here.
        a = self._f("SG-006", "tool claim", "a.py")
        queue = self._queue([a])

        def report(verdicts):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                r = report_mod.build_report(report_mod.ReportInputs(
                    run=report_mod.RunConfig(
                        target="t",
                        fail_on=None,
                        timestamp="2026-08-05T00:00:00Z",
                    ),
                    findings=findings_mod.FindingSet(
                        findings=[a],
                        verdicts=verdicts,
                        verdicts_supplied=True,
                    ),
                ))
            return r["meta"]["coverage"]["verdicts"]

        # (a) no advisor ever answered this cell
        missing = report({})
        # (b) an advisor answered, echoing somebody else's finding (run-6: the
        #     cell dispatched for SG-006 returned ESS-036)
        misrouted = report({queue[0]["queue_id"]: {
            "verdict": "REJECTED", "reasoning": "r", "finding_id": "ESS-036"}})

        self.assertEqual(missing["unanswered"], 1)
        self.assertEqual(misrouted["unanswered"], 1)     # same headline ...
        self.assertEqual(missing["misrouted"], 0)        # ... different cause
        self.assertEqual(misrouted["misrouted"], 1)

    def test_unanswered_is_null_when_no_verdicts_were_supplied(self):
        # 0 would read as "nothing went unanswered" for a run that never ran a
        # verify phase; null says "not measured" (as tool_axis.rejection_rate
        # already does).
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f("A-1", "first claim", "a.py")]),
        ))
        self.assertEqual(
            r["meta"]["coverage"]["verdicts"],
            {
                "queued": 1,
                "cut": 0,
                "supplied": 0,
                "matched": 0,
                "unknown": 0,
                "unanswered": None,
                "misrouted": 0,
                "unloadable": 0,
            },
        )

class TestVerdictCutAccounting(unittest.TestCase):
    def _f(self, fid, sev="MEDIUM"):
        return {
            "id": fid,
            "severity": sev,
            "panel": "code",
            "category": "logic",
            "title": "t-" + fid,
            "confidence": "POSSIBLE",
            "description": "d",
            "location": {"file": fid + ".py", "line_start": 1},
        }

    def test_uncapped_run_reports_cut_zero(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f("A"), self._f("B")]),
        ))
        v = r["meta"]["coverage"]["verdicts"]
        self.assertEqual(v["cut"], 0)
        self.assertEqual(v["queued"], 2)

    def test_capped_run_reports_the_cut(self):
        findings = [self._f("A", "CRITICAL"), self._f("B", "HIGH"), self._f("C", "LOW")]
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on=None,
                timestamp="2026-08-05T00:00:00Z",
                max_verify=1,
            ),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        v = r["meta"]["coverage"]["verdicts"]
        self.assertEqual(v["queued"], 1)
        self.assertEqual(v["cut"], 2)

class TestMetaCoverage(unittest.TestCase):
    def _tool(self, fid="T-1"):
        return {
            "id": fid,
            "source": "tool:bandit",
            "severity": "HIGH",
            "panel": "security",
            "category": "secrets",
            "title": "x",
            "confidence": "LIKELY",
            "description": "d",
            "location": {"file": "a.py", "line_start": 1},
            "provenance": {"confirmation_reasoning": "B105"},
        }

    def test_coverage_block_holds_the_moved_fields(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._tool()]),
            tools=plan_mod.ToolAxis(
                policy_mode="enforced",
                tools_ran={"bandit"},
                dispositions={"bandit": {"status": "ok", "findings": 1}},
            ),
        ))
        cov = r["meta"]["coverage"]
        self.assertEqual(cov["adapters"]["bandit"]["status"], "ok")
        self.assertEqual(cov["tools_ran"], ["bandit"])
        self.assertEqual(cov["tool_policy_mode"], "enforced")
        self.assertIn("tool_axis", cov)
        self.assertIn("verdicts", cov)

    def test_moved_fields_are_gone_from_top_level_meta(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._tool()]),
        ))
        m = r["meta"]
        for k in ("tool_axis", "verdicts", "tool_policy_mode", "build_executing_tools"):
            self.assertNotIn(k, m)

    def test_coverage_present_on_a_findings_only_run(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "A",
                        "severity": "LOW",
                        "panel": "code",
                        "category": "logic",
                        "title": "t",
                        "confidence": "POSSIBLE",
                        "description": "d",
                        "location": {"file": "a.py", "line_start": 1},
                    }
                ],
            ),
        ))
        self.assertIn("coverage", r["meta"])
        self.assertEqual(r["meta"]["coverage"]["tool_policy_mode"], "unknown")
        self.assertEqual(r["meta"]["coverage"]["adapters"], {})

class TestCoverageEndToEnd(unittest.TestCase):
    def test_full_coverage_block_is_honest(self):
        tool = {
            "id": "T-1",
            "source": "tool:bandit",
            "severity": "HIGH",
            "panel": "security",
            "category": "secrets",
            "title": "x",
            "confidence": "LIKELY",
            "description": "d",
            "location": {"file": "a.py", "line_start": 1},
            "provenance": {"confirmation_reasoning": "B105"},
        }
        agent = {
            "id": "A-1",
            "severity": "LOW",
            "panel": "code",
            "category": "logic",
            "title": "t",
            "confidence": "POSSIBLE",
            "description": "d",
            "location": {"file": "b.py", "line_start": 2},
        }
        disp = {
            "bandit": {"status": "ok", "findings": 1},
            "semgrep": {"status": "failed", "findings": 0, "reason": "empty output file"},
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on="high",
                timestamp="2026-08-05T00:00:00Z",
                max_verify=1,
            ),
            findings=findings_mod.FindingSet(findings=[tool, agent]),
            tools=plan_mod.ToolAxis(
                policy_mode="enforced",
                tools_ran={"bandit"},
                dispositions=disp,
            ),
        ))
        cov = r["meta"]["coverage"]
        # semgrep failed -> not in tools_ran / build_executing_tools
        self.assertNotIn("semgrep", cov["tools_ran"])
        self.assertEqual(cov["adapters"]["semgrep"]["status"], "failed")
        # the cut is disclosed
        self.assertEqual(cov["verdicts"]["cut"], 1)
        self.assertEqual(cov["tool_policy_mode"], "enforced")

class TestFanOutCoverageMeta(unittest.TestCase):
    def _f(self):
        return {
            "id": "A",
            "severity": "LOW",
            "panel": "code",
            "category": "x",
            "title": "t",
            "confidence": "POSSIBLE",
            "description": "d",
            "location": {"file": "a.py", "line_start": 1},
        }

    def test_fan_out_present_under_coverage(self):
        fo = {
            "planned": {"code": 2},
            "executed": {"code": 1},
            "groups_complete": ["g1"],
            "groups_partial": ["g2"],
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-07T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f()]),
            plan=plan_mod.PlanInputs(fan_out=fo),
        ))
        self.assertEqual(r["meta"]["coverage"]["fan_out"], fo)

    def test_fan_out_null_when_absent(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-07T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f()]),
        ))
        self.assertIsNone(r["meta"]["coverage"]["fan_out"])

class TestCoverageDivergence(unittest.TestCase):
    GROUPS = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_inconclusive_on_incomplete_high_value_panel(self):
        fan_out = {
            "planned": {"security": 21, "code": 10},
            "executed": {"security": 3, "code": 10},
            "groups_complete": [],
            "groups_partial": ["g1"],
        }
        # Real files on disk: the letter is health-derived, and a fixture with
        # no readable LoC has no letter to make provisional.
        with _target_with_files(self.GROUPS) as tgt:
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=tgt, fail_on="high", timestamp=self.TS),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=self.GROUPS, fan_out=fan_out),
            ))
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")
        self.assertIsNone(r["summary"]["overall_grade"])
        # No findings -> no weighted defect -> health 100 -> S, held provisional
        # because a high-value panel did not complete.
        self.assertEqual(r["summary"]["provisional_grade"], "S")
        self.assertEqual(
            r["meta"]["coverage"]["divergence"]["panels"]["security"],
            {"planned": 21, "executed": 3},
        )
        self.assertNotIn("code", r["meta"]["coverage"]["divergence"]["panels"])

    def test_tool_noscan_is_disclosed_without_sinking_the_gate(self):
        # #1335: a semgrep that scanned 0 files gets no coverage credit (it is
        # absent from tools_ran), but it is NOT a coverage loss the operator can
        # fix -- on a no-surface repo there was nothing for it to scan. So it is
        # disclosed as `produced_noscan` and must never reach tools_absent,
        # which is what turns the gate INCONCLUSIVE.
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.GROUPS,
                                     scout_requested=["trivy", "semgrep"]),
            tools=plan_mod.ToolAxis(
                tools_ran=["trivy"],
                dispositions={"trivy": {"status": "ok", "findings": 2},
                              "semgrep": {"status": "noscan", "findings": 0}}),
        ))
        self.assertEqual(r["meta"]["coverage"]["divergence"]["tools"],
                         {"semgrep": "produced_noscan"})
        self.assertNotIn("semgrep", r["meta"]["coverage"]["tools_ran"])
        self.assertNotEqual(r["summary"]["gate"], "INCONCLUSIVE")

    def test_tool_requested_absent_is_disclosed_and_inconclusive(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.GROUPS, scout_requested=["trivy", "semgrep"]),
            tools=plan_mod.ToolAxis(tools_ran=["trivy"]),
        ))
        self.assertEqual(
            r["meta"]["coverage"]["divergence"]["tools"], {"semgrep": "requested_absent"}
        )
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")

    def test_backward_compat_no_fanout_no_scout(self):
        with _target_with_files(self.GROUPS) as tgt:
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=tgt, fail_on="high", timestamp=self.TS),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=self.GROUPS),
            ))
        # Clean tree, fully covered: no weighted defect at all -> health 100 -> S.
        self.assertEqual(r["summary"]["overall_grade"], "S")
        self.assertEqual(r["summary"]["gate"], "PASS")
        self.assertTrue(r["summary"]["coverage_certified"])
        self.assertIsNone(r["summary"]["provisional_grade"])
        self.assertEqual(r["meta"]["coverage"]["divergence"], {"panels": {}, "tools": {}})

    def test_present_empty_dispatch_plan_is_inconclusive(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.GROUPS,
                integrity={"plans_seen": 1, "empty_dispatch_plans": 1},
            ),
        ))
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")
        self.assertFalse(r["summary"]["coverage_certified"])

class TestFloorCellCoverageWiring(unittest.TestCase):
    """5.0 (matrix Sec5.1): build_report's own wiring of audit_floor_cells --
    not just the pure function (TestFloorCellAudit above). Mirrors
    TestCoverageDivergence's tools_absent-level coverage for the same
    INCONCLUSIVE-forcing mechanism."""

    GROUPS = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_missing_floor_cell_forces_inconclusive_and_is_disclosed(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.GROUPS,
                coverages=[{"group": "g1", "floor": ["SEC"], "effective": ["SEC"]}],
            ),
            tools=plan_mod.ToolAxis(ingested_paths=[]),
        ))
        self.assertEqual(r["meta"]["coverage"]["cells"]["missing_floor"], [["g1", "SEC"]])
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")
        self.assertFalse(r["summary"]["coverage_certified"])

    def test_present_floor_cell_stays_certified(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.GROUPS,
                coverages=[{"group": "g1", "floor": ["SEC"], "effective": ["SEC"]}],
            ),
            tools=plan_mod.ToolAxis(
                ingested_paths=[os.path.join(".panopticon", "findings-g1-SEC.json")],
            ),
        ))
        self.assertEqual(r["meta"]["coverage"]["cells"]["missing_floor"], [])
        self.assertEqual(r["summary"]["gate"], "PASS")
        self.assertTrue(r["summary"]["coverage_certified"])

    def test_backward_compat_no_coverages_no_regression(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.GROUPS),
        ))
        self.assertEqual(r["meta"]["coverage"]["cells"], {"missing_floor": []})
        self.assertEqual(r["summary"]["gate"], "PASS")

class TestResumeDisclosure(unittest.TestCase):
    G = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_build_report_emits_resume(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.G,
                resume={
                    "fan_out": {"total": 74, "done": 33, "pending": 41},
                    "verify": {"total": 52, "done": 12, "pending": 40},
                },
            ),
        ))
        self.assertEqual(r["meta"]["coverage"]["resume"]["fan_out"]["done"], 33)
        self.assertEqual(r["meta"]["coverage"]["resume"]["verify"]["pending"], 40)

    def test_build_report_resume_defaults_none(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G),
        ))
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
            rc = syn.main(["--out", out, fpath])
            self.assertIsInstance(rc, int)
            self.assertTrue(os.path.exists(out))
            with open(out) as fh:
                report = json.load(fh)
            self.assertEqual(report["meta"]["coverage"]["resume"]["verify"]["total"], 0)
            self.assertEqual(report["summary"]["gate"], "OFF")
            self.assertFalse(report["summary"]["coverage_certified"])
            self.assertIn("entries list", report["meta"]["integrity"]["invalid_verify_queue"])

class TestRenderSummaryCoverage(unittest.TestCase):
    def test_inconclusive_summary_names_divergence(self):
        fan_out = {
            "planned": {"security": 21},
            "executed": {"security": 3},
            "groups_complete": [],
            "groups_partial": ["g1"],
        }
        groups = [{"name": "g1", "files": ["a.py"]}]
        # Real files: the summary line prints a PROVISIONAL letter, and there is
        # no letter to hold provisional without readable LoC.
        with _target_with_files(groups) as tgt:
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target=tgt,
                    fail_on="high",
                    timestamp="2026-01-01T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=groups, fan_out=fan_out),
            ))
        text = render_mod.render_summary(r)
        self.assertIn("INCONCLUSIVE", text)
        self.assertIn("NOT CERTIFIED", text)
        self.assertIn("security", text)
        self.assertIn("provisional", text.lower())

class TestRenderSummaryResume(unittest.TestCase):
    G = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_resume_line_shown_when_pending(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.G,
                resume={
                    "fan_out": {"total": 74, "done": 33, "pending": 41},
                    "verify": {"total": 52, "done": 12, "pending": 40},
                },
            ),
        ))
        text = render_mod.render_summary(r)
        self.assertIn("Resume:", text)
        self.assertIn("33/74", text)
        self.assertIn("12/52", text)

    def test_no_resume_line_when_complete(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.G,
                resume={
                    "fan_out": {"total": 74, "done": 74, "pending": 0},
                    "verify": {"total": 52, "done": 52, "pending": 0},
                },
            ),
        ))
        self.assertNotIn("Resume:", render_mod.render_summary(r))

    def test_no_resume_line_when_resume_absent(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G),
        ))  # resume=None
        self.assertNotIn("Resume:", render_mod.render_summary(r))

class TestIntegrity(unittest.TestCase):
    G = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_certify_integrity_not_ok_is_inconclusive(self):
        r = grading_mod.certify("A", [], "high", set(), [], integrity_ok=False)
        self.assertEqual(r["gate"], "INCONCLUSIVE")
        self.assertFalse(r["coverage_certified"])

    def test_certify_integrity_ok_default_unchanged(self):
        r = grading_mod.certify("A", [], "high", set(), [])
        self.assertEqual(r["gate"], "PASS")
        self.assertTrue(r["coverage_certified"])

    def test_certify_integrity_not_ok_fail_still_wins(self):
        # Precedence truth-table (spec requirement): a confirmed CRITICAL
        # finding must still FAIL the gate when integrity is also broken --
        # integrity_ok=False must never downgrade a FAIL to INCONCLUSIVE.
        crit = [{"severity": "CRITICAL", "evidence": {"status": "advisor_confirmed"}}]
        r = grading_mod.certify("F", crit, "high", set(), [], integrity_ok=False)
        self.assertEqual(r["gate"], "FAIL")
        self.assertFalse(r["coverage_certified"])

    def test_certify_integrity_not_ok_off_preserved(self):
        # No --fail-on -> gate is OFF regardless of coverage; integrity_ok
        # must not force it to INCONCLUSIVE.
        r = grading_mod.certify("A", [], None, set(), [], integrity_ok=False)
        self.assertEqual(r["gate"], "OFF")
        self.assertFalse(r["coverage_certified"])

    def test_reconcile_flags_unexpected_and_missing(self):
        plan = [
            {"role": "panel_review", "out_file": ".panopticon/findings-g1-code-panel_review.json"},
            {
                "role": "lens_sweep",
                "out_file": ".panopticon/findings-g1-code-lens_sweep-style.json",
            },
        ]
        ingested = [
            ".panopticon/findings-g1-code-panel_review.json",
            ".panopticon/findings-EVIL-decoy.json",
        ]
        unexpected, missing = integrity_mod.reconcile_findings_files(plan, ingested)
        self.assertEqual(unexpected, [".panopticon/findings-EVIL-decoy.json"])
        self.assertEqual(missing, [".panopticon/findings-g1-code-lens_sweep-style.json"])

    def test_reconcile_skipped_without_plan(self):
        self.assertEqual(integrity_mod.reconcile_findings_files([], ["whatever.json"]), ([], []))
        self.assertEqual(integrity_mod.reconcile_findings_files(None, ["x.json"]), ([], []))

    def test_build_report_emits_integrity_and_inconclusive_on_unexpected(self):
        integ = {
            "unexpected_findings_files": [".panopticon/findings-EVIL.json"],
            "missing_planned_files": [],
            "unenforced_acknowledged": False,
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G, integrity=integ),
        ))
        self.assertEqual(r["meta"]["integrity"], integ)
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")

    def test_a_missing_owed_snapshot_cannot_certify(self):
        # #1511/#1208: "not measured" must be impossible on a driver run. The
        # snapshot the run owed is gone, so integrity is unproven -- that has to
        # read like the substitution it could be hiding, not like a clean run.
        integ = {
            "unexpected_findings_files": [],
            "missing_planned_files": [],
            "content_mismatched_files": [],
            "content_snapshot_unreadable": False,
            "content_snapshot_missing": True,
            "unenforced_acknowledged": False,
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G, integrity=integ),
        ))
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")
        self.assertIs(r["summary"]["coverage_certified"], False)

    def test_build_report_integrity_defaults_empty(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G),
        ))
        self.assertEqual(
            r["meta"]["integrity"],
            {
                "unexpected_findings_files": [],
                "missing_planned_files": [],
                "duplicate_out_files": [],
                "mislabeled_findings_files": [],
                "cross_domain_findings": [],
                "empty_dispatch_plans": 0,
                "invalid_dispatch_plans": [],
                "invalid_verify_queue": None,
                "unenforced_acknowledged": False,
                "plans_seen": 0,
            },
        )
        self.assertEqual(r["summary"]["gate"], "PASS")

    def test_build_report_integrity_non_dict_does_not_raise(self):
        # M10: a truthy non-dict integrity (e.g. a stray list) must fall back
        # to the default rather than raise on the .get() calls below it.
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G, integrity=["not", "a", "dict"]),
        ))
        self.assertEqual(
            r["meta"]["integrity"],
            {
                "unexpected_findings_files": [],
                "missing_planned_files": [],
                "duplicate_out_files": [],
                "mislabeled_findings_files": [],
                "cross_domain_findings": [],
                "empty_dispatch_plans": 0,
                "invalid_dispatch_plans": [],
                "invalid_verify_queue": None,
                "unenforced_acknowledged": False,
                "plans_seen": 0,
            },
        )
        self.assertEqual(r["summary"]["gate"], "PASS")

    def test_present_semantically_invalid_plan_is_inconclusive(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.G,
                integrity={
                    "plans_seen": 1,
                    "invalid_dispatch_plans": [
                        {"file": "p.json", "reason": "entry 0 is not an object"}
                    ],
                },
            ),
        ))
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")
        self.assertFalse(r["summary"]["coverage_certified"])

    def test_main_rejects_symlinked_artifact_root(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, os.path.join(d, ".panopticon"))
            with _chdir(d):
                self.assertEqual(syn.main(["--fail-on", "high"]), 2)

    def test_missing_alone_does_not_force_inconclusive(self):
        integ = {
            "unexpected_findings_files": [],
            "missing_planned_files": [".panopticon/findings-g1-x.json"],
            "unenforced_acknowledged": False,
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G, integrity=integ),
        ))
        self.assertEqual(r["summary"]["gate"], "PASS")

class TestRenderSummaryIntegrity(unittest.TestCase):
    G = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_integrity_line_on_unexpected(self):
        integ = {
            "unexpected_findings_files": [".panopticon/findings-EVIL.json"],
            "missing_planned_files": [],
            "unenforced_acknowledged": False,
        }
        text = render_mod.render_summary(
            report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=self.G, integrity=integ),
            ))
        )
        self.assertIn("Integrity:", text)
        self.assertIn("findings-EVIL.json", text)

    def test_no_integrity_line_when_clean(self):
        self.assertNotIn(
            "Integrity:", render_mod.render_summary(report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=self.G),
            )))
        )

class TestDeltaClassify(unittest.TestCase):
    def test_build_report_stamps_delta_when_hunks_present(self):
        findings = [
            {
                "id": "A-1",
                "title": "on",
                "severity": "HIGH",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "x",
                "location": {"file": "a.py", "line_start": 11},
            },
            {
                "id": "A-2",
                "title": "off",
                "severity": "HIGH",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "x",
                "location": {"file": "a.py", "line_start": 90},
            },
        ]
        hunks = {
            "base": "main",
            "base_source": "explicit",
            "diff_context": 5,
            "files_changed": 1,
            "hunks": {"a.py": [(10, 12)]},
        }
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-01-01T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=findings),
            delta=delta_mod.DeltaContext(diff_hunks=hunks, diff_context=5),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        by = {f["id"]: f["delta"]["on_diff"] for f in rep["findings"]}
        self.assertTrue(by["A-1"])
        self.assertFalse(by["A-2"])

    def test_build_report_no_delta_key_when_diff_hunks_omitted(self):
        """Backward compatibility: no diff_hunks kwarg -> no delta stamping at all
        (not even a False/None placeholder) — existing non-delta callers unaffected."""
        findings = [
            {
                "id": "A-1",
                "title": "x",
                "severity": "HIGH",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "x",
                "location": {"file": "a.py", "line_start": 11},
            },
        ]
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-01-01T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        self.assertNotIn("delta", rep["findings"][0])

    def test_build_report_no_delta_when_base_unresolved(self):
        """diff_hunks present but base is None (unresolved) -> delta_mode is False,
        so findings are left unstamped. (Orchestrator Task 5 now fails loudly
        before this artifact shape can occur in practice.)"""
        findings = [
            {
                "id": "A-1",
                "title": "x",
                "severity": "HIGH",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "x",
                "location": {"file": "a.py", "line_start": 11},
            },
        ]
        hunks = {
            "base": None,
            "base_source": "unresolved",
            "diff_context": 5,
            "files_changed": 0,
            "hunks": {},
        }
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-01-01T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=findings),
            delta=delta_mod.DeltaContext(diff_hunks=hunks, diff_context=5),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        self.assertNotIn("delta", rep["findings"][0])

class TestDeltaGate(unittest.TestCase):
    """#449 Task 8 (rework): on-diff gate/grade scoping, summary.delta,
    coverage.delta with three commit anchors. An unresolvable base is now a
    loud orchestrator failure (Task 5) that never reaches synthesize, so
    delta_mode alone drives these blocks -- no delta_unresolved path."""

    def _findings(self):
        return [
            {
                "id": "A-1",
                "title": "on-high",
                "severity": "HIGH",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "x",
                "location": {"file": "a.py", "line_start": 11},
            },
            {
                "id": "A-2",
                "title": "pre-high",
                "severity": "HIGH",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "x",
                "location": {"file": "a.py", "line_start": 90},
            },
        ]

    def test_gate_scopes_to_on_diff(self):
        hunks = {
            "base": "main",
            "base_source": "explicit",
            "diff_context": 5,
            "files_changed": 1,
            "hunks": {"a.py": [(10, 12)]},
        }
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on="high",
                timestamp="2026-01-01T00:00:00Z",
                gate_unverified=True,
                gate_scope="on-diff",
            ),
            findings=findings_mod.FindingSet(findings=self._findings()),
            delta=delta_mod.DeltaContext(diff_hunks=hunks, diff_context=5),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        # only the on-diff HIGH gates
        self.assertEqual(rep["summary"]["delta"]["on_diff"].get("high"), 1)
        self.assertEqual(rep["summary"]["delta"]["pre_existing"].get("high"), 1)
        self.assertEqual(rep["meta"]["coverage"]["delta"]["base"], "main")

    def test_gate_scope_all_gates_everything(self):
        hunks = {
            "base": "main",
            "base_source": "explicit",
            "diff_context": 5,
            "files_changed": 1,
            "hunks": {"a.py": [(10, 12)]},
        }
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on="high",
                timestamp="2026-01-01T00:00:00Z",
                gate_unverified=True,
                gate_scope="all",
            ),
            findings=findings_mod.FindingSet(findings=self._findings()),
            delta=delta_mod.DeltaContext(diff_hunks=hunks, diff_context=5),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        self.assertEqual(rep["summary"]["gate"], "FAIL")  # both HIGHs count

    def test_coverage_delta_carries_three_anchors(self):
        hunks = {
            "base": "main",
            "base_source": "fallback",
            "diff_context": 5,
            "base_commit": "b0",
            "delta_start": "d0",
            "delta_end": "d1",
            "includes_uncommitted": False,
            "files_changed": 1,
            "hunks": {"a.py": [(10, 12)]},
        }
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on="high",
                timestamp="2026-01-01T00:00:00Z",
                gate_unverified=True,
            ),
            findings=findings_mod.FindingSet(findings=self._findings()),
            delta=delta_mod.DeltaContext(diff_hunks=hunks, diff_context=5),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        d = rep["meta"]["coverage"]["delta"]
        self.assertEqual((d["base_commit"], d["delta_start"], d["delta_end"]), ("b0", "d0", "d1"))
        self.assertIs(d["includes_uncommitted"], False)

    def test_base_less_artifact_is_non_delta_not_inconclusive(self):
        # No delta_unresolved path anymore: a base-less artifact (which the
        # orchestrator no longer produces) is treated as a plain review.
        hunks = {
            "base": None,
            "base_source": "unresolved",
            "diff_context": 5,
            "files_changed": 0,
            "hunks": {},
        }
        rep = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on="high",
                timestamp="2026-01-01T00:00:00Z",
                gate_unverified=True,
            ),
            findings=findings_mod.FindingSet(findings=self._findings()),
            delta=delta_mod.DeltaContext(diff_hunks=hunks, diff_context=5),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]),
        ))
        self.assertNotEqual(rep["summary"]["gate"], "INCONCLUSIVE")
        self.assertIsNone(rep["summary"]["delta"])
        self.assertIsNone(rep["meta"]["coverage"]["delta"])

class TestUnloadableVerdictsGate(unittest.TestCase):
    """#979: an un-loadable verdict is missing verify coverage — a PASS with
    verdicts lost must read INCONCLUSIVE, not certified-clean."""

    def _crit(self):
        return [{"severity": "CRITICAL", "evidence": {"status": "advisor_confirmed"}}]

    def test_unloadable_forces_inconclusive_on_pass(self):
        r = grading_mod.certify("A", [], "high", set(), [], verdicts_unloadable=1)
        self.assertEqual(r["gate"], "INCONCLUSIVE")
        self.assertFalse(r["coverage_certified"])

    def test_zero_unloadable_leaves_pass(self):
        r = grading_mod.certify("A", [], "high", set(), [], verdicts_unloadable=0)
        self.assertEqual(r["gate"], "PASS")
        self.assertTrue(r["coverage_certified"])

    def test_unanswered_supplied_verdict_forces_inconclusive(self):
        r = grading_mod.certify("A", [], "high", set(), [], verdicts_unanswered=1)
        self.assertEqual(r["gate"], "INCONCLUSIVE")
        self.assertFalse(r["coverage_certified"])

    def test_unloadable_never_masks_fail(self):
        r = grading_mod.certify("F", self._crit(), "high", set(), [], verdicts_unloadable=2)
        self.assertEqual(r["gate"], "FAIL")

    def test_build_report_wires_unloadable_into_gate(self):
        f = {
            "id": "A-1",
            "title": "claim",
            "severity": "HIGH",
            "confidence": "POSSIBLE",
            "panel": "code",
            "category": "logic",
            "description": "d",
            "location": {"file": "a.py", "line_start": 1},
        }
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            clean = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on="high",
                    timestamp="2026-08-05T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(
                    findings=[dict(f)],
                    verdicts={},
                    verdicts_supplied=True,
                ),
            ))
            lossy = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on="high",
                    timestamp="2026-08-05T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(
                    findings=[dict(f)],
                    verdicts={},
                    verdicts_supplied=True,
                    verdict_unloadable=[{"file": "x.json", "reason": "unparseable"}],
                ),
            ))
        self.assertEqual(clean["summary"]["gate"], "INCONCLUSIVE")
        self.assertEqual(lossy["summary"]["gate"], "INCONCLUSIVE")

class TestCostLedger(unittest.TestCase):
    """meta.cost (4.3.2): the run's dispatch ledger, derived from artifacts —
    the 4.x cost baseline every 5.x economics exit criterion keys on."""

    def _f(self, fid, fname):
        return {
            "id": fid,
            "title": fid,
            "severity": "HIGH",
            "confidence": "POSSIBLE",
            "panel": "code",
            "category": "logic",
            "description": "d",
            "location": {"file": fname, "line_start": 1},
        }

    def test_cost_ledger_rows(self):
        # #run10: this fed build_report a hand-built `cost_fan_out` list of
        # panel_review/lens_sweep rows -- the only way that argument was ever
        # non-empty, since the filter behind it matched no plan the pipeline can
        # write. Retargeted onto driver_cost, so the ledger's LIVE path is the
        # one with end-to-end build_report coverage.
        dc = {"review_cells": 4, "verify_primary": 2, "verify_backup": 1,
              "verify_tools": 3, "tool_scan": 2}
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[self._f("A-1", "a.py"), self._f("A-2", "b.py")],
            ),
            plan=plan_mod.PlanInputs(scout_profiles_seen=3),
            cost=cost_mod.CostInputs(driver_cost=dc),
        ))
        cost = r["meta"]["cost"]
        self.assertIsNone(cost["tokens"])
        self.assertEqual(
            cost["dispatches"],
            [
                {"phase": "scout", "role": "scout", "model": None, "count": 3},
                {"phase": "review", "role": "domain_panel", "model": None, "count": 4},
                {"phase": "verify", "role": "domain_advisor", "model": None, "count": 2},
                {"phase": "verify", "role": "domain_advisor_backup", "model": None,
                 "count": 1},
                {"phase": "verify", "role": "tool_advisor", "model": None, "count": 3},
                {"phase": "tools", "role": "scan", "model": None, "count": 2},
            ],
        )

    def test_cost_ledger_without_plans(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f("A-1", "a.py")]),
        ))
        phases = [d["phase"] for d in r["meta"]["cost"]["dispatches"]]
        self.assertEqual(phases, ["scout", "verify"])
        self.assertEqual(r["meta"]["cost"]["dispatches"][0]["count"], 0)

    def test_tokens_surface_host_reported_usage(self):
        # #run10 D4: the driver is a subprocess and cannot observe per-dispatch
        # token usage -- it lives in the HOST's fan-out journal, so meta.cost.tokens
        # sat permanently null while run-10 burned ~21.05M subagent tokens. A host
        # that knows its usage writes usage.json; it is surfaced verbatim.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "usage.json"), "w", encoding="utf-8") as fh:
                json.dump({"total": 21053000, "by_phase": {"review": 10290000}}, fh)
            usage = cost_mod.load_run_usage(d)
        self.assertEqual(usage["total"], 21053000)
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f("A-1", "a.py")]),
            cost=cost_mod.CostInputs(run_usage=usage),
        ))
        self.assertEqual(r["meta"]["cost"]["tokens"]["total"], 21053000)

    def test_tokens_stay_null_without_host_usage(self):
        # No usage.json -> null, exactly as before. We never estimate tokens from
        # the dispatch counts: a fabricated ledger is worse than an honest gap.
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(cost_mod.load_run_usage(d))                 # absent
            with open(os.path.join(d, "usage.json"), "w", encoding="utf-8") as fh:
                fh.write("{not json")
            self.assertIsNone(cost_mod.load_run_usage(d))                 # malformed
            with open(os.path.join(d, "usage.json"), "w", encoding="utf-8") as fh:
                json.dump({}, fh)
            self.assertIsNone(cost_mod.load_run_usage(d))                 # empty
        self.assertIsNone(cost_mod.load_run_usage(""))
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f("A-1", "a.py")]),
        ))
        self.assertIsNone(r["meta"]["cost"]["tokens"])

    def test_cost_in_report_schema(self):
        import json

        with open(
            os.path.join(SKILL_ROOT, "reference", "report-schema.json"),
            encoding="utf-8",
        ) as fh:
            schema = json.load(fh)
        self.assertIn("cost", schema["properties"]["meta"]["properties"])

class TestToolCoverageCertification(unittest.TestCase):
    """#1031: tool-coverage certification keys on the runner's DETERMINISTIC
    adapter manifest (selected/produced/missing), not the scout's advisory tool
    list. A scout naming a tool the runner can't run -> disclosed, never gates."""

    TS = "2026-08-17T00:00:00Z"

    def _div_tools(self, r):
        return r["meta"]["coverage"]["divergence"]["tools"]

    def test_scout_noise_disclosed_not_gating(self):
        # scout named tools with no adapter / inapplicable to the target; every
        # SELECTED adapter produced -> certified, noise only disclosed.
        tm = {
            "selected": ["eslint-security", "semgrep"],
            "produced": ["eslint-security", "semgrep"],
            "missing": [],
            "excluded_scope": [],
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=["bcryptjs", "pip-audit", "eslint"]),
            tools=plan_mod.ToolAxis(manifest=tm),
        ))
        self.assertEqual(
            self._div_tools(r),
            {
                "bcryptjs": "requested_unavailable",
                "pip-audit": "requested_unavailable",
                "eslint": "requested_unavailable",
            },
        )
        self.assertTrue(r["summary"]["coverage_certified"])

    def test_produced_but_unusable_adapter_gates(self):
        # #1512 / Codex BR-02: bandit was selected and wrote bytes, so the
        # manifest calls it produced with nothing missing -- but ingestion could
        # not parse those bytes. Deriving coverage from the manifest alone
        # certified a scanner that never delivered a finding it could read.
        tm = {"selected": ["bandit", "gitleaks"],
              "produced": ["bandit", "gitleaks"], "missing": [], "excluded_scope": []}
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=[]),
            tools=plan_mod.ToolAxis(
                manifest=tm, tools_ran={"gitleaks"},
                dispositions={"bandit": {"status": "failed", "findings": 0,
                                         "reason": "unparseable: x"},
                              "gitleaks": {"status": "ok", "findings": 1}}),
        ))
        self.assertEqual(self._div_tools(r), {"bandit": "produced_unusable"})
        self.assertFalse(r["summary"]["coverage_certified"])
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")
        # the reason stays legible in the artifact, not just the label
        self.assertIn("unparseable",
                      r["meta"]["coverage"]["adapters"]["bandit"]["reason"])

    def test_unusable_gates_while_noscan_beside_it_does_not(self):
        # The two #1512 / #1335 verdicts must not collapse into each other: one
        # is lost coverage an operator can act on, the other is a no-surface
        # disclosure. Same run, same manifest, different outcomes.
        tm = {"selected": ["bandit", "semgrep"],
              "produced": ["bandit", "semgrep"], "missing": [], "excluded_scope": []}
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=[]),
            tools=plan_mod.ToolAxis(
                manifest=tm, tools_ran=set(),
                dispositions={"bandit": {"status": "failed", "findings": 0,
                                         "reason": "unparseable: x"},
                              "semgrep": {"status": "noscan", "findings": 0}}),
        ))
        self.assertEqual(self._div_tools(r),
                         {"bandit": "produced_unusable", "semgrep": "produced_noscan"})
        self.assertFalse(r["summary"]["coverage_certified"])

    def test_a_manifest_without_ingestion_keeps_the_1031_behaviour(self):
        # --no-tools / no --tools-dir: there are no dispositions to judge
        # usability with. Inferring "unusable" from their absence would fail
        # every selected adapter on a run that never ingested.
        tm = {"selected": ["bandit"], "produced": ["bandit"], "missing": [],
              "excluded_scope": []}
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=[]),
            tools=plan_mod.ToolAxis(manifest=tm),
        ))
        self.assertEqual(self._div_tools(r), {})
        self.assertTrue(r["summary"]["coverage_certified"])

    def test_real_missing_adapter_gates(self):
        # a SELECTED adapter that didn't produce is a real coverage loss ->
        # requested_absent -> not certified, even if the scout never named it.
        tm = {
            "selected": ["eslint-security", "npm-audit"],
            "produced": ["eslint-security"],
            "missing": ["npm-audit"],
            "excluded_scope": [],
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=[]),
            tools=plan_mod.ToolAxis(manifest=tm),
        ))
        self.assertEqual(self._div_tools(r), {"npm-audit": "requested_absent"})
        self.assertFalse(r["summary"]["coverage_certified"])

    def test_scout_wanted_a_real_missing_adapter_still_gates(self):
        # the scout named a selected-but-unproduced adapter: it's a real gap.
        tm = {
            "selected": ["npm-audit"],
            "produced": [],
            "missing": ["npm-audit"],
            "excluded_scope": [],
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=["npm-audit", "bcryptjs"]),
            tools=plan_mod.ToolAxis(manifest=tm),
        ))
        self.assertEqual(
            self._div_tools(r),
            {"npm-audit": "requested_absent", "bcryptjs": "requested_unavailable"},
        )
        self.assertFalse(r["summary"]["coverage_certified"])

    def test_manifest_absent_uses_legacy_scout_gate(self):
        # no manifest -> unchanged 4.x behavior (scout_requested - produced).
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_requested=["eslint"]),
            tools=plan_mod.ToolAxis(tools_ran=[]),
        ))
        self.assertEqual(self._div_tools(r), {"eslint": "requested_absent"})
        self.assertFalse(r["summary"]["coverage_certified"])

class TestOcrdbValidation(unittest.TestCase):
    """5.0 Slice A Task 3: synthesize auto-loads the OCRDb bundle, stamps
    the version, and validates finding codes against it."""

    def _bundle(self):
        return ocrdb.load_bundle()

    def test_valid_code_kept_and_counted_zero(self):
        b = self._bundle()
        real = ocrdb.domain_menu(b, "SEC")[0]["code"]
        findings = [{"code": real, "domain": "SEC"}]
        cov = codes_mod.validate_finding_codes(findings, b)
        self.assertEqual(findings[0]["code"], real)
        self.assertEqual(cov["invalid_codes"], 0)

    def test_unknown_code_replaced_with_fallback_and_counted(self):
        b = self._bundle()
        findings = [{"code": "SEC-ZZZ", "domain": "SEC"}]
        cov = codes_mod.validate_finding_codes(findings, b)
        self.assertEqual(findings[0]["code"], "SEC-X0X")
        self.assertEqual(cov["invalid_codes"], 1)
        self.assertEqual(cov["fallbacks"].get("SEC"), 1)

    def test_code_without_domain_derives_domain_from_code(self):
        b = self._bundle()
        findings = [{"code": "SEC-ZZZ"}]  # no "domain" key
        cov = codes_mod.validate_finding_codes(findings, b)
        self.assertEqual(findings[0]["code"], "SEC-X0X")  # domain derived via ocrdb.domain_of
        self.assertEqual(cov["invalid_codes"], 1)
        self.assertEqual(cov["fallbacks"].get("SEC"), 1)

    def test_explicit_fallback_counted_as_fallback_not_invalid(self):
        b = self._bundle()
        findings = [{"code": "SEC-X0X", "domain": "SEC"}]
        cov = codes_mod.validate_finding_codes(findings, b)
        self.assertEqual(cov["invalid_codes"], 0)
        self.assertEqual(cov["fallbacks"].get("SEC"), 1)

    def test_bundle_absent_leaves_findings_and_returns_none(self):
        findings = [{"code": "SEC-A1A"}]
        cov = codes_mod.validate_finding_codes(findings, None)
        self.assertIsNone(cov)
        self.assertEqual(findings[0]["code"], "SEC-A1A")  # untouched

    def test_build_report_stamps_ocrdb_version(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[{"title": "t", "severity": "LOW", "code": "SEC-A1A", "domain": "SEC"}],
            ),
        ))
        self.assertEqual(report["meta"]["ocrdb_version"], "0.5.0")
        self.assertIsNotNone(report["meta"]["coverage"]["ocrdb"])

    def test_build_report_bundle_absent_is_null_and_safe(self):
        with unittest.mock.patch("scripts.ocrdb.load_bundle", return_value=None):
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
                findings=findings_mod.FindingSet(
                    findings=[{"title": "t", "severity": "LOW", "code": "SEC-A1A", "domain": "SEC"}],
                ),
            ))
        self.assertIsNone(report["meta"]["ocrdb_version"])
        self.assertIsNone(report["meta"]["coverage"]["ocrdb"])
        self.assertEqual(report["findings"][0]["code"], "SEC-A1A")  # untouched, bundle-absent path

class TestStrictGate(unittest.TestCase):
    # P2/#446, combined effect: derive_evidence now checks the advisor
    # verdict before the finding's source, and the verify queue (fingerprint-
    # keyed, queues every finding) can actually route a tool claim to that
    # verdict. Together: an unverified tool HIGH is `tool_reported`, which is
    # not gate-eligible, so it no longer fails the build on its own -- it
    # takes an advisor CONFIRMED to fail the gate. --gate-unverified remains
    # the escape hatch that restores the old "every non-rejected claim gates"
    # behavior.
    def _tool_high(self):
        return {
            "id": "T-1",
            "source": "tool:bandit",
            "severity": "HIGH",
            "panel": "security",
            "category": "secrets",
            "title": "hardcoded password",
            "confidence": "LIKELY",
            "description": "d",
            "location": {"file": "a.py", "line_start": 1},
            "provenance": {"confirmation_reasoning": "B105"},
        }

    def test_unverified_tool_high_no_longer_fails_the_gate(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._tool_high()]),
        ))
        self.assertEqual(r["summary"]["gate"], "PASS")
        self.assertEqual(r["findings"][0]["evidence"]["status"], "tool_reported")

    def test_confirmed_tool_high_fails_the_gate(self):
        f = self._tool_high()
        prepared, _ = findings_mod.prepare_for_queue([dict(f)])
        queue, _c = evidence_mod.build_verify_queue(prepared)
        qid = queue[0]["queue_id"]
        verdicts = {
            qid: {
                "verdict": "CONFIRMED",
                "finding_id": queue[0]["finding"]["id"],
                "reasoning": "real credential",
            }
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[f],
                verdicts=verdicts,
                verdicts_supplied=True,
            ),
        ))
        self.assertEqual(r["summary"]["gate"], "FAIL")

    def test_gate_unverified_still_includes_tool_reported(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on="high",
                timestamp="2026-08-05T00:00:00Z",
                gate_unverified=True,
            ),
            findings=findings_mod.FindingSet(findings=[self._tool_high()]),
        ))
        self.assertEqual(r["summary"]["gate"], "FAIL")

class ReportInputsTest(unittest.TestCase):
    """WS-0 S2: the grouped build_report input structs. Their defaults must
    mean exactly what the omitted keyword meant on the 33-argument signature,
    and the four-stage orchestrator must not depend on which of them a caller
    spelled out."""

    def _run(self):
        return report_mod.RunConfig(target="t", fail_on="high", timestamp=DEFAULT_TIMESTAMP)

    def test_omitted_structs_equal_their_explicit_defaults(self):
        f = _make_finding(severity="HIGH")
        terse = report_mod.build_report(report_mod.ReportInputs(
            run=self._run(), findings=findings_mod.FindingSet(findings=[dict(f)])))
        explicit = report_mod.build_report(report_mod.ReportInputs(
            run=self._run(),
            findings=findings_mod.FindingSet(findings=[dict(f)]),
            delta=delta_mod.DeltaContext(),
            plan=plan_mod.PlanInputs(),
            tools=plan_mod.ToolAxis(),
            cost=cost_mod.CostInputs(),
        ))
        self.assertEqual(terse, explicit)
        # the "not measured" values the defaults stand for
        cov = terse["meta"]["coverage"]
        self.assertEqual(cov["tool_policy_mode"], "unknown")
        self.assertEqual(cov["scout_profiles_seen"], 0)
        self.assertIsNone(cov["delta"])
        self.assertIsNone(cov["resume"])
        self.assertIsNone(terse["meta"]["cost"]["tokens"])
        self.assertEqual(terse["meta"]["integrity"]["plans_seen"], 0)
        self.assertEqual(terse["groups"], [])

    def test_structs_are_frozen(self):
        import dataclasses
        run = self._run()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            run.target = "u"
        fs = findings_mod.FindingSet(findings=[])
        with self.assertRaises(dataclasses.FrozenInstanceError):
            fs.verdicts = {}

    def test_delta_context_active_needs_a_base(self):
        self.assertFalse(delta_mod.DeltaContext().active)
        self.assertFalse(delta_mod.DeltaContext(diff_hunks={"hunks": {}}).active)
        self.assertTrue(delta_mod.DeltaContext(diff_hunks={"base": "main", "hunks": {}}).active)

    def test_legacy_positional_signature_is_gone(self):
        with self.assertRaises(TypeError):
            report_mod.build_report([], [], "t", "high", DEFAULT_TIMESTAMP)

    def test_stages_compose_to_the_report(self):
        # build_report is resolve -> reconcile -> grade -> cost -> assemble;
        # running the stages by hand must give the same envelope.
        f = _make_finding(severity="HIGH")
        inp = report_mod.ReportInputs(
            run=self._run(), findings=findings_mod.FindingSet(findings=[dict(f)]),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]))
        whole = report_mod.build_report(inp)
        inp = report_mod.ReportInputs(
            run=self._run(), findings=findings_mod.FindingSet(findings=[dict(f)]),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}]))
        resolved = verdicts_mod.resolve_findings(inp.findings, inp.delta, inp.run)
        reconciled = plan_mod.reconcile(inp.plan, inp.tools, resolved)
        graded = grading_mod.grade_report(inp.run, resolved, reconciled)
        cost = cost_mod.cost_section(inp.cost, 0, resolved.verdict_stats["queued"])
        by_hand = report_mod.assemble(inp.run, resolved, reconciled, graded, cost)
        self.assertEqual(whole, by_hand)
        self.assertEqual(list(whole), ["schema_version", "meta", "summary", "groups",
                                       "findings", "discarded_claims", "cross_panel"])

class RunConfigLoaderTest(unittest.TestCase):
    """WS-0 S3: RunConfig.from_args resolves the CLI against groups.json."""

    def test_explicit_changes_beats_a_discovered_repo_mode(self):
        run = report_mod.RunConfig.from_args(
            _cli_args(changes=True), {"mode": "repo"}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.review_type, "changes")

    def test_discovered_mode_maps_to_review_type(self):
        run = report_mod.RunConfig.from_args(_cli_args(), {"mode": "files"}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.review_type, "changes")
        run = report_mod.RunConfig.from_args(_cli_args(), {"mode": "bogus"}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.review_type, "repo")
        run = report_mod.RunConfig.from_args(_cli_args(), {}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.review_type, "repo")

    def test_explicit_security_beats_the_file(self):
        run = report_mod.RunConfig.from_args(
            _cli_args(security="redteam"), {"security_mode": "standard"}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.security_mode, "redteam")

    def test_security_defaults_to_standard_even_when_the_file_says_null(self):
        run = report_mod.RunConfig.from_args(
            _cli_args(), {"security_mode": None}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.security_mode, "standard")
        run = report_mod.RunConfig.from_args(_cli_args(), {}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.security_mode, "standard")

    def test_flags_are_carried_verbatim(self):
        run = report_mod.RunConfig.from_args(
            _cli_args(target="t", fail_on="high", gate_unverified=True, max_verify=7,
                      gate_scope="all"), {}, DEFAULT_TIMESTAMP)
        self.assertEqual((run.target, run.fail_on, run.timestamp, run.gate_unverified,
                          run.max_verify, run.gate_scope),
                         ("t", "high", DEFAULT_TIMESTAMP, True, 7, "all"))

    def test_host_capabilities_defaults_to_empty_dict_when_omitted(self):
        # A caller that predates 5.1 surface 2 (or a code path that just
        # never read the artifact) must not have to know this parameter
        # exists -- omitting it reads as "nobody looked", same as {}.
        run = report_mod.RunConfig.from_args(_cli_args(), {}, DEFAULT_TIMESTAMP)
        self.assertEqual(run.host_capabilities, {})

    def test_host_capabilities_threads_through_verbatim(self):
        env = {"schema_version": 1, "host": "claude", "probed_at": "T",
              "capabilities": {hosts_mod.ARTIFACT_WRITE_GUARD:
                               {"state": hosts_mod.PROVEN, "by": "b", "detail": "d"}}}
        run = report_mod.RunConfig.from_args(_cli_args(), {}, DEFAULT_TIMESTAMP,
                                             host_capabilities=env)
        self.assertEqual(run.host_capabilities, env)

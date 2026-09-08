"""Tests for scripts.synthesize: main()/CLI wiring. Module-level behaviour lives in
tests/synth/test_<module>.py (WS-0 S4).
"""
import contextlib
import io
import os
import json
import tempfile
import unittest
from unittest import mock

import scripts.synthesize as syn
import scripts.run_tools as run_tools
import scripts.synth.findings as findings_mod
import scripts.synth.plan as plan_mod
import scripts.synth.verdicts as verdicts_mod
import scripts.synth.render as render_mod
import scripts.evidence as evidence_mod

import pytest

from tests.synth.helpers import _chdir, _agentic


@pytest.fixture(autouse=True)
def _isolate_cwd_from_stale_panopticon(tmp_path, monkeypatch):
    """Run every test in this module from an isolated cwd.

    Many tests call ``synthesize.main()`` without ``--run-dir``/``--groups``, so
    run_dir falls back to a cwd-relative ``.panopticon``. In a developer's real
    checkout that directory can hold a stale pre-5.1 flat ``tools-manifest.json``
    (no ``schema_version``), which synthesize's #17 guard correctly rejects with
    a loud ``sys.exit`` -- turning a stray local artifact into ~9 spurious test
    failures. Isolating the cwd makes the suite read only what each test writes
    (and stops the handful of relative-path tests from littering the repo root).
    Tests that manage their own cwd (``prev = os.getcwd()`` + restore) are
    unaffected -- they simply save/restore this tmp cwd; reference-data reads are
    ``__file__``-relative, so they don't depend on cwd.
    """
    monkeypatch.chdir(tmp_path)


class TestPipelineCitations(unittest.TestCase):
    def test_citations_enriched_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "findings-g1-security.json")
            with open(fp, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "SE-001",
                                "title": "sqli",
                                "severity": "HIGH",
                                "confidence": "CERTAIN",
                                "panel": "security",
                                "category": "injection",
                                "source": "tool:semgrep",
                                "location": {"file": "a.py", "line_start": 1},
                                "citations": {"cwe": ["CWE-89"]},
                            }
                        ]
                    },
                    fh,
                )
            out = os.path.join(d, "report.json")

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                syn.main(["--target", "src", "--out", out, fp])
            with open(out) as _fh:
                report = json.load(_fh)
            cites = report["findings"][0]["citations"]
            self.assertEqual(cites["cwe"][0]["name"][:3], "Imp")
            self.assertIn("A03:2021-Injection", cites["owasp"])

class TestToolsDirIntegration(unittest.TestCase):
    def test_tool_findings_merged_and_reinforced(self):
        with tempfile.TemporaryDirectory() as d:
            agent = os.path.join(d, "findings-g1-security.json")
            with open(agent, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "SE-001",
                                "title": "sqli",
                                "severity": "HIGH",
                                "confidence": "LIKELY",
                                "panel": "security",
                                "category": "sql-injection",
                                "source": "agent:security-reviewer",
                                "location": {"file": "app/db.py", "line_start": 42},
                                "cvss": {"score": 8.1, "vector": "x"},
                                "exploit_scenario": "y",
                            }
                        ]
                    },
                    fh,
                )
            td = os.path.join(d, "tools")
            os.makedirs(td)
            with open(os.path.join(td, "semgrep.sarif"), "w") as fh:
                json.dump(
                    {
                        "runs": [
                            {
                                "tool": {
                                    "driver": {
                                        "name": "semgrep",
                                        "rules": [
                                            {
                                                "id": "sql-injection",
                                                "properties": {"tags": ["CWE-89"]},
                                            }
                                        ],
                                    }
                                },
                                "results": [
                                    {
                                        "ruleId": "sql-injection",
                                        "level": "error",
                                        "message": {"text": "SQL injection"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "app/db.py"},
                                                    "region": {"startLine": 42},
                                                }
                                            }
                                        ],
                                    }
                                ],
                            }
                        ]
                    },
                    fh,
                )
            out = os.path.join(d, "report.json")

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                syn.main(["--target", "src", "--tools-dir", td, "--out", out, agent])
            with open(out) as _fh:
                report = json.load(_fh)
            secs = [f for f in report["findings"] if f["panel"] == "security"]
            self.assertEqual(len(secs), 1)  # agent+tool at same locus deduped to one
            self.assertTrue(secs[0].get("reinforced"))
            self.assertIn("cwe", secs[0].get("citations", {}))  # tool CWE-89 carried onto survivor

class TestHtmlOut(unittest.TestCase):
    def test_html_out_writes_file(self):
        with tempfile.TemporaryDirectory() as d:
            out_json = os.path.join(d, "report.json")
            out_html = os.path.join(d, "report.html")
            finding = os.path.join(d, "findings-x-code.json")
            with open(finding, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "CODE-001",
                                "title": "x",
                                "severity": "LOW",
                                "panel": "code",
                                "category": "style",
                                "location": {"file": "a.py", "line_start": 1},
                            }
                        ]
                    },
                    fh,
                )
            rc = syn.main(["--target", "test", "--out", out_json, "--html-out", out_html, finding])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out_html))
            with open(out_html, encoding="utf-8") as fh:
                self.assertIn("<!DOCTYPE html>", fh.read())

    def test_html_out_escapes_special_characters(self):
        with tempfile.TemporaryDirectory() as d:
            out_json = os.path.join(d, "report.json")
            out_html = os.path.join(d, "report.html")
            finding = os.path.join(d, "findings-x-code.json")
            with open(finding, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "CODE-001",
                                "title": "<script>alert('title')</script>",
                                "description": "<b>Description with <img src=x onerror=alert(1)></b>",
                                "severity": "LOW",
                                "panel": "code",
                                "category": "style",
                                "location": {"file": "<script>a.py</script>", "line_start": 1},
                            }
                        ]
                    },
                    fh,
                )
            rc = syn.main(["--target", "test", "--out", out_json, "--html-out", out_html, finding])
            self.assertEqual(rc, 0)
            with open(out_html, encoding="utf-8") as fh:
                content = fh.read()
            self.assertNotIn("<script>alert('title')</script>", content)
            self.assertNotIn("<img src=x onerror=alert(1)>", content)

    def test_compare_mode_writes_html(self):
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.json")
            b = os.path.join(d, "b.json")
            out = os.path.join(d, "compare.html")
            for path, findings in [
                (a, []),
                (
                    b,
                    [
                        {
                            "id": "CODE-001",
                            "title": "x",
                            "severity": "LOW",
                            "panel": "code",
                            "category": "style",
                            "location": {"file": "a.py", "line_start": 1},
                            "evidence": {
                                "status": "unverified",
                                "verified_by": None,
                                "reasoning": None,
                                "citation_quality": "none",
                            },
                        }
                    ],
                ),
            ]:
                with open(path, "w") as fh:
                    json.dump(
                        {
                            "meta": {
                                "target": "t",
                                "review_type": "repo",
                                "timestamp": "2026-08-01",
                                "version": "4.0.0",
                                "security_mode": "standard",
                            },
                            "summary": {
                                "overall_grade": "A",
                                "risk_level": "LOW",
                                "top_issues": [],
                                "gate": "PASS",
                                "gate_policy": "confirmed_only",
                                "stats": {
                                    "critical": 0,
                                    "high": 0,
                                    "medium": 0,
                                    "low": len(findings),
                                    "info": 0,
                                },
                                "evidence_stats": {},
                            },
                            "groups": [],
                            "findings": findings,
                            "cross_panel": {"integration_findings": []},
                        },
                        fh,
                    )
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
                json.dump(
                    {
                        "meta": {
                            "target": "t",
                            "review_type": "repo",
                            "timestamp": "2026-08-01",
                            "version": "4.0.0",
                            "security_mode": "standard",
                        },
                        "summary": {
                            "overall_grade": "A",
                            "risk_level": "LOW",
                            "top_issues": [],
                            "gate": "PASS",
                            "gate_policy": "confirmed_only",
                            "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                            "evidence_stats": {},
                        },
                        "groups": [],
                        "findings": [],
                        "cross_panel": {"integration_findings": []},
                    },
                    fh,
                )
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
                json.dump(
                    {
                        "meta": {
                            "target": "t",
                            "review_type": "repo",
                            "timestamp": "2026-08-01",
                            "version": "4.0.0",
                            "security_mode": "standard",
                        },
                        "summary": {
                            "overall_grade": "A",
                            "risk_level": "LOW",
                            "top_issues": [],
                            "gate": "PASS",
                            "gate_policy": "confirmed_only",
                            "stats": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                            "evidence_stats": {},
                        },
                        "groups": [],
                        "findings": [],
                        "cross_panel": {"integration_findings": []},
                    },
                    fh,
                )
            with open(invalid, "w") as fh:
                fh.write("not json")
            with unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as captured:
                rc = syn.main(["--compare", invalid, valid, "--html-out", out])
            self.assertNotEqual(rc, 0)
            self.assertIn("invalid JSON", captured.getvalue())

    def test_derive_html_path_is_case_insensitive(self):
        self.assertEqual(render_mod._derive_html_path("report.json"), "report.json.html")
        self.assertEqual(render_mod._derive_html_path("report.JSON"), "report.JSON.html")
        self.assertEqual(render_mod._derive_html_path("report.Json"), "report.Json.html")
        self.assertEqual(render_mod._derive_html_path("dir"), os.path.join("dir", "report.html"))

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
            self.assertEqual(
                queue["entries"][0]["queue_id"],
                evidence_mod.finding_fingerprint(queue["entries"][0]["finding"]),
            )

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
            qid = evidence_mod.finding_fingerprint(finding)
            # #1109: the verdict must echo the finding's CONTENT-derived id (what
            # load_findings assigns), not any agent-supplied id -- mirrors the
            # advisor echoing the driver-assigned id in production.
            expected_fid = evidence_mod.matrix_finding_id(findings_mod.normalize_finding(finding))
            with open(os.path.join(vd, "%s.json" % qid), "w") as fh:
                json.dump(
                    {"finding_id": expected_fid, "verdict": "CONFIRMED",
                     "reasoning": "verified"}, fh
                )
            out = os.path.join(d, "report.json")
            rc = syn.main(["--verdicts-dir", vd, "--fail-on", "high", "--out", out, fp])
            self.assertEqual(rc, 1)  # gate FAIL -> exit 1
            with open(out) as fh:
                report = json.load(fh)
            self.assertEqual(report["findings"][0]["evidence"]["status"], "advisor_confirmed")
            self.assertEqual(report["summary"]["gate"], "FAIL")

    def test_gate_unverified_flag(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = self._write_findings(d, [_agentic(sev="CRITICAL")])
            out = os.path.join(d, "report.json")
            rc = syn.main(["--gate-unverified", "--fail-on", "critical", "--out", out, fp])
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
                json.dump(
                    {
                        "version": "4.0.0",
                        "cut_by_max_verify": 0,
                        "entries": [{"queue_id": "000-STALE", "priority": 1, "finding": {}}],
                    },
                    fh,
                )
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
                fh.write(
                    '{"verdict": "CONFIRMED", ' '"reasoning": "the "eval" call is safe"}'
                )  # unescaped "
            out = os.path.join(d, "report.json")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = syn.main(["--verdicts-dir", vd, "--out", out, fp])
            self.assertEqual(rc, 0)
            with open(out) as fh:
                report = json.load(fh)
            self.assertEqual(report["meta"]["coverage"]["verdicts"]["unloadable"], 1)
            self.assertIn("un-loadable", err.getvalue())

    def test_two_distinct_corrupt_verdict_files_counted_once_each(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            finding = _agentic()
            fp = self._write_findings(d, [finding])
            vd = os.path.join(d, ".panopticon", "verdicts")
            os.makedirs(vd)
            with open(os.path.join(vd, "bad1.json"), "w") as fh:
                fh.write("not json {")
            with open(os.path.join(vd, "bad2.json"), "w") as fh:
                fh.write("also not } json")
            out = os.path.join(d, "report.json")
            syn.main(["--verdicts-dir", vd, "--out", out, fp])
            with open(out, encoding="utf-8") as fh:
                report = json.load(fh)
            self.assertEqual(report["meta"]["coverage"]["verdicts"]["unloadable"], 2)

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
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "A-1",
                                "title": "tangled branch",
                                "severity": "MEDIUM",
                                "confidence": "POSSIBLE",
                                "panel": "code",
                                "category": "logic",
                                "location": {"file": "svc.py", "line_start": 7},
                            }
                        ]
                    },
                    fh,
                )
            td = os.path.join(d, "tools")
            os.makedirs(td)
            with open(os.path.join(td, "bandit.sarif"), "w") as fh:
                json.dump(
                    {
                        "runs": [
                            {
                                "tool": {"driver": {"name": "bandit", "rules": [{"id": "B105"}]}},
                                "results": [
                                    {
                                        "ruleId": "B105",
                                        "level": "error",
                                        "message": {"text": "hardcoded password"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "app.py"},
                                                    "region": {"startLine": 10},
                                                }
                                            }
                                        ],
                                    },
                                    {
                                        "ruleId": "B105",
                                        "level": "error",
                                        "message": {"text": "hardcoded password"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "app.py"},
                                                    "region": {"startLine": 20},
                                                }
                                            }
                                        ],
                                    },
                                ],
                            }
                        ]
                    },
                    fh,
                )

            queue_out = os.path.join(d, "unused-report.json")
            rc1 = syn.main(["--emit-verify-queue", "--tools-dir", td, "--out", queue_out, agent])
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
            tool_entries = [
                e
                for e in queue["entries"]
                if str(e["finding"].get("source", "")).startswith("tool:")
            ]
            self.assertEqual(len(tool_entries), 1)
            tool_qid = tool_entries[0]["queue_id"]
            vd = os.path.join(d, "verdicts")
            os.makedirs(vd)
            with open(os.path.join(vd, "%s.json" % tool_qid), "w") as fh:
                json.dump(
                    {
                        "run_id": queue["run_id"],
                        "finding_id": tool_entries[0]["finding"].get("id"),
                        "verdict": "CONFIRMED",
                        "reasoning": "Advisor prose, deliberately nothing "
                        "like the rule id B105.",
                    },
                    fh,
                )

            report_out = os.path.join(d, "report.json")
            rc2 = syn.main(["--tools-dir", td, "--verdicts-dir", vd, "--out", report_out, agent])
            self.assertEqual(rc2, 0)
            with open(report_out) as fh:
                report = json.load(fh)
            emitted = report["findings"] + report["discarded_claims"]
            tool_out = [f for f in emitted if str(f.get("source", "")).startswith("tool:")]
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
            # evidence.build_verify_queue and report_mod.build_report).
            self.assertEqual(pass1_qids, pass2_fps)

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
                syn.main(
                    ["--target", ".", "--tools-dir", tools, "--out", os.path.join(d, "r.json"), fp]
                )
        self.assertNotIn("appears un-ingested", err.getvalue())

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
                rc = syn.main(
                    [
                        "--target",
                        "t",
                        "--fail-on",
                        "high",
                        "--out",
                        os.path.join(pan, "report.json"),
                        findings,
                    ]
                )
            finally:
                os.chdir(cwd)
            self.assertEqual(rc, 2)  # INCONCLUSIVE -> exit 2
            with open(os.path.join(pan, "report.json")) as fh:
                rep = _json.load(fh)
            self.assertEqual(
                rep["meta"]["coverage"]["divergence"]["tools"], {"semgrep": "requested_absent"}
            )

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

class TestScoutToolDisclosure(unittest.TestCase):
    """#471 remainder: a scout returning tools:[] is a silent decline of the
    tool layer -- must be disclosed on stderr and readable from the artifact
    (scout_profiles_seen > 0 with scout_requested [])."""

    def test_scout_declining_tools_is_disclosed(self):

        with tempfile.TemporaryDirectory() as d, _chdir(d):
            os.makedirs(".panopticon")
            with open(os.path.join(".panopticon", "scout-g1.json"), "w") as fh:
                json.dump({"group": "g1", "tools": [], "panels": ["code"]}, fh)
            fp = os.path.join(d, "findings-g1-code.json")
            with open(fp, "w") as fh:
                json.dump({"findings": []}, fh)
            out = os.path.join(d, "r.json")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                rc = syn.main(["--target", "src", "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertIn("requested NO tools", err.getvalue())
            with open(out) as fh:
                report = json.load(fh)
            cov = report["meta"]["coverage"]
            self.assertEqual(cov["scout_profiles_seen"], 1)
            self.assertEqual(cov["scout_requested"], [])

    def test_no_scout_profiles_no_disclosure(self):

        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = os.path.join(d, "findings-g1-code.json")
            with open(fp, "w") as fh:
                json.dump({"findings": []}, fh)
            out = os.path.join(d, "r.json")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                rc = syn.main(["--target", "src", "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertNotIn("requested NO tools", err.getvalue())
            with open(out) as fh:
                report = json.load(fh)
            self.assertEqual(report["meta"]["coverage"]["scout_profiles_seen"], 0)

class TestUnusableScannerCertification(unittest.TestCase):
    """#1512 / Codex BR-02, end to end on real artifacts.

    The acceptance asks for a REAL raw output file and a REAL manifest rather
    than a hand-built build_report input, because the defect lived precisely in
    the gap between what the runner wrote and what ingestion could read -- a
    pre-built input closes that gap by construction and cannot fail."""

    def _run(self, d, payload):
        td = os.path.join(d, "tools")
        os.makedirs(td)
        with open(os.path.join(td, "bandit.sarif"), "wb") as fh:
            fh.write(payload)
        # The real writer's own manifest: bandit selected AND produced, nothing
        # missing -- which is the truth about bytes, and a lie about coverage.
        run_tools.write_manifest(os.path.join(d, "tools-manifest.json"),
                                 ["bandit"], [os.path.join(td, "bandit.sarif")],
                                 run_id="rid-1")
        fp = os.path.join(d, "findings-g1-code.json")
        with open(fp, "w") as fh:
            json.dump({"findings": []}, fh)
        out = os.path.join(d, "r.json")
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = syn.main(["--target", "src", "--run-dir", d, "--tools-dir", td,
                           "--fail-on", "high", "--out", out, fp])
        with open(out, encoding="utf-8") as fh:
            return rc, json.load(fh)

    def test_unparseable_scanner_output_cannot_certify(self):
        with tempfile.TemporaryDirectory() as d:
            rc, report = self._run(d, b"not JSON")
        cov = report["meta"]["coverage"]
        self.assertEqual(cov["adapters"]["bandit"]["status"], "failed")
        self.assertEqual(cov["tools_ran"], [])
        self.assertEqual(cov["divergence"]["tools"], {"bandit": "produced_unusable"})
        self.assertFalse(report["summary"]["coverage_certified"])
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")
        self.assertEqual(rc, 2)

    def test_valid_zero_finding_output_still_certifies(self):
        # `empty` is completed coverage, not lost coverage -- a scanner that ran
        # and found nothing is the outcome the whole pipeline hopes for.
        sarif = json.dumps({"runs": [{"tool": {"driver": {"name": "bandit",
                                                          "rules": []}},
                                      "results": []}]}).encode("utf-8")
        with tempfile.TemporaryDirectory() as d:
            rc, report = self._run(d, sarif)
        cov = report["meta"]["coverage"]
        self.assertEqual(cov["adapters"]["bandit"]["status"], "empty")
        self.assertEqual(cov["tools_ran"], ["bandit"])
        self.assertEqual(cov["divergence"]["tools"], {})
        self.assertTrue(report["summary"]["coverage_certified"])
        self.assertEqual(rc, 0)


class TestRunDirArtifactResolution(unittest.TestCase):
    """#17/#16: under 5.1 per-run folders synthesize must resolve run artifacts
    (scout-*, tools-manifest, ...) from dirname(--groups), NOT flat .panopticon.
    Reading them flat zeroed scout coverage (#16) and certified tool coverage
    against a stale/foreign manifest (#17)."""

    def _layout(self, d, manifest=None):
        run_dir = os.path.join(d, ".panopticon", "runs", "tag")
        os.makedirs(run_dir)
        with open(os.path.join(run_dir, "groups.json"), "w") as fh:
            json.dump({"groups": [{"name": "g1", "files": []},
                                   {"name": "g2", "files": []}]}, fh)
        for g in ("g1", "g2"):
            with open(os.path.join(run_dir, "scout-%s.json" % g), "w") as fh:
                json.dump({"group": g, "tools": ["semgrep"], "panels": ["code"]}, fh)
        tm = manifest if manifest is not None else {
            "schema_version": 1, "run_id": "rid-1", "selected": ["semgrep"],
            "produced": ["semgrep"], "missing": [], "excluded_scope": []}
        with open(os.path.join(run_dir, "tools-manifest.json"), "w") as fh:
            json.dump(tm, fh)
        fp = os.path.join(d, "findings-g1-code.json")
        with open(fp, "w") as fh:
            json.dump({"findings": []}, fh)
        return os.path.join(run_dir, "groups.json"), fp

    def _run(self, groups, fp, out):
        return syn.main(["--target", "src", "--groups", groups,
                         "--run-id", "rid-1", "--out", out, fp])

    def test_scouts_resolved_from_run_dir_not_flat(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            groups, fp = self._layout(d)
            # a STALE flat manifest (pre-5.1, no schema_version) the OLD code read;
            # the fix must ignore it — if it read flat here the schema assertion
            # below would fire and this test would fail loudly.
            os.makedirs(".panopticon", exist_ok=True)
            with open(os.path.join(".panopticon", "tools-manifest.json"), "w") as fh:
                json.dump({"selected": ["bandit"], "produced": ["bandit"]}, fh)
            out = os.path.join(d, "r.json")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = self._run(groups, fp, out)
            self.assertEqual(rc, 0)
            cov = json.load(open(out))["meta"]["coverage"]
            self.assertEqual(cov["scout_profiles_seen"], 2)   # old flat glob => 0
            self.assertIn("semgrep", cov["scout_requested"])

    def test_driver_cost_ledger_resolved_from_run_dir_not_flat(self):
        # #21: the driver cost ledger (dispatch-plan-driver.json + verdicts/) must
        # resolve under run_dir like every other 5.1 artifact. Read flat, the plan
        # is absent -> driver_cost_counts returns None -> cost_dispatches falls back
        # to the empty 4.x shape, silently falsifying meta.cost on EVERY 5.1 run.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            run_dir = os.path.join(d, ".panopticon", "runs", "tag")
            os.makedirs(os.path.join(run_dir, "verdicts"))
            with open(os.path.join(run_dir, "groups.json"), "w") as fh:
                json.dump({"groups": [{"name": "g1", "files": []},
                                      {"name": "g2", "files": []}]}, fh)
            for g in ("g1", "g2"):
                with open(os.path.join(run_dir, "scout-%s.json" % g), "w") as fh:
                    json.dump({"group": g, "panels": ["code"]}, fh)
            with open(os.path.join(run_dir, "tools-manifest.json"), "w") as fh:
                json.dump({"schema_version": 1, "run_id": "rid-1",
                           "selected": [], "produced": [], "missing": []}, fh)
            fcod = os.path.join(d, "findings-g1-COD.json")
            fsec = os.path.join(d, "findings-g2-SEC.json")
            for f in (fcod, fsec):
                with open(f, "w") as fh:
                    json.dump({"findings": []}, fh)
            with open(os.path.join(run_dir, "dispatch-plan-driver.json"), "w") as fh:
                json.dump([{"group": "g1", "domain": "COD", "out_file": fcod},
                           {"group": "g2", "domain": "SEC", "out_file": fsec}], fh)
            with open(os.path.join(run_dir, "verdicts", "verdicts-g1-COD.json"), "w") as fh:
                json.dump({"verdicts": []}, fh)   # one primary bundle
            # a STALE flat plan the OLD code would have read -- the fix must ignore it
            os.makedirs(".panopticon", exist_ok=True)
            with open(os.path.join(".panopticon", "dispatch-plan-driver.json"), "w") as fh:
                json.dump([{"group": "STALE", "domain": "X", "out_file": "x"}], fh)
            out = os.path.join(d, "r.json")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = syn.main(["--target", "src",
                               "--groups", os.path.join(run_dir, "groups.json"),
                               "--run-id", "rid-1", "--out", out, fcod, fsec])
            self.assertEqual(rc, 0)
            rows = json.load(open(out))["meta"]["cost"]["dispatches"]
            by_role = {r["role"]: r["count"] for r in rows}
            # driver-path shape from the run_dir plan -- NOT the legacy None fallback
            self.assertEqual(by_role.get("domain_panel"), 2)     # 2 plan cells
            self.assertEqual(by_role.get("domain_advisor"), 1)   # 1 primary verify bundle
            self.assertNotIn("advisor", by_role)                 # legacy shape would have this

    def test_foreign_run_id_manifest_is_a_loud_error(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            groups, fp = self._layout(d, manifest={
                "schema_version": 1, "run_id": "SOME-OTHER-RUN",
                "selected": [], "produced": [], "missing": []})
            out = os.path.join(d, "r.json")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self._run(groups, fp, out)

    def test_pre_5_1_schemaless_manifest_in_run_dir_is_a_loud_error(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            groups, fp = self._layout(d, manifest={
                "selected": ["bandit"], "produced": ["bandit"]})   # no schema_version
            out = os.path.join(d, "r.json")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self._run(groups, fp, out)

    def test_run_id_without_run_dir_warns_loudly(self):
        # #17 fail-open guard: a 5.1 run (--run-id) that falls back to flat
        # .panopticon must say so loudly rather than silently read stale artifacts.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            os.makedirs(".panopticon")
            fp = os.path.join(d, "findings-g1-code.json")
            with open(fp, "w") as fh:
                json.dump({"findings": []}, fh)
            out = os.path.join(d, "r.json")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                rc = syn.main(["--target", "src", "--run-id", "rid-1", "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertIn("no run directory resolved", err.getvalue())

class MainLoaderOrderTest(unittest.TestCase):
    """WS-0 S3 fix #1: main() must run FindingSet.prepare()/the
    --emit-verify-queue branch BEFORE plan_mod.load_verify_queue() (and
    FindingSet.load()'s verdicts read) -- the old main() prepared findings,
    branched on --emit-verify-queue (which can DELETE a stale
    verify-queue.json left by a PREVIOUS run), and only THEN read the queue
    file and loaded verdicts. Reading the queue before the branch runs would
    let a stale queue leak into verdict_run_id/resume/invalid_verify_queue on
    the "nothing to queue this run" path even though emit_verify_queue just
    removed the file."""

    def test_verify_queue_is_read_after_the_emit_branch_runs(self):
        calls = []
        real_emit = verdicts_mod.emit_verify_queue
        real_load_queue = plan_mod.load_verify_queue

        def spy_emit(findings, run_dir, max_verify):
            calls.append("emit")
            return real_emit(findings, run_dir, max_verify)

        def spy_load_queue(run_dir):
            calls.append("load_queue")
            return real_load_queue(run_dir)

        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = os.path.join(d, "findings-g1-code.json")
            with open(fp, "w") as fh:
                json.dump({"findings": []}, fh)   # nothing to queue this run
            panopticon_dir = os.path.join(d, ".panopticon")
            os.makedirs(panopticon_dir)
            qpath = os.path.join(panopticon_dir, "verify-queue.json")
            with open(qpath, "w") as fh:
                # A leftover queue from a PREVIOUS run -- a real run_id and
                # entries, so a stale READ (not just a missed delete) would be
                # observable, not just a file-existence check.
                json.dump({"run_id": "stale-run", "entries": [{"queue_id": "STALE"}]}, fh)
            out = os.path.join(d, "report.json")
            with mock.patch.object(verdicts_mod, "emit_verify_queue", side_effect=spy_emit), \
                    mock.patch.object(plan_mod, "load_verify_queue", side_effect=spy_load_queue):
                rc = syn.main(["--emit-verify-queue", "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))
            # The old main()'s order: emit_verify_queue's stale-queue deletion
            # runs BEFORE anything reads the queue file.
            self.assertEqual(calls, ["emit", "load_queue"])
            # And the deletion is real: a fresh read after main() returns sees
            # no queue at all, exactly like a run with no leftover file.
            self.assertEqual(plan_mod.load_verify_queue(panopticon_dir), (None, None))

"""Tests for scripts.synthesize: main()/CLI wiring. Module-level behaviour lives in
tests/synth/test_<module>.py (WS-0 S4).
"""
import ast
import contextlib
import datetime as datetime_mod
import html
import inspect
import io
import os
import json
import tempfile
from pathlib import Path
import unittest
from unittest import mock

import scripts.run_tools as run_tools_mod
import scripts.synthesize as syn
import scripts.tools_manifest as tools_manifest
import scripts.synth.findings as findings_mod
import scripts.phases.coverage as coverage_phase
import scripts.synth.coverage_io as coverage_io
import scripts.synth.integrity as integrity_mod
import scripts.synth.verdicts as verdicts_mod
import scripts.synth.render as render_mod
import scripts.synth.report as report_mod
import scripts.evidence as evidence_mod

import pytest

from tests._test_helpers import only
from tests.synth.helpers import (
    _chdir, _agentic,
    _isolate_cwd_from_stale_panopticon as _isolate_cwd_from_stale_panopticon,
)


class _FrozenDateTime(datetime_mod.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 10, 8, 17, 0, 0, tzinfo=tz)


class TestPipelineCitations(unittest.TestCase):
    def test_citations_enriched_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "findings-g1-SEC.json")
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
            agent = os.path.join(d, "findings-g1-SEC.json")
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
    def _assert_escaped_fields(self, content, fields):
        for raw in fields:
            self.assertIn(html.escape(raw), content)
            self.assertNotIn(raw, content)

    def test_html_out_writes_file(self):
        with tempfile.TemporaryDirectory() as d:
            out_json = os.path.join(d, "report.json")
            out_html = os.path.join(d, "report.html")
            finding = os.path.join(d, "findings-x-COD.json")
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
            finding = os.path.join(d, "findings-x-COD.json")
            title = "<script>alert('title')</script>"
            description = "<b>Description with <img src=x onerror=alert(1)></b>"
            location_file = "<script>a.py</script>"
            with open(finding, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "CODE-001",
                                "title": title,
                                "description": description,
                                "severity": "LOW",
                                "panel": "code",
                                "category": "style",
                                "location": {"file": location_file, "line_start": 1},
                            }
                        ]
                    },
                    fh,
                )
            rc = syn.main(["--target", "test", "--out", out_json, "--html-out", out_html, finding])
            self.assertEqual(rc, 0)
            with open(out_html, encoding="utf-8") as fh:
                content = fh.read()
            fields = (title, description, location_file)
            self._assert_escaped_fields(content, fields)
            # An empty renderer used to pass the old absence-only assertions.
            with self.assertRaises(AssertionError):
                self._assert_escaped_fields("", fields)

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
            with mock.patch("sys.stderr", new_callable=io.StringIO) as captured:
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
            with mock.patch("sys.stderr", new_callable=io.StringIO) as captured:
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
        fp = os.path.join(d, ".panopticon", "findings-g1-SEC.json")
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
            # #2101: carries a real OCRDb code so the verdict below can carry a
            # VALID differing one -- the shape that used to be applied.
            finding = _agentic(code="SEC-A1A", domain="SEC")
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
                     "code": "SEC-A2A",       # valid, and not the finding's
                     "reasoning": "verified"}, fh
                )
            out = os.path.join(d, "report.json")
            rc = syn.main(["--verdicts-dir", vd, "--fail-on", "high", "--out", out, fp])
            self.assertEqual(rc, 1)  # gate FAIL -> exit 1
            with open(out) as fh:
                report = json.load(fh)
            self.assertEqual(report["findings"][0]["evidence"]["status"], "advisor_confirmed")
            self.assertEqual(report["summary"]["gate"], "FAIL")
            # #2101 through the REAL pipeline: the advisor's differing OCRDb code
            # is recorded and never applied. The contradiction was a COMPOSITION
            # gap -- evidence.apply_verdict then apply_verdict_quality, each
            # correct alone -- so it is pinned here, where synthesize composes
            # them itself, and not only by a hand-composed pair.
            published = report["findings"][0]
            self.assertEqual(published["code"], "SEC-A1A")        # the panel's
            self.assertEqual(published["provenance"]["advisor_code"], "SEC-A2A")
            self.assertNotIn("code_corrected_by", published)
            self.assertNotIn("code_corrections", report["meta"]["coverage"]["ocrdb"])

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
            agent = os.path.join(d, "findings-g1-COD.json")
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
            fp = os.path.join(d, "findings-g1-COD.json")
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
            fp = os.path.join(d, "findings-g1-COD.json")
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
            findings = os.path.join(pan, "findings-g1-COD.json")
            with open(findings, "w") as fh:
                _json.dump({"findings": []}, fh)
            with _chdir(d):
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
            findings = os.path.join(pan, "findings-a-COD.json")
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
            fp = os.path.join(d, "findings-g1-COD.json")
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
            fp = os.path.join(d, "findings-g1-COD.json")
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
        tools_manifest.write_manifest(os.path.join(d, "tools-manifest.json"),
                                      ["bandit"], [os.path.join(td, "bandit.sarif")],
                                      run_id="rid-1")
        fp = os.path.join(d, "findings-g1-COD.json")
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


class TestUnusableScannerCertificationAfterAnEarlierScan(TestUnusableScannerCertification):
    """#2873: the pair above, run again after an earlier scan left its ledgers
    full. `run_tools()` empties them when a run starts and nothing empties them
    when it ends, so under xdist the pair read another test's network posture on
    some orderings only (`'pip-audit': 'network_unavailable'` in its divergence).
    Here every ledger `run_tools()` empties -- the `.clear()` calls written in
    its own body, so one more written there is found, though one emptied through
    a helper would not be -- is filled first, in the class setup, which runs
    before each test's fixtures wherever the test lands. The pair passes, and
    the ledgers read empty, only if every test starts as a fresh scan does
    (`_fresh_run_ledgers`, tests/conftest.py)."""

    @staticmethod
    def _ledgers():
        ledgers = []
        for node in ast.walk(ast.parse(inspect.getsource(run_tools_mod.run_tools))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "clear":
                ledger = run_tools_mod
                for name in ast.unparse(node.func.value).split("."):
                    ledger = getattr(ledger, name)
                ledgers.append(ledger)
        return ledgers

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        for ledger in cls._ledgers():    # what an earlier test's scan leaves, for a tool this pair never runs
            if isinstance(ledger, set):
                ledger.add("pip-audit")
            else:
                ledger["pip-audit"] = "left by an earlier scan"
        # and the posture #2873's pair inherited: that scan's online egress was refused
        tools_manifest._NETWORK_POSTURE["pip-audit"] = run_tools_mod.egress.UNAVAILABLE

    @classmethod
    def tearDownClass(cls):
        for ledger in cls._ledgers():
            ledger.clear()
        super().tearDownClass()

    def test_every_ledger_a_scan_empties_is_empty_when_a_test_starts(self):
        ledgers = self._ledgers()
        self.assertEqual(7, len(ledgers))
        self.assertEqual([], [ledger for ledger in ledgers if ledger])


class TestAScanLeavesTheLedgersToTheNextClassSetup(unittest.TestCase):
    """#2873, the fixture's other half (round 1, B1): what a test's scan leaves
    in the ledgers is emptied when the test ENDS, not only when the next one
    starts, because a class setup runs between the two and may read them
    (`TestSchemaParity.setUpClass` writes a manifest that takes five of them by
    default). This class's one test leaves every ledger full; its class
    teardown runs right after that test's fixtures tear down, wherever xdist
    places it, and requires them empty."""

    def test_a_scan_leaves_every_ledger_full(self):
        for ledger in TestUnusableScannerCertificationAfterAnEarlierScan._ledgers():
            if isinstance(ledger, set):
                ledger.add("pip-audit")
            else:
                ledger["pip-audit"] = "left by this test's scan"

    @classmethod
    def tearDownClass(cls):
        ledgers = TestUnusableScannerCertificationAfterAnEarlierScan._ledgers()
        full = [ledger for ledger in ledgers if ledger]
        for ledger in ledgers:
            ledger.clear()
        super().tearDownClass()
        if full:
            raise AssertionError("left full after the test that filled them: %r" % (full,))


class TestAScanStartsWithEveryLedgerEmpty(unittest.TestCase):
    """#2873 (round 1, F1): `run_tools()`'s own start-of-run reset, as behaviour.
    The harness now empties the ledgers around every test, so a reset that stops
    running while its `.clear()` stays in the source would otherwise go unseen:
    a run over no tools must leave every ledger empty."""

    def test_a_run_over_no_tools_empties_every_ledger(self):
        ledgers = TestUnusableScannerCertificationAfterAnEarlierScan._ledgers()
        for ledger in ledgers:
            if isinstance(ledger, set):
                ledger.add("pip-audit")
            else:
                ledger["pip-audit"] = "left by an earlier scan"
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stderr(io.StringIO()):
            run_tools_mod.run_tools(d, [], os.path.join(d, "tools"), runner=lambda *args, **kwargs: None)
        self.assertEqual([], [ledger for ledger in ledgers if ledger])


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
        fp = os.path.join(d, "findings-g1-COD.json")
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
                self.assertEqual(self._run(groups, fp, out), 3)
            self.assertFalse(os.path.exists(out))

    def test_pre_5_1_schemaless_manifest_in_run_dir_is_a_loud_error(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            groups, fp = self._layout(d, manifest={
                "selected": ["bandit"], "produced": ["bandit"]})   # no schema_version
            out = os.path.join(d, "r.json")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(self._run(groups, fp, out), 3)
            self.assertFalse(os.path.exists(out))

    def test_run_id_without_run_dir_warns_loudly(self):
        # #17 fail-open guard: a 5.1 run (--run-id) that falls back to flat
        # .panopticon must say so loudly rather than silently read stale artifacts.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            os.makedirs(".panopticon")
            fp = os.path.join(d, "findings-g1-COD.json")
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
    --emit-verify-queue branch BEFORE integrity_mod.load_verify_queue() (and
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
        real_load_queue = integrity_mod.load_verify_queue

        def spy_emit(findings, run_dir, max_verify):
            calls.append("emit")
            return real_emit(findings, run_dir, max_verify)

        def spy_load_queue(run_dir):
            calls.append("load_queue")
            return real_load_queue(run_dir)

        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = os.path.join(d, "findings-g1-COD.json")
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
                    mock.patch.object(integrity_mod, "load_verify_queue",
                                      side_effect=spy_load_queue):
                rc = syn.main(["--emit-verify-queue", "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))
            # The old main()'s order: emit_verify_queue's stale-queue deletion
            # runs BEFORE anything reads the queue file.
            self.assertEqual(calls, ["emit", "load_queue"])
            # And the deletion is real: a fresh read after main() returns sees
            # no queue at all, exactly like a run with no leftover file.
            self.assertEqual(integrity_mod.load_verify_queue(panopticon_dir),
                             (None, None))


class TestTheCompletionPathValidatesWhatItWrote(unittest.TestCase):
    """#1639 P15 ruling 2: the artifacts AS WRITTEN are validated, and an
    invalid one is a terminal status of its own.

    Three facts a consumer must be able to tell apart, and each now has its own
    channel: terminal completion (this exit status), artifact validity (this
    exit status too, distinctly -- code 4, "artifact invalid"), and coverage
    certification (`summary.gate` / `summary.coverage_certified`, codes 1 and
    2, both of them VALID reports about a coverage question). Validating the
    in-memory report only would miss the two artifacts a consumer actually
    reads: the HYDRATED union of the split parts, and the X0X sibling.
    """

    def _fixture(self, d):
        fp = os.path.join(d, "findings-g1-SEC.json")
        with open(fp, "w") as fh:
            json.dump({"findings": [_agentic("SE-001")]}, fh)
        return fp, os.path.join(d, "report.json")

    def _run(self, args):
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = syn.main(args)
        return rc, buf.getvalue(), err.getvalue()

    def test_a_valid_run_is_unaffected(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp, out = self._fixture(d)
            rc, stdout, stderr = self._run(["--target", "src", "--out", out, fp])
        self.assertEqual(rc, 0)
        self.assertNotIn("artifact invalid", stderr)
        self.assertIn("Grade:", stdout)

    def test_x0x_serialization_stays_ascii_escaped_and_multiline(self):
        import scripts.x0x_report as x0x_report

        x0x = {
            "schema_version": 1,
            "generated_by": {"panopticon_version": "test", "run_id": "run-1"},
            "ocrdb_version": "test",
            "candidates": [{
                "domain": "SEC",
                "summary": "caf\u00e9",
                "severity": "LOW",
                "occurrences": [{"file": "src/example.py"}],
            }],
        }
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp, out = self._fixture(d)
            with mock.patch.object(x0x_report, "build_emission",
                                   return_value=(x0x, None)):
                rc, _stdout, stderr = self._run(["--target", "src", "--out", out, fp])
            raw = Path(out.replace(".json", "-x0x.json")).read_text(encoding="utf-8")
        self.assertEqual(rc, 0, stderr)
        self.assertGreater(len(raw.splitlines()), 1)
        self.assertIn("\\u00e9", raw)
        self.assertNotIn("\u00e9", raw)
        self.assertEqual(json.loads(raw), x0x)

    def test_bidi_path_controls_are_inert_before_x0x_validation(self):
        # #2712 review round 2 / #2118 items 1-2: every bidi control that can
        # occur in a repository path reaches the finding normalizer, is
        # preserved as an inert spelling in both artifacts, and cannot make
        # synthesize exit ARTIFACT_INVALID.
        points = (
            0x061C,
            0x200E, 0x200F,
            0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
            0x2066, 0x2067, 0x2068, 0x2069,
        )
        findings = [
            _agentic(
                "SE-%03d" % (index + 1), sev="LOW", code="SEC-X0X",
                domain="SEC", title="catalog gap %d" % index,
                short_title="catalog gap %d" % index,
                location={"file": "src/x%sy.py" % chr(point), "line_start": 1},
            )
            for index, point in enumerate(points)
        ]
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = os.path.join(d, "findings-g1-SEC.json")
            with open(fp, "w", encoding="utf-8") as fh:
                json.dump({"findings": findings}, fh, ensure_ascii=False)
            out = os.path.join(d, "report.json")
            rc, _stdout, stderr = self._run(
                ["--target", "src", "--run-id", "run-1", "--out", out, fp])
            x0x_path = out.replace(".json", "-x0x.json")
            with open(x0x_path, encoding="utf-8") as fh:
                x0x = json.load(fh)

            self.assertEqual(syn.validate_artifacts(out, x0x_path), [])

        self.assertEqual(rc, 0, stderr)
        self.assertEqual(
            {occurrence["file"]
             for candidate in x0x["candidates"]
             for occurrence in candidate["occurrences"]},
            {"src/x\\u%04xy.py" % point for point in points},
        )

    def test_an_invalid_part_is_caught_through_the_hydrated_union(self):
        # The MAIN report stays valid; the defect is in a `_partN.json`, which
        # is exactly the artifact a consumer hydrates and validates and which
        # nothing on this path had ever read back.
        real_write = render_mod.write_report

        def _corrupting_write(report, out_path, max_bytes=None):
            paths = real_write(report, out_path)
            part = out_path.replace(".json", "_part2.json")
            with open(part, "w", encoding="utf-8") as fh:
                json.dump({"findings": [{"id": "SE-002", "title": "t",
                                         "severity": "SEVERE",   # not a severity
                                         "confidence": "LIKELY", "panel": "security",
                                         "category": "injection",
                                         "evidence": {"status": "unverified"}}]}, fh)
            report["meta"]["parts"] = [os.path.basename(part)]
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(report, fh)
            return paths

        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp, out = self._fixture(d)
            with mock.patch.object(render_mod, "write_report",
                                   side_effect=_corrupting_write):
                rc, stdout, stderr = self._run(["--target", "src", "--out", out, fp])
        self.assertEqual(rc, 4)
        self.assertIn("artifact invalid: 1 schema errors", stderr)
        self.assertIn("SEVERE", stderr)
        # The gate/certification story is untouched: a different question,
        # separately answered, still printed.
        self.assertIn("Grade:", stdout)
        self.assertIn("Gate:", stdout)

    def test_an_invalid_x0x_artifact_fails_the_run(self):
        import scripts.x0x_report as x0x_report

        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp, out = self._fixture(d)
            with mock.patch.object(
                    x0x_report, "build_emission",
                    return_value=({"candidates": []}, None)):   # no schema_version
                rc, stdout, stderr = self._run(["--target", "src", "--out", out, fp])
        self.assertEqual(rc, 4)
        self.assertIn("artifact invalid:", stderr)
        self.assertIn("report-x0x.json", stderr)
        self.assertIn("Grade:", stdout)

    def test_a_locus_free_gap_is_logged_while_the_rest_of_x0x_is_emitted(self):
        # #2713 revised owner ruling: discard only the unrepresentable finding,
        # log it separately, and leave the candidate artifact byte-identical to
        # the same run without that finding. Re-running is deterministic, and a
        # later clean run removes the stale failure log.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = os.path.join(d, "findings-g1-SEC.json")
            located = _agentic(
                "SE-076", sev="LOW", code="SEC-X0X", domain="SEC",
                title="located catalog gap", short_title="located gap",
                location={"file": "src/app.py", "line_start": 7},
            )
            locus_free = _agentic(
                "SE-077", sev="LOW", code="SEC-X0X", domain="SEC",
                title="repo-wide dependency gap", short_title="dependency gap",
                location={},
            )
            with open(fp, "w", encoding="utf-8") as fh:
                json.dump({"findings": [located, locus_free]}, fh)
            out = os.path.join(d, "report.json")
            x0x_path = out.replace(".json", "-x0x.json")
            failure_path = x0x_path.replace(".json", "-failures.json")

            with mock.patch.object(datetime_mod, "datetime", _FrozenDateTime):
                rc, stdout, stderr = self._run(
                    ["--target", "src", "--run-id", "run-1", "--out", out, fp])
            x0x_bytes = Path(x0x_path).read_bytes()
            failure_bytes = Path(failure_path).read_bytes()

            self.assertEqual(rc, 0, stderr)
            self.assertEqual(syn.validate_artifacts(out, x0x_path), [])
            self.assertTrue(os.path.isfile(out + ".html"))
            self.assertIn(
                "repo-wide dependency gap",
                Path(out + ".html").read_text(encoding="utf-8"),
            )
            with open(out, encoding="utf-8") as fh:
                report = json.load(fh)
            x0x = json.loads(x0x_bytes)
            failure_log = json.loads(failure_bytes)

            self.assertEqual(len(report["findings"]), 2)
            candidate = only(x0x["candidates"], "candidate")
            self.assertEqual(
                only(candidate["occurrences"], "occurrence")["file"], "src/app.py")
            failure = only(
                failure_log["discarded_findings"], "discarded finding")
            self.assertEqual(failure["reason"], "no file locus")
            self.assertIn("repo-wide dependency gap", failure["diagnostic"])
            self.assertIn("discarded 1 locus-free", stderr)
            self.assertIn(failure_path, stderr)
            self.assertIn("X0X artifact:", stdout)
            self.assertNotIn("artifact invalid", stderr)

            # A resume/replay over unchanged inputs reproduces both artifacts.
            with mock.patch.object(datetime_mod, "datetime", _FrozenDateTime):
                rc, _stdout, stderr = self._run(
                    ["--target", "src", "--run-id", "run-1", "--out", out, fp])
            self.assertEqual(rc, 0, stderr)
            self.assertEqual(Path(x0x_path).read_bytes(), x0x_bytes)
            self.assertEqual(Path(failure_path).read_bytes(), failure_bytes)

            # Removing only the offending finding cannot perturb X0X bytes and
            # must remove the now-stale sidecar.
            with open(fp, "w", encoding="utf-8") as fh:
                json.dump({"findings": [located]}, fh)
            with mock.patch.object(datetime_mod, "datetime", _FrozenDateTime):
                rc, _stdout, stderr = self._run(
                    ["--target", "src", "--run-id", "run-1", "--out", out, fp])
            self.assertEqual(rc, 0, stderr)
            self.assertEqual(Path(x0x_path).read_bytes(), x0x_bytes)
            self.assertFalse(os.path.lexists(failure_path))
            self.assertNotIn("locus-free", stderr)

    def test_an_unhydratable_part_is_an_invalid_artifact_not_a_silent_pass(self):
        # A `meta.parts` pointer at a file that cannot be read makes the union
        # unknowable. Fail closed: the run cannot claim its artifact is valid.
        real_write = render_mod.write_report

        def _dangling_write(report, out_path, max_bytes=None):
            paths = real_write(report, out_path)
            report["meta"]["parts"] = ["report_part2.json"]   # never written
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(report, fh)
            return paths

        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp, out = self._fixture(d)
            with mock.patch.object(render_mod, "write_report",
                                   side_effect=_dangling_write):
                rc, _stdout, stderr = self._run(["--target", "src", "--out", out, fp])
        self.assertEqual(rc, 4)
        self.assertIn("artifact invalid:", stderr)

    def test_the_two_passes_are_labelled_and_an_error_is_not_printed_twice(self):
        # M1/M2: the pre-write pass and the artifact pass validate different
        # documents, so both run — but on the common case they find the SAME
        # defect, and printing it twice with only a filename between the two
        # copies reads as two problems. The status line is the source of truth
        # for the count.
        real_write = render_mod.write_report

        def _passthrough(report, out_path, max_bytes=None):
            return real_write(report, out_path)

        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = os.path.join(d, "findings-g1-COD.json")
            with open(fp, "w") as fh:
                json.dump({"findings": [_agentic("SE-001")]}, fh)
            out = os.path.join(d, "report.json")
            # Corrupt the built report AFTER validation would have seen it is
            # impossible from outside; instead break it in a way BOTH passes
            # see, by writing the same document through unchanged.
            with mock.patch.object(render_mod, "write_report",
                                   side_effect=_passthrough),                     mock.patch.object(report_mod, "REPORT_SCHEMA_VERSION", "one"):
                rc, _stdout, stderr = self._run(["--target", "src", "--out", out, fp])
        self.assertEqual(rc, 4, stderr)
        self.assertIn("SCHEMA pre-write: schema: $.schema_version", stderr)
        self.assertIn("already listed above as pre-write", stderr)
        self.assertEqual(stderr.count("$.schema_version:"), 1, stderr)
        self.assertIn("artifact invalid: 1 schema errors", stderr)

    def test_the_gate_still_owns_codes_1_and_2(self):
        # Artifact validity must not shadow the gate's own verdicts.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp, out = self._fixture(d)
            rc, _stdout, stderr = self._run(
                ["--target", "src", "--fail-on", "high", "--gate-unverified",
                 "--out", out, fp])
        self.assertEqual(rc, 1)
        self.assertNotIn("artifact invalid", stderr)


# #1639 P15 fix round 1, C1. The shapes a review agent can write that the
# published schema does not permit -- every one of them observed or probed
# against a real `synthesize.main()`. Before the type-repair pass, 15 of these
# turned a completed run into terminal `error` (rc 4): an untrusted writer
# decided whether a paid-for run produced a result. The principle is in
# `synth/validate_schema.py`: the schema pins the CONTROLLER's output, so
# everything an agent writes is normalized to the pinned types first.
#
# The third column is the stderr fragment the run must ANNOUNCE for that
# shape -- `PINS` for the schema-driven repair pass, a boundary's own text for
# the boundaries that do their own normalizing, and `None` only for the shapes
# some other normalizer already handled, which are here as regression guards
# rather than as new coverage. No silent repair: a value we changed or dropped
# is a fact about the reviewer's output.
PINS = "report-schema.json pins"

_SLOPPY_AGENT_SHAPES = [
    ("location.file int", {"location": {"file": 7, "line_start": 3}}, PINS),
    ("location.file dict", {"location": {"file": {"path": "a.py"}}}, PINS),
    ("location.file list", {"location": {"file": ["a.py"]}}, PINS),
    ("location.line_start string", {"location": {"file": "a.py", "line_start": "42"}}, PINS),
    ("location.line_start zero", {"location": {"file": "a.py", "line_start": 0}}, PINS),
    ("location.line_start negative", {"location": {"file": "a.py", "line_start": -1}}, PINS),
    ("location.line_start float", {"location": {"file": "a.py", "line_start": 4.5}}, PINS),
    ("location.function int", {"location": {"file": "a.py", "line_start": 3, "function": 7}}, PINS),
    ("description int", {"description": 7}, PINS),
    ("impact list", {"impact": ["bad"]}, PINS),
    ("remediation dict", {"remediation": {"do": "this"}}, PINS),
    ("references bare string", {"references": "CWE-89"}, PINS),
    ("references int items", {"references": [1, 2]}, PINS),
    ("cvss bare float", {"cvss": 7.5}, PINS),
    ("cvss numeric string", {"cvss": "9.8"}, PINS),
    ("cvss.score string", {"cvss": {"score": "9.8"}}, PINS),
    ("domain off-enum", {"domain": "XYZ"}, PINS),
    ("depth off-enum", {"depth": "profound"}, PINS),
    ("source_role off-enum", {"source_role": "ninja"}, PINS),
    ("provenance.discovered_by int", {"provenance": {"discovered_by": 5}}, PINS),
    ("severity_override string", {"severity_override": "yes"}, PINS),
    ("backup_confirmed string", {"backup_confirmed": "yes"}, "stripped self-asserted"),
    ("tool_evidence.rule_id int", {"tool_evidence": {"rule_id": 5}}, PINS),
    ("code int", {"code": 7}, PINS),
    ("category int", {"category": 7}, PINS),
    # Fix round 2: four more boundaries the round-1 pass never saw.
    ("code with a non-roster domain prefix", {"code": "CWE-798"},
     "names no OCRDb domain"),                                          # F1
    ("domain off-enum with a matching code", {"domain": "XYZ", "code": "XYZ-A1A"},
     "names no OCRDb domain"),                                          # F1
    ("provenance.model with no discovered_by",
     {"provenance": {"model": "gpt-6"}}, "role recorded as"),           # F2
    ("provenance.discovered_by dict",
     {"provenance": {"model": "m", "discovered_by": {"a": 1}}}, PINS),  # F2
    ("agent-supplied delta outside delta mode",
     {"delta": {"on_diff": "yes", "hunk": "a", "distance": "x"}},
     "stripped self-asserted"),  # F4
    # Fix round 3, R2-1: the two `_OWNED_DOWNSTREAM` entries whose declared
    # normalizer RAISES on the value it is declared to normalize. `panel` is
    # tested for set membership (unhashable -> TypeError) before any derivation,
    # and the `epss` consumer in citations.py assumes objects.
    ("panel dict", {"panel": {"a": 1}}, PINS),
    ("panel list", {"panel": [1]}, PINS),
    ("citations.epss dict", {"citations": {"epss": {"a": 1}}}, PINS),
    ("citations.epss string", {"citations": {"epss": "x"}}, PINS),
    ("citations.epss string items", {"citations": {"epss": ["x"]}}, PINS),
    ("citations.epss list items", {"citations": {"epss": [[1]]}}, PINS),
    # Already handled elsewhere -- regression guards.
    ("location empty", {"location": {}}, None),
    ("citations.owasp int items", {"citations": {"owasp": [1]}}, None),
    ("unknown extra key", {"invented_by_the_agent": {"x": 1}}, None),
]


@pytest.mark.parametrize("label,patch,announces",
                         _SLOPPY_AGENT_SHAPES,
                         ids=[s[0] for s in _SLOPPY_AGENT_SHAPES])
def test_a_sloppy_agent_finding_never_ends_the_run(label, patch, announces, tmp_path):
    finding = {"id": "SE-001", "title": "sqli", "severity": "MEDIUM",
               "confidence": "LIKELY", "panel": "code", "category": "injection",
               "location": {"file": "a.py", "line_start": 1}}
    finding.update(patch)
    fp = tmp_path / "findings-g1-COD.json"
    fp.write_text(json.dumps({"findings": [finding]}), encoding="utf-8")
    out = tmp_path / "report.json"
    buf, err = io.StringIO(), io.StringIO()
    with _chdir(str(tmp_path)), contextlib.redirect_stdout(buf), \
            contextlib.redirect_stderr(err):
        rc = syn.main(["--target", "src", "--out", str(out), str(fp)])
    assert rc == 0, "%s ended the run (rc=%s): %s" % (label, rc, err.getvalue())
    assert "artifact invalid" not in err.getvalue(), label
    if announces:
        assert announces in err.getvalue(), \
            "%s was accepted silently; the boundary must say what it changed" % label


def test_a_target_pre_committed_coverage_file_cannot_end_the_run(tmp_path):
    # #1639 P15 C1 vector 3: `<run_dir>/coverage-*.json` is globbed straight
    # out of the scanned repository on the agentic path, so a hostile target
    # can pre-commit one. `meta.coverage.cells.missing_floor` publishes its
    # group/domain pair as two strings -- a non-string pair must be dropped
    # here, not carried into the artifact and rejected at the exit.
    run_dir = tmp_path / ".panopticon"
    run_dir.mkdir()
    (run_dir / "coverage-evil.json").write_text(
        json.dumps({"group": 7, "floor": ["SEC"], "effective": ["SEC"]}), encoding="utf-8")
    (run_dir / "coverage-ok.json").write_text(
        json.dumps({"group": "app", "floor": [9, "SEC"], "effective": ["SEC"]}),
        encoding="utf-8")
    fp = tmp_path / "findings-app-COD.json"
    fp.write_text(json.dumps({"findings": []}), encoding="utf-8")
    out = tmp_path / "report.json"
    buf, err = io.StringIO(), io.StringIO()
    with _chdir(str(tmp_path)), contextlib.redirect_stdout(buf), \
            contextlib.redirect_stderr(err):
        rc = syn.main(["--target", "src", "--run-dir", str(run_dir),
                       "--out", str(out), str(fp)])
    assert rc in (0, 2), err.getvalue()      # 2 = INCONCLUSIVE, a GATE verdict
    assert "artifact invalid" not in err.getvalue()
    report = json.loads(out.read_text(encoding="utf-8"))
    for pair in report["meta"]["coverage"]["cells"]["missing_floor"]:
        assert all(isinstance(x, str) for x in pair), pair


# Fix round 3, R2-2. Round 1 pinned what `missing_floor` PUBLISHES; the READ
# was still raw, and the real record shape is `{group, floor, excluded,
# effective}` -- `group` is used as a dict key, `floor` is iterated and
# `excluded` becomes a set, so eleven ordinary wrong types ended the run in
# TypeError before the published pair was ever built.
_HOSTILE_COVERAGE_CELLS = [
    ("group dict", {"group": {"a": 1}, "floor": ["SEC"]}),
    ("group list", {"group": [1], "floor": ["SEC"]}),
    ("group int", {"group": 7, "floor": ["SEC"]}),
    ("floor int", {"group": "g1", "floor": 7}),
    ("floor bool", {"group": "g1", "floor": True}),
    ("floor bare string", {"group": "g1", "floor": "SEC"}),
    ("floor nested list", {"group": "g1", "floor": [[1]]}),
    ("floor dict", {"group": "g1", "floor": {"SEC": 1}}),
    ("excluded int", {"group": "g1", "floor": ["SEC"], "excluded": 7}),
    ("excluded float", {"group": "g1", "floor": ["SEC"], "excluded": 1.5}),
    ("excluded nested list", {"group": "g1", "floor": ["SEC"], "excluded": [[1]]}),
]


@pytest.mark.parametrize("label,cell", _HOSTILE_COVERAGE_CELLS,
                         ids=[x[0] for x in _HOSTILE_COVERAGE_CELLS])
def test_no_coverage_cell_a_target_can_write_ends_the_run(tmp_path, label, cell):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "coverage-g1.json").write_text(json.dumps(cell), encoding="utf-8")
    fp = run_dir / "findings-g1-SEC.json"
    fp.write_text(json.dumps({"findings": []}), encoding="utf-8")
    out = tmp_path / "report.json"
    buf, err = io.StringIO(), io.StringIO()
    with _chdir(str(tmp_path)), contextlib.redirect_stdout(buf), \
            contextlib.redirect_stderr(err):
        rc = syn.main(["--target", "src", "--run-dir", str(run_dir),
                       "--out", str(out), str(fp)])
    assert rc in (0, 2), err.getvalue()      # 2 = INCONCLUSIVE, a GATE verdict
    assert "artifact invalid" not in err.getvalue()
    report = json.loads(out.read_text(encoding="utf-8"))
    for pair in report["meta"]["coverage"]["cells"]["missing_floor"]:
        assert all(isinstance(x, str) for x in pair), pair


def test_the_coverage_reader_reads_the_shape_the_phase_writes(tmp_path):
    from scripts.phases import runio
    root = str(tmp_path)
    runio._write_json(runio._pano(root, "groups.json"), {
        "groups": [{"name": "g1", "files": ["app.py"]}]})
    runio._write_json(runio._pano(root, "scout-g1.json"), {"domains": ["OPS"]})
    matrix = {"g1": {"floor": {"COD", "TST"}, "exclude": {"TST"}}}
    with mock.patch.object(runio, "load_committed_groups", return_value=(matrix, [])):
        result = coverage_phase.coverage_execute(root, {"run_id": "round-trip"})
    assert result.kind == "advanced"
    directory = runio._pano(root)
    records = coverage_io.load_coverage_files(directory)
    assert len(records) == 1
    cell = records[0]
    assert cell["group"] == "g1"
    assert cell["floor"] == ["COD", "TST"]
    assert cell["excluded"] == ["TST"]
    assert cell["effective"] == ["COD", "OPS"]
    assert cell["run_id"] == "round-trip"
    assert coverage_io.audit_floor_cells(records, {}) == {"missing_floor": [["g1", "COD"]]}
    findings = tmp_path / "findings-g1-COD.json"
    findings.write_text('{"findings": []}')
    assert coverage_io.audit_floor_cells(records, coverage_io.present_cells([str(findings)])) == {
        "missing_floor": []}
    assert coverage_io.audit_floor_cells(records, {"other": {"COD"}}) == {
        "missing_floor": [["g1", "COD"]]}
    (Path(directory) / "coverage-malformed.json").write_text('{broken')
    assert coverage_io.load_coverage_files(directory) == records


def test_a_cross_domain_finding_with_a_mistyped_code_cannot_end_the_run(tmp_path):
    # #1639 P15 C1 vector 2: integrity.cross_domain_findings copies `code` and
    # `domain` verbatim off the agent payload into a section the schema types.
    fp = tmp_path / "findings-g1-SEC.json"
    fp.write_text(json.dumps({"findings": [
        {"id": "TS-001", "title": "t", "severity": "LOW", "confidence": "POSSIBLE",
         "panel": "test", "category": "coverage", "domain": "TST", "code": 7,
         "location": {"file": "a.py", "line_start": 1}}]}), encoding="utf-8")
    out = tmp_path / "report.json"
    buf, err = io.StringIO(), io.StringIO()
    with _chdir(str(tmp_path)), contextlib.redirect_stdout(buf), \
            contextlib.redirect_stderr(err):
        rc = syn.main(["--target", "src", "--out", str(out), str(fp)])
    assert rc == 0, err.getvalue()
    assert "artifact invalid" not in err.getvalue()
    for row in json.loads(out.read_text(encoding="utf-8"))["meta"]["integrity"]["cross_domain_findings"]:
        assert isinstance(row["finding_domain"], str), row
        assert row["code"] is None or isinstance(row["code"], str), row


def test_a_code_with_no_ocrdb_domain_files_under_the_ZZZ_sentinel(tmp_path):
    # #1639 P15 fix round 2, F1. `repair_finding` derives its rules from
    # report-schema.json, but the completion path enforces TWO schemas, and the
    # X0X sibling pins `candidates[].domain` to the 11-domain roster. Its value
    # came straight off the agent's `code` prefix with no roster check, so
    # `"code": "CWE-798"` -- the CWE id in the OCRDb code field, the single most
    # plausible slip there is -- emitted `domain: "CWE"` and ended the run.
    # Silently: `code` is a perfectly good string, so the repair pass had
    # nothing to say about it.
    fp = tmp_path / "findings-g1-COD.json"
    fp.write_text(json.dumps({"findings": [
        {"id": "SE-001", "title": "hardcoded key", "severity": "HIGH",
         "confidence": "LIKELY", "panel": "code", "category": "secrets",
         "code": "CWE-798", "location": {"file": "a.py", "line_start": 1}}]}),
        encoding="utf-8")
    out = tmp_path / "report.json"
    buf, err = io.StringIO(), io.StringIO()
    with _chdir(str(tmp_path)), contextlib.redirect_stdout(buf), \
            contextlib.redirect_stderr(err):
        rc = syn.main(["--target", "src", "--out", str(out), str(fp)])
    assert rc == 0, err.getvalue()
    assert "artifact invalid" not in err.getvalue()
    assert "names no OCRDb domain" in err.getvalue(), err.getvalue()
    x0x = json.loads((tmp_path / "report-x0x.json").read_text(encoding="utf-8"))
    assert [c["domain"] for c in x0x["candidates"]] == ["ZZZ"], x0x
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["findings"][0]["code"] == "ZZZ-X0X"


def test_an_advisor_verdict_with_mistyped_prose_cannot_end_the_run(tmp_path):
    # #1639 P15 fix round 2, F3: the verify round writes THREE type-pinned
    # fields onto an already-normalized finding from a SECOND agent-authored
    # source -- the advisor's verdict JSON -- after the findings boundary. One
    # advisor typing a list where a string belongs produced four schema errors
    # and a terminal `error`.
    run_dir = tmp_path / "run"
    vdir = tmp_path / "verdicts"
    run_dir.mkdir()
    vdir.mkdir()
    fp = run_dir / "findings-g1-SEC.json"
    fp.write_text(json.dumps({"findings": [_agentic("SE-001")]}), encoding="utf-8")
    out = tmp_path / "report.json"
    buf, err = io.StringIO(), io.StringIO()
    with _chdir(str(tmp_path)), contextlib.redirect_stdout(buf), \
            contextlib.redirect_stderr(err):
        syn.main(["--target", "src", "--run-dir", str(run_dir),
                  "--emit-verify-queue", str(fp)])
        queue = json.loads((run_dir / "verify-queue.json").read_text(encoding="utf-8"))
        fid = queue["entries"][0]["finding"]["id"]
        (vdir / "verdicts-g1-SEC.json").write_text(json.dumps(
            {"verdicts": [{"finding_id": fid, "verdict": "CONFIRMED",
                           "reasoning": [1, 2], "model": 7}],
             "_panopticon": {"run_id": queue["run_id"], "role": "domain_advisor",
                             "domain": "SEC", "group": "g1", "stage": "primary"}}),
            encoding="utf-8")
        rc = syn.main(["--target", "src", "--run-dir", str(run_dir),
                       "--verdicts-dir", str(vdir), "--out", str(out), str(fp)])
    assert rc == 0, err.getvalue()
    assert "artifact invalid" not in err.getvalue()
    report = json.loads(out.read_text(encoding="utf-8"))
    # The verdict still BOUND -- the repair must not cost the run its verification.
    assert report["meta"]["coverage"]["verdicts"]["matched"] == 1, report["meta"]["coverage"]["verdicts"]
    finding = report["findings"][0]
    assert finding["evidence"]["status"] == "advisor_confirmed", finding["evidence"]
    assert isinstance(finding["evidence"]["reasoning"], str), finding["evidence"]
    assert isinstance(finding["provenance"]["confirmed_by_model"], str)


def test_a_mistyped_groups_json_cannot_end_the_run(tmp_path):
    # #1639 P15 fix round 2, F6: `.panopticon/groups.json` sits in the same
    # target-writable directory as `coverage-*.json`, and `load_groups_json` is
    # tolerant BY DESIGN ("never abort a run"). `groups[].files` is pinned as an
    # array, so a bare string aborted the run two hundred lines later -- the
    # loader's promise broken by a validator it never heard of.
    groups = tmp_path / "groups.json"
    groups.write_text(json.dumps({"groups": [
        {"name": "g1", "files": "a.py"},
        {"name": 7, "files": ["b.py"]},
        {"name": "g3", "files": ["c.py", 9]}]}), encoding="utf-8")
    fp = tmp_path / "findings-g1-COD.json"
    fp.write_text(json.dumps({"findings": []}), encoding="utf-8")
    out = tmp_path / "report.json"
    buf, err = io.StringIO(), io.StringIO()
    with _chdir(str(tmp_path)), contextlib.redirect_stdout(buf), \
            contextlib.redirect_stderr(err):
        rc = syn.main(["--target", "src", "--groups", str(groups),
                       "--out", str(out), str(fp)])
    assert rc == 0, err.getvalue()
    assert "artifact invalid" not in err.getvalue()
    report = json.loads(out.read_text(encoding="utf-8"))
    for group in report["groups"]:
        assert isinstance(group["name"], str), group
        assert isinstance(group["files"], list), group
        assert all(isinstance(f, str) for f in group["files"]), group


# The rest of what a target can write into `.panopticon/groups.json`: `files`
# omitted (`grading` subscripts it), `parent` and `groups` mistyped (both are
# subscripted or regexed), `mode` read as a dict KEY (unhashable -> TypeError),
# and `security_mode` copied into an enum-pinned `meta` field.
_HOSTILE_GROUPS_JSON = [
    ("files omitted", {"groups": [{"name": "g1"}]}),
    ("groups not a list", {"groups": "g1"}),
    ("a group that is not an object", {"groups": [7, {"name": "g1", "files": []}]}),
    ("parent mistyped", {"groups": [{"name": "g1", "files": ["a.py"], "parent": 7}]}),
    ("mode mistyped", {"groups": [], "mode": ["repo"]}),
    ("security_mode mistyped", {"groups": [], "security_mode": 7}),
    ("security_mode off-enum", {"groups": [], "security_mode": "wide-open"}),
]


@pytest.mark.parametrize("label,groups_json", _HOSTILE_GROUPS_JSON,
                         ids=[x[0] for x in _HOSTILE_GROUPS_JSON])
def test_no_groups_json_a_target_can_write_ends_the_run(tmp_path, label, groups_json):
    groups = tmp_path / "groups.json"
    groups.write_text(json.dumps(groups_json), encoding="utf-8")
    fp = tmp_path / "findings-g1-COD.json"
    fp.write_text(json.dumps({"findings": []}), encoding="utf-8")
    out = tmp_path / "report.json"
    buf, err = io.StringIO(), io.StringIO()
    with _chdir(str(tmp_path)), contextlib.redirect_stdout(buf), \
            contextlib.redirect_stderr(err):
        rc = syn.main(["--target", "src", "--groups", str(groups),
                       "--out", str(out), str(fp)])
    assert rc == 0, err.getvalue()
    assert "artifact invalid" not in err.getvalue()
    assert "groups.json:" in err.getvalue(), err.getvalue()
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["meta"]["security_mode"] in ("standard", "redteam")


# The rest of the run folder, swept field by field against both schemas
# (#1639 P15 fix round 2, the implementer's own trace). Everything under
# `.panopticon` is readable and pre-committable by the reviewed repository, so
# every artifact synthesize reads gets one deliberately wrong-typed value here.
# The two that were NOT tolerant: a verify-queue entry whose `finding` is not
# an object (AttributeError in `group_runner.pending_verdicts`, whose docstring
# already promised to skip malformed entries) and a tools-manifest whose
# `selected` names are not strings (TypeError joining them in
# `render.render_summary`, on a report that had already validated).
_HOSTILE_RUN_ARTIFACTS = [
    ("host-capabilities.json", {"host": 7, "capabilities": [], "cli_flags": 3}),
    ("panel-tools-context.json", {"with": "many", "without": None}),
    ("usage.json", {"total": "lots", "by_phase": 7}),
    ("unenforced-ack.json", {"acknowledged": 7, "hashes": "x"}),
    ("panel-test-inventory.json", {"g1": 7}),
    ("scout-g1.json", {"tools": [7, "semgrep"], "domains": 7}),
    ("dispatch-plan-driver.json", {"cells": 7}),
    ("verify-queue.json", {"entries": [{"queue_id": 7, "finding": 9}], "run_id": 7}),
    # The REAL record shape (R2-2): `{group, floor, excluded, effective}` is
    # what `phases.coverage` writes and `coverage_io` reads. The row that
    # named `cells`/`missing_floor` exercised nothing.
    ("coverage-g1.json", {"group": {"a": 1}, "floor": 7, "excluded": [[1]],
                          "effective": ["SEC"]}),
    ("tools-manifest.json", {"schema_version": 1, "selected": [7], "missing": 8}),
]


@pytest.mark.parametrize("name,body", _HOSTILE_RUN_ARTIFACTS,
                         ids=[x[0] for x in _HOSTILE_RUN_ARTIFACTS])
def test_no_run_artifact_a_target_can_write_ends_the_run(tmp_path, name, body):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / name).write_text(json.dumps(body), encoding="utf-8")
    fp = run_dir / "findings-g1-SEC.json"
    fp.write_text(json.dumps({"findings": [_agentic("SE-001")]}), encoding="utf-8")
    out = tmp_path / "report.json"
    buf, err = io.StringIO(), io.StringIO()
    with _chdir(str(tmp_path)), contextlib.redirect_stdout(buf), \
            contextlib.redirect_stderr(err):
        rc = syn.main(["--target", "src", "--run-dir", str(run_dir),
                       "--out", str(out), str(fp)])
    assert rc != 4, err.getvalue()
    assert "artifact invalid" not in err.getvalue()
    # No JSON-path (type) error from either schema. `meta.schema_errors` also
    # counts the advisory domain checks, which this fixture deliberately trips.
    assert "schema: $." not in err.getvalue()
    json.loads(out.read_text(encoding="utf-8"))


class TestACorruptToolsManifestCannotCertify(unittest.TestCase):
    """#1644: corruption was treated as absence, and absence chose the
    permissive path.

    `ToolAxis.load` turned an unreadable / invalid-JSON / non-object
    `tools-manifest.json` into `manifest=None` without recording anything, and
    `reconcile` then took the NO-manifest branch: `tools_absent` =
    scout_requested - produced. A scanner the runner SELECTED but the scout
    never requested therefore vanished from `tools_absent`, and the
    certification input looked complete.

    End to end on real artifacts, like #1512's neighbour above: the defect is in
    what a read does with a file on disk, and a hand-built `build_report` input
    closes that gap by construction.
    """

    def _run(self, d, manifest_bytes=None, scout_tools=("semgrep",)):
        run_dir = os.path.join(d, "run")
        tools_dir = os.path.join(run_dir, "tools")
        os.makedirs(tools_dir)
        # A scout that asked for semgrep, and no tool output at all: on the
        # no-manifest path that is one lost tool and an INCONCLUSIVE gate.
        with open(os.path.join(run_dir, "scout-g1.json"), "w") as fh:
            json.dump({"group": "g1", "tools": list(scout_tools), "domains": []}, fh)
        if manifest_bytes is not None:
            with open(os.path.join(run_dir, "tools-manifest.json"), "wb") as fh:
                fh.write(manifest_bytes)
        fp = os.path.join(run_dir, "findings-g1-COD.json")
        with open(fp, "w") as fh:
            json.dump({"findings": []}, fh)
        out = os.path.join(d, "r.json")
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            rc = syn.main(["--target", "src", "--run-dir", run_dir,
                           "--tools-dir", tools_dir, "--fail-on", "critical",
                           "--out", out, fp])
        with open(out, encoding="utf-8") as fh:
            return rc, json.load(fh), err.getvalue()

    def test_an_unparseable_manifest_is_an_integrity_failure_not_a_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            rc, report, err = self._run(d, b"not json")
        reason = report["meta"]["integrity"]["tools_manifest_invalid"]
        self.assertTrue(reason, "the corrupt manifest was not recorded anywhere")
        self.assertIn("tools-manifest", reason)
        self.assertFalse(report["summary"]["coverage_certified"])
        self.assertIn("tools manifest unreadable", report["summary"]["coverage_note"])
        # The permissive fallback is what #1644 is about: with no readable
        # manifest the required set is unknown, so `tools_absent` is not
        # invented from the scout's advisory list.
        self.assertEqual(report["meta"]["coverage"]["divergence"]["tools"], {})
        # Fix round 1 F1: it is an INTEGRITY failure, and every integrity
        # failure forces INCONCLUSIVE (`invalid_verify_queue`,
        # `content_snapshot_unreadable`, ...). Anything softer is a lever: the
        # same inputs gated INCONCLUSIVE before the manifest was corrupted, so
        # a PASS here would mean one byte of a target-writable file buys a
        # clean CI gate.
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")
        self.assertEqual(rc, 2)
        self.assertIn("tools-manifest", err)

    def test_a_scanner_the_scout_never_asked_for_no_longer_vanishes(self):
        """The exact mechanism, with nothing else able to fail the run.

        The runner selected a scanner and wrote no output; the scout never
        requested it. With the manifest readable that is one lost tool. Corrupt
        the manifest and the scout-derived fallback computes
        `[] - produced == []` -- no gap, certification complete, and the only
        record that a scanner was ever selected is the file that cannot be read.
        """
        with tempfile.TemporaryDirectory() as d:
            _rc, report, _err = self._run(d, b"not json", scout_tools=())
        self.assertFalse(report["summary"]["coverage_certified"])
        self.assertTrue(report["meta"]["integrity"]["tools_manifest_invalid"])

    def test_a_non_object_manifest_is_the_same_failure(self):
        with tempfile.TemporaryDirectory() as d:
            _rc, report, _err = self._run(d, b'["semgrep"]')
        self.assertIn("not a JSON object",
                      report["meta"]["integrity"]["tools_manifest_invalid"])
        self.assertFalse(report["summary"]["coverage_certified"])

    def test_an_ABSENT_manifest_keeps_the_scout_derived_gate(self):
        # A pre-#1031 run, or `--no-tools`: nothing was corrupted, so the 4.x
        # scout-derived path stands exactly as it did.
        with tempfile.TemporaryDirectory() as d:
            rc, report, _err = self._run(d, None)
        self.assertIsNone(report["meta"]["integrity"]["tools_manifest_invalid"])
        self.assertEqual(report["meta"]["coverage"]["divergence"]["tools"],
                         {"semgrep": "requested_absent"})
        self.assertFalse(report["summary"]["coverage_certified"])
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")
        self.assertEqual(rc, 2)


class TestDiscoveryDisclosuresReachTheReport(unittest.TestCase):
    """#2271: discovery's degradation disclosures, end to end through main().

    `discovery.py` writes `method` / `files_seen` / `files_truncated` /
    `git_failure` into the `discovery` block of `groups.json` and prints the
    last two on its OWN stderr. On the driver path `phases/discovery` runs the
    child through `child._run_child` (both streams into bounded buffers) and
    reads that stderr only when `groups.json` is MISSING, and no synth module,
    renderer or schema read the block -- so on a successful `driver run` a git
    listing failure (a raw walk that does not honour the target's `.gitignore`,
    "this run's surface may be far larger than the target's own") and a
    truncated surface were captured and dropped.

    End to end rather than through a hand-built `build_report` input: the
    defect was a value that existed on disk and reached no seam, so only a run
    that really reads the file can prove the thread.
    """

    DISCOVERY = {"method": "walk", "files_seen": 3, "files_truncated": 2,
                 "git_failure": "exit 128: fatal: <ROOT>/.git: not a directory"}

    def _run(self, d, discovery):
        run_dir = os.path.join(d, ".panopticon", "runs", "tag")
        os.makedirs(run_dir)
        groups = {"groups": [{"name": "g1", "files": ["a.py"]}]}
        if discovery is not None:
            groups["discovery"] = discovery
        with open(os.path.join(run_dir, "groups.json"), "w", encoding="utf-8") as fh:
            json.dump(groups, fh)
        with open(os.path.join(run_dir, "tools-manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"schema_version": 1, "run_id": "rid-1", "selected": [],
                       "produced": [], "missing": [], "excluded_scope": []}, fh)
        fp = os.path.join(run_dir, "findings-g1-COD.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump({"findings": []}, fh)
        out = os.path.join(d, "r.json")
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = syn.main(["--target", "src",
                           "--groups", os.path.join(run_dir, "groups.json"),
                           "--run-id", "rid-1", "--fail-on", "critical",
                           "--out", out, fp])
        with open(out, encoding="utf-8") as fh:
            report = json.load(fh)
        return rc, report, render_mod.render_summary(report)

    def test_a_degraded_discovery_is_published_and_rendered(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            rc, report, md = self._run(d, self.DISCOVERY)
        integ = report["meta"]["integrity"]
        self.assertEqual(integ["discovery_git_failure"],
                         "exit 128: fatal: <ROOT>/.git: not a directory")
        self.assertEqual(integ["discovery_files_truncated"], 2)
        # Non-gating, and the same precedence the existing truncation
        # disclosure already had: the reviewed surface is a SUPERSET (git
        # failure) or a PREFIX (truncation) of the intended one, and the
        # artifacts on disk are what they claim to be.
        self.assertEqual(rc, 0)
        self.assertEqual(report["summary"]["gate"], "PASS")
        self.assertNotIn("NOT CERTIFIED", md)
        self.assertIn("**Note:** DISCOVERY FELL BACK TO A RAW WALK — exit 128: "
                      "fatal: <ROOT>/.git: not a directory", md)
        self.assertIn("**Note:** DISCOVERY TRUNCATED — 2 files beyond the cap "
                      "were not reviewed", md)

    def test_no_discovery_block_publishes_null_and_renders_nothing(self):
        # A pre-#1576 run folder, and a direct `synthesize.py` call over
        # hand-collected findings: not measured, never a zero nobody measured.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            rc, report, md = self._run(d, None)
        integ = report["meta"]["integrity"]
        self.assertIsNone(integ["discovery_git_failure"])
        self.assertIsNone(integ["discovery_files_truncated"])
        self.assertEqual(rc, 0)
        self.assertNotIn("DISCOVERY", md)

    def test_a_clean_git_discovery_renders_neither_line(self):
        # The COMMON case: `_discovery_block` publishes `files_truncated: 0` on
        # every scan and `git_failure: null` on every git-listed one, so a
        # healthy run must add no line at all -- and the measured zero still
        # reaches the artifact, where it reads apart from the null above.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            _rc, report, md = self._run(d, {"method": "git", "files_seen": 3,
                                            "files_truncated": 0,
                                            "git_failure": None})
        self.assertIsNone(report["meta"]["integrity"]["discovery_git_failure"])
        self.assertEqual(report["meta"]["integrity"]["discovery_files_truncated"], 0)
        self.assertNotIn("DISCOVERY", md)


class TestSecCarveOutDisclosureReachesTheReport(unittest.TestCase):
    """#1757 (AGT-1355709320), owner ruling 2026-09-25: a target-authored
    `exclude_paths:` may not remove a file the objective SEC floor matches from
    the SEC domain, and *such an exclusion is disclosed in the report's coverage
    section instead of silently applied*. The disclosure is the half of the
    ruling that only the report can keep, so it is proved end to end through
    `main()` -- discovery writes the block into `groups.json`, this is the thread
    that carries it to `meta.coverage` and to the rendered summary.
    """

    CARVE = {"globs": ["vendor/**"], "files": ["vendor/requirements.txt"],
             "count": 1}

    def _run(self, d, carve):
        run_dir = os.path.join(d, ".panopticon", "runs", "tag")
        os.makedirs(run_dir)
        groups = {"groups": [{"name": "g1", "files": ["a.py"]}]}
        if carve is not None:
            groups["exclude_paths"] = carve.get("globs") or []
            groups["exclude_paths_sec_carve_out"] = carve
        with open(os.path.join(run_dir, "groups.json"), "w", encoding="utf-8") as fh:
            json.dump(groups, fh)
        with open(os.path.join(run_dir, "tools-manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"schema_version": 1, "run_id": "rid-1", "selected": [],
                       "produced": [], "missing": [], "excluded_scope": []}, fh)
        fp = os.path.join(run_dir, "findings-g1-COD.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump({"findings": []}, fh)
        out = os.path.join(d, "r.json")
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = syn.main(["--target", "src",
                           "--groups", os.path.join(run_dir, "groups.json"),
                           "--run-id", "rid-1", "--fail-on", "critical",
                           "--out", out, fp])
        with open(out, encoding="utf-8") as fh:
            report = json.load(fh)
        return rc, report, render_mod.render_summary(report)

    def test_the_block_reaches_meta_coverage_and_the_summary(self):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            rc, report, md = self._run(d, self.CARVE)
        self.assertEqual(rc, 0)
        self.assertEqual(report["meta"]["coverage"]["exclude_paths_sec_carve_out"],
                         self.CARVE)
        self.assertIn("1 file(s) kept for SEC review only", md)

    def test_no_pruning_policy_publishes_no_key_and_renders_nothing(self):
        # Zero behaviour change is zero OUTPUT change, the rule `exclude_paths`
        # itself follows in `groups.json`: a run with nothing committed carries
        # no key at all rather than a zero nobody measured.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            _rc, report, md = self._run(d, None)
        self.assertNotIn("exclude_paths_sec_carve_out", report["meta"]["coverage"])
        self.assertNotIn("kept for SEC review only", md)

    def test_a_target_authored_block_is_repaired_at_the_read(self):
        # `groups.json` is read out of the target's own `.panopticon/`, and both
        # lists here are target-authored, so the block is repaired on the way in
        # exactly as `tools_excluded` is -- never published as it was written.
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            _rc, report, _md = self._run(d, {"globs": ["vendor/**", 7],
                                             "files": ["ok.yaml", None],
                                             "count": "lots"})
        self.assertEqual(report["meta"]["coverage"]["exclude_paths_sec_carve_out"],
                         {"globs": ["vendor/**"], "files": ["ok.yaml"], "count": 0})

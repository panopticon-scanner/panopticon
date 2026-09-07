"""Tests for scripts.synth.render: report writing, redaction, summary and compare rendering.
"""
import contextlib
import io
import os
import json
import tempfile
import unittest
from unittest import mock

import scripts.synth.render as render_mod


class TestCompareParts(unittest.TestCase):
    def test_read_json_report_merges_meta_parts(self):
        # #run7 ARC-D1A: --compare must merge split-report continuation parts, not
        # silently drop every part2+ finding.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "r_part2.json"), "w") as fh:
                json.dump({"findings": [{"id": "F2"}],
                           "discarded_claims": [{"id": "D2"}]}, fh)
            main = os.path.join(d, "r.json")
            with open(main, "w") as fh:
                json.dump({"meta": {"parts": ["r_part2.json"]},
                           "summary": {"gate": "PASS"},
                           "findings": [{"id": "F1"}], "discarded_claims": []}, fh)
            rep = render_mod._read_json_report(main)
        self.assertEqual([f["id"] for f in rep["findings"]], ["F1", "F2"])
        self.assertEqual([x["id"] for x in rep["discarded_claims"]], ["D2"])
        self.assertEqual(rep["summary"]["gate"], "PASS")   # main meta/summary kept

    def test_read_json_report_missing_part_fails_loud(self):
        with tempfile.TemporaryDirectory() as d:
            main = os.path.join(d, "r.json")
            with open(main, "w") as fh:
                json.dump({"meta": {"parts": ["missing_part2.json"]},
                           "findings": []}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertIsNone(render_mod._read_json_report(main))  # not a silent partial
            self.assertIn("incomplete", err.getvalue())

    def test_read_json_report_recovers_discarded_sibling_without_parts(self):
        # #run9 ARC-D1A: discarded_claims can spill to a <stem>-discarded.json
        # sibling INDEPENDENTLY of meta.parts, so --compare must follow that pointer
        # even when there are no parts -- else it drops every rejected claim.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "r-discarded.json"), "w") as fh:
                json.dump({"discarded_claims": [{"id": "D1"}, {"id": "D2"}]}, fh)
            main = os.path.join(d, "r.json")
            with open(main, "w") as fh:
                json.dump({"meta": {"discarded_claims_file": "r-discarded.json"},
                           "summary": {"gate": "PASS"},
                           "findings": [{"id": "F1"}], "discarded_claims": []}, fh)
            rep = render_mod._read_json_report(main)
        self.assertEqual([f["id"] for f in rep["findings"]], ["F1"])
        self.assertEqual([x["id"] for x in rep["discarded_claims"]], ["D1", "D2"])

    def test_read_json_report_missing_discarded_sibling_fails_loud(self):
        with tempfile.TemporaryDirectory() as d:
            main = os.path.join(d, "r.json")
            with open(main, "w") as fh:
                json.dump({"meta": {"discarded_claims_file": "gone.json"},
                           "findings": []}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertIsNone(render_mod._read_json_report(main))   # not a silent partial
            self.assertIn("incomplete", err.getvalue())

class TestGradeTextRendering(unittest.TestCase):
    def test_a_letter_renders_bare(self):
        self.assertEqual(render_mod._grade_text({"overall_grade": "B"}), "B")

    def test_a_held_letter_renders_provisional(self):
        self.assertEqual(render_mod._grade_text({"overall_grade": None,
                                          "provisional_grade": "C"}),
                         "C (provisional)")

    def test_no_letter_at_all_renders_n_a_not_the_word_none(self):
        # The old two-way format produced "None (provisional)" here, which reads
        # as a grade rather than as the absence of one.
        text = render_mod._grade_text({"overall_grade": None, "provisional_grade": None})
        self.assertNotIn("None", text)
        self.assertIn("n/a", text)

class TestRenderDelta(unittest.TestCase):
    """#449 Task 9: render_summary surfaces summary.delta -- on-diff counts,
    all-severity pre-existing counts, and a loud (advisory, non-gating)
    warning when pre-existing CRITICAL+HIGH > 0."""

    def _report(self, pre):
        return {
            "meta": {"target": "t"},
            "summary": {
                "overall_grade": "B",
                "risk_level": "MEDIUM",
                "gate": "PASS",
                "stats": {},
                "evidence_stats": {},
                "delta": {"on_diff": {"high": 1}, "pre_existing": pre},
            },
            "groups": [],
            "findings": [],
        }

    def test_warns_on_pre_existing_high(self):
        out = render_mod.render_summary(self._report({"critical": 0, "high": 2, "medium": 5, "low": 3}))
        self.assertIn("pre-existing", out.lower())
        self.assertIn("2", out)  # HIGH count
        self.assertIn("⚠", out)  # loud warning glyph
        self.assertIn("5", out)  # MEDIUM count still shown

    def test_no_warning_without_high(self):
        out = render_mod.render_summary(self._report({"critical": 0, "high": 0, "medium": 4, "low": 1}))
        self.assertNotIn("⚠", out)
        self.assertIn("4", out)  # MEDIUM count still shown

    def test_delta_lines_placed_between_evidence_and_groups(self):
        r = self._report({"critical": 1, "high": 0, "medium": 0, "low": 0})
        out = render_mod.render_summary(r)
        lines = out.split("\n")
        ev_idx = next(i for i, ln in enumerate(lines) if ln.startswith("**Evidence:**"))
        groups_idx = next(i for i, ln in enumerate(lines) if ln == "## Groups")
        ondiff_idx = next(i for i, ln in enumerate(lines) if ln.startswith("**On-diff:**"))
        pre_idx = next(i for i, ln in enumerate(lines) if ln.startswith("**Pre-existing"))
        self.assertTrue(ev_idx < ondiff_idx < pre_idx < groups_idx)

    def test_no_delta_block_when_not_delta_mode(self):
        r = self._report({"critical": 0, "high": 0, "medium": 0, "low": 0})
        r["summary"]["delta"] = None
        out = render_mod.render_summary(r)
        self.assertNotIn("On-diff", out)
        self.assertNotIn("Pre-existing", out)

class TestReportSecretRedaction(unittest.TestCase):
    """#run7 SEC-B2C: secrets a reviewer quoted-but-didn't-redact must be masked
    before the report reaches any shareable artifact (report.json/html/x0x)."""

    def test_redacts_findings_and_discarded_claims(self):
        secret = "ghp_" + "Z" * 36
        report = {
            "findings": [{"id": "F1", "severity": "HIGH", "line_start": 3,
                          "description": "leaked %s here" % secret,
                          "references": ["see %s" % secret]}],
            "discarded_claims": [{"id": "D1", "reason": "quoted %s" % secret}],
        }
        render_mod.redact_report_secrets(report)
        blob = json.dumps(report)
        self.assertNotIn(secret, blob)
        self.assertIn("[REDACTED_TOKEN]", report["findings"][0]["description"])
        self.assertIn("[REDACTED_TOKEN]", report["findings"][0]["references"][0])
        self.assertIn("[REDACTED_TOKEN]", report["discarded_claims"][0]["reason"])
        # structured scalars survive
        self.assertEqual(report["findings"][0]["severity"], "HIGH")
        self.assertEqual(report["findings"][0]["line_start"], 3)

    def test_no_findings_or_discarded_is_safe(self):
        r = {"findings": []}
        render_mod.redact_report_secrets(r)
        self.assertEqual(r["findings"], [])

class TestWriteReportDiscardedSplit(unittest.TestCase):
    """#15: a large discarded_claims set (unbounded in the REJECTED count, which
    grows when verification works well) must not floor chunk_limit into one finding
    per part (417 files on run-6). It's written to a sibling artifact instead."""

    def _report(self, n_findings, n_discarded):
        return {
            "meta": {"coverage": {}},
            "findings": [{"id": "F%d" % i, "severity": "LOW", "desc": "d" * 250}
                         for i in range(n_findings)],
            "discarded_claims": [{"id": "D%d" % i, "reason": "x" * 400}
                                 for i in range(n_discarded)],
        }

    def test_large_discarded_split_to_sibling_bounded_parts(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            report = self._report(n_findings=60, n_discarded=200)   # ~80KB discarded
            with contextlib.redirect_stderr(io.StringIO()):
                written = render_mod.write_report(report, out, max_bytes=8000)
            disc = os.path.join(d, "report-discarded.json")
            self.assertIn(disc, written)
            self.assertTrue(os.path.isfile(disc))
            main = json.load(open(out))
            self.assertEqual(main.get("discarded_claims"), [])
            self.assertEqual(main["meta"]["discarded_claims_count"], 200)
            self.assertEqual(main["meta"]["discarded_claims_file"], "report-discarded.json")
            self.assertEqual(len(json.load(open(disc))["discarded_claims"]), 200)
            parts = [p for p in written if "_part" in p]
            self.assertGreater(len(parts), 0)     # findings still needed splitting
            self.assertLess(len(parts), 30)       # bounded — old bug: ~60 parts

    def test_sibling_replace_failure_leaves_no_dangling_main_report(self):
        # #run7 COD-F1A: the small-report branch used to commit the MAIN report
        # (with meta.discarded_claims_file set) before the sibling, so a failed
        # sibling write left the main report pointing at a file that never
        # existed. Committing the pointed-to sibling first means a sibling
        # failure aborts before the main is written -- no dangling pointer.
        real_replace = os.replace

        def flaky(src, dst):
            if "discarded" in os.path.basename(dst):
                raise OSError("boom writing sibling")
            return real_replace(src, dst)

        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            # 1 finding but a big discarded set -> sibling split + small branch.
            report = self._report(n_findings=1, n_discarded=200)
            with mock.patch("os.replace", side_effect=flaky):
                with self.assertRaises(OSError):
                    render_mod.write_report(report, out, max_bytes=2000)
            self.assertFalse(os.path.exists(out))            # main never committed
            self.assertFalse(os.path.exists(
                os.path.join(d, "report-discarded.json")))    # sibling not left
            self.assertEqual(os.listdir(d), [])               # no stray temps

    def test_base_over_max_is_loud_not_silent(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            report = {"meta": {"bloat": "y" * 20000},
                      "findings": [{"id": "F%d" % i, "desc": "d" * 250} for i in range(5)]}
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                render_mod.write_report(report, out, max_bytes=8000)
            self.assertIn("report base is", err.getvalue())   # loud, not silent floor

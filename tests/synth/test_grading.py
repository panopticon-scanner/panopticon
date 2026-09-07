"""Tests for scripts.synth.grading: health score, letter grade, certification, gate roles.
"""
import os
import tempfile
import unittest

import scripts.synth.grading as grading_mod
import scripts.synth.render as render_mod


class TestGrading(unittest.TestCase):
    def _f(self, sev):
        return {"severity": sev}

    def test_grade_rule(self):
        self.assertEqual(grading_mod.grade([self._f("CRITICAL")]), "F")
        self.assertEqual(grading_mod.grade([self._f("HIGH")]), "D")
        self.assertEqual(grading_mod.grade([self._f("MEDIUM")]), "C")
        self.assertEqual(grading_mod.grade([self._f("LOW")]), "B")
        self.assertEqual(grading_mod.grade([self._f("INFO")]), "A")
        self.assertEqual(grading_mod.grade([]), "A")

    def test_risk_level(self):
        self.assertEqual(grading_mod.risk_level([self._f("HIGH"), self._f("LOW")]), "HIGH")
        self.assertEqual(grading_mod.risk_level([self._f("INFO")]), "LOW")

    def test_gate_off_when_no_threshold(self):
        self.assertEqual(grading_mod.gate_verdict([self._f("CRITICAL")], None), "OFF")

    def test_gate_fail_at_or_above_threshold(self):
        self.assertEqual(grading_mod.gate_verdict([self._f("HIGH")], "high"), "FAIL")
        self.assertEqual(grading_mod.gate_verdict([self._f("CRITICAL")], "high"), "FAIL")
        self.assertEqual(grading_mod.gate_verdict([self._f("MEDIUM")], "high"), "PASS")

    def test_severity_stats(self):
        stats = grading_mod.severity_stats([self._f("HIGH"), self._f("HIGH"), self._f("LOW")])
        self.assertEqual(stats["high"], 2)
        self.assertEqual(stats["low"], 1)
        self.assertEqual(stats["critical"], 0)

class TestCertify(unittest.TestCase):
    def _crit(self):
        return [{"severity": "CRITICAL", "evidence": {"status": "advisor_confirmed"}}]

    def test_clean_complete_pass_real_grade(self):
        r = grading_mod.certify("A", [], "high", set(), [])
        self.assertEqual(r["gate"], "PASS")
        self.assertEqual(r["overall_grade"], "A")
        self.assertIsNone(r["provisional_grade"])
        self.assertTrue(r["coverage_certified"])
        self.assertIsNone(r["coverage_note"])

    def test_clean_high_value_incomplete_inconclusive(self):
        r = grading_mod.certify("B", [], "high", {"security"}, [])
        self.assertEqual(r["gate"], "INCONCLUSIVE")
        self.assertIsNone(r["overall_grade"])
        self.assertEqual(r["provisional_grade"], "B")
        self.assertFalse(r["coverage_certified"])

    def test_clean_low_value_tail_pass_with_note(self):
        r = grading_mod.certify("B", [], "high", {"test"}, [])
        self.assertEqual(r["gate"], "PASS")
        self.assertIsNone(r["overall_grade"])
        self.assertEqual(r["provisional_grade"], "B")
        self.assertFalse(r["coverage_certified"])
        self.assertIn("test", r["coverage_note"])

    def test_confirmed_fail_beats_inconclusive(self):
        r = grading_mod.certify("F", self._crit(), "high", {"security"}, [])
        self.assertEqual(r["gate"], "FAIL")

    def test_off_preserved_with_gap(self):
        r = grading_mod.certify("B", [], None, {"security"}, [])
        self.assertEqual(r["gate"], "OFF")
        self.assertFalse(r["coverage_certified"])

    def test_requested_absent_tool_inconclusive(self):
        r = grading_mod.certify("A", [], "high", set(), ["semgrep"])
        self.assertEqual(r["gate"], "INCONCLUSIVE")
        self.assertFalse(r["coverage_certified"])

class TestHealthScore(unittest.TestCase):
    """#1146: secondary health index = the share of reviewed LoC NOT under
    severity-weighted defect footprint, on a 0-100 scale, reported ALONGSIDE the
    letter grade and never touching the gate. Higher = healthier; 100 = clean."""

    def test_loc_span_point_and_range(self):
        self.assertEqual(grading_mod._loc_span({"location": {"line_start": 10, "line_end": 10}}), 1)
        self.assertEqual(grading_mod._loc_span({"location": {"line_start": 20, "line_end": 59}}), 40)

    def test_loc_span_tolerates_missing_or_bad_range(self):
        self.assertEqual(grading_mod._loc_span({}), 1)
        self.assertEqual(grading_mod._loc_span({"location": {"line_start": None}}), 1)
        self.assertEqual(grading_mod._loc_span({"location": {"line_start": 5}}), 1)
        # inverted range floors at 1, never negative
        self.assertEqual(grading_mod._loc_span({"location": {"line_start": 9, "line_end": 3}}), 1)

    def test_weighted_defect_line_span_weighting(self):
        findings = [
            {"severity": "HIGH", "location": {"line_start": 20, "line_end": 59}},
            {"severity": "LOW", "location": {"line_start": 1, "line_end": 1}},
            {"severity": "INFO", "location": {"line_start": 1, "line_end": 100}},
        ]
        # 25*40 (HIGH span 40) + 1*1 (LOW span 1) + 0*100 (INFO weight 0)
        self.assertEqual(grading_mod.weighted_defect(findings), 1001)

    def test_health_score_is_the_clean_share_on_a_0_100_scale(self):
        # 2000 clean LoC against 100 weighted defect -> 2000/2100 of the total.
        self.assertEqual(grading_mod.health_score(2000, 100), 95.24)
        # Equal parts -> the midpoint, which is what makes the scale readable.
        self.assertEqual(grading_mod.health_score(500, 500), 50.0)

    def test_a_clean_repo_scores_a_perfect_100_not_none(self):
        # THE bug this formula exists to fix: under `total_loc / weighted_defect`
        # the single best possible outcome divided by zero and reported None, so
        # a spotless scan had a blank health field.
        self.assertEqual(grading_mod.health_score(2000, 0), 100.0)

    def test_health_score_is_bounded_at_both_ends(self):
        # Never above 100 ...
        self.assertLessEqual(grading_mod.health_score(10 ** 9, 1), 100.0)
        # ... and never below 0, however wide the defect footprint gets. The
        # rejected `100 - weighted/total_loc` form goes NEGATIVE here (-25.0):
        # a 100-line file-scoped run with ten HIGH findings spanning 50 lines.
        self.assertEqual(grading_mod.health_score(100, 25 * 50 * 10), 0.79)
        self.assertGreaterEqual(grading_mod.health_score(1, 10 ** 9), 0.0)

    def test_health_score_none_only_when_nothing_was_reviewed(self):
        # Both inputs zero is the ONLY undefined case now, and it means a broken
        # run (no readable reviewed file), not a clean one.
        self.assertIsNone(grading_mod.health_score(0, 0))

    def test_health_score_orders_the_six_calibration_targets(self):
        # Real measured (total_loc, weighted_defect) from the six calibration
        # runs. The score must rank them exactly as the old ratio did -- this is
        # a rescale, not a re-ranking -- while spreading them across ~35 points
        # instead of the 1.38 that `100 - weighted/total_loc` would have given.
        targets = [("fzf", 51789, 93341), ("gotify", 31277, 52305),
                   ("ripgrep", 68932, 72954), ("express", 21911, 14512),
                   ("btcpayserver", 321482, 183694), ("solidus", 251596, 105547)]
        scored = [(grading_mod.health_score(loc, wd), name) for name, loc, wd in targets]
        old_order = [n for _, n in sorted((loc / wd, n) for n, loc, wd in targets)]
        self.assertEqual([n for _, n in sorted(scored)], old_order)
        self.assertGreater(max(s for s, _ in scored) - min(s for s, _ in scored), 30)

    def test_nonblank_loc_excludes_blanks_and_dedupes(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.py"), "w") as fh:
                fh.write("import os\n\n   \nx = 1\n")  # 2 non-blank lines
            groups = [
                {"name": "g", "files": ["a.py"]},
                {"name": "h", "files": ["a.py"]},
            ]  # same file -> counted once
            self.assertEqual(grading_mod.nonblank_loc(d, groups), 2)

    def test_nonblank_loc_tolerates_missing_file(self):
        self.assertEqual(grading_mod.nonblank_loc("/no/such/dir", [{"name": "g", "files": ["nope.py"]}]), 0)

class TestGateSeverityRoles(unittest.TestCase):
    """Which severities --fail-on puts in play, and which the FAIL is made of.

    A bare severity distribution does not say which levels can break a build --
    that depends on --fail-on, which lives elsewhere in the report. These roles
    put the gate's reach onto the distribution itself.
    """

    ALL = [{"severity": s} for s in ("HIGH", "MEDIUM", "LOW", "INFO")]

    def test_fail_on_critical_puts_only_critical_in_play(self):
        roles = grading_mod.gate_severity_roles(self.ALL, "CRITICAL")
        self.assertEqual(roles["in_play"], ["CRITICAL"])
        # No CRITICAL findings exist, so it is in play and did NOT fire.
        self.assertEqual(roles["contributing"], [])

    def test_fail_on_high_marks_high_as_contributing(self):
        roles = grading_mod.gate_severity_roles(self.ALL, "HIGH")
        self.assertEqual(roles["in_play"], ["CRITICAL", "HIGH"])
        self.assertEqual(roles["contributing"], ["HIGH"])

    def test_fail_on_medium_walks_the_threshold_down(self):
        roles = grading_mod.gate_severity_roles(self.ALL, "MEDIUM")
        self.assertEqual(roles["in_play"], ["CRITICAL", "HIGH", "MEDIUM"])
        self.assertEqual(roles["contributing"], ["HIGH", "MEDIUM"])

    def test_no_fail_on_puts_nothing_in_play(self):
        roles = grading_mod.gate_severity_roles(self.ALL, None)
        self.assertEqual(roles, {"fail_on": None, "in_play": [], "contributing": []})

    def test_unknown_fail_on_marks_nothing_rather_than_crashing(self):
        # gate_verdict would raise on this; the display must degrade to unmarked.
        self.assertEqual(grading_mod.gate_severity_roles(self.ALL, "SEVERE"),
                         {"fail_on": None, "in_play": [], "contributing": []})

    def test_roles_never_outrank_the_gate_verdict(self):
        # THE correctness property. Roles come from the gate-eligible set, so a
        # level can never be painted "contributing" while the gate passes. Feed
        # both the same list and the two must agree, at every threshold.
        for pop in ([], [{"severity": "INFO"}], self.ALL,
                    [{"severity": "CRITICAL"}] + self.ALL):
            for fail_on in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                roles = grading_mod.gate_severity_roles(pop, fail_on)
                verdict = grading_mod.gate_verdict(pop, fail_on)
                self.assertEqual(bool(roles["contributing"]), verdict == "FAIL",
                                 "%s @ %s: %r vs %s" % (pop, fail_on, roles, verdict))

class TestSeverityBlockRendering(unittest.TestCase):
    """The distribution as rendered, with the gate's reach marked on it."""

    STATS = {"critical": 0, "high": 101, "medium": 296, "low": 315, "info": 105}

    def _block(self, fail_on, eligible=None):
        eligible = eligible if eligible is not None else (
            [{"severity": s} for s in ("HIGH", "MEDIUM", "LOW", "INFO")])
        return "\n".join(render_mod._render_severity_block(
            self.STATS, grading_mod.gate_severity_roles(eligible, fail_on)))

    def test_every_severity_is_listed_with_its_count(self):
        out = self._block("HIGH")
        for sev, n in (("CRITICAL", 0), ("HIGH", 101), ("MEDIUM", 296),
                       ("LOW", 315), ("INFO", 105)):
            self.assertIn("%s: %d" % (sev, n), out)

    def test_in_play_but_empty_reads_as_in_play_not_as_a_failure(self):
        out = self._block("CRITICAL")
        self.assertIn("**CRITICAL: 0** \u2014 in play, none found", out)
        self.assertNotIn("FAILS THE GATE", out)

    def test_contributing_levels_say_so(self):
        out = self._block("MEDIUM")
        self.assertIn("**HIGH: 101** \u2014 **FAILS THE GATE**", out)
        self.assertIn("**MEDIUM: 296** \u2014 **FAILS THE GATE**", out)
        # below the threshold -> plain, no marker
        self.assertIn("- LOW: 315", out)
        self.assertIn("- INFO: 105", out)

    def test_the_threshold_is_named(self):
        self.assertIn("`--fail-on MEDIUM`", self._block("MEDIUM"))

    def test_without_fail_on_nothing_is_marked(self):
        out = self._block(None)
        self.assertNotIn("FAILS THE GATE", out)
        self.assertNotIn("in play", out)
        self.assertNotIn("--fail-on", out)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.assertIn("- %s: " % sev, out)

    def test_active_findings_that_cannot_gate_are_marked_in_play_not_failing(self):
        # 101 active HIGHs, none of them gate-eligible: the count is alarming and
        # the gate is untouched. Painting it as a failure would be the lie.
        out = self._block("HIGH", eligible=[])
        self.assertIn("**HIGH: 101** \u2014 in play, nothing confirmed here", out)
        self.assertNotIn("FAILS THE GATE", out)

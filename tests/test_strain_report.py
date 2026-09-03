"""StrainReport: the catalog MIS-FIT signal, companion to X0XReport.

X0X reports ABSENCE (a reviewer filed `<DOM>-X0X` because nothing fit) and can
only argue the `new_code` disposition. Strain reports DISAGREEMENT — two codes
in play and a reader had to choose — which is the only evidence that can argue
`boundary` or `refine_existing`, both already in OCRDb's vocabulary.
"""
import json
import os
import unittest

from scripts import strain_report as sr

_SCHEMA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "skill", "reference", "strain-report-schema.json")


def _finding(fid="SEC-1", code="DAT-C1B", advisor=None, file="app.py",
             line=10, title="t", severity="MEDIUM", reasoning=None):
    f = {"id": fid, "code": code, "title": title, "severity": severity,
         "location": {"file": file, "line_start": line}}
    prov = {}
    if advisor:
        prov["advisor_code"] = advisor
    if reasoning:
        prov["confirmation_reasoning"] = reasoning
    if prov:
        f["provenance"] = prov
    return f


class TestDirection(unittest.TestCase):
    """`direction` is what tells an adjudicator which way to read the record."""

    def test_real_code_to_gap_declares_a_gap(self):
        # The signal X0X can never produce: a real code was filed, so no
        # fallback was ever raised and the pool never heard about it.
        self.assertEqual(sr.direction("SEC-B1C", "SEC-X0X"), "declares_gap")

    def test_gap_to_real_code_refutes_the_gap(self):
        # The pool should DROP this candidate — an independent read found a code.
        self.assertEqual(sr.direction("COD-X0X", "COD-C3C"), "refutes_gap")

    def test_code_to_code_is_a_boundary_question(self):
        self.assertEqual(sr.direction("DAT-C1C", "OPS-D1B"), "code_to_code")

    def test_gap_to_gap_is_not_a_gap_claim(self):
        # Two domains' fallbacks are not a disagreement about a code.
        self.assertEqual(sr.direction("COD-X0X", "QAL-X0X"), "code_to_code")


class TestAdvisorRecodeSignals(unittest.TestCase):
    def test_records_only_disagreements(self):
        findings = [_finding("A", "DAT-C1B", advisor="QAL-G1A"),
                    _finding("B", "DAT-C1B", advisor="DAT-C1B"),   # agrees
                    _finding("C", "DAT-C1B")]                      # no advisor
        sigs = sr.advisor_recode_signals(findings, "run1")
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0]["code_filed"], "DAT-C1B")
        self.assertEqual(sigs[0]["code_preferred"], "QAL-G1A")

    def test_same_pair_clusters_and_counts(self):
        # One occurrence is an anecdote; the same pair recurring across
        # independent sites is a boundary that does not hold. Recurrence is the
        # number an adjudicator actually reads.
        findings = [_finding("A", "DAT-C1C", advisor="OPS-D1B", file="a.py"),
                    _finding("B", "DAT-C1C", advisor="OPS-D1B", file="b.py"),
                    _finding("C", "DAT-C1C", advisor="OPS-D1B", file="c.py")]
        sigs = sr.advisor_recode_signals(findings, "run1")
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0]["recurrence"], 3)
        self.assertEqual(len(sigs[0]["occurrences"]), 3)

    def test_carries_the_advisors_own_argument(self):
        # The advisor usually argues the boundary explicitly; that argument is
        # the most useful thing in the record.
        f = _finding("A", "SEC-B1C", advisor="SEC-X0X",
                     reasoning="no code covers this sanitizer bypass")
        sig = sr.advisor_recode_signals([f], "run1")[0]
        self.assertIn("sanitizer bypass", sig["rationale"])

    def test_cross_domain_is_flagged(self):
        f = _finding("A", "DAT-C1C", advisor="OPS-D1B")
        self.assertTrue(sr.advisor_recode_signals([f], "run1")[0]["cross_domain"])
        g = _finding("B", "QAL-G1A", advisor="QAL-G2A")
        self.assertFalse(sr.advisor_recode_signals([g], "run1")[0]["cross_domain"])

    def test_a_finding_with_no_file_is_skipped(self):
        f = _finding("A", "DAT-C1B", advisor="QAL-G1A")
        f["location"] = {}
        self.assertEqual(sr.advisor_recode_signals([f], "run1"), [])


class TestCrossRunSignals(unittest.TestCase):
    def test_same_site_different_codes_is_strain(self):
        runs = [("r1", [_finding("A", "DAT-C1C", file="a.py", line=10)]),
                ("r2", [_finding("B", "OPS-D1B", file="a.py", line=12)])]
        sigs = sr.cross_run_signals(runs)
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0]["signal"], "cross_run_disagreement")
        self.assertTrue(sigs[0]["cross_domain"])

    def test_agreement_on_any_code_is_not_strain(self):
        # Partial overlap is ordinary sampling variance — one run simply found
        # something extra — not a disagreement about how to code the site.
        runs = [("r1", [_finding("A", "DAT-C1C", file="a.py", line=10),
                        _finding("B", "QAL-G1A", file="a.py", line=11)]),
                ("r2", [_finding("C", "DAT-C1C", file="a.py", line=12)])]
        self.assertEqual(sr.cross_run_signals(runs), [])

    def test_the_pair_is_symmetric_and_clusters_once(self):
        # Neither run is authoritative, so argument order must not split one
        # boundary into two records — that understates its recurrence, which is
        # the number the adjudicator reads.
        runs = [("r1", [_finding("A", "ARC-A3A", file="a.py", line=10),
                        _finding("B", "QAL-D1A", file="b.py", line=10)]),
                ("r2", [_finding("C", "QAL-D1A", file="a.py", line=10),
                        _finding("D", "ARC-A3A", file="b.py", line=10)])]
        sigs = sr.cross_run_signals(runs)
        self.assertEqual(len(sigs), 1, "opposite orderings must not split")
        self.assertEqual(sigs[0]["recurrence"], 2)

    def test_a_real_code_sorts_before_a_gap(self):
        # So `direction` reports declares_gap, not refutes_gap, for a split
        # where one run found a code and the other declared a gap.
        runs = [("r1", [_finding("A", "COD-X0X", file="a.py", line=10)]),
                ("r2", [_finding("B", "COD-B2A", file="a.py", line=10)])]
        sig = sr.cross_run_signals(runs)[0]
        self.assertEqual(sig["code_filed"], "COD-B2A")
        self.assertEqual(sig["direction"], "declares_gap")

    def test_distant_lines_in_one_file_are_different_sites(self):
        runs = [("r1", [_finding("A", "DAT-C1C", file="a.py", line=10)]),
                ("r2", [_finding("B", "OPS-D1B", file="a.py", line=900)])]
        self.assertEqual(sr.cross_run_signals(runs), [])

    def test_occurrences_name_both_runs(self):
        runs = [("r1", [_finding("A", "DAT-C1C", file="a.py", line=10)]),
                ("r2", [_finding("B", "OPS-D1B", file="a.py", line=10)])]
        got = {o.get("run_id") for o in sr.cross_run_signals(runs)[0]["occurrences"]}
        self.assertEqual(got, {"r1", "r2"})

    def test_no_rationale_on_a_cross_run_signal(self):
        # Neither run knew it was disagreeing. The absent argument is the honest
        # marker of why this signal is weaker per instance than an advisor recode.
        runs = [("r1", [_finding("A", "DAT-C1C", file="a.py", line=10)]),
                ("r2", [_finding("B", "OPS-D1B", file="a.py", line=10)])]
        self.assertNotIn("rationale", sr.cross_run_signals(runs)[0])


class TestBuildReport(unittest.TestCase):
    def _schema(self):
        with open(_SCHEMA, encoding="utf-8") as fh:
            return json.load(fh)

    def test_report_validates_against_its_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        findings = [_finding("A", "SEC-B1C", advisor="SEC-X0X",
                             reasoning="nothing fits")]
        runs = [("r1", [_finding("B", "DAT-C1C", file="x.py", line=10)]),
                ("r2", [_finding("C", "OPS-D1B", file="x.py", line=10)])]
        rep = sr.build_report(findings, {"ocrdb_version": "0.5.0",
                                         "version": "5.0.1"},
                              "r1", cross_runs=runs)
        errs = list(jsonschema.Draft7Validator(self._schema()).iter_errors(rep))
        self.assertEqual(errs, [], "; ".join(e.message for e in errs[:3]))
        self.assertEqual(len(rep["signals"]), 2)   # one of each signal type

    def test_compared_runs_recorded_only_for_cross_run(self):
        rep = sr.build_report([], {"ocrdb_version": "0.5.0"}, "r1")
        self.assertNotIn("compared_runs", rep["generated_by"])
        rep2 = sr.build_report([], {"ocrdb_version": "0.5.0"}, "r1",
                               cross_runs=[("r1", []), ("r2", [])])
        self.assertEqual(rep2["generated_by"]["compared_runs"], ["r1", "r2"])

    def test_a_clean_run_emits_an_empty_signal_list(self):
        # No strain is a real result, not a missing report.
        rep = sr.build_report([_finding("A", "DAT-C1B")], {"ocrdb_version": "0.5.0"}, "r1")
        self.assertEqual(rep["signals"], [])


if __name__ == "__main__":
    unittest.main()

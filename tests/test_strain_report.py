"""StrainReport: the catalog MIS-FIT signal, companion to X0XReport.

X0X reports ABSENCE (a reviewer filed `<DOM>-X0X` because nothing fit) and can
only argue the `new_code` disposition. Strain reports DISAGREEMENT — two codes
in play and a reader had to choose — which is the only evidence that can argue
`boundary` or `refine_existing`, both already in OCRDb's vocabulary.
"""
import contextlib
import io
import json
import os
import subprocess
import sys
import unittest

from scripts import ocrdb
from scripts import strain_report as sr
from scripts import x0x_report as x0x

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


class TestSharedReportContracts(unittest.TestCase):
    def test_occurrences_preserve_optional_fields_and_strain_run_id(self):
        for location, expected in (
            ({}, None),
            ({"file": ""}, None),
            ({"file": "a.py"}, {"file": "a.py"}),
            ({"file": "a.py", "line_start": 0, "line_end": None},
             {"file": "a.py", "line_start": 0}),
            ({"file": "a.py", "line_start": 2, "line_end": 4},
             {"file": "a.py", "line_start": 2, "line_end": 4}),
        ):
            for fid in (None, "", "finding-1"):
                with self.subTest(location=location, fid=fid):
                    finding = {"id": fid, "location": location}
                    before = json.dumps(finding, sort_keys=True)
                    occurrence = dict(expected) if expected is not None else None
                    if occurrence is not None and fid:
                        occurrence["finding_id"] = fid
                    self.assertEqual(x0x._occurrence(finding), occurrence)
                    self.assertEqual(sr._occurrence(finding), occurrence)
                    self.assertEqual(sr._occurrence(finding, ""), occurrence)
                    with_run = dict(occurrence, run_id="run-1") if occurrence else None
                    self.assertEqual(sr._occurrence(finding, "run-1"), with_run)
                    self.assertEqual(json.dumps(finding, sort_keys=True), before)

    def test_the_two_emitters_answer_the_probe_table_identically(self):
        # #2236 (ARC-101960059), the reproduction that filed it. The two
        # emitters are companions over the same findings, and both halves
        # disagreed: `x0x_report.is_fallback` matched `-X0X` case-SENSITIVELY
        # while `strain_report._is_gap` upper-cased first, so `sec-x0x` was a
        # catalog gap to one and an ordinary code to the other; and
        # `x0x_report._domain` clamped an off-roster prefix to the `ZZZ`
        # sentinel while `strain_report._domain` published it verbatim -- into a
        # `domain` whose schema enum IS the roster, and into the `cross_domain`
        # flag. Codes arrive verbatim from the reviewer with no case-fold
        # upstream, so neither edge is hypothetical. One owner now
        # (`ocrdb.is_fallback_code` / `ocrdb.roster_domain`), and this table is
        # asserted EQUAL across the two modules rather than twice over.
        for code, gap, domain in (
            ("SEC-X0X", True, "SEC"),
            ("sec-x0x", True, "SEC"),
            ("Sec-X0x", True, "SEC"),
            ("zzz-x0x", True, "ZZZ"),
            ("sec-a1a", False, "SEC"),
            ("XYZ-A1A", False, "ZZZ"),
            ("NOTADOMAIN-A1A", False, "ZZZ"),
        ):
            with self.subTest(code=code), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(x0x.is_fallback(code), gap)
                self.assertEqual(sr._is_gap(code), gap)
                self.assertEqual(x0x._domain({"code": code}), domain)
                self.assertEqual(sr._domain(code), domain)

    def test_the_shared_domain_predicate_is_total_and_roster_pinned(self):
        # The edges the probe table does not reach. `ocrdb.domain_of` is kept in
        # the table as the RAW claim -- it says what a code claims, not whether
        # the claim is a domain -- so the clamp is visible as the difference
        # between the columns. Every clamped answer is `ocrdb.UNKNOWN_DOMAIN`,
        # which is in both artifacts' `domain` enum; there is no third answer
        # and no `None`, which is what lets the two emitters be compared at all.
        for code, raw, domain in (
            ("SEC-A1A", "SEC", "SEC"),
            ("sec-X0X", "sec", "SEC"),
            (" sec-X0X", " sec", "SEC"),      # stripped, then clamped if needed
            ("SEC", None, "SEC"),             # prefix-only: no hyphen, still SEC
            ("-X0X", "", "ZZZ"),
            (None, None, "ZZZ"),
            (27, None, "ZZZ"),
        ):
            with self.subTest(code=code), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(ocrdb.domain_of(code), raw)
                self.assertEqual(sr._domain(code), domain)
                self.assertEqual(x0x._domain({"code": code}), domain)
                self.assertTrue(ocrdb.is_domain(sr._domain(code)))
                # x0x still prefers the finding's own `domain` field over the
                # code prefix, and normalizes that through the same clamp.
                self.assertEqual(x0x._domain({"code": code, "domain": "dat"}), "DAT")
                self.assertEqual(x0x._domain({"code": code, "domain": "nope"}), "ZZZ")

    def test_both_emitters_disclose_the_clamp_on_stderr(self):
        # A clamp rewrites a published value, so neither emitter may do it
        # silently -- and each line is bounded and `%r`-rendered, because the
        # code is agent-authored (`x0x_report`'s line already was).
        for module, call in ((x0x, lambda: x0x._domain({"id": "gap-1",
                                                        "code": "BOG-A1A"})),
                             (sr, lambda: sr._domain("BOG-A1A"))):
            with self.subTest(module=module.__name__):
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertEqual(call(), "ZZZ")
                line = err.getvalue()
                self.assertEqual(len(line.splitlines()), 1)
                self.assertIn("'BOG'", line)
                self.assertIn("not an OCRDb domain", line)

    def test_reports_remain_flat_importable_in_a_fresh_interpreter(self):
        scripts = os.path.join(os.path.dirname(os.path.dirname(__file__)), "skill", "scripts")
        code = """import json, sys
sys.path.insert(0, sys.argv[1])
import ocrdb, strain_report, x0x_report
finding = {'id': 'f', 'location': {'file': 'a.py'}}
print(json.dumps([ocrdb.domain_of('SEC-A1A'),
                  strain_report._occurrence(finding, 'r'), x0x_report._occurrence(finding)]))
"""
        proc = subprocess.run([sys.executable, "-I", "-c", code, scripts],
                              capture_output=True, text=True, timeout=10, check=True)
        self.assertEqual(json.loads(proc.stdout), ["SEC",
            {"file": "a.py", "finding_id": "f", "run_id": "r"},
            {"file": "a.py", "finding_id": "f"}])


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

    def test_a_finding_with_no_file_is_announced_then_skipped(self):
        # #1807 DAT-2501524861: the recode itself is real evidence -- only its
        # occurrence record is impossible, because the schema requires a file and
        # inventing one would be a lie. Announce the drop rather than swallow it.
        f = _finding("A", "DAT-C1B", advisor="QAL-G1A", title="pinning\tpolicy")
        f["location"] = {}
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(sr.advisor_recode_signals([f], "run1"), [])
        self.assertEqual(err.getvalue(),
                         "strain: 'A': dropping an advisor recode with no file "
                         "location: 'DAT-C1B' -> 'QAL-G1A' 'pinning policy'\n")

    def test_a_hostile_recode_cannot_forge_a_second_diagnostic_line(self):
        # Review I1: `id`, `code` and `provenance.advisor_code` are all
        # agent-authored, and this is the module's ONLY terminal output, so it
        # inherits no posture. One finding must not be able to clear the screen,
        # ring the bell, or write a line that reads as this tool's own honest
        # output -- nor fill the terminal with a 200-char code.
        f = _finding("\x1b[2J\x07ID\nstrain: FAKE: nothing dropped",
                     "DAT-C1B" + "!" * 200,
                     advisor="QAL-G1A\nstrain: forged second line",
                     title="pinning\npolicy" + "x" * 200)
        f["location"] = {}
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(sr.advisor_recode_signals([f], "run1"), [])
        out = err.getvalue()
        self.assertEqual(len(out.splitlines()), 1)        # one physical line
        self.assertNotIn("\x1b", out)                     # no raw ESC
        self.assertNotIn("\x07", out)                     # no raw BEL
        self.assertIn("\\x1b[2J", out)                    # escaped, inert
        self.assertIn("'DAT-C1B" + "!" * 32 + "\u2026'", out)   # code bound at 40, cut marked
        self.assertIn("'pinning policyxxx", out)          # title squeezed
        # %r can expand one escaped character to six, so the real ceiling is
        # 6 x (title + two codes) + fixed prose -- not the pre-escape caps.
        self.assertLessEqual(len(out), 6 * (120 + 40 + 40) + 200)


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


def test_write_report_replaces_destination(tmp_path):
    output = tmp_path / "report.json"
    expected = tmp_path / "report-strain.json"
    expected.write_text("old contents", encoding="utf-8")
    document = {"schema_version": 1, "findings": []}
    actual = sr.write_report(document, str(output))
    assert actual == str(expected)
    assert json.loads(expected.read_text(encoding="utf-8")) == document
    assert expected.read_text(encoding="utf-8").endswith("\n")
    assert not (tmp_path / "report-strain.json.tmp").exists()


if __name__ == "__main__":
    unittest.main()

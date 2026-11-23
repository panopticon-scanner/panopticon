import contextlib
import functools
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import scripts.evidence as evidence_mod
import scripts.ocrdb as ocrdb
import scripts.strain_report as strain_mod
import scripts.synth.findings as findings_mod
import scripts.synth.codes as codes_mod
import scripts.synth.report as report_mod


def _bundle():
    return {"domains": {"SEC": {"entries": {
        "SEC-A1A": {"name": "n1", "default_severity": "MEDIUM"},
        "SEC-B2B": {"name": "n2", "default_severity": "HIGH"}}}}}


@functools.lru_cache(maxsize=1)
def _bundle_07():
    path = Path(__file__).parent / "fixtures" / "ocrdb-0.7.0-dev.json"
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


class TestVerdictQuality(unittest.TestCase):
    def test_default_severity_lookup(self):
        b = _bundle()
        self.assertEqual(ocrdb.default_severity(b, "SEC-A1A"), "MEDIUM")
        self.assertIsNone(ocrdb.default_severity(b, "SEC-ZZZ"))
        self.assertIsNone(ocrdb.default_severity(None, "SEC-A1A"))

    def test_advisor_differing_code_is_not_applied(self):
        # #2101: an advisor's differing OCRDb code is a RECORDED second opinion
        # (evidence.apply_verdict -> provenance.advisor_code), and this step used
        # to overwrite the very code that record is about. It no longer reads the
        # verdict's code at all; severity is the only axis it mutates.
        b = _bundle()
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH", "domain": "SEC"}
        cov = codes_mod.apply_verdict_quality(
            [f], {id(f): {"code": "SEC-B2B", "verdict": "CONFIRMED", "stage": "primary"}}, b)
        self.assertEqual(f["code"], "SEC-A1A")           # the panel's code, published
        self.assertEqual(f["severity"], "HIGH")          # two-axis invariant
        self.assertNotIn("code_corrected_by", f)
        self.assertNotIn("code_corrections", cov)

    def test_live_call_order_records_the_advisor_code_and_never_applies_it(self):
        # The production order is evidence.apply_verdict (synth.verdicts._bind_
        # verdicts) and THEN codes.apply_verdict_quality, a few lines later in
        # resolve_findings. The contradiction #2101 names was only visible
        # COMPOSED: step one wrote the record, step two overwrote the code the
        # record was about, so each step read correctly on its own.
        b = _bundle()
        for advisor_code, where in (("SEC-B2B", "valid in the bundle"),
                                    ("SEC-ZZZ", "absent from the bundle")):
            with self.subTest(advisor_code=advisor_code, where=where):
                f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH",
                     "domain": "SEC", "title": "t",
                     "location": {"file": "app.py", "line_start": 10}}
                v = {"code": advisor_code, "verdict": "CONFIRMED",
                     "stage": "primary", "reasoning": "the advisor's own argument"}
                evidence_mod.apply_verdict(f, v)
                cov = codes_mod.apply_verdict_quality([f], {id(f): v}, b)
                self.assertEqual(f["code"], "SEC-A1A")        # published: the panel's
                self.assertEqual(f["provenance"]["advisor_code"], advisor_code)
                self.assertEqual(f["severity"], "HIGH")       # two-axis invariant
                self.assertNotIn("code_corrected_by", f)
                self.assertNotIn("code_corrections", cov)
                # The record-only CONSUMER still sees it: that is the whole point
                # of recording a disagreement nobody applies.
                self.assertEqual(
                    [(s["code_filed"], s["code_preferred"], s["recurrence"])
                     for s in strain_mod.advisor_recode_signals([f], "run1")],
                    [("SEC-A1A", advisor_code, 1)])

    def test_override_missing_reason_reverts_to_code_default(self):
        b = _bundle()
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "CRITICAL", "domain": "SEC",
             "severity_override": {"from": "MEDIUM", "to": "CRITICAL"}}   # no reason
        cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "MEDIUM")                 # reverted to code default
        self.assertNotIn("severity_override", f)
        self.assertEqual(cov["overrides"]["count"], 0)
        # #2101's ONE severity consequence, pinned. The revert target is the
        # PUBLISHED code's default. The deleted code-application branch ran
        # earlier in this same loop iteration, so an applied advisor code used to
        # decide this default too: SEC-B2B (HIGH) would have reverted the finding
        # to HIGH. Severity is still mutated only by the override discipline --
        # it is the default the discipline measures against that moved, onto the
        # code the report actually publishes.
        g = {"id": "SEC-2", "code": "SEC-A1A", "severity": "CRITICAL", "domain": "SEC",
             "severity_override": {"from": "MEDIUM", "to": "CRITICAL"}}   # no reason
        cov = codes_mod.apply_verdict_quality(
            [g], {id(g): {"code": "SEC-B2B", "verdict": "CONFIRMED", "stage": "primary"}}, b)
        self.assertEqual(g["severity"], "MEDIUM")     # SEC-A1A's default, not SEC-B2B's HIGH
        self.assertNotIn("severity_override", g)
        self.assertEqual(cov["overrides"]["count"], 0)

    def test_valid_override_kept_and_counted_up(self):
        b = _bundle()
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "CRITICAL", "domain": "SEC",
             "severity_override": {"from": "MEDIUM", "to": "CRITICAL", "reason": "prod exposed"}}
        cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertEqual(cov["overrides"],
                         {"count": 1, "up": 1, "down": 0,
                          "clamped": 0, "missing": 0})

    def test_backup_confirm_sets_flag(self):
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH"}
        codes_mod.apply_verdict_quality(
            [f], {id(f): {"verdict": "CONFIRMED", "stage": "backup"}}, _bundle())
        self.assertTrue(f.get("backup_confirmed"))

    def test_build_report_counts_land_in_ocrdb_coverage(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fp = os.path.join(tmp_dir, "findings-app-SEC.json")
            with open(fp, "w", encoding="utf-8") as fh:
                json.dump({"findings": [
                    {"domain": "SEC", "code": "SEC-A1A", "severity": "CRITICAL",
                     "title": "t", "description": "x",
                     "location": {"file": "a.py", "line_start": 1}, "category": "authz",
                     "severity_override": {"from": "MEDIUM", "to": "CRITICAL", "reason": "prod"}}]}, fh)
            findings = findings_mod.load_findings([fp])
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="src",
                    fail_on=None,
                    timestamp="2026-08-15T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(findings=findings),
            ))
            ocrdb_cov = report["meta"]["coverage"]["ocrdb"]
            self.assertEqual(ocrdb_cov["overrides"]["count"], 1)
            self.assertNotIn("code_corrections", ocrdb_cov)   # retired with #2101

    def test_override_de_escalation_counts_down(self):
        b = _bundle()  # SEC-A1A default MEDIUM
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "LOW", "domain": "SEC",
             "severity_override": {"from": "MEDIUM", "to": "LOW", "reason": "intended lower"}}
        cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(cov["overrides"],
                         {"count": 1, "up": 0, "down": 1,
                          "clamped": 0, "missing": 0})

    def test_07_agentic_off_default_without_override_reverts_and_counts_missing(self):
        b = _bundle_07()
        f = {"id": "AGT-implicit", "code": "AGT-A1B", "severity": "HIGH",
             "domain": "AGT", "source_role": "domain_panel"}
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "MEDIUM")
        self.assertNotIn("severity_override", f)
        self.assertEqual(cov["overrides"],
                         {"count": 0, "up": 0, "down": 0,
                          "clamped": 0, "missing": 1})
        self.assertIn("AGT-implicit: agent severity HIGH without severity_override "
                      "reverted to OCRDb AGT-A1B default MEDIUM", stderr.getvalue())

    def test_07_tool_severity_without_override_is_not_clamped(self):
        b = _bundle_07()
        f = {"id": "TOOL-1", "code": "AGT-A1B", "severity": "HIGH",
             "domain": "AGT", "source": "tool:semgrep"}
        cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(cov["overrides"]["missing"], 0)

    def test_07_in_range_raise_accepts_rung_label_or_exact_condition(self):
        b = _bundle_07()
        condition = (b["domains"]["TST"]["entries"]["TST-A1D"]
                     ["severity_range"]["raise_when"][0]["condition"])
        for rung in ("raise_when[0]", condition):
            with self.subTest(rung=rung):
                f = {"id": "TST-raise", "code": "TST-A1D", "severity": "MEDIUM",
                     "domain": "TST", "severity_override": {
                         "from": "LOW", "to": "MEDIUM",
                         "reason": "the flag controls an enforcement mode", "rung": rung}}
                cov = codes_mod.apply_verdict_quality([f], {}, b)
                self.assertEqual(f["severity"], "MEDIUM")
                self.assertEqual(f["severity_override"]["to"], "MEDIUM")
                self.assertEqual(cov["overrides"]["clamped"], 0)

    def test_07_above_ceiling_is_clamped_even_with_a_rung(self):
        b = _bundle_07()
        secret_reason = "do-not-echo-this-agent-text"
        f = {"id": "TST-ceiling", "code": "TST-A1D", "severity": "HIGH",
             "domain": "TST", "severity_override": {
                 "from": "LOW", "to": "HIGH", "reason": secret_reason,
                 "rung": "raise_when[0]"}}
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "MEDIUM")
        self.assertEqual(f["severity_override"]["to"], "MEDIUM")
        self.assertEqual(cov["overrides"],
                         {"count": 1, "up": 1, "down": 0,
                          "clamped": 1, "missing": 0})
        self.assertIn("TST-ceiling: severity override HIGH clamped to MEDIUM", stderr.getvalue())
        self.assertNotIn(secret_reason, stderr.getvalue())

    def test_07_raise_without_rung_is_clamped_to_default(self):
        b = _bundle_07()
        f = {"id": "TST-no-rung", "code": "TST-A1D", "severity": "MEDIUM",
             "domain": "TST", "severity_override": {
                 "from": "LOW", "to": "MEDIUM", "reason": "enforcement matters"}}
        cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "LOW")
        self.assertEqual(f["severity_override"]["to"], "LOW")
        self.assertEqual(cov["overrides"],
                         {"count": 1, "up": 0, "down": 0,
                          "clamped": 1, "missing": 0})

    def test_07_raise_is_clamped_to_highest_cited_rung(self):
        b = _bundle_07()
        f = {"id": "SEC-rung", "code": "SEC-E1B", "severity": "CRITICAL",
             "domain": "SEC", "severity_override": {
                 "from": "MEDIUM", "to": "CRITICAL", "reason": "reachable advisory",
                 "rung": "raise_when[0]"}}
        cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["severity_override"]["to"], "HIGH")
        self.assertEqual(cov["overrides"]["clamped"], 1)

    def test_07_lower_without_rung_or_modifier_reverts_to_default(self):
        b = _bundle_07()
        f = {"id": "ACC-no-rung", "code": "ACC-A1A", "severity": "MEDIUM",
             "domain": "ACC", "severity_override": {
                 "from": "HIGH", "to": "MEDIUM", "reason": "secondary control"}}
        cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["severity_override"]["to"], "HIGH")
        self.assertEqual(cov["overrides"]["clamped"], 1)

    def test_07_cited_lower_rung_is_honoured(self):
        b = _bundle_07()
        condition = (b["domains"]["ACC"]["entries"]["ACC-A1A"]
                     ["severity_range"]["lower_when"][0]["condition"])
        for rung in ("lower_when[0]", condition):
            with self.subTest(rung=rung):
                f = {"id": "ACC-rung", "code": "ACC-A1A", "severity": "MEDIUM",
                     "domain": "ACC", "severity_override": {
                         "from": "HIGH", "to": "MEDIUM",
                         "reason": "duplicate named control", "rung": rung}}
                cov = codes_mod.apply_verdict_quality([f], {}, b)
                self.assertEqual(f["severity"], "MEDIUM")
                self.assertEqual(f["severity_override"]["to"], "MEDIUM")
                self.assertEqual(cov["overrides"]["clamped"], 0)

    def test_07_below_floor_without_modifier_is_clamped_to_floor(self):
        b = _bundle_07()
        f = {"id": "TST-floor", "code": "TST-A1B", "severity": "INFO",
             "domain": "TST", "severity_override": {
                 "from": "MEDIUM", "to": "INFO",
                 "reason": "the context is test-or-fixture-scope: a small helper",
                 "rung": "lower_when[0]"}}
        cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "LOW")
        self.assertEqual(f["severity_override"]["to"], "LOW")
        self.assertEqual(cov["overrides"],
                         {"count": 1, "up": 0, "down": 1,
                          "clamped": 1, "missing": 0})

    def test_07_controlled_modifier_can_lower_below_floor(self):
        b = _bundle_07()
        f = {"id": "TST-modifier", "code": "TST-A1B", "severity": "INFO",
             "domain": "TST", "severity_override": {
                 "from": "MEDIUM", "to": "INFO",
                 "reason": "test-or-fixture-scope: the helper exists only in a fixture",
                 "rung": "lower_when[0]"}}
        cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "INFO")
        self.assertEqual(f["severity_override"]["to"], "INFO")
        self.assertEqual(cov["overrides"],
                         {"count": 1, "up": 0, "down": 1,
                          "clamped": 0, "missing": 0})

    def test_bundle_absent_missing_reason_override_leaves_severity_no_crash(self):
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "CRITICAL",
             "severity_override": {"from": "MEDIUM", "to": "CRITICAL"}}   # no reason
        cov = codes_mod.apply_verdict_quality([f], {}, None)             # bundle absent
        self.assertEqual(f["severity"], "CRITICAL")          # untouched (default_severity None -> can't revert)
        self.assertNotIn("severity_override", f)          # override still dropped + disclosed
        self.assertNotIn("code_corrections", cov)         # retired with #2101

    def test_backup_confirmed_not_set_for_primary_or_backup_reject(self):
        f1 = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH"}
        codes_mod.apply_verdict_quality(
            [f1], {id(f1): {"verdict": "CONFIRMED", "stage": "primary"}}, _bundle())
        self.assertNotIn("backup_confirmed", f1)          # primary confirm != double-confirm
        f2 = {"id": "SEC-2", "code": "SEC-A1A", "severity": "HIGH"}
        codes_mod.apply_verdict_quality(
            [f2], {id(f2): {"verdict": "REJECTED", "stage": "backup"}}, _bundle())
        self.assertNotIn("backup_confirmed", f2)          # backup reject != confirm

    def test_no_verdict_code_reaches_the_finding(self):
        b = _bundle()
        f1 = {"id": "SEC-1", "code": "SEC-A1A", "severity": "LOW"}          # verdict has no code
        codes_mod.apply_verdict_quality([f1], {id(f1): {"verdict": "CONFIRMED"}}, b)
        self.assertEqual(f1["code"], "SEC-A1A")
        self.assertNotIn("code_corrected_by", f1)
        f2 = {"id": "SEC-2", "code": "SEC-A1A", "severity": "LOW"}          # invalid code
        codes_mod.apply_verdict_quality(
            [f2], {id(f2): {"code": "SEC-ZZZ", "verdict": "CONFIRMED"}}, b)
        self.assertEqual(f2["code"], "SEC-A1A")
        self.assertNotIn("code_corrected_by", f2)
        f3 = {"id": "SEC-3", "code": "SEC-A1A", "severity": "LOW"}          # a real, differing code
        cov = codes_mod.apply_verdict_quality(
            [f3], {id(f3): {"code": "SEC-B2B", "verdict": "CONFIRMED"}}, b)
        self.assertEqual(f3["code"], "SEC-A1A")           # #2101: not even a valid one
        self.assertNotIn("code_corrected_by", f3)
        self.assertNotIn("code_corrections", cov)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# #3754: test-quality, accessibility, CI-hygiene and code-quality findings rated
# CRITICAL. The shipped catalog (0.6.0) has no severity ranges, so an agent's
# claimed severity stood whatever its code. Until 0.7 ships, each of the four
# domains has a ceiling, the highest of its codes' 0.7 ceilings; it applies to the
# domain of a VALID code only. A claim with no code or an unknown one keeps its
# severity (a clamp CRITICAL -> HIGH flips the default gate, and a real injection
# must not be silenced by which cell wrote it up) and is flagged.

def _real_bundle():
    return ocrdb.load_bundle()


def _claim(code=None, severity="CRITICAL", cell="TST", source=None, **more):
    f = {"id": "F-1", "severity": severity, "title": "t", "description": "d",
         "location": {"file": "a.py", "line_start": 1}, "category": "c",
         evidence_mod.CELL_DOMAIN_FIELD: cell, "_group": "app"}
    if code is not None:
        f["code"] = code
    if source is not None:
        f["source"] = source
    f.update(more)
    return f


class TestTheDomainCeiling(unittest.TestCase):
    """The rule, on the shipped catalog."""

    def apply(self, finding, verdict=None):
        with contextlib.redirect_stderr(io.StringIO()):
            codes_mod.apply_verdict_quality([finding], {id(finding): verdict} if verdict else {},
                                            _real_bundle())
        return finding

    def test_the_table_is_the_0_7_catalogue_s_highest_ceiling_per_domain(self):
        # The four domains the issue is about (test quality, accessibility, CI and
        # operations hygiene, code quality), each at its 0.7 codes' highest ceiling.
        top = {}
        for domain, block in _bundle_07()["domains"].items():
            ceilings = [entry["severity_range"]["ceiling"]
                        for entry in block["entries"].values()
                        if isinstance(entry, dict) and isinstance(entry.get("severity_range"), dict)]
            top[domain] = max(ceilings, key=lambda s: codes_mod._SEV_ORDINAL[s])
        self.assertEqual({"TST": "HIGH", "ACC": "HIGH", "OPS": "HIGH", "QAL": "MEDIUM"},
                         ocrdb.DOMAIN_CEILINGS)
        self.assertEqual({domain: top[domain] for domain in ocrdb.DOMAIN_CEILINGS},
                         ocrdb.DOMAIN_CEILINGS)
        # Only domains whose codes stop below CRITICAL can have a ceiling at all.
        self.assertNotIn("CRITICAL", ocrdb.DOMAIN_CEILINGS.values())

    def test_the_shipped_catalogue_has_no_ranges(self):
        # Why the table exists. When this fails, 0.7 has shipped and the table goes.
        bundle = _real_bundle()
        self.assertEqual("0.6.0", ocrdb.BUNDLE_VERSION)
        self.assertFalse([code for block in bundle["domains"].values()
                          for code, entry in block["entries"].items()
                          if ocrdb.severity_range(bundle, code)])

    def test_a_coded_claim_above_its_domain_s_ceiling_is_lowered_and_says_so(self):
        for code, claimed, ceiling in (("TST-A1B", "CRITICAL", "HIGH"),
                                       ("TST-A1B", "HIGH", None),
                                       (_first_code("ACC"), "CRITICAL", "HIGH"),
                                       (_first_code("OPS"), "CRITICAL", "HIGH"),
                                       (_first_code("QAL"), "HIGH", "MEDIUM"),
                                       (_first_code("QAL"), "CRITICAL", "MEDIUM"),
                                       (_first_code("QAL"), "MEDIUM", None)):
            with self.subTest(code=code, claimed=claimed):
                f = self.apply(_claim(code, claimed))
                if ceiling is None:
                    self.assertEqual(claimed, f["severity"])
                    self.assertNotIn("severity_ceiling", f)
                else:
                    self.assertEqual(ceiling, f["severity"])
                    self.assertEqual({"from": claimed, "domain": code[:3], "ceiling": ceiling},
                                     f["severity_ceiling"])
                self.assertNotIn("severity_outside_range", f)

    def test_the_record_says_the_severity_the_discipline_left(self):
        # A reasonless override resets a claim to its code's default; when that
        # default is above the ceiling, the record's `from` is the default, not the
        # claim. (No shipped code has such a default: a synthetic catalog.)
        bundle = {"domains": {"TST": {"entries": {"TST-Z9Z": {"default_severity": "CRITICAL"}}}}}
        f = _claim("TST-Z9Z", "LOW", severity_override={"from": "LOW", "to": "LOW"})
        with contextlib.redirect_stderr(io.StringIO()):
            codes_mod.apply_verdict_quality([f], {}, bundle)
        self.assertEqual("HIGH", f["severity"])
        self.assertEqual({"from": "CRITICAL", "domain": "TST", "ceiling": "HIGH"},
                         f["severity_ceiling"])

    def test_a_ceiling_is_not_counted_as_a_missing_override(self):
        f = _claim("TST-A1B", "CRITICAL")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            counts = codes_mod.apply_verdict_quality([f], {}, _real_bundle())
        self.assertEqual(0, counts["overrides"]["missing"])
        self.assertNotIn("without severity_override", err.getvalue())
        self.assertIn("above the TST ceiling", err.getvalue())

    def test_the_code_s_domain_decides_not_the_cell_s(self):
        # A SEC code written up by a TST cell is a SEC claim, and the reverse.
        f = self.apply(_claim("SEC-A2A", "CRITICAL", cell="TST"))
        self.assertEqual("CRITICAL", f["severity"])
        self.assertNotIn("severity_ceiling", f)
        self.assertNotIn("severity_outside_range", f)
        f = self.apply(_claim("TST-A1B", "CRITICAL", cell="SEC"))
        self.assertEqual("HIGH", f["severity"])

    def test_an_override_does_not_lift_a_claim_past_the_ceiling(self):
        f = self.apply(_claim("TST-A1B", "CRITICAL", severity_override={
            "from": "MEDIUM", "to": "CRITICAL", "reason": "the suite guards payments"}))
        self.assertEqual("HIGH", f["severity"])
        self.assertEqual("CRITICAL", f["severity_ceiling"]["from"])

    def test_the_merge_ranks_by_the_same_answer(self):
        # #3727: one decision, read by the merge before anything is applied.
        self.assertEqual("HIGH", codes_mod.severity_after_discipline(
            _claim("TST-A1B", "CRITICAL"), _real_bundle()))

    def test_an_uncoded_claim_keeps_its_severity_and_is_flagged(self):
        for code in (None, "TST-ZZZ", "NOPE", 7):
            with self.subTest(code=code):
                f = self.apply(_claim(code, "CRITICAL", cell="TST"))
                self.assertEqual("CRITICAL", f["severity"])
                self.assertNotIn("severity_ceiling", f)
                self.assertEqual({"domain": "TST", "ceiling": "HIGH"},
                                 f["severity_outside_range"])
        f = self.apply(_claim(None, "HIGH", cell="QAL"))
        self.assertEqual(("HIGH", {"domain": "QAL", "ceiling": "MEDIUM"}),
                         (f["severity"], f["severity_outside_range"]))

    def test_nothing_is_flagged_at_or_under_the_ceiling_or_outside_the_four(self):
        for cell, severity in (("TST", "HIGH"), ("QAL", "MEDIUM"), ("SEC", "CRITICAL"),
                               ("COD", "CRITICAL"), (None, "CRITICAL"), ("ZZZ", "CRITICAL")):
            with self.subTest(cell=cell, severity=severity):
                f = self.apply(_claim(None, severity, cell=cell))
                self.assertEqual(severity, f["severity"])
                self.assertNotIn("severity_outside_range", f)

    def test_a_scanner_finding_is_untouched(self):
        for code in ("TST-A1B", None):
            with self.subTest(code=code):
                f = self.apply(_claim(code, "CRITICAL", source="tool:semgrep"))
                self.assertEqual("CRITICAL", f["severity"])
                self.assertNotIn("severity_ceiling", f)
                self.assertNotIn("severity_outside_range", f)

    def test_the_0_7_ranges_still_decide_where_they_exist(self):
        # The ceiling never raises, and inside a range it is never lower than it.
        b = _bundle_07()
        f = _claim("TST-A1B", "CRITICAL")
        with contextlib.redirect_stderr(io.StringIO()):
            codes_mod.apply_verdict_quality([f], {}, b)
        self.assertLessEqual(codes_mod._SEV_ORDINAL[f["severity"]],
                             codes_mod._SEV_ORDINAL["HIGH"])


def _first_code(domain):
    return sorted(_real_bundle()["domains"][domain]["entries"])[0]


class TestTheReportSaysSo(unittest.TestCase):
    """End to end: the gate, the letter and what the operator reads."""

    def run_synth(self, claims, cell="TST", extra=()):
        import scripts.synthesize as syn
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "findings-app-%s.json" % cell)
            with open(fp, "w", encoding="utf-8") as fh:
                json.dump({"findings": claims}, fh)
            out = os.path.join(d, "r.json")
            self.stdout, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(err):
                self.rc = syn.main(["--repo", "--target", "src", "--gate-unverified",
                                    "--fail-on", "critical", "--out", out, *extra, fp])
            with open(out, encoding="utf-8") as fh:
                self.page = open(out + ".html", encoding="utf-8").read() \
                    if os.path.exists(out + ".html") else ""
                return json.load(fh)

    @staticmethod
    def claim(code=None, severity="CRITICAL", line=3):
        c = {"severity": severity, "title": "copy-pasted docstring %d" % line,
             "description": "the test name says one thing and asserts another",
             "confidence": "CERTAIN", "category": "test_quality",
             "location": {"file": "tests/test_a.py", "line_start": line}}
        if code is not None:
            c["code"] = code
        return c

    def test_a_coded_test_quality_critical_does_not_fail_the_default_gate(self):
        report = self.run_synth([self.claim("TST-A1B")])
        finding, = report["findings"]
        self.assertEqual("HIGH", finding["severity"])
        self.assertEqual({"from": "CRITICAL", "domain": "TST", "ceiling": "HIGH"},
                         finding["severity_ceiling"])
        self.assertEqual({"TST": [finding["id"]]}, report["meta"]["severity_ceiling"])
        self.assertEqual(0, report["summary"]["stats"]["critical"])
        self.assertNotEqual("FAIL", report["summary"]["gate"])
        self.assertIn("**Lowered to the domain's ceiling:** 1", self.stdout.getvalue())
        self.assertIn("above the TST ceiling", self.page)

    def test_an_uncoded_critical_from_a_test_cell_stands_and_is_flagged(self):
        report = self.run_synth([self.claim()])
        finding, = report["findings"]
        self.assertEqual("CRITICAL", finding["severity"])
        self.assertEqual({"domain": "TST", "ceiling": "HIGH"}, finding["severity_outside_range"])
        self.assertEqual([finding["id"]], report["meta"]["severity_outside_range"])
        self.assertEqual("FAIL", report["summary"]["gate"])
        self.assertEqual(1, self.rc)
        self.assertIn("**Rated above the domain's range:** 1", self.stdout.getvalue())
        self.assertIn("above the TST range", self.page)
        self.assertNotIn("severity_ceiling", report["meta"])

    def test_a_security_critical_is_as_it_was(self):
        report = self.run_synth([self.claim("SEC-A2A")], cell="SEC")
        finding, = report["findings"]
        self.assertEqual("CRITICAL", finding["severity"])
        for key in ("severity_ceiling", "severity_outside_range"):
            self.assertNotIn(key, finding)
            self.assertNotIn(key, report["meta"])
        self.assertNotIn("domain's ceiling", self.stdout.getvalue())

    def test_the_schema_describes_all_three(self):
        import jsonschema
        import scripts.synth.validate_schema as validate_schema_mod
        schema = json.loads((Path(validate_schema_mod.REFERENCE_DIR)
                             / validate_schema_mod.REPORT_SCHEMA).read_text(encoding="utf-8"))
        jsonschema.validate(self.run_synth([self.claim("TST-A1B"), self.claim(line=9)]), schema)


class TestTheAdvisorAssessesSeverityOnRecord(unittest.TestCase):
    """#3754, record-only in 5.5: the domain advisor judges whether a CRITICAL or
    HIGH claim's severity fits. Its assessment is shown beside the finding and
    changes nothing."""

    def bound(self, verdict, finding=None):
        f = finding or _claim("SEC-A2A", "CRITICAL", cell="SEC")
        evidence_mod.apply_verdict(f, dict({"verdict": "CONFIRMED", "reasoning": "r"}, **verdict))
        with contextlib.redirect_stderr(io.StringIO()):
            codes_mod.apply_verdict_quality([f], {id(f): verdict}, _real_bundle())
        return f

    def test_it_is_recorded_and_applies_nothing(self):
        for word in ("CONFIRMED", "REJECTED", "NEEDS_MORE_INFO"):
            with self.subTest(word=word):
                f = self.bound({"verdict": word, "severity_assessed": {
                    "severity": "MEDIUM", "reason": "reachable only from an admin CLI"}})
                self.assertEqual("CRITICAL", f["severity"])
                self.assertEqual({"severity": "MEDIUM",
                                  "reason": "reachable only from an admin CLI"},
                                 f["severity_assessed"])

    def test_a_malformed_assessment_is_no_assessment(self):
        for value in (None, "MEDIUM", {"severity": "MEDIUM"}, {"reason": "r"},
                      {"severity": "medium", "reason": "r"}, {"severity": "SEVERE", "reason": "r"},
                      {"severity": "MEDIUM", "reason": ""}, {"severity": "MEDIUM", "reason": 3},
                      ["MEDIUM", "r"]):
            with self.subTest(value=value):
                self.assertNotIn("severity_assessed", self.bound({"severity_assessed": value}))
        self.assertNotIn("severity_assessed", self.bound({}))

    def test_the_reason_is_bounded_and_one_line(self):
        f = self.bound({"severity_assessed": {"severity": "LOW",
                                              "reason": "line one\nline two " + "x" * 900}})
        reason = f["severity_assessed"]["reason"]
        self.assertNotIn("\n", reason)
        self.assertEqual(evidence_mod.SEVERITY_ASSESSED_REASON_MAX, len(reason))
        self.assertEqual(400, evidence_mod.SEVERITY_ASSESSED_REASON_MAX)
        self.assertTrue(reason.startswith("line one"))

    def test_a_scanner_finding_takes_no_assessment(self):
        f = self.bound({"severity_assessed": {"severity": "LOW", "reason": "r"}},
                       finding=_claim(None, "CRITICAL", source="tool:semgrep"))
        self.assertNotIn("severity_assessed", f)

    def test_the_page_shows_it_beside_the_finding(self):
        import scripts.html_report as html_report
        f = self.bound({"severity_assessed": {"severity": "MEDIUM", "reason": "admin only"}})
        f["evidence"] = {"status": "advisor_confirmed"}
        card = html_report._render_card(f)
        self.assertIn("Advisor's severity", card)
        self.assertIn("MEDIUM", card)
        self.assertIn("admin only", card)

    def test_the_prompt_asks_and_every_advisor_schema_carries_the_field(self):
        root = Path(__file__).resolve().parents[1] / "skill"
        prompt = (root / "agents" / "domain-advisor.md").read_text(encoding="utf-8")
        self.assertIn("severity_assessed", prompt)
        self.assertIn("is recorded beside the finding and changes nothing", prompt)
        receipt = json.loads((root / "reference" / "advisor-verdict-schema.json")
                             .read_text(encoding="utf-8"))
        node = receipt["properties"]["severity_assessed"]
        self.assertEqual(["reason", "severity"], sorted(node["required"]))
        for name in ("verify-primary-generation-schema.json",
                     "verify-backup-generation-schema.json"):
            with self.subTest(schema=name):
                strict = json.loads((root / "reference" / name).read_text(encoding="utf-8"))
                shapes = [k for k in strict["$defs"] if k.startswith("verdict") and k != "verdict_value"]
                self.assertIn("verdict", shapes)
                for shape in shapes:
                    items = strict["$defs"][shape]
                    self.assertIn("severity_assessed", items["required"], shape)
                    self.assertIn("null", json.dumps(items["properties"]["severity_assessed"]))
        # A strict host writes null when it has nothing to say; the receipt takes it.
        import jsonschema
        verdict = {"finding_id": "F", "verdict": "CONFIRMED", "confidence": "CERTAIN",
                   "reasoning": "r", "explored": [], "references": [], "citations": {}}
        for value in (None, {"severity": "LOW", "reason": "r"}):
            jsonschema.validate(dict(verdict, severity_assessed=value), receipt)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(dict(verdict, severity_assessed={"severity": "LOW"}), receipt)

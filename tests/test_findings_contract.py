"""#1513 / Codex BR-03: one runtime acceptance rule for the findings contract.

The defect was three shallow checks that each accepted `findings: [null]` --
the driver's completion predicate, resume's done-predicate, and direct
synthesis -- so a reviewer that returned garbage was indistinguishable from one
that found nothing. Fixing any single site leaves the others able to certify
invalid input, which is why the rule lives in one place and all three use it.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import scripts.findings_contract as fc
import scripts.group_runner as gr
import scripts.phases.review as review
import scripts.synth.coverage_io as coverage_io
import scripts.synth.findings as findings_mod
import scripts.synth.integrity as integrity_mod
import scripts.synthesize as syn
import shutil
from tests._test_helpers import write_host_evidence
from scripts import hosts
import scripts.phases.runio as runio
import scripts.phases.requests as requests


class PayloadDefectsTest(unittest.TestCase):
    def test_cell_of_rejects_invalid_names_and_preserves_hyphenated_groups(self):
        for name in ("report-A-SEC.json", "findings-A-SEC.txt", "findings-A.json",
                     "findings--SEC.json", "findings-A-.json"):
            with self.subTest(name=name):
                self.assertIsNone(fc.cell_of(name))
        self.assertEqual(fc.cell_of("findings-app-web-SEC.json"), ["app-web", "SEC"])
        self.assertEqual(fc.cell_of(Path("/tmp/findings-app-web-SEC.json")),
                         ["app-web", "SEC"])

    def test_a_stamped_empty_review_is_acceptable(self):
        # The outcome the pipeline hopes for: the reviewer ran and found nothing.
        self.assertEqual(fc.payload_defects({"findings": []}), [])

    def test_findings_of_objects_are_acceptable(self):
        self.assertEqual(fc.payload_defects({"findings": [{"title": "x"}]}), [])

    def test_a_null_element_is_a_defect(self):
        defects = fc.payload_defects({"findings": [None]})
        self.assertEqual(len(defects), 1)
        self.assertEqual(defects[0]["index"], 0)
        self.assertIn("NoneType", defects[0]["reason"])

    def test_every_non_object_element_is_named_with_its_index(self):
        # "mixed valid/invalid" must not read as wholly completed, and the
        # report has to be able to say WHICH entries were dropped.
        defects = fc.payload_defects(
            {"findings": [{"title": "real"}, "a string", 42, {"title": "also real"}]})
        self.assertEqual([d["index"] for d in defects], [1, 2])
        self.assertIn("str", defects[0]["reason"])
        self.assertIn("int", defects[1]["reason"])

    def test_a_non_object_payload_is_a_defect(self):
        for payload in ([], "x", 3, None):
            defects = fc.payload_defects(payload)
            self.assertEqual(len(defects), 1)
            self.assertIsNone(defects[0]["index"])

    def test_a_missing_or_non_list_findings_key_is_a_defect(self):
        for payload in ({}, {"findings": None}, {"findings": {}}):
            defects = fc.payload_defects(payload)
            self.assertEqual(len(defects), 1, payload)
            self.assertIsNone(defects[0]["index"])

    def test_is_acceptable_mirrors_the_defect_list(self):
        self.assertTrue(fc.is_acceptable({"findings": [{"t": 1}]}))
        self.assertFalse(fc.is_acceptable({"findings": [None]}))


class OneCellIdentityParserTest(unittest.TestCase):
    """ARC-3899903550 (#1765): every reader of the cell-file name must give the
    same answer, because the four that parsed it independently disagreed.

    `cell_of` did not validate the domain, `present_cells` and
    `integrity._expected_from_filename` did, and `synth/findings.GROUP_RE`
    accepted the retired 4.x `-panel_review` / `-lens_sweep-<lens>` suffixes and
    the panel names beside the domain codes. The consequential disagreement was
    an off-roster or mistyped domain: ingest stamped no `_group`, the mislabel
    guard said "nothing wrong", the floor audit could not see the cell -- and
    the defect diagnostic claimed a cell for it anyway. Every branch failed
    toward invisible, in four different directions.
    """

    # The triage probe table, plus a hyphenated group, a hyphenated group with a
    # lowercase domain, a missing domain and a non-findings name. `None` means
    # "this name identifies no cell", which every reader must agree on.
    CASES = (
        ("findings-App-SEC.json", ("App", "SEC")),
        ("findings-App-XYZ.json", None),
        ("findings-App-security-panel_review.json", None),
        ("findings-App-SEC-lens_sweep-foo.json", None),
        ("findings-App-sec.json", None),
        ("findings-a-b-SEC.json", ("a-b", "SEC")),
        ("findings-a-b-sec.json", None),
        ("findings-App.json", None),
        ("groups.json", None),
    )

    def _ingested_group(self, name):
        """The `_group` ingest stamps on a finding read out of a file so named."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, name)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"findings": [{"severity": "LOW", "panel": "code"}]}, fh)
            with contextlib.redirect_stderr(io.StringIO()):
                loaded = findings_mod.load_findings([path])
        self.assertEqual(len(loaded), 1, name)
        return loaded[0].get("_group")

    def test_every_reader_of_the_name_agrees_on_the_cell(self):
        for name, cell in self.CASES:
            with self.subTest(name=name):
                self.assertEqual(fc.cell_of(name), list(cell) if cell else None)
                self.assertEqual(coverage_io.present_cells([name]),
                                 {cell[0]: {cell[1]}} if cell else {})
                self.assertEqual(integrity_mod._expected_from_filename(name), cell)
                self.assertEqual(self._ingested_group(name),
                                 cell[0] if cell else None)

    def test_a_dropped_off_roster_file_is_named_without_a_cell(self):
        # Validating the domain must not cost the diagnostic its subject: a file
        # whose trailing token is no OCRDb domain names no cell, but the operator
        # still has to be told the file was dropped.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "findings-App-XYZ.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"findings": [None]}, fh)
            with contextlib.redirect_stderr(io.StringIO()):
                _kept, diagnostics = findings_mod.load_findings_detailed([path])
                malformed = integrity_mod.malformed_findings_files([path])
        self.assertEqual([entry["file"] for entry in diagnostics], [path])
        self.assertIsNone(diagnostics[0]["cell"])
        self.assertEqual([entry["file"] for entry in malformed], [path])
        self.assertIsNone(malformed[0]["cell"])


class SharedAcceptanceTest(unittest.TestCase):
    """The three sites the issue names must agree, or the weakest one decides."""

    PAYLOAD = {"findings": [None],
               "_panopticon": {"run_id": "RID", "role": "domain_panel",
                               "domain": "SEC", "group": "App"}}

    def _cell(self, d):
        path = os.path.join(d, "findings-App-SEC.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.PAYLOAD, fh)
        return path

    def test_the_driver_does_not_call_a_null_cell_complete(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "findings-App-SEC.json"),
                      "w", encoding="utf-8") as fh:
                json.dump(self.PAYLOAD, fh)
            self.assertFalse(review._cell_done(d, {"run_id": "RID"}, "App", "SEC"))

    def test_resume_does_not_call_a_null_cell_done(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(gr.entry_is_done(self._cell(d)))

    def test_direct_synthesis_reports_the_dropped_entry(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._cell(d)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                findings, diagnostics = findings_mod.load_findings_detailed([path])
        self.assertEqual(findings, [])
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0]["file"], path)
        self.assertEqual(diagnostics[0]["cell"], ["App", "SEC"])
        self.assertIn("NoneType", diagnostics[0]["defects"][0]["reason"])

    def test_salvageable_findings_survive_a_partly_bad_file(self):
        # Dropping the real findings too would destroy evidence to punish a
        # protocol error. The file is recorded as defective AND its usable
        # findings are still reported -- an incomplete report, not an empty one.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "findings-App-SEC.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"findings": [
                    {"title": "real", "severity": "HIGH", "domain": "SEC",
                     "code": "SEC-A1A", "category": "x",
                     "location": {"file": "a.py", "line_start": 1}}, None]}, fh)
            with contextlib.redirect_stderr(io.StringIO()):
                findings, diagnostics = findings_mod.load_findings_detailed([path])
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(diagnostics), 1)

    def test_load_findings_keeps_its_list_return(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._cell(d)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(findings_mod.load_findings([path]), [])


class BoundedRedispatchTest(unittest.TestCase):
    """Rejecting a bad cell without bounding the retry just trades a false
    certification for an infinite loop: review_execute recomputes pending from
    _cell_done every invocation, so a reviewer that keeps writing garbage would
    be re-dispatched forever."""

    RUN_ID = "RID"

    def _repo(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("x = 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        # #1344 F3: review_execute's driver-plan write gates on PROVEN
        # evidence now, not the bare claim.
        write_host_evidence(d, {c: hosts.PROVEN for c in hosts.CAPABILITIES})
        runio._write_json(runio._pano(d, "groups.json"),
                          {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n")
            fh.write("groups:\n  app:\n    match: ['src/**']\n")
        runio._write_json(runio._pano(d, "coverage-app.json"),
                          {"group": "app", "floor": ["QAL"], "effective": ["QAL"],
                           "run_id": self.RUN_ID})
        return d, {"run_id": self.RUN_ID, "host": "claude",
                   "security_mode": "standard", "flags": {"fail_on": "high"}}

    def _write_garbage(self, d):
        for e in requests.load_dispatch_request(d)["entries"]:
            runio._write_json(e["out_file"], {
                "findings": [None],
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": "QAL", "group": "app"}})

    def test_a_persistently_bad_cell_stops_being_redispatched(self):
        d, m = self._repo()
        rounds = 0
        while review.review_execute(d, m).kind == "checkpoint":
            rounds += 1
            self._write_garbage(d)
            self.assertLess(rounds, 10, "unbounded redispatch loop")
        self.assertEqual(rounds, review.MAX_CELL_ATTEMPTS)
        # the phase must ADVANCE rather than wedge the run forever...
        self.assertTrue(review.review_done(d, m))
        # ...and the cell must not read as completed work
        self.assertFalse(review._cell_done(d, m, "app", "QAL"))

    def test_a_cell_that_recovers_is_not_penalised(self):
        # The retry exists for the transient case run-11 actually hit: a cell
        # that wrote unparseable JSON once and succeeded on re-dispatch.
        d, m = self._repo()
        self.assertEqual(review.review_execute(d, m).kind, "checkpoint")
        self._write_garbage(d)
        self.assertEqual(review.review_execute(d, m).kind, "checkpoint")
        for e in requests.load_dispatch_request(d)["entries"]:
            runio._write_json(e["out_file"], {
                "findings": [],
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": "QAL", "group": "app"}})
        self.assertEqual(review.review_execute(d, m).kind, "advanced")
        self.assertTrue(review._cell_done(d, m, "app", "QAL"))


class EndToEndCertificationTest(unittest.TestCase):
    """The acceptance's real subject: direct synthesis on a malformed cell must
    not certify. Fixing the driver's done-predicate alone would leave this
    path able to do it."""

    def _report(self, payload):
        with tempfile.TemporaryDirectory() as d:
            run_dir = os.path.join(d, ".panopticon")
            os.makedirs(run_dir)
            with open(os.path.join(run_dir, "coverage-App.json"), "w") as fh:
                json.dump({"group": "App", "floor": ["SEC"], "effective": ["SEC"]}, fh)
            cell = os.path.join(run_dir, "findings-App-SEC.json")
            with open(cell, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            out = os.path.join(d, "r.json")
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = syn.main(["--target", "t", "--run-dir", run_dir,
                               "--fail-on", "high", "--out", out, cell])
            with open(out, encoding="utf-8") as fh:
                return rc, json.load(fh)

    def test_a_null_entry_cell_cannot_certify(self):
        rc, report = self._report({"findings": [None]})
        integ = report["meta"]["integrity"]
        self.assertEqual(len(integ["malformed_findings_files"]), 1)
        entry = integ["malformed_findings_files"][0]
        self.assertEqual(entry["cell"], ["App", "SEC"])
        self.assertIn("NoneType", entry["defects"][0]["reason"])
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")
        self.assertFalse(report["summary"]["coverage_certified"])
        self.assertEqual(rc, 2)
        # the cell was written, so filename presence alone would have called the
        # SEC floor satisfied -- it must read as missing instead
        self.assertEqual(report["meta"]["coverage"]["cells"]["missing_floor"],
                         [["App", "SEC"]])

    def test_a_clean_empty_cell_still_certifies(self):
        rc, report = self._report(
            {"findings": [], "_panopticon": {"role": "domain_panel",
                                             "group": "App", "domain": "SEC"}})
        self.assertEqual(report["meta"]["integrity"]["malformed_findings_files"], [])
        self.assertEqual(report["meta"]["coverage"]["cells"]["missing_floor"], [])
        self.assertNotEqual(report["summary"]["gate"], "INCONCLUSIVE")
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()

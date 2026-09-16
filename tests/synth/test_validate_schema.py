"""Tests for scripts.synth.validate_schema: the published-schema layer (#1639 P15)."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

import scripts.synth.findings as findings_mod
import scripts.synth.report as report_mod
import scripts.synth.validate_schema as validate_schema_mod

from tests.synth.helpers import DEFAULT_TIMESTAMP


def _minimal_report():
    """A real, empty report from the real producer -- not a hand-written dict.

    A hand-written "minimal" report is the thing this module exists to catch,
    so building the baseline by hand would test the fixture rather than the
    schema."""
    return report_mod.build_report(report_mod.ReportInputs(
        run=report_mod.RunConfig(target="src", fail_on=None,
                                 timestamp=DEFAULT_TIMESTAMP),
        findings=findings_mod.FindingSet(findings=[])))


class TestSchemaErrors(unittest.TestCase):
    def test_a_conforming_report_produces_no_errors(self):
        self.assertEqual(validate_schema_mod.schema_errors(_minimal_report()), [])

    def test_null_sections_are_rejected_with_their_json_path(self):
        # Codex's repro (#1639 P15): every top-level key present, three of them
        # null. The hand checks saw five keys and said nothing.
        report = dict(_minimal_report(), meta=None, summary=None, cross_panel=None)
        errors = validate_schema_mod.schema_errors(report)
        self.assertEqual(
            [e.split(":")[1].strip() for e in errors],
            ["$.cross_panel", "$.meta", "$.summary"])

    def test_errors_are_sorted_by_json_path(self):
        # iter_errors' order is unspecified; this text lands in stderr and in
        # a report field, so two runs over the same artifact must agree.
        report = dict(_minimal_report(), meta=None, summary=None, cross_panel=None)
        errors = validate_schema_mod.schema_errors(report)
        self.assertEqual(errors, sorted(errors))

    def test_the_x0x_schema_is_reachable_by_name(self):
        x0x = {"schema_version": 1, "candidates": [],
               "generated_by": {"panopticon_version": "5.2.0", "run_id": "r1"},
               "ocrdb_version": "0.5.0"}
        self.assertEqual(
            validate_schema_mod.schema_errors(x0x, validate_schema_mod.X0X_SCHEMA),
            [])
        self.assertTrue(
            validate_schema_mod.schema_errors({"candidates": []},
                                              validate_schema_mod.X0X_SCHEMA))

    def test_an_undescribed_meta_section_is_rejected(self):
        # #1602 ruling 4: `meta` is closed. This is the whole point of the
        # issue -- `host_capabilities` drifted for a release because an
        # undescribed section validated fine, and a parity test alone would
        # only catch it in CI, not in a run.
        report = _minimal_report()
        report["meta"]["invented_section"] = {"anything": True}
        errors = validate_schema_mod.schema_errors(report)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("invented_section", errors[0])
        self.assertTrue(errors[0].startswith("schema: $.meta:"), errors[0])

    def test_every_key_the_writers_stamp_after_build_is_described(self):
        # The keys written OUTSIDE assemble() -- by the split writer and by
        # attach_schema_status -- are the ones a closed `meta` is most likely
        # to reject by surprise, because they are added after the document
        # validate_report saw.
        report = _minimal_report()
        report["meta"]["parts"] = ["report_part2.json"]
        report["meta"]["discarded_claims_file"] = "report-discarded.json"
        report["meta"]["discarded_claims_count"] = 3
        report["meta"]["schema_errors"] = 0
        self.assertEqual(validate_schema_mod.schema_errors(report), [])

    def test_a_missing_jsonschema_fails_closed(self):
        # `sys.modules[name] = None` is what Python itself raises ImportError
        # on, so this is the real import path, not a stubbed-out branch.
        with mock.patch.dict(sys.modules, {"jsonschema": None}):
            errors = validate_schema_mod.schema_errors(_minimal_report())
        self.assertEqual(
            errors,
            ["schema: jsonschema not installed — report schema not validated"])

    def test_an_unreadable_schema_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "report-schema.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            errors = validate_schema_mod.schema_errors(_minimal_report(),
                                                       schema_path=path)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("report-schema.json unreadable", errors[0])
        self.assertIn("report schema not validated", errors[0])

    def test_an_absent_schema_file_fails_closed(self):
        errors = validate_schema_mod.schema_errors(
            _minimal_report(), schema_path="/nonexistent/report-schema.json")
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("report schema not validated", errors[0])

    def test_the_reference_dir_is_the_shipped_one(self):
        # A wrong REFERENCE_DIR would fail closed on every call, which is safe
        # but useless; pin that it resolves onto the real shipped contracts.
        for name in (validate_schema_mod.REPORT_SCHEMA,
                     validate_schema_mod.X0X_SCHEMA):
            path = os.path.join(validate_schema_mod.REFERENCE_DIR, name)
            self.assertTrue(os.path.isfile(path), path)
            with open(path, encoding="utf-8") as fh:
                self.assertIn("$schema", json.load(fh))


if __name__ == "__main__":
    unittest.main()

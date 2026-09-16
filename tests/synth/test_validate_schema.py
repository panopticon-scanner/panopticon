"""Tests for scripts.synth.validate_schema: the published-schema layer (#1639 P15)."""
import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

import scripts.synth.findings as findings_mod
import scripts.synth.report as report_mod
import scripts.synth.validate_schema as validate_schema_mod

import scripts.synthesize as synthesize

from tests.synth.helpers import DEFAULT_TIMESTAMP, _chdir


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


def _probe_finding():
    """The ordinary agent finding every probe patches one field of."""
    return {"id": "SE-001", "title": "sqli", "severity": "MEDIUM",
            "confidence": "LIKELY", "panel": "code", "category": "injection",
            "location": {"file": "a.py", "line_start": 1}}


def _synthesize_one(patch):
    """(rc, report, stderr) for one agent finding through the real main()."""
    finding = _probe_finding()
    finding.update(patch)
    with tempfile.TemporaryDirectory() as d, _chdir(d):
        path = os.path.join(d, "findings-g1-code.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"findings": [finding]}, fh)
        out = os.path.join(d, "report.json")
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(err):
            try:
                rc = synthesize.main(["--target", "src", "--out", out, path])
            except Exception as exc:      # a crash is a failure with a reason
                return -1, {"findings": [{}]}, "%r\n%s" % (exc, err.getvalue())
        with open(out, encoding="utf-8") as fh:
            return rc, json.load(fh), err.getvalue()


_MISSING = object()


def _valid_finding():
    return {"id": "SE-001", "title": "t", "severity": "HIGH", "confidence": "LIKELY",
            "panel": "security", "category": "injection",
            "evidence": {"status": "unverified"}}


# An UNHASHABLE value is always among them (fix round 3, R2-3). One probe value
# per node, and a string for every enum node, is what let `panel` keep a false
# ownership claim for two rounds: its normalizer is a SET membership test, so
# only a dict or a list reaches the TypeError, and the generator could not
# produce one.
_UNHASHABLE = ({"a": 1}, [1])


def _values_the_schema_rejects(node):
    """Several deliberately wrong values for one pinned subschema.

    At least two, always including an unhashable container: a normalizer that
    survives `"wrong"` and raises on `{"a": 1}` has not normalized anything.
    """
    if "enum" in node:
        return ["not-in-this-vocabulary"] + list(_UNHASHABLE)
    types = node.get("type")
    types = [] if types is None else (types if isinstance(types, list) else [types])
    if "string" in types:
        return list(_UNHASHABLE)
    if "integer" in types or "number" in types:
        return ["not a number"] + list(_UNHASHABLE)
    if "boolean" in types:
        return ["yes"] + list(_UNHASHABLE)
    if "array" in types:
        return [{"not": "a list"}, "not a list"]
    if "object" in types:
        return ["not an object", [1]]
    return []


# How each `_OWNED_DOWNSTREAM` entry is checked. The declared owner is asked for
# the value it would produce and the ARTIFACT must carry exactly that: "not the
# agent's value" is not the claim the entry makes, and an owned field that was
# simply DROPPED passed the old `assertNotEqual` (`citations` did, for a round).
# Two fields are genuinely run-dependent -- a content hash and a generated id --
# and for those the assertion is presence plus the pinned type.
_OWNED_BY_NORMALIZER = ("severity", "confidence", "title", "short_title")
_OWNED_RUN_DEPENDENT = ("id", "fingerprint")


class TestEveryPinnedFieldIsRepairedOrOwned(unittest.TestCase):
    """#1639 P15 C1: the drift guard for the principle itself.

    The principle only holds if EVERY type the schema pins on a finding is
    either normalized at the boundary or owned outright by a controller stage.
    A field that is neither is a lever an agent can pull to end a run, and the
    next one would be added in silence -- the failure mode #1602 is about.
    This reads the schema, never a copy of it.
    """

    def setUp(self):
        self.item = validate_schema_mod.finding_item_schema()
        self.assertTrue(self.item.get("properties"), "findings item schema not loaded")

    def test_every_pinned_field_survives_a_wrong_typed_agent_value(self):
        """The drift guard for the principle, through the REAL pipeline.

        One mechanism for both halves (fix round 2, F5): inject a value the
        schema rejects and run the actual `synthesize.main()`. A field that is
        REPAIRED must not end the run; a field declared owned must additionally
        come out carrying the controller's answer rather than the agent's.
        Round 1 ran the probe through `normalize_finding` alone and `continue`d
        on owned fields, which is why two false ownership claims shipped: a
        stage that runs later (`derive_evidence`) or only sometimes
        (`classify_findings`) is invisible to a boundary-only probe.
        """
        owned = validate_schema_mod._OWNED_DOWNSTREAM
        self.assertEqual(sorted(owned),
                         sorted(_OWNED_BY_NORMALIZER + _OWNED_RUN_DEPENDENT),
                         "an owned field with no check above is an unproven claim: "
                         "say how the controller's value for it is established")
        for name, node in sorted(self.item["properties"].items()):
            for bad in _values_the_schema_rejects(node):
                with self.subTest(field=name, value=repr(bad)):
                    rc, report, err = _synthesize_one({name: bad})
                    self.assertEqual(
                        rc, 0,
                        "an agent %s of %r ended the run (rc=%s): %s\nRepair it "
                        "at a boundary, or declare it in _OWNED_DOWNSTREAM with "
                        "the stage that owns it." % (name, bad, rc, err))
                    if name not in owned:
                        continue
                    got = report["findings"][0].get(name, _MISSING)
                    if name in _OWNED_BY_NORMALIZER:
                        probe = _probe_finding()
                        probe[name] = copy.deepcopy(bad)
                        want = findings_mod.normalize_finding(probe).get(name)
                        self.assertEqual(
                            got, want,
                            "%s: the artifact carries %r, but %s -- the stage "
                            "_OWNED_DOWNSTREAM names -- answers %r. Ownership "
                            "means the controller's value reaches the report."
                            % (name, got, owned[name].split(" ")[0], want))
                    else:
                        self.assertIsNot(got, _MISSING,
                                         "%s is absent from the artifact: dropped "
                                         "is not owned" % name)
                        self.assertTrue(
                            validate_schema_mod._conforms(got, node),
                            "%s came out as %r, which the schema still rejects"
                            % (name, got))
                        self.assertNotEqual(got, bad, name)

    def test_every_owned_field_still_exists_and_says_who_owns_it(self):
        for name, reason in sorted(validate_schema_mod._OWNED_DOWNSTREAM.items()):
            with self.subTest(field=name):
                self.assertIn(name, self.item["properties"],
                              "%s is no longer in the schema -- drop the entry" % name)
                self.assertGreater(len(reason), 20, name)

    def test_a_repair_announces_itself(self):
        finding = _valid_finding()
        finding["references"] = "CWE-89"
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            validate_schema_mod.repair_finding(finding)
        self.assertEqual(finding["references"], ["CWE-89"])
        self.assertIn("repaired references", err.getvalue())

    def test_a_drop_announces_itself(self):
        finding = _valid_finding()
        finding["depth"] = "profound"
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            validate_schema_mod.repair_finding(finding)
        self.assertNotIn("depth", finding)
        self.assertIn("dropped depth", err.getvalue())

    def test_a_bare_cvss_score_is_kept_not_discarded(self):
        # The one repair that is more than a type cast: `cvss: 7.5` says
        # something real, and dropping it would lose a reviewer's judgement
        # AND trip the CVSS-required rule for a security HIGH.
        finding = _valid_finding()
        finding["cvss"] = 7.5
        with contextlib.redirect_stderr(io.StringIO()):
            validate_schema_mod.repair_finding(finding)
        self.assertEqual(finding["cvss"], {"score": 7.5})

    def test_a_location_file_is_dropped_rather_than_invented(self):
        # str(7) would be a fabricated path, and location.file drives on-diff
        # classification and group attribution.
        finding = _valid_finding()
        finding["location"] = {"file": 7, "line_start": 3}
        with contextlib.redirect_stderr(io.StringIO()):
            validate_schema_mod.repair_finding(finding)
        self.assertNotIn("location", finding)

    def test_an_unreadable_schema_makes_repair_a_no_op_not_a_crash(self):
        finding = _valid_finding()
        finding["depth"] = "profound"
        with mock.patch.object(validate_schema_mod, "finding_item_schema",
                               return_value={}):
            with contextlib.redirect_stderr(io.StringIO()):
                validate_schema_mod.repair_finding(finding)
        self.assertEqual(finding["depth"], "profound")   # untouched, never raised


if __name__ == "__main__":
    unittest.main()


class TestRepairToolsSanitized(unittest.TestCase):
    """#1646: `tools-manifest.json` is TARGET-WRITABLE, and its `sanitized`
    block now reaches the report (`meta.tools.sanitized`) and the HTML.

    The principle #1639 P15 established applies unchanged: the schema pins the
    CONTROLLER's output, so a target-sourced input is normalized to the pinned
    types at its boundary. A hostile manifest must cost a warning and the
    malformed rows, never the run and never an `artifact invalid` exit.
    """

    def _repair(self, value):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            got = validate_schema_mod.repair_tools_sanitized(value)
        return got, err.getvalue()

    def test_a_well_formed_block_passes_through(self):
        block = {"pip-audit": {"source": "requirements.txt", "kept": 2,
                               "dropped": [{"line": "-e .", "reason": "editable"}],
                               "hashes_stripped": True}}
        got, err = self._repair(block)
        self.assertEqual(got, block)
        self.assertEqual(err, "")

    def test_a_non_object_block_reads_as_nothing_measured(self):
        for bad in ("[]", [], 7, None, "pip-audit"):
            with self.subTest(value=repr(bad)):
                got, _err = self._repair(bad)
                self.assertEqual(got, {})

    def test_a_non_object_row_is_dropped_with_a_warning(self):
        got, err = self._repair({"pip-audit": ["-e ."]})
        self.assertEqual(got, {})
        self.assertIn("pip-audit", err)

    def test_a_non_string_tool_name_is_dropped(self):
        got, _err = self._repair({7: {"kept": 1}})
        self.assertEqual(got, {})

    def test_wrongly_typed_fields_are_dropped_not_coerced_into_a_lie(self):
        got, err = self._repair({"pip-audit": {
            "source": {"nested": "object"}, "kept": "lots",
            "hashes_stripped": "yes", "dropped": "everything"}})
        self.assertEqual(got, {"pip-audit": {}})
        for field in ("source", "kept", "hashes_stripped", "dropped"):
            self.assertIn(field, err)

    def test_a_boolean_kept_is_not_an_integer(self):
        # True == 1 in Python but `jsonschema` does not accept a bool where an
        # integer is pinned, so an unrepaired True would fail the ARTIFACT.
        got, _err = self._repair({"pip-audit": {"kept": True}})
        self.assertEqual(got, {"pip-audit": {}})

    def test_malformed_dropped_rows_are_dropped_row_by_row(self):
        got, _err = self._repair({"pip-audit": {"dropped": [
            {"line": "-e .", "reason": "editable"},
            {"line": 7, "reason": "editable"},
            "not a row",
            {"line": "./x"},
        ]}})
        self.assertEqual(got, {"pip-audit": {
            "dropped": [{"line": "-e .", "reason": "editable"}]}})

    def test_an_unknown_field_inside_a_row_is_dropped(self):
        # `meta` is closed and the parity walk is stricter still: a key the
        # schema does not describe must not ride into the artifact.
        got, _err = self._repair({"pip-audit": {"kept": 1, "surprise": "x"}})
        self.assertEqual(got, {"pip-audit": {"kept": 1}})

    def test_the_two_bound_disclosures_survive_the_repair(self):
        # #1646 fix round 1: `truncated` and `dropped_truncated` say the
        # disclosure itself was capped. Dropping them would turn a bounded
        # answer back into one that reads as complete.
        block = {"pip-audit": {"source": "requirements.txt", "kept": 1,
                               "dropped": [], "hashes_stripped": False,
                               "truncated": True, "dropped_truncated": 300}}
        got, err = self._repair(block)
        self.assertEqual(got, block)
        self.assertEqual(err, "")

    def test_wrongly_typed_bound_disclosures_are_dropped(self):
        got, err = self._repair({"pip-audit": {"truncated": "yes",
                                               "dropped_truncated": True}})
        self.assertEqual(got, {"pip-audit": {}})
        self.assertIn("truncated", err)
        self.assertIn("dropped_truncated", err)

    def test_a_hostile_manifest_never_makes_the_artifact_invalid(self):
        report = _minimal_report()
        report["meta"]["tools"]["sanitized"] = validate_schema_mod.\
            repair_tools_sanitized({"pip-audit": {"kept": "lots",
                                                  "dropped": [{"line": None}]}},
                                   warn=lambda _m: None)
        self.assertEqual(validate_schema_mod.schema_errors(report), [])


class TestRepairToolsNetwork(unittest.TestCase):
    """#1645: `tools-manifest.json`'s `network` block reaches the report
    (`meta.tools.network`) and the HTML, and the manifest is TARGET-WRITABLE.

    Same principle as `sanitized` beside it: the schema pins the CONTROLLER's
    output, so a target-sourced input is normalized to the pinned types at its
    boundary. A hostile manifest costs a warning and the malformed rows, never
    the run and never an `artifact invalid` exit.
    """

    def _repair(self, value):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            got = validate_schema_mod.repair_tools_network(value)
        return got, err.getvalue()

    def test_a_well_formed_block_passes_through(self):
        block = {"semgrep": "none", "pip-audit": "proxied:pypi.org"}
        got, err = self._repair(block)
        self.assertEqual(got, block)
        self.assertEqual(err, "")

    def test_a_non_object_block_reads_as_nothing_measured(self):
        for bad in ("none", [], 7, None, ["semgrep"]):
            with self.subTest(value=repr(bad)):
                got, _err = self._repair(bad)
                self.assertEqual(got, {})

    def test_a_non_string_posture_is_dropped_not_coerced(self):
        # `{"semgrep": {"network": "none"}}` has no honest string, and
        # stringifying it would publish a posture nobody recorded.
        got, err = self._repair({"semgrep": {"kind": "none"}, "trivy": 7})
        self.assertEqual(got, {})
        self.assertIn("semgrep", err)
        self.assertIn("trivy", err)

    def test_a_non_string_tool_name_is_dropped(self):
        got, _err = self._repair({7: "none"})
        self.assertEqual(got, {})

    def test_a_hostile_posture_string_is_bounded(self):
        # Target-writable text bound for two published artifacts; the report
        # already bounds every other such field, and an unbounded one here
        # would ride a megabyte into the HTML.
        got, _err = self._repair({"semgrep": "x" * 5000})
        self.assertLessEqual(len(got["semgrep"]),
                             validate_schema_mod.NETWORK_POSTURE_MAX)

    def test_a_hostile_manifest_never_makes_the_artifact_invalid(self):
        report = _minimal_report()
        report["meta"]["tools"]["network"] = validate_schema_mod.\
            repair_tools_network({"semgrep": {"deeply": ["nested"]},
                                  "pip-audit": "proxied:pypi.org"},
                                 warn=lambda _m: None)
        self.assertEqual(validate_schema_mod.schema_errors(report), [])

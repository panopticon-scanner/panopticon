"""#2104: the format version of agent findings and verdict records.

The rule (`findings_contract.schema_version_defect`):
- absent reads as version 1;
- exactly the int 1 is supported;
- anything else is refused, fail-closed, with fixed text that never echoes the
  value.

Each case is proved at the boundaries where a record is really admitted or read:
- `persist.write_reply` (return-persist receipt);
- the self-write done predicates (`group_runner.entry_is_done`,
  `review._cell_done`, `persist.is_done`, `verify_tools._valid_verdict_at`);
- synthesis (`synthesize.main`, `load_findings_detailed`, and the two
  `evidence` verdict loaders).

A bundle with one unknown VERDICT version is refused whole at receipt and in the
done predicates, but at synthesis only that verdict is lost. Both halves are
pinned here, so nobody "fixes" one to match the other.
"""
import json
import os
import shutil
import tempfile
import unittest

import scripts.evidence as evidence
import scripts.findings_contract as fc
import scripts.group_runner as group_runner
import scripts.phases.persist as persist
import scripts.phases.review as review
import scripts.phases.runio as runio
import scripts.phases.verify as verify
import scripts.phases.verify_tools as verify_tools
import scripts.synth.findings as findings_mod
import scripts.synth.validate_schema as validate_schema
from tests import test_findings_contract as findings_contract_tests
from tests.phases import test_persist as persist_tests

ABSENT = object()
SUPPORTED = (ABSENT, 1)
# The unknown cases: a future int, values that compare EQUAL to 1 without being
# the int (`1.0`, `True`), and the shapes a model might plausibly emit.
UNKNOWN = (2, 0, -1, 1.0, True, False, "1", None, [1], {"v": 1})
REASON = "unsupported schema_version"
STAMP = {"run_id": "RID", "group": "app", "domain": "SEC"}


def _versioned(record, version):
    record = dict(record)
    if version is not ABSENT:
        record["schema_version"] = version
    return record


def _verdict(finding_id="F1", version=ABSENT):
    return _versioned(persist_tests._advisor_verdict(finding_id), version)


class _Tree(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.d, ignore_errors=True))
        os.makedirs(os.path.join(self.d, ".panopticon", "runs", "t", "verdicts"))

    def _out(self, *parts):
        return os.path.join(self.d, ".panopticon", "runs", "t", *parts)

    def _review_entry(self, **extra):
        return persist_tests._entry(self._out("findings-app-SEC.json"), id="review-app-SEC",
                                    **dict(STAMP, **extra))

    def _tool_entry(self):
        return persist_tests._entry(self._out("verdicts", "q-0001.json"), id="verify-tool-q-0001")

    def _bundle(self, env, version=ABSENT, verdict_versions=None):
        versions = verdict_versions or {}
        return _versioned({"verdicts": [_verdict(i, versions.get(i, ABSENT)) for i in env["ids"]],
                           "_panopticon": dict(STAMP, stage="primary")}, version)


class TheRuleTest(unittest.TestCase):
    def test_absent_and_the_int_one_are_supported_and_nothing_else_is(self):
        for version in SUPPORTED:
            self.assertIsNone(fc.schema_version_defect(_versioned({}, version)), version)
        for version in UNKNOWN:
            self.assertEqual(REASON, fc.schema_version_defect({"schema_version": version}),
                             repr(version))
        self.assertIsNone(fc.schema_version_defect(["schema_version"]))

    def test_a_bundle_is_refused_for_its_own_or_any_verdicts_version(self):
        ok = [{"finding_id": "F1"}, {"finding_id": "F2", "schema_version": 1}]
        self.assertIsNone(fc.bundle_version_defect({"schema_version": 1}, ok))
        self.assertEqual(REASON, fc.bundle_version_defect({"schema_version": 2}, ok))
        self.assertEqual(REASON, fc.bundle_version_defect({}, ok + [{"schema_version": 2}]))

    def test_the_findings_contract_refuses_the_whole_payload(self):
        self.assertEqual([{"index": None, "reason": REASON}],
                         fc.payload_defects({"schema_version": 2, "findings": [{}]}))
        self.assertEqual([], fc.payload_defects({"schema_version": 1, "findings": [{}]}))


class AtReceiptTest(_Tree):
    """`persist.write_reply`: refused before the schema check, so the reason is
    the fixed text and never jsonschema's echo of the value."""

    def _refused(self, entry, body):
        ok, reason = persist.write_reply(entry, json.dumps(body))
        self.assertFalse(ok)
        self.assertEqual("reply for %r rejected: %s" % (entry["id"], REASON), reason)
        self.assertFalse(os.path.exists(entry["out_file"]))

    def test_a_review_reply(self):
        for version in SUPPORTED:
            entry = self._review_entry()
            ok, reason = persist.write_reply(entry, json.dumps(
                _versioned({"findings": [], "_panopticon": STAMP}, version)))
            self.assertTrue(ok, reason)
            os.remove(entry["out_file"])
        for version in UNKNOWN:
            with self.subTest(version=version):
                self._refused(self._review_entry(),
                              _versioned({"findings": [], "_panopticon": STAMP}, version))

    def test_a_tool_verdict(self):
        for version in SUPPORTED:
            entry = self._tool_entry()
            ok, reason = persist.write_reply(entry, json.dumps(_verdict(version=version)))
            self.assertTrue(ok, reason)
            os.remove(entry["out_file"])
        for version in UNKNOWN:
            with self.subTest(version=version):
                self._refused(self._tool_entry(), _verdict(version=version))

    def test_a_verdict_bundle_is_refused_whole_for_one_unknown_verdict(self):
        env = persist_tests._verify_cell(self.d)
        first = env["ids"][0]
        for version in UNKNOWN:
            with self.subTest(version=version):
                self._refused(env["entry"], self._bundle(env, version=version))
                self._refused(env["entry"], self._bundle(env, verdict_versions={first: version}))
        ok, reason = persist.write_reply(env["entry"], json.dumps(
            self._bundle(env, version=1, verdict_versions={first: 1})))
        self.assertTrue(ok, reason)

    def test_the_version_and_the_identity_stamp_are_each_their_own_refusal(self):
        wrong = dict(STAMP, group="other")
        for body, expected in (
                ({"schema_version": 1, "findings": [], "_panopticon": wrong},
                 "_panopticon.group is 'other', the entry is 'app'"),
                ({"schema_version": 2, "findings": [], "_panopticon": STAMP}, REASON),
                ({"schema_version": 2, "findings": [], "_panopticon": wrong}, REASON)):
            entry = self._review_entry()
            ok, reason = persist.write_reply(entry, json.dumps(body))
            self.assertFalse(ok)
            self.assertTrue(reason.endswith(expected), reason)
        # The predicate itself, past the receipt's ordering: each check answers alone.
        entry = self._review_entry()
        self.assertEqual((False, "_panopticon.group is 'other', the entry is 'app'"),
                         persist.accepts(entry, {"findings": [], "_panopticon": wrong}))
        self.assertEqual((False, REASON),
                         persist.accepts(entry, {"schema_version": 2, "findings": [],
                                                 "_panopticon": STAMP}))

    def test_the_version_is_checked_for_an_entry_that_declares_no_identity(self):
        # Beside the stamp, not inside it: an entry naming no cell skips the stamp
        # check entirely, and the version is still refused.
        bare = persist_tests._entry(self._out("findings-app-SEC.json"), id="review-app-SEC")
        self.assertEqual((True, ""), persist.accepts(bare, {"findings": []}))
        self.assertEqual((False, REASON), persist.accepts(bare, {"schema_version": 2, "findings": []}))

    def test_the_controller_fills_the_stamp_and_never_the_version(self):
        entry = self._review_entry()
        ok, reason = persist.write_reply(entry, json.dumps({"findings": []}))
        self.assertTrue(ok, reason)
        written = runio._load_json(entry["out_file"])
        self.assertEqual("controller", written["_panopticon"]["stamped_by"])
        self.assertNotIn("schema_version", written)

    def test_claude_generation_still_validates_for_absent_and_one_only(self):
        # S1: Claude receives the receipt schema verbatim as --json-schema.
        env = persist_tests._verify_cell(self.d)
        cases = ((self._review_entry(), {"findings": [], "_panopticon": STAMP}),
                 (env["entry"], self._bundle(env)),
                 (self._tool_entry(), _verdict()))
        for entry, body in cases:
            schema = persist.launch_schema(entry, "claude")
            self.assertEqual(persist.role_schema(entry), schema)
            for version in SUPPORTED:
                self.assertEqual([], validate_schema.schema_errors(
                    _versioned(body, version), schema_path=schema), (entry["id"], version))
            for version in (2, True, "1", None):
                self.assertTrue(validate_schema.schema_errors(
                    _versioned(body, version), schema_path=schema), (entry["id"], version))
        bundle_entry, bundle = cases[1]
        bundle["verdicts"][0]["schema_version"] = 2
        self.assertTrue(validate_schema.schema_errors(
            bundle, schema_path=persist.launch_schema(bundle_entry, "claude")))


class TheVersionlessWindowStaysOpenTest(_Tree):
    """#3482 asks the advisors, and requires Codex's projections, to emit
    `schema_version: 1`. It does NOT close #2104's window: admission still reads a
    reply that omits the version as v1, for both roles #3482 touches. Closing the
    window is a separate coordinator ruling."""

    def test_a_versionless_verify_bundle_and_tool_verdict_are_still_admitted(self):
        env = persist_tests._verify_cell(self.d)
        bundle = self._bundle(env)
        self.assertNotIn("schema_version", bundle)
        self.assertEqual((True, ""), persist.write_reply(env["entry"], json.dumps(bundle)))
        verdict = _verdict()
        self.assertNotIn("schema_version", verdict)
        self.assertEqual((True, ""), persist.write_reply(self._tool_entry(), json.dumps(verdict)))


class InTheDonePredicatesTest(_Tree):
    """The self-write path: the agent wrote the file, so nothing checked it on
    the way in. An unknown version is not done, and the cell is re-dispatched."""

    def test_a_findings_file(self):
        manifest = {"run_id": "RID"}
        entry = self._review_entry(delivery=None)
        for version, done in [(v, True) for v in SUPPORTED] + [(v, False) for v in UNKNOWN]:
            with self.subTest(version=version):
                runio._write_json(entry["out_file"], _versioned(
                    {"findings": [], "_panopticon": STAMP}, version))
                self.assertIs(done, group_runner.entry_is_done(entry["out_file"], entry))
                self.assertIs(done, persist.is_done(entry))
        runio._write_json(runio._pano(self.d, "findings-app-SEC.json"),
                          {"schema_version": 2, "findings": [], "_panopticon": STAMP})
        self.assertFalse(review._cell_done(self.d, manifest, "app", "SEC"))
        runio._write_json(runio._pano(self.d, "findings-app-SEC.json"),
                          {"schema_version": 1, "findings": [], "_panopticon": STAMP})
        self.assertTrue(review._cell_done(self.d, manifest, "app", "SEC"))

    def test_a_verdict_bundle_is_not_done_for_one_unknown_verdict(self):
        env = persist_tests._verify_cell(self.d)
        first = env["ids"][0]
        for version in SUPPORTED:
            runio._write_json(env["entry"]["out_file"], self._bundle(env, version=version))
            self.assertTrue(persist.is_done(env["entry"]), version)
        for version in UNKNOWN:
            with self.subTest(version=version):
                runio._write_json(env["entry"]["out_file"], self._bundle(env, version=version))
                self.assertFalse(persist.is_done(env["entry"]))
                runio._write_json(env["entry"]["out_file"],
                                  self._bundle(env, verdict_versions={first: version}))
                self.assertFalse(persist.is_done(env["entry"]))

    def test_a_tool_verdict(self):
        entry = self._tool_entry()
        for version, done in [(v, True) for v in SUPPORTED] + [(v, False) for v in UNKNOWN]:
            with self.subTest(version=version):
                runio._write_json(entry["out_file"], _verdict(version=version))
                self.assertIs(done, verify_tools._valid_verdict_at(entry["out_file"]))
                self.assertIs(done, persist.is_done(entry))

    def test_a_backup_bundle_whose_round_is_done_on_its_label(self):
        # A backup part is answered once its bundle is LABELED (`_part_done`), so
        # the label check is where its version is refused.
        manifest = {"run_id": "RID"}
        path = verify._verify_out_file(self.d, "app", "SEC", "backup")
        stamp = dict(STAMP, stage="backup")
        for version, verdict_version, done in ((ABSENT, ABSENT, True), (1, 1, True),
                                               (2, ABSENT, False), (ABSENT, 2, False)):
            runio._write_json(path, _versioned(
                {"verdicts": [_verdict("F1", verdict_version)], "_panopticon": stamp}, version))
            self.assertIs(done, verify._part_done(self.d, manifest, "app", "SEC", "backup",
                                                  0, [{"id": "F1"}]), (version, verdict_version))


class AtSynthesisTest(_Tree):
    _report = findings_contract_tests.EndToEndCertificationTest._report

    _FINDING = {"id": "F1", "code": "SEC-A1A", "severity": "HIGH", "title": "t",
                "category": "SEC", "location": {"file": "a.py", "line": 1},
                "description": "d"}

    def test_an_unknown_findings_version_is_malformed_and_cannot_certify(self):
        rc, report = self._report({"schema_version": 2, "findings": [self._FINDING],
                                   "_panopticon": {"group": "App", "domain": "SEC"}})
        malformed = report["meta"]["integrity"]["malformed_findings_files"]
        self.assertEqual([{"index": None, "reason": REASON}], malformed[0]["defects"])
        self.assertEqual([], report["findings"], "a refused payload is not ingested")
        self.assertFalse(report["summary"]["coverage_certified"])
        self.assertEqual(2, rc)

    def test_absent_and_one_are_read_and_certify(self):
        for version in SUPPORTED:
            rc, report = self._report(_versioned(
                {"findings": [], "_panopticon": {"group": "App", "domain": "SEC"}}, version))
            self.assertEqual([], report["meta"]["integrity"]["malformed_findings_files"])
            self.assertEqual(0, rc, version)

    def test_the_findings_loader_ingests_nothing_from_a_refused_payload(self):
        path = runio._pano(self.d, "findings-app-SEC.json")
        for version, count in ((ABSENT, 1), (1, 1), (2, 0), (1.0, 0)):
            runio._write_json(path, _versioned(
                {"findings": [self._FINDING], "_panopticon": STAMP}, version))
            self.assertEqual(count, len(findings_mod.load_findings_detailed([path])[0]), version)

    def test_a_bundles_own_version_loses_the_file_and_a_verdicts_loses_only_it(self):
        verdicts_dir = self._out("verdicts")
        path = os.path.join(verdicts_dir, "verdicts-app-SEC.json")
        runio._write_json(path, {"schema_version": 2, "verdicts": [_verdict("F1")],
                                 "_panopticon": dict(STAMP, stage="primary")})
        by_fid, unloadable = evidence.load_verdict_bundles(verdicts_dir)
        self.assertEqual({}, by_fid)
        self.assertEqual([{"file": "verdicts-app-SEC.json", "reason": REASON}], unloadable)
        runio._write_json(path, {"verdicts": [_verdict("F1", 2), _verdict("F2", 1), _verdict("F3")],
                                 "_panopticon": dict(STAMP, stage="primary")})
        by_fid, unloadable = evidence.load_verdict_bundles(verdicts_dir)
        self.assertEqual({"F2", "F3"}, set(by_fid))
        self.assertEqual([{"file": "verdicts-app-SEC.json", "entry": 0, "reason": REASON}],
                         unloadable)

    def test_a_single_tool_verdict(self):
        verdicts_dir = self._out("verdicts")
        path = os.path.join(verdicts_dir, "q-0001.json")
        for version, loaded in ((ABSENT, True), (1, True), (2, False), (True, False)):
            runio._write_json(path, _verdict(version=version))
            verdicts, unloadable = evidence.load_verdicts_detailed(verdicts_dir)
            self.assertIs(loaded, "q-0001" in verdicts, version)
            self.assertEqual([] if loaded else [{"file": "q-0001.json", "reason": REASON}],
                             unloadable)


if __name__ == "__main__":
    unittest.main()

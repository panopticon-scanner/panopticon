import json
import os
import tempfile
from pathlib import Path
import unittest

import scripts.evidence as evidence
import scripts.synthesize as synthesize
import scripts.synth.findings as findings_mod
import scripts.synth.report as report_mod
import scripts.synth.codes as codes_mod

def _bundle(tmp_path, name, verdicts, stage="primary", run_id="R"):
    d = tmp_path / "verdicts"
    d.mkdir(exist_ok=True)
    (d / name).write_text(json.dumps({
        "verdicts": verdicts,
        "_panopticon": {"run_id": run_id, "role": "domain_advisor",
                        "domain": "SEC", "group": "app", "stage": stage}}))
    return str(d)

class TestVerdictBundles(unittest.TestCase):
    def test_bundle_flattens_by_finding_id(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            d_path = _bundle(tmp_path, "verdicts-app-SEC.json",
                        [{"finding_id": "SEC-100", "verdict": "CONFIRMED", "reasoning": "x"},
                         {"finding_id": "SEC-200", "verdict": "REJECTED", "reasoning": "y"}])
            by_fid, bad = evidence.load_verdict_bundles(d_path)
            self.assertEqual(bad, [])
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid, run_id="R")
            self.assertEqual(v["verdict"], "CONFIRMED")
            self.assertEqual(v["run_id"], "R")
            self.assertEqual(v["stage"], "primary")

    def test_backup_overrides_primary_for_same_finding(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            _bundle(tmp_path, "verdicts-app-SEC.json",
                    [{"finding_id": "SEC-100", "verdict": "CONFIRMED"}], stage="primary")
            d_path = _bundle(tmp_path, "verdicts-app-SEC-backup.json",
                        [{"finding_id": "SEC-100", "verdict": "REJECTED"}], stage="backup")
            by_fid, _ = evidence.load_verdict_bundles(d_path)
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid, run_id="R")
            self.assertEqual(v["verdict"], "REJECTED")
            self.assertEqual(v["stage"], "backup")

    def test_match_by_id_enforces_run_id(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            d_path = _bundle(tmp_path, "verdicts-app-SEC.json",
                        [{"finding_id": "SEC-100", "verdict": "CONFIRMED"}], run_id="R")
            by_fid, _ = evidence.load_verdict_bundles(d_path)
            f = {"id": "SEC-100"}
            self.assertEqual(evidence.match_verdict_by_id(f, by_fid, run_id="R")["verdict"], "CONFIRMED")
            self.assertIsNone(evidence.match_verdict_by_id(f, by_fid, run_id="OTHER"))
            self.assertIsNone(evidence.match_verdict_by_id({"id": "SEC-999"}, by_fid, run_id="R"))

    def test_single_verdict_files_are_not_bundles(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            v_dir = tmp_path / "verdicts"
            v_dir.mkdir()
            (v_dir / "abc123.json").write_text(json.dumps(
                {"finding_id": "SEC-1", "verdict": "CONFIRMED"}))
            by_fid, bad = evidence.load_verdict_bundles(str(v_dir))
            self.assertEqual(by_fid, {})
            self.assertEqual(bad, [])

    def test_build_report_binds_bundle_verdict_by_finding_id(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            fp = tmp_path / "findings-app-SEC.json"
            fp.write_text(json.dumps({"findings": [
                {"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH",
                 "title": "authz bypass", "description": "x",
                 "location": {"file": "app/x.py", "line_start": 4}, "category": "authz"}]}))
            findings = findings_mod.load_findings([str(fp)])
            fid = findings[0]["id"]
            d_path = _bundle(tmp_path, "verdicts-app-SEC.json",
                        [{"finding_id": fid, "verdict": "CONFIRMED", "reasoning": "ok"}],
                        run_id="R")
            by_fid, _ = evidence.load_verdict_bundles(d_path)
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="src",
                    fail_on="high",
                    timestamp="2026-08-15T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(
                    findings=findings,
                    verdicts={},
                    verdicts_supplied=True,
                    verdict_run_id="R",
                    verdict_bundles=by_fid,
                ),
            ))
            self.assertEqual(report["findings"][0]["evidence"]["status"], "advisor_confirmed")

    def test_queue_id_match_not_overwritten_by_fid_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            fp = tmp_path / "findings-app-SEC.json"
            fp.write_text(json.dumps({"findings": [
                {"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH", "title": "authz",
                 "description": "x", "location": {"file": "app/x.py", "line_start": 4},
                 "category": "authz"}]}))
            findings = findings_mod.load_findings([str(fp)])
            fid = findings[0]["id"]
            qid = evidence.finding_fingerprint(findings[0])
            verdicts = {qid: {"finding_id": fid, "verdict": "REJECTED"}}
            by_fid = {fid: [{"finding_id": fid, "verdict": "CONFIRMED", "run_id": None}]}
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="src",
                    fail_on="high",
                    timestamp="2026-08-15T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(
                    findings=findings,
                    verdicts=verdicts,
                    verdicts_supplied=True,
                    verdict_bundles=by_fid,
                ),
            ))
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["discarded_claims"][0]["evidence"]["status"], "rejected")

    def test_the_controller_stamp_decides_run_id_and_stage(self):
        # #1638 P16 fix round 2, N2: `run_id` and `stage` are CONTROLLER-stamped
        # identity (persist._STAMP_KEYS), not advisor opinion. They used to be
        # taken from the verdict when it carried them, which let one primary
        # bundle declare a second entry `stage: "backup"` and fabricate a
        # gate-eligible `backup_scope_limited` disclosure. The stamp wins now.
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            v_dir = tmp_path / "verdicts"
            v_dir.mkdir()
            (v_dir / "verdicts-app-SEC.json").write_text(json.dumps({
                "verdicts": [{"finding_id": "SEC-100", "verdict": "CONFIRMED",
                              "run_id": "OWN", "stage": "backup"}],
                "_panopticon": {"run_id": "BUNDLE", "stage": "primary"}}))
            by_fid, _ = evidence.load_verdict_bundles(str(v_dir))
            self.assertIsNone(
                evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="OWN"))
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="BUNDLE")
            self.assertEqual(v["run_id"], "BUNDLE")
            self.assertEqual(v["stage"], "primary")

    def test_non_dict_panopticon_is_tolerated(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            v_dir = tmp_path / "verdicts"
            v_dir.mkdir()
            (v_dir / "verdicts-app-SEC.json").write_text(json.dumps(
                {"verdicts": [{"finding_id": "SEC-1", "verdict": "CONFIRMED"}],
                 "_panopticon": ["oops"]}))
            by_fid, bad = evidence.load_verdict_bundles(str(v_dir))
            self.assertIn("SEC-1", by_fid)

    def test_stale_cross_run_backup_does_not_evict_valid_primary(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            _bundle(tmp_path, "verdicts-app-SEC.json",
                    [{"finding_id": "SEC-100", "verdict": "CONFIRMED"}], stage="primary", run_id="R")
            d_path = _bundle(tmp_path, "verdicts-app-SEC-backup.json",
                        [{"finding_id": "SEC-100", "verdict": "REJECTED"}], stage="backup", run_id="OLD")
            by_fid, _ = evidence.load_verdict_bundles(d_path)
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid, run_id="R")
            self.assertIsNotNone(v)
            self.assertEqual(v["verdict"], "CONFIRMED")

    def test_load_verdicts_detailed_ignores_bundles(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            v_dir = tmp_path / "verdicts"
            v_dir.mkdir()
            (v_dir / "verdicts-app-SEC.json").write_text(json.dumps(
                {"verdicts": [{"finding_id": "SEC-1", "verdict": "CONFIRMED"}],
                 "_panopticon": {"run_id": "R", "stage": "primary"}}))
            (v_dir / "junk.json").write_text("not json {")
            verds, unloadable = evidence.load_verdicts_detailed(str(v_dir))
            files = {u["file"] for u in unloadable}
            self.assertNotIn("verdicts-app-SEC.json", files)
            self.assertIn("junk.json", files)

    def test_valid_bundle_run_has_zero_unloadable(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            fp = tmp_path / "findings-app-SEC.json"
            fp.write_text(json.dumps({"findings": [
                {"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH", "title": "t",
                 "description": "x", "location": {"file": "a.py", "line_start": 1},
                 "category": "authz"}]}))
            findings = findings_mod.load_findings([str(fp)])
            fid = findings[0]["id"]
            vd = tmp_path / "verdicts"
            vd.mkdir()
            (vd / "verdicts-app-SEC.json").write_text(json.dumps(
                {"verdicts": [{"finding_id": fid, "verdict": "CONFIRMED"}],
                 "_panopticon": {"run_id": "R", "role": "domain_advisor",
                                 "domain": "SEC", "group": "app", "stage": "primary"}}))
            out = tmp_path / "report.json"
            cwd = os.getcwd()
            try:
                os.chdir(tmp_path)
                synthesize.main(["--verdicts-dir", str(vd), "--out", str(out), str(fp)])
            finally:
                os.chdir(cwd)
            rep = json.loads(out.read_text())
            self.assertEqual(rep["meta"]["coverage"]["verdicts"]["unloadable"], 0)
            self.assertEqual(rep["findings"][0]["evidence"]["status"], "advisor_confirmed")

    def test_bundle_verdict_counted_in_supplied(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            fp = tmp_path / "findings-app-SEC.json"
            fp.write_text(json.dumps({"findings": [
                {"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH", "title": "t",
                 "description": "x", "location": {"file": "a.py", "line_start": 1},
                 "category": "authz"}]}))
            findings = findings_mod.load_findings([str(fp)])
            fid = findings[0]["id"]
            d_path = _bundle(tmp_path, "verdicts-app-SEC.json",
                        [{"finding_id": fid, "verdict": "CONFIRMED"}], run_id=None)
            by_fid, _ = evidence.load_verdict_bundles(d_path)
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="src",
                    fail_on="high",
                    timestamp="2026-08-15T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(
                    findings=findings,
                    verdicts={},
                    verdicts_supplied=True,
                    verdict_bundles=by_fid,
                ),
            ))
            vs = report["meta"]["coverage"]["verdicts"]
            self.assertEqual(vs["matched"], 1)
            self.assertGreaterEqual(vs["supplied"], 1)
            self.assertLessEqual(vs["matched"], vs["supplied"])

if __name__ == '__main__':
    unittest.main()


class TestScopeLimitedBackup(unittest.TestCase):
    """#1638 P16 ruling 3: an evidence-scope failure is not a substantive
    disagreement. A backup NEEDS_MORE_INFO that NAMES the files it could not
    reach (`missing_evidence`) no longer displaces a primary CONFIRMED -- run-13
    published the redaction-order defect as unverifiable for exactly that
    reason. A backup NMI with no `missing_evidence` keeps today's semantics."""

    def _by_fid(self, tmp_path, backup):
        _bundle(tmp_path, "verdicts-app-SEC.json",
                [{"finding_id": "SEC-100", "verdict": "CONFIRMED",
                  "reasoning": "traced the call order"}], stage="primary")
        d_path = _bundle(tmp_path, "verdicts-app-SEC-backup.json", [backup],
                         stage="backup")
        by_fid, _ = evidence.load_verdict_bundles(d_path)
        return by_fid

    def test_scope_limited_backup_nmi_keeps_the_primary_confirmed(self):
        with tempfile.TemporaryDirectory() as d:
            by_fid = self._by_fid(Path(d), {
                "finding_id": "SEC-100", "verdict": "NEEDS_MORE_INFO",
                "reasoning": "the call sites were not in my scope",
                "missing_evidence": ["synth/grading.py", "synthesize.py"]})
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="R")
            self.assertEqual(v["verdict"], "CONFIRMED")
            self.assertEqual(v["stage"], "primary")
            self.assertEqual(evidence.carried_paths(v),
                             ["synth/grading.py", "synthesize.py"])

    def test_scope_limited_backup_yields_the_backup_scope_limited_status(self):
        with tempfile.TemporaryDirectory() as d:
            by_fid = self._by_fid(Path(d), {
                "finding_id": "SEC-100", "verdict": "NEEDS_MORE_INFO",
                "reasoning": "out of scope",
                "missing_evidence": ["synth/grading.py"]})
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="R")
            ev_obj = evidence.derive_evidence({"id": "SEC-100"}, v)
            self.assertEqual(ev_obj["status"], "backup_scope_limited")
            self.assertEqual(ev_obj["missing_evidence"], ["synth/grading.py"])
            self.assertIn("backup_scope_limited", evidence.EVIDENCE_STATUSES)
            self.assertIn("backup_scope_limited", evidence.GATE_ELIGIBLE_DEFAULT)

    def test_backup_nmi_without_missing_evidence_still_wins(self):
        with tempfile.TemporaryDirectory() as d:
            by_fid = self._by_fid(Path(d), {
                "finding_id": "SEC-100", "verdict": "NEEDS_MORE_INFO",
                "reasoning": "the code genuinely does not say"})
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="R")
            self.assertEqual(v["verdict"], "NEEDS_MORE_INFO")
            self.assertEqual(v["stage"], "backup")
            self.assertEqual(
                evidence.derive_evidence({"id": "SEC-100"}, v)["status"],
                "needs_more_info")

    def test_a_scope_limited_backup_never_rescues_a_primary_rejection(self):
        # Only a primary CONFIRMED is retained; anything else keeps the backup.
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            _bundle(tmp_path, "verdicts-app-SEC.json",
                    [{"finding_id": "SEC-100", "verdict": "REJECTED"}],
                    stage="primary")
            d_path = _bundle(tmp_path, "verdicts-app-SEC-backup.json",
                             [{"finding_id": "SEC-100",
                               "verdict": "NEEDS_MORE_INFO",
                               "missing_evidence": ["other.py"]}],
                             stage="backup")
            by_fid, _ = evidence.load_verdict_bundles(d_path)
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="R")
            self.assertEqual(v["verdict"], "NEEDS_MORE_INFO")
            self.assertEqual(v["stage"], "backup")

    def test_missing_evidence_must_be_a_list_of_paths(self):
        for junk in ("grading.py", [], [""], [123], {"a": 1}, None):
            self.assertEqual(
                evidence.scope_limited_paths(
                    {"verdict": "NEEDS_MORE_INFO", "missing_evidence": junk}),
                [], junk)
        # ... and only on a NEEDS_MORE_INFO verdict
        self.assertEqual(
            evidence.scope_limited_paths(
                {"verdict": "CONFIRMED", "missing_evidence": ["a.py"]}), [])

    def test_report_marks_the_finding_backup_unconfirmed(self):
        # Ruling 3: `backup_confirmed` stays FALSE -- the backup did not
        # corroborate, it could not look.
        f = {"id": "SEC-100", "code": "SEC-A1A", "severity": "HIGH"}
        v = {"finding_id": "SEC-100", "verdict": "CONFIRMED", "stage": "primary",
             evidence.SCOPE_LIMITED_FIELD: ["synth/grading.py"]}
        codes_mod.apply_verdict_quality([f], {id(f): v}, None)
        self.assertIs(f["backup_confirmed"], False)


class TestPlantedCarrierIsNotTrusted(unittest.TestCase):
    """#1638 P16 fix round 1, F1. `_backup_missing_evidence` is a CONTROLLER key:
    `match_verdict_by_id` is its only writer. Nothing enforced that -- the loaders
    copied an agent's verdict object verbatim -- so an advisor could plant the key
    itself and (a) have a REJECTION laundered into a gate-eligible CONFIRMED, or
    (b) fabricate a "backup could not see" disclosure with no backup round at all.
    The adversarial backup is precisely the surface the threat model distrusts."""

    def _plant(self, tmp_path, primary, backup=None):
        _bundle(tmp_path, "verdicts-app-SEC.json", [primary], stage="primary")
        d_path = _bundle(tmp_path, "verdicts-app-SEC-backup.json",
                         [backup], stage="backup") if backup else (
            str(tmp_path / "verdicts"))
        by_fid, _ = evidence.load_verdict_bundles(d_path)
        return by_fid

    def test_a_planted_carrier_cannot_launder_a_backup_rejection(self):
        with tempfile.TemporaryDirectory() as d:
            by_fid = self._plant(
                Path(d),
                {"finding_id": "SEC-100", "verdict": "CONFIRMED"},
                {"finding_id": "SEC-100", "verdict": "REJECTED",
                 "reasoning": "the code does not do this",
                 evidence.SCOPE_LIMITED_FIELD: ["x.py"]})
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="R")
            self.assertEqual(v["verdict"], "REJECTED")
            self.assertEqual(v["stage"], "backup")
            self.assertNotIn(evidence.SCOPE_LIMITED_FIELD, v)
            self.assertEqual(
                evidence.derive_evidence({"id": "SEC-100"}, v)["status"],
                "rejected")

    def test_a_planted_carrier_fabricates_no_backup_disclosure(self):
        # No backup round ran at all: a primary that plants the key must still
        # derive `advisor_confirmed`, with no `missing_evidence` in the report.
        with tempfile.TemporaryDirectory() as d:
            by_fid = self._plant(Path(d), {
                "finding_id": "SEC-100", "verdict": "CONFIRMED",
                "reasoning": "y",
                evidence.SCOPE_LIMITED_FIELD: ["/etc/passwd"]})
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="R")
            self.assertNotIn(evidence.SCOPE_LIMITED_FIELD, v)
            ev_obj = evidence.derive_evidence({"id": "SEC-100"}, v)
            self.assertEqual(ev_obj["status"], "advisor_confirmed")
            self.assertNotIn("missing_evidence", ev_obj)

    def test_every_underscore_key_is_stripped_from_an_agent_verdict(self):
        # The rule is the TRUST BOUNDARY, not one key: an agent writes no
        # underscore-prefixed key, the way it stamps no `_panopticon` identity.
        with tempfile.TemporaryDirectory() as d:
            by_fid = self._plant(Path(d), {
                "finding_id": "SEC-100", "verdict": "CONFIRMED",
                "_merged_ids": ["SEC-999"], "_group": "Other",
                evidence.SCOPE_LIMITED_FIELD: ["x.py"]})
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="R")
            self.assertEqual([k for k in v if k.startswith("_")], [])

    def test_the_legacy_single_verdict_loader_strips_it_too(self):
        with tempfile.TemporaryDirectory() as d:
            v_dir = Path(d) / "verdicts"
            v_dir.mkdir()
            (v_dir / "Q1.json").write_text(json.dumps(
                {"finding_id": "SEC-100", "verdict": "CONFIRMED",
                 evidence.SCOPE_LIMITED_FIELD: ["x.py"]}))
            verdicts, bad = evidence.load_verdicts_detailed(str(v_dir))
            self.assertEqual(bad, [])
            self.assertNotIn(evidence.SCOPE_LIMITED_FIELD, verdicts["Q1"])

    def test_missing_evidence_on_a_non_nmi_verdict_is_ignored(self):
        # The PUBLIC field is only meaningful on a NEEDS_MORE_INFO; a CONFIRMED
        # or REJECTED verdict decided, and what it did not read is not a scope
        # failure. (Already true; pinned so the F1 reordering cannot undo it.)
        for outcome in ("CONFIRMED", "REJECTED"):
            self.assertEqual(
                evidence.scope_limited_paths(
                    {"verdict": outcome, "missing_evidence": ["a.py"]}),
                [], outcome)

    def test_scope_limited_paths_never_reads_the_controller_carrier(self):
        # F1 ruling 2: the branch `match_verdict_by_id` consults is the public
        # field, evaluated only once NEEDS_MORE_INFO is established.
        self.assertEqual(
            evidence.scope_limited_paths(
                {"verdict": "REJECTED",
                 evidence.SCOPE_LIMITED_FIELD: ["a.py"]}), [])
        self.assertEqual(
            evidence.carried_paths(
                {"verdict": "CONFIRMED",
                 evidence.SCOPE_LIMITED_FIELD: ["a.py"]}), ["a.py"])


class TestStageIsControllerOwned(unittest.TestCase):
    """Fix round 2, N2. `stage` decides which candidate is treated as the
    adversarial second opinion, so an advisor that declares its own reproduces
    round-0's fabricated-disclosure shape with no `_`-prefixed key at all: ONE
    primary bundle, two entries for one finding, no backup round anywhere."""

    def _one_primary_bundle(self, tmp_path, verdicts):
        v_dir = tmp_path / "verdicts"
        v_dir.mkdir(exist_ok=True)
        (v_dir / "verdicts-app-SEC.json").write_text(json.dumps({
            "verdicts": verdicts,
            "_panopticon": {"run_id": "R", "role": "domain_advisor",
                            "domain": "SEC", "group": "app",
                            "stage": "primary"}}))
        return str(v_dir)

    def test_a_primary_bundle_cannot_declare_its_own_backup_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._one_primary_bundle(Path(d), [
                {"finding_id": "SEC-100", "verdict": "CONFIRMED",
                 "reasoning": "mine"},
                {"finding_id": "SEC-100", "verdict": "NEEDS_MORE_INFO",
                 "stage": "backup",
                 "missing_evidence": ["/etc/shadow", "secrets/prod.env"]}])
            by_fid, _ = evidence.load_verdict_bundles(path)
            self.assertEqual({v.get("stage") for v in by_fid["SEC-100"]},
                             {"primary"})
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="R")
            ev_obj = evidence.derive_evidence({"id": "SEC-100"}, v)
            self.assertEqual(ev_obj["status"], "advisor_confirmed")
            self.assertNotIn("missing_evidence", ev_obj)

    def test_an_unstamped_bundle_gets_no_backup_stage_either(self):
        # Fail closed: with no controller stamp there is no authority for
        # "backup", so the verdict reads as primary rather than as a second
        # opinion. `persist` refuses an unstamped bundle anyway.
        with tempfile.TemporaryDirectory() as d:
            v_dir = Path(d) / "verdicts"
            v_dir.mkdir()
            (v_dir / "verdicts-app-SEC.json").write_text(json.dumps(
                {"verdicts": [{"finding_id": "SEC-1", "verdict": "CONFIRMED",
                               "stage": "backup"}]}))
            by_fid, _ = evidence.load_verdict_bundles(str(v_dir))
            self.assertEqual(by_fid["SEC-1"][0]["stage"], "primary")

    def test_the_legacy_loader_derives_stage_from_the_file_name(self):
        # Path-derived, never agent-declared: a legacy single-verdict file is
        # written to a path the CONTROLLER chose.
        with tempfile.TemporaryDirectory() as d:
            v_dir = Path(d) / "verdicts"
            v_dir.mkdir()
            (v_dir / "Q1.json").write_text(json.dumps(
                {"finding_id": "SEC-1", "verdict": "CONFIRMED",
                 "stage": "backup"}))
            (v_dir / "Q2-backup.json").write_text(json.dumps(
                {"finding_id": "SEC-2", "verdict": "CONFIRMED"}))
            verdicts, bad = evidence.load_verdicts_detailed(str(v_dir))
            self.assertEqual(bad, [])
            self.assertEqual(verdicts["Q1"]["stage"], "primary")
            self.assertEqual(verdicts["Q2-backup"]["stage"], "backup")


class TestDuplicateVerdictsTakeTheLeastFavourable(unittest.TestCase):
    """Fix round 2, N6. `match_verdict_by_id` took the FIRST candidate of the
    winning stage, so a backup bundle carrying both a scope-limited NMI and a
    REJECTED for one finding silently discarded the refutation. When an advisor
    says two things about one claim, the finding gets the least favourable of
    them: REJECTED > NEEDS_MORE_INFO > CONFIRMED."""

    def _dupes(self, tmp_path, verdicts, stage="backup"):
        _bundle(tmp_path, "verdicts-app-SEC.json",
                [{"finding_id": "SEC-100", "verdict": "CONFIRMED"}],
                stage="primary")
        d_path = _bundle(tmp_path, "verdicts-app-SEC-backup.json", verdicts,
                         stage=stage)
        return evidence.load_verdict_bundles(d_path)[0]

    def test_a_rejection_beats_a_scope_limited_nmi_in_the_same_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            by_fid = self._dupes(Path(d), [
                {"finding_id": "SEC-100", "verdict": "NEEDS_MORE_INFO",
                 "missing_evidence": ["x.py"]},
                {"finding_id": "SEC-100", "verdict": "REJECTED",
                 "reasoning": "the code does not do this"}])
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="R")
            self.assertEqual(v["verdict"], "REJECTED")
            self.assertEqual(
                evidence.derive_evidence({"id": "SEC-100"}, v)["status"],
                "rejected")

    def test_a_rejection_beats_a_confirmation_in_the_same_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            by_fid = self._dupes(Path(d), [
                {"finding_id": "SEC-100", "verdict": "CONFIRMED"},
                {"finding_id": "SEC-100", "verdict": "REJECTED"}])
            self.assertEqual(
                evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="R")["verdict"],
                "REJECTED")

    def test_an_nmi_beats_a_confirmation_in_the_same_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            by_fid = self._dupes(Path(d), [
                {"finding_id": "SEC-100", "verdict": "CONFIRMED"},
                {"finding_id": "SEC-100", "verdict": "NEEDS_MORE_INFO"}])
            self.assertEqual(
                evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="R")["verdict"],
                "NEEDS_MORE_INFO")

    def test_duplicate_primaries_keep_first_wins(self):
        # Deliberately NOT extended to the primary round: it establishes a
        # finding, so demoting on contradiction would hand a hostile advisor a
        # free lever (emit CONFIRMED + NEEDS_MORE_INFO, drop it out of the
        # gate). A backup that wanted to refute can already emit the REJECTED
        # alone, so the rule gives it nothing new. Unchanged behaviour.
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            d_path = _bundle(tmp_path, "verdicts-app-SEC.json",
                             [{"finding_id": "SEC-100", "verdict": "CONFIRMED"},
                              {"finding_id": "SEC-100", "verdict": "REJECTED"}],
                             stage="primary")
            by_fid, _ = evidence.load_verdict_bundles(d_path)
            self.assertEqual(
                evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="R")["verdict"],
                "CONFIRMED")


class TestTheTwoNeedsMoreInfoShapesAreOrdered(unittest.TestCase):
    """Fix round 3, D4. `_VERDICT_SCEPTICISM` scored a bare NEEDS_MORE_INFO and
    a scope-limited one identically, and `min` is stable -- so the advisor's own
    array order decided whether the finding ended at factor 0.5 and out of the
    gate or 1.5 and in it. A bare NMI is the more sceptical of the two: it says
    the advisor LOOKED and the code does not say, where a scope-limited one says
    it was not allowed to look. REJECTED > NMI (bare) > NMI (scope-limited) >
    CONFIRMED."""

    def _kept(self, backups):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            _bundle(tmp_path, "verdicts-app-SEC.json",
                    [{"finding_id": "SEC-100", "verdict": "CONFIRMED"}],
                    stage="primary")
            d_path = _bundle(tmp_path, "verdicts-app-SEC-backup.json", backups,
                             stage="backup")
            by_fid, _ = evidence.load_verdict_bundles(d_path)
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid,
                                             run_id="R")
            return v, evidence.derive_evidence({"id": "SEC-100"}, v)["status"]

    BARE = {"finding_id": "SEC-100", "verdict": "NEEDS_MORE_INFO",
            "reasoning": "the code genuinely does not say"}
    SCOPED = {"finding_id": "SEC-100", "verdict": "NEEDS_MORE_INFO",
              "missing_evidence": ["x.py"]}

    def test_a_bare_nmi_wins_whichever_order_it_arrives_in(self):
        for backups in ([self.SCOPED, self.BARE], [self.BARE, self.SCOPED]):
            v, status = self._kept(backups)
            self.assertEqual(v["verdict"], "NEEDS_MORE_INFO")
            self.assertEqual(v["stage"], "backup")
            self.assertEqual(status, "needs_more_info", backups)

    def test_a_rejection_still_beats_both(self):
        rejected = {"finding_id": "SEC-100", "verdict": "REJECTED"}
        for backups in ([self.SCOPED, self.BARE, rejected],
                        [rejected, self.BARE, self.SCOPED]):
            self.assertEqual(self._kept(backups)[1], "rejected", backups)

    def test_a_scope_limited_nmi_alone_is_still_the_disclosure(self):
        self.assertEqual(self._kept([self.SCOPED])[1], "backup_scope_limited")

"""Tests for scripts.synth.integrity: planned-vs-ingested findings files, labels, the
unenforced ack and meta.integrity.
"""
import contextlib
import io
import os
import json
import tempfile
import unittest

import scripts.synthesize as syn
import scripts.synth.findings as findings_mod
import scripts.synth.plan as plan_mod
import scripts.synth.integrity as integrity_mod
import scripts.group_runner as gr
import scripts.synth.report as report_mod


class TestFindingsFileIntegrity(unittest.TestCase):
    """#936 duplicate out_file + #937 content-vs-filename validation."""

    def test_duplicate_out_files_detected(self):
        plan = [
            {
                "role": "panel_review",
                "out_file": ".panopticon/findings-g1-redteam-panel_review.json",
            },
            {
                "role": "panel_review",
                "out_file": ".panopticon/findings-g1-redteam-panel_review.json",
            },
            {
                "role": "lens_sweep",
                "out_file": ".panopticon/findings-g1-code-lens_sweep-style.json",
            },
        ]
        self.assertEqual(
            integrity_mod.duplicate_out_files(plan), [".panopticon/findings-g1-redteam-panel_review.json"]
        )
        self.assertEqual(integrity_mod.duplicate_out_files([]), [])

    def test_expected_from_filename(self):
        # #run10: keyed on the cell shape phases.review._cell_entry writes. The group
        # may contain hyphens, so the DOMAIN is the last token.
        self.assertEqual(
            integrity_mod._expected_from_filename("findings-DocumentsIntake-SEC.json"),
            ("DocumentsIntake", "SEC"),
        )
        self.assertEqual(
            integrity_mod._expected_from_filename("findings-My-Hyphenated-Group-COD.json"),
            ("My-Hyphenated-Group", "COD"),
        )
        self.assertIsNone(integrity_mod._expected_from_filename("groups.json"))
        # not an OCRDb domain -> not a reviewer findings file
        self.assertIsNone(integrity_mod._expected_from_filename("findings-g1-NOPE.json"))
        # the retired 4.x spellings are no longer produced, so no longer parsed
        self.assertIsNone(
            integrity_mod._expected_from_filename("findings-g1-redteam-panel_review.json"))

    def test_mislabeled_when_content_disagrees(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "findings-g1-SEC.json")
            with open(good, "w") as fh:
                json.dump({"findings": [{"domain": "SEC"}],
                           "_panopticon": {"group": "g1", "domain": "SEC"}}, fh)
            # a COD cell's output written into the SEC cell's file = mis-target
            bad = os.path.join(d, "findings-g2-SEC.json")
            with open(bad, "w") as fh:
                json.dump({"findings": [{"domain": "COD"}],
                           "_panopticon": {"group": "g2", "domain": "COD"}}, fh)
            # right domain, wrong GROUP -- an overwritten sibling cell
            wrong_group = os.path.join(d, "findings-g3-SEC.json")
            with open(wrong_group, "w") as fh:
                json.dump({"findings": [{"domain": "SEC"}],
                           "_panopticon": {"group": "g9", "domain": "SEC"}}, fh)
            self.assertEqual(integrity_mod.mislabeled_findings_files([good]), [])
            self.assertEqual(integrity_mod.mislabeled_findings_files([bad]), [bad])
            self.assertEqual(integrity_mod.mislabeled_findings_files([wrong_group]), [wrong_group])

    def test_cross_domain_finding_is_not_a_mislabeled_file(self):
        # #calibration-4 (gotify): the stamp is CORRECT -- the file is exactly
        # where it belongs -- but one finding is filed under another domain.
        # That is a reviewer stepping outside its lane, not a mis-targeted
        # write, and it must not sink certification. On gotify it did: 0 stamp
        # mismatches across 160 files, 3 cross-domain findings in 2 of them,
        # and the whole run came back NOT CERTIFIED.
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-ClientDevices-ARC.json")
            with open(p, "w") as fh:
                json.dump({"findings": [{"domain": "ARC", "ocrdb_code": "ARC-D1E"},
                                        {"domain": "TST", "ocrdb_code": "TST-X0X"}],
                           "_panopticon": {"group": "ClientDevices",
                                           "domain": "ARC"}}, fh)
            self.assertEqual(integrity_mod.mislabeled_findings_files([p]), [])
            xd = integrity_mod.cross_domain_findings([p])
            self.assertEqual(len(xd), 1)
            self.assertEqual(xd[0]["cell_domain"], "ARC")
            self.assertEqual(xd[0]["finding_domain"], "TST")
            self.assertEqual(xd[0]["code"], "TST-X0X")

    def test_cross_domain_findings_ignores_in_domain_and_absent(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-g1-SEC.json")
            with open(p, "w") as fh:
                json.dump({"findings": [{"domain": "SEC"}, {"title": "no domain"}],
                           "_panopticon": {"group": "g1", "domain": "SEC"}}, fh)
            self.assertEqual(integrity_mod.cross_domain_findings([p]), [])

    def test_cross_domain_findings_do_not_block_certification(self):
        # The whole point of the split: reported, never gating. Asserted
        # against the mislabeled case in the same shape, so this cannot pass
        # by simply failing to notice either field.
        def report(**integrity):
            base = {"unexpected_findings_files": [], "missing_planned_files": [],
                    "duplicate_out_files": [], "mislabeled_findings_files": [],
                    "cross_domain_findings": [], "empty_dispatch_plans": 0,
                    "invalid_dispatch_plans": [], "invalid_verify_queue": None,
                    "unenforced_acknowledged": False, "plans_seen": 1}
            base.update(integrity)
            return report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on="high",
                    timestamp="2026-01-01T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(integrity=base),
            ))

        xdom = [{"file": "findings-g1-ARC.json", "cell_domain": "ARC",
                 "finding_domain": "TST", "code": "TST-X0X"}]
        clean_gate = report()["summary"]["gate"]
        self.assertEqual(report(cross_domain_findings=xdom)["summary"]["gate"],
                         clean_gate, "cross-domain findings changed the gate")
        # the genuine integrity failure still does gate, so the assertion above
        # is meaningful rather than vacuous
        self.assertEqual(
            report(mislabeled_findings_files=["findings-g1-ARC.json"])["summary"]["gate"],
            "INCONCLUSIVE")

    def test_absent_fields_are_not_second_guessed(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-g1-COD.json")
            with open(p, "w") as fh:
                json.dump({"findings": [{"description": "no domain field"}]}, fh)
            self.assertEqual(integrity_mod.mislabeled_findings_files([p]), [])

    def test_mislabeled_file_forces_inconclusive_end_to_end(self):
        # --fail-on high makes the base gate PASS (no high findings); the
        # integrity gap then raises it to INCONCLUSIVE (OFF would be preserved).
        prev = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            p = os.path.join(d, "findings-g1-SEC.json")        # SEC cell name
            with open(p, "w") as fh:                            # COD cell content
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "XX-001",
                                "title": "t",
                                "severity": "LOW",
                                "confidence": "POSSIBLE",
                                "panel": "code",
                                "domain": "COD",
                                "source_role": "domain_panel",
                                "category": "x",
                                "location": {"file": "a.py", "line_start": 1},
                            }
                        ],
                        "_panopticon": {"group": "g1", "domain": "COD",
                                        "role": "domain_panel"},
                    },
                    fh,
                )
            out = os.path.join(d, "report.json")
            try:
                os.chdir(d)
                with contextlib.redirect_stdout(io.StringIO()):
                    syn.main(["--target", "t", "--fail-on", "high", "--out", out, p])
            finally:
                os.chdir(prev)
            with open(out, encoding="utf-8") as fh:
                report = json.load(fh)
            self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")
            self.assertFalse(report["summary"]["coverage_certified"])
            self.assertIn(
                os.path.basename(p),
                " ".join(report["meta"]["integrity"]["mislabeled_findings_files"]),
            )

    def test_real_tapestry_corpus_is_consistent_when_present(self):
        # If PANOPTICON_TAPESTRY_CORPUS_PATH is set, its reviewer findings files
        # must not trip the mislabel check (they were authored by the real
        # reviewers) — a regression canary against false positives.
        import glob

        base = os.environ.get("PANOPTICON_TAPESTRY_CORPUS_PATH", "")
        if not base:
            self.skipTest("PANOPTICON_TAPESTRY_CORPUS_PATH not set")
        files = glob.glob(os.path.join(base, "findings-*.json"))
        if not files:
            self.skipTest("No findings files found in PANOPTICON_TAPESTRY_CORPUS_PATH")
        self.assertEqual(integrity_mod.mislabeled_findings_files(files), [])

class TestReadUnenforcedAck(unittest.TestCase):
    """M8: read_unenforced_ack had zero direct test coverage -- exactly where
    I1's real defect lived (a stale/spurious ack silently poisoning every
    later run's meta.integrity.unenforced_acknowledged)."""

    def test_true_when_acknowledged(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ack.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"acknowledged": True, "roles": ["panel_review"]}, fh)
            self.assertTrue(integrity_mod.read_unenforced_ack(path))

    def test_false_when_missing(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "does-not-exist.json")
            self.assertFalse(integrity_mod.read_unenforced_ack(path))

    def test_false_when_malformed_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ack.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            self.assertFalse(integrity_mod.read_unenforced_ack(path))

    def test_false_when_non_dict_payload(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ack.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(["not", "a", "dict"], fh)
            self.assertFalse(integrity_mod.read_unenforced_ack(path))

class TestReconcileRealpath(unittest.TestCase):
    def test_symlinked_plan_paths_match_physical_ingested_paths(self):
        # #947 FIXME-1: macOS /var -> /private/var symlink made abspath
        # comparison flag every file on a clean run. realpath both sides.
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "real")
            os.makedirs(real)
            link = os.path.join(d, "link")
            os.symlink(real, link)
            fname = "findings-g1-code-panel_review.json"
            with open(os.path.join(real, fname), "w") as fh:
                json.dump({"findings": []}, fh)
            plan = [{"out_file": os.path.join(link, fname)}]  # symlink form
            ingested = [os.path.join(real, fname)]  # physical form
            unexpected, missing = integrity_mod.reconcile_findings_files(plan, ingested)
        self.assertEqual((unexpected, missing), ([], []))

class IntegritySectionTest(unittest.TestCase):
    """WS-0 S3: meta.integrity assembled from the plan lists and ingested files."""

    KEYS = ["unexpected_findings_files", "missing_planned_files", "duplicate_out_files",
            "mislabeled_findings_files", "cross_domain_findings", "unenforced_acknowledged",
            "ack_stale", "content_hashes_checked", "content_mismatched_files",
            "content_snapshot_unreadable", "content_snapshot_missing",
            "empty_dispatch_plans", "invalid_dispatch_plans",
            "invalid_verify_queue", "plans_seen"]

    def test_key_order_is_the_report_contract(self):
        with tempfile.TemporaryDirectory() as d:
            sec = integrity_mod.integrity_section([], [], d, 0, 0, None)
        self.assertEqual(list(sec), self.KEYS)
        self.assertFalse(sec["unenforced_acknowledged"])
        self.assertNotIn("write_guard_covers_bash", sec)

    def test_ack_is_honoured_and_a_stale_one_is_reported(self):
        plan = [{"group": "g1", "domain": "code", "out_file": "findings-g1-code.json"}]
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "unenforced-ack.json"), "w") as fh:
                json.dump({"acknowledged": True, "plan_sha256": integrity_mod._plan_hash(plan),
                           "write_guard_covers_bash": True}, fh)
            sec = integrity_mod.integrity_section([plan], [], d, 1, 0, None)
            self.assertTrue(sec["unenforced_acknowledged"])
            self.assertFalse(sec["ack_stale"])
            self.assertTrue(sec["write_guard_covers_bash"])
            self.assertEqual(sec["missing_planned_files"], ["findings-g1-code.json"])
            with open(os.path.join(d, "unenforced-ack.json"), "w") as fh:
                json.dump({"acknowledged": True, "plan_sha256": "0" * 64}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                sec = integrity_mod.integrity_section([plan], [], d, 1, 0, None)
            self.assertFalse(sec["unenforced_acknowledged"])
            self.assertTrue(sec["ack_stale"])
            self.assertIn("STALE ack", err.getvalue())
            self.assertFalse(sec["write_guard_covers_bash"])   # ack present, field absent

    def _cell(self, run_dir, body=b'{"findings": []}'):
        path = os.path.join(run_dir, "findings-app-QAL.json")
        with open(path, "wb") as fh:
            fh.write(body)
        return path

    def _driver_plan(self, run_dir, out_file):
        with open(os.path.join(run_dir, "dispatch-plan-driver.json"), "w") as fh:
            json.dump([{"group": "app", "domain": "QAL", "out_file": out_file}], fh)

    def test_snapshot_is_read_from_the_run_dir_not_the_flat_path(self):
        # #1511 / Codex BR-01: the driver writes the snapshot into the PER-RUN
        # folder, but the verifier defaulted to top-level `.panopticon/`, found
        # nothing, and read the run as one that never had a snapshot -- so the
        # content-substitution guard was inactive on every ordinary driver run
        # (run-11 shipped CERTIFIED with content_hashes_checked null).
        with tempfile.TemporaryDirectory() as run_dir:
            cell = self._cell(run_dir)
            self._driver_plan(run_dir, cell)
            gr.snapshot_out_files([{"out_file": cell}],
                                  out_path=os.path.join(run_dir, "out-file-hashes.json"))
            with open(cell, "wb") as fh:            # substitute AFTER the snapshot
                fh.write(b'{"findings": ["INJECTED"]}')
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                sec = integrity_mod.integrity_section([], [cell], run_dir, 0, 0, None)
        self.assertEqual(sec["content_hashes_checked"], 1)
        self.assertEqual(sec["content_mismatched_files"], [cell])
        self.assertFalse(sec["content_snapshot_missing"])

    def test_a_stale_top_level_snapshot_cannot_poison_the_active_run(self):
        # The active run's snapshot is authoritative; a leftover top-level file
        # from an earlier run must neither replace it nor manufacture a mismatch.
        with tempfile.TemporaryDirectory() as root:
            run_dir = os.path.join(root, ".panopticon", "runs", "tag")
            os.makedirs(run_dir)
            cell = self._cell(run_dir)
            self._driver_plan(run_dir, cell)
            gr.snapshot_out_files([{"out_file": cell}],
                                  out_path=os.path.join(run_dir, "out-file-hashes.json"))
            with open(os.path.join(root, ".panopticon", "out-file-hashes.json"), "w") as fh:
                json.dump({os.path.realpath(cell): "0" * 64}, fh)
            cwd = os.getcwd()
            os.chdir(root)
            try:
                sec = integrity_mod.integrity_section([], [cell], run_dir, 0, 0, None)
            finally:
                os.chdir(cwd)
        self.assertEqual(sec["content_mismatched_files"], [])
        self.assertEqual(sec["content_hashes_checked"], 1)

    def test_a_driver_run_owing_a_snapshot_that_is_gone_fails_closed(self):
        # #1208: deleting the baseline read as a benign "not measured". On a run
        # whose driver plan declares cells, the snapshot is OWED -- its absence
        # is a deleted baseline, not an ordinary non-fan-out run.
        with tempfile.TemporaryDirectory() as run_dir:
            cell = self._cell(run_dir)
            self._driver_plan(run_dir, cell)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                sec = integrity_mod.integrity_section([], [cell], run_dir, 0, 0, None)
        self.assertTrue(sec["content_snapshot_missing"])
        self.assertIsNone(sec["content_hashes_checked"])
        self.assertIn("snapshot", err.getvalue().lower())

    def test_a_run_that_owes_nothing_keeps_a_benign_absence(self):
        # No driver plan = a legacy / manual synthesize invocation. Unchanged.
        with tempfile.TemporaryDirectory() as run_dir:
            cell = self._cell(run_dir)
            sec = integrity_mod.integrity_section([], [cell], run_dir, 0, 0, None)
        self.assertFalse(sec["content_snapshot_missing"])
        self.assertIsNone(sec["content_hashes_checked"])

    def test_an_empty_driver_plan_owes_nothing(self):
        # A declared-nothing plan cannot have produced a snapshot, so its
        # absence is not evidence of deletion.
        with tempfile.TemporaryDirectory() as run_dir:
            with open(os.path.join(run_dir, "dispatch-plan-driver.json"), "w") as fh:
                json.dump([], fh)
            sec = integrity_mod.integrity_section([], [], run_dir, 0, 0, None)
        self.assertFalse(sec["content_snapshot_missing"])

    def test_counts_pass_through(self):
        with tempfile.TemporaryDirectory() as d:
            sec = integrity_mod.integrity_section([[], []], [], d, 2, 3, "cannot read verify queue: x")
        self.assertEqual(sec["empty_dispatch_plans"], 2)
        self.assertEqual(sec["plans_seen"], 2)
        self.assertEqual(sec["invalid_dispatch_plans"], 3)
        self.assertEqual(sec["invalid_verify_queue"], "cannot read verify queue: x")

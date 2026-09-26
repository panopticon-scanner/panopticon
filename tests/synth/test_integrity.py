"""Tests for scripts.synth.integrity: planned-vs-ingested findings files, labels, the
unenforced ack and meta.integrity.
"""
import contextlib
import glob
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
import scripts.synth.tool_axis as tool_axis_mod
import scripts.synth.verdicts as verdicts_mod


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

    def test_tapestry_corpus_mislabel_canary(self):
        # A two-group matrix covers every real domain, empty and populated cells,
        # and a hyphenated group name on every ordinary test run.
        domains = ("SEC", "COD", "ARC", "TST", "QAL", "AGT", "DAT", "OPS", "ACC", "LNG")
        with tempfile.TemporaryDirectory() as base:
            files = []
            for group in ("Client-Devices", "ServiceAPI"):
                for index, domain in enumerate(domains):
                    path = os.path.join(base, f"findings-{group}-{domain}.json")
                    payload = {
                        "findings": [] if index % 3 == 0 else [{
                            "domain": domain,
                            "code": f"{domain}-X0X",
                            "title": f"{group} {domain} review",
                            "description": "A bounded review finding in the seeded corpus.",
                            "severity": "LOW",
                            "source_role": "domain_panel",
                            "location": {"file": "src/service.py", "line_start": index + 1},
                        }],
                        "_panopticon": {
                            "group": group, "domain": domain,
                            "role": "domain_panel", "run_id": "seeded-canary",
                        },
                        "schema_version": 1,
                    }
                    if group == "Client-Devices" and domain == "ARC":
                        payload["findings"].append({
                            "domain": "TST", "code": "TST-X0X",
                            "title": "Cross-domain testing gap",
                            "description": "The ARC reviewer found a testing gap.",
                            "severity": "LOW", "source_role": "domain_panel",
                            "location": {"file": "tests/test_service.py", "line_start": 8},
                        })
                    with open(path, "w", encoding="utf-8") as fh:
                        json.dump(payload, fh)
                    files.append(path)

            self.assertEqual(len(files), 20)
            self.assertEqual(integrity_mod.mislabeled_findings_files(files), [])
            self.assertEqual(
                [(row["cell_domain"], row["finding_domain"], row["code"])
                 for row in integrity_mod.cross_domain_findings(files)],
                [("ARC", "TST", "TST-X0X")],
            )

            # One reviewer writes a COD-stamped cell under a SEC filename.
            planted = os.path.join(base, "findings-Planted-SEC.json")
            with open(planted, "w", encoding="utf-8") as fh:
                json.dump({"findings": [], "_panopticon": {
                    "group": "Planted", "domain": "COD", "role": "domain_panel",
                    "run_id": "seeded-canary",
                }, "schema_version": 1}, fh)
            self.assertEqual(integrity_mod.mislabeled_findings_files(files + [planted]),
                             [planted])

        # An operator-supplied corpus is an additional read-only check. A typo
        # or an empty directory is a failed precondition, never a silent skip.
        if "PANOPTICON_TAPESTRY_CORPUS_PATH" in os.environ:
            external = os.environ["PANOPTICON_TAPESTRY_CORPUS_PATH"]
            self.assertTrue(os.path.isdir(external),
                            f"Invalid PANOPTICON_TAPESTRY_CORPUS_PATH: {external!r}")
            external_files = sorted(glob.glob(os.path.join(external, "findings-*.json")))
            self.assertTrue(external_files,
                            f"No findings-*.json in PANOPTICON_TAPESTRY_CORPUS_PATH: {external!r}")
            self.assertEqual(integrity_mod.mislabeled_findings_files(external_files), [])

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

class LoadVerifyQueueTest(unittest.TestCase):
    """Moved from tests/synth/test_plan.py with the function it covers (fix
    round 1 F1): it produces `meta.integrity.invalid_verify_queue`, so it
    belongs beside the section that publishes it, and `plan` was at its
    700-line ceiling. Behaviour is unchanged -- the three outcomes are the
    same three."""

    def test_load_verify_queue_three_outcomes(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(integrity_mod.load_verify_queue(d), (None, None))
            qp = os.path.join(d, "verify-queue.json")
            with open(qp, "w") as fh:
                json.dump({"run_id": "r1", "entries": []}, fh)
            queue, invalid = integrity_mod.load_verify_queue(d)
            self.assertEqual(queue["run_id"], "r1")
            self.assertIsNone(invalid)
            with open(qp, "w") as fh:
                json.dump({"entries": "nope"}, fh)
            self.assertEqual(integrity_mod.load_verify_queue(d),
                             (None, "verify queue has no entries list"))
            with open(qp, "w") as fh:
                fh.write("{")
            queue, invalid = integrity_mod.load_verify_queue(d)
            self.assertIsNone(queue)
            self.assertTrue(invalid.startswith("cannot read verify queue: "))


class IntegritySectionTest(unittest.TestCase):
    """WS-0 S3: meta.integrity assembled from the plan lists and ingested files."""

    KEYS = ["unexpected_findings_files", "missing_planned_files",
            "malformed_findings_files", "duplicate_out_files",
            "mislabeled_findings_files", "cross_domain_findings", "unenforced_acknowledged",
            "ack_stale", "content_hashes_checked", "content_mismatched_files",
            "content_snapshot_unreadable", "content_snapshot_missing",
            "empty_dispatch_plans", "invalid_dispatch_plans",
            "invalid_verify_queue", "plans_seen",
            # SEC-377944137 (#1832): the guard on `plans_seen`, published
            # beside it -- always present, like every other key here.
            "dispatch_plan_missing", "dispatch_plan_mismatched"]
    # #1644 lands `tools_manifest_invalid` on the section, but from reconcile
    # (which is the only caller that holds the tool axis), not from
    # integrity_section -- so the KEY ORDER pinned here is deliberately
    # unchanged and the new key is asserted where it is added.

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


class TestADeletedDispatchPlanIsDeletedEvidence(unittest.TestCase):
    """SEC-377944137 (#1832): #1208's own reasoning, one file up.

    #1208 closed the cheap erasure -- delete `out-file-hashes.json` and a
    detected findings substitution read as "not measured". Deleting the driver
    PLAN as well re-opened it, because every check keyed on that plan reads its
    ABSENCE as owing nothing: `_owes_a_snapshot` returns False (so
    `content_snapshot_missing` goes quiet), `reconcile_findings_files` returns
    `([], [])` by design, `duplicate_out_files([])` is `[]`, and
    `empty_dispatch_plans` counts empty LISTS, of which there are none when
    there are no plan FILES. `plans_seen` is the one key that notices, and it
    was not in `integrity_ok`.

    The anchor is the run manifest's recorded `review` dispatch, threaded in as
    `plan_owed`: where the write guard mediates `Write` no dispatched agent may
    write that manifest, and
    `runio._foreign_manifest` discards a git-tracked or foreign-stamped one. A
    direct `synthesize.py` call over hand-collected findings has no driver to
    ask, passes nothing, and keeps today's benign reading.
    """

    CELLS = (("Core", "SEC"), ("Core", "ARC"))

    def setUp(self):
        self.run_dir = os.path.realpath(
            self.enterContext(tempfile.TemporaryDirectory(prefix="sec-integ-")))
        self.paths = []
        for group, domain in self.CELLS:
            path = os.path.join(self.run_dir, "findings-%s-%s.json" % (group, domain))
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"_panopticon": {"group": group, "domain": domain},
                           "findings": [{"id": "%s-1" % domain,
                                         "title": "a real HIGH", "severity": "HIGH",
                                         "confidence": "CERTAIN",
                                         "location": {"file": "x.py", "line_start": 1}}]},
                          fh)
            self.paths.append(path)
        plan = [{"id": "review-%s-%s" % c, "group": c[0], "domain": c[1],
                 "out_file": os.path.join(self.run_dir, "findings-%s-%s.json" % c)}
                for c in self.CELLS]
        with open(os.path.join(self.run_dir, plan_mod.DRIVER_DISPATCH_PLAN),
                  "w", encoding="utf-8") as fh:
            json.dump(plan, fh)
        gr.snapshot_out_files(plan, out_path=os.path.join(self.run_dir,
                                                          "out-file-hashes.json"))

    def _section(self, plan_owed, plan_sha256=None):
        plans = plan_mod.load_dispatch_plans_detailed(self.run_dir)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            sec = integrity_mod.integrity_section(plans[0], self.paths, self.run_dir,
                                                  plans[1], plans[2], None,
                                                  plan_owed=plan_owed,
                                                  plan_sha256=plan_sha256)
        return sec, err.getvalue()

    def _plan_hash(self):
        return integrity_mod._plan_hash(
            plan_mod.load_dispatch_plans_detailed(self.run_dir)[0][0])

    def _integrity_ok(self, section):
        """reconcile's OWN `integrity_ok`, never re-spelled here: a test that
        re-states the expression cannot fail when the expression is the bug."""
        inp = report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high",
                                     timestamp="2026-01-01T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["a.py"]}],
                                     integrity=dict(section)))
        resolved = verdicts_mod.resolve_findings(
            inp.findings, inp.delta, inp.run,
            gated_suppressed=inp.tools.gated_suppressed)
        return tool_axis_mod.reconcile(inp.plan, inp.tools, resolved,
                                       run=inp.run).integrity_ok

    def _substitute(self):
        """Drop the HIGH out of the SEC cell, after the snapshot was taken."""
        with open(self.paths[0], "w", encoding="utf-8") as fh:
            json.dump({"_panopticon": {"group": "Core", "domain": "SEC"},
                       "findings": []}, fh)

    def test_row_1_an_honest_run_certifies(self):
        sec, _err = self._section(plan_owed=True)
        self.assertEqual(sec["plans_seen"], 1)
        self.assertEqual(sec["content_hashes_checked"], 2)
        self.assertEqual(sec["content_mismatched_files"], [])
        self.assertFalse(sec["dispatch_plan_missing"])
        self.assertTrue(self._integrity_ok(sec))

    def test_row_2_a_substitution_with_the_evidence_intact_is_caught(self):
        self._substitute()
        sec, _err = self._section(plan_owed=True)
        self.assertEqual(sec["content_mismatched_files"], [self.paths[0]])
        self.assertFalse(sec["dispatch_plan_missing"])
        self.assertFalse(self._integrity_ok(sec))

    def test_row_3_deleting_the_snapshot_does_not_erase_it(self):
        # #1208, unchanged: the plan still declares cells, so the snapshot is OWED.
        self._substitute()
        os.remove(os.path.join(self.run_dir, "out-file-hashes.json"))
        sec, _err = self._section(plan_owed=True)
        self.assertTrue(sec["content_snapshot_missing"])
        self.assertFalse(sec["dispatch_plan_missing"])
        self.assertFalse(self._integrity_ok(sec))

    def test_row_4_deleting_the_plan_too_does_not_erase_it_either(self):
        # The finding: one more `rm` and every plan-keyed check went quiet.
        self._substitute()
        os.remove(os.path.join(self.run_dir, "out-file-hashes.json"))
        os.remove(os.path.join(self.run_dir, plan_mod.DRIVER_DISPATCH_PLAN))
        sec, err = self._section(plan_owed=True)
        self.assertEqual(sec["plans_seen"], 0)
        self.assertIsNone(sec["content_hashes_checked"])
        self.assertEqual(sec["content_mismatched_files"], [])
        self.assertFalse(sec["content_snapshot_missing"])
        self.assertTrue(sec["dispatch_plan_missing"])
        self.assertFalse(self._integrity_ok(sec))
        self.assertIn("deleted evidence", err)

    def test_the_stamped_hash_clears_the_plan_that_produced_it(self):
        sec, err = self._section(plan_owed=True, plan_sha256=self._plan_hash())
        self.assertFalse(sec["dispatch_plan_mismatched"])
        self.assertTrue(self._integrity_ok(sec))
        self.assertNotIn("NOT the one this run wrote", err)

    def test_a_plan_that_is_present_but_not_this_run_s_is_tamper(self):
        # Replacing the plan is the same erasure as deleting it, and cheaper: a
        # narrower plan has fewer cells for reconcile to miss.
        sec, err = self._section(plan_owed=True, plan_sha256="0" * 64)
        self.assertEqual(sec["plans_seen"], 1)          # present, and parses
        self.assertFalse(sec["dispatch_plan_missing"])   # so not a deletion
        self.assertTrue(sec["dispatch_plan_mismatched"])
        self.assertFalse(self._integrity_ok(sec))
        self.assertIn("NOT the one this run wrote", err)

    def test_a_deleted_plan_is_not_also_reported_as_mismatched(self):
        # One fault, one key: absence is `dispatch_plan_missing`, and there is
        # no content to disagree with.
        os.remove(os.path.join(self.run_dir, plan_mod.DRIVER_DISPATCH_PLAN))
        sec, _err = self._section(plan_owed=True, plan_sha256="0" * 64)
        self.assertTrue(sec["dispatch_plan_missing"])
        self.assertFalse(sec["dispatch_plan_mismatched"])

    def test_a_run_with_no_driver_to_ask_keeps_the_benign_reading(self):
        # Back-compat pin: a direct `synthesize.py` call over hand-collected
        # findings passes no --plan-owed, and absence stays "not measured" --
        # the property every other key in this dict has.
        os.remove(os.path.join(self.run_dir, plan_mod.DRIVER_DISPATCH_PLAN))
        plans = plan_mod.load_dispatch_plans_detailed(self.run_dir)
        sec = integrity_mod.integrity_section(plans[0], self.paths, self.run_dir,
                                              plans[1], plans[2], None)
        self.assertEqual(sec["plans_seen"], 0)
        self.assertFalse(sec["dispatch_plan_missing"])
        self.assertFalse(sec["dispatch_plan_mismatched"])
        self.assertTrue(self._integrity_ok(sec))

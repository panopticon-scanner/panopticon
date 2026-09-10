"""Integration tests for scripts.driver: run(), the CLI, the PHASES table and the
end-to-end loops. Per-phase tests live in tests/phases/test_<module>.py, mirroring
skill/scripts/phases/ (WS-0 D5). This file carried a TECH DEBT note about being an
unsplittable monolith from 5.0 until then.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import scripts.phases.runio as runio
import scripts.phases.engine as engine
import scripts.phases.requests as requests
import scripts.phases.discovery as discovery
import scripts.phases.coverage as coverage
import scripts.phases.review as review
import scripts.phases.verify as verify
import scripts.phases.synthesize as synthesize
import scripts.phases.validate as validate_phase

import scripts.driver as driver
import scripts.diff_map as diff_map
import scripts.groups_schema as groups_schema
import scripts.plan_contract as plan_contract
import scripts.run_manifest as run_manifest

from tools.git_repo import make_git_repo


class TestDriverCLIAndEndToEnd(unittest.TestCase):
    def _repo(self):
        return make_git_repo(
            test_case=self,
            files={"src/app.py": "def f():\n    return 1\n"},
            groups_yml="groups:\n  Core:\n    match: ['src/**']\n    panels: [COD]\n",
            branch="main",
            user_email="t@t",
            user_name="t",
        )

    def _args(self, target, *extra):
        return driver.build_parser().parse_args(["run", target, *extra])

    def _inject_scouts(self, root):
        for g, _ in coverage._discovered_groups(root):
            p = runio._pano(root, "scout-%s.json" % g)
            if not os.path.exists(p):
                runio._write_json(p, {"group": g, "panels": ["code"]})

    def _inject_review(self, root):
        # Simulates the dispatched domain-panel reviewers landing their
        # findings files, so the E2E loop can progress past the review
        # checkpoint (P4 cell fan-out) the same way _inject_scouts simulates
        # the scout checkpoint.
        req = runio._load_json(runio._pano(root, "dispatch-request.json"))
        if not (isinstance(req, dict) and req.get("checkpoint") == "review"):
            return
        run_id = run_manifest.load_manifest(root)["run_id"]
        for e in req["entries"]:
            stem = os.path.basename(e["out_file"])[len("findings-"):-len(".json")]
            group, domain = stem.rsplit("-", 1)
            runio._write_json(e["out_file"], {"findings": [],
                "_panopticon": {"run_id": run_id, "role": "domain_panel",
                                 "domain": domain, "group": group}})

    def test_first_run_writes_manifest_and_baseline(self):
        d = self._repo()
        driver.run(self._args(d))
        self.assertIsNotNone(run_manifest.load_manifest(d))
        self.assertTrue(os.path.isfile(runio._pano(d, "tree-baseline.txt")))

    def test_corrupt_manifest_is_reset_not_wedged(self):
        # #5.0-13: a present-but-unparseable run-manifest.json must not raise an
        # uncaught FileExistsError from write_manifest (write-once); it's reset.
        d = self._repo()
        with open(run_manifest.manifest_path(d), "w", encoding="utf-8") as fh:
            fh.write("{ not valid json")
        status = driver.run(self._args(d))   # must not raise FileExistsError
        self.assertNotEqual(status["status"], "error", status.get("message"))
        self.assertIsNotNone(run_manifest.load_manifest(d))   # fresh manifest written

    def test_resolve_review_root_failure_is_status_error(self):
        # #5.0-14: a --pr acquisition failure (gh/network/bad PR) is reported via
        # the status protocol, not a raw RuntimeError escaping run().
        d = self._repo()
        with mock.patch.object(runio, "resolve_review_root",
                               side_effect=RuntimeError("gh: PR not found")):
            status = driver.run(self._args(d))
        self.assertEqual(status["status"], "error")
        self.assertIn("resolve review root", status["message"])

    def test_end_to_end_reaches_report(self):
        d = self._repo()
        # --no-tools keeps this review->report end-to-end deterministic: with a
        # working tools image present the tool scan emits findings, and the
        # #5.0-03 tool-advisor verify round has no servicer in this fixture (that
        # path is covered by test_driver_tool_verify.py).
        args = self._args(d, "--no-tools")
        status = driver.run(args)
        self.assertEqual(status["status"], "checkpoint")
        self.assertEqual(status["checkpoint"], "scout")
        for _ in range(30):
            if status["status"] == "checkpoint":
                self._inject_scouts(d)
                self._inject_review(d)
            status = driver.run(args)
            self.assertNotEqual(status["status"], "error", status.get("message"))
            if status["status"] == "complete":
                break
        self.assertEqual(status["status"], "complete")
        self.assertTrue(os.path.isfile(runio._pano(d, "report.json")))
        # #1: re-invoking a COMPLETED run refuses (never silently returns a
        # possibly-stale report as though it were fresh) and names --reset; the
        # durable report stays on disk.
        redo = driver.run(args)
        self.assertEqual(redo["status"], "error")
        self.assertIn("already complete", redo["message"])
        self.assertIn("--reset", redo["message"])
        self.assertTrue(os.path.isfile(runio._pano(d, "report.json")))
        # --reset starts a new run: back to the first checkpoint, not an error
        self.assertEqual(
            driver.run(self._args(d, "--no-tools", "--reset"))["status"],
            "checkpoint")

    def test_resume_reemits_same_checkpoint_before_dispatch(self):
        d = self._repo()
        args = self._args(d)
        s1 = driver.run(args)
        s2 = driver.run(args)   # nothing serviced -> identical checkpoint
        self.assertEqual((s1["checkpoint"], s1["group"]),
                         (s2["checkpoint"], s2["group"]))

    def test_flag_drift_is_refused(self):
        d = self._repo()
        driver.run(self._args(d))                       # manifest = standard
        status = driver.run(self._args(d, "--security", "redteam"))
        self.assertEqual(status["status"], "error")
        self.assertIn("drift", status["message"])

    def test_flag_drift_refused_no_synthesize_divergence(self):
        # RETIRED HAZARD (#957 both-pass flag mismatch): the manifest pins the
        # gate flags once; a conflicting re-invocation is refused, so pass-1 and
        # pass-2 synthesize can never diverge.
        d = self._repo()
        driver.run(self._args(d, "--fail-on", "high"))
        status = driver.run(self._args(d, "--fail-on", "low"))
        self.assertEqual(status["status"], "error")
        self.assertIn("drift", status["message"])

    def test_scope_group_flag_parses(self):
        args = driver.build_parser().parse_args(["run", "x", "-g", "Auth"])
        self.assertEqual(args.scope_group, "Auth")
        self.assertIsNone(args.scope_file)
        self.assertIsNone(args.scope_dir)

    def test_scope_flags_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            driver.build_parser().parse_args(
                ["run", "x", "-g", "Auth", "-f", "src/app.py"])

    def test_scope_changed_flag_parses(self):
        args = driver.build_parser().parse_args(["run", "x", "-c"])
        self.assertTrue(args.scope_changed)
        self.assertEqual(driver._scope_from_args(args),
                         {"mode": "changed", "target": None})

    def test_scope_files_flag_parses(self):
        args = driver.build_parser().parse_args(
            ["run", "x", "--files", "a.py", "b.py"])
        self.assertEqual(args.scope_files, ["a.py", "b.py"])
        self.assertEqual(driver._scope_from_args(args),
                         {"mode": "files", "target": ["a.py", "b.py"]})

    def test_scope_changed_is_mutually_exclusive_with_group(self):
        with self.assertRaises(SystemExit):
            driver.build_parser().parse_args(["run", "x", "-g", "Auth", "-c"])

    def test_scope_recorded_on_manifest(self):
        d = self._repo()
        driver.run(self._args(d, "-g", "Auth"))
        manifest = run_manifest.load_manifest(d)
        self.assertEqual(manifest["scope"], {"mode": "group", "target": "Auth"})

    def test_scope_drift_is_refused(self):
        d = self._repo()
        driver.run(self._args(d, "-g", "Auth"))          # manifest scoped to Auth
        status = driver.run(self._args(d, "-g", "Checkout"))
        self.assertEqual(status["status"], "error")
        self.assertIn("drift", status["message"])
        self.assertIn("scope", status["message"])

    def test_reset_restarts_from_scratch(self):
        # #1515: --no-tools because this is the one lifecycle test that advances
        # far enough to reach tools_execute, which spawns run_tools.py as a
        # CHILD process -- conftest's docker refusal is in-process and cannot
        # cross that boundary. Without the flag this test launched a real
        # `docker run --memory 6g` scanner on any workstation with the image.
        # It asserts on the reset/checkpoint state machine, not on scanners.
        d = self._repo()
        args = self._args(d, "--no-tools")
        driver.run(args)
        self._inject_scouts(d)
        driver.run(args)                                # advance past scout
        status = driver.run(self._args(d, "--no-tools", "--reset"))
        self.assertEqual(status["status"], "checkpoint")
        self.assertEqual(status["checkpoint"], "scout")
        # reset never deletes the committed matrix
        self.assertTrue(os.path.isfile(runio._pano(d, "groups.yml")))

    def test_main_prints_status_and_returns_exit_code(self):
        d = self._repo()
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = driver.main(["run", d])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(buf.getvalue())["status"], "checkpoint")

    def test_pr_acquires_worktree_and_records_manifest(self):
        # C1 flip: driver --pr now acquires the deterministic PR worktree via
        # resolve_review_root, rather than refusing. Finding B: with NO explicit
        # --base, manifest["base"] stays None (anti-drift key -- a bare resume
        # passes base=None -> no false drift) and the gh-detected PR base lands
        # in manifest["pr_base"], the origin-preference channel.
        d = self._repo()
        args = driver.build_parser().parse_args(["run", d, "--pr", "7"])
        with mock.patch(
                "scripts.phases.runio.resolve_review_root",
                return_value=(d, d, "main")) as resolve:
            status = driver.run(args)
        resolve.assert_called_once()
        _call_args, call_kwargs = resolve.call_args
        self.assertEqual(call_kwargs.get("pr"), 7)
        self.assertNotEqual(status["status"], "error", status.get("message"))
        manifest = run_manifest.load_manifest(d)
        self.assertEqual(manifest["pr"], 7)
        self.assertEqual(manifest["worktree"], d)
        self.assertIsNone(manifest["base"])          # explicit-only; none given
        self.assertEqual(manifest["pr_base"], "main")  # gh base -> pr_base channel
        self.assertEqual(manifest["scope"], {"mode": "changed", "target": None})

    def test_run_finalizes_worktree_only_on_complete(self):
        # Ruling A wiring: run() surfaces+releases the worktree via
        # _finalize_worktree ONLY when the engine returns status=="complete" --
        # never on a mid-run checkpoint (which must leave the worktree in place so
        # the resume can re-enter it).
        d = self._repo()
        complete = {"status": "complete", "phase": None, "checkpoint": None,
                    "group": None, "dispatch_request": None, "advanced": [],
                    "message": "all phases complete"}
        checkpoint = dict(complete, status="checkpoint", checkpoint="scout")

        with mock.patch("scripts.phases.engine.run_engine", return_value=complete), \
                mock.patch("scripts.phases.validate._finalize_worktree") as fin:
            status = driver.run(self._args(d))
        self.assertEqual(status["status"], "complete")
        fin.assert_called_once()

        d2 = self._repo()
        with mock.patch("scripts.phases.engine.run_engine", return_value=checkpoint), \
                mock.patch("scripts.phases.validate._finalize_worktree") as fin2:
            status2 = driver.run(self._args(d2))
        self.assertEqual(status2["status"], "checkpoint")
        fin2.assert_not_called()

    def test_fresh_manifest_clears_stale_artifacts(self):
        # I1: a stale report.json with no manifest must be cleared on the first
        # run, not resumed as "synthesize done".
        d = self._repo()
        stale = runio._pano(d, "report.json")
        runio._write_json(stale, {"stale": True})
        status = driver.run(self._args(d))     # first run -> manifest built
        self.assertNotEqual(status["status"], "error", status.get("message"))
        self.assertFalse(os.path.exists(stale))  # stale artifact cleared

    def test_missing_baseline_self_heals_on_resume(self):
        # I2: a manifest written without a baseline (interrupt window) must get
        # the baseline captured on the next invocation.
        d = self._repo()
        m = run_manifest.build_manifest(
            target=d, review_root=d, host="claude", security_mode="standard")
        run_manifest.write_manifest(d, m)        # manifest, but NO baseline
        self.assertFalse(os.path.exists(runio._pano(d, "tree-baseline.txt")))
        driver.run(self._args(d))                # resume -> should self-heal
        self.assertTrue(os.path.exists(runio._pano(d, "tree-baseline.txt")))

class TestReviewMatrixEndToEnd(unittest.TestCase):
    """Task 6: the whole 5.0 review matrix, end to end, against the real
    driver + discovery + synthesize subprocesses -- discovery -> coverage
    (+scout domains) -> tools -> review (cells fire) -> verify (no-op) ->
    synthesize -> a real report.json with (domain, code) findings."""

    def _repo(self):
        # #5.0-11: GLOBAL_FLOOR folds ARC/COD/DAT/TST into every group's
        # effective panel set; exclude the three non-COD floor members so
        # this fixture keeps its original single-cell (COD-only) shape.
        return make_git_repo(
            test_case=self,
            files={"src/app.py": "def f():\n    return 1\n"},
            groups_yml=("groups:\n"
                        "  Core:\n"
                        "    match: ['src/**']\n"
                        "    panels: [COD]\n"
                        "    exclude: [ARC, DAT, TST]\n"),
            branch=None,
            user_email="t@t",
            user_name="t",
        )

    def _args(self, d):
        # --no-tools: this fixture services scout + review checkpoints only; with
        # a tools image present the tool scan would emit the #5.0-03 tool-advisor
        # verify round, which has no servicer here (that path is covered by
        # test_driver_tool_verify.py). Keeps the run deterministic across envs.
        return driver.build_parser().parse_args(
            ["run", d, "--host", "claude", "--no-tools"])

    def _service(self, d, status, run_id):
        # emulate the orchestrator dispatching whatever the checkpoint asked for
        if status.get("checkpoint") == "scout":
            for g, _ in coverage._discovered_groups(d):
                p = runio._pano(d, "scout-%s.json" % g)
                if not os.path.exists(p):
                    runio._write_json(p, {"group": g, "domains": ["COD"]})
        elif status.get("checkpoint") == "review":
            req = runio._load_json(runio._pano(d, "dispatch-request.json"))
            for e in req["entries"]:
                # #5: review cells are batched (group=None on the request); each
                # entry is self-describing -- id == "review-<group>-<domain>".
                grp, dom = e["id"][len("review-"):].rsplit("-", 1)
                runio._write_json(e["out_file"], {
                    "findings": [{"title": "t", "severity": "LOW",
                                  "domain": dom, "code": dom + "-X0X",
                                  "location": {"file": "src/app.py", "line": 1}}],
                    "_panopticon": {"run_id": run_id, "role": "domain_panel",
                                    "domain": dom, "group": grp}})

    def test_review_matrix_reaches_report_with_coded_findings(self):
        d = self._repo()
        args = self._args(d)
        status = driver.run(args)
        run_id = run_manifest.load_manifest(d)["run_id"]
        for _ in range(40):
            if status["status"] == "checkpoint":
                self._service(d, status, run_id)
            status = driver.run(args)
            self.assertNotEqual(status["status"], "error", status.get("message"))
            if status["status"] == "complete":
                break
        self.assertEqual(status["status"], "complete")
        report = runio._load_json(runio._pano(d, "report.json"))
        codes = [f.get("code") for f in report.get("findings", [])]
        self.assertTrue(any(c and c.startswith("COD") for c in codes))
        self.assertEqual(report["meta"]["ocrdb_version"], "0.5.0")

class TestVerifyMatrixEndToEnd(unittest.TestCase):
    """5.0-P5 Slice B Task 5: verify is no longer a no-op. Against the real
    driver functions (verify_execute/verify_done) and
    a real synthesize.py subprocess (phases.synthesize.synthesize_execute) -- mirrors
    TestReviewMatrixEndToEnd's real-artifact style, but drives review/verify
    state directly on disk (as TestVerifyPrimary/TestVerifyBackup in
    test_driver_verify.py do) rather than through the full driver.run()
    checkpoint loop, since a withheld verdict would otherwise re-emit the verify
    checkpoint forever."""

    RUN_ID = "RID"

    def _repo(self, floor):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("def f():\n    return 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        runio._write_json(runio._pano(d, "groups.json"),
                           {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        with open(runio._pano(d, "groups.yml"), "w") as fh:
            fh.write("groups:\n  app:\n    match: ['src/**']\n")   # #1092 healthy resume
        runio._write_json(runio._pano(d, "coverage-app.json"),
                           {"group": "app", "floor": floor, "effective": floor,
                            "run_id": self.RUN_ID})
        return d

    def _manifest(self):
        return {"run_id": self.RUN_ID, "host": "claude", "security_mode": "standard",
                "flags": {"fail_on": "high"}}

    def _write_cell(self, d, domain, severity="HIGH"):
        # A HIGH finding at the default (POSSIBLE) confidence scores 5*0.8*1 =
        # 4.0 -- above F_p (1.5, engages the primary advisor) but, even once
        # advisor_confirmed (x1.5 -> 6.0), below F_b (8.0, summons a backup) --
        # so the primary round alone settles the cell.
        runio._write_json(runio._pano(d, "findings-app-%s.json" % domain), {
            "findings": [{"title": "issue in %s" % domain, "severity": severity,
                          "domain": domain, "code": domain + "-A1A", "category": "authz",
                          "location": {"file": "src/app.py", "line_start": 1}}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                            "domain": domain, "group": "app"}})

    def _confirm_bundle(self, d, manifest, domain, group="app"):
        cell = review._load_cell_findings(d, manifest, group, domain)
        fid = cell[0]["id"]   # driver's own id assignment -- what an advisor echoes
        return json.dumps({"verdicts": [{"finding_id": fid, "verdict": "CONFIRMED",
                                         "reasoning": "verified by advisor"}],
                           "_panopticon": {"run_id": manifest["run_id"],
                                           "role": "domain_advisor", "domain": domain,
                                           "group": group, "stage": "primary"}})

    def _self_write(self, entry, text):
        """Simulate the advisor self-writing its bundle to entry['out_file']."""
        os.makedirs(os.path.dirname(entry["out_file"]), exist_ok=True)
        with open(entry["out_file"], "w") as fh:
            fh.write(text)

    def test_confirmed_verdict_reaches_advisor_confirmed_report(self):
        d = self._repo(["SEC"])
        self._write_cell(d, "SEC")
        manifest = self._manifest()

        result = verify.verify_execute(d, manifest)
        self.assertEqual(result.kind, "checkpoint")
        self.assertEqual(result.checkpoint, "verify")
        req = runio._load_json(runio._pano(d, "dispatch-request.json"))
        entry = req["entries"][0]

        text = self._confirm_bundle(d, manifest, "SEC")
        self._self_write(entry, text)

        result2 = verify.verify_execute(d, manifest)   # drains the (empty) backup round
        self.assertEqual(result2.kind, "advanced")
        self.assertTrue(verify.verify_done(d, manifest))

        synth = synthesize.synthesize_execute(d, manifest)
        self.assertEqual(synth.kind, "advanced")
        report = runio._load_json(runio._pano(d, "report.json"))
        finding = next(f for f in report["findings"] if f.get("domain") == "SEC")
        self.assertEqual(finding["evidence"]["status"], "advisor_confirmed")
        # verify actually resolved the cell -- not left as an unanswered gap.
        self.assertNotEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_withheld_engaged_cell_yields_inconclusive(self):
        d = self._repo(["SEC"])
        self._write_cell(d, "SEC")
        manifest = self._manifest()

        result = verify.verify_execute(d, manifest)   # engages SEC, dispatches, never answered
        self.assertEqual(result.checkpoint, "verify")
        self.assertFalse(verify.verify_done(d, manifest))

        synth = synthesize.synthesize_execute(d, manifest)
        self.assertEqual(synth.kind, "advanced")
        report = runio._load_json(runio._pano(d, "report.json"))
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")
        self.assertIn(["app", "SEC"],
                      report["meta"]["coverage"]["verify_matrix"]["unverified_engaged"])

    def test_resume_checkpoint_names_only_the_undone_cell(self):
        d = self._repo(["SEC", "QAL"])
        self._write_cell(d, "SEC")
        self._write_cell(d, "QAL")
        manifest = self._manifest()

        result = verify.verify_execute(d, manifest)   # both cells pending, one dispatch
        self.assertEqual(result.checkpoint, "verify")
        req = runio._load_json(runio._pano(d, "dispatch-request.json"))
        outs = sorted(os.path.basename(e["out_file"]) for e in req["entries"])
        self.assertEqual(outs, ["verdicts-app-QAL.json", "verdicts-app-SEC.json"])
        sec_entry = next(e for e in req["entries"]
                         if e["out_file"].endswith("verdicts-app-SEC.json"))

        text = self._confirm_bundle(d, manifest, "SEC")
        self._self_write(sec_entry, text)

        result2 = verify.verify_execute(d, manifest)
        self.assertEqual(result2.kind, "checkpoint")
        req2 = runio._load_json(runio._pano(d, "dispatch-request.json"))
        outs2 = [os.path.basename(e["out_file"]) for e in req2["entries"]]
        self.assertEqual(outs2, ["verdicts-app-QAL.json"])   # SEC is done; only QAL remains

class TestDriverRunLoopEndToEnd(unittest.TestCase):
    """P6.1: the controller run-loop drives review + verify to a graded report
    purely by self-writing each checkpoint's entries' out_files between driver
    invocations (no persist_returned_verdict, no write_mode)."""

    RUN_ID = "RID"

    def _repo(self, floor):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("def f():\n    return 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        runio._write_json(runio._pano(d, "groups.json"),
                           {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        with open(runio._pano(d, "groups.yml"), "w") as fh:
            fh.write("groups:\n  app:\n    match: ['src/**']\n")   # #1092 healthy resume
        runio._write_json(runio._pano(d, "coverage-app.json"),
                           {"group": "app", "floor": floor, "effective": floor,
                            "run_id": self.RUN_ID})
        return d

    def _manifest(self):
        return {"run_id": self.RUN_ID, "host": "claude", "security_mode": "standard",
                "flags": {"fail_on": "high"}}

    def _self_write_review(self, d, entry, domain, group="app"):
        runio._write_json(entry["out_file"], {
            "findings": [{"title": "issue in %s" % domain, "severity": "HIGH",
                          "domain": domain, "code": domain + "-A1A", "category": "authz",
                          "location": {"file": "src/app.py", "line_start": 1}}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                            "domain": domain, "group": group}})

    def _self_write_verify(self, d, manifest, entry, domain, group="app"):
        cell = review._load_cell_findings(d, manifest, group, domain)
        fid = cell[0]["id"]
        stage = "backup" if entry["out_file"].endswith("-backup.json") else "primary"
        runio._write_json(entry["out_file"], {
            "verdicts": [{"finding_id": fid, "verdict": "CONFIRMED",
                          "reasoning": "verified"}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_advisor",
                            "domain": domain, "group": group, "stage": stage}})

    def test_loop_reaches_graded_report_via_self_writes(self):
        d = self._repo(["SEC"])
        manifest = self._manifest()
        # review checkpoint
        r = review.review_execute(d, manifest)
        self.assertEqual(r.checkpoint, "review")
        req = requests.load_dispatch_request(d)
        for e in req["entries"]:
            self.assertNotIn("write_mode", e)          # unified self-write shape
            self._self_write_review(d, e, "SEC")
        self.assertTrue(review.review_done(d, manifest))
        # verify checkpoint (primary; SEC HIGH is < F_b so no backup)
        v = verify.verify_execute(d, manifest)
        self.assertEqual(v.checkpoint, "verify")
        req = requests.load_dispatch_request(d)
        for e in req["entries"]:
            self._self_write_verify(d, manifest, e, "SEC")
        v2 = verify.verify_execute(d, manifest)
        self.assertEqual(v2.kind, "advanced")
        self.assertTrue(verify.verify_done(d, manifest))
        # synthesize → graded report, advisor_confirmed, not INCONCLUSIVE
        self.assertEqual(synthesize.synthesize_execute(d, manifest).kind, "advanced")
        report = runio._load_json(runio._pano(d, "report.json"))
        finding = next(f for f in report["findings"] if f.get("domain") == "SEC")
        self.assertEqual(finding["evidence"]["status"], "advisor_confirmed")
        self.assertNotEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_below_gate_cell_needs_no_verify(self):
        d = self._repo(["QAL"])
        manifest = self._manifest()
        review.review_execute(d, manifest)
        for e in requests.load_dispatch_request(d)["entries"]:
            runio._write_json(e["out_file"], {
                "findings": [{"title": "nit", "severity": "LOW", "domain": "QAL",
                              "code": "QAL-A1A", "category": "style",
                              "location": {"file": "src/app.py", "line_start": 1}}],
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": "QAL", "group": "app"}})
        # QAL LOW scores 0 < F_p → verify engages nothing → advances
        self.assertEqual(verify.verify_execute(d, manifest).kind, "advanced")
        self.assertTrue(verify.verify_done(d, manifest))

    def test_scout_checkpoint_is_read_only_return_persist(self):
        # The run's FIRST checkpoint (scout) is the opposite shape from
        # review/verify: the scout agent is read-only and cannot self-write,
        # so the host must capture its RETURNED ScopeProfile JSON and write it
        # to the entry's out_file itself (no write-guard involved). Drive that
        # live — no pre-seeded coverage-<group>.json — through coverage_execute.
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("def f():\n    return 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        runio._write_json(runio._pano(d, "groups.json"),
                           {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        with open(runio._pano(d, "groups.yml"), "w") as fh:
            fh.write("groups:\n  app:\n    match: ['src/**']\n")   # #1091 healthy resume
        manifest = self._manifest()

        result = coverage.coverage_execute(d, manifest)
        self.assertEqual(result.kind, "checkpoint")
        self.assertEqual(result.checkpoint, "scout")
        self.assertFalse(coverage.coverage_done(d, manifest))

        req = requests.load_dispatch_request(d)
        self.assertEqual(req["checkpoint"], "scout")
        for entry in req["entries"]:
            # host-side return-persist: no self-write, the host writes what
            # the read-only scout returned.
            runio._write_json(entry["out_file"],
                               {"group": "app", "domains": ["SEC"]})

        result2 = coverage.coverage_execute(d, manifest)
        self.assertEqual(result2.kind, "advanced")
        self.assertTrue(coverage.coverage_done(d, manifest))

class TestDriverSingleScopeEndToEnd(unittest.TestCase):
    """P6.2: a committed multi-group matrix + `manifest["scope"]` restricts
    the REAL `discovery.py --repo-scan --scope-group` subprocess to the
    target group's files, and the run-loop reaches a graded report from that
    restricted matrix -- mirrors TestDriverRunLoopEndToEnd's self-write
    harness (P6.1), starting one phase earlier at discovery. A repo with no
    committed groups.yml fails discovery loudly (run `panopticon setup`
    first) rather than silently reviewing everything."""

    RUN_ID = "RID"

    def _repo_with_two_groups(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        for p in ("src/auth/login.py", "src/checkout/pay.py", "src/checkout/cart.py"):
            full = os.path.join(d, *p.split("/"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as fh:
                fh.write("def f():\n    return 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        with open(runio._pano(d, "groups.yml"), "w") as fh:
            # #5.0-11: GLOBAL_FLOOR folds ARC/COD/DAT/TST into every group's
            # effective panel set; exclude all four so each group's fixture
            # keeps its original single-cell (SEC-only) shape.
            fh.write(
                "groups:\n"
                "  Auth:\n    match: ['src/auth/**']\n    panels: [SEC]\n"
                "    exclude: [ARC, COD, DAT, TST]\n"
                "  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n"
                "    exclude: [ARC, COD, DAT, TST]\n")
        # discovery_execute subprocesses the REAL discovery.py --repo-scan,
        # which discovers via `git ls-files` -- commit the fixture so it's seen.
        subprocess.run(["git", "init", "-q"], cwd=d, check=True)
        subprocess.run(["git", "add", "-A"], cwd=d, check=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-qm", "x"], cwd=d, check=True)
        return d

    def _manifest(self):
        return {"run_id": self.RUN_ID, "host": "claude", "security_mode": "standard",
                "flags": {"fail_on": "high"},
                "scope": {"mode": "group", "target": "Checkout"}}

    def _self_write_review(self, entry, domain, group):
        runio._write_json(entry["out_file"], {
            "findings": [{"title": "issue in %s" % domain, "severity": "HIGH",
                          "domain": domain, "code": domain + "-A1A", "category": "authz",
                          "location": {"file": "src/checkout/pay.py", "line_start": 1}}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                            "domain": domain, "group": group}})

    def _self_write_verify(self, d, manifest, entry, domain, group):
        cell = review._load_cell_findings(d, manifest, group, domain)
        fid = cell[0]["id"]
        stage = "backup" if entry["out_file"].endswith("-backup.json") else "primary"
        runio._write_json(entry["out_file"], {
            "verdicts": [{"finding_id": fid, "verdict": "CONFIRMED",
                          "reasoning": "verified"}],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_advisor",
                            "domain": domain, "group": group, "stage": stage}})

    def test_single_scope_restricts_matrix_and_reaches_graded_report(self):
        d = self._repo_with_two_groups()
        manifest = self._manifest()

        # discovery: the real discovery.py --repo-scan --scope-group Checkout
        # subprocess -- single-scope restricts the matrix to the target group.
        result = discovery.discovery_execute(d, manifest)
        self.assertEqual(result.kind, "advanced")
        groups_json = runio._load_json(runio._pano(d, "groups.json"))
        names = {g["name"] for g in groups_json["groups"]}
        files = sorted(f for g in groups_json["groups"] for f in g["files"])
        self.assertEqual(names, {"Checkout"})              # Auth excluded entirely
        self.assertEqual(files, ["src/checkout/cart.py", "src/checkout/pay.py"])

        # coverage: scout checkpoint (read-only return-persist) then floor+scout
        cov = coverage.coverage_execute(d, manifest)
        self.assertEqual(cov.checkpoint, "scout")
        self.assertIsNone(cov.group)                 # #1056: scouts batched, group=None
        req = requests.load_dispatch_request(d)
        for e in req["entries"]:
            runio._write_json(e["out_file"], {"group": "Checkout", "domains": ["SEC"]})
        self.assertEqual(coverage.coverage_execute(d, manifest).kind, "advanced")
        self.assertTrue(coverage.coverage_done(d, manifest))

        # review checkpoint -- self-write cell findings, scoped to Checkout's files
        r = review.review_execute(d, manifest)
        self.assertEqual(r.checkpoint, "review")
        self.assertIsNone(r.group)                          # #5: review cells batched, group=None
        req = requests.load_dispatch_request(d)
        for e in req["entries"]:
            self.assertNotIn("write_mode", e)               # unified self-write shape
            self._self_write_review(e, "SEC", "Checkout")
        self.assertTrue(review.review_done(d, manifest))

        # verify checkpoint -- primary only (SEC HIGH is < F_b, so no backup)
        v = verify.verify_execute(d, manifest)
        self.assertEqual(v.checkpoint, "verify")
        req = requests.load_dispatch_request(d)
        for e in req["entries"]:
            self._self_write_verify(d, manifest, e, "SEC", "Checkout")
        self.assertEqual(verify.verify_execute(d, manifest).kind, "advanced")
        self.assertTrue(verify.verify_done(d, manifest))

        # synthesize -> graded report, every finding confined to Checkout's files
        self.assertEqual(synthesize.synthesize_execute(d, manifest).kind, "advanced")
        report = runio._load_json(runio._pano(d, "report.json"))
        self.assertTrue(report["findings"])
        for f in report["findings"]:
            self.assertTrue(f["location"]["file"].startswith("src/checkout/"))
        finding = next(f for f in report["findings"] if f.get("domain") == "SEC")
        self.assertEqual(finding["evidence"]["status"], "advisor_confirmed")
        self.assertNotEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_discovery_without_committed_groups_yml_raises_loud_setup_error(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, ".panopticon"))   # no groups.yml -- un-setup repo
        manifest = self._manifest()
        with self.assertRaises(runio.DriverError) as cm:
            discovery.discovery_execute(d, manifest)
        self.assertIn("panopticon setup", str(cm.exception))

class TestDriverDeltaEndToEnd(unittest.TestCase):
    """P6.3: the LAST 5.0 driver e2e -- proves the delta (`-c`) + `--pr` paths
    against a REAL git repo, no live `gh`. Mirrors
    TestDriverSingleScopeEndToEnd's real-git-repo + self-write harness
    (P6.2), scoped to `changed` instead of `group`:

    - `-c` delta: the real `discovery.py --repo-scan --scope-changed
      --base` subprocess restricts groups.json to the one changed file and
      emits `.panopticon/diff-hunks.json`; the run-loop reaches a graded
      report whose delta block is populated and whose gate is scoped to the
      on-diff findings only (a pre-existing off-diff HIGH that would flip
      `fail_on: high` to FAIL never reaches the gate).
    - `--pr` resume: `resolve_review_root(pr=...)` is idempotent over the
      deterministic worktree (diff_map._worktree_dir, P6.1) and
      `validate_execute` releases it -- function-level, mocking
      diff_map.acquire_pr/release_worktree since a live `gh` PR isn't
      available in tests.
    - requires-setup: `-c` on a repo with no committed groups.yml fails
      loudly, same as P6.2's group-scope case.
    """

    RUN_ID = "RID"

    def _repo_with_changed_file(self):
        """A committed two-group matrix repo (Auth untouched; Checkout's
        cart.py untouched too) plus one UNCOMMITTED edit to Checkout/pay.py --
        the `-c` delta's changed file. Returns (repo_dir, base_sha): base_sha
        anchors `--scope-changed --base`; HEAD stays pinned there (the edit is
        uncommitted, like a live `-c` invocation), so diff-hunks.json's
        includes_uncommitted comes back True.

        pay.py is padded to 60 lines: the edit lands at line 2 (an on-diff
        finding is placed there), and a pre-existing finding is placed at
        line 58 -- well outside the default +/-5 diff-context tolerance
        window around the line-2 hunk, so it classifies off-diff.
        """
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        for p in ("src/auth/login.py", "src/checkout/cart.py"):
            full = os.path.join(d, *p.split("/"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as fh:
                fh.write("def f():\n    return 1\n")
        pay_lines = ["def charge(amount):", "    return amount", "",
                     "def refund(amount):", "    return -amount"]
        pay_lines += ["# pad line %d" % i for i in range(6, 61)]
        pay_path = os.path.join(d, "src", "checkout", "pay.py")
        os.makedirs(os.path.dirname(pay_path), exist_ok=True)
        with open(pay_path, "w") as fh:
            fh.write("\n".join(pay_lines) + "\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        with open(runio._pano(d, "groups.yml"), "w") as fh:
            # #5.0-11: GLOBAL_FLOOR folds ARC/COD/DAT/TST into every group's
            # effective panel set. Deliberately NOT excluded here (unlike the
            # other two matrix e2e fixtures): audit_floor_cells checks the
            # DISCLOSED floor (declared | GLOBAL_FLOOR), not the exclude-netted
            # effective set, so excluding a global-floor domain leaves it
            # "on the floor" with no findings file -> missing_floor -> the
            # gate downgrades PASS to INCONCLUSIVE, which would defeat this
            # test's on-diff-vs-all gate-scope comparison (its whole point).
            # Instead Checkout's review cell fires all 5 floor domains and
            # _self_write_review_two_findings below services all of them
            # (SEC real, the other 4 empty) so every floor cell is present.
            fh.write(
                "groups:\n"
                "  Auth:\n    match: ['src/auth/**']\n    panels: [SEC]\n"
                "  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n")
        subprocess.run(["git", "init", "-q"], cwd=d, check=True)
        subprocess.run(["git", "add", "-A"], cwd=d, check=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-qm", "x"], cwd=d, check=True)
        base_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=d,
                                  capture_output=True, text=True,
                                  check=True).stdout.strip()
        # Uncommitted edit -- the -c delta's live-tree change.
        pay_lines[1] = "    return amount * 2  # bumped"
        with open(pay_path, "w") as fh:
            fh.write("\n".join(pay_lines) + "\n")
        return d, base_sha

    def _manifest(self, base):
        return {"run_id": self.RUN_ID, "host": "claude", "security_mode": "standard",
                "flags": {"fail_on": "high"},
                "scope": {"mode": "changed", "target": None}, "base": base}

    def _self_write_scout(self, entry):
        runio._write_json(entry["out_file"], {"group": "Checkout", "domains": ["SEC"]})

    def _self_write_review_two_findings(self, entries):
        """SEC gets one on-diff LOW (pay.py's edited line 2) and one
        pre-existing HIGH (line 58, far outside the diff-context window).
        Combined cell score (0 + 5*0.8 = 4.0) stays under F_b (8.0), so no
        backup round is summoned. #5.0-11: GLOBAL_FLOOR also fires
        ARC/COD/DAT/TST for this group -- service those with empty cells (no
        findings) so every floor cell is present (audit_floor_cells) without
        adding score-engaging noise (they never reach F_p, so verify only
        ever dispatches for SEC)."""
        for e in entries:
            domain = e["id"].rsplit("-", 1)[-1]
            if domain == "SEC":
                findings = [
                    {"title": "on-diff nit", "severity": "LOW", "domain": "SEC",
                     "code": "SEC-A1A", "category": "authz",
                     "location": {"file": "src/checkout/pay.py", "line_start": 2}},
                    {"title": "pre-existing gap", "severity": "HIGH", "domain": "SEC",
                     "code": "SEC-A2A", "category": "authz",
                     "location": {"file": "src/checkout/pay.py", "line_start": 58}},
                ]
            else:
                findings = []
            runio._write_json(e["out_file"], {
                "findings": findings,
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": domain, "group": "Checkout"}})

    def _self_write_verify_all(self, d, manifest, entry):
        cell = review._load_cell_findings(d, manifest, "Checkout", "SEC")
        runio._write_json(entry["out_file"], {
            "verdicts": [{"finding_id": f["id"], "verdict": "CONFIRMED",
                          "reasoning": "verified"} for f in cell],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_advisor",
                            "domain": "SEC", "group": "Checkout", "stage": "primary"}})

    def test_changed_scope_restricts_matrix_emits_diff_hunks_and_report_has_delta(self):
        d, base_sha = self._repo_with_changed_file()
        manifest = self._manifest(base_sha)

        # discovery: the real discovery.py --repo-scan --scope-changed
        # --base subprocess -- restricts groups.json to the one changed file.
        result = discovery.discovery_execute(d, manifest)
        self.assertEqual(result.kind, "advanced")
        groups_json = runio._load_json(runio._pano(d, "groups.json"))
        names = {g["name"] for g in groups_json["groups"]}
        files = sorted(f for g in groups_json["groups"] for f in g["files"])
        self.assertEqual(names, {"Checkout"})            # Auth excluded entirely
        self.assertEqual(files, ["src/checkout/pay.py"])  # cart.py unchanged, excluded

        # discovery.py's on-diff hunk map, alongside groups.json.
        hunks_path = runio._pano(d, "diff-hunks.json")
        self.assertTrue(os.path.isfile(hunks_path))
        hunks = runio._load_json(hunks_path)
        self.assertEqual(hunks["base"], base_sha)
        self.assertEqual(hunks["base_commit"], base_sha)
        self.assertTrue(hunks["includes_uncommitted"])
        self.assertIn("src/checkout/pay.py", hunks["hunks"])

        # coverage: scout checkpoint then floor+scout (SEC as committed, plus
        # #5.0-11's GLOBAL_FLOOR ARC/COD/DAT/TST on every group)
        cov = coverage.coverage_execute(d, manifest)
        self.assertEqual(cov.checkpoint, "scout")
        self.assertIsNone(cov.group)                 # #1056: scouts batched, group=None
        req = requests.load_dispatch_request(d)
        for e in req["entries"]:
            self._self_write_scout(e)
        self.assertEqual(coverage.coverage_execute(d, manifest).kind, "advanced")
        self.assertTrue(coverage.coverage_done(d, manifest))

        # review checkpoint -- 2 cells (Checkout/SEC committed + universal COD).
        # #5.0-19: pay.py is a single, surfaceless file, so the global floor's
        # ARC/DAT/TST are surface-gated off; self-write both findings into SEC
        # (scoped to pay.py) and an empty cell into COD.
        r = review.review_execute(d, manifest)
        self.assertEqual(r.checkpoint, "review")
        req = requests.load_dispatch_request(d)
        self.assertEqual(len(req["entries"]), 2)
        self._self_write_review_two_findings(req["entries"])
        self.assertTrue(review.review_done(d, manifest))

        # verify checkpoint -- primary only (combined score < F_b, no backup)
        v = verify.verify_execute(d, manifest)
        self.assertEqual(v.checkpoint, "verify")
        req = requests.load_dispatch_request(d)
        self.assertEqual(len(req["entries"]), 1)
        self._self_write_verify_all(d, manifest, req["entries"][0])
        self.assertEqual(verify.verify_execute(d, manifest).kind, "advanced")
        self.assertTrue(verify.verify_done(d, manifest))

        # synthesize -> a graded report with a populated delta block.
        self.assertEqual(synthesize.synthesize_execute(d, manifest).kind, "advanced")
        report = runio._load_json(runio._pano(d, "report.json"))

        delta_meta = report["meta"]["coverage"]["delta"]
        self.assertIsNotNone(delta_meta)
        self.assertEqual(delta_meta["base"], base_sha)
        self.assertTrue(delta_meta["includes_uncommitted"])
        self.assertEqual(delta_meta["files_changed"], 1)
        self.assertEqual(delta_meta["on_diff_total"], 1)
        self.assertEqual(delta_meta["pre_existing_total"], 1)

        delta_summary = report["summary"]["delta"]
        self.assertIsNotNone(delta_summary)
        self.assertEqual(delta_summary["on_diff"]["low"], 1)
        self.assertEqual(delta_summary["pre_existing"]["high"], 1)

        on_diff_f = next(f for f in report["findings"] if f["severity"] == "LOW")
        pre_existing_f = next(f for f in report["findings"] if f["severity"] == "HIGH")
        self.assertTrue(on_diff_f["delta"]["on_diff"])
        self.assertFalse(pre_existing_f["delta"]["on_diff"])
        self.assertEqual(on_diff_f["evidence"]["status"], "advisor_confirmed")
        self.assertEqual(pre_existing_f["evidence"]["status"], "advisor_confirmed")

        # gate scoped on-diff (the default --gate-scope): fail_on=high WOULD
        # FAIL on the pre-existing HIGH if it leaked into the gate -- it
        # doesn't, only the on-diff LOW is gate-eligible, so the gate stays
        # clean of it.
        self.assertEqual(report["summary"]["gate"], "PASS")

        # Item 7 (load-bearing proof): flip --gate-scope to "all" on the SAME
        # artifacts and the pre-existing off-diff HIGH now reaches the gate ->
        # FAIL. This proves the default on-diff scoping is what produced the PASS
        # (not a vacuous pass), i.e. gate scope actually changes the outcome.
        manifest["flags"]["gate_scope"] = "all"
        self.assertEqual(synthesize.synthesize_execute(d, manifest).kind, "advanced")
        report_all = runio._load_json(runio._pano(d, "report.json"))
        self.assertEqual(report_all["summary"]["gate"], "FAIL")

    def test_changed_scope_without_committed_groups_yml_raises_loud_setup_error(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, ".panopticon"))   # no groups.yml -- un-setup repo
        manifest = self._manifest(base="deadbeef")
        with self.assertRaises(runio.DriverError) as cm:
            discovery.discovery_execute(d, manifest)
        self.assertIn("panopticon setup", str(cm.exception))

    def test_pr_resolve_review_root_worktree_is_idempotent(self):
        """resolve_review_root(pr=...) acquires the deterministic per-(repo,
        PR) worktree (diff_map._worktree_dir, P6.1); a second acquire for the
        SAME (repo, PR) resumes the SAME path without a second underlying
        create. `diff_map.acquire_pr` is mocked (no live `gh`) with a fake
        that mirrors the REAL function's own idempotency contract: reuse an
        already-materialized deterministic worktree rather than recreating
        it, using the real (un-mocked) `_worktree_dir` to compute the path."""
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        subprocess.run(["git", "init", "-q"], cwd=d, check=True)
        wt = diff_map._worktree_dir(d, 7)
        self.addCleanup(lambda: shutil.rmtree(wt, ignore_errors=True))
        created = {"count": 0}

        def fake_acquire_pr(pr_number, repo=".", runner=subprocess.run):
            path = diff_map._worktree_dir(repo, pr_number)
            if not os.path.isdir(path):
                created["count"] += 1
                os.makedirs(path)
            return {"worktree": path, "base": "main", "head_sha": "deadbeef"}

        with mock.patch.object(diff_map, "acquire_pr",
                               side_effect=fake_acquire_pr) as m:
            root1, worktree1, base1 = runio.resolve_review_root(d, pr=7)
            root2, worktree2, base2 = runio.resolve_review_root(d, pr=7)

        self.assertEqual(m.call_count, 2)
        self.assertEqual(m.call_args_list[0].args[0], 7)
        self.assertEqual(m.call_args_list[0].kwargs["repo"], d)
        self.assertEqual(root1, wt)
        self.assertEqual(worktree1, wt)
        self.assertEqual(base1, "main")
        self.assertEqual(root2, wt)
        self.assertEqual(worktree2, wt)
        self.assertEqual(base2, "main")
        self.assertEqual(created["count"], 1)   # 2nd acquire reused, no re-create

    def test_validate_does_not_release_pr_worktree(self):
        """Ruling A: validate_execute does NOT release manifest["worktree"] --
        the PR worktree IS the review root, so releasing here would delete
        report.json + the manifest mid-machine. It still writes validate.json and
        advances on a clean tree; release-on-complete is covered at the run()
        level (test_run_finalizes_worktree_only_on_complete)."""
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        subprocess.run(["git", "init", "-q"], cwd=d, check=True)
        validate_phase.capture_tree_baseline(d)   # real git status --porcelain, clean
        wt = diff_map._worktree_dir(d, 7)
        manifest = {"run_id": self.RUN_ID, "worktree": wt}

        with mock.patch.object(diff_map, "release_worktree") as rel:
            result = validate_phase.validate_execute(d, manifest)

        self.assertEqual(result.kind, "advanced")
        rel.assert_not_called()
        validate = runio._load_json(runio._pano(d, "validate.json"))
        self.assertTrue(validate["tree_clean"])
        self.assertEqual(validate["unexpected_changes"], [])

class TestDriverEntrypoint(unittest.TestCase):
    """#5.0-01: the documented `python3 skill/scripts/driver.py run ...` must
    start without ModuleNotFoundError. This runs the driver as a FRESH process
    with PYTHONPATH stripped, because conftest sets PYTHONPATH in-process and
    would otherwise mask the missing sys.path bootstrap (the actual bug)."""

    def _repo_root(self):
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_documented_invocation_starts_without_import_crash(self):
        root = self._repo_root()
        driver_py = os.path.join(root, "skill", "scripts", "driver.py")
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        r = subprocess.run([sys.executable, driver_py, "run", "--help"],
                           capture_output=True, text=True, env=env, cwd=root)
        self.assertNotIn("ModuleNotFoundError", r.stderr,
                         "driver crashed at import as a fresh process:\n%s" % r.stderr)
        self.assertEqual(r.returncode, 0,
                         "`driver.py run --help` exited %d:\n%s"
                         % (r.returncode, r.stderr))

class TestResetGlobs(unittest.TestCase):
    def test_reset_clears_stale_delta_artifacts(self):
        # #5.0-07: --reset must clear stale delta artifacts so they can't
        # silently re-scope (diff-hunks) or content-check (out-file-hashes) a run.
        self.assertIn("diff-hunks.json", driver._RESET_GLOBS)
        self.assertIn("out-file-hashes.json", driver._RESET_GLOBS)

    def test_reset_clears_driver_dispatch_plan(self):
        # #5.0-16: --reset must clear the driver's own dispatch plan so a
        # --reset run re-declares its cells from fresh coverage.
        self.assertIn("dispatch-plan-driver.json", driver._RESET_GLOBS)

class TestDriverPlanIssues(unittest.TestCase):
    """#5.0-16 H2 unit: plan_contract.driver_plan_issues validates the driver's
    matrix domain-cell plan, distinct from the 4.x panel-review plan_issues."""

    def test_valid_domain_cell_plan_has_no_issues(self):
        plan = [{"group": "app", "domain": "SEC",
                 "out_file": "/x/.panopticon/findings-app-SEC.json"}]
        self.assertEqual(plan_contract.driver_plan_issues(plan), [])

    def test_empty_or_non_list_plan_is_invalid(self):
        self.assertTrue(plan_contract.driver_plan_issues([]))
        self.assertTrue(plan_contract.driver_plan_issues({}))

    def test_panel_shaped_entry_is_invalid(self):
        # A 4.x panel-review entry (no `domain`) must NOT validate as a driver
        # plan -- the two contracts are disjoint.
        plan = [{"role": "panel_review", "group": "app", "panel": "security",
                 "out_file": "/x/findings-app-security-panel_review.json"}]
        issues = plan_contract.driver_plan_issues(plan)
        self.assertTrue(any("unsupported domain" in i for i in issues))

    def test_missing_group_and_out_file_flagged(self):
        issues = plan_contract.driver_plan_issues([{"domain": "SEC"}])
        self.assertTrue(any("group" in i for i in issues))
        self.assertTrue(any("out_file" in i for i in issues))

    def test_out_file_basename_must_match_group_domain(self):
        plan = [{"group": "app", "domain": "SEC",
                 "out_file": "/x/findings-other-SEC.json"}]
        issues = plan_contract.driver_plan_issues(plan)
        self.assertTrue(any("basename" in i for i in issues))

class TestDriverIntegrityWiring(unittest.TestCase):
    """#5.0-16: the driver emits dispatch-plan-driver.json (H2, reconcile) and
    out-file-hashes.json (H3, content snapshot) so both anti-tampering controls
    -- dead on the driver path when neither artifact was written -- actually
    run. Drives review->verify->synthesize via self-writes (like
    TestDriverRunLoopEndToEnd) and asserts on the graded report's
    meta.integrity."""

    RUN_ID = "RID"

    def _repo(self, effective):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("def f():\n    return 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        # #1511 BR-06: PERSIST the manifest before writing any run artifact.
        # These tests used an in-memory manifest dict that was never written, so
        # `_run_tag` found nothing and every `_pano` call resolved the flat
        # top-level layout -- the class asserted the two anti-tamper controls
        # worked on a code path production never takes, and the per-run wiring
        # bug (#1511) sailed through a suite that appeared to cover it.
        self._m = run_manifest.build_manifest(
            target=d, review_root=d, host="claude", security_mode="standard",
            run_id=self.RUN_ID, flags={"fail_on": "high"})
        run_manifest.write_manifest(d, self._m)
        self._run_dir = os.path.join(d, ".panopticon", "runs",
                                     run_manifest.run_tag(self._m))
        runio._write_json(runio._pano(d, "groups.json"),
                           {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        with open(runio._pano(d, "groups.yml"), "w") as fh:
            fh.write("groups:\n  app:\n    match: ['src/**']\n")   # #1092 healthy resume
        runio._write_json(runio._pano(d, "coverage-app.json"),
                           {"group": "app", "floor": effective,
                            "effective": effective, "run_id": self.RUN_ID})
        # Run artifacts must land INSIDE the run folder, not beside it.
        self.assertTrue(os.path.isfile(os.path.join(self._run_dir, "groups.json")),
                        "fixture wrote run artifacts to the flat layout")
        # A stale top-level snapshot from an earlier run: if any of this class's
        # assertions can be satisfied by reading it, the wiring is wrong.
        runio._write_json(
            os.path.join(d, ".panopticon", "out-file-hashes.json"),
            {os.path.join(self._run_dir, "findings-app-QAL.json"): "0" * 64})
        return d

    def _manifest(self):
        return self._m

    def _cell_payload(self, domain, title="nit"):
        # QAL LOW scores below F_p, so verify engages nothing -- the only reason
        # a gate could go INCONCLUSIVE is the integrity signal under test.
        return {"findings": [{"title": title, "severity": "LOW", "domain": domain,
                              "code": domain + "-A1A", "category": "style",
                              "location": {"file": "src/app.py", "line_start": 1}}],
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": domain, "group": "app"}}

    def _drive_review(self, d, m, domain="QAL"):
        r = review.review_execute(d, m)
        self.assertEqual(r.checkpoint, "review")
        for e in requests.load_dispatch_request(d)["entries"]:
            runio._write_json(e["out_file"], self._cell_payload(domain))
        self.assertTrue(review.review_done(d, m))

    def test_clean_run_integrity_not_inconclusive(self):
        d = self._repo(["QAL"])
        m = self._manifest()
        self._drive_review(d, m)
        # verify engages nothing -> advances, but snapshots at its top first
        self.assertEqual(verify.verify_execute(d, m).kind, "advanced")
        self.assertTrue(verify.verify_done(d, m))
        self.assertTrue(os.path.isfile(runio._pano(d, "dispatch-plan-driver.json")))
        self.assertTrue(os.path.isfile(runio._pano(d, "out-file-hashes.json")))
        self.assertEqual(synthesize.synthesize_execute(d, m).kind, "advanced")
        report = runio._load_json(runio._pano(d, "report.json"))
        integ = report["meta"]["integrity"]
        self.assertGreaterEqual(integ["plans_seen"], 1)
        self.assertEqual(integ["unexpected_findings_files"], [])
        self.assertEqual(integ["missing_planned_files"], [])
        self.assertEqual(integ["invalid_dispatch_plans"], [])
        self.assertEqual(integ["content_mismatched_files"], [])
        self.assertEqual(integ["empty_dispatch_plans"], 0)
        self.assertGreaterEqual(integ["content_hashes_checked"], 1)
        self.assertNotEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_h2_injected_undeclared_findings_file_forces_inconclusive(self):
        d = self._repo(["QAL"])
        m = self._manifest()
        self._drive_review(d, m)
        verify.verify_execute(d, m)   # snapshot taken over the DECLARED cells
        # a rogue reviewer writes a cell the plan never declared
        runio._write_json(runio._pano(d, "findings-app-BOGUS.json"),
                           {"findings": [], "_panopticon": {
                               "run_id": self.RUN_ID, "role": "domain_panel",
                               "domain": "BOGUS", "group": "app"}})
        synthesize.synthesize_execute(d, m)
        report = runio._load_json(runio._pano(d, "report.json"))
        integ = report["meta"]["integrity"]
        self.assertTrue(any("findings-app-BOGUS.json" in p
                            for p in integ["unexpected_findings_files"]),
                        integ["unexpected_findings_files"])
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_h3_content_substitution_after_snapshot_forces_inconclusive(self):
        d = self._repo(["QAL"])
        m = self._manifest()
        self._drive_review(d, m)
        verify.verify_execute(d, m)   # snapshot the ORIGINAL bytes now
        self.assertTrue(os.path.isfile(runio._pano(d, "out-file-hashes.json")))
        # substitute the DECLARED cell's bytes after the snapshot
        cell = runio._pano(d, "findings-app-QAL.json")
        runio._write_json(cell, self._cell_payload("QAL", title="INJECTED"))
        synthesize.synthesize_execute(d, m)
        report = runio._load_json(runio._pano(d, "report.json"))
        integ = report["meta"]["integrity"]
        # still a DECLARED file -> not unexpected; only the content check fires
        self.assertEqual(integ["unexpected_findings_files"], [])
        self.assertTrue(any("findings-app-QAL.json" in p
                            for p in integ["content_mismatched_files"]),
                        integ["content_mismatched_files"])
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_resume_is_idempotent_snapshot_one_way_plan_stable(self):
        d = self._repo(["QAL"])
        m = self._manifest()
        self._drive_review(d, m)
        plan_path = runio._pano(d, "dispatch-plan-driver.json")
        plan1 = runio._load_json(plan_path)
        review.review_execute(d, m)   # second pass: plan write is a no-op
        self.assertEqual(runio._load_json(plan_path), plan1)
        verify.verify_execute(d, m)   # first snapshot
        hashes_path = runio._pano(d, "out-file-hashes.json")
        snap1 = runio._load_json(hashes_path)
        # substitute a declared cell, then a SECOND verify_execute must NOT
        # re-hash -- re-hashing would silently mask the substitution
        with open(runio._pano(d, "findings-app-QAL.json"), "a") as fh:
            fh.write("\n")
        verify.verify_execute(d, m)
        self.assertEqual(runio._load_json(hashes_path), snap1)

class TestDriverHardening(unittest.TestCase):
    """#1033: small driver robustness residuals from the P3 tail."""

    def _pano_dir(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(runio._pano(d))
        return d

    def test_phase_result_rejects_unknown_kind(self):   # #5
        for kind in ("advanced", "checkpoint"):
            self.assertEqual(engine.PhaseResult(kind=kind).kind, kind)
        for bad in ("advance", "complete", "error", ""):
            with self.assertRaises(ValueError):
                engine.PhaseResult(kind=bad)

    def test_next_verb_is_removed(self):   # #10
        with self.assertRaises(SystemExit):
            driver.build_parser().parse_args(["next", "."])
        self.assertEqual(driver.build_parser().parse_args(["run", "."]).verb, "run")

    def test_committed_groups_parsed_once_per_version(self):   # #7
        d = self._pano_dir()
        with open(runio._pano(d, "groups.yml"), "w", encoding="utf-8") as fh:
            fh.write("groups:\n  Auth:\n    match: ['src/auth/**']\n")
        runio._parse_committed_groups.cache_clear()
        self.addCleanup(runio._parse_committed_groups.cache_clear)
        calls = []
        real = groups_schema.parse_groups
        with mock.patch("scripts.groups_schema.parse_groups",
                        side_effect=lambda doc: calls.append(1) or real(doc)):
            runio.load_committed_groups(d)
            runio.load_committed_groups(d)      # same file -> cache hit
        self.assertEqual(len(calls), 1)

    def test_phase_driver_error_is_status_error(self):   # #9 (run level)
        d = self._pano_dir()

        def boom_exec(r, m):
            raise runio.DriverError("kaboom")
        boom = engine.Phase(name="discovery", kind="deterministic",
                            done=lambda r, m: False, execute=boom_exec)
        args = driver.build_parser().parse_args(["run", d])
        status = driver.run(args, phases=(boom,))
        self.assertEqual(status["status"], "error")
        self.assertIn("kaboom", status["message"])

    def test_main_driver_error_prints_status_and_exits_1(self):   # #9 (CLI level)
        # no committed groups.yml -> discovery raises DriverError -> main() prints
        # ONE status:error JSON line (no traceback) and returns exit code 1.
        d = self._pano_dir()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = driver.main(["run", d])
        self.assertEqual(rc, 1)
        status = json.loads(buf.getvalue().strip().splitlines()[-1])
        self.assertEqual(status["status"], "error")

    def test_spawn_oserror_becomes_driver_error(self):   # #6
        d = self._pano_dir()
        with open(runio._pano(d, "groups.yml"), "w", encoding="utf-8") as fh:
            fh.write("groups:\n  Auth:\n    match: ['**/*.py']\n")
        with mock.patch("subprocess.run",
                        side_effect=OSError("ENOENT: no python")):
            with self.assertRaises(runio.DriverError) as ctx:
                discovery.discovery_execute(d, {"security_mode": "standard",
                                             "scope": {"mode": "repo"}})
        self.assertIn("could not spawn", str(ctx.exception))

    def test_load_ocrdb_bundle_wraps_valueerror(self):   # #1034/#1
        # a malformed OCRDb bundle on the driver path becomes a DriverError
        # (clean status:error), not a raw traceback crashing the phase.
        with mock.patch("scripts.ocrdb.load_bundle",
                        side_effect=ValueError("bundle malformed")):
            with self.assertRaises(runio.DriverError):
                runio._load_ocrdb_bundle()

    def test_render_criteria_gates_and_falls_back(self):   # #1035
        b = {"domains": {"SEC": {"entries": {
            "SEC-A1A": {"name": "cmd-inj", "criteria": "qualifies when unsanitized"},
            "SEC-A1B": {"name": "nocrit"}}}}}
        out = review._render_criteria(b, "SEC")
        self.assertIn("SEC-A1A", out)
        self.assertIn("qualifies when unsanitized", out)
        self.assertNotIn("SEC-A1B", out)              # no criteria -> omitted
        none = review._render_criteria(
            {"domains": {"SEC": {"entries": {"SEC-A1B": {"name": "nocrit"}}}}}, "SEC")
        self.assertIn("no explicit OCRDb criteria", none)   # never blank

    def test_verify_entry_carries_the_criteria_lens(self):   # #1035
        b = {"domains": {"SEC": {"entries": {
            "SEC-A1A": {"name": "cmd-inj", "default_severity": "HIGH",
                        "criteria": "CRITSENTINEL when the sink is reached"}}}}}
        cell = [{"id": "SEC-1", "title": "t", "severity": "HIGH", "domain": "SEC",
                 "category": "x", "location": {"file": "a.py", "line_start": 1}}]
        entry = verify._verify_entry("/repo", {"run_id": "R", "host": "claude"},
                                     "app", "SEC", ["a.py"], cell, "claude", b,
                                     "primary")
        self.assertIn("CRITSENTINEL", entry["prompt"])


if __name__ == "__main__":
    unittest.main()

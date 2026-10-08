"""Driver entrypoint, plan issue, and recoverability tests."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import scripts.phases.runio as runio
import scripts.phases.engine as engine
import scripts.phases.coverage as coverage
import scripts.phases.synthesize as synthesize_phase
import scripts.phases.tools as tools_phase
import scripts.phases.validate as validate_phase

import scripts.driver as driver
import scripts.plan_contract as plan_contract
import scripts.run_manifest as run_manifest

from tests.tools.git_repo import make_git_repo


from tests.driver_helpers import start_module_patches

def setUpModule():
    global _run_probes_patch, _readiness_docker_patch
    _run_probes_patch, _readiness_docker_patch = start_module_patches()


def tearDownModule():
    _run_probes_patch.stop()
    _readiness_docker_patch.stop()


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
                           capture_output=True, text=True, timeout=30,
                           env=env, cwd=root)
        self.assertNotIn("ModuleNotFoundError", r.stderr,
                         "driver crashed at import as a fresh process:\n%s" % r.stderr)
        self.assertEqual(r.returncode, 0,
                         "`driver.py run --help` exited %d:\n%s"
                         % (r.returncode, r.stderr))

    def test_migrate_config_verb_writes_the_root_file(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            open(os.path.join(d, ".panopticon", "groups.yml"), "w").write(
                "groups:\n  A:\n    match: ['a/**']\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = driver.main(["migrate-config", d])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(os.path.join(d, "panopticon.yml")))
            self.assertIn("delete", out.getvalue())

    def test_migrate_config_verb_refuses_loud(self):
        with tempfile.TemporaryDirectory() as d:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = driver.main(["migrate-config", d])
            self.assertEqual(rc, 1)
            self.assertIn("no `.panopticon/groups.yml`", err.getvalue())


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

    def test_reset_removes_stale_run_files_and_preserves_durable_artifact(self):
        # The suite's external TMPDIR supplies a newly allocated review root
        # on each platform; this calls the real deletion boundary.
        with tempfile.TemporaryDirectory() as root:
            artifacts = os.path.join(root, ".panopticon")
            os.mkdir(artifacts)
            stale = ("diff-hunks.json", "out-file-hashes.json",
                     "dispatch-plan-driver.json")
            for name in stale:
                with open(os.path.join(artifacts, name), "w", encoding="utf-8") as fh:
                    fh.write("stale")
            durable = os.path.join(artifacts, "report-run-1.json")
            with open(durable, "w", encoding="utf-8") as fh:
                fh.write("keep")
            driver._clear_run_artifacts(root)
            for name in stale:
                self.assertFalse(os.path.exists(os.path.join(artifacts, name)), name)
            with open(durable, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "keep")


class TestX0XFailureStatus(unittest.TestCase):
    def test_terminal_status_retains_the_synthesize_disclosure(self):
        root = make_git_repo(
            test_case=self,
            files={"src/app.py": "x = 1\n"},
            branch="main", user_email="t@t", user_name="t",
        )
        args = driver.build_parser().parse_args(["run", root, "--no-tools"])
        failure_path = os.path.join(root, ".panopticon", "report-x0x-failures.json")
        disclosure = {
            "count": 2,
            "path": failure_path,
            "message": ("X0X discarded 2 locus-free catalog-gap finding(s); "
                        "failure log: %s" % failure_path),
        }
        with mock.patch.object(synthesize_phase, "x0x_failure_disclosure",
                               return_value=disclosure):
            status = driver.run(args, phases=())

        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(status["x0x_discarded"], 2)
        self.assertEqual(status["x0x_failure_log"], failure_path)
        self.assertIn(disclosure["message"], status["message"])


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


class TestAnEnvironmentMovingMidRunIsRecoverable(unittest.TestCase):
    """#1637 P08 fix round 1 (F1b/F2/F3). Readiness fails closed BEFORE the
    first paid dispatch, so the only way to reach the tools phase with a
    scanner that produces nothing is for the environment to move after the
    scouts have been paid for. Everything about that path has to leave the run
    recoverable -- which, on the first cut, none of it did."""

    def _repo(self):
        return make_git_repo(
            test_case=self,
            files={"src/app.py": "def f():\n    return 1\n"},
            groups_yml="groups:\n  Core:\n    match: ['src/**']\n    panels: [COD]\n",
            branch="main", user_email="t@t", user_name="t")

    def _args(self, target, *extra):
        return driver.build_parser().parse_args(["run", target, *extra])

    def _inject_scouts(self, root):
        for g, _ in coverage._discovered_groups(root):
            p = runio._pano(root, "scout-%s.json" % g)
            if not os.path.exists(p):
                runio._write_json(p, {"group": g, "panels": ["code"]})

    def test_an_engine_that_cannot_advance_is_an_error_status_not_a_traceback(self):
        # F1b: run_engine's progress guard raises RuntimeError, which
        # driver.run did not catch -- the operator got a traceback and no
        # status JSON at all, which is the one thing the status protocol
        # exists to prevent.
        d = self._repo()
        stuck = engine.Phase(name="discovery", kind="deterministic",
                             done=lambda r, m: False,
                             execute=lambda r, m: engine.PhaseResult(
                                 kind="advanced", message="nope"))
        status = driver.run(self._args(d, "--no-tools"), phases=(stuck,))
        self.assertEqual(status["status"], "error")
        self.assertIn("without satisfying its done() predicate",
                      status["message"])

    def test_no_tools_rescues_an_in_flight_run_without_discarding_it(self):
        # F2: `--no-tools` was refused as flag drift on a run already in
        # flight, so the only exit from a mid-run image loss was `--reset` --
        # which discards every paid scout, the exact loss ruling 4 set out to
        # prevent.
        d = self._repo()
        first = driver.run(self._args(d))
        self.assertEqual(first["checkpoint"], "scout")
        scout_file = runio._pano(d, "scout-Core.json")
        self._inject_scouts(d)
        rescue = driver.run(self._args(d, "--no-tools"))
        self.assertNotEqual(rescue["status"], "error", rescue.get("message"))
        # The paid work survives, the manifest records the downgrade, and the
        # tools marker is rewritten as the operator's own choice.
        self.assertTrue(os.path.isfile(scout_file))
        manifest = run_manifest.load_manifest(d)
        self.assertIs(manifest["flags"]["tools"], False)
        change = manifest["flag_changes"][-1]
        self.assertEqual((change["flag"], change["to"]), ("tools", False))
        self.assertIsInstance(change["at"], str)
        marker = runio._load_json(runio._pano(d, "tools-ran.json"))
        self.assertEqual(marker["note"], tools_phase.NO_TOOLS_NOTE)

    def test_turning_tools_back_on_mid_run_is_still_drift(self):
        # The downgrade is one-way: panels already dispatched saw no scanner
        # evidence, and no later flag can change what they were shown.
        d = self._repo()
        driver.run(self._args(d, "--no-tools"))
        status = driver.run(self._args(d, "--tools"))
        self.assertEqual(status["status"], "error")
        self.assertIn("drift", status["message"])

    def _complete_a_run(self, d):
        """Drive a --no-tools run to `complete`, servicing every checkpoint."""
        args = self._args(d, "--no-tools")
        status = driver.run(args)
        for _ in range(30):
            if status["status"] == "checkpoint":
                self._inject_scouts(d)
                req = runio._load_json(runio._pano(d, "dispatch-request.json"))
                if isinstance(req, dict) and req.get("checkpoint") == "review":
                    run_id = run_manifest.load_manifest(d)["run_id"]
                    for e in req["entries"]:
                        stem = os.path.basename(
                            e["out_file"])[len("findings-"):-len(".json")]
                        group, domain = stem.rsplit("-", 1)
                        runio._write_json(e["out_file"], {
                            "findings": [],
                            "_panopticon": {"run_id": run_id,
                                            "role": "domain_panel",
                                            "domain": domain, "group": group}})
            status = driver.run(args)
            if status["status"] == "complete":
                break
        self.assertEqual(status["status"], "complete", status)
        return status

    def test_a_completed_run_stays_complete_whatever_the_tools_marker_says(self):
        # F3: the already-complete guard asked every phase predicate, so an
        # environmental skip (never "done") let a finished run re-enter, re-run
        # the scan, and hand back the OLD report as though it were fresh --
        # which that guard's own comment calls the worst failure mode for a
        # review tool.
        d = self._repo()
        args = self._args(d, "--no-tools")
        self._complete_a_run(d)
        # Now make the marker read like an environmental skip from an earlier
        # invocation -- exactly what a docker-absent scan leaves behind.
        runio._write_json(runio._pano(d, "tools-ran.json"),
                          {"schema_version": 1, "ran": False, "skipped": True,
                           "crashed": False, "note": "no tool output produced",
                           "returncode": 0,
                           "run_id": run_manifest.load_manifest(d)["run_id"],
                           "attempt_invocation": "an-earlier-invocation"})
        redo = driver.run(args)
        self.assertEqual(redo["status"], "error", redo)
        self.assertIn("already complete", redo["message"])
        self.assertIn("--reset", redo["message"])

    def test_no_tools_aimed_at_a_finished_run_leaves_its_record_alone(self):
        # N1: the downgrade was recorded BEFORE the already-complete guard
        # refused, so `--no-tools` at a finished run rewrote its manifest --
        # `flags.tools` flipped and a `flag_changes` entry appeared -- for a
        # run that has nothing left to rescue. Harmless until the terminal
        # artifacts are lost and the run resumes, at which point the
        # regenerated report says `disabled_mid_run: true` beside panels that
        # all saw scanner evidence: the run record and the report contradicting
        # each other, on the very surface this work added.
        d = self._repo()
        self._complete_a_run(d)
        # The run is driven with --no-tools so its tools phase spawns nothing;
        # rewrite the finished manifest to the tools-ENABLED shape a real
        # scanner run leaves behind, which is what makes the next --no-tools a
        # downgrade rather than a no-op.
        path = run_manifest.manifest_path(d)
        finished = run_manifest.load_manifest(d)
        finished["flags"]["tools"] = None
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(finished, fh, indent=2, sort_keys=True)
        before = open(path, "rb").read()
        status = driver.run(self._args(d, "--no-tools"))
        self.assertEqual(status["status"], "error", status)
        self.assertIn("already complete", status["message"])
        self.assertEqual(open(path, "rb").read(), before)


class TestRunConvertsAConfinementRefusal(unittest.TestCase):
    """Item 24 R1-1, the twin of `driver setup`'s: every artifact an engine
    phase writes goes through the whole-path confinement, which refuses a
    planted component with `ValueError` -- not `DriverError`. `run()` converted
    only `DriverError` and `EngineStalled`, so that refusal escaped as a
    traceback and the host asking for a status got no JSON at all.

    Refusing is the guard WORKING. It is an outcome of the verb, so it speaks
    the verb's status protocol.
    """

    def _repo(self):
        return make_git_repo(test_case=self, files={"src/checkout/pay.py": "x = 1\n"},
                             branch="main", user_email="t@t", user_name="t")

    def test_a_confinement_refusal_from_a_phase_is_an_error_status(self):
        d = self._repo()
        boom = ValueError("artifact path escapes .panopticon via a symlinked "
                          "component: '%s/.panopticon/report.json'" % d)
        args = driver.build_parser().parse_args(["run", d])
        with mock.patch("scripts.phases.engine.run_engine", side_effect=boom):
            status = driver.run(args)
        self.assertEqual(status["status"], "error", status)
        self.assertIn("escapes .panopticon", status["message"])

    # #1735 fix round 1: the same rule, for the three writes that happen BEFORE
    # `run_engine` and were therefore outside that `except`. Every one of them
    # can now refuse (the manifest rewrite could not, before this issue), and on
    # exactly the hostile tree the fix targets they would have died as a raw
    # traceback with no JSON behind them.

    def _plant(self, d, name):
        """A `.panopticon/<name>` symlink at a victim outside the artifact root."""
        pano = os.path.join(d, ".panopticon")
        os.makedirs(pano, exist_ok=True)
        victim = os.path.join(d, "victim.txt")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write("PRECIOUS")
        os.symlink(victim, os.path.join(pano, name))
        return victim

    def _assert_refusal(self, status, victim, fragment="escapes .panopticon"):
        self.assertEqual(status["status"], "error", status)
        self.assertIn(fragment, status["message"])
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")

    def test_a_planted_manifest_tmp_is_an_error_status_not_a_traceback(self):
        # The #1735 tree itself: `record_posture_disclosure` runs on the first
        # invocation of every run, and its staging path is a fixed name a target
        # can commit.
        d = self._repo()
        victim = self._plant(d, "run-manifest.json.tmp")
        args = driver.build_parser().parse_args(["run", d])
        status = driver.run(args)
        self._assert_refusal(status, victim)

    def test_a_refused_tools_downgrade_is_an_error_status(self):
        # Ruling 1's SECOND site, on a real in-flight run rather than a forced
        # branch: round 1's version planted the link and mocked the predicate on
        # a repo with no manifest, so `run()` took the first-invocation branch
        # and neither `is_tools_downgrade` nor `record_tools_downgrade` was ever
        # called -- the assertion was satisfied by the posture-disclosure
        # refusal three stanzas later, leaving this site unpinned.
        #
        # So: one invocation to establish the run (flags.tools unset), THEN the
        # plant, then `--no-tools` -- the allowed mid-run downgrade (#1637 P08
        # F2), whose rewrite stages through the planted name. No mock on the
        # path under test; `wraps` only so the call itself can be asserted.
        d = self._repo()
        with mock.patch("scripts.phases.engine.run_engine",
                        return_value={"status": "in_progress"}):
            first = driver.run(driver.build_parser().parse_args(["run", d]))
        self.assertNotEqual(first["status"], "error", first)
        victim = self._plant(d, "run-manifest.json.tmp")
        args = driver.build_parser().parse_args(["run", d, "--no-tools"])
        with mock.patch.object(run_manifest, "record_tools_downgrade",
                               wraps=run_manifest.record_tools_downgrade) as rec:
            status = driver.run(args)
        self.assertTrue(rec.called, "the downgrade branch was never taken")
        self._assert_refusal(status, victim)

    def test_a_planted_runs_directory_link_is_an_error_status(self):
        # `_ensure_run_symlinks` runs before the posture probe and refuses a
        # planted `runs` with DriverError -- the other exception type, on the
        # other side of the same missing `try`.
        d = self._repo()
        victim = self._plant(d, "runs")
        args = driver.build_parser().parse_args(["run", d])
        status = driver.run(args)
        self._assert_refusal(status, victim, "symlinked path")

    def test_a_refused_baseline_capture_is_an_error_status(self):
        # `capture_tree_baseline` writes a `.panopticon` artifact on the same
        # stretch, so it answers to the same rule.
        d = self._repo()
        victim = self._plant(d, "run-manifest.json.tmp.unused")
        boom = ValueError("artifact path escapes .panopticon via a symlinked "
                          "component: '%s/.panopticon/runs/t/tree-baseline.json'" % d)
        args = driver.build_parser().parse_args(["run", d])
        with mock.patch.object(validate_phase, "capture_tree_baseline",
                               side_effect=boom):
            status = driver.run(args)
        self._assert_refusal(status, victim)

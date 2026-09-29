"""Integration tests for scripts.driver: run(), the CLI, the PHASES table and the
end-to-end loops. Per-phase tests live in tests/phases/test_<module>.py, mirroring
skill/scripts/phases/ (WS-0 D5). This file carried a TECH DEBT note about being an
unsplittable monolith from 5.0 until then.
"""
import contextlib
import io
import json
import os
import unittest
from unittest import mock

import scripts.phases.runio as runio
import scripts.phases.coverage as coverage

from tests._test_helpers import all_proven_artifact as _all_proven_artifact
from tests._test_helpers import docker_probe_runner
import scripts.driver as driver
import scripts.host_disclosure as host_disclosure
import scripts.run_manifest as run_manifest
from scripts import hosts

from tests.tools.git_repo import make_git_repo


_ALL_PROVEN = {c: hosts.PROVEN for c in hosts.CAPABILITIES}

_run_probes_patch = None
_readiness_docker_patch = None


def setUpModule():
    # #1344 F3: driver.run() calls host_probes.run_probes() for REAL on every
    # invocation (spec 5.2), and the real probe reads THIS MACHINE's
    # ~/.claude/agents. This file exercises the phase ORCHESTRATION, not the
    # probes themselves (that is test_host_probes.py / test_host_evidence_
    # wiring.py's job) -- every class below runs the same unstated
    # `--host claude` default, so left unmocked, every enforced / write-guard
    # assertion in this file would pass or fail depending on whether the
    # developer's machine happens to have panopticon's shells registered,
    # exactly the machine-dependence test_host_evidence_wiring.py's
    # `_pinned_registration` exists to remove. Patched once at module scope
    # rather than per-class because the hazard is identical everywhere here.
    global _run_probes_patch
    _run_probes_patch = mock.patch(
        "scripts.host_probes.run_probes",
        side_effect=lambda host, target, **kw: _all_proven_artifact(host))
    _run_probes_patch.start()
    # #1637 P08: `readiness` now leads PHASES and fails closed on a missing
    # tools image, so every lifecycle test here would stop at the first phase
    # instead of reaching the one it is about. State the environment (daemon
    # up, image present) once, with a fake runner -- the suite must still
    # never touch a real docker. A test that means to exercise the REFUSAL
    # patches this attribute itself (tests/phases/test_readiness.py).
    global _readiness_docker_patch
    _readiness_docker_patch = mock.patch(
        "scripts.phases.readiness_checks.DOCKER_RUNNER", docker_probe_runner())
    _readiness_docker_patch.start()


def tearDownModule():
    _run_probes_patch.stop()
    _readiness_docker_patch.stop()

def test_all_proven_artifacts_do_not_share_capability_state():
    first = _all_proven_artifact("claude")
    second = _all_proven_artifact("kimi")
    first["capabilities"][hosts.TOOL_POLICY_ENFORCED]["state"] = hosts.REFUTED
    assert second["host"] == "kimi"
    assert second["capabilities"][hosts.TOOL_POLICY_ENFORCED]["state"] == "proven"


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

    def test_foreign_manifest_message_names_the_actual_signal(self):
        for tracked in (True, False):
            with self.subTest(tracked=tracked):
                root = self._repo()
                args = self._args(root)
                driver.run(args)
                path = run_manifest.manifest_path(root)
                manifest = run_manifest.load_manifest(root)
                manifest["review_root"] = root if tracked else "/different/tree"
                runio._write_json(path, manifest)
                error = io.StringIO()
                with mock.patch.object(runio, "_manifest_committed", return_value=tracked), \
                        contextlib.redirect_stderr(error):
                    driver.run(args)
                line = next(line for line in error.getvalue().splitlines()
                            if "ignoring foreign run-manifest.json" in line)
                self.assertIn("git-tracked" if tracked else "stamped review_root", line)
                self.assertNotIn("stamped review_root" if tracked else "git-tracked", line)

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

    def _settings(self, root, max_per_group):
        """Rewrite the fixture's root config with a `settings:` grain knob.

        `max_per_group` and not `max_verify`: #1681 Plan 2 made the verify cap
        a GATE key whose built-in default (uncapped) is stricter than any
        number, so a committed one is refused and never reaches a flag. The
        grain knob is the one a repository may still set -- both values below
        sit inside the 8-48 band, so nothing is clamped either.
        """
        with open(os.path.join(root, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write("version: 1\n"
                     "groups:\n  Core:\n    match: ['src/**']\n    panels: [COD]\n"
                     "settings:\n  max_per_group: %d\n" % max_per_group)

    def test_changing_a_settings_knob_between_resumes_is_flag_drift(self):
        # #1681 Plan 1: the grain knobs resolve CLI > `settings:` and the
        # manifest pins the EFFECTIVE value, so editing the committed config
        # between resumes drifts exactly like editing the flag would -- the
        # anti-drift keys would be a lie otherwise. (DELETING the knob is not
        # drift: an incoming None never conflicts, so the run resumes on the
        # value the manifest already pinned.)
        d = self._repo()
        self._settings(d, 12)
        driver.run(self._args(d))
        self.assertEqual(run_manifest.load_manifest(d)["flags"]["max_per_group"], 12)
        self._settings(d, 20)
        status = driver.run(self._args(d))
        self.assertEqual(status["status"], "error")
        self.assertIn("drift", status["message"])
        self.assertIn("max_per_group", status["message"])

    def test_a_committed_security_mode_is_honoured_and_recorded(self):
        # #1681 Plan 2: `security` is a GATE key and `redteam` is stricter than
        # the built-in `standard`, so a target may tighten its own review this
        # way. It is a top-level manifest field rather than a flag, so run() --
        # not _cli_flags -- resolves it, and the same resolution is what
        # build_manifest records. A bare resume on the unchanged config must
        # then match its own manifest instead of drifting against it.
        d = self._repo()
        with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write("version: 1\n"
                     "groups:\n  Core:\n    match: ['src/**']\n    panels: [COD]\n"
                     "settings:\n  security: redteam\n")
        first = driver.run(self._args(d))
        m = run_manifest.load_manifest(d)
        self.assertEqual(m["security_mode"], "redteam")
        self.assertEqual(m["config_requested"], {"security": "redteam"})
        self.assertEqual(m["config_effective"], {"security": "redteam"})
        resumed = driver.run(self._args(d))
        self.assertEqual((resumed["status"], resumed["checkpoint"]),
                         (first["status"], first["checkpoint"]))
        self.assertEqual(first["status"], "checkpoint")

    def test_a_huge_committed_integer_cannot_crash_the_run(self):
        # Final review F1: `settings: {max_verify: <400 digits>}` reached
        # `config_schema._rank`'s `float(value)` and raised OverflowError out
        # of `driver._resolve_config` -- the target crashed the driver before
        # a single reviewer was dispatched. `driver run` must answer with a
        # STATUS, and the number must land in the manifest as a refusal.
        d = self._repo()
        with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write("version: 1\n"
                     "groups:\n  Core:\n    match: ['src/**']\n    panels: [COD]\n"
                     "settings:\n  max_verify: %s\n" % ("9" * 400))
        status = driver.run(self._args(d, "--no-tools"))
        self.assertEqual(status["status"], "checkpoint", status.get("message"))
        m = run_manifest.load_manifest(d)
        self.assertEqual(m["config_effective"], {})
        self.assertEqual([r["key"] for r in m["config_refused"]], ["max_verify"])
        self.assertIn("out of range", m["config_refused"][0]["reason"])
        self.assertIsInstance(m["config_requested"]["max_verify"], str)

    def test_a_committed_default_gate_value_does_not_break_a_resume(self):
        # Final review F4: a gate value EQUAL to the built-in default was
        # written into `effective`, which made a no-op into an OPINION. A run
        # created with `--security redteam` whose target then committed
        # `security: standard` (and `tools: true`, already the default) was
        # refused on the next bare resume -- "flag drift ... use --reset" --
        # while the disclosure printed on that same invocation said nothing
        # changes. The run's own posture is unmoved.
        d = self._repo()
        # No --no-tools: `tools: true` has to reach the ratchet to be the
        # second equal-to-default value under test (conftest refuses the
        # docker daemon, and the run stops at the scout checkpoint anyway).
        first = driver.run(self._args(d, "--security", "redteam"))
        self.assertEqual(first["status"], "checkpoint", first.get("message"))
        self.assertIsNone(run_manifest.load_manifest(d)["flags"]["tools"])
        with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write("version: 1\n"
                     "groups:\n  Core:\n    match: ['src/**']\n    panels: [COD]\n"
                     "settings:\n  security: standard\n  tools: true\n")
        resumed = driver.run(self._args(d))
        self.assertEqual(resumed["status"], "checkpoint", resumed.get("message"))
        self.assertEqual(resumed["checkpoint"], first["checkpoint"])
        self.assertEqual(run_manifest.load_manifest(d)["security_mode"], "redteam")

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
        # reset never deletes the committed matrix (#1681: it lives at the
        # repo root, outside the `.panopticon` scratch reset clears at all)
        self.assertTrue(os.path.isfile(os.path.join(d, "panopticon.yml")))

    def test_main_prints_status_and_returns_exit_code(self):
        d = self._repo()
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = driver.main(["run", d])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(buf.getvalue())["status"], "checkpoint")

    def test_host_generic_prints_the_fallback_notice_once(self):
        # D1: this fixture's first checkpoint is `scout`, which carries no
        # write-capable role, so the unenforced-ack gate (review-only) never
        # fires and --allow-unenforced is not needed to reach it.
        d = self._repo()
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), mock.patch("sys.stdout", out):
            driver.main(["run", d, "--host", "generic"])
        self.assertEqual(1, err.getvalue().count(host_disclosure.GENERIC_FALLBACK_NOTICE))

    def test_a_resumed_generic_run_prints_it_again_without_the_flag(self):
        # Resume path: --host is absent and the manifest is authoritative. The
        # notice comes from the RESOLVED host, not from argv.
        d = self._repo()
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(io.StringIO()), mock.patch("sys.stdout", out):
            driver.main(["run", d, "--host", "generic"])
        with contextlib.redirect_stderr(err), mock.patch("sys.stdout", out):
            driver.main(["run", d])
        self.assertEqual(1, err.getvalue().count(host_disclosure.GENERIC_FALLBACK_NOTICE))

    def test_host_claude_prints_no_fallback_notice(self):
        d = self._repo()
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), mock.patch("sys.stdout", out):
            driver.main(["run", d])
        self.assertNotIn(host_disclosure.GENERIC_FALLBACK_NOTICE, err.getvalue())

    def test_pr_acquires_worktree_and_records_manifest(self):
        # C1 flip: driver --pr now acquires the deterministic PR worktree via
        # resolve_review_root, rather than refusing. Finding B: with NO explicit
        # --base, manifest["base"] stays None (anti-drift key -- a bare resume
        # passes base=None -> no false drift) and the gh-detected PR base lands
        # in manifest["pr_base"], the origin-preference channel.
        # #2272: --no-tools for the same reason test_reset_restarts_from_scratch
        # carries it (#1515). Before #2272 the delta path put the run's own
        # untracked `.panopticon/` artifacts on the review surface, so this run
        # stopped at a spurious scout checkpoint; with them dropped the changed
        # set is empty and the run advances into tools_execute, whose child
        # run_tools.py probes docker outside conftest's in-process refusal.
        d = self._repo()
        args = driver.build_parser().parse_args(["run", d, "--pr", "7", "--no-tools"])
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

    def test_the_exhausted_cell_list_in_the_message_is_bounded(self):
        # Fix round 1, N2: the COUNT is exact and always has been; the named
        # list was joined uncapped, so a run that lost 100 cells put 100
        # `group/domain` pairs into one status line that hosts and CI parse.
        d = self._repo()
        complete = {"status": "complete", "phase": None, "checkpoint": None,
                    "group": None, "dispatch_request": None, "advanced": [],
                    "message": "all phases complete"}
        cells = ["g%02d/SEC" % i for i in range(12)]
        with mock.patch("scripts.phases.engine.run_engine", return_value=complete), \
                mock.patch("scripts.phases.validate._finalize_worktree"), \
                mock.patch("scripts.phases.review.exhausted_cells", return_value=cells):
            status = driver.run(self._args(d))
        self.assertEqual(status["cells_exhausted"], 12)          # exact
        self.assertIn("cells_exhausted: 12", status["message"])
        for named in cells[:10]:
            self.assertIn(named, status["message"])
        self.assertNotIn(cells[10], status["message"])
        self.assertNotIn(cells[11], status["message"])
        self.assertIn("2 more", status["message"])

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

"""Tests for scripts.phases.tools: the SAST/SCA adapter phase.
"""
import os
import tempfile
import unittest
from unittest import mock

import scripts.phases.engine as engine
import scripts.phases.runio as runio
import scripts.phases.tools as tools_phase


class TestToolsPhase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "flags": {}}

    def test_produced_output_marks_ran(self):
        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            os.makedirs(out, exist_ok=True)
            open(os.path.join(out, "trivy.json"), "w").close()
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("subprocess.run", side_effect=fake_run):
            result = tools_phase.tools_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        marker = runio._load_json(runio._pano(self.root, "tools-ran.json"))
        self.assertTrue(marker["ran"])
        self.assertTrue(tools_phase.tools_done(self.root, self.manifest))

    def _run_with_manifest(self, redacted):
        """A scan that writes one capture and the runner's own coverage
        manifest, whose `redacted` field is what run_tools observed."""
        def fake_run(cmd, **kw):
            out = cmd[cmd.index("--out") + 1]
            os.makedirs(out, exist_ok=True)
            open(os.path.join(out, "trivy.json"), "w").close()
            if redacted is not None:
                runio._write_json(cmd[cmd.index("--manifest") + 1],
                                  {"schema_version": 1, "selected": ["trivy"],
                                   "produced": ["trivy"], "redacted": redacted,
                                   # THIS run's id: the phase refuses a claim
                                   # carried by another run's manifest (N2).
                                   "run_id": self.manifest["run_id"]})
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("subprocess.run", side_effect=fake_run):
            tools_phase.tools_execute(self.root, self.manifest)
        return runio._load_json(runio._pano(self.root, "tools-ran.json"))

    def test_marker_copies_the_runners_redaction_claim(self):
        # #1639 P11 ruling 4, fix round 1 F5: the raw captures under
        # `.panopticon/tools/` go through run_tools' redaction choke point and
        # the marker says so -- an operator about to copy that directory into a
        # CI artifact reads the claim from the run's own artifacts. The phase
        # COPIES what the runner reported; it does not assert another module's
        # behaviour with a literal nobody checks.
        self.assertIs(self._run_with_manifest(True)["redacted"], True)

    def test_marker_does_not_upgrade_a_runner_that_reported_no_pass(self):
        self.assertIs(self._run_with_manifest(False)["redacted"], False)

    def test_marker_ignores_a_previous_runs_manifest(self):
        # Round 2 N2: run_tools.main() writes the manifest only after the scan
        # returns, so a runner that lands captures and then dies leaves the
        # PREVIOUS invocation's manifest in place -- and the phase would copy
        # its `redacted: true` for captures this run never passed. That is F5's
        # own failure mode one level up, in the overstatement direction.
        runio._write_json(runio._pano(self.root, "tools-manifest.json"),
                          {"schema_version": 1, "run_id": "OLD-RUN",
                           "produced": ["trivy"], "redacted": True})

        def fake_run(cmd, **kw):     # writes a capture, never the manifest
            out = cmd[cmd.index("--out") + 1]
            os.makedirs(out, exist_ok=True)
            open(os.path.join(out, "trivy.json"), "w").close()
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("subprocess.run", side_effect=fake_run):
            tools_phase.tools_execute(self.root, self.manifest)
        marker = runio._load_json(runio._pano(self.root, "tools-ran.json"))
        self.assertEqual(marker["run_id"], "R")
        self.assertTrue(marker["ran"])          # the scan really did produce
        self.assertIs(marker["redacted"], False)

    def test_marker_claims_nothing_when_the_runner_left_no_manifest(self):
        # A crash before the manifest was written leaves no claim to copy, and
        # the phase invents none.
        self.assertIs(self._run_with_manifest(None)["redacted"], False)

    def test_no_tools_marker_claims_nothing_about_redaction(self):
        # `--no-tools` writes no capture at all, so it must not claim a pass
        # over files an earlier run left in place.
        m = {"run_id": "R", "flags": {"tools": False}}
        with mock.patch("subprocess.run"):
            tools_phase.tools_execute(self.root, m)
        marker = runio._load_json(runio._pano(self.root, "tools-ran.json"))
        self.assertNotIn("redacted", marker)

    def test_passes_manifest_flag(self):
        # #1031: tools_execute asks run_tools for the deterministic adapter
        # manifest so synthesize certifies tool coverage against it, not the
        # scout's advisory list.
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            out = cmd[cmd.index("--out") + 1]
            os.makedirs(out, exist_ok=True)
            open(os.path.join(out, "trivy.json"), "w").close()
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("subprocess.run", side_effect=fake_run):
            tools_phase.tools_execute(self.root, self.manifest)
        cmd = captured["cmd"]
        self.assertIn("--manifest", cmd)
        self.assertEqual(cmd[cmd.index("--manifest") + 1],
                         runio._pano(self.root, "tools-manifest.json"))

    def test_docker_absent_is_disclosed_skip_that_advances(self):
        def fake_run(cmd, **kw):   # produces nothing, exits 0 (docker missing)
            return mock.Mock(returncode=0, stdout="",
                             stderr="panopticon-tools image not available; skipping")
        with mock.patch("subprocess.run", side_effect=fake_run):
            result = tools_phase.tools_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        marker = runio._load_json(runio._pano(self.root, "tools-ran.json"))
        self.assertFalse(marker["ran"])
        self.assertTrue(marker["skipped"])
        self.assertFalse(marker["crashed"])   # #1033: rc 0 + no output = benign
        self.assertIn("image not available", marker["note"])

    def test_tool_crash_is_distinct_from_docker_absent(self):
        # #1033: rc != 0 + no output = a real scanner/runner CRASH, recorded with
        # a distinct `crashed` marker (still advances -- tools are best-effort).
        def crash_run(cmd, **kw):
            return mock.Mock(returncode=2, stdout="", stderr="run_tools traceback")
        with mock.patch("subprocess.run", side_effect=crash_run):
            result = tools_phase.tools_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        marker = runio._load_json(runio._pano(self.root, "tools-ran.json"))
        self.assertFalse(marker["ran"])
        self.assertTrue(marker["crashed"])
        self.assertEqual(marker["returncode"], 2)

    def test_no_tools_flag_skips_subprocess(self):
        m = {"run_id": "R", "flags": {"tools": False}}
        with mock.patch("subprocess.run") as run_mock:
            result = tools_phase.tools_execute(self.root, m)
        run_mock.assert_not_called()
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(runio._load_json(runio._pano(self.root, "tools-ran.json"))["skipped"])


class TestAnEnvironmentalSkipIsNotDone(unittest.TestCase):
    """#1637 P08 ruling 4: `tools-ran.json parses` made an ENVIRONMENTAL skip
    -- Docker down, or the image absent -- done for ever, so installing the
    image mid-run never retried the scan. Run-13's 85 panels ran without
    scanner evidence behind exactly that cached marker. A skip is now done only
    when it was the operator's choice (`--no-tools`); the environmental one
    costs one `docker image inspect` on the next invocation.
    """

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        # F1: a real manifest carries this invocation's token -- driver.run
        # mints one per call. The environmental-skip questions below are all
        # asked from a LATER invocation (token "inv-2"), which is the cadence
        # ruling 4 names: re-evaluated on the next `driver run`.
        self.manifest = {"run_id": "R", "flags": {}, "invocation": "inv-2"}

    def _marker(self, **fields):
        body = {"schema_version": 1, "ran": False, "skipped": False,
                "crashed": False, "note": "", "returncode": 0, "run_id": "R",
                "attempt_invocation": "inv-1"}
        body.update(fields)
        runio._write_json(runio._pano(self.root, "tools-ran.json"), body)
        return tools_phase.tools_done(self.root, self.manifest)

    def test_an_environmental_skip_is_not_done(self):
        self.assertFalse(self._marker(
            skipped=True, note="panopticon-tools image not available; skipping"))

    def test_a_skip_with_no_note_at_all_is_not_done(self):
        self.assertFalse(self._marker(skipped=True, note=""))

    def test_a_produced_scan_is_done(self):
        self.assertTrue(self._marker(ran=True))

    def test_a_crashed_scan_is_done(self):
        # Best-effort by design: a crash is disclosed and gated elsewhere
        # (#1033), and re-running the same broken scanner every invocation
        # would wedge the run rather than fix it.
        self.assertTrue(self._marker(crashed=True, skipped=True, returncode=2))

    def test_the_operators_own_no_tools_skip_is_done(self):
        m = {"run_id": "R", "flags": {"tools": False}}
        with mock.patch("subprocess.run") as run_mock:
            tools_phase.tools_execute(self.root, m)
        run_mock.assert_not_called()
        self.assertTrue(tools_phase.tools_done(self.root, m))

    def test_an_unparseable_marker_is_not_done(self):
        with open(runio._pano(self.root, "tools-ran.json"), "w",
                  encoding="utf-8") as fh:
            fh.write("{ not json")
        self.assertFalse(tools_phase.tools_done(self.root, self.manifest))


class TestTheRetryIsInvocationScopedNotStepScoped(unittest.TestCase):
    """F1: `tools_done` is recomputed on EVERY engine step, not once per run.

    An environmental skip that is simply "not done" makes `run_engine`
    re-select `tools` immediately, in the same invocation, until max_steps
    (10 000) -- then an uncaught RuntimeError, no status JSON, and `review`
    never reached. The trigger is the exact case ruling 4 exists for:
    run_tools exits 0 having written nothing (image absent, or no applicable
    adapter).

    So the retry is scoped to the INVOCATION: `tools_execute` stamps the
    marker with this invocation's token, and a skip carrying the current
    token is done FOR THIS INVOCATION and not-done for the next `driver run`.
    """

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.children = []

    def _manifest(self, token):
        return {"run_id": "R", "flags": {}, "invocation": token}

    def _silent_child(self, cmd, review_root, phase, timeout=None):
        """run_tools' docker-absent path: exit 0, write nothing."""
        self.children.append(phase)
        return mock.Mock(
            returncode=0, stdout="",
            stderr="panopticon-tools image not available; skipping tool scan")

    def _engine(self, token):
        reached = {"review": False}

        def review_execute(root, manifest):
            reached["review"] = True
            return engine.PhaseResult(kind="advanced", message="review")

        phases = (
            engine.Phase("tools", "deterministic",
                         tools_phase.tools_done, tools_phase.tools_execute),
            engine.Phase("review", "deterministic",
                         lambda root, m: reached["review"], review_execute),
        )
        with mock.patch.object(tools_phase.child, "_run_child",
                               side_effect=self._silent_child):
            result = engine.run_engine(self.root, self._manifest(token), phases,
                                       max_steps=25)
        return result, reached

    def test_a_silent_tools_child_runs_once_and_the_run_proceeds(self):
        result, reached = self._engine("inv-1")
        self.assertEqual(self.children, ["tools"])
        self.assertTrue(reached["review"])
        self.assertEqual(result["status"], "complete")

    def test_the_next_invocation_retries_it_exactly_once_more(self):
        self._engine("inv-1")
        self._engine("inv-2")
        self.assertEqual(self.children, ["tools", "tools"])

    def test_the_marker_carries_the_invocation_that_attempted_it(self):
        self._engine("inv-1")
        marker = runio._load_json(runio._pano(self.root, "tools-ran.json"))
        self.assertEqual(marker["attempt_invocation"], "inv-1")

    def test_a_marker_with_no_token_is_never_done_even_with_no_token_to_match(self):
        """Fail CLOSED on the None/None case.

        `driver.run` always mints a token, so this is not reachable from the
        CLI today -- but `None == None` is True, which means the moment any
        future caller of `run_engine` forgets the key, an environmental skip is
        done for ever and run-13's regression is back verbatim. The cost of
        failing closed is one retry by the next minted invocation, which is
        exactly what a pre-#1637 marker already gets."""
        runio._write_json(runio._pano(self.root, "tools-ran.json"),
                          {"schema_version": 1, "ran": False, "skipped": True,
                           "crashed": False, "note": "", "returncode": 0,
                           "run_id": "R"})
        self.assertFalse(tools_phase.tools_done(self.root,
                                                {"run_id": "R", "flags": {}}))

    def test_a_forged_marker_cannot_claim_this_invocations_token(self):
        # The token is a fresh uuid per invocation, so a .panopticon file a
        # hostile target pre-commits cannot name it; one that omits the field
        # reads as another invocation's and is retried.
        runio._write_json(runio._pano(self.root, "tools-ran.json"),
                          {"schema_version": 1, "ran": False, "skipped": True,
                           "crashed": False, "note": "", "returncode": 0,
                           "run_id": "R"})
        self.assertFalse(tools_phase.tools_done(self.root,
                                                self._manifest("inv-9")))


class TestTheNoToolsMarkerIsFlagAware(unittest.TestCase):
    """F5: `readiness_done` re-evaluates when the manifest's `tools` flag no
    longer matches the artifact's; `tools_done`'s `--no-tools` branch did not,
    so a `--no-tools` marker stayed done on a run that had since been switched
    back to tools-enabled."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        runio._write_json(
            runio._pano(self.root, "tools-ran.json"),
            {"schema_version": 1, "ran": False, "skipped": True,
             "crashed": False, "note": tools_phase.NO_TOOLS_NOTE,
             "returncode": None, "run_id": "R", "attempt_invocation": "inv-1"})

    def test_done_while_the_manifest_still_says_no_tools(self):
        self.assertTrue(tools_phase.tools_done(
            self.root, {"run_id": "R", "flags": {"tools": False},
                        "invocation": "inv-2"}))

    def test_not_done_once_the_manifest_says_tools_are_enabled(self):
        for flag in (None, True):
            with self.subTest(tools=flag):
                self.assertFalse(tools_phase.tools_done(
                    self.root, {"run_id": "R", "flags": {"tools": flag},
                                "invocation": "inv-2"}))

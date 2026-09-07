"""Tests for scripts.phases.tools: the SAST/SCA adapter phase.
"""
import os
import tempfile
import unittest
from unittest import mock

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

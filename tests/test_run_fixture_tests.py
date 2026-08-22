"""#878: unit coverage for skill/scripts/run_fixture_tests.py.

The script shells out to docker for everything real; these tests patch the
module's subprocess (and path constants) so the orchestration logic -- manifest
handling, fixture presence bookkeeping, the #664 argv-not-interpolated
contract, CLI flow -- is pinned without Docker.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scripts.run_fixture_tests as rft


class _Res:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout


class TestLoadManifest(unittest.TestCase):
    def test_missing_manifest_exits_1(self):
        with mock.patch.object(rft, "MANIFEST", Path("/nonexistent/manifest.json")):
            with self.assertRaises(SystemExit) as cm:
                rft.load_manifest()
        self.assertEqual(cm.exception.code, 1)

    def test_invalid_json_exits_1(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "manifest.json"
            p.write_text("{not json")
            with mock.patch.object(rft, "MANIFEST", p):
                with self.assertRaises(SystemExit) as cm:
                    rft.load_manifest()
        self.assertEqual(cm.exception.code, 1)

    def test_valid_manifest_round_trips(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "manifest.json"
            p.write_text(json.dumps({"fixtures": [{"name": "x"}]}))
            with mock.patch.object(rft, "MANIFEST", p):
                self.assertEqual(rft.load_manifest(), {"fixtures": [{"name": "x"}]})


class TestCheckFixtures(unittest.TestCase):
    def test_local_unbaked_fixture_checked_on_host(self):
        # baked:false fixtures are validated against the host checkout, never
        # the image (checking inside the image would always read MISSING).
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "tests", "fixtures", "hostile"))
            fixtures = [
                {"name": "hostile", "path": "tests/fixtures/hostile", "baked": False},
                {"name": "ghost", "path": "tests/fixtures/ghost", "baked": False},
            ]
            with mock.patch.object(rft, "REPO_ROOT", Path(d)):
                present, missing = rft.check_fixtures("tag", fixtures)
        self.assertEqual(present, ["hostile"])
        self.assertEqual(missing, ["ghost"])

    def test_baked_fixtures_resolved_from_image_probe_output(self):
        fixtures = [{"name": "rust", "path": "/opt/f/rust", "baked": True},
                    {"name": "node", "path": "/opt/f/node", "baked": True}]
        probe = _Res(stdout="PRESENT:/opt/f/rust\nMISSING:/opt/f/node\n")
        with mock.patch.object(rft.subprocess, "run", return_value=probe) as m:
            present, missing = rft.check_fixtures("tag", fixtures)
        self.assertEqual(present, ["rust"])
        self.assertEqual(missing, ["node"])
        # #664 contract: the sh script is a FIXED constant; paths ride as argv
        # after the "sh" $0 placeholder, never interpolated into the script.
        cmd = m.call_args.args[0]
        script_idx = cmd.index("-c") + 1
        self.assertNotIn("/opt/f/rust", cmd[script_idx])
        self.assertEqual(cmd[script_idx + 1], "sh")
        self.assertEqual(cmd[script_idx + 2:], ["/opt/f/rust", "/opt/f/node"])

    def test_no_baked_paths_skips_docker_entirely(self):
        with mock.patch.object(rft.subprocess, "run") as m:
            present, missing = rft.check_fixtures("tag", [])
        m.assert_not_called()
        self.assertEqual((present, missing), ([], []))


class TestRunTests(unittest.TestCase):
    def test_test_filter_becomes_k_expression_and_mounts_are_ro(self):
        with mock.patch.object(rft.subprocess, "run", return_value=_Res(3)) as m:
            rc = rft.run_tests("tag", test="rust")
        self.assertEqual(rc, 3)          # pytest exit code propagates verbatim
        cmd = m.call_args.args[0]
        self.assertIn("-k", cmd)
        self.assertEqual(cmd[cmd.index("-k") + 1], "test_rust_integration")
        self.assertTrue(any(str(a).endswith("/skill:/opt/panopticon/skill:ro")
                            for a in cmd))

    def test_no_filter_runs_whole_tools_tree(self):
        with mock.patch.object(rft.subprocess, "run", return_value=_Res(0)) as m:
            rft.run_tests("tag")
        cmd = m.call_args.args[0]
        self.assertNotIn("-k", cmd)
        self.assertIn("/opt/panopticon/tests/tools", cmd)

    def test_run_tests_is_bounded_by_timeout(self):
        with mock.patch.object(rft.subprocess, "run", return_value=_Res(0)) as m:
            rft.run_tests("tag")
        self.assertEqual(m.call_args.kwargs.get("timeout"), rft.TEST_TIMEOUT)  # #1114

    def test_run_tests_timeout_returns_124(self):
        with mock.patch.object(rft.subprocess, "run",
                               side_effect=rft.subprocess.TimeoutExpired("cmd", rft.TEST_TIMEOUT)):
            self.assertEqual(rft.run_tests("tag"), 124)  # bounded, not an infinite hang


class TestDockerTimeouts(unittest.TestCase):
    """#1113: docker probes and the image build must all be time-bounded."""

    def test_docker_available_probe_carries_timeout(self):
        with mock.patch.object(rft.subprocess, "run", return_value=_Res(0)) as m:
            rft.docker_available()
        self.assertEqual(m.call_args.kwargs.get("timeout"), rft.PROBE_TIMEOUT)

    def test_image_exists_probe_carries_timeout(self):
        with mock.patch.object(rft.subprocess, "run", return_value=_Res(0)) as m:
            rft.image_exists("tag")
        self.assertEqual(m.call_args.kwargs.get("timeout"), rft.PROBE_TIMEOUT)

    def test_build_image_carries_timeout(self):
        with mock.patch.object(rft.subprocess, "run", return_value=_Res(0)) as m:
            rft.build_image("tag")
        self.assertEqual(m.call_args.kwargs.get("timeout"), rft.BUILD_TIMEOUT)

    def test_probe_timeout_is_unavailable_not_crash(self):
        with mock.patch.object(rft.subprocess, "run",
                               side_effect=rft.subprocess.TimeoutExpired("cmd", rft.PROBE_TIMEOUT)):
            self.assertFalse(rft.docker_available())
            self.assertFalse(rft.image_exists("tag"))


class TestMain(unittest.TestCase):
    def _manifest(self, d):
        p = Path(d) / "manifest.json"
        p.write_text(json.dumps({"fixtures": [
            {"name": "rust", "language": "rust", "path": "/opt/f/rust"}]}))
        return p

    def test_docker_unavailable_is_rc_1(self):
        with mock.patch.object(rft, "docker_available", return_value=False):
            self.assertEqual(rft.main([]), 1)

    def test_happy_path_uses_existing_image_and_propagates_pytest_rc(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(rft, "MANIFEST", self._manifest(d)), \
                    mock.patch.object(rft, "docker_available", return_value=True), \
                    mock.patch.object(rft, "image_exists", return_value=True), \
                    mock.patch.object(rft, "build_image") as build, \
                    mock.patch.object(rft, "check_fixtures",
                                      return_value=(["rust"], [])), \
                    mock.patch.object(rft, "run_tests", return_value=0):
                rc = rft.main([])
        self.assertEqual(rc, 0)
        build.assert_not_called()        # existing image reused

    def test_rebuild_flag_forces_build(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(rft, "MANIFEST", self._manifest(d)), \
                    mock.patch.object(rft, "docker_available", return_value=True), \
                    mock.patch.object(rft, "image_exists", return_value=True), \
                    mock.patch.object(rft, "build_image") as build, \
                    mock.patch.object(rft, "check_fixtures", return_value=([], [])), \
                    mock.patch.object(rft, "run_tests", return_value=0):
                rft.main(["--rebuild"])
        build.assert_called_once()


class TestCheckFixturesInjection(unittest.TestCase):
    def _capture_cmd(self, fixtures):
        captured = {}

        def fake_run(cmd, capture_output=False, text=False, timeout=None):
            captured["cmd"] = cmd
            # Echo back PRESENT for each positional path (args after the $0 "sh")
            paths = cmd[cmd.index("-c") + 3:]
            out = "\n".join("PRESENT:%s" % p for p in paths)
            return mock.Mock(stdout=out, returncode=0)

        with mock.patch.object(rft.subprocess, "run", fake_run):
            present, missing = rft.check_fixtures("img:tag", fixtures)
        return captured["cmd"], present, missing

    def test_paths_are_positional_args_not_script_text(self):
        evil = '"; touch /tmp/pwned; echo "'
        cmd, present, _ = self._capture_cmd(
            [{"name": "evil", "path": evil, "baked": True}])
        # The script is the constant loop; the evil path appears ONLY as a
        # trailing positional argument, never inside the -c script body.
        script = cmd[cmd.index("-c") + 1]
        self.assertNotIn("touch /tmp/pwned", script)
        self.assertNotIn(evil, script)
        self.assertIn('for p in "$@"', script)
        self.assertEqual(cmd[-1], evil)          # passed as inert data
        self.assertEqual(present, ["evil"])       # round-trips by name

    def test_dollar_and_backtick_paths_are_inert(self):
        for evil in ("$(rm -rf /)", "`id`", "a b; whoami"):
            cmd, present, _ = self._capture_cmd(
                [{"name": "x", "path": evil, "baked": True}])
            script = cmd[cmd.index("-c") + 1]
            self.assertNotIn(evil, script)
            self.assertEqual(cmd[-1], evil)
            self.assertEqual(present, ["x"])

    def test_present_and_missing_map_back_by_name(self):
        def fake_run(cmd, capture_output=False, text=False, timeout=None):
            return mock.Mock(stdout="PRESENT:/opt/a\nMISSING:/opt/b",
                             returncode=0)
        fixtures = [{"name": "A", "path": "/opt/a", "baked": True},
                    {"name": "B", "path": "/opt/b", "baked": True}]
        with mock.patch.object(rft.subprocess, "run", fake_run):
            present, missing = rft.check_fixtures("img:tag", fixtures)
        self.assertEqual(present, ["A"])
        self.assertEqual(missing, ["B"])

    def test_no_baked_fixtures_skips_docker(self):
        called = {"n": 0}

        def fake_run(*a, **k):
            called["n"] += 1
            return mock.Mock(stdout="", returncode=0)
        with mock.patch.object(rft.subprocess, "run", fake_run):
            present, missing = rft.check_fixtures("img:tag", [])
        self.assertEqual((present, missing), ([], []))
        self.assertEqual(called["n"], 0)          # no docker invocation


if __name__ == "__main__":
    unittest.main()

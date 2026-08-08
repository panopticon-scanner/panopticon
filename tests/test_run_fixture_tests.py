"""Shell-injection regression for check_fixtures (#664).

check_fixtures asks the fixtures Docker image whether each baked fixture path
exists. The old implementation spliced each manifest path into an `sh -c`
script via an f-string, so a path containing shell metacharacters executed as
code. The fix passes paths as positional arguments to a constant script; these
tests pin that the untrusted path never reaches the script text and that a
metacharacter-laden path is treated as inert data.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill", "scripts"))
import run_fixture_tests as rft


class TestCheckFixturesInjection(unittest.TestCase):
    def _capture_cmd(self, fixtures):
        captured = {}

        def fake_run(cmd, capture_output=False, text=False):
            captured["cmd"] = cmd
            # Echo back PRESENT for each positional path (args after the $0 "sh")
            paths = cmd[cmd.index("sh", 5) + 1:]
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
        def fake_run(cmd, capture_output=False, text=False):
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

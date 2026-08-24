"""Containment and environment tests for scripts.run_tools."""
import os
import tempfile
import unittest
from unittest import mock

import scripts.run_tools as rt

from run_tools_test_helpers import _FakeResult


class TestContainment(unittest.TestCase):
    def _calls(self, tools, online=False, env=None):
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')
        def runner(cmd, **kw):
            calls.append(cmd); return fake
        with mock.patch.dict(os.environ, env or {}, clear=True):
            with tempfile.TemporaryDirectory() as d:
                rt.run_tools(d, tools, os.path.join(d, "out"),
                             runner=runner, online=online)
        return calls

    def test_every_dispatch_has_network_none(self):
        for cmd in self._calls(["semgrep", "cargo-audit"]):
            self.assertIn("--network", cmd)          # clear failure, not ValueError (#780)
            i = cmd.index("--network")
            self.assertLess(i + 1, len(cmd), "--network has no value argument")
            self.assertEqual(cmd[i + 1], "none")

    def test_nvd_api_key_never_forwarded(self):
        for cmd in self._calls(["dependency-check"],
                               env={"NVD_API_KEY": "dummy"}):
            self.assertNotIn("-e", cmd)
            self.assertNotIn("NVD_API_KEY", cmd)

    def test_online_only_adapters_skipped_offline(self):
        calls = self._calls(["pip-audit", "npm-audit", "cargo-audit"])
        joined = [" ".join(c) for c in calls]
        self.assertEqual(len(calls), 1)
        self.assertIn("cargo-audit", joined[0])

    def test_online_flag_dispatches_online_only_with_network(self):
        calls = self._calls(["pip-audit"], online=True)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("--network", calls[0])

    def test_roslyn_never_gets_network_even_online(self):
        calls = self._calls(["roslyn-secguard"], online=True)
        self.assertEqual(len(calls), 1)               # #run7 COD-A2C: clear fail if roslyn was skipped
        self.assertIn("--network", calls[0])          # clear failure, not ValueError (#781)
        i = calls[0].index("--network")
        self.assertLess(i + 1, len(calls[0]), "--network has no value argument")
        self.assertEqual(calls[0][i + 1], "none")

    def test_filter_online_helper(self):
        chosen = ["semgrep", "pip-audit", "npm-audit", "gosec"]
        self.assertEqual(rt.filter_online(chosen, online=False),
                         ["semgrep", "gosec"])
        self.assertEqual(rt.filter_online(chosen, online=True), chosen)

    def test_calls_helper_does_not_leak_environ(self):
        # Regression: _calls must restore os.environ after patching.
        original = dict(os.environ)
        self.test_nvd_api_key_never_forwarded()
        self.assertEqual(dict(os.environ), original)

"""Docker availability probe tests for scripts.run_tools."""
import unittest

import scripts.run_tools as rt

from run_tools_test_helpers import _FakeResult


class TestRunTools(unittest.TestCase):
    def test_docker_unavailable_when_runner_fails(self):
        def runner(cmd, **kw):
            raise FileNotFoundError("docker not installed")
        self.assertFalse(rt.docker_available(runner=runner))

    def test_docker_available_when_inspect_ok(self):
        self.assertTrue(rt.docker_available(runner=lambda cmd, **kw: _FakeResult(returncode=0)))

    def test_docker_unavailable_when_image_missing(self):
        # Docker is installed (no exception) but `image inspect` returns non-zero
        # because the panopticon-tools image isn't built -> unavailable.
        self.assertFalse(rt.docker_available(runner=lambda cmd, **kw: _FakeResult(returncode=1)))

    def test_docker_available_probe_carries_timeout(self):
        # #1112: the gating probe must be bounded so a wedged daemon can't hang.
        seen = {}
        def runner(cmd, **kw):
            seen.update(kw)
            return _FakeResult(returncode=0)
        rt.docker_available(runner=runner)
        self.assertEqual(seen.get("timeout"), rt.DOCKER_PROBE_TIMEOUT)

    def test_docker_unavailable_when_probe_times_out(self):
        def runner(cmd, **kw):
            raise rt.subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        self.assertFalse(rt.docker_available(runner=runner))  # bounded, no hang

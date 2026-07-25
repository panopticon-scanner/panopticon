import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import run_tools as rt


class TestRunTools(unittest.TestCase):
    def test_docker_unavailable_when_runner_fails(self):
        def runner(cmd, **kw):
            raise FileNotFoundError("docker not installed")
        self.assertFalse(rt.docker_available(runner=runner))

    def test_docker_available_when_inspect_ok(self):
        class R:  # noqa
            returncode = 0
        self.assertTrue(rt.docker_available(runner=lambda cmd, **kw: R()))

    def test_docker_unavailable_when_image_missing(self):
        # Docker is installed (no exception) but `image inspect` returns non-zero
        # because the panopticon-tools image isn't built -> unavailable.
        class R:  # noqa
            returncode = 1
        self.assertFalse(rt.docker_available(runner=lambda cmd, **kw: R()))

    def test_select_tools(self):
        tools = rt.select_tools(["python", "go"], has_deps=True)
        self.assertIn("semgrep", tools)
        self.assertIn("gitleaks", tools)
        self.assertIn("trivy", tools)
        self.assertIn("bandit", tools)
        self.assertIn("gosec", tools)
        self.assertNotIn("brakeman", tools)

    def test_run_tools_passes_exact_timeout_and_survives_timeout(self):
        import subprocess as sp
        seen = {}
        def runner(cmd, **kw):
            seen['timeout'] = kw.get('timeout')
            raise sp.TimeoutExpired(cmd, kw.get('timeout') or 0)
        with tempfile.TemporaryDirectory() as d:
            paths = rt.run_tools(d, ["semgrep"], os.path.join(d, "out"), runner=runner)
            self.assertEqual(seen['timeout'], rt.TOOL_TIMEOUT)  # exact timeout, not just non-None
            self.assertEqual(paths, [])                         # timed-out tool skipped, no raise

    def test_run_tools_skips_tool_on_unexpected_returncode(self):
        # returncode not in (0, 1) means the tool errored (not "clean"/"findings"):
        # skip it, write no file, and don't raise.
        class R: returncode = 2; stdout = b'garbage'; stderr = b'boom'
        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            paths = rt.run_tools(d, ["semgrep"], out_dir, runner=lambda cmd, **kw: R())
            self.assertEqual(paths, [])                          # skipped
            self.assertFalse(os.path.exists(os.path.join(out_dir, "semgrep.sarif")))

    def test_run_tools_builds_exact_docker_argv(self):
        calls = []
        class R: returncode = 0; stdout = b'{"runs":[]}'; stderr = b''
        def runner(cmd, **kw):
            calls.append(cmd); return R()
        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            rt.run_tools(d, ["semgrep"], out_dir, image="panopticon-tools", runner=runner)
            expected = ["docker", "run", "--rm",
                        "-v", "%s:/src:ro" % os.path.abspath(d),
                        "panopticon-tools"] + rt.TOOL_CMD["semgrep"]
            self.assertEqual(calls[0], expected)   # exact argv: flags, :ro mount, image, per-tool cmd
            with open(os.path.join(out_dir, "semgrep.sarif"), "rb") as fh:
                self.assertEqual(fh.read(), R.stdout)  # runner stdout bytes persisted verbatim

    def test_run_tools_continues_after_one_tool_fails(self):
        def runner(cmd, **kw):
            if "semgrep" in cmd: raise OSError("boom")
            class R: returncode = 0; stdout = b'{"runs":[]}'; stderr = b''
            return R()
        with tempfile.TemporaryDirectory() as d:
            paths = rt.run_tools(d, ["semgrep", "gitleaks"], os.path.join(d, "out"), runner=runner)
            self.assertEqual(len(paths), 1)                  # gitleaks still ran

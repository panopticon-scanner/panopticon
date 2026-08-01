import io
import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.run_tools as rt
import scripts._run_adapter as ra


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


class TestAdapterDispatch(unittest.TestCase):
    def test_select_adapters_by_ecosystem(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "requirements.txt"), "w").close()
            names = rt.select_adapters(d)
            self.assertIn("pip-audit", names)
            self.assertNotIn("npm-audit", names)

    def test_run_adapters_writes_raw_output(self):
        class FakeAdapter:
            name = "fake"
            def is_applicable(self, target): return True
            def invoke(self, target): return (b'{"results":[]}', 0)

        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            rt.run_adapters({"fake": FakeAdapter()}, d, out_dir)
            with open(os.path.join(out_dir, "fake.json")) as fh:
                self.assertEqual(json.load(fh), {"results": []})

    def test_run_tools_dispatches_phase1_adapter_via_docker_helper(self):
        class FakeAdapter:
            name = "fake"
            def is_applicable(self, target): return True
            def invoke(self, target): return (b'{"findings":[]}', 0)

        calls = []
        class R: returncode = 0; stdout = b'{"findings":[]}'; stderr = b''
        def runner(cmd, **kw):
            calls.append(cmd); return R()

        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            rt.ADAPTERS["fake"] = FakeAdapter()
            try:
                rt.run_tools(d, ["fake"], out_dir, image="panopticon-tools", runner=runner)
            finally:
                rt.ADAPTERS.pop("fake", None)
            self.assertEqual(len(calls), 1)
            self.assertTrue(any("_run_adapter.py" in arg for arg in calls[0]))
            self.assertIn("fake", calls[0])
            with open(os.path.join(out_dir, "fake.json"), "rb") as fh:
                self.assertEqual(fh.read(), R.stdout)


class TestRunAdapterHelper(unittest.TestCase):
    def test_main_runs_named_adapter_and_returns_rc(self):
        class FakeAdapter:
            name = "fake"
            def invoke(self, target): return (b'{"ok":true}', 0)

        ra.ADAPTERS["fake"] = FakeAdapter()
        try:
            stdout = io.BytesIO()
            class FakeOut:
                buffer = stdout
            old_stdout = sys.stdout
            sys.stdout = FakeOut()
            try:
                rc = ra.main(["_run_adapter.py", "fake", "/tmp/target"])
            finally:
                sys.stdout = old_stdout
            self.assertEqual(rc, 0)
            self.assertEqual(stdout.getvalue(), b'{"ok":true}')
        finally:
            ra.ADAPTERS.pop("fake", None)

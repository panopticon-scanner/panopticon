import io
import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
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
            expected = ["docker", "run", "--rm", "--network", "none",
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
            self.assertIn("/opt/panopticon/scripts/_run_adapter.py", calls[0])
            self.assertIn("fake", calls[0])
            with open(os.path.join(out_dir, "fake.json"), "rb") as fh:
                self.assertEqual(fh.read(), R.stdout)

    def test_run_tools_uses_readonly_src_mount_for_phase2_build_adapters(self):
        calls = []
        class R: returncode = 0; stdout = b'{"runs":[]}'; stderr = b''
        def runner(cmd, **kw):
            calls.append(cmd); return R()

        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            for tool in ("spotbugs", "roslyn-secguard"):
                rt.run_tools(d, [tool], out_dir, image="panopticon-tools", runner=runner)
            mounts = [cmd[cmd.index("-v") + 1] for cmd in calls]
            self.assertEqual(mounts, [
                "%s:/src:ro" % os.path.abspath(d),
                "%s:/src:ro" % os.path.abspath(d),
            ])


    def test_default_selection_includes_phase1_adapters(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "requirements.txt"), "w").close()
            open(os.path.join(d, "package-lock.json"), "w").close()
            chosen = rt.select_tools([], has_deps=False) + [
                name for name in rt.select_adapters(d) if name in rt.PHASE1_ADAPTERS
            ]
            self.assertIn("pip-audit", chosen)
            self.assertIn("npm-audit", chosen)


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

    def test_main_skips_unregistered_adapter(self):
        rc = ra.main(["_run_adapter.py", "not-a-real-adapter", "/tmp/target"])
        self.assertEqual(rc, 0)

    def test_main_skips_adapter_that_crashes(self):
        class CrashingAdapter:
            name = "crash"
            def invoke(self, target):
                raise RuntimeError("boom")

        ra.ADAPTERS["crash"] = CrashingAdapter()
        try:
            rc = ra.main(["_run_adapter.py", "crash", "/tmp/target"])
            self.assertEqual(rc, 0)
        finally:
            ra.ADAPTERS.pop("crash", None)


class TestContainment(unittest.TestCase):
    def _calls(self, tools, online=False, env=None):
        calls = []
        class R: returncode = 0; stdout = b'{"runs":[]}'; stderr = b''
        def runner(cmd, **kw):
            calls.append(cmd); return R()
        old = dict(os.environ)
        os.environ.update(env or {})
        try:
            with tempfile.TemporaryDirectory() as d:
                rt.run_tools(d, tools, os.path.join(d, "out"),
                             runner=runner, online=online)
        finally:
            os.environ.clear(); os.environ.update(old)
        return calls

    def test_every_dispatch_has_network_none(self):
        for cmd in self._calls(["semgrep", "cargo-audit"]):
            i = cmd.index("--network")
            self.assertEqual(cmd[i + 1], "none")

    def test_nvd_api_key_never_forwarded(self):
        for cmd in self._calls(["dependency-check"],
                               env={"NVD_API_KEY": "sekrit"}):
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
        i = calls[0].index("--network")
        self.assertEqual(calls[0][i + 1], "none")

    def test_filter_online_helper(self):
        chosen = ["semgrep", "pip-audit", "npm-audit", "gosec"]
        self.assertEqual(rt.filter_online(chosen, online=False),
                         ["semgrep", "gosec"])
        self.assertEqual(rt.filter_online(chosen, online=True), chosen)


class TestDetectLanguages(unittest.TestCase):
    def test_detects_by_extension_with_pruning(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "pkg"))
            os.makedirs(os.path.join(d, "node_modules", "dep"))
            open(os.path.join(d, "pkg", "app.py"), "w").close()
            open(os.path.join(d, "pkg", "ui.tsx"), "w").close()
            open(os.path.join(d, "node_modules", "dep", "index.js"), "w").close()
            langs = rt.detect_languages(d)
        self.assertIn("python", langs)
        self.assertIn("typescript", langs)
        self.assertNotIn("javascript", langs)  # only under pruned node_modules

    def test_empty_tree_detects_nothing(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(rt.detect_languages(d), [])

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
import scripts.run_tools as rt
import scripts._run_adapter as ra


class _FakeResult:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


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

    def test_recommendable_tools_is_the_selectable_universe(self):
        # #1053: the scout must recommend tools only from the set run_tools can
        # actually select/run -- the base SARIF tools + LANG_TOOL SAST + the
        # Phase-1/Phase-2 adapters. Excludes the retired bare `eslint` (can't run
        # on arbitrary targets), includes eslint-security.
        rec = rt.recommendable_tools()
        self.assertEqual(rec, sorted(rec))                 # sorted, stable
        for t in ("semgrep", "gitleaks", "trivy", "bandit", "gosec",
                  "eslint-security", "osv-scanner", "cargo-audit"):
            self.assertIn(t, rec)
        self.assertNotIn("eslint", rec)                    # retired bare eslint
        self.assertNotIn("pytest", rec)                    # never an adapter

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
        fake = _FakeResult(returncode=2, stdout=b'garbage', stderr=b'boom')
        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            paths = rt.run_tools(d, ["semgrep"], out_dir, runner=lambda cmd, **kw: fake)
            self.assertEqual(paths, [])                          # skipped
            self.assertFalse(os.path.exists(os.path.join(out_dir, "semgrep.sarif")))

    def test_failed_rerun_removes_stale_output(self):
        fake = _FakeResult(returncode=2, stdout=b"", stderr=b"failed")
        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            sarif = os.path.join(out_dir, "semgrep.sarif")
            os.makedirs(out_dir)
            with open(sarif, "w") as fh:
                fh.write("{}")
            paths = rt.run_tools(d, ["semgrep"], out_dir, runner=lambda cmd, **kw: fake)
            self.assertEqual(paths, [])
            self.assertFalse(os.path.exists(sarif))

    def test_manifest_discloses_missing_selected_tools(self):
        with tempfile.TemporaryDirectory() as d:
            semgrep = os.path.join(d, "semgrep.sarif")
            with open(semgrep, "w", encoding="utf-8") as fh:
                fh.write('{"runs":[]}')
            path = os.path.join(d, "run-manifest.json")
            payload = rt.write_manifest(
                path, ["semgrep", "gitleaks", "semgrep"], [semgrep])
            self.assertEqual(payload["selected"], ["semgrep", "gitleaks"])
            self.assertEqual(payload["produced"], ["semgrep"])
            self.assertEqual(payload["missing"], ["gitleaks"])
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), payload)

    def test_is_excluded_matches_subtree(self):
        self.assertTrue(rt._is_excluded("tests/fixtures/insecure-js/app.js",
                                        ["tests/fixtures/*"]))
        self.assertFalse(rt._is_excluded("skill/scripts/x.py",
                                         ["tests/fixtures/*"]))
        self.assertFalse(rt._is_excluded("a.js", []))

    def test_partition_demotes_adapter_with_only_excluded_files(self):
        class _Ad:
            def __init__(self, files):
                self._files = files
            def applicable_files(self, target):
                return [os.path.join(target, f) for f in self._files]
        class _NoFiles:  # lockfile-triggered adapter: stays required
            pass
        adapters = {"eslint-security": _Ad(["tests/fixtures/insecure-js/app.js"]),
                    "with-src": _Ad(["skill/x.js", "tests/fixtures/y.js"]),
                    "osv-scanner": _NoFiles()}
        required, excluded = rt.partition_by_exclusion(
            adapters, "/repo", ["tests/fixtures/*"])
        self.assertEqual(excluded, ["eslint-security"])
        self.assertCountEqual(required, ["with-src", "osv-scanner"])

    def test_partition_no_exclusions_demotes_nothing(self):
        class _Ad:
            def applicable_files(self, target):
                return [os.path.join(target, "tests/fixtures/a.js")]
        required, excluded = rt.partition_by_exclusion(
            {"eslint-security": _Ad()}, "/repo", [])
        self.assertEqual(excluded, [])
        self.assertEqual(required, ["eslint-security"])

    def test_manifest_records_excluded_scope(self):
        with tempfile.TemporaryDirectory() as d:
            payload = rt.write_manifest(
                os.path.join(d, "m.json"), ["semgrep"], [],
                excluded_scope=["eslint-security"])
            self.assertEqual(payload["excluded_scope"], ["eslint-security"])
            self.assertNotIn("eslint-security", payload["selected"])

    def test_eslint_applicable_files_drives_is_applicable(self):
        from scripts.tools.eslint_security import EslintSecurityAdapter
        with tempfile.TemporaryDirectory() as d:
            ad = EslintSecurityAdapter()
            self.assertFalse(ad.is_applicable(d))
            os.makedirs(os.path.join(d, "tests", "fixtures"))
            with open(os.path.join(d, "tests", "fixtures", "app.js"), "w") as fh:
                fh.write("//")
            self.assertTrue(ad.is_applicable(d))
            files = ad.applicable_files(d)
            self.assertEqual(len(files), 1)
            self.assertTrue(files[0].endswith("app.js"))

    def test_manifest_selection_excludes_offline_policy_skips(self):
        with tempfile.TemporaryDirectory() as d:
            effective = rt.filter_online(
                ["semgrep", "pip-audit", "npm-audit"], online=False)
            payload = rt.write_manifest(
                os.path.join(d, "manifest.json"), effective, [])
            self.assertEqual(payload["selected"], ["semgrep"])
            self.assertEqual(payload["missing"], ["semgrep"])

    def test_default_artifact_output_rejects_symlinked_root(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, os.path.join(d, ".panopticon"))
            with self.assertRaisesRegex(ValueError, "not a symlink"):
                rt.run_tools(d, ["semgrep"],
                             os.path.join(d, ".panopticon", "tools"))

    def test_run_tools_builds_exact_docker_argv(self):
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')
        def runner(cmd, **kw):
            calls.append(cmd); return fake
        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            rt.run_tools(d, ["semgrep"], out_dir, image="panopticon-tools", runner=runner)
            docker_bin = shutil.which("docker") or "docker"
            expected = [docker_bin, "run", "--rm", "--network", "none",
                        "-v", "%s:/src:ro" % os.path.abspath(d),
                        "panopticon-tools"] + rt.TOOL_CMD["semgrep"]
            self.assertEqual(calls[0], expected)   # exact argv: flags, :ro mount, image, per-tool cmd
            with open(os.path.join(out_dir, "semgrep.sarif"), "rb") as fh:
                self.assertEqual(fh.read(), fake.stdout)  # runner stdout bytes persisted verbatim

    def test_run_tools_continues_after_one_tool_fails(self):
        def runner(cmd, **kw):
            if "semgrep" in cmd: raise OSError("boom")
            return _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')
        with tempfile.TemporaryDirectory() as d:
            paths = rt.run_tools(d, ["semgrep", "gitleaks"], os.path.join(d, "out"), runner=runner)
            self.assertEqual(len(paths), 1)                  # gitleaks still ran

    def test_run_tools_truncates_oversized_output_with_marker(self):
        """#1111: oversized stdout must truncate, not OOM-buffer or silently skip."""
        huge = b"x" * (rt.MAX_TOOL_OUTPUT_BYTES + 100000)

        class _FakeStream:
            def __init__(self, data):
                self._data = data
            def read(self, n=-1):
                if not self._data:
                    return b""
                if n < 0:
                    chunk, self._data = self._data, b""
                    return chunk
                chunk, self._data = self._data[:n], self._data[n:]
                return chunk

        class _FakePopen:
            def __init__(self, data):
                self.stdout = _FakeStream(data)
                self.stderr = _FakeStream(b"")
                self._rc = 0
            def wait(self, timeout=None):
                return self._rc
            def poll(self):
                return self._rc

        def runner(cmd, **kw):
            return _FakePopen(huge)

        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            paths = rt.run_tools(d, ["semgrep"], out_dir, runner=runner)
            self.assertEqual(len(paths), 1)
            with open(paths[0], "rb") as fh:
                written = fh.read()
            self.assertLess(len(written), len(huge))
            self.assertIn(b"TRUNCATED", written)


class TestAdapterDispatch(unittest.TestCase):
    def test_select_adapters_by_ecosystem(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "requirements.txt"), "w").close()
            names = rt.select_adapters(d)
            self.assertIn("pip-audit", names)
            self.assertNotIn("npm-audit", names)

    def test_run_tools_dispatches_phase1_adapter_via_docker_helper(self):
        class FakeAdapter:
            name = "fake"
            def is_applicable(self, target): return True
            def invoke(self, target): return (b'{"findings":[]}', 0)

        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"findings":[]}', stderr=b'')
        def runner(cmd, **kw):
            calls.append(cmd); return fake

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
                self.assertEqual(fh.read(), fake.stdout)

    def test_empty_adapter_output_fails_closed(self):
        # #1051: an adapter run that exits 0 with EMPTY stdout is a silent
        # failure, not a clean run. Fail closed: announce it, write NO file, and
        # drop it from the produced set so write_manifest lands it in `missing`
        # (-> INCONCLUSIVE) instead of certifying it as ran-clean.
        class FakeAdapter:
            name = "fake"
            def is_applicable(self, target): return True
        fake = _FakeResult(returncode=0, stdout=b'', stderr=b'')
        def runner(cmd, **kw):
            return fake
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out")
            rt.ADAPTERS["fake"] = FakeAdapter()
            try:
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    paths = rt.run_tools(d, ["fake"], out, runner=runner)
            finally:
                rt.ADAPTERS.pop("fake", None)
            self.assertIn("produced no output", err.getvalue())
            self.assertEqual(paths, [])                                   # not produced
            self.assertFalse(os.path.exists(os.path.join(out, "fake.json")))  # no empty file

    def test_empty_adapter_output_lands_in_manifest_missing(self):
        # #1051, end-to-end: the empty-output adapter must show up in the
        # runner's coverage manifest as `missing`, never `produced` -- that is
        # the signal synthesize's #1031 gate turns into INCONCLUSIVE.
        class FakeAdapter:
            name = "fake"
            def is_applicable(self, target): return True
        fake = _FakeResult(returncode=0, stdout=b'', stderr=b'')
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out")
            rt.ADAPTERS["fake"] = FakeAdapter()
            try:
                written = rt.run_tools(d, ["fake"], out, runner=lambda cmd, **kw: fake)
            finally:
                rt.ADAPTERS.pop("fake", None)
            payload = rt.write_manifest(
                os.path.join(d, "m.json"), ["fake"], written)
            self.assertEqual(payload["produced"], [])
            self.assertEqual(payload["missing"], ["fake"])

    def test_run_tools_uses_readonly_src_mount_for_phase2_build_adapters(self):
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')
        def runner(cmd, **kw):
            calls.append(cmd); return fake

        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            for tool in ("spotbugs", "roslyn-secguard"):
                rt.run_tools(d, [tool], out_dir, image="panopticon-tools", runner=runner)
            expected_mount = "%s:/src:ro" % os.path.abspath(d)
            for cmd in calls:
                self.assertIn(expected_mount, cmd)


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

    def test_main_fails_closed_on_unregistered_adapter(self):
        # #1051: an unregistered adapter must exit non-zero (was 0 == "ran clean")
        rc = ra.main(["_run_adapter.py", "not-a-real-adapter", "/tmp/target"])
        self.assertEqual(rc, ra.FAIL_RC)

    def test_main_fails_closed_on_adapter_that_crashes(self):
        # #1051 / SEC-G2B: a crash must exit non-zero, never a silent rc 0
        class CrashingAdapter:
            name = "crash"
            def invoke(self, target):
                raise RuntimeError("boom")

        ra.ADAPTERS["crash"] = CrashingAdapter()
        try:
            rc = ra.main(["_run_adapter.py", "crash", "/tmp/target"])
            self.assertEqual(rc, ra.FAIL_RC)
        finally:
            ra.ADAPTERS.pop("crash", None)


class TestContainment(unittest.TestCase):
    def _calls(self, tools, online=False, env=None):
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')
        def runner(cmd, **kw):
            calls.append(cmd); return fake
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
        self.assertIn("--network", calls[0])          # clear failure, not ValueError (#781)
        i = calls[0].index("--network")
        self.assertLess(i + 1, len(calls[0]), "--network has no value argument")
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

    def test_run_tools_skips_when_output_exceeds_cap(self):
        huge = b"x" * (rt.MAX_TOOL_OUTPUT_BYTES + 10)
        fake = _FakeResult(returncode=0, stdout=huge)
        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            paths = rt.run_tools(d, ["semgrep"], out_dir, runner=lambda cmd, **kw: fake)
            self.assertEqual(paths, [])
            self.assertFalse(os.path.exists(os.path.join(out_dir, "semgrep.sarif")))

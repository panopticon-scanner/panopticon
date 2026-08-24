"""Core run_tools tests: selection, manifest, partitioning, output handling."""
import contextlib
import io
import json
import os
import shutil
import subprocess as sp
import sys
import tempfile
import threading
import unittest
from unittest import mock

import scripts.run_tools as rt
from scripts.tools.eslint_security import EslintSecurityAdapter  # #run7 TST-G2A

from run_tools_test_helpers import _FakeResult


class TestRunTools(unittest.TestCase):
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

    def test_recommendable_tools_all_resolve_to_a_registry(self):
        # #run7 ARC-A4C: every recommendable name must resolve to a real
        # invocation -- a legacy TOOL_CMD entry or an ADAPTERS entry. A name in
        # neither would silently fall through run_tools' dispatch loop and
        # surface only as a manifest `missing` entry (fail-closed but with no
        # diagnostic). Trip loudly here so a future rename/typo is caught.
        from scripts.tools import ADAPTERS
        from scripts.tools.legacy_sarif import TOOL_CMD
        resolvable = set(TOOL_CMD) | set(ADAPTERS)
        unresolved = [t for t in rt.recommendable_tools() if t not in resolvable]
        self.assertEqual(unresolved, [], unresolved)

    def test_select_tools(self):
        tools = rt.select_tools(["python", "go"], has_deps=True)
        self.assertIn("semgrep", tools)
        self.assertIn("gitleaks", tools)
        self.assertIn("trivy", tools)
        self.assertIn("bandit", tools)
        self.assertIn("gosec", tools)
        self.assertNotIn("brakeman", tools)

    def test_run_tools_passes_exact_timeout_and_survives_timeout(self):
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
            self.assertEqual(len(calls), 1)        # #run7 COD-A2C: clear fail if runner never fired
            self.assertEqual(calls[0], expected)   # exact argv: flags, :ro mount, image, per-tool cmd
            with open(os.path.join(out_dir, "semgrep.sarif"), "rb") as fh:
                self.assertEqual(fh.read(), fake.stdout)  # runner stdout bytes persisted verbatim

    def test_bandit_pins_ini_when_target_has_bandit_config(self):
        # #run7: bandit auto-discovers nested .bandit files (e.g. git worktrees)
        # and ERRORS ("Multiple .bandit files found") -> empty output, silently
        # unproduced -> certification blocked. Pin the target's own config with
        # --ini to bypass discovery, ONLY when the target actually has one.
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

        def runner(cmd, **kw):
            calls.append(cmd)
            return fake
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, ".bandit"), "w").close()
            rt.run_tools(d, ["bandit"], os.path.join(d, "out"),
                         image="panopticon-tools", runner=runner)
            self.assertIn("--ini", calls[0])
            i = calls[0].index("--ini")
            self.assertEqual(calls[0][i + 1], "/src/.bandit")   # container-side config path

    def test_bandit_no_ini_when_target_has_no_bandit_config(self):
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

        def runner(cmd, **kw):
            calls.append(cmd)
            return fake
        with tempfile.TemporaryDirectory() as d:   # no .bandit -> bandit's defaults
            rt.run_tools(d, ["bandit"], os.path.join(d, "out"),
                         image="panopticon-tools", runner=runner)
            self.assertNotIn("--ini", calls[0])
            self.assertEqual(calls[0][-len(rt.TOOL_CMD["bandit"]):],
                             rt.TOOL_CMD["bandit"])   # unchanged argv

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


class TestStreamingRunnerAndDeadline(unittest.TestCase):
    """#run7 COD-A2A / #1111: production must STREAM tool output through the
    bounded sink (not buffer it whole and drop), and the streaming read must be
    bounded by a wall-clock deadline the way subprocess.run's timeout was."""

    def test_default_runner_streams_not_buffers(self):
        # With no runner injected, run_tools uses the streaming _popen_runner
        # (a live Popen), NOT subprocess.run (which buffered all output in memory
        # and always took the drop path -- the #1111 guard was unreachable).
        seen = {}

        def fake_capture(label, tool, docker, out_path, runner):
            seen["runner"] = runner
            return None

        with mock.patch.object(rt, "_capture_run", side_effect=fake_capture):
            with tempfile.TemporaryDirectory() as d:
                rt.run_tools(d, ["semgrep"], os.path.join(d, "out"))
        self.assertIs(seen["runner"], rt._popen_runner)
        self.assertIsNot(seen["runner"], sp.run)

    def test_popen_runner_streams_real_subprocess_to_disk(self):
        # The default runner returns a real Popen whose stdout _capture_run
        # routes to _stream_and_write (proc.stdout is a stream, not bytes).
        proc = rt._popen_runner(
            [sys.executable, "-c", "import sys; sys.stdout.write('hello-stream')"],
            stdout=sp.PIPE, stderr=sp.PIPE)
        self.assertIsInstance(proc, sp.Popen)
        self.assertNotIsInstance(proc.stdout, (bytes, type(None)))   # streaming route
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "o.sarif")
            written = rt._stream_and_write("tool", "py", proc, out)
            self.assertEqual(written, out)
            with open(out, "rb") as fh:
                self.assertEqual(fh.read(), b"hello-stream")

    def test_watchdog_kills_hung_tool_and_skips(self):
        # A tool whose stdout.read() BLOCKS (hang) must be killed at the deadline
        # and skipped -- the bound subprocess.run's timeout used to give, now
        # enforced during the streaming read.
        released = threading.Event()

        class _HangStdout:
            def read(self, n=-1):
                released.wait(5)      # unblocks only when kill() releases it
                return b""            # then EOF
            def close(self):
                pass

        class _HangProc:
            def __init__(self):
                self.stdout = _HangStdout()
                self.stderr = io.BytesIO(b"")
                self._rc = None
            def wait(self, timeout=None):
                return -9             # SIGKILL
            def poll(self):
                return self._rc
            def kill(self):
                self._rc = -9
                released.set()

        proc = _HangProc()
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stderr(err):
            out = rt._stream_and_write("tool", "hang", proc,
                                       os.path.join(d, "o.sarif"), timeout=0.3)
        self.assertIsNone(out)                       # hung tool skipped, not hung forever
        self.assertIn("timed out", err.getvalue())
        self.assertTrue(released.is_set())           # the watchdog actually fired

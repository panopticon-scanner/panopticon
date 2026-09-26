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

from conftest import REPO_ROOT
from _test_helpers import fake_pem, pem_begin, pem_end
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

    def test_recommendable_tools_gated_by_language_and_applicability(self):
        # run-9 E1: gating to a language set drops the SAST for absent languages
        # (gosec on a Python repo), and gating to a target drops adapters not
        # applicable to it -- so the scout sees the runner's actual set and can't
        # over-request a cross-language scanner (the requested_unavailable noise).
        import tempfile
        gated = rt.recommendable_tools(languages=["python"])
        self.assertIn("bandit", gated)                     # python SAST kept
        self.assertNotIn("gosec", gated)                   # go SAST dropped
        self.assertIn("semgrep", gated)                    # always-on SARIF kept
        with tempfile.TemporaryDirectory() as d:           # no applicable adapters
            gt = rt.recommendable_tools(languages=[], target=d)
            self.assertNotIn("gosec", gt)
            self.assertNotIn("cargo-audit", gt)            # adapter, not applicable
            self.assertTrue(rt.BASE_TOOLS <= set(gt))      # always-on remain
        self.assertEqual(rt.recommendable_tools(),         # ungated default unchanged
                         sorted(rt.BASE_TOOLS | set(rt.LANG_TOOL.values())
                                | rt.PHASE1_ADAPTERS | rt.PHASE2_ADAPTERS))

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
        # #1740 fix round 2: the subtree is spelled `**`. Under the gitignore
        # semantics discovery has always used for these globs, `*` stays inside
        # a path segment -- `tests/fixtures/*` is the direct children and
        # nothing deeper, which is the next assertion.
        self.assertTrue(rt._is_excluded("tests/fixtures/insecure-js/app.js",
                                        ["tests/fixtures/**"]))
        self.assertFalse(rt._is_excluded("skill/scripts/x.py",
                                         ["tests/fixtures/**"]))
        self.assertFalse(rt._is_excluded("a.js", []))

    def test_a_single_star_stops_at_the_separator_like_gitignore(self):
        # The semantics change itself, pinned: `fnmatch` spanned `/` here and
        # discovery never did, so one committed `exclude_paths:` line meant two
        # different scopes (#1740 fix round 2).
        self.assertTrue(rt._is_excluded("tests/fixtures/app.js",
                                        ["tests/fixtures/*"]))
        self.assertFalse(rt._is_excluded("tests/fixtures/insecure-js/app.js",
                                         ["tests/fixtures/*"]))
        # a trailing `/` claims the tree, which fnmatch matched never
        self.assertTrue(rt._is_excluded("tests/fixtures/insecure-js/app.js",
                                        ["tests/fixtures/"]))

    def test_partition_demotes_adapter_with_only_excluded_files(self):
        class _Ad:
            def __init__(self, files):
                self._files = files
            def applicable_files(self, target):
                return [os.path.join(target, f) for f in self._files]
        class _NoFiles:  # lockfile-triggered adapter: stays required
            pass
        # `**`, not `*`: the glob vocabulary is discovery's (#1740 fix round 2).
        adapters = {"eslint-security": _Ad(["tests/fixtures/insecure-js/app.js"]),
                    "with-src": _Ad(["skill/x.js", "tests/fixtures/y.js"]),
                    "osv-scanner": _NoFiles()}
        required, excluded = rt.partition_by_exclusion(
            adapters, "/repo", ["tests/fixtures/**"])
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
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as trusted:
            docker = os.path.join(trusted, "docker")
            with open(docker, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\nexit 99\n")
            os.chmod(docker, 0o700)
            out_dir = os.path.join(d, "out")
            with mock.patch.dict(os.environ, {"PATH": trusted}, clear=False):
                rt.run_tools(d, ["semgrep"], out_dir, image="panopticon-tools",
                             runner=runner)
            docker_bin = os.path.realpath(docker)
            self.assertEqual(len(calls), 1)        # #run7 COD-A2C: clear fail if runner never fired
            cmd0 = calls[0]
            # #run9 OPS-D1A: a --cidfile is injected right after `run` (dynamic temp
            # path) so a hung container can be `docker kill`ed on timeout.
            self.assertEqual(cmd0[:3], [docker_bin, "run", "--cidfile"])
            self.assertTrue(cmd0[3].endswith(os.sep + "cid"))
            # #run8 OPS-D1A: hard resource ceilings sit right after `run --rm`,
            # before the image, so an adversarial target can't exhaust the runner.
            # #run10 SEC-C1A: privilege-drop flags sit with the resource ceilings,
            # before the image, so an attacker-influenced build cannot use Linux
            # capabilities or gain new privileges inside the container.
            # #1877: and the working directory sits with them, so the container
            # starts OUTSIDE the `/src` mount rather than on the image's
            # `WORKDIR /src` -- the target's own tree.
            self.assertEqual(cmd0[4:], (["--rm"] + rt._resource_limit_flags()
                        + rt._privilege_drop_flags()
                        + ["-w", rt.ADAPTER_EMPTY_CWD]
                        + ["--network", "none",
                           "-v", "%s:/src:ro" % os.path.abspath(d),
                           "panopticon-tools"] + rt.TOOL_CMD["semgrep"]))
            self.assertIn("--cap-drop=ALL", cmd0)
            self.assertIn("--security-opt=no-new-privileges", cmd0)
            with open(os.path.join(out_dir, "semgrep.sarif"), "rb") as fh:
                self.assertEqual(fh.read(), fake.stdout)  # runner stdout bytes persisted verbatim

    def test_orphaned_container_is_killed_on_cleanup(self):
        # #run9 OPS-D1A: when the `docker run` CLI proc is still running after the
        # stream ends, cleanup must `docker kill` the container it launched (via the
        # --cidfile) -- proc.kill() alone leaves the --rm container running.
        import types
        killed = []

        class _Proc:
            # stdout EOF immediately, but poll() reports the client STILL alive, so
            # the cleanup branch (proc.kill() + container kill) runs synchronously.
            stdout = types.SimpleNamespace(read=lambda n=-1: b"", close=lambda: None)
            stderr = types.SimpleNamespace(read=lambda: b"", close=lambda: None)
            def kill(self): pass
            def wait(self): return 0
            def poll(self): return None

        with tempfile.TemporaryDirectory() as d:
            cidfile = os.path.join(d, "cid")
            with open(cidfile, "w") as fh:
                fh.write("deadbeefcafe\n")

            def fake_docker(cmd, **kw):
                killed.append((cmd, kw))
                return _FakeResult(returncode=0, stdout=b"", stderr=b"")

            trusted = os.path.join(d, "trusted")
            os.makedirs(trusted)
            docker = os.path.join(trusted, "docker")
            with open(docker, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\nexit 99\n")
            os.chmod(docker, 0o700)
            docker_env = {"PATH": os.path.dirname(docker)}
            with mock.patch.object(rt.subprocess, "run", side_effect=fake_docker):
                rt._stream_and_write("tool", "semgrep", _Proc(),
                                     os.path.join(d, "out.sarif"),
                                     timeout=60, docker_bin=docker, cidfile=cidfile,
                                     docker_env=docker_env)
        self.assertTrue(
            any(c[:2] == [docker, "kill"] and "deadbeefcafe" in c
                and kw["env"] == docker_env for c, kw in killed),
            "container was not `docker kill`ed on cleanup: %r" % killed)

    def test_container_kill_noops_without_a_cidfile(self):
        # No cidfile (non-docker path / container never started) -> no docker kill,
        # no crash.
        import types
        called = []

        class _Proc:
            stdout = types.SimpleNamespace(read=lambda n=-1: b"", close=lambda: None)
            stderr = types.SimpleNamespace(read=lambda: b"", close=lambda: None)
            def kill(self): pass
            def wait(self): return 0
            def poll(self): return None

        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(rt.subprocess, "run",
                                   side_effect=lambda *a, **k: called.append(a)):
                rt._stream_and_write("tool", "semgrep", _Proc(),
                                     os.path.join(d, "out.sarif"), timeout=60)
        self.assertEqual(called, [])

    def test_bandit_pins_a_scanner_owned_ini_whatever_the_target_ships(self):
        # #run7: bandit auto-discovers nested .bandit files (e.g. git worktrees)
        # and ERRORS ("Multiple .bandit files found") -> empty output, silently
        # unproduced -> certification blocked. #1839 (SEC-752508850): the pin is
        # a config the SCANNER generates, and it is unconditional -- pinning the
        # TARGET's copy let the reviewed repo choose bandit's exclude/tests, and
        # pinning nothing when it shipped none left the discovery walk reachable.
        for plant in (True, False):
            calls = []
            fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

            def runner(cmd, _calls=calls, **kw):
                _calls.append(cmd)
                return fake
            with self.subTest(target_has_bandit=plant), \
                    tempfile.TemporaryDirectory() as d:
                if plant:
                    open(os.path.join(d, ".bandit"), "w").close()
                rt.run_tools(d, ["bandit"], os.path.join(d, "out"),
                             image="panopticon-tools", runner=runner)
                self.assertEqual(len(calls), 1)      # run-9 TST-B3A: guard calls[0]
                self.assertIn("--ini", calls[0])
                i = calls[0].index("--ini")
                self.assertEqual(calls[0][i + 1],
                                 "%s/%s" % (rt.BANDIT_INI_MOUNT, rt.BANDIT_INI_NAME))
                self.assertNotIn("/src/.bandit", calls[0])
                self.assertIn("-v", calls[0])
                self.assertIn("%s:ro" % rt.BANDIT_INI_MOUNT,
                              " ".join(calls[0]))    # mounted read-only

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


class TestSemgrepScanCount(unittest.TestCase):
    """#1335: a semgrep whose config carries no rules for the target's languages
    scans 0 files and emits an empty-but-valid SARIF -- indistinguishable, in the
    artifact, from a semgrep that genuinely ran clean. The SARIF has no
    scanned-files signal (`invocations` is just executionSuccessful; the driver's
    rule list is the config's, not what matched), so the only evidence is
    semgrep's stderr. Capture it at run time, when it still exists."""

    def test_parses_the_scanned_file_count_from_stderr(self):
        self.assertEqual(rt._semgrep_scanned_files(b"Ran 412 rules on 0 files.\n"), 0)
        self.assertEqual(rt._semgrep_scanned_files(b"ran 8 rules on 137 files: 2 findings."), 137)
        self.assertEqual(
            rt._semgrep_scanned_files(b"noise\nRan 1 rule on 5 files\nmore noise"), 5)

    def test_absent_or_unrecognised_stderr_yields_no_claim(self):
        # Parsing English stderr is brittle across semgrep versions, so the
        # failure mode must be "no signal", never a fabricated 0 -- a false
        # `noscan` would strip real coverage credit.
        for stderr in (b"", b"Scan completed successfully.", b"Ran rules on files",
                       None, b"Ran 5 rules on many files"):
            self.assertIsNone(rt._semgrep_scanned_files(stderr))

    def test_annotation_injects_the_count_into_the_sarif(self):
        payload = json.dumps({"runs": [{"results": []}]}).encode("utf-8")
        annotated = rt._annotate_scanned_files(payload, 0)
        doc = json.loads(annotated)
        self.assertEqual(doc["runs"][0]["properties"]["panopticon_scanned_files"], 0)
        self.assertEqual(doc["runs"][0]["results"], [], "annotation altered the findings")

    def test_annotation_leaves_unparseable_or_shapeless_output_alone(self):
        for payload in (b"{not json", b"[]", b'{"runs": []}', b'{"runs": [123]}'):
            self.assertEqual(rt._annotate_scanned_files(payload, 0), payload)

    def test_semgrep_capture_annotates_from_its_own_stderr(self):
        # End to end through the real streaming writer: the child prints a SARIF
        # on stdout and semgrep's summary line on stderr.
        child = ("import sys; sys.stderr.write('Ran 400 rules on 0 files.\\n'); "
                 "sys.stdout.write('{\"runs\": [{\"results\": []}]}')")
        proc = rt._popen_runner([sys.executable, "-c", child],
                                stdout=sp.PIPE, stderr=sp.PIPE)
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "semgrep.sarif")
            self.assertEqual(
                rt._stream_and_write("tool", "semgrep", proc, out, timeout=8), out)
            with open(out, encoding="utf-8") as fh:
                doc = json.load(fh)
        self.assertEqual(doc["runs"][0]["properties"]["panopticon_scanned_files"], 0)

    def test_other_tools_are_not_annotated(self):
        child = ("import sys; sys.stderr.write('Ran 400 rules on 0 files.\\n'); "
                 "sys.stdout.write('{\"runs\": [{\"results\": []}]}')")
        proc = rt._popen_runner([sys.executable, "-c", child],
                                stdout=sp.PIPE, stderr=sp.PIPE)
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "bandit.sarif")
            rt._stream_and_write("tool", "bandit", proc, out, timeout=8)
            with open(out, encoding="utf-8") as fh:
                doc = json.load(fh)
        self.assertNotIn("properties", doc["runs"][0])


class TestStreamingRunnerAndDeadline(unittest.TestCase):
    """#run7 COD-A2A / #1111: production must STREAM tool output through the
    bounded sink (not buffer it whole and drop), and the streaming read must be
    bounded by a wall-clock deadline the way subprocess.run's timeout was."""

    def test_default_runner_streams_not_buffers(self):
        # With no runner injected, run_tools uses the streaming _popen_runner
        # (a live Popen), NOT subprocess.run (which buffered all output in memory
        # and always took the drop path -- the #1111 guard was unreachable).
        seen = {}

        def fake_capture(label, tool, docker, out_path, runner, **_kwargs):
            seen["runner"] = runner
            return None

        with mock.patch.object(rt, "_capture_run", side_effect=fake_capture):
            with tempfile.TemporaryDirectory() as d:
                rt.run_tools(d, ["semgrep"], os.path.join(d, "out"))
        self.assertIs(seen["runner"]._panopticon_runner, rt._popen_runner)
        self.assertIsNot(seen["runner"]._panopticon_runner, sp.run)
        self.assertTrue(os.path.isabs(seen["runner"]._panopticon_env["PATH"].split(
            os.pathsep)[0]))

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

    def test_chatty_stderr_does_not_deadlock_the_stdout_capture(self):
        # #1510 (Codex BR-05 = run-11 COD-1902034584): _stream_and_write read
        # stdout to EOF and only THEN proc.stderr.read(). A child that fills the
        # 64KB stderr pipe blocks on write before it ever writes stdout, so the
        # parent waits on stdout the blocked child cannot produce -- deadlock,
        # resolved only by the watchdog burning the whole scan timeout.
        #
        # A real subprocess is mandatory here: a fake stream that returns bytes
        # immediately models no backpressure, so it cannot fail this test.
        child = ("import sys; sys.stderr.write('x' * (2 * 1024 * 1024)); "
                 "sys.stderr.flush(); sys.stdout.write('{}'); sys.stdout.flush()")
        proc = rt._popen_runner([sys.executable, "-c", child],
                                stdout=sp.PIPE, stderr=sp.PIPE)
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stderr(err):
            out = os.path.join(d, "o.sarif")
            written = rt._stream_and_write("tool", "chatty", proc, out, timeout=8)
            self.assertEqual(written, out, "chatty stderr deadlocked the capture")
            with open(out, "rb") as fh:
                self.assertEqual(fh.read(), b"{}")
        self.assertNotIn("timed out", err.getvalue())

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


class TestVirtualenvExclusion(unittest.TestCase):
    """#1638 P09 (D8): keep the scanners out of virtualenvs in the first place.

    The ingest-side filter drops what a scanner reports from a venv; this is the
    other half -- the scanners that expose an exclusion knob are told not to walk
    it at all, and the manifest records what was pruned and why.
    """

    def _venv(self, root, rel, marker=True, shape=True):
        """A virtualenv as a creator leaves one: the marker AND an interpreter.

        #1839: the marker alone is a claim the target can make in one file, so
        `find_virtualenvs` wants the structure too. `shape=False` plants the
        bare marker this fixture used to write.
        """
        os.makedirs(os.path.join(root, rel), exist_ok=True)
        if marker:
            with open(os.path.join(root, rel, "pyvenv.cfg"), "w") as fh:
                fh.write("home = /usr/bin\nversion = 3.12.0\n")
        if shape:
            os.makedirs(os.path.join(root, rel, "bin"), exist_ok=True)
            with open(os.path.join(root, rel, "bin", "python"), "w") as fh:
                fh.write("")

    def test_find_virtualenvs_reports_marker_first_then_name(self):
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, "env")                       # metadata, odd name
            self._venv(d, ".venv")                     # pipenv in-project
            self._venv(d, "venv", marker=False)        # name fallback only
            os.makedirs(os.path.join(d, "src"))        # real source
            self.assertEqual(
                rt.find_virtualenvs(d),
                [{"path": ".venv", "reason": "pyvenv.cfg"},
                 {"path": "env", "reason": "pyvenv.cfg"},
                 {"path": "venv", "reason": "name"}])

    def test_find_virtualenvs_is_depth_bounded(self):
        # Venvs live near the root; an unbounded walk is paid on every scan.
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, os.path.join("a", "b", ".venv"))        # depth 3: found
            self._venv(d, os.path.join("a", "b", "c", ".venv"))   # depth 4: not
            self.assertEqual([v["path"] for v in rt.find_virtualenvs(d)],
                             ["a/b/.venv"])

    def test_find_virtualenvs_does_not_descend_into_one(self):
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, ".venv")
            self._venv(d, os.path.join(".venv", "venv"))
            self.assertEqual([v["path"] for v in rt.find_virtualenvs(d)], [".venv"])

    def test_semgrep_and_trivy_get_their_own_exclusion_knob(self):
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

        def runner(cmd, **kw):
            calls.append(cmd)
            return fake
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, ".venv")
            rt.run_tools(d, ["semgrep", "trivy", "gitleaks"],
                         os.path.join(d, "out"), runner=runner)
            semgrep, trivy, gitleaks = calls
            # Attached form (F7): a directory named `-rf` can never read as a flag.
            self.assertIn("--exclude=.venv", semgrep)
            self.assertEqual(semgrep[-1], "/src")     # the scan target stays last
            self.assertIn("--skip-dirs=.venv", trivy)  # trivy matches root-relative
            self.assertEqual(trivy[-1], "/src")
            # Gitleaks has no path-exclusion flag; the adapter owns its rule
            # config and the ingest filter handles virtualenv paths.
            self.assertEqual(gitleaks[-3:], ["python3",
                             "/opt/panopticon/scripts/_run_adapter.py", "gitleaks"])

    def test_no_venv_means_no_added_flags(self):
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

        def runner(cmd, **kw):
            calls.append(cmd)
            return fake
        with tempfile.TemporaryDirectory() as d:
            rt.run_tools(d, ["semgrep", "bandit"], os.path.join(d, "out"),
                         runner=runner)
            # #1839: bandit's argv carries the scanner-owned `--ini` either way
            # (the #run7 discovery walk must never run), and nothing else.
            expected = {"semgrep": list(rt.TOOL_CMD["semgrep"]),
                        "bandit": list(rt.TOOL_CMD["bandit"][:1])
                        + ["--ini", "%s/%s" % (rt.BANDIT_INI_MOUNT,
                                               rt.BANDIT_INI_NAME)]
                        + list(rt.TOOL_CMD["bandit"][1:])}
            for cmd, tool in zip(calls, ("semgrep", "bandit")):
                self.assertEqual(cmd[-len(expected[tool]):], expected[tool], tool)

    def test_an_option_shaped_directory_name_stays_a_value(self):
        # F7: the attached form is what makes this safe, not the tool's parser.
        cmd = rt._with_venv_excludes(
            "semgrep", list(rt.TOOL_CMD["semgrep"]), [{"path": "-rf", "reason": "name"}])
        self.assertIn("--exclude=-rf", cmd)
        self.assertNotIn("-rf", cmd)

    def test_bandit_excludes_the_marker_detected_dirs_too(self):
        # F3: `.bandit` carries only the NAME spellings, so a venv detected by
        # its `pyvenv.cfg` under another name was excluded for semgrep/trivy and
        # still walked by bandit. bandit has a real `--exclude`, so it joins.
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

        def runner(cmd, **kw):
            calls.append(cmd)
            return fake
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, "env")
            rt.run_tools(d, ["bandit"], os.path.join(d, "out"), runner=runner)
            flag = [a for a in calls[0] if a.startswith("--exclude=")]
            self.assertEqual(len(flag), 1, calls[0])
            entries = flag[0][len("--exclude="):].split(",")
            self.assertIn("/src/env", entries)          # container-side path
            for default in rt.BANDIT_DEFAULT_EXCLUDES:  # never WIDEN the scan
                self.assertIn(default, entries)

    def test_bandit_cli_exclude_is_composed_of_scanner_owned_entries(self):
        # bandit PREFERS a CLI --exclude over its ini's `exclude` rather than
        # merging them, so the flag must carry everything the scan relies on.
        # #1839 (SEC-752508850): "everything" no longer includes the TARGET's
        # own `.bandit` entries -- reading them made the reviewed repository the
        # author of the scan's scope, through the same file that also sets
        # `tests` and `skips`.
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

        def runner(cmd, **kw):
            calls.append(cmd)
            return fake
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, ".venv")
            with open(os.path.join(d, ".bandit"), "w") as fh:
                fh.write("[bandit]\nexclude = /tests,tests,/.worktrees\n")
            rt.run_tools(d, ["bandit"], os.path.join(d, "out"), runner=runner)
            flag = [a for a in calls[0] if a.startswith("--exclude=")]
            entries = flag[0][len("--exclude="):].split(",")
            for entry in rt.BANDIT_SCANNER_EXCLUDES + (".git", "/src/.venv"):
                self.assertIn(entry, entries)
            self.assertNotIn("/tests", entries)     # the target's choice: no
            self.assertIn("--ini", calls[0])        # the ini pin is still there

    def test_a_symlink_out_of_the_target_is_not_a_virtualenv(self):
        # F1: `os.walk` will not DESCEND a symlink, but `isfile` follows one, so
        # a link pointing at a venv outside the target was stat'd and flagged.
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as outside:
            self._venv(outside, "real")
            os.symlink(os.path.join(outside, "real"), os.path.join(d, "linked"))
            os.symlink(os.path.join(outside, "real"), os.path.join(d, ".venv"))
            self.assertEqual(rt.find_virtualenvs(d), [])

    def test_a_symlink_inside_the_target_is_still_a_virtualenv(self):
        # Confinement, not blanket symlink rejection: a link that stays inside
        # the target resolves to a real venv of the target.
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, os.path.join("build", "env"))
            os.symlink(os.path.join(d, "build", "env"), os.path.join(d, "linked"))
            self.assertEqual([v["path"] for v in rt.find_virtualenvs(d)],
                             ["build/env", "linked"])

    def test_manifest_records_excluded_dirs_with_reasons(self):
        with tempfile.TemporaryDirectory() as d:
            payload = rt.write_manifest(
                os.path.join(d, "m.json"), ["semgrep"], [],
                excluded_dirs=[{"path": ".venv", "reason": "pyvenv.cfg"},
                               {"path": "venv", "reason": "name"}])
            # #1740: `skipped` defaults to True, the pre-#1740 meaning of
            # this list, for a caller handing `find_virtualenvs` output in.
            self.assertEqual(payload["excluded_dirs"],
                             [{"path": ".venv", "reason": "pyvenv.cfg",
                               "skipped": True},
                              {"path": "venv", "reason": "name",
                               "skipped": True}])
            # F2: the list is what the SCAN was told to skip, found by a
            # depth-bounded walk -- ingest prunes a superset, at any depth.
            self.assertEqual(payload["depth_bound"], rt.VENV_MAX_DEPTH)
            with open(os.path.join(d, "m.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), payload)

    def test_manifest_records_the_exclude_globs_it_was_given(self):
        # #1740 fix round 1: the committed `exclude_paths:` policy now reaches
        # the scan, so the manifest says which globs this run was handed --
        # beside `excluded_scope` (the adapters those globs disqualified) and
        # `excluded_dirs` (the virtualenvs). Stated on every manifest, `[]`
        # included: absence must not read as "nobody measured".
        with tempfile.TemporaryDirectory() as d:
            payload = rt.write_manifest(os.path.join(d, "m.json"), ["semgrep"], [],
                                        exclude_globs=["tests/fixtures/**"])
            self.assertEqual(payload["exclude_globs"], ["tests/fixtures/**"])
            bare = rt.write_manifest(os.path.join(d, "b.json"), ["semgrep"], [])
            self.assertEqual(bare["exclude_globs"], [])

    def test_main_records_the_exclude_globs_it_was_passed(self):
        with tempfile.TemporaryDirectory() as d:
            manifest = os.path.join(d, "tools-manifest.json")
            with mock.patch.object(rt, "docker_available", return_value=False), \
                    contextlib.redirect_stderr(io.StringIO()):
                rt.main(["--target", d, "--out", os.path.join(d, "out"),
                         "--tools", "semgrep", "--manifest", manifest,
                         "--exclude", "tests/fixtures/**"])
            with open(manifest, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["exclude_globs"],
                                 ["tests/fixtures/**"])

    def test_manifest_records_what_the_sanitizer_dropped(self):
        # #1646 ruling 3: the audit was PARTIAL and the manifest says so.
        block = {"pip-audit": {"source": "requirements.txt", "kept": 2,
                               "dropped": [{"line": "-e .", "reason": "editable"}],
                               "hashes_stripped": True}}
        with tempfile.TemporaryDirectory() as d:
            payload = rt.write_manifest(os.path.join(d, "m.json"), ["pip-audit"],
                                        [], sanitized=block)
            self.assertEqual(payload["sanitized"], block)
            with open(os.path.join(d, "m.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["sanitized"], block)

    def test_manifest_sanitized_defaults_to_empty(self):
        # Stated on every manifest, `{}` included: absence must not be readable
        # as "nobody measured" -- the same rule `excluded_dirs` follows.
        with tempfile.TemporaryDirectory() as d:
            payload = rt.write_manifest(os.path.join(d, "m.json"), ["semgrep"], [])
            self.assertEqual(payload["sanitized"], {})

    def test_collect_sanitization_asks_only_the_adapters_that_answer(self):
        class _Quiet:
            pass

        class _Loud:
            def sanitization_report(self, target):
                return {"source": "requirements.txt", "kept": 1, "dropped": []}

        class _Absent:
            def sanitization_report(self, target):
                return None
        got = rt.collect_sanitization(
            {"semgrep": _Quiet(), "pip-audit": _Loud(), "npm-audit": _Absent()},
            "/repo")
        self.assertEqual(got, {"pip-audit": {"source": "requirements.txt",
                                             "kept": 1, "dropped": []}})

    def test_collect_sanitization_survives_a_crashing_adapter(self):
        class _Boom:
            def sanitization_report(self, target):
                raise OSError("unreadable")
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            self.assertEqual(rt.collect_sanitization({"pip-audit": _Boom()}, "/repo"), {})
        self.assertIn("pip-audit", buf.getvalue())

    def test_main_records_the_sanitizer_disclosure_in_the_manifest(self):
        # Docker absent: the disclosure is a pure filesystem read, so it is
        # faithful on the branch that never launches a scanner -- exactly like
        # `excluded_scope` and `excluded_dirs` beside it.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "requirements.txt"), "w") as fh:
                fh.write("-e .\nok==1\n")
            manifest = os.path.join(d, "tools-manifest.json")
            with mock.patch.object(rt, "docker_available", return_value=False), \
                    contextlib.redirect_stderr(io.StringIO()):
                rt.main(["--target", d, "--out", os.path.join(d, "out"),
                         "--tools", "pip-audit", "--online", "--manifest", manifest])
            with open(manifest, encoding="utf-8") as fh:
                written = json.load(fh)
            self.assertEqual(written["sanitized"]["pip-audit"]["kept"], 1)
            self.assertEqual(written["sanitized"]["pip-audit"]["dropped"],
                             [{"line": "-e .", "reason": "editable"}])

    def test_manifest_excluded_dirs_defaults_to_empty(self):
        with tempfile.TemporaryDirectory() as d:
            payload = rt.write_manifest(os.path.join(d, "m.json"), ["semgrep"], [])
            self.assertEqual(payload["excluded_dirs"], [])
            self.assertEqual(payload["depth_bound"], rt.VENV_MAX_DEPTH)

    def test_main_records_the_detected_venvs_in_the_manifest(self):
        # Docker absent: selection is still faithful, and so is what it pruned.
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, ".venv")
            manifest = os.path.join(d, "tools-manifest.json")
            with mock.patch.object(rt, "docker_available", return_value=False), \
                    contextlib.redirect_stderr(io.StringIO()):
                rt.main(["--target", d, "--out", os.path.join(d, "out"),
                         "--tools", "semgrep", "--manifest", manifest])
            with open(manifest, encoding="utf-8") as fh:
                written = json.load(fh)
            self.assertEqual(written["excluded_dirs"],
                             [{"path": ".venv", "reason": "pyvenv.cfg",
                               "skipped": True}])
            self.assertEqual(written["depth_bound"], rt.VENV_MAX_DEPTH)

    # #1740 (ARC-F2A): the scan side of "no drop on a directory NAME alone".
    # `find_virtualenvs` flags `venv`/`.venv` by name with no `pyvenv.cfg`
    # behind it, and semgrep/trivy/bandit were told to skip it in every mode --
    # so `app/venv/` was a blind spot for three scanners on the very runs whose
    # gate exists to refuse that inference. Under redteam the name-only dirs
    # are SCANNED, and the manifest says so per directory.

    def test_partition_skips_every_venv_under_standard(self):
        dirs = [{"path": ".venv", "reason": "pyvenv.cfg"},
                {"path": "venv", "reason": "name"}]
        skip, rows = rt.partition_venv_dirs(dirs, "standard")
        self.assertEqual(skip, dirs)
        self.assertEqual(rows, [{"path": ".venv", "reason": "pyvenv.cfg",
                                 "skipped": True},
                                {"path": "venv", "reason": "name",
                                 "skipped": True}])

    def test_partition_scans_every_detected_dir_under_redteam(self):
        # #1740 admitted the name-only kind; #1839 ruling 2 admits the
        # marker-confirmed kind for the same reason, one step further on.
        dirs = [{"path": ".venv", "reason": "pyvenv.cfg"},
                {"path": "venv", "reason": "name"}]
        skip, rows = rt.partition_venv_dirs(dirs, "redteam")
        self.assertEqual(skip, [])
        self.assertEqual(rows, [{"path": ".venv", "reason": "pyvenv.cfg",
                                 "skipped": False},
                                {"path": "venv", "reason": "name",
                                 "skipped": False}])

    def test_no_venv_gets_a_scanner_skip_flag_under_redteam(self):
        # The argv is the control: a directory the manifest says was scanned
        # must not appear in any scanner's exclusion knob. #1839 ruling 2: that
        # now holds for the MARKER-confirmed directories too -- a file the
        # target wrote is more attacker-controlled than a name it chose.
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

        def runner(cmd, **kw):
            calls.append(cmd)
            return fake
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, ".venv")                     # marker + shape
            self._venv(d, "venv", marker=False)        # name only
            skip, rows = rt.partition_venv_dirs(rt.find_virtualenvs(d), "redteam")
            self.assertEqual(skip, [])
            self.assertEqual([r["skipped"] for r in rows], [False, False])
            rt.run_tools(d, ["semgrep", "trivy", "bandit"],
                         os.path.join(d, "out"), runner=runner, venv_dirs=skip)
        semgrep, trivy, bandit = calls
        for spelling in (".venv", "venv"):
            self.assertNotIn("--exclude=%s" % spelling, semgrep)
            self.assertNotIn("--skip-dirs=%s" % spelling, trivy)
        # No venv to skip means no bandit --exclude at all; its scanner-owned
        # ini still carries the defaults (see tests/test_run_tools_dispatch.py).
        self.assertEqual([a for a in bandit if a.startswith("--exclude=")], [])

    def test_main_records_which_venvs_the_scan_skipped(self):
        for mode, skipped in (("standard", True), ("redteam", False)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                self._venv(d, "venv", marker=False)
                manifest = os.path.join(d, "tools-manifest.json")
                with mock.patch.object(rt, "docker_available", return_value=False), \
                        contextlib.redirect_stderr(io.StringIO()):
                    rt.main(["--target", d, "--out", os.path.join(d, "out"),
                             "--tools", "semgrep", "--manifest", manifest,
                             "--security", mode])
                with open(manifest, encoding="utf-8") as fh:
                    written = json.load(fh)
                self.assertEqual(written["excluded_dirs"],
                                 [{"path": "venv", "reason": "name",
                                   "skipped": skipped}])

    def test_main_hands_the_scanners_only_the_dirs_it_skips(self):
        captured = {}

        def fake_run_tools(target, tools, out, **kw):
            captured.update(kw)
            return []
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, ".venv")
            self._venv(d, "venv", marker=False)
            with mock.patch.object(rt, "docker_available", return_value=True), \
                    mock.patch.object(rt, "run_tools", side_effect=fake_run_tools), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rt.main(["--target", d, "--out", os.path.join(d, "out"),
                         "--tools", "semgrep", "--security", "redteam"])
        self.assertEqual(captured["venv_dirs"], [])   # #1839 ruling 2

    def test_the_default_mode_is_standard(self):
        # Under `standard` nothing changes: both spellings stay out of the scan.
        captured = {}

        def fake_run_tools(target, tools, out, **kw):
            captured.update(kw)
            return []
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, "venv", marker=False)
            with mock.patch.object(rt, "docker_available", return_value=True), \
                    mock.patch.object(rt, "run_tools", side_effect=fake_run_tools), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                rt.main(["--target", d, "--out", os.path.join(d, "out"),
                         "--tools", "semgrep"])
        self.assertEqual(captured["venv_dirs"],
                         [{"path": "venv", "reason": "name"}])

    def test_bandit_config_excludes_both_venv_spellings(self):
        import configparser
        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(REPO_ROOT, ".bandit"))
        excludes = [x.strip() for x in cfg["bandit"]["exclude"].split(",")]
        for entry in ("/.venv", ".venv", "/venv", "venv"):
            self.assertIn(entry, excludes)

    # Ruling 3's five manifests, and the adapters that key on each. poetry.lock
    # and uv.lock select no adapter today -- trivy reads them from its own root
    # scan, which the venv skip-dir never covers.
    _DEP_MARKERS = {"requirements.txt": ("pip-audit", "osv-scanner"),
                    "pyproject.toml": ("pip-audit", "osv-scanner"),
                    "Pipfile.lock": ("osv-scanner",),
                    "poetry.lock": (),
                    "uv.lock": ()}

    def test_every_python_manifest_survives_beside_an_excluded_venv(self):
        # Ruling 3: the exclusion covers the venv TREE and nothing at the root.
        for marker, adapters in sorted(self._DEP_MARKERS.items()):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as d:
                self._venv(d, ".venv")
                for where in (d, os.path.join(d, ".venv")):
                    with open(os.path.join(where, marker), "w") as fh:
                        fh.write("")
                venvs = rt.find_virtualenvs(d)
                self.assertEqual([v["path"] for v in venvs], [".venv"])
                globs = ["%s/*" % v["path"] for v in venvs]
                self.assertFalse(rt._is_excluded(marker, globs))       # root: audited
                self.assertTrue(rt._is_excluded(".venv/" + marker, globs))  # copy: not
                # The scanners are told to skip the venv, never the root.
                skips = rt._with_venv_excludes("trivy", list(rt.TOOL_CMD["trivy"]), venvs)
                self.assertEqual([a for a in skips if a.startswith("--skip-dirs=")],
                                 ["--skip-dirs=.venv"])
                selected = rt.select_adapters(d)
                for name in adapters:
                    self.assertIn(name, selected, marker)

    def test_the_manifest_survival_check_is_not_vacuous(self):
        # MUTATION: exclude the PARENT instead of the venv and every assertion
        # above must go red -- proof the check can fail at all.
        for marker in sorted(self._DEP_MARKERS):
            with self.subTest(marker=marker):
                self.assertTrue(rt._is_excluded(marker, ["*"]))
                self.assertTrue(rt._is_excluded(marker, ["*/%s" % marker, marker]))


class TestATargetFileCannotNarrowTheScan(unittest.TestCase):
    """run-14 SEC-1486247143 (#1839): the reviewed repo does not choose what the
    scanners look at.

    Three target-authored levers, all on the path CI's merge gate runs
    (`run_tools.py` -> `security_gate.py`, with no agentic axis to compensate):
    a planted `pyvenv.cfg`, a directory named with a glob metacharacter, and --
    in the sibling class in tests/test_run_tools_dispatch.py -- a committed
    `.bandit`. Every assertion here is on the ARGV, because that is the only
    place the narrowing was visible.
    """

    def _plant(self, root):
        """The reproduction probe's tree: the repo's real source under a planted
        marker file, plus a directory literally named `*` that IS a virtualenv
        by shape -- so only the metacharacter keeps it out of the knobs."""
        os.makedirs(os.path.join(root, "src"))
        with open(os.path.join(root, "src", "app.py"), "w") as fh:
            fh.write("import os\n")
        for rel in ("src", "*"):
            os.makedirs(os.path.join(root, rel), exist_ok=True)
            with open(os.path.join(root, rel, rt.VENV_MARKER), "w") as fh:
                fh.write("home = /usr\n")
        os.makedirs(os.path.join(root, "*", "bin"))
        with open(os.path.join(root, "*", "bin", "python"), "w") as fh:
            fh.write("")

    def test_a_bare_marker_beside_real_source_is_not_a_virtualenv(self):
        # One committed file removed `src/` from three scanners. A virtualenv
        # has a SHAPE as well as a marker; a marker alone is a claim.
        with tempfile.TemporaryDirectory() as d:
            self._plant(d)
            found = {v["path"]: v["reason"] for v in rt.find_virtualenvs(d)}
        self.assertEqual(found["src"], rt.VENV_MARKER_NO_SHAPE)
        self.assertEqual(found["*"], rt.VENV_MARKER)

    def test_the_walk_still_descends_a_directory_it_would_not_skip(self):
        # `src/` is scanned, so a REAL venv inside it must still be found --
        # the old code stopped walking at anything it flagged.
        with tempfile.TemporaryDirectory() as d:
            self._plant(d)
            os.makedirs(os.path.join(d, "src", ".venv", "bin"))
            for rel in (os.path.join("src", ".venv", rt.VENV_MARKER),
                        os.path.join("src", ".venv", "bin", "python")):
                with open(os.path.join(d, rel), "w") as fh:
                    fh.write("")
            found = {v["path"]: v["reason"] for v in rt.find_virtualenvs(d)}
        self.assertEqual(found["src/.venv"], rt.VENV_MARKER)

    def test_neither_plant_is_handed_to_a_scanner_in_either_mode(self):
        for mode in rt.SECURITY_MODES:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                self._plant(d)
                skip, rows = rt.partition_venv_dirs(rt.find_virtualenvs(d), mode)
                self.assertEqual([e["path"] for e in skip], [])
                by_path = {r["path"]: r for r in rows}
                # NAMED, not silently absent: a directory nobody can express as
                # an exclusion must be scanned AND disclosed.
                self.assertFalse(by_path["src"]["skipped"])
                self.assertFalse(by_path["*"]["skipped"])
                self.assertIn(rt.VENV_MARKER, by_path["src"]["note"])
                self.assertIn("exclusion", by_path["*"]["note"])

    def test_no_scanner_is_ever_handed_a_glob_pattern(self):
        # `--exclude` and `--skip-dirs` take GLOBS, so a directory named `*`
        # was "skip the whole tree" -- the attached `--flag=value` form (#1638
        # P09 F7) stops an OPTION, not a pattern.
        dirs = [{"path": "*", "reason": rt.VENV_MARKER},
                {"path": "lib[0]", "reason": "name"},
                {"path": "q?", "reason": rt.VENV_MARKER},
                {"path": ".venv", "reason": rt.VENV_MARKER}]
        for tool, flag in (("semgrep", "--exclude="), ("trivy", "--skip-dirs=")):
            cmd = rt._with_venv_excludes(tool, list(rt.TOOL_CMD[tool]), dirs)
            self.assertEqual([a for a in cmd if a.startswith(flag)],
                             ["%s.venv" % flag], tool)
        cmd = rt._with_venv_excludes("bandit", list(rt.TOOL_CMD["bandit"]), dirs)
        entries = [a for a in cmd if a.startswith("--exclude=")][0]
        entries = entries[len("--exclude="):].split(",")
        self.assertIn("/src/.venv", entries)
        for planted in ("/src/*", "/src/lib[0]", "/src/q?"):
            self.assertNotIn(planted, entries)

    def test_a_marker_confirmed_virtualenv_is_scanned_under_redteam(self):
        # #1740 ruled that under redteam a finding may not be lost to a
        # directory NAME. A file the same target WROTE is more
        # attacker-controlled than a name, not less.
        skip, rows = rt.partition_venv_dirs(
            [{"path": ".venv", "reason": rt.VENV_MARKER}], "redteam")
        self.assertEqual(skip, [])
        self.assertEqual(rows, [{"path": ".venv", "reason": rt.VENV_MARKER,
                                 "skipped": False}])

    def test_a_real_virtualenv_is_still_skipped_under_standard(self):
        # The #1638 P09 cost saving stands where the target is not the threat --
        # and the manifest row is what `security_gate` reads back to say so.
        skip, rows = rt.partition_venv_dirs(
            [{"path": ".venv", "reason": rt.VENV_MARKER},
             {"path": "venv", "reason": "name"}], "standard")
        self.assertEqual([e["path"] for e in skip], [".venv", "venv"])
        self.assertEqual(rows, [{"path": ".venv", "reason": rt.VENV_MARKER,
                                 "skipped": True},
                                {"path": "venv", "reason": "name",
                                 "skipped": True}])

    def test_the_manifest_carries_the_note_for_a_directory_it_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            _skip, rows = rt.partition_venv_dirs(
                [{"path": "*", "reason": rt.VENV_MARKER}], "standard")
            payload = rt.write_manifest(os.path.join(d, "m.json"), ["semgrep"],
                                        [], excluded_dirs=rows)
        row = payload["excluded_dirs"][0]
        self.assertFalse(row["skipped"])
        self.assertIn("exclusion", row["note"])

    def test_the_probe_tree_reaches_every_scanner_in_both_modes(self):
        # End to end: `main`'s partition feeding the dispatch argv, which is
        # what CI runs. The reproduction was `--exclude=*` plus `--exclude=src`.
        for mode in rt.SECURITY_MODES:
            calls = []
            fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

            def runner(cmd, _calls=calls, **kw):
                _calls.append(cmd)
                return fake
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                self._plant(d)
                skip, _rows = rt.partition_venv_dirs(rt.find_virtualenvs(d), mode)
                rt.run_tools(d, ["semgrep", "trivy", "bandit"],
                             os.path.join(d, "out"), runner=runner, venv_dirs=skip)
            for cmd in calls:
                for arg in cmd:
                    self.assertNotIn(arg, ("--exclude=*", "--exclude=src",
                                           "--skip-dirs=*", "--skip-dirs=src"))
                for arg in [a for a in cmd if a.startswith("--exclude=")]:
                    for entry in arg[len("--exclude="):].split(","):
                        self.assertNotIn(entry, ("/src/*", "/src/src"))


class TestRawCaptureRedaction(unittest.TestCase):
    """#1639 P11: the raw captures under `.panopticon/tools/` are what an operator
    copies into a CI artifact, and nothing redacted them -- the report's pass
    (`redact.redact_tree`, #1634) runs over the REPORT tree and never touches
    these files. Every write path now goes through ONE choke point,
    `_redact_capture`, immediately before `_atomic_write`.

    The marker is `ghp_` + 36 token characters: a shape `scripts/redact.py`
    ALREADY masks, so a survival here is a wiring defect and never a pattern-set
    gap (that is #1572). Not a credential -- 'A'*29 is not a secret.
    """

    MARKER = "ghp_" + "CAPTURE" + "A" * 29
    GOLDENS = os.path.join(REPO_ROOT, "tests", "goldens", "tool-raw")

    def _sarif(self, secret):
        """A gitleaks-shaped SARIF carrying `secret` in the two places a secret
        scanner puts one: the result message and the snippet."""
        return json.dumps({"runs": [{
            "tool": {"driver": {"name": "gitleaks", "rules": [
                {"id": "github-pat"}]}},
            "results": [{
                "ruleId": "github-pat", "level": "error",
                "message": {"text": "github-pat detected: %s" % secret},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "app/settings.py"},
                    "region": {"startLine": 7,
                               "snippet": {"text": "TOKEN = '%s'" % secret}}}}],
            }]}]}).encode("utf-8")

    def _stream(self, payload, tool="gitleaks", out_name="gitleaks.sarif"):
        """Drive the REAL streaming writer over a child that prints `payload`.
        python3 (never a scanner binary, never docker) -- same seam the semgrep
        annotation tests use."""
        child = "import sys; sys.stdout.buffer.write(%r)" % payload
        proc = rt._popen_runner([sys.executable, "-c", child],
                                stdout=sp.PIPE, stderr=sp.PIPE)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        out = os.path.join(d, out_name)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                rt._stream_and_write("tool", tool, proc, out, timeout=30), out)
        with open(out, "rb") as fh:
            return fh.read()

    def test_completed_path_redacts(self):
        """`_write_completed`: the CompletedProcess runner (Codex's repro --
        `_write_completed` saved a credential-shaped value verbatim)."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        out = os.path.join(d, "gitleaks.sarif")
        res = _FakeResult(returncode=1, stdout=self._sarif(self.MARKER))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(rt._write_completed("tool", "gitleaks", res, out), out)
        with open(out, "rb") as fh:
            written = fh.read()
        self.assertNotIn(self.MARKER.encode(), written)
        self.assertIn(b"[REDACTED_TOKEN]", written)

    def test_streamed_path_redacts(self):
        written = self._stream(self._sarif(self.MARKER))
        self.assertNotIn(self.MARKER.encode(), written)
        self.assertIn(b"[REDACTED_TOKEN]", written)

    def test_streamed_path_redacts_after_its_stderr_annotation(self):
        """semgrep's capture is rewritten by `_annotate_from_stderr` on the way
        out; the choke point sits after it, so the annotator can never reopen
        the hole."""
        payload = json.dumps({"runs": [{"results": [], "tool": {"driver": {
            "name": "semgrep"}}}], "leak": self.MARKER}).encode("utf-8")
        written = self._stream(payload, tool="semgrep", out_name="semgrep.sarif")
        self.assertNotIn(self.MARKER.encode(), written)
        self.assertIn(b"[REDACTED_TOKEN]", written)

    def test_truncated_path_redacts_the_retained_prefix(self):
        """The over-cap branch keeps the first MAX_TOOL_OUTPUT_BYTES and appends
        a marker; the retained prefix is redacted too."""
        payload = self._sarif(self.MARKER) + b"z" * 4000
        with mock.patch.object(rt, "MAX_TOOL_OUTPUT_BYTES", 1200):
            written = self._stream(payload)
        self.assertIn(b"TRUNCATED", written)
        self.assertNotIn(self.MARKER.encode(), written)
        self.assertIn(b"[REDACTED_TOKEN]", written)

    def test_every_write_path_goes_through_the_choke_point(self):
        """Structural, over the AST: every `_atomic_write` call in run_tools.py
        names `_redact_capture` INLINE in the data it hands over. A fourth
        capture path added later cannot land unredacted, and the check reads the
        tree rather than the text -- a grep passes on a call that merely
        mentions the name in a comment or a string.

        Scope, stated so it is not mistaken for more than it is: this guards
        CAPTURE writes, not the tools directory. `write_manifest` writes
        `tools-manifest.json` into the same out-dir with a plain `open()`, and
        deliberately does not go through the choke point -- its payload is
        controller-composed (tool names, produced paths, `run_id`, the
        virtualenv rows the runner's own walk found, `redacted`), never scanner
        text, and `json.dump` escapes any control character a hostile directory
        name could carry, so it needs neither redaction nor `_prompt_safe`
        (which exists to protect PROMPT-LINE structure, and nothing interpolates
        these rows into a prompt). Nor does the directory-walk guard below reach
        it: the driver points `--manifest` at `.panopticon/tools-manifest.json`,
        a sibling of the captures directory rather than a file inside it. If the
        manifest ever starts carrying scanner-derived text, it needs the choke
        point and a guard of its own.
        """
        import ast
        with open(os.path.join(REPO_ROOT, "skill", "scripts", "run_tools.py"),
                  encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == "_atomic_write"]
        self.assertTrue(calls, "no _atomic_write call sites found -- guard is vacuous")
        unguarded = []
        for call in calls:
            # Inline anywhere in the data expression: the truncation path is
            # `_redact_capture(...) + marker`, because the marker is appended
            # AFTER the pass.
            data = call.args[1] if len(call.args) > 1 else None
            redacted = data is not None and any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "_redact_capture" for n in ast.walk(data))
            if not redacted:
                unguarded.append(call.lineno)
        self.assertEqual(unguarded, [],
                         "unredacted _atomic_write at lines %s" % unguarded)

    def test_run_tools_leaves_no_marker_anywhere_in_the_out_dir(self):
        """The guard by construction: walk everything a run drops in the tools
        directory rather than naming the files, so a future capture path is
        covered without remembering to extend this test."""
        payload = self._sarif(self.MARKER)

        def runner(cmd, **kw):
            return _FakeResult(returncode=0, stdout=payload)

        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        out_dir = os.path.join(d, "tools")
        with contextlib.redirect_stderr(io.StringIO()):
            written = rt.run_tools(d, ["gitleaks", "semgrep", "osv-scanner"],
                                   out_dir, runner=runner)
        self.assertEqual(len(written), 3, written)   # non-vacuous: files exist
        leaked = []
        for root, _dirs, files in os.walk(out_dir):
            for name in sorted(files):
                path = os.path.join(root, name)
                with open(path, "rb") as fh:
                    if self.MARKER.encode() in fh.read():
                        leaked.append(name)
        self.assertEqual(leaked, [], "raw capture kept the marker: %s" % leaked)

    # #1572: the ONE golden a rule legitimately fires on, and exactly what it
    # does to it. pip-audit's capture embeds a CVE advisory about
    # `Proxy-Authorization` leaks, which quotes `https://username:password@proxy:8080`
    # as the shape it is describing. That is a well-formed credential URL, and
    # the URL-userinfo rule masks its password -- correctly: a redactor cannot
    # know that this particular password is the literal word "password".
    #
    # Pinned as a SUBSTITUTION rather than by exempting the file, because the
    # claim this test exists to make is about STRUCTURE. The change is one
    # substring inside one JSON string value; every `ruleId`, `location`,
    # `region` and `level` in the document is still byte-identical, which is
    # what the assertion below now says for this golden and says by identity
    # for the other fourteen.
    EXPECTED_MASKS = {
        "pip-audit.raw": (b"https://username:password@proxy:8080",
                          b"https://username:[REDACTED]@proxy:8080"),
    }

    def test_clean_goldens_are_byte_identical(self):
        """Ruling 1: redaction never changes SARIF STRUCTURE. Every committed
        real-scanner golden -- 15 tools, SARIF, JSON and XML -- comes back
        byte-for-byte through the choke point, so `ruleId`, `locations`,
        `region` line numbers and `level` are provably untouched on output that
        carries no secret -- and, for the one golden that does carry a
        credential shape, changed by exactly the one substitution named in
        EXPECTED_MASKS and nothing else."""
        names = sorted(n for n in os.listdir(self.GOLDENS) if n.endswith(".raw"))
        self.assertIn("gitleaks.raw", names)
        self.assertGreaterEqual(len(names), 15, names)
        self.assertLessEqual(set(self.EXPECTED_MASKS), set(names),
                             "EXPECTED_MASKS names a golden that is gone")
        changed = []
        for name in names:
            with open(os.path.join(self.GOLDENS, name), "rb") as fh:
                raw = fh.read()
            want = raw
            if name in self.EXPECTED_MASKS:
                before, after = self.EXPECTED_MASKS[name]
                self.assertIn(before, raw, "%s no longer carries the specimen "
                              "EXPECTED_MASKS is about" % name)
                want = raw.replace(before, after)
            if rt._redact_capture(name[:-4], raw) != want:
                changed.append(name)
        self.assertEqual(changed, [], "redaction rewrote a clean golden: %s" % changed)


class TestCaptureRedactionKeepsEveryFinding(unittest.TestCase):
    """#1639 P11 fix round 1 (F1): a flat regex pass over a whole JSON capture
    is not structure-safe. Every pattern in `scripts/redact.py` is anchored to a
    character class that excludes `"` -- except the PEM rule, which was `.*?`
    under DOTALL. A capture whose first BEGIN has no END of its own (the
    committed gitleaks golden quotes exactly that: a truncated key snippet) runs
    on until a LATER result's snippet supplies one, and everything in between --
    whole results, their rule ids and their locations -- collapses into one
    token. The output is still valid JSON, so ingest parses it happily and
    simply reports fewer findings, the survivor carrying somebody else's
    location.
    """

    TOKEN = "ghp_" + "POC" + "C" * 33

    def _capture(self):
        """The reviewer's four-result PoC: an unterminated BEGIN in result 2 and
        the END that closes it in result 4, with an unrelated result between."""
        def result(rule, uri, line, snippet):
            return {"ruleId": rule, "level": "error",
                    "message": {"text": "%s detected in %s" % (rule, uri)},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": line,
                                   "snippet": {"text": snippet}}}}]}
        return json.dumps({"runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [
                result("generic-api-key", "a/one.env", 1,
                       "TOKEN=%s" % self.TOKEN),
                result("private-key", "b/two.pem", 2,
                       pem_begin() + "\nMIIBsomekey\n"),
                result("aws-access-token", "c/three.py", 3, "harmless"),
                result("private-key", "d/four.pem", 9,
                       "AB12cd==\n" + pem_end()),
            ]}]}).encode("utf-8")

    def test_no_finding_is_lost_and_no_location_is_re_attributed(self):
        doc = json.loads(rt._redact_capture("gitleaks", self._capture()))
        runs = doc["runs"]
        self.assertEqual(len(runs), 1)
        results = runs[0]["results"]
        self.assertEqual(len(results), 4, "results were swallowed: %s" % results)
        self.assertEqual([r["ruleId"] for r in results],
                         ["generic-api-key", "private-key", "aws-access-token",
                          "private-key"])
        self.assertEqual(
            [(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
              r["locations"][0]["physicalLocation"]["region"]["startLine"])
             for r in results],
            [("a/one.env", 1), ("b/two.pem", 2), ("c/three.py", 3),
             ("d/four.pem", 9)])

    def test_the_secrets_in_that_capture_are_still_masked(self):
        out = rt._redact_capture("gitleaks", self._capture())
        self.assertNotIn(self.TOKEN.encode(), out)
        self.assertIn(b"[REDACTED_TOKEN]", out)

    def test_a_non_json_capture_keeps_the_lines_around_a_pem(self):
        """The XML/plain-text fallback (spotbugs is the one non-JSON golden).
        A complete block spanning lines is still masked -- and an unterminated
        BEGIN earlier in the file no longer eats the records between them."""
        raw = ('<BugInstance type="ONE" file="app/a.java"/>\n'
               '<Snippet>%s\nMIIBtruncated</Snippet>\n'
               '<BugInstance type="TWO" file="app/b.java"/>\n'
               '<Snippet>%s</Snippet>\n'
               % (pem_begin(), fake_pem("MIIBrealkey"))).encode()
        out = rt._redact_capture("spotbugs", raw)
        self.assertIn(b'<BugInstance type="TWO" file="app/b.java"/>', out)
        self.assertIn(b"[REDACTED_PRIVATE_KEY]", out)
        self.assertNotIn(b"MIIBrealkey", out)

    def test_a_non_json_capture_masks_a_pem_quoted_from_source(self):
        """Round 2 N1: a scanner snippet that quotes a key out of C/Java/older-
        Python source -- one double-quoted literal per PEM line -- is the shape
        the round-1 `[^"]` bound stopped masking. The flat pass is what an XML
        capture gets, so the pattern itself has to cover it."""
        raw = ('<BugInstance type="HARDCODED_KEY" file="app/Crypto.java"/>\n'
               '<Snippet>KEY = ("%s\\n"\n'
               '       "MIIEpAIBAAKCAQEAxLEAKEDKEYBODY0123456789abcdef\\n"\n'
               '       "%s");</Snippet>\n'
               % (pem_begin(), pem_end())).encode()
        out = rt._redact_capture("spotbugs", raw)
        self.assertIn(b"[REDACTED_PRIVATE_KEY]", out)
        self.assertNotIn(b"MIIEpAIBAAKCAQEAxLEAKEDKEYBODY", out)
        self.assertIn(b'<BugInstance type="HARDCODED_KEY" file="app/Crypto.java"/>',
                      out)

    def test_a_json_capture_keeps_its_own_formatting(self):
        """Re-serialization is only reached when redaction fired, and it keeps
        the producer's own layout where that is recognisable -- so a capture
        diffed across two runs shows the masked value, not a reformatting of
        every line."""
        doc = {"runs": [{"results": [{"ruleId": "x",
                                      "message": {"text": self.TOKEN}}]}]}
        for style in ({"indent": 1}, {"indent": 2}, {}, {"separators": (",", ":")}):
            raw = json.dumps(doc, **style).encode("utf-8")
            out = rt._redact_capture("gitleaks", raw).decode("utf-8")
            with self.subTest(style=style):
                self.assertNotIn(self.TOKEN, out)
                self.assertEqual(
                    out, json.dumps(json.loads(out), **style),
                    "re-serialized in a different layout than the capture's")


class TestTruncationDoesNotHalfKeepASecret(unittest.TestCase):
    """#1639 P11 fix round 1 (F2): the byte cap is measured on the RAW stream
    (ruling 4 -- it is the only count that bounds memory), so it can land in the
    middle of a token, and the length-anchored pattern no longer matches the
    fragment left behind. Scanner output is line-oriented, so dropping back to
    the last newline before the cap drops the partial value instead of keeping
    half of it."""

    TOKEN = "ghp_" + "CUT" + "Q" * 33

    def _stream(self, payload, cap):
        child = "import sys; sys.stdout.buffer.write(%r)" % payload
        proc = rt._popen_runner([sys.executable, "-c", child],
                                stdout=sp.PIPE, stderr=sp.PIPE)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        out = os.path.join(d, "gitleaks.sarif")
        with contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(rt, "MAX_TOOL_OUTPUT_BYTES", cap):
            self.assertEqual(
                rt._stream_and_write("tool", "gitleaks", proc, out, timeout=30), out)
        with open(out, "rb") as fh:
            return fh.read()

    def test_a_token_split_by_the_cap_is_dropped_not_half_kept(self):
        head = b"keep this whole line\n"
        payload = head + b"TOKEN=" + self.TOKEN.encode() + b"\nzzzz\n"
        # Land the cap ten characters into the token.
        written = self._stream(payload, len(head) + len("TOKEN=") + 10)
        self.assertIn(b"keep this whole line", written)
        self.assertIn(b"TRUNCATED", written)
        self.assertNotIn(b"ghp_", written)

    def test_a_capture_with_no_line_break_keeps_its_prefix(self):
        """The trim must never empty a file: single-line output (a compact
        SARIF) has no newline to fall back to, so the prefix is kept as it was
        and the fragment risk is what the marker comment documents."""
        payload = b"x" * 400
        written = self._stream(payload, 100)
        self.assertIn(b"TRUNCATED", written)
        self.assertTrue(written.startswith(b"x" * 100), written[:120])
        self.assertFalse(written.startswith(b"x" * 101), written[:120])

    def test_the_trim_never_discards_a_long_last_line(self):
        """A capture that is one newline followed by an enormous single line
        must not be trimmed back to that first newline -- a line that long is
        not line-oriented output, and the retained evidence matters more than
        the fragment. Bounded by `_TRUNCATE_TRIM_MAX`, so the test is written
        against the constant rather than a number that could drift past it."""
        body = b"y" * (rt._TRUNCATE_TRIM_MAX + 5000)
        written = self._stream(b"{\n" + body, rt._TRUNCATE_TRIM_MAX + 2000)
        self.assertIn(b"TRUNCATED", written)
        self.assertGreater(written.count(b"y"), rt._TRUNCATE_TRIM_MAX)


class TestTheManifestReportsTheRedactionPass(unittest.TestCase):
    """#1639 P11 fix round 1 (F5): `tools-ran.json`'s `redacted` claim used to
    be a literal in the phase module asserting another module's behaviour. The
    runner reports what it actually did -- `_redact_capture` records each
    capture it passes, `write_manifest` publishes it, and the phase copies the
    answer instead of restating it."""

    TOKEN = "ghp_" + "MANIFEST" + "M" * 28

    def _run(self, d, patch_identity=False):
        payload = json.dumps({"runs": [{"results": [
            {"ruleId": "r", "message": {"text": self.TOKEN}}]}]}).encode()

        def runner(cmd, **kw):
            return _FakeResult(returncode=0, stdout=payload)

        out_dir = os.path.join(d, "tools")
        ctx = (mock.patch.object(rt, "_redact_capture", lambda tool, data: data)
               if patch_identity else contextlib.nullcontext())
        with contextlib.redirect_stderr(io.StringIO()), ctx:
            written = rt.run_tools(d, ["gitleaks", "semgrep"], out_dir, runner=runner)
        return rt.write_manifest(os.path.join(d, "tools-manifest.json"),
                                 ["gitleaks", "semgrep"], written)

    def test_a_run_through_the_choke_point_claims_the_pass(self):
        with tempfile.TemporaryDirectory() as d:
            payload = self._run(d)
        self.assertEqual(payload["produced"], ["gitleaks", "semgrep"])
        self.assertIs(payload["redacted"], True)

    def test_bypassing_the_choke_point_makes_the_claim_go_false(self):
        """The coupling: with the redactor replaced by identity the captures are
        written unmasked, and the artifact says so rather than repeating a
        literal `true` nobody checked."""
        with tempfile.TemporaryDirectory() as d:
            payload = self._run(d, patch_identity=True)
            with open(os.path.join(d, "tools", "gitleaks.sarif"), "rb") as fh:
                self.assertIn(self.TOKEN.encode(), fh.read())   # non-vacuous
        self.assertEqual(payload["produced"], ["gitleaks", "semgrep"])
        self.assertIs(payload["redacted"], False)

    def test_no_capture_written_makes_no_claim(self):
        # The docker-absent manifest (produced=[]): nothing was written, so
        # there is nothing to vouch for.
        with tempfile.TemporaryDirectory() as d:
            payload = rt.write_manifest(os.path.join(d, "m.json"),
                                        ["gitleaks"], [])
        self.assertIs(payload["redacted"], False)


class TestEslintFileCoverageCapture(unittest.TestCase):
    def test_invalid_eslint_captures_discard_parser_text_and_still_fail_ingestion(self):
        from scripts import ingest_tools, security_gate
        sentinel = "PRIVATE_SOURCE_SENTINEL"
        fatal = {"filePath": "/src/bad.js", "fatalErrorCount": 1,
                 "source": sentinel, "output": sentinel,
                 "messages": [{"ruleId": None, "fatal": True,
                               "message": "Parsing error: " + sentinel}]}
        documents = [
            {"panopticon_eslint": {"version": 1, "typescript_parser": "unavailable",
                                  "files": [], "files_count": -1}, "results": [fatal]},
            [fatal, {"filePath": "/src/neighbor.js", "messages": "invalid"}],
            [None, fatal],
        ]
        raw_cases = [json.dumps(doc).encode() for doc in documents]
        raw_cases.append(json.dumps([fatal]).encode()[:-1])  # truncated native JSON
        for raw in raw_cases:
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as target:
                cleaned = rt._redact_capture("eslint-security", raw)
                self.assertNotIn(sentinel.encode(), cleaned)
                with self.assertRaises(ValueError):
                    EslintSecurityAdapter().parse(cleaned, "g1")
                capture = os.path.join(target, "eslint-security.json")
                with open(capture, "wb") as fh:
                    fh.write(cleaned)
                findings, dispositions = ingest_tools.ingest_dir_detailed(target, "g1")
                self.assertEqual(findings, [])
                self.assertEqual(dispositions["eslint-security"]["status"], "failed")
                self.assertNotIn(sentinel, json.dumps(dispositions))
                # Use a separate subdirectory so the manifest is never scanner input.
                tools = os.path.join(target, "tools")
                os.mkdir(tools)
                moved = os.path.join(tools, "eslint-security.json")
                os.rename(capture, moved)
                manifest = os.path.join(target, "manifest.json")
                payload = rt.write_manifest(manifest, ["eslint-security"], [moved])
                self.assertEqual(payload["file_coverage"], {})
                _, _, failures, _, _ = security_gate.evaluate(tools, manifest)
                self.assertTrue(failures)

    def test_missing_parser_envelope_survives_runner_and_ingestion(self):
        from scripts import ingest_tools, run_tools
        document = {"panopticon_eslint": {"version": 1, "typescript_parser": "unavailable",
                     "files_count": 1, "files": ["nested/app.ts"]}, "results": []}
        raw = run_tools._redact_capture("eslint-security", json.dumps(document).encode())
        with tempfile.TemporaryDirectory() as target:
            capture = os.path.join(target, "eslint-security.json")
            manifest = os.path.join(target, "manifest.json")
            with open(capture, "wb") as fh:
                fh.write(raw)
            findings, dispositions = ingest_tools.ingest_dir_detailed(target, "g1")
            run_tools.write_manifest(manifest, ["eslint-security"], [capture])
            with open(manifest) as fh:
                payload = json.load(fh)
        facts = dispositions["eslint-security"]["file_coverage"]
        self.assertEqual(findings, [])
        self.assertEqual((facts["parsed_files"], facts["unavailable_files"]), (0, 1))
        self.assertEqual(facts["files"], [{"file": "nested/app.ts", "reason": "typescript_parser_unavailable"}])
        self.assertEqual(payload["file_coverage"]["eslint-security"], facts)

    def test_manifest_and_redacted_capture_keep_only_safe_parser_facts(self):
        from scripts import run_tools
        from scripts.tools.eslint_security import EslintSecurityAdapter
        payload = [
            {"filePath": "/src/good.js", "messages": [{"ruleId": "security/detect-eval-with-expression",
             "message": "eval with expression", "line": 1}]},
            {"filePath": "/src/bad.js", "fatalErrorCount": 1,
             "source": "private source text", "output": "private source text",
             "messages": [{"ruleId": None, "fatal": True, "message": "Parsing error: private source text"}]},
        ]
        raw = run_tools._redact_capture("eslint-security", json.dumps(payload).encode())
        self.assertNotIn(b"private source text", raw)
        findings, facts = EslintSecurityAdapter().parse_with_file_coverage(raw, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(facts["unparsed_files"], 1)
        with tempfile.TemporaryDirectory() as target:
            capture = os.path.join(target, "eslint-security.json")
            manifest = os.path.join(target, "manifest.json")
            with open(capture, "wb") as fh:
                fh.write(raw)
            run_tools.write_manifest(manifest, ["eslint-security"], [capture])
            with open(manifest) as fh:
                result = json.load(fh)
        self.assertEqual(result["file_coverage"]["eslint-security"], facts)
        self.assertEqual(result["missing"], [])

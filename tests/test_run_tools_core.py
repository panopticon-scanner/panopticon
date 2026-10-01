"""Core run_tools tests: selection, manifest, partitioning, output handling."""
import ast
import contextlib
import io
import json
import os
import subprocess as sp
import tempfile
import unittest
from unittest import mock

import scripts.run_tools as rt
import scripts.scanner_config as sc
import scripts.tool_capture as tc
import scripts.tools_manifest as tm
import scripts.venv_scope as vs
from scripts.tools.eslint_security import EslintSecurityAdapter  # #run7 TST-G2A

from tests._test_helpers import REPO_ROOT
from tests.run_tools_test_helpers import _FakeResult


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

    def test_the_registry_and_the_recommendable_set_are_the_same_set(self):
        # #2235 (ARC-3428598333): the test above is the only direction anyone
        # had pinned, and it is the harmless one -- an unresolvable name
        # fail-closes. The reverse gap is the silent one: a tool that is
        # registered and runnable but that nothing can ever select, because its
        # name reached `ADAPTERS` and not `PHASE1_ADAPTERS`/`PHASE2_ADAPTERS`
        # (the selection tables `recommendable_tools` unions). The two sets are
        # equal today, so make that a decision rather than a coincidence: an
        # adapter deliberately kept unselectable -- as the retired bare
        # `eslint` was, by being removed from ADAPTERS -- must say so here.
        from scripts.tools import ADAPTERS
        from scripts.tools.legacy_sarif import TOOL_CMD
        registry = set(TOOL_CMD) | set(ADAPTERS)
        recommendable = set(rt.recommendable_tools())
        self.assertEqual(
            recommendable, registry,
            "recommendable-only %r (no invocation: fail-closed, no diagnostic); "
            "registry-only %r (runnable but unselectable -- add it to a PHASE "
            "table or retire it from ADAPTERS)"
            % (sorted(recommendable - registry), sorted(registry - recommendable)))

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
            payload = tm.write_manifest(
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
            payload = tm.write_manifest(
                os.path.join(d, "manifest.json"), effective, [])
            self.assertEqual(payload["selected"], ["semgrep"])
            self.assertEqual(payload["missing"], ["semgrep"])

    def test_default_artifact_output_rejects_symlinked_root(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, os.path.join(d, ".panopticon"))
            with self.assertRaisesRegex(ValueError, "not a symlink"):
                rt.run_tools(d, ["semgrep"],
                             os.path.join(d, ".panopticon", "tools"))

    def test_nested_artifact_output_symlink_cannot_escape_a_real_artifact_root(self):
        with tempfile.TemporaryDirectory() as target, tempfile.TemporaryDirectory() as outside:
            artifacts = os.path.join(target, ".panopticon")
            os.mkdir(artifacts)
            marker = os.path.join(outside, "untouched.txt")
            with open(marker, "wb") as fh:
                fh.write(b"outside contents stay intact\n")
            os.symlink(outside, os.path.join(artifacts, "tools"))
            with mock.patch.object(rt, "docker_available", return_value=False) as docker, \
                    mock.patch.object(rt.subprocess, "run") as launch:
                with self.assertRaisesRegex(
                        ValueError, "^scanner output escapes the target artifact directory$"):
                    rt.run_tools(target, ["semgrep"], os.path.join(artifacts, "tools", "scan"))
                docker.assert_not_called()
                launch.assert_not_called()
            self.assertEqual(os.listdir(outside), ["untouched.txt"])
            with open(marker, "rb") as fh:
                self.assertEqual(fh.read(), b"outside contents stay intact\n")
            inside = os.path.join(artifacts, "runs", "owned", "tools")
            self.assertEqual(rt.validate_output_dir(target, inside), inside)

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
            self.assertEqual(cmd0[4:], (["--rm"] + rt.resource_limit_flags()
                        + sc.privilege_drop_flags()
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
                tc._stream_and_write("tool", "semgrep", _Proc(),
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
                tc._stream_and_write("tool", "semgrep", _Proc(),
                                     os.path.join(d, "out.sarif"), timeout=60)
        self.assertEqual(called, [])

    def test_bandit_always_gets_an_explicit_ini_and_the_mode_says_whose(self):
        # #run7: bandit auto-discovers nested .bandit files (e.g. git worktrees)
        # and ERRORS ("Multiple .bandit files found") -> empty output, silently
        # unproduced -> certification blocked. So the `--ini` is EXPLICIT on
        # every run, whichever file it names. #1839 (SEC-752508850): pinning the
        # TARGET's copy let the reviewed repo choose bandit's exclude/tests --
        # and the owner ruling of 2026-09-25 on #1924 scopes that to the mode,
        # the same split the gate uses: under redteam bandit honours no
        # target-authored config, under `standard` an operator's own `.bandit`
        # is theirs to keep. A target with none gets ours either way.
        owned = "%s/%s" % (rt.SCANNER_CONFIG_MOUNT, rt.BANDIT_INI_NAME)
        for mode in rt.SECURITY_MODES:
            for plant in (True, False):
                expected = ("/src/.bandit" if plant and mode != "redteam"
                            else owned)
                calls = []
                fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

                def runner(cmd, _calls=calls, **kw):
                    _calls.append(cmd)
                    return fake
                with self.subTest(mode=mode, target_has_bandit=plant), \
                        tempfile.TemporaryDirectory() as d:
                    if plant:
                        open(os.path.join(d, ".bandit"), "w").close()
                    rt.run_tools(d, ["bandit"], os.path.join(d, "out"),
                                 image="panopticon-tools", runner=runner,
                                 security_mode=mode)
                    self.assertEqual(len(calls), 1)  # run-9 TST-B3A: guard calls[0]
                    self.assertIn("--ini", calls[0])
                    i = calls[0].index("--ini")
                    self.assertEqual(calls[0][i + 1], expected)
                    # One read-only FILE mount, named for the ini inside the
                    # container (review Q4-bis) -- never a directory of ours.
                    mount = "%s:ro" % owned
                    if expected == owned:
                        self.assertNotIn("/src/.bandit", calls[0])
                        self.assertIn("-v", calls[0])
                        self.assertTrue(
                            [a for a in calls[0] if a.endswith(mount)],
                            calls[0])
                    else:
                        # Nothing of ours is staged, so there is no mount.
                        self.assertNotIn("%s:ro" % rt.SCANNER_CONFIG_MOUNT,
                                         " ".join(calls[0]))

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

    def test_semgrep_and_trivy_get_their_own_exclusion_knob(self):
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

        def runner(cmd, **kw):
            calls.append(cmd)
            return fake
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, ".venv")
            rt.run_tools(d, ["semgrep", "trivy", "gitleaks"],
                         os.path.join(d, "out"), runner=runner,
                         exclude_globs=["tests/fixtures/**"])
            semgrep, trivy, gitleaks = calls
            # Attached form (F7): a directory named `-rf` can never read as a flag.
            self.assertIn("--exclude=.venv", semgrep)
            self.assertIn("--exclude=tests/fixtures/**", semgrep)
            self.assertEqual(semgrep[-1], "/src")     # the scan target stays last
            self.assertIn("--skip-dirs=.venv", trivy)  # trivy matches root-relative
            self.assertNotIn("--exclude=tests/fixtures/**", trivy)
            self.assertEqual(trivy[-1], "/src")
            # Gitleaks has no path-exclusion flag; the adapter owns its rule
            # config and the ingest filter handles virtualenv paths.
            self.assertEqual(gitleaks[-5:],
                             ["python3", "/opt/panopticon/scripts/_run_adapter.py",
                              "--security", "standard", "gitleaks"])

    def test_semgrep_owns_its_ignore_policy_without_dropping_test_code(self):
        cmd = rt.TOOL_CMD["semgrep"]
        self.assertIn("--jobs=3", cmd)
        self.assertIn("--x-ignore-semgrepignore-files", cmd)
        self.assertIn("--no-git-ignore", cmd)
        for pattern in (".git", ".svn", "_darcs", "build/", "vendor/", "dist/",
                        "*.min.js", ".env/", ".tox/", "node_modules/", ".npm/",
                        ".yarn/", ".venv/", "_opam/", "_build/", "_cargo/",
                        ".panopticon/", ".worktrees/", ".superpowers/",
                        "__pycache__/", ".ruff_cache/", ".pytest_cache/",
                        ".mypy_cache/", "*.egg-info/", ".DS_Store"):
            self.assertIn("--exclude=%s" % pattern, cmd)
        for test_pattern in ("test/", "tests/", "testsuite/", "*_test.go"):
            self.assertNotIn("--exclude=%s" % test_pattern, cmd)
        self.assertEqual(cmd[-1], "/src")

    def test_manifest_records_the_semgrep_scope_observed_on_the_argv(self):
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')
        with tempfile.TemporaryDirectory() as root:
            complete = rt.run_tools(
                root, ["semgrep"], os.path.join(root, "complete"),
                runner=lambda cmd, **kw: fake)
            observed = tm.write_manifest(
                os.path.join(root, "complete.json"), ["semgrep"], complete)
            without_policy = [arg for arg in rt.TOOL_CMD["semgrep"]
                              if arg != "--x-ignore-semgrepignore-files"]
            with mock.patch.dict(rt.TOOL_CMD, {"semgrep": without_policy}):
                incomplete = rt.run_tools(
                    root, ["semgrep"], os.path.join(root, "incomplete"),
                    runner=lambda cmd, **kw: fake)
            missing = tm.write_manifest(
                os.path.join(root, "incomplete.json"), ["semgrep"], incomplete)
        self.assertEqual(observed["scanner_scope"], {
            "semgrep": tm.SEMGREP_SCOPE_POLICY})
        self.assertEqual(missing["scanner_scope"], {})

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
            # (the #run7 discovery walk must never run) and the scanner-owned
            # `--exclude` either way (an ini that fails to arrive is fail-open),
            # and nothing else. semgrep is byte-identical to TOOL_CMD.
            at = list(rt.TOOL_CMD["bandit"]).index("/src")
            expected = {
                "semgrep": list(rt.TOOL_CMD["semgrep"]),
                "bandit": (list(rt.TOOL_CMD["bandit"][:1])
                           + ["--ini", "%s/%s" % (rt.SCANNER_CONFIG_MOUNT,
                                                  rt.BANDIT_INI_NAME)]
                           + list(rt.TOOL_CMD["bandit"][1:at])
                           + ["--exclude=%s" % vs._bandit_exclude_value([])]
                           + list(rt.TOOL_CMD["bandit"][at:]))}
            for cmd, tool in zip(calls, ("semgrep", "bandit")):
                self.assertEqual(cmd[-len(expected[tool]):], expected[tool], tool)

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
            skip, rows = vs.partition_venv_dirs(vs.find_virtualenvs(d), "redteam")
            self.assertEqual(skip, [])
            self.assertEqual([r["skipped"] for r in rows], [False, False])
            rt.run_tools(d, ["semgrep", "trivy", "bandit"],
                         os.path.join(d, "out"), runner=runner, venv_dirs=skip)
        semgrep, trivy, bandit = calls
        for spelling in (".venv", "venv"):
            self.assertNotIn("--exclude=%s" % spelling, semgrep)
            self.assertNotIn("--skip-dirs=%s" % spelling, trivy)
        # bandit's `--exclude` is still there and still SCANNER-owned: no venv
        # in it, and the entries the scan relies on carried on the argv rather
        # than left to an ini that is fail-open on arrival (round 1 N1).
        entries = [a for a in bandit
                   if a.startswith("--exclude=")][0][len("--exclude="):].split(",")
        self.assertNotIn("/src/.venv", entries)
        self.assertNotIn("/src/venv", entries)
        for owned in rt.BANDIT_SCANNER_EXCLUDES:
            self.assertIn(owned, entries)

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
                         "--tools", "semgrep", "--security", "redteam",
                         "--exclude", "tests/fixtures/**"])
        self.assertEqual(captured["venv_dirs"], [])   # #1839 ruling 2
        self.assertEqual(captured["exclude_globs"], ["tests/fixtures/**"])

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
                venvs = vs.find_virtualenvs(d)
                self.assertEqual([v["path"] for v in venvs], [".venv"])
                globs = ["%s/*" % v["path"] for v in venvs]
                self.assertFalse(rt._is_excluded(marker, globs))       # root: audited
                self.assertTrue(rt._is_excluded(".venv/" + marker, globs))  # copy: not
                # The scanners are told to skip the venv, never the root.
                skips = vs._with_venv_excludes("trivy", list(rt.TOOL_CMD["trivy"]), venvs)
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

    def test_the_manifest_carries_the_note_for_a_directory_it_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            _skip, rows = vs.partition_venv_dirs(
                [{"path": "*", "reason": rt.VENV_MARKER}], "standard")
            payload = tm.write_manifest(os.path.join(d, "m.json"), ["semgrep"],
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
                skip, _rows = vs.partition_venv_dirs(vs.find_virtualenvs(d), mode)
                rt.run_tools(d, ["semgrep", "trivy", "bandit"],
                             os.path.join(d, "out"), runner=runner, venv_dirs=skip)
            for cmd in calls:
                for arg in cmd:
                    self.assertNotIn(arg, ("--exclude=*", "--exclude=src",
                                           "--skip-dirs=*", "--skip-dirs=src"))
                for arg in [a for a in cmd if a.startswith("--exclude=")]:
                    for entry in arg[len("--exclude="):].split(","):
                        self.assertNotIn(entry, ("/src/*", "/src/src"))


class TestNoTargetTextReachesAScannerConfig(unittest.TestCase):
    """#1839 fix round 1 (review C1/I1/I2): the DIRECTORY NAME is target input too.

    Round 0 replaced the target's `.bandit` with a scanner-owned ini -- and then
    interpolated a directory name straight off `os.walk` into it, so a
    venv-shaped directory named `x\ntests = B101` added a second key to the
    `[bandit]` section (bandit reads `tests`, `skips`, `configfile` and six more
    from there whenever the CLI leaves them at their default) and a directory
    named `a,b` injected the bare exclude entry `b`, which substring-matches
    almost every path. The ini is a CONSTANT now, and a path reaches an exclusion
    knob only through an ALLOWLIST.
    """

    # Names the ALLOWLIST must refuse. `a\x00b` is refused by the predicate but
    # cannot be planted on disk (the kernel rejects it), so it is tested against
    # the predicate only, in `_PREDICATE_ONLY`.
    HOSTILE = ("x\ntests = B101", "a,b", "{src,q}", "-rf", "sr c",
               "pkg\rskips = B602", "caf\u00e9", "*", "q?", "lib[0]")
    _PREDICATE_ONLY = ("a\x00b",)

    def _shaped_venv(self, root, name):
        """A directory the SHAPE test accepts, under a hostile name."""
        os.makedirs(os.path.join(root, name, "bin"), exist_ok=True)
        for rel in (rt.VENV_MARKER, os.path.join("bin", "python")):
            with open(os.path.join(root, name, rel), "w") as fh:
                fh.write("")

    def test_the_bandit_ini_is_byte_identical_whatever_the_tree_holds(self):
        # The ini's ONLY job is to pre-empt bandit's `.bandit` discovery walk
        # (#run7). Nothing in it comes from the target, so nothing in the tree
        # can change a byte of it.
        baseline = rt.BANDIT_INI_TEXT
        for name in self.HOSTILE:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                self._shaped_venv(d, name)
                skip, _rows = vs.partition_venv_dirs(vs.find_virtualenvs(d),
                                                     "standard")
                self.assertEqual(rt.BANDIT_INI_TEXT, baseline)
                # ...and the CLI value is the scanner-owned baseline exactly:
                # nothing hostile was added, so nothing can split it either.
                cmd = vs._with_venv_excludes("bandit",
                                             list(rt.TOOL_CMD["bandit"]), skip)
                self.assertEqual([a for a in cmd if a.startswith("--exclude=")],
                                 ["--exclude=%s" % vs._bandit_exclude_value([])])

    def test_the_library_default_partitions_before_it_excludes_anything(self):
        # Review I2: `run_tools()`'s own default was the RAW `find_virtualenvs`
        # list, so a bare-marker `src/` went straight to all three knobs -- the
        # triage extract's reproduction, on the module's own convenience path.
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

        def runner(cmd, **kw):
            calls.append(cmd)
            return fake
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "src"))
            for rel in ("app.py", rt.VENV_MARKER):
                with open(os.path.join(d, "src", rel), "w") as fh:
                    fh.write("")
            rt.run_tools(d, ["semgrep", "trivy", "bandit"],
                         os.path.join(d, "out"), runner=runner)
        semgrep, trivy, bandit = calls
        self.assertNotIn("--exclude=src", semgrep)
        self.assertNotIn("--skip-dirs=src", trivy)
        entries = [a for a in bandit if a.startswith("--exclude=")][0].split(",")
        self.assertNotIn("/src/src", entries)

    def test_a_config_that_cannot_be_staged_costs_that_tool_and_nothing_else(self):
        # Review N3: the ini write raised straight out of the dispatch loop, so a
        # full or read-only $TMPDIR took semgrep and every adapter after bandit
        # down with it. One tool's problem stays one tool's problem -- and the
        # tool lands in `missing`, which is the fail-closed direction.
        # #1839: trivy is staged the same way now, so it fails closed the same
        # way (the ignore list being the scanner's is not optional).
        for staged in sorted(rt.SCANNER_OWNED_CONFIG):
            calls = []
            fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

            def runner(cmd, _calls=calls, **kw):
                _calls.append(cmd)
                return fake
            err = io.StringIO()
            real_mkdtemp = sc.tempfile.mkdtemp

            def only_the_config_fails(*a, **kw):
                if str(kw.get("prefix", "")).startswith("pano-scanner-config-"):
                    raise OSError("No space left on device")
                return real_mkdtemp(*a, **kw)
            with self.subTest(tool=staged), tempfile.TemporaryDirectory() as d, \
                    mock.patch.object(sc.tempfile, "mkdtemp",
                                      side_effect=only_the_config_fails), \
                    contextlib.redirect_stderr(err):
                written = rt.run_tools(d, [staged, "semgrep"],
                                       os.path.join(d, "out"), runner=runner)
                self.assertEqual(len(calls), 1)         # semgrep still ran
                self.assertIn("semgrep", calls[0])
                self.assertEqual(len(written), 1)       # the other produced none
                self.assertIn("No space left on device", err.getvalue())
                self.assertIn("tool %s skipped" % staged, err.getvalue())


class TestInlineSuppressionIsNeutralisedUnderRedteamOnly(unittest.TestCase):
    """#1839 (run-14 SEC-284952751): an inline suppression COMMENT in the
    target's own source -- `# nosemgrep`, `# nosec`, `gitleaks:allow` -- is the
    other half of the scan-root class, and it is NOT the same thing as an
    ignore file.

    A comment sits in the diff a reviewer reads, and under `standard` -- an
    operator scanning their own repository -- it stands, and the manifest says
    it stood. This repository's own CI (`security.yml` and the fork-PR
    `security-fork.yml`) scans in `redteam` (#2125), so nothing target-authored
    is honoured on either check. Under `--security redteam` the tree is
    untrusted and every scanner whose pinned version exposes the knob is told
    to stop honouring it. Only knobs that EXIST are passed: a flag a pinned
    scanner rejects is a tool that exits non-zero and produces no SARIF, which
    is the #1452 selected-but-unproduced class, not a control.
    """

    def _argv(self, tool, security_mode):
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

        def runner(cmd, **_kw):
            calls.append(list(cmd))
            return fake
        with tempfile.TemporaryDirectory() as d:
            rt.run_tools(d, [tool], os.path.join(d, "out"), runner=runner,
                         venv_dirs=[], security_mode=security_mode)
        self.assertEqual(len(calls), 1)
        return calls[0]

    def test_semgrep_stops_honouring_nosemgrep_under_redteam(self):
        self.assertIn("--disable-nosem", self._argv("semgrep", "redteam"))

    def test_bandit_stops_honouring_nosec_under_redteam(self):
        self.assertIn("--ignore-nosec", self._argv("bandit", "redteam"))

    def test_standard_honours_both(self):
        self.assertNotIn("--disable-nosem", self._argv("semgrep", "standard"))
        self.assertNotIn("--ignore-nosec", self._argv("bandit", "standard"))

    def test_the_default_mode_honours_them_too(self):
        calls = []
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')

        def runner(cmd, **_kw):
            calls.append(list(cmd))
            return fake
        with tempfile.TemporaryDirectory() as d:
            rt.run_tools(d, ["semgrep"], os.path.join(d, "out"), runner=runner,
                         venv_dirs=[])
        self.assertNotIn("--disable-nosem", calls[0])

    def test_the_flag_goes_before_the_scan_root(self):
        # semgrep takes its scan root positionally and last; a flag after it
        # would be read as a second target.
        argv = self._argv("semgrep", "redteam")
        self.assertEqual(argv[-1], "/src")
        self.assertLess(argv.index("--disable-nosem"), argv.index("/src"))

    def test_a_tool_with_no_verified_knob_gets_no_invented_one(self):
        # gosec honours `// #nosec` and its own knob was NOT verified against
        # the pinned image in this round, so the residual is DISCLOSED on the
        # manifest instead of guessed at on the argv.
        self.assertIsNone(sc.SUPPRESSION_COMMENTS["gosec"][1])
        argv = self._argv("gosec", "redteam")
        self.assertEqual(argv[-len(rt.TOOL_CMD["gosec"]):],
                         list(rt.TOOL_CMD["gosec"]))

    def test_every_named_knob_is_a_flag_and_every_tool_is_one_we_run(self):
        for tool, (comment, flag) in sc.SUPPRESSION_COMMENTS.items():
            with self.subTest(tool=tool):
                self.assertIn(tool, rt.recommendable_tools(),
                              "%s is not a tool this runner can select" % tool)
                if flag is not None:
                    self.assertTrue(flag.startswith("--"), flag)
                    self.assertIsNotNone(
                        comment, "a knob for a tool that honours no comment")


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
                cleaned = tc._redact_capture("eslint-security", raw)
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
                payload = tm.write_manifest(manifest, ["eslint-security"], [moved])
                self.assertEqual(payload["file_coverage"], {})
                _, _, failures, _, _ = security_gate.evaluate(tools, manifest)
                self.assertTrue(failures)

    def test_missing_parser_envelope_survives_runner_and_ingestion(self):
        from scripts import ingest_tools, tool_capture, tools_manifest
        document = {"panopticon_eslint": {"version": 1, "typescript_parser": "unavailable",
                     "files_count": 1, "files": ["nested/app.ts"]}, "results": []}
        raw = tool_capture._redact_capture("eslint-security",
                                          json.dumps(document).encode())
        with tempfile.TemporaryDirectory() as target:
            capture = os.path.join(target, "eslint-security.json")
            manifest = os.path.join(target, "manifest.json")
            with open(capture, "wb") as fh:
                fh.write(raw)
            findings, dispositions = ingest_tools.ingest_dir_detailed(target, "g1")
            tools_manifest.write_manifest(manifest, ["eslint-security"], [capture])
            with open(manifest) as fh:
                payload = json.load(fh)
        facts = dispositions["eslint-security"]["file_coverage"]
        self.assertEqual(findings, [])
        self.assertEqual((facts["parsed_files"], facts["unavailable_files"]), (0, 1))
        self.assertEqual(facts["files"], [{"file": "nested/app.ts", "reason": "typescript_parser_unavailable"}])
        self.assertEqual(payload["file_coverage"]["eslint-security"], facts)

    def test_manifest_and_redacted_capture_keep_only_safe_parser_facts(self):
        from scripts import tool_capture, tools_manifest
        from scripts.tools.eslint_security import EslintSecurityAdapter
        payload = [
            {"filePath": "/src/good.js", "messages": [{"ruleId": "security/detect-eval-with-expression",
             "message": "eval with expression", "line": 1}]},
            {"filePath": "/src/bad.js", "fatalErrorCount": 1,
             "source": "private source text", "output": "private source text",
             "messages": [{"ruleId": None, "fatal": True, "message": "Parsing error: private source text"}]},
        ]
        raw = tool_capture._redact_capture("eslint-security",
                                          json.dumps(payload).encode())
        self.assertNotIn(b"private source text", raw)
        findings, facts = EslintSecurityAdapter().parse_with_file_coverage(raw, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(facts["unparsed_files"], 1)
        with tempfile.TemporaryDirectory() as target:
            capture = os.path.join(target, "eslint-security.json")
            manifest = os.path.join(target, "manifest.json")
            with open(capture, "wb") as fh:
                fh.write(raw)
            tools_manifest.write_manifest(manifest, ["eslint-security"], [capture])
            with open(manifest) as fh:
                result = json.load(fh)
        self.assertEqual(result["file_coverage"]["eslint-security"], facts)
        self.assertEqual(result["missing"], [])


class TestTheCliRunsUnderTheSigtermWrapper(unittest.TestCase):
    """#2507: a hand-run `run_tools.py` must end its scanner containers on a
    SIGTERM the way a Ctrl-C already does.

    The driver path was closed by #2199: `driver.py`'s `__main__` block runs
    every verb through `procgroup.sigterm_as_interrupt`, so a supervisor's stop
    raises the interrupt the teardown paths already handle, and the `docker run`
    clients -- launched without `start_new_session`, so they sit in the driver's
    own session -- get the signal and proxy it to each container's PID 1. Run by
    hand there was no wrapper: a plain `kill` ended the process at SIGTERM's
    default disposition, so no `finally` ran, the capture's watchdog timer died
    with the process, and the `docker run --rm` client was orphaned with its
    container running to its own end.

    Read off the AST the way `tests/test_procgroup.py` reads the driver's, and
    asserted to be INSIDE the `__main__` guard: the suite imports `run_tools`,
    and installing a SIGTERM handler at import time would replace the default
    disposition every other test runs against.
    """

    def test_the_main_guard_runs_main_under_it_and_nothing_else_does(self):
        path = os.path.join(REPO_ROOT, "skill", "scripts", "run_tools.py")
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), path)
        guards = [node for node in tree.body if isinstance(node, ast.If)
                  and ast.unparse(node.test) == "__name__ == '__main__'"]
        self.assertEqual(1, len(guards), "run_tools.py has no single __main__ guard")
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and ast.unparse(node.func).endswith("sigterm_as_interrupt")]
        self.assertEqual(1, len(calls), "the CLI installs it once, at its entry")
        self.assertIn(calls[0], list(ast.walk(guards[0])),
                      "installed outside the __main__ guard, i.e. at import time")
        self.assertEqual(["main"], [ast.unparse(arg) for arg in calls[0].args])

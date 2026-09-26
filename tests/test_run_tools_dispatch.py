"""Adapter dispatch tests for scripts.run_tools."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.run_tools as rt

from run_tools_test_helpers import _DockerStub, _FakeResult


class TestAdapterDispatch(unittest.TestCase):
    def test_main_tools_with_exclude_does_not_crash(self):
        # COD-X0X: `--tools ... --exclude ...` built a LIST of adapters and passed
        # it to partition_by_exclusion, which iterates .items() -> AttributeError
        # crashed the whole CLI before any scan. The combination is operator-facing
        # (documented in --exclude help), so it must resolve cleanly.
        class FakeAdapter:
            def applicable_files(self, target):
                return []
        with mock.patch.dict(rt.ADAPTERS, {"faketool": FakeAdapter()}, clear=False), \
             mock.patch("scripts.run_tools.docker_available", return_value=True), \
             mock.patch("scripts.run_tools.run_tools", return_value={}), \
             contextlib.redirect_stderr(io.StringIO()):
            rc = rt.main(["--tools", "faketool", "--exclude", "tests/fixtures/*",
                          "--target", ".", "--out", "/tmp/pano-x0x"])
        self.assertEqual(rc, 0)

    def test_docker_unavailable_writes_full_skip_manifest(self):
        # COD-X0X #1406: when docker is unavailable, main() used to `return 0`
        # BEFORE the manifest block, silently discarding the --manifest artifact
        # a caller relies on for coverage gating -- indistinguishable from
        # --manifest never being passed. It must instead disclose the whole
        # selected set as `missing` (produced=[]), the way every other skip
        # surface in this module stays visible.
        with tempfile.TemporaryDirectory() as d:
            manifest = os.path.join(d, "cov", "manifest.json")
            with mock.patch("scripts.run_tools.docker_available", return_value=False), \
                 mock.patch("scripts.run_tools.run_tools",
                            side_effect=AssertionError("scan must not run without docker")), \
                 contextlib.redirect_stderr(io.StringIO()):
                rc = rt.main(["--tools", "semgrep", "--target", d,
                              "--out", os.path.join(d, "out"),
                              "--manifest", manifest, "--run-id", "r8"])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(manifest))   # not silently discarded
            with open(manifest, encoding="utf-8") as fh:
                payload = json.load(fh)
            self.assertEqual(payload["selected"], ["semgrep"])
            self.assertEqual(payload["produced"], [])
            self.assertEqual(payload["missing"], ["semgrep"])  # whole scan missing
            self.assertEqual(payload["run_id"], "r8")

    def test_docker_unavailable_without_manifest_is_a_clean_noop(self):
        # The docker-absent path stays a clean skip when no manifest was asked
        # for: exit 0, the scan itself never runs, and nothing is written.
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("scripts.run_tools.docker_available", return_value=False), \
                 mock.patch("scripts.run_tools.run_tools",
                            side_effect=AssertionError("scan must not run without docker")), \
                 contextlib.redirect_stderr(io.StringIO()):
                rc = rt.main(["--tools", "semgrep", "--target", d,
                              "--out", os.path.join(d, "out")])
            self.assertEqual(rc, 0)
            self.assertEqual(os.listdir(d), [])   # no artifact written

class TestDefaultSelectionBranch(unittest.TestCase):
    """#1526 (TST-A2C): main()'s `else` arm -- taken whenever --tools is omitted
    -- is the branch EVERY real scan uses (driver.tools_execute and
    .github/workflows/security.yml both omit the flag), yet every rt.main() test
    passed --tools and took the other arm. Its four constituents were unit-tested
    in isolation; their COMPOSITION was not.

    Docker is reported unavailable so the manifest records the selection without
    launching a container: `selected` is exactly the composed `chosen` list."""

    def _selection_for(self, target, extra=()):
        with tempfile.TemporaryDirectory() as d:
            manifest = os.path.join(d, "manifest.json")
            with mock.patch("scripts.run_tools.docker_available", return_value=False), \
                 mock.patch("scripts.run_tools.run_tools",
                            side_effect=AssertionError("scan must not run without docker")), \
                 contextlib.redirect_stderr(io.StringIO()):
                rc = rt.main(["--target", target, "--out", os.path.join(d, "out"),
                              "--manifest", manifest] + list(extra))
            self.assertEqual(rc, 0)
            with open(manifest, encoding="utf-8") as fh:
                return json.load(fh)

    def _expected(self, target, deps=False, exclude=()):
        selected_adapters = rt.select_adapters(target)
        required_names, _ = rt.partition_by_exclusion(
            selected_adapters, target, list(exclude))
        phase1 = [n for n in required_names if n in rt.PHASE1_ADAPTERS]
        phase2 = [n for n in required_names if n in rt.PHASE2_ADAPTERS]
        languages = rt.detect_languages(target)
        return rt.filter_online(
            rt.select_tools(languages, deps) + phase1 + phase2, False)

    def _polyglot(self, target):
        """A target that draws from BOTH phase sets, so neither half of the
        concatenation can be asserted vacuously."""
        for name, body in (("requirements.txt", "requests==2.0.0\n"),   # phase 1
                           ("app.py", "x = 1\n"),
                           ("Cargo.lock", "[[package]]\nname = \"x\"\n"),  # phase 2
                           ("Gemfile.lock", "GEM\n  specs:\n")):           # phase 2
            with open(os.path.join(target, name), "w") as fh:
                fh.write(body)

    def test_omitting_tools_composes_the_production_selection(self):
        with tempfile.TemporaryDirectory() as target:
            self._polyglot(target)
            payload = self._selection_for(target, extra=["--deps"])
            expected = self._expected(target, deps=True)
            required, _ = rt.partition_by_exclusion(
                rt.select_adapters(target), target, [])
        self.assertEqual(payload["selected"], list(dict.fromkeys(expected)))
        # Both halves of `phase1 + phase2` must actually be exercised, or the
        # equality above proves only that an empty list equals an empty list.
        self.assertTrue([n for n in required if n in rt.PHASE1_ADAPTERS],
                        "fixture selected no phase-1 adapter")
        self.assertTrue([n for n in required if n in rt.PHASE2_ADAPTERS],
                        "fixture selected no phase-2 adapter")
        self.assertTrue(set(rt.PHASE2_ADAPTERS) & set(payload["selected"]),
                        "phase-2 adapters never reached the selection")

    def test_the_default_branch_really_is_the_one_production_takes(self):
        # Pin the premise rather than trusting it: if driver ever started
        # passing --tools, this test would be guarding the wrong arm.
        import scripts.phases.tools as tools_phase
        from scripts.phases import child, runio
        with tempfile.TemporaryDirectory() as root:
            with mock.patch.object(child, "_run_child", return_value=_FakeResult(0, "", "")) as run, \
                    contextlib.redirect_stderr(io.StringIO()):
                result = tools_phase.tools_execute(root, {"run_id": "default-run"})
            run.assert_called_once()
            argv = run.call_args.args[0]
            self.assertEqual(os.path.basename(argv[1]), "run_tools.py")
            self.assertNotIn("--tools", argv)
            self.assertFalse(any(arg.startswith("--tools=") for arg in argv))
            self.assertEqual(argv[argv.index("--target") + 1], root)
            self.assertIn("--deps", argv)
            marker = runio._load_json(runio._pano(root, "tools-ran.json"))
            self.assertEqual(marker["run_id"], "default-run")
            self.assertFalse(marker["ran"])
            self.assertFalse(marker["crashed"])
            self.assertEqual(marker["note"], "no tool output produced")
            self.assertEqual(result.kind, "advanced")

    def test_language_detection_feeds_the_selection(self):
        # detect_languages is one of the four composed functions; a target with
        # no recognised language must not silently select the python set.
        with tempfile.TemporaryDirectory() as target:
            with open(os.path.join(target, "app.py"), "w") as fh:
                fh.write("x = 1\n")
            python_selection = self._selection_for(target)["selected"]
        with tempfile.TemporaryDirectory() as target:
            with open(os.path.join(target, "README.md"), "w") as fh:
                fh.write("# nothing\n")
            bare_selection = self._selection_for(target)["selected"]
        self.assertNotEqual(python_selection, bare_selection)


class TestAdapterSelection(unittest.TestCase):
    def test_gitleaks_uses_owned_config_adapter_in_production(self):
        calls = []

        def runner(cmd, **kw):
            calls.append(cmd)
            return _FakeResult(returncode=1, stdout=b'{"runs":[]}')

        with tempfile.TemporaryDirectory() as target:
            out_dir = os.path.join(target, "out")
            written = rt.run_tools(target, ["gitleaks"], out_dir,
                                   runner=runner, venv_dirs=[])
            self.assertEqual(len(calls), 1)
            scan_argv = calls[0]
            self.assertEqual(scan_argv[-3:], ["python3",
                             "/opt/panopticon/scripts/_run_adapter.py", "gitleaks"])
            self.assertEqual(scan_argv[scan_argv.index("--network") + 1], "none")
            self.assertIn("%s:/src:ro" % os.path.abspath(target), scan_argv)
            scripts_dir = os.path.dirname(os.path.abspath(rt.__file__))
            self.assertIn("%s:/opt/panopticon/scripts:ro" % scripts_dir, scan_argv)
            self.assertEqual(scan_argv[scan_argv.index("-w") + 1],
                             rt.ADAPTER_EMPTY_CWD)
            for flag in ("--memory", "--memory-swap", "--cpus", "--pids-limit",
                         "--cap-drop=ALL", "--security-opt=no-new-privileges"):
                self.assertIn(flag, scan_argv)
            self.assertEqual(len(written), 1)
            self.assertEqual(os.path.basename(written[0]), "gitleaks.sarif")
            self.assertTrue(os.path.isfile(written[0]))

    def test_gitleaks_abnormal_exit_remains_missing(self):
        with tempfile.TemporaryDirectory() as target:
            out_dir = os.path.join(target, "out")
            written = rt.run_tools(
                target, ["gitleaks"], out_dir, venv_dirs=[],
                runner=lambda cmd, **kw: _FakeResult(
                    returncode=7, stdout=b'{"runs":[]}', stderr=b'failed'))
            payload = rt.write_manifest(os.path.join(target, "manifest.json"),
                                        ["gitleaks"], written)
            self.assertEqual(written, [])
            self.assertEqual(payload["produced"], [])
            self.assertEqual(payload["missing"], ["gitleaks"])
            self.assertFalse(os.path.exists(os.path.join(out_dir, "gitleaks.sarif")))

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
            with mock.patch.dict(rt.ADAPTERS, {"fake": FakeAdapter()}, clear=False):
                rt.run_tools(d, ["fake"], out_dir, image="panopticon-tools", runner=runner)
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
            with mock.patch.dict(rt.ADAPTERS, {"fake": FakeAdapter()}, clear=False):
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    paths = rt.run_tools(d, ["fake"], out, runner=runner)
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
            with mock.patch.dict(rt.ADAPTERS, {"fake": FakeAdapter()}, clear=False):
                written = rt.run_tools(d, ["fake"], out, runner=lambda cmd, **kw: fake)
            payload = rt.write_manifest(
                os.path.join(d, "m.json"), ["fake"], written)
            self.assertEqual(payload["produced"], [])
            self.assertEqual(payload["missing"], ["fake"])

    def test_every_container_works_outside_the_target_mount(self):
        # #1646 C1(b), generalized by #1877: the image ends `WORKDIR /src` and
        # /src IS the target mount, so a container that starts there resolves
        # whatever cwd-relative name its scanner tries -- pip's archive names,
        # npm's `.npmrc`, semgrep's `.semgrepignore` -- inside the reviewed
        # repo. EVERY dispatch now starts outside the mount, the legacy
        # TOOL_CMD path (semgrep here) and the adapter path (pip-audit,
        # osv-scanner) alike, so this is no longer one adapter's exemption.
        # #1645: the stub answers the egress control plane too, or pip-audit
        # would fail closed (no proxy -> no dispatch) and never reach the
        # assertion this test is about.
        stub = _DockerStub()
        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            with contextlib.redirect_stderr(io.StringIO()):
                rt.run_tools(d, ["pip-audit", "osv-scanner", "semgrep"], out_dir,
                             image="panopticon-tools", runner=stub, online=True)
        calls = stub.dispatches()
        self.assertEqual(len(calls), 3, "expected all three tools dispatched, "
                                        "got %r" % sorted(calls))
        for key, argv in sorted(calls.items()):
            self.assertIn("-w", argv, "%s dispatched with no -w" % key)
            i = argv.index("-w")
            self.assertLess(i + 1, len(argv), "%s: -w has no value" % key)
            self.assertEqual(argv[i + 1], rt.ADAPTER_EMPTY_CWD,
                             "%s started in %r" % (key, argv[i + 1]))
            self.assertNotEqual(argv[i + 1], "/src")

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

    def test_phase1_adapter_registry_not_leaked(self):
        # Regression: phase-1 adapter tests must restore rt.ADAPTERS.
        original = dict(rt.ADAPTERS)
        self.test_run_tools_dispatches_phase1_adapter_via_docker_helper()
        self.assertEqual(dict(rt.ADAPTERS), original)

    def test_docker_invocations_carry_resource_ceilings(self):
        # #run8 OPS-D1A: every tool/adapter container must run with hard
        # memory/CPU/PID ceilings so an adversarial target cannot drive the
        # container to exhaust the host runner before the wall-clock timeout.
        # Exercises BOTH the legacy SARIF path (semgrep) and the adapter path.
        class FakeAdapter:
            name = "fake"
            def is_applicable(self, target): return True
            def invoke(self, target): return (b'{"findings":[]}', 0)
        fake = _FakeResult(returncode=0, stdout=b'{"findings":[]}', stderr=b'')
        calls = []
        def runner(cmd, **kw):
            calls.append(cmd); return fake
        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            with mock.patch.dict(rt.ADAPTERS, {"fake": FakeAdapter()}, clear=False):
                rt.run_tools(d, ["semgrep", "fake"], out_dir,
                             image="panopticon-tools", runner=runner)
            self.assertEqual(len(calls), 2)   # legacy + adapter both dispatched
            for cmd in calls:
                self.assertIn("--memory", cmd)
                self.assertIn("--memory-swap", cmd)
                self.assertIn("--cpus", cmd)
                self.assertIn("--pids-limit", cmd)
                # swap pinned equal to memory so an allocation is OOM-killed at
                # the ceiling rather than spilling into swap.
                self.assertEqual(cmd[cmd.index("--memory") + 1],
                                 cmd[cmd.index("--memory-swap") + 1])
                # docker requires all options BEFORE the image; a ceiling placed
                # after the image name would be passed to the tool, not enforced.
                self.assertLess(cmd.index("--pids-limit"),
                                cmd.index("panopticon-tools"))

    def test_resource_ceiling_flag_can_be_disabled_via_env(self):
        # An operator on a cgroup that rejects --pids-limit can drop just that
        # flag by exporting an empty value; the others stay applied.
        with mock.patch.object(rt, "CONTAINER_PIDS_LIMIT", ""):
            flags = rt._resource_limit_flags()
        self.assertNotIn("--pids-limit", flags)
        self.assertIn("--memory", flags)
        self.assertIn("--cpus", flags)


class TestBanditConfigIsScannerOwned(unittest.TestCase):
    """run-14 SEC-752508850 (#1839): the target chose bandit's tests.

    `run_tools` PINNED the reviewed repo's own `.bandit` with `--ini`, and that
    file carries `exclude`, `tests` and `skips` -- so a committed
    `tests = [B101]` made bandit report one check and nothing else, on the path
    CI's merge gate runs. brakeman and bundler-audit already answer #run7's
    multiple-config ERROR with a SCANNER-OWNED config in scratch; bandit now
    does the same, unconditionally, so the target's file never reaches the argv
    whether or not it exists.
    """

    HOSTILE_INI = "[bandit]\nexclude = src\ntests = B999\nskips = B101\n"

    def _dispatch(self, plant_ini=True, plant_venv=True):
        """One faked bandit dispatch; returns (argv, the ini text it mounted)."""
        seen = {"argv": None, "ini": None, "mount": None, "dir_mode": None,
                "file_mode": None}
        fake = _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')
        suffix = ":%s/%s:ro" % (rt.BANDIT_INI_MOUNT, rt.BANDIT_INI_NAME)

        def runner(cmd, **_kw):
            cmd = list(cmd)
            seen["argv"] = cmd
            hosts = [a[:-len(suffix)] for a in cmd if a.endswith(suffix)]
            if hosts:
                seen["mount"] = hosts[0]
                # Read it WHILE the dispatch is in flight: the scratch is
                # removed when the tool returns, so this also proves the file
                # is there when the container starts. The mount source is the
                # FILE; the directory around it is the scanner's alone.
                with open(hosts[0], encoding="utf-8") as fh:
                    seen["ini"] = fh.read()
                seen["file_mode"] = os.stat(hosts[0]).st_mode & 0o777
                seen["dir_mode"] = os.stat(os.path.dirname(hosts[0])).st_mode & 0o777
            return fake
        with tempfile.TemporaryDirectory() as d:
            if plant_ini:
                with open(os.path.join(d, ".bandit"), "w", encoding="utf-8") as fh:
                    fh.write(self.HOSTILE_INI)
            if plant_venv:
                os.makedirs(os.path.join(d, ".venv", "bin"))
                for rel in (rt.VENV_MARKER, os.path.join("bin", "python")):
                    with open(os.path.join(d, ".venv", rel), "w") as fh:
                        fh.write("")
            rt.run_tools(d, ["bandit"], os.path.join(d, "out"), runner=runner,
                         venv_dirs=[{"path": ".venv", "reason": rt.VENV_MARKER}])
        return seen

    def _ini_excludes(self, text):
        line = [ln for ln in text.splitlines() if ln.startswith("exclude")][0]
        return [e.strip() for e in line.split("=", 1)[1].split(",") if e.strip()]

    def test_the_targets_own_ini_never_reaches_the_argv(self):
        seen = self._dispatch()
        argv = seen["argv"]
        self.assertNotIn("/src/.bandit", argv)
        self.assertIn("--ini", argv)
        self.assertEqual(argv[argv.index("--ini") + 1],
                         "%s/%s" % (rt.BANDIT_INI_MOUNT, rt.BANDIT_INI_NAME))
        self.assertIsNotNone(seen["mount"], argv)

    def test_the_scratch_directory_is_private_and_only_the_file_is_shared(self):
        # The tools image runs as `USER scanner` (uid 1000), so the ini has to
        # be readable across the bind mount -- but that is a property of the
        # FILE (0644). Mounting the file alone lets the scratch directory keep
        # `mkdtemp`'s 0700: no `chmod 0755` on a directory, which is the
        # permissive-mask pattern both bandit (B103) and semgrep flag, and
        # nothing else in that directory is ever exposed to the container.
        seen = self._dispatch()
        self.assertEqual(0o700, seen["dir_mode"])
        self.assertEqual(0o644, seen["file_mode"])
        self.assertTrue(seen["mount"].endswith(os.sep + rt.BANDIT_INI_NAME),
                        seen["mount"])

    def test_the_pin_is_unconditional(self):
        # #run7 is a nested checkout's `.bandit` making bandit ERROR and emit
        # nothing. A target with no `.bandit` of its own got no --ini at all,
        # so the discovery walk -- and that failure -- was still reachable.
        seen = self._dispatch(plant_ini=False, plant_venv=False)
        self.assertIn("--ini", seen["argv"])
        self.assertIn("[bandit]", seen["ini"])

    def test_the_generated_ini_chooses_no_tests_and_skips_nothing(self):
        seen = self._dispatch()
        self.assertNotIn("tests", seen["ini"])
        self.assertNotIn("skips", seen["ini"])
        self.assertNotIn("B999", seen["ini"])
        self.assertNotIn("B101", seen["ini"])

    def test_the_generated_ini_keeps_the_exclusions_the_scan_relies_on(self):
        seen = self._dispatch()
        entries = self._ini_excludes(seen["ini"])
        for default in rt.BANDIT_DEFAULT_EXCLUDES:      # never WIDEN the scan
            self.assertIn(default, entries)
        for owned in rt.BANDIT_SCANNER_EXCLUDES:        # nested checkouts (#run7)
            self.assertIn(owned, entries)
        self.assertNotIn("src", entries)                # the target's choice: no
        # Round 1 C1: this run's virtualenvs are NOT in the ini -- nothing
        # target-derived is -- they are on the argv, which cannot grow a key.
        self.assertNotIn("/src/.venv", entries)
        argv_entries = [a for a in seen["argv"] if a.startswith("--exclude=")]
        self.assertEqual(len(argv_entries), 1, seen["argv"])
        self.assertIn("/src/.venv",
                      argv_entries[0][len("--exclude="):].split(","))

    def test_the_ini_is_a_constant_no_tree_can_change(self):
        # Round 1 C1: a venv-shaped directory named `x\ntests = B101` used to add
        # a second key to the `[bandit]` section, and bandit prefers an ini key
        # over the CLI whenever the CLI left that option at its default -- so one
        # `mkdir` chose bandit's `tests`, `skips` or `configfile`.
        plain = self._dispatch(plant_ini=False, plant_venv=False)["ini"]
        hostile = self._dispatch()["ini"]
        self.assertEqual(plain, hostile)
        self.assertEqual(plain, rt.BANDIT_INI_TEXT)
        self.assertEqual(len([ln for ln in plain.splitlines() if "=" in ln]), 1)

    def test_the_argv_value_extends_the_ini_and_never_contradicts_it(self):
        # bandit PREFERS the CLI `--exclude` over the ini's, so the CLI value
        # must carry everything the ini carries -- plus this run's virtualenvs,
        # which the ini deliberately does not name (round 1 C1).
        venvs = [{"path": ".venv", "reason": rt.VENV_MARKER}]
        cmd = rt._with_venv_excludes("bandit", list(rt.TOOL_CMD["bandit"]), venvs)
        argv_value = [a for a in cmd
                      if a.startswith("--exclude=")][0][len("--exclude="):]
        ini_value = self._ini_excludes(rt.BANDIT_INI_TEXT)
        for entry in ini_value:
            self.assertIn(entry, argv_value.split(","))
        self.assertIn("/src/.venv", argv_value.split(","))
        self.assertNotIn("/src/.venv", ini_value)

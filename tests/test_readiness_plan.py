"""#3233: `driver readiness` takes the run's flags and says what that run would meet, while changing
nothing: no byte under the target moves, no host CLI starts, and every temp directory it makes is
gone when it returns."""
import contextlib
import dataclasses
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import scripts.discovery as discovery
import scripts.dispatch as dispatch
import scripts.driver as driver
import scripts.phases.readiness_checks as readiness_checks
import scripts.phases.readiness_plan as readiness_plan
import scripts.phases.tools as tools_phase
import scripts.phases.verify_tools as verify_tools
import scripts.run_manifest as run_manifest
from scripts import hosts
from tests._test_helpers import our_manifest
from tests.phases.test_readiness_verb import _docker_runner
from tests.tools.git_repo import make_git_repo

FILES = {"src/app.py": "def f():\n    return 1\n", "src/util.py": "def g():\n    return 2\n",
         "tests/test_app.py": "def test_f():\n    assert True\n", "README.md": "# x\n"}
MATRIX = "version: 1\ngroups:\n  Core:\n    match: ['src/**']\n    panels: [COD]\n"
EVERY_FLAG = ["--host", "claude", "--security", "redteam", "--fail-on", "high", "--severity", "all",
              "--gate-scope", "all", "--diff-context", "3", "--tools", "--online",
              "--allow-target-build", "--include-fixtures", "--allow-unenforced",
              "--max-per-group", "10", "--max-verify", "5", "-d", "src", "--mode", "headless",
              "--concurrency", "2", "--max-iterations", "3", "--max-budget-usd", "1",
              "--max-turns", "4", "--entry-timeout", "60", "--max-groups", "5", "--reset", "--json"]


def _snapshot(root):
    """Every path under `root` with its type, mode and content, links not followed."""
    seen = {}
    for base, dirs, files in os.walk(root):
        for name in dirs + files:
            path = os.path.join(base, name)
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                body = os.readlink(path)
            elif stat.S_ISREG(info.st_mode):
                with open(path, "rb") as fh:
                    body = fh.read()
            else:
                body = None
            seen[os.path.relpath(path, root)] = (stat.S_IFMT(info.st_mode), info.st_mode & 0o7777,
                                                 body)
    return seen


class _Case(unittest.TestCase):
    def setUp(self):
        self.root = make_git_repo(self, files=dict(FILES, **{"panopticon.yml": MATRIX}))
        self.shells = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.shells, True)
        row = dataclasses.replace(hosts.HOSTS["claude"], registration_dir=self.shells)
        patcher = mock.patch.dict(hosts.HOSTS, {"claude": row})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _readiness(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(readiness_checks, "DOCKER_RUNNER", _docker_runner()), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = driver.main(["readiness", self.root, *argv])
        return code, out.getvalue()

    def _plan(self, *argv):
        code, text = self._readiness("--json", *argv)
        self.assertIn(code, (0, 1))
        return json.loads(text)["run_plan"]

    def _populate_a_run(self, tools_ran=True):
        manifest = our_manifest(self.root, run_manifest.build_manifest(
            target=self.root, review_root=self.root, host="claude", security_mode="standard",
            flags={"max_verify": None}))
        run_manifest.write_manifest(self.root, manifest)
        folder = os.path.join(self.root, ".panopticon", "runs", run_manifest.run_tag(manifest))
        os.makedirs(os.path.join(folder, "tools"), exist_ok=True)
        with open(os.path.join(folder, "tools-ran.json"), "w", encoding="utf-8") as fh:
            json.dump({"ran": tools_ran, "run_id": manifest["run_id"]}, fh)
        with open(os.path.join(folder, "tools", "semgrep.sarif"), "w", encoding="utf-8") as fh:
            fh.write('{"torn')
        with open(os.path.join(folder, "findings-Core-COD.json"), "w", encoding="utf-8") as fh:
            json.dump({"findings": []}, fh)
        os.symlink(run_manifest.run_tag(manifest), os.path.join(self.root, ".panopticon", "runs",
                                                                 "latest"))
        return manifest


class ItChangesNothingTest(_Case):
    def _guarded(self, *argv):
        real = subprocess.Popen
        spawned = []

        def popen(args, *rest, **kw):
            argv0 = args if isinstance(args, str) else list(args)
            names = [os.path.basename(str(a)) for a in (argv0[:2] if isinstance(argv0, list)
                                                       else [argv0])]
            spawned.append(names)
            if names[0] != "git" and names[:2] != ["env", "git"]:
                raise AssertionError("readiness launched %r" % (argv0,))
            return real(args, *rest, **kw)
        with mock.patch.object(subprocess, "Popen", popen), \
                mock.patch.object(os, "system", side_effect=AssertionError("os.system")), \
                mock.patch.object(os, "popen", side_effect=AssertionError("os.popen")):
            result = self._readiness(*argv)
        return result, spawned

    def test_a_populated_run_folder_is_byte_identical_with_every_flag(self):
        self._populate_a_run()
        for argv in (EVERY_FLAG, ["--pr", "7", "--setup", "--discard-batch", "1"], ["-c"],
                     ["--base", "main", "--no-tools"]):
            with self.subTest(argv=argv[:4]):
                before, shells = _snapshot(self.root), _snapshot(self.shells)
                (code, _out), spawned = self._guarded(*argv)
                self.assertIn(code, (0, 1))
                self.assertEqual(before, _snapshot(self.root))
                self.assertEqual(shells, _snapshot(self.shells))
                self.assertTrue(all(names[0] in ("git", "env") for names in spawned), spawned)

    def test_the_run_argv_parses_for_readiness_as_it_does_for_the_loop(self):
        def dests(verb):
            parser = driver.build_parser()
            action = next(a for a in parser._actions if a.dest == "verb")
            return {a.dest for a in action.choices[verb]._actions}
        self.assertEqual(dests("loop") | {"json"}, dests("readiness"))
        args = driver.parse_cli(["readiness", ".", "--security", "redteam"])
        self.assertEqual("redteam", args.security)

    def test_every_temp_directory_is_gone_on_every_exit_path(self):
        made = []
        real = tempfile.mkdtemp

        def mkdtemp(*a, **kw):
            made.append(real(*a, **kw))
            return made[-1]
        cases = ((discovery, "main", lambda: readiness_plan.groups_row(self.root, {}),
                  (None, RuntimeError("boom"), SystemExit(2), KeyboardInterrupt())),
                 (dispatch, "emit_host_agents", lambda: readiness_plan.shells_row("claude"),
                  (None, RuntimeError("boom"), OSError("full"), KeyboardInterrupt())))
        for module, name, call, outcomes in cases:
            for raised in outcomes:
                with self.subTest(name=name, raised=raised), \
                        mock.patch.object(tempfile, "mkdtemp", mkdtemp), \
                        (mock.patch.object(module, name, side_effect=raised) if raised
                         else contextlib.nullcontext()), \
                        contextlib.suppress(KeyboardInterrupt):
                    row = call()
                    self.assertIsInstance(row["detail"], str)
        self.assertGreater(len(made), 4)
        self.assertEqual([], [path for path in made if os.path.exists(path)])


class GroupsTest(_Case):
    def test_it_counts_what_discovery_will_dispatch_and_names_the_derived(self):
        row = self._plan()["groups"]
        self.assertEqual(1, row["committed"])
        self.assertTrue(row["derived"])
        self.assertIn("1 committed + %d derived" % len(row["derived"]), row["detail"])
        for name in row["derived"]:
            self.assertIn(name, row["detail"])

    def test_the_flags_reach_discovery(self):
        with mock.patch.object(discovery, "main", wraps=discovery.main) as main:
            self._plan("--security", "redteam", "-d", "src", "--max-per-group", "7")
        argv = main.call_args.args[0]
        self.assertEqual(["redteam", "src", "7"],
                         [argv[argv.index(flag) + 1] for flag in
                          ("--security", "--scope-dir", "--max-per-group")])
        self.assertNotIn(self.root, argv[argv.index("--out") + 1])

    def test_a_committed_leaf_split_into_chunks_still_counts_as_committed(self):
        row = self._plan("--max-per-group", "1")["groups"]
        self.assertEqual(2, row["committed"])                 # Core_1 and Core_2: src/ holds two
        self.assertFalse([name for name in row["derived"] if name.startswith("Core")])

    def test_a_delta_scope_is_not_counted(self):
        for argv in (["-c"], ["--base", "main"], ["--pr", "3"]):
            with self.subTest(argv=argv), mock.patch.object(discovery, "main") as main:
                row = self._plan(*argv)["groups"]
                self.assertIsNone(row["committed"])
                self.assertIn("delta scope", row["detail"])
                main.assert_not_called()

    def test_a_discovery_failure_is_a_row_never_a_traceback(self):
        for raised in (RuntimeError("boom"), SystemExit(2), ValueError("refused")):
            with self.subTest(raised=raised), \
                    mock.patch.object(discovery, "main", side_effect=raised):
                row = readiness_plan.groups_row(self.root, {})
                self.assertIsNone(row["committed"])
                self.assertIn("discovery could not count them", row["detail"])

    def test_a_refusal_names_discoverys_own_reason(self):
        with open(os.path.join(self.root, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write('version: 1\ngroups:\n  "bad name":\n    match: [x]\n')
        row = readiness_plan.groups_row(self.root, {})
        self.assertIn("could not count them", row["detail"])
        self.assertIn("refusing", row["detail"])


class ShellsTest(_Case):
    def test_missing_then_current_then_stale(self):
        row = readiness_plan.shells_row("claude")
        self.assertEqual(sorted(os.path.basename(path) for path in dispatch.emit_host_agents(
            "claude", tempfile.mkdtemp())), sorted(row["missing"]))
        self.assertIn("missing", row["detail"])
        dispatch.emit_host_agents("claude", self.shells)
        self.assertEqual({"ok": None, "stale": [], "missing": [],
                          "detail": "current in %s" % self.shells},
                         readiness_plan.shells_row("claude"))
        name = sorted(os.listdir(self.shells))[0]
        with open(os.path.join(self.shells, name), "a", encoding="utf-8") as fh:
            fh.write("\nedited\n")
        row = readiness_plan.shells_row("claude")
        self.assertEqual(([name], [], "warn"), (row["stale"], row["missing"], row["ok"]))
        self.assertIn("--emit-host-agents claude", row["detail"])

    def test_the_render_never_writes_the_registration_directory(self):
        dispatch.emit_host_agents("claude", self.shells)
        before = _snapshot(self.shells)
        with mock.patch.object(dispatch, "emit_host_agents",
                               wraps=dispatch.emit_host_agents) as emit:
            readiness_plan.shells_row("claude")
        out_dir = emit.call_args.args[1]
        self.assertNotEqual(os.path.realpath(out_dir), self.shells)
        self.assertFalse(os.path.exists(out_dir))
        self.assertEqual(before, _snapshot(self.shells))

    def test_a_link_in_the_registration_directory_is_not_followed(self):
        dispatch.emit_host_agents("claude", self.shells)
        name = sorted(os.listdir(self.shells))[0]
        real = os.path.join(self.shells, name)
        moved = real + ".real"
        os.rename(real, moved)
        os.symlink(moved, real)
        row = readiness_plan.shells_row("claude")
        self.assertIn("could not compare", row["detail"])

    def test_a_host_with_no_shells_says_so(self):
        self.assertIn("n/a", readiness_plan.shells_row("generic")["detail"])


class EnforcementTest(_Case):
    def test_the_no_launch_half_is_measured_and_the_stop_is_never_promised(self):
        row = self._plan()["enforcement"]
        self.assertEqual(hosts.REFUTED, row["tool_policy_enforced"])      # no shells emitted yet
        self.assertIn("from the registered shells", row["detail"])
        self.assertIn("can't say whether the loop will stop", row["detail"])
        dispatch.emit_host_agents("claude", self.shells)
        self.assertEqual(hosts.PROVEN, self._plan()["enforcement"]["tool_policy_enforced"])

    def test_with_the_acknowledgement_it_says_what_the_run_will_do(self):
        row = self._plan("--allow-unenforced")["enforcement"]
        self.assertIn("recorded, not refused", row["detail"])

    def test_a_host_whose_probe_launches_is_not_probed(self):
        with mock.patch.object(readiness_plan.probes_common,
                               "probe_registered_shell_tools") as probe:
            row = readiness_plan.enforcement_row("codex", {})
        probe.assert_not_called()
        self.assertIsNone(row["tool_policy_enforced"])
        self.assertIn("needs a launch", row["detail"])


class GateAndFlagsTest(_Case):
    def test_no_fail_on_warns_that_the_gate_is_off(self):
        row = self._plan()["gate"]
        self.assertEqual("warn", row["ok"])
        self.assertIn("gate: OFF", row["detail"])

    def test_a_fail_on_flag_or_a_committed_one_gates(self):
        self.assertEqual("high", self._plan("--fail-on", "high")["gate"]["fail_on"])
        with open(os.path.join(self.root, "panopticon.yml"), "a", encoding="utf-8") as fh:
            fh.write("settings:\n  fail_on: medium\n")
        self.assertEqual("medium", self._plan()["gate"]["fail_on"])

    def test_a_committed_security_mode_is_what_the_row_and_discovery_use(self):
        with open(os.path.join(self.root, "panopticon.yml"), "a", encoding="utf-8") as fh:
            fh.write("settings:\n  security: redteam\n")
        with mock.patch.object(discovery, "main", wraps=discovery.main) as main:
            self.assertIn("security redteam", self._plan()["flags"]["detail"])
        argv = main.call_args.args[0]
        self.assertEqual("redteam", argv[argv.index("--security") + 1])

    def test_the_flags_row_says_reset_does_nothing_here(self):
        detail = self._plan("--reset", "--security", "redteam", "-d", "src")["flags"]["detail"]
        self.assertIn("security redteam", detail)
        self.assertIn("scope directory src", detail)
        self.assertIn("readiness does not", detail)
        self.assertNotIn("--reset", self._plan()["flags"]["detail"])

    def test_the_rows_render_in_the_table_and_none_gates(self):
        code, text = self._readiness("--host", "generic")
        for name in readiness_plan.ROWS:
            self.assertIn("  %s " % name, text)
        with mock.patch.object(readiness_plan, "rows", return_value={
                name: {"ok": "warn", "detail": "x"} for name in readiness_plan.ROWS}):
            self.assertEqual(code, self._readiness("--host", "generic")[0])


class ToolFindingsTest(_Case):
    def test_a_fresh_target_gives_no_number(self):
        row = self._plan()["tool-findings"]
        self.assertIsNone(row["count"])
        self.assertIn("not known until the tools phase runs", row["detail"])
        self.assertNotIn("queue", row["detail"])

    def test_a_resume_counts_with_the_verify_phases_own_function(self):
        self._populate_a_run()
        with mock.patch.object(verify_tools, "_tool_verify_queue",
                               return_value=[("q1", {}), ("q2", {})]) as queue:
            row = self._plan()["tool-findings"]
        self.assertEqual(2, row["count"])
        self.assertIn("before review merges", row["detail"])
        self.assertEqual(self.root, queue.call_args.args[0])

    def test_torn_or_hostile_tool_output_is_a_row_not_a_crash(self):
        self._populate_a_run()
        self.assertIsInstance(self._plan()["tool-findings"]["detail"], str)
        for raised in (ValueError("torn"), RecursionError(), OSError("gone"), KeyError("x")):
            with self.subTest(raised=raised), \
                    mock.patch.object(verify_tools, "_tool_verify_queue", side_effect=raised):
                row = self._plan()["tool-findings"]
                self.assertIsNone(row["count"])
                self.assertIn("could not be read", row["detail"])

    def test_a_scan_that_did_not_run_is_not_counted(self):
        self._populate_a_run(tools_ran=False)
        with mock.patch.object(verify_tools, "_tool_verify_queue") as queue:
            self.assertIsNone(self._plan()["tool-findings"]["count"])
        queue.assert_not_called()

    def test_the_loop_says_it_when_the_tools_phase_ends(self):
        manifest = {"flags": {"max_verify": None}}
        with mock.patch.object(verify_tools, "_tool_verify_queue", return_value=[1, 2, 3]):
            note = tools_phase._tool_findings_note(self.root, manifest)
        self.assertEqual("3 tool finding(s) will each get an advisor, before review merges "
                         "(uncapped)", note)
        self.assertNotIn("queue", note)
        with mock.patch.object(verify_tools, "_tool_verify_queue", side_effect=ValueError("x")):
            self.assertEqual("", tools_phase._tool_findings_note(self.root, manifest))
        with mock.patch.object(verify_tools, "_tool_verify_queue", return_value=[1]):
            self.assertIn("capped at 4", tools_phase._tool_findings_note(
                self.root, {"flags": {"max_verify": 4}}))


class OnlineToolsAndInstallTest(_Case):
    def test_online_only_adapters_are_named_when_withheld(self):
        row = self._plan()["online-tools"]
        self.assertEqual(["npm-audit", "pip-audit"], row["withheld"])
        self.assertIn("requested_unavailable", row["detail"])
        self.assertEqual([], self._plan("--online")["online-tools"]["withheld"])
        self.assertIn("--no-tools", self._plan("--no-tools")["online-tools"]["detail"])

    def test_a_different_copy_of_the_skill_is_named(self):
        self.assertEqual([], readiness_plan.install_row(self.root)["elsewhere"])
        other = os.path.join(self.root, "skill", "scripts")
        os.makedirs(other)
        open(os.path.join(other, "driver.py"), "w").close()
        row = readiness_plan.install_row(self.root)
        self.assertEqual("warn", row["ok"])
        self.assertIn(os.path.realpath(os.path.join(self.root, "skill")), row["detail"])
        self.assertEqual(readiness_plan.SKILL_ROOT, row["skill"])

    def test_this_copy_reached_by_another_path_is_not_a_different_copy(self):
        os.symlink(readiness_plan.SKILL_ROOT, os.path.join(self.root, "skill"))
        self.assertEqual([], readiness_plan.install_row(self.root)["elsewhere"])

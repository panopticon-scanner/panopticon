"""#3735: delta review is withdrawn in 5.4. Every way into it is refused, with one message,
before anything is launched or written."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import scripts.delta_withdrawn as delta_withdrawn
import scripts.discovery as discovery
import scripts.driver as driver
import scripts.phases.readiness as readiness
import scripts.phases.runio as runio
import scripts.repo_config as repo_config
import scripts.phases.synthesize as synthesize_phase
import scripts.run_manifest as run_manifest
import scripts.synthesize as synthesize

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER_PY = os.path.join(ROOT, "skill", "scripts", "driver.py")
WITHDRAWN = "delta review was withdrawn in 5.4 (#3735) and removed in 5.5 (#3736): "
ADVICE = "Run a whole-repository review, or scope one with -f, -d, -g or --files."

# Each flag on its own, as an operator types it, and how the refusal names it.
DRIVER = (("--pr", ["--pr", "7"]), ("--changes (-c)", ["--changes"]), ("--changes (-c)", ["-c"]),
          ("--base", ["--base", "main"]), ("--gate-scope", ["--gate-scope", "on-diff"]),
          ("--gate-scope", ["--gate-scope", "all"]), ("--diff-context", ["--diff-context", "5"]),
          # #3737 review F1: zero is a value. `0 == False`, and it read as not given.
          ("--pr", ["--pr", "0"]), ("--pr", ["--pr=0"]), ("--pr", ["--pr", "-0"]),
          ("--pr", ["--pr", "7", "--pr", "0"]),
          ("--diff-context", ["--diff-context", "0"]), ("--diff-context", ["--diff-context=0"]),
          ("--diff-context", ["--diff-c", "0"]), ("--base", ["--base", ""]))


def refused(call, argv):
    """(exit code, stderr) of an entry point that must stop on `argv`."""
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        try:
            code = call(argv)
        except SystemExit as stop:
            code = stop.code
    return code, err.getvalue()


class TestTheDriverRefusesEveryDeltaFlag(unittest.TestCase):
    def test_each_flag_on_each_verb_that_takes_it(self):
        for verb in ("run", "loop", "readiness"):
            for name, flags in DRIVER:
                with self.subTest(verb=verb, flags=flags), \
                        mock.patch.object(runio, "resolve_review_root") as resolve, \
                        mock.patch("scripts.orchestrate.main_verb") as loop, \
                        mock.patch("scripts.host_probes.run_probes") as probes, \
                        mock.patch("scripts.diff_map.acquire_pr") as acquire:
                    code, err = refused(driver.main, [verb, "x"] + flags)
                    self.assertEqual(2, code)
                    self.assertIn(WITHDRAWN + name + " is refused. " + ADVICE, err)
                    for touched in (resolve, loop, probes, acquire):    # nothing was started
                        touched.assert_not_called()

    def test_persist_refuses_the_two_it_takes(self):
        for name, flags in (("--pr", ["--pr", "7"]), ("--base", ["--base", "main"]),
                            ("--pr", ["--pr", "0"]), ("--pr", ["--pr=0"])):
            with self.subTest(flags=flags), \
                    mock.patch.object(runio, "resolve_review_root") as resolve, \
                    mock.patch("scripts.orchestrate.main_verb") as persist:
                code, err = refused(driver.main, ["persist", "scout-app", "x"] + flags)
                self.assertEqual(2, code)
                self.assertIn(WITHDRAWN + name + " is refused. ", err)
                resolve.assert_not_called()
                persist.assert_not_called()

    def test_several_flags_are_named_in_one_message(self):
        code, err = refused(driver.main, ["loop", "x", "--pr", "7", "--base", "main",
                                          "--gate-scope", "all"])
        self.assertEqual(2, code)
        self.assertIn(WITHDRAWN + "--pr, --base, --gate-scope are refused. " + ADVICE, err)
        self.assertEqual(1, err.count("delta review was withdrawn"))

    def test_files_with_a_base_is_refused_and_files_alone_is_not(self):
        """`--files` with `--base` wrote a hunk map and scoped the gate to it. `--files`
        alone is a scope, not a delta, and is unchanged."""
        code, err = refused(driver.main, ["run", "x", "--files", "a.py", "--base", "main"])
        self.assertEqual(2, code)
        self.assertIn(WITHDRAWN + "--base is refused. ", err)
        for scope in (["--files", "a.py", "b.py"], ["-f", "a.py"], ["-d", "src"], ["-g", "Core"], []):
            with self.subTest(scope=scope):
                args = driver.parse_cli(["run", "x"] + scope)
                self.assertEqual([], delta_withdrawn.given(args, delta_withdrawn.DRIVER_FLAGS))

    def test_the_verbs_that_take_no_delta_flag_do_not_know_them(self):
        for verb in ("setup", "migrate-config"):
            for flags in (["--pr", "7"], ["--base", "main"], ["-c"], ["--gate-scope", "all"]):
                with self.subTest(verb=verb, flags=flags):
                    code, err = refused(driver.main, [verb, "x"] + flags)
                    self.assertEqual(2, code)
                    self.assertIn("unrecognized arguments", err)

    def test_the_whole_command_line_as_a_child_process(self):
        """The real `driver.py`, in a directory that is no repository: exit 2 and
        nothing written, for every verb that takes the flags. (Run through `env`: the
        PR scan wants a command that starts with a fixed program, and our own scan
        honours no inline suppression.)"""
        with tempfile.TemporaryDirectory() as empty:
            for argv in (["loop", ".", "--pr", "7"], ["run", ".", "-c"],
                         ["readiness", ".", "--base", "main"],
                         ["persist", "scout-app", "--pr", "7", "."]):
                with self.subTest(argv=argv):
                    done = subprocess.run(["env", sys.executable, DRIVER_PY, *argv], cwd=empty,
                                          capture_output=True, text=True, timeout=120, check=False)
                    self.assertEqual(2, done.returncode, done.stderr)
                    self.assertIn(WITHDRAWN, done.stderr)
                    self.assertEqual([], os.listdir(empty))


class TestARunStartedAsADeltaReviewIsNotResumed(unittest.TestCase):
    """A bare `driver run` or `driver loop` resumed whatever the manifest said, so a
    run started with `-c` went on as a delta run with no flag typed at all."""

    DELTA = ({"scope": {"mode": "changed", "target": None}}, {"base": "main"}, {"pr": 7},
             {"pr": 0}, {"pr_base": "main"}, {"worktree": "/tmp/pr-7"})

    def test_what_makes_a_manifest_a_delta_run(self):
        whole = {"scope": {"mode": "repo", "target": None}, "base": None, "pr": None,
                 "pr_base": None, "worktree": None, "flags": {"gate_scope": "all"}}
        self.assertFalse(delta_withdrawn.is_delta_run(whole))
        for scope in ("file", "directory", "group", "files"):
            self.assertFalse(delta_withdrawn.is_delta_run(dict(whole, scope={"mode": scope})))
        for fields in self.DELTA:
            with self.subTest(fields=fields):
                self.assertTrue(delta_withdrawn.is_delta_run(dict(whole, **fields)))
        for not_a_manifest in (None, [], "changed", 7):
            self.assertFalse(delta_withdrawn.is_delta_run(not_a_manifest))

    def test_run_loop_and_persist_stop_before_anything_starts(self):
        # #3782: `run` and `loop` make this check themselves, with the review root held, so
        # each is driven as far as that check here: a real directory to hold, and what
        # comes after it (first contact, the engine, a probe) watched for a call.
        import scripts.loop_setup as loop_setup
        for fields in self.DELTA:
            for verb in ("run", "loop", "persist"):
                argv = [verb] + (["scout-app"] if verb == "persist" else []) + ["x"]
                root = os.path.realpath(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, root, ignore_errors=True)
                with self.subTest(verb=verb, fields=fields), \
                        mock.patch.object(runio, "resolve_review_root",
                                          return_value=(root, None, None)), \
                        mock.patch.object(run_manifest, "load_manifest",
                                          return_value=dict(fields, run_id="R")), \
                        mock.patch("scripts.orchestrate.persist_cli") as persist, \
                        mock.patch.object(driver.first_contact, "assess") as contact, \
                        mock.patch.object(loop_setup.first_contact, "assess_loop") as loop, \
                        mock.patch.object(driver.engine, "run_engine") as run, \
                        mock.patch("scripts.host_probes.run_probes") as probes:
                    out, err = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        code = driver.main(argv)
                    said = err.getvalue() if verb == "persist" else out.getvalue()
                    self.assertEqual(2 if verb == "persist" else 1, code)
                    self.assertIn(WITHDRAWN + "this run folder was started as a delta review "
                                  "and cannot be resumed (--reset discards it and starts a "
                                  "whole-repository run). " + ADVICE, said)
                    for touched in (persist, contact, loop, run, probes):
                        touched.assert_not_called()
                    self.assertEqual(os.listdir(root), [])        # nothing written under it

    def test_a_reset_and_a_whole_repository_run_go_on(self):
        whole = {"scope": {"mode": "repo", "target": None}, "run_id": "R"}
        for argv, manifest in ((["run", "x", "--reset"], {"pr": 7, "run_id": "R"}),
                               (["run", "x"], whole), (["run", "x"], None)):
            with self.subTest(argv=argv, manifest=manifest), \
                    mock.patch.object(runio, "resolve_review_root",
                                      return_value=("/root", None, None)), \
                    mock.patch.object(run_manifest, "load_manifest", return_value=manifest), \
                    mock.patch.object(driver, "run", return_value={"status": "complete"}) as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                driver.main(argv)
                run.assert_called_once()


    def test_readiness_does_not_say_the_loop_would_resume_it(self):
        with tempfile.TemporaryDirectory() as root:
            for scope, resumable in (({"mode": "changed", "target": None}, False),
                                     ({"mode": "repo", "target": None}, True)):
                manifest = run_manifest.build_manifest(
                    target=root, review_root=root, host="claude", security_mode="standard",
                    scope=scope)
                tag = run_manifest.run_tag(manifest)
                os.makedirs(os.path.join(root, ".panopticon", "runs", tag), exist_ok=True)
                with self.subTest(scope=scope), \
                        mock.patch.object(readiness, "_trusted_manifest", return_value=manifest):
                    row = readiness._existing_run_row(root)
                if resumable:
                    self.assertEqual("started", row["status"])
                    self.assertNotIn("withdrawn", row["detail"])
                else:
                    self.assertEqual((tag, "error", 0), (row["tag"], row["status"], row["pending"]))
                    self.assertIn("was started as a delta review and cannot be resumed: delta "
                                  "review was withdrawn in 5.4 (#3735) and removed in 5.5 "
                                  "(#3736); `--reset` starts a whole-repository run",
                                  row["detail"])


class TestTheChildScriptsRefuseThemToo(unittest.TestCase):
    """`discovery.py` writes the hunk map and `synthesize.py` reads it. The driver runs
    both as children; a host agent can run either by hand."""

    def test_discovery_refuses_each_flag_and_writes_nothing(self):
        cases = (("--scope-changed", ["--scope-changed"]), ("--base", ["--base", "main"]),
                 ("--base", ["--scope-files", "a.py", "--base", "main"]),
                 ("--pr-base", ["--pr-base", "main"]), ("--pr-worktree", ["--pr-worktree"]),
                 ("--diff-context", ["--diff-context", "5"]),
                 ("--diff-context", ["--diff-context", "0"]), ("--diff-context", ["--diff-context=0"]))
        with tempfile.TemporaryDirectory() as d:
            for name, flags in cases:
                with self.subTest(flags=flags):
                    out = os.path.join(d, "groups.json")
                    code, err = refused(discovery.main,
                                        ["--repo-scan", "--repo", d, "--out", out] + flags)
                    self.assertEqual(2, code)
                    self.assertIn("panopticon: " + WITHDRAWN + name + " is refused. " + ADVICE, err)
                    self.assertEqual([], os.listdir(d))

    def test_synthesize_refuses_each_flag_and_writes_nothing(self):
        cases = (("--changes (-c)", ["--changes"]), ("--changes (-c)", ["-c"]),
                 ("--diff-hunks", ["--diff-hunks", "diff-hunks.json"]),
                 ("--diff-hunks-run-id", ["--diff-hunks-run-id", "R"]),
                 ("--gate-scope", ["--gate-scope", "on-diff"]),      # the default, typed
                 ("--gate-scope", ["--gate-scope", "all"]),
                 ("--diff-context", ["--diff-context", "5"]),        # the default, typed
                 ("--diff-context", ["--diff-context", "0"]), ("--diff-context", ["--diff-context=0"]))
        with tempfile.TemporaryDirectory() as d:
            for name, flags in cases:
                with self.subTest(flags=flags):
                    code, err = refused(synthesize.main,
                                        ["--target", d, "--out", os.path.join(d, "report.json")]
                                        + flags)
                    self.assertEqual(2, code)
                    self.assertIn("synthesize: " + WITHDRAWN + name + " is refused. " + ADVICE, err)
                    self.assertEqual([], os.listdir(d))

    def test_an_abbreviated_flag_is_refused_as_the_flag(self):
        """argparse takes a unique prefix. The refusal reads the parsed value, not the
        text of the argument."""
        code, err = refused(synthesize.main, ["--gate-sc", "all", "--out", "/nowhere/report.json"])
        self.assertEqual(2, code)
        self.assertIn(WITHDRAWN + "--gate-scope is refused. ", err)
        code, err = refused(driver.main, ["loop", "x", "--gate-sc", "all"])
        self.assertEqual(2, code)
        self.assertIn(WITHDRAWN + "--gate-scope is refused. ", err)

    def test_the_parsers_defaults_are_what_they_were(self):
        """The refusal asks whether a flag was typed; it does not change what an
        untyped one means to the code below it."""
        args = synthesize.build_parser().parse_args([])
        self.assertEqual(("on-diff", 5, None, False),
                         (args.gate_scope, args.diff_context, args.diff_hunks, args.changes))
        self.assertEqual([], delta_withdrawn.given(
            delta_withdrawn.typed(synthesize.build_parser(), [], delta_withdrawn.SYNTHESIZE_FLAGS),
            delta_withdrawn.SYNTHESIZE_FLAGS))


class TestZeroIsAValue(unittest.TestCase):
    """#3737 review F1. `given` tested `not in (None, False)`, and `0 == False`: `--pr 0`
    went on to `gh pr view 0`, a PR worktree and a delta manifest."""

    def test_given_reads_a_flag_by_identity(self):
        flags = (("pr", "--pr"), ("changes", "--changes"), ("base", "--base"))
        for value, typed in ((0, True), (0.0, True), ("", True), ("0", True), (7, True),
                             (True, True), ([], True), (None, False), (False, False)):
            with self.subTest(value=value):
                args = mock.Mock(spec=["pr", "changes", "base"], pr=value, changes=False, base=None)
                self.assertEqual(["--pr"] if typed else [], delta_withdrawn.given(args, flags))

    def test_the_real_driver_stops_on_pr_zero_before_it_looks_for_a_pull_request(self):
        with tempfile.TemporaryDirectory() as empty:
            for argv in (["run", ".", "--no-tools", "--pr", "0"], ["loop", ".", "--pr=0"],
                         ["readiness", ".", "--pr", "0"], ["persist", "x", ".", "--pr", "0"],
                         ["run", ".", "--diff-context", "0"]):
                with self.subTest(argv=argv):
                    done = subprocess.run(["env", sys.executable, DRIVER_PY, *argv], cwd=empty,
                                          capture_output=True, text=True, timeout=120, check=False)
                    self.assertEqual(2, done.returncode, done.stderr)
                    self.assertIn(WITHDRAWN, done.stderr)
                    self.assertNotIn("Traceback", done.stderr)
                    self.assertEqual([], os.listdir(empty))


class TestNoCodeLiftsTheRefusal(unittest.TestCase):
    """The delta code's own tests reach it with `refuse_delta=False`. That is acceptable
    only while nothing a command line can run passes it: read from the source of every
    module under `skill/scripts` and `devtools`."""

    ENTRY = {"main", "_repo_scan", "_repo_scan_args"}

    def modules(self):
        for top in ("skill/scripts", "devtools"):
            for folder, _dirs, names in os.walk(os.path.join(ROOT, top)):
                for name in sorted(names):
                    if name.endswith(".py"):
                        yield os.path.join(folder, name)

    def test_nothing_passes_refuse_delta_and_nothing_else_reads_it(self):
        import ast
        seen, holders = 0, set()
        for path in self.modules():
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), path)
            seen += 1
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    self.assertEqual([], [k.arg for k in node.keywords if k.arg == "refuse_delta"],
                                     "%s:%d passes refuse_delta" % (path, node.lineno))
                    called = getattr(node.func, "attr", getattr(node.func, "id", None))
                    if called in self.ENTRY:
                        # ...or by position: only the parameter itself, handed down.
                        extra = node.args[1:]
                        self.assertTrue(all(isinstance(arg, ast.Name) and arg.id == "refuse_delta"
                                            for arg in extra),
                                        "%s:%d passes a second argument to %s" % (
                                            path, node.lineno, called))
                if isinstance(node, ast.Name) and node.id == "refuse_delta":
                    holders.add(os.path.relpath(path, ROOT))
                if isinstance(node, ast.arg) and node.arg == "refuse_delta":
                    holders.add(os.path.relpath(path, ROOT))
        self.assertGreater(seen, 150)
        self.assertEqual({"skill/scripts/discovery.py", "skill/scripts/synthesize.py"}, holders)

    def test_the_parameter_defaults_to_refusing(self):
        import inspect
        for function in (discovery.main, discovery._repo_scan, discovery._repo_scan_args,
                         synthesize.main):
            self.assertIs(True, inspect.signature(function).parameters["refuse_delta"].default)


class TestAHunkMapLeftInARunFolderTurnsNothingOn(unittest.TestCase):
    """The driver handed `--diff-hunks` to synthesize whenever `diff-hunks.json` was in the
    run folder, whatever the manifest said: on a resume, a file left on disk was enough."""

    def argv_for(self, manifest):
        with tempfile.TemporaryDirectory() as root:
            root = os.path.realpath(root)
            os.makedirs(runio._pano(root))
            with open(runio._pano(root, "diff-hunks.json"), "w", encoding="utf-8") as fh:
                json.dump({"schema_version": 1, "base": "main", "run_id": "R",
                           "hunks": {"a.py": [[1, 5]]}}, fh)
            captured = {}

            def child(cmd, **_kw):
                captured["cmd"] = list(cmd)
                with open(cmd[cmd.index("--out") + 1], "w", encoding="utf-8") as fh:
                    json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
                return mock.Mock(returncode=0, stdout="", stderr="")
            with mock.patch("scripts.phases.child._run_child", side_effect=child), \
                    contextlib.redirect_stderr(io.StringIO()):
                synthesize_phase.synthesize_execute(root, manifest)
            return captured["cmd"]

    def test_a_whole_repository_run_hands_over_no_hunk_map_and_no_gate_scope(self):
        # `gate_scope: all` is what a committed config can still say; `diff_context`
        # is what an older run's manifest could hold.
        cmd = self.argv_for({"run_id": "R", "security_mode": "standard",
                             "scope": {"mode": "repo", "target": None},
                             "flags": {"fail_on": "high", "gate_scope": "all",
                                       "diff_context": 9}})
        for flag in ("--diff-hunks", "--diff-hunks-run-id", "--gate-scope", "--diff-context"):
            self.assertNotIn(flag, cmd)
        self.assertEqual("high", cmd[cmd.index("--fail-on") + 1])
        # ...so the child the driver starts is never one its own refusal stops.
        parsed = delta_withdrawn.typed(synthesize.build_parser(), cmd[2:],
                                       delta_withdrawn.SYNTHESIZE_FLAGS)
        self.assertEqual([], delta_withdrawn.given(parsed, delta_withdrawn.SYNTHESIZE_FLAGS))

    def test_the_discovery_child_is_handed_no_diff_context_either(self):
        """#3737 review F2: a run started on 5.3 with `--diff-context N` and no diff is a
        whole-repository run. Its manifest still holds the flag, and the driver forwarded
        it: the child then refused a flag nobody had typed."""
        import scripts.phases.discovery as discovery_phase
        captured = {}

        def child(cmd, **_kw):
            captured["cmd"] = list(cmd)
            return mock.Mock(returncode=2, stdout="", stderr="stopped here")
        for scope, forwarded in (({"mode": "repo", "target": None}, False),
                                 ({"mode": "files", "target": ["a.py"]}, False),
                                 ({"mode": "changed", "target": None}, True)):
            manifest = {"run_id": "R", "security_mode": "standard", "scope": scope,
                        "flags": {"diff_context": 0}}
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as root, \
                    mock.patch("scripts.phases.child._run_child", side_effect=child), \
                    contextlib.redirect_stderr(io.StringIO()):
                root = os.path.realpath(root)
                os.makedirs(os.path.join(root, ".panopticon"))
                with open(os.path.join(root, repo_config.CONFIG_NAMES[0]), "w",
                          encoding="utf-8") as fh:
                    fh.write("version: 1\ngroups:\n  Core:\n    match: ['src/**']\n")
                with self.assertRaises(runio.DriverError):
                    discovery_phase.discovery_execute(root, manifest)
                self.assertEqual(forwarded, "--diff-context" in captured["cmd"])


if __name__ == "__main__":
    unittest.main()

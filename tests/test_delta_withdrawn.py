"""#3735, #3736: delta review was withdrawn in 5.4 and its code removed in 5.5. Every way
into it is still refused, by name and with one message, before anything is launched or
written -- never as argparse's "unrecognized arguments"."""
import ast
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
UNKNOWN = "unrecognized arguments"
NO_VALUE = "expected one argument"

# Each flag on its own, as an operator types it, and how the refusal names it.
DRIVER = (("--pr", ["--pr", "7"]), ("--changes (-c)", ["--changes"]), ("--changes (-c)", ["-c"]),
          ("--base", ["--base", "main"]), ("--gate-scope", ["--gate-scope", "on-diff"]),
          ("--gate-scope", ["--gate-scope", "all"]), ("--diff-context", ["--diff-context", "5"]),
          # #3737 review F1: zero is a value. `0 == False`, and it read as not given.
          ("--pr", ["--pr", "0"]), ("--pr", ["--pr=0"]), ("--pr", ["--pr", "-0"]),
          ("--pr", ["--pr", "7", "--pr", "0"]),
          ("--diff-context", ["--diff-context", "0"]), ("--diff-context", ["--diff-context=0"]),
          ("--diff-context", ["--diff-c", "0"]), ("--base", ["--base", ""]),
          # #3736: a value the flag never took, and a flag it could not be typed beside.
          # Each was argparse's own error ("invalid choice", "invalid int value", "not
          # allowed with argument"), which named choices that no longer exist.
          ("--gate-scope", ["--gate-scope", "changed"]), ("--pr", ["--pr", "abc"]),
          ("--diff-context", ["--diff-context", "many"]),
          ("--changes (-c)", ["-c", "-d", "src"]), ("--changes (-c)", ["-f", "a.py", "--changes"]),
          ("--changes (-c)", ["--files", "a.py", "b.py", "-c"]),
          # #3800 review, item 1: a flag that takes a value, typed with none. Last on the
          # line, or before another option. Each was "expected one argument".
          ("--pr", ["--pr"]), ("--base", ["--base"]), ("--gate-scope", ["--gate-scope"]),
          ("--diff-context", ["--diff-context"]), ("--pr", ["--pr", "--host", "claude"]),
          ("--base", ["--base", "--host", "claude"]), ("--pr, --base", ["--pr", "--base"]))


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
                        mock.patch("scripts.host_probes.run_probes") as probes:
                    code, err = refused(driver.main, [verb, "x"] + flags)
                    self.assertEqual(2, code)
                    self.assertIn(WITHDRAWN + name + (" are" if ", " in name else " is")
                                  + " refused. " + ADVICE + "\n", err)
                    self.assertNotIn(UNKNOWN, err)
                    self.assertNotIn(NO_VALUE, err)
                    for touched in (resolve, loop, probes):            # nothing was started
                        touched.assert_not_called()

    def test_persist_refuses_the_two_it_takes(self):
        for name, flags in (("--pr", ["--pr", "7"]), ("--base", ["--base", "main"]),
                            ("--pr", ["--pr", "0"]), ("--pr", ["--pr=0"]),
                            ("--pr", ["--pr", "abc"]), ("--base", ["--base", ""]),
                            ("--pr", ["--pr"]), ("--base", ["--base"]),
                            ("--base", ["--base", "--setup"])):
            with self.subTest(flags=flags), \
                    mock.patch.object(runio, "resolve_review_root") as resolve, \
                    mock.patch("scripts.orchestrate.main_verb") as persist:
                code, err = refused(driver.main, ["persist", "scout-app", "x"] + flags)
                self.assertEqual(2, code)
                self.assertIn(WITHDRAWN + name + " is refused. " + ADVICE + "\n", err)
                self.assertNotIn(UNKNOWN, err)
                self.assertNotIn(NO_VALUE, err)
                resolve.assert_not_called()
                persist.assert_not_called()

    def test_several_flags_are_named_in_one_message(self):
        code, err = refused(driver.main, ["loop", "x", "--pr", "7", "--base", "main",
                                          "--gate-scope", "all"])
        self.assertEqual(2, code)
        self.assertIn(WITHDRAWN + "--pr, --base, --gate-scope are refused. " + ADVICE, err)
        self.assertEqual(1, err.count("delta review was withdrawn"))
        self.assertNotIn(UNKNOWN, err)

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
                    self.assertIn(UNKNOWN, err)      # they never took one

    def test_every_refused_flag_is_one_its_parser_still_takes(self):
        """The refusal reads a parsed value, so a flag dropped from a parser would fall
        back to argparse's own error. Each dest in the three tables is on its parser,
        unset until typed."""
        parser = driver.build_parser()
        for verb in ("run", "loop", "readiness"):
            args = parser.parse_args([verb, "x"])
            self.assertEqual([None, False, None, None, None],
                             [getattr(args, dest) for dest, _n in delta_withdrawn.DRIVER_FLAGS])
        persist = parser.parse_args(["persist", "scout-app", "x"])
        self.assertEqual((None, None), (persist.pr, persist.base))
        args = synthesize.build_parser().parse_args([])
        self.assertEqual([None] * 5,
                         [getattr(args, dest) for dest, _n in delta_withdrawn.SYNTHESIZE_FLAGS])
        scan, _repo = discovery._repo_scan_args(["--repo-scan", "x"])
        self.assertEqual([False, None, None, False, None],
                         [getattr(scan, dest) for dest, _n in delta_withdrawn.DISCOVERY_FLAGS])

    def test_the_help_says_what_became_of_each_flag(self):
        for verb in ("run", "loop", "readiness", "persist"):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
                driver.build_parser().parse_args([verb, "--help"])
            text = " ".join(out.getvalue().split())
            self.assertEqual(2 if verb == "persist" else 5,
                             text.count("Removed in 5.5 and refused (#3736): a delta-review flag"),
                             verb)
            for gone in ("on-diff", "merge-base", "pull request", "worktree", "{on-diff,all}"):
                self.assertNotIn(gone, text, verb)

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
                    self.assertNotIn(UNKNOWN, done.stderr)
                    self.assertEqual([], os.listdir(empty))


class TestARunStartedAsADeltaReviewIsNotResumed(unittest.TestCase):
    """A bare `driver run` or `driver loop` resumed whatever the manifest said, so a
    run started with `-c` went on as a delta run with no flag typed at all. 5.5 writes
    none of these keys; a run folder from 5.3 or earlier can still hold them."""

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
                                          return_value=root), \
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
                                      return_value="/root"), \
                    mock.patch.object(run_manifest, "load_manifest", return_value=manifest), \
                    mock.patch.object(driver, "run", return_value={"status": "complete"}) as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                driver.main(argv)
                run.assert_called_once()

    def test_a_reset_passes_the_check_that_run_and_loop_make_themselves(self):
        """`--reset` discards the folder, so the refusal does not apply. `run` and `loop`
        are driven to the step after the check (first contact), which stops them here."""
        import scripts.first_contact as first_contact
        import scripts.loop_setup as loop_setup
        reached = first_contact.FirstContactHalt("reached first contact")
        for fields in self.DELTA:
            for verb in ("run", "loop"):
                root = os.path.realpath(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, root, ignore_errors=True)
                with self.subTest(verb=verb, fields=fields), \
                        mock.patch.object(runio, "resolve_review_root", return_value=root), \
                        mock.patch.object(run_manifest, "load_manifest",
                                          return_value=dict(fields, run_id="R")), \
                        mock.patch.object(driver.first_contact, "assess", side_effect=reached), \
                        mock.patch.object(loop_setup.first_contact, "assess_loop",
                                          side_effect=reached), \
                        mock.patch.object(driver.engine, "run_engine") as run:
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                        driver.main([verb, "x", "--reset"])
                    self.assertIn("reached first contact", out.getvalue())
                    self.assertNotIn("delta review", out.getvalue())
                    run.assert_not_called()

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
    """`discovery.py` wrote the hunk map and `synthesize.py` read it. The driver runs
    both as children; a host agent can run either by hand."""

    def test_discovery_refuses_each_flag_and_writes_nothing(self):
        cases = (("--scope-changed", ["--scope-changed"]), ("--base", ["--base", "main"]),
                 ("--base", ["--scope-files", "a.py", "--base", "main"]),
                 ("--pr-base", ["--pr-base", "main"]), ("--pr-worktree", ["--pr-worktree"]),
                 ("--diff-context", ["--diff-context", "5"]),
                 ("--diff-context", ["--diff-context", "0"]), ("--diff-context", ["--diff-context=0"]),
                 ("--diff-context", ["--diff-context", "many"]),
                 ("--scope-changed", ["--scope-changed", "--scope-dir", "src"]),
                 ("--scope-changed", ["--scope-files", "a.py", "--scope-changed"]),
                 ("--base", ["--base"]), ("--pr-base", ["--pr-base"]),
                 ("--diff-context", ["--diff-context"]),
                 ("--pr-base", ["--pr-base", "--security", "redteam"]))
        with tempfile.TemporaryDirectory() as d:
            for name, flags in cases:
                with self.subTest(flags=flags):
                    out = os.path.join(d, "groups.json")
                    code, err = refused(discovery.main,
                                        ["--repo-scan", "--repo", d, "--out", out] + flags)
                    self.assertEqual(2, code)
                    self.assertIn("panopticon: " + WITHDRAWN + name + " is refused. " + ADVICE, err)
                    self.assertNotIn(UNKNOWN, err)
                    self.assertNotIn(NO_VALUE, err)
                    self.assertEqual([], os.listdir(d))

    def test_synthesize_refuses_each_flag_and_writes_nothing(self):
        cases = (("--changes (-c)", ["--changes"]), ("--changes (-c)", ["-c"]),
                 ("--diff-hunks", ["--diff-hunks", "diff-hunks.json"]),
                 ("--diff-hunks-run-id", ["--diff-hunks-run-id", "R"]),
                 ("--gate-scope", ["--gate-scope", "on-diff"]),      # the default, typed
                 ("--gate-scope", ["--gate-scope", "all"]),
                 ("--diff-context", ["--diff-context", "5"]),        # the default, typed
                 ("--diff-context", ["--diff-context", "0"]), ("--diff-context", ["--diff-context=0"]),
                 ("--diff-context", ["--diff-context", "many"]),
                 ("--gate-scope", ["--gate-scope", "changed"]),
                 ("--changes (-c)", ["--repo", "--changes"]), ("--changes (-c)", ["-c", "--repo"]),
                 ("--diff-hunks", ["--diff-hunks"]), ("--diff-hunks-run-id", ["--diff-hunks-run-id"]),
                 ("--gate-scope", ["--gate-scope"]), ("--diff-context", ["--diff-context"]),
                 ("--diff-hunks", ["--diff-hunks", "--repo"]))
        with tempfile.TemporaryDirectory() as d:
            for name, flags in cases:
                with self.subTest(flags=flags):
                    code, err = refused(synthesize.main,
                                        ["--target", d, "--out", os.path.join(d, "report.json")]
                                        + flags)
                    self.assertEqual(2, code)
                    self.assertIn("synthesize: " + WITHDRAWN + name + " is refused. " + ADVICE, err)
                    self.assertNotIn(UNKNOWN, err)
                    self.assertNotIn(NO_VALUE, err)
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

    def test_the_real_scripts_refuse_as_child_processes(self):
        scripts = os.path.join(ROOT, "skill", "scripts")
        with tempfile.TemporaryDirectory() as empty:
            for script, argv in (("discovery.py", ["--repo-scan", ".", "--scope-changed"]),
                                 ("discovery.py", ["--repo-scan", ".", "--base", "main"]),
                                 ("discovery.py", ["--repo-scan", ".", "--base"]),
                                 ("synthesize.py", ["--repo", "--gate-scope", "on-diff"]),
                                 ("synthesize.py", ["--repo", "--diff-hunks"]),
                                 ("driver.py", ["run", ".", "--pr"]),
                                 ("driver.py", ["persist", "scout-app", ".", "--base"]),
                                 ("synthesize.py", ["-c"])):
                with self.subTest(script=script, argv=argv):
                    done = subprocess.run(["env", sys.executable, os.path.join(scripts, script),
                                           *argv], cwd=empty, capture_output=True, text=True,
                                          timeout=120, check=False)
                    self.assertEqual(2, done.returncode, done.stderr)
                    self.assertIn(WITHDRAWN, done.stderr)
                    self.assertNotIn(UNKNOWN, done.stderr)
                    self.assertNotIn(NO_VALUE, done.stderr)
                    self.assertNotIn("Traceback", done.stderr)
                    self.assertEqual([], os.listdir(empty))


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
                    self.assertNotIn(UNKNOWN, done.stderr)
                    self.assertNotIn("Traceback", done.stderr)
                    self.assertEqual([], os.listdir(empty))


class TestTheDeltaCodeIsGone(unittest.TestCase):
    """#3736. In 5.4 the delta code was still there, reached by its own tests through a
    `refuse_delta=False` parameter. Read from the source of every module under
    `skill/scripts` and `devtools`: the parameter, the two modules and the names that
    did the work are gone, so nothing is left for a new caller to reach."""

    MODULES = ("skill/scripts/diff_map.py", "skill/scripts/synth/delta.py")
    NAMES = frozenset((
        "refuse_delta", "diff_map", "hunk_map", "diff_anchors", "acquire_pr", "release_worktree",
        "DiffMapError", "collect_changed_files", "resolve_base", "resolve_base_or_die",
        "write_diff_hunks", "_stamp_diff_hunks", "_finalize_worktree", "_worktree_dirty",
        "on_diff_active", "pre_existing_active", "delta_mode", "delta_meta", "delta_artifact",
        "delta_zero_hunks", "delta_scope_suppressed_git_drivers", "pr_worktree_root",
        "mutate", "transport_command_keys", "repository_settings"))

    def modules(self):
        for top in ("skill/scripts", "devtools"):
            for folder, _dirs, names in os.walk(os.path.join(ROOT, top)):
                for name in sorted(names):
                    if name.endswith(".py"):
                        yield os.path.join(folder, name)

    @staticmethod
    def spelled(tree):
        """Every identifier and every whole string constant in one module."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                yield node.id, node.lineno
            elif isinstance(node, ast.Attribute):
                yield node.attr, node.lineno
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                yield node.name, node.lineno
            elif isinstance(node, ast.arg):
                yield node.arg, node.lineno
            elif isinstance(node, ast.keyword) and node.arg:
                yield node.arg, node.lineno
            elif isinstance(node, ast.alias):
                for part in (node.name + "." + (node.asname or "")).split("."):
                    yield part, node.lineno
            elif isinstance(node, ast.ImportFrom):
                for part in (node.module or "").split("."):
                    yield part, node.lineno
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                yield node.value, node.lineno

    def test_the_two_modules_are_deleted(self):
        for module in self.MODULES:
            self.assertFalse(os.path.lexists(os.path.join(ROOT, module)), module)

    def test_no_module_spells_a_name_of_the_delta_code(self):
        seen, found = 0, []
        for path in self.modules():
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), path)
            seen += 1
            found += ["%s:%d %s" % (os.path.relpath(path, ROOT), line, name)
                      for name, line in self.spelled(tree) if name in self.NAMES]
        self.assertGreater(seen, 150)
        self.assertEqual([], found)

    def test_the_reader_can_see_each_way_a_name_is_spelled(self):
        # Vacuity: an empty list is also what a reader that sees nothing returns.
        source = ("import scripts.diff_map as dm\nfrom scripts.synth import delta_meta\n"
                  "def hunk_map(refuse_delta=True):\n    return dm.acquire_pr(mutate=1)\n"
                  "KEY = 'delta_zero_hunks'\nclass DiffMapError(Exception):\n    pass\n"
                  "x = resolve_base\n")
        self.assertEqual(
            {"diff_map", "delta_meta", "hunk_map", "refuse_delta", "acquire_pr", "mutate",
             "delta_zero_hunks", "DiffMapError", "resolve_base"},
            {name for name, _line in self.spelled(ast.parse(source))} & self.NAMES)

    def test_no_entry_point_takes_a_switch_for_the_refusal(self):
        import inspect
        for function in (discovery.main, discovery._repo_scan, discovery._repo_scan_args,
                         synthesize.main, driver.main, driver.parse_cli):
            self.assertEqual(["argv"], list(inspect.signature(function).parameters),
                             function.__qualname__)


class TestAHunkMapLeftInARunFolderTurnsNothingOn(unittest.TestCase):
    """The driver handed `--diff-hunks` to synthesize whenever `diff-hunks.json` was in the
    run folder, whatever the manifest said: on a resume, a file left on disk was enough.
    Since #3736 nothing reads the file at all."""

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
        parsed = synthesize.build_parser().parse_args(cmd[2:])
        self.assertEqual([], delta_withdrawn.given(parsed, delta_withdrawn.SYNTHESIZE_FLAGS))

    def test_the_discovery_child_is_handed_no_diff_context_either(self):
        """#3737 review F2: a run started on 5.3 with `--diff-context N` and no diff is a
        whole-repository run. Its manifest still holds the flag, and the driver forwarded
        it: the child then refused a flag nobody had typed."""
        captured = {}

        def child(cmd, **_kw):
            captured["cmd"] = list(cmd)
            return mock.Mock(returncode=2, stdout="", stderr="stopped here")
        for scope in ({"mode": "repo", "target": None}, {"mode": "files", "target": ["a.py"]}):
            manifest = {"run_id": "R", "security_mode": "standard", "scope": scope,
                        "flags": {"diff_context": 0, "gate_scope": "all"}}
            with self.subTest(scope=scope):
                with self.assertRaisesRegex(runio.DriverError, "stopped here"):
                    self.discover(manifest, child)
                for flag in ("--diff-context", "--scope-changed", "--base", "--pr-base",
                             "--pr-worktree"):
                    self.assertNotIn(flag, captured["cmd"])
                parsed, _repo = discovery._repo_scan_args(captured["cmd"][2:])
                self.assertEqual([], delta_withdrawn.given(parsed, delta_withdrawn.DISCOVERY_FLAGS))

    def discover(self, manifest, child):
        import scripts.phases.discovery as discovery_phase
        with tempfile.TemporaryDirectory() as root, \
                mock.patch("scripts.phases.child._run_child", side_effect=child), \
                contextlib.redirect_stderr(io.StringIO()):
            root = os.path.realpath(root)
            os.makedirs(os.path.join(root, ".panopticon"))
            with open(os.path.join(root, repo_config.CONFIG_NAMES[0]), "w",
                      encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Core:\n    match: ['src/**']\n")
            return discovery_phase.discovery_execute(root, manifest)

    def test_a_delta_manifest_never_becomes_a_whole_repository_scan(self):
        """#3736: the phase has no delta scope to hand its child, and a scope it does not
        know falls to the whole repository. The driver refuses to resume such a run before
        any phase; the phase refuses it too, and starts no child."""
        child = mock.Mock()
        for fields in ({"scope": {"mode": "changed", "target": None}}, {"base": "main"},
                       {"pr": 7}, {"pr": 0}, {"pr_base": "main"}, {"worktree": "/tmp/pr-7"}):
            manifest = dict({"run_id": "R", "security_mode": "standard",
                             "scope": {"mode": "repo", "target": None}}, **fields)
            with self.subTest(fields=fields):
                with self.assertRaises(runio.DriverError) as stopped:
                    self.discover(manifest, child)
                self.assertEqual(
                    "discovery: " + WITHDRAWN + "this run folder was started as a delta review "
                    "and cannot be resumed (--reset discards it and starts a whole-repository "
                    "run). " + ADVICE, str(stopped.exception))
        child.assert_not_called()


if __name__ == "__main__":
    unittest.main()

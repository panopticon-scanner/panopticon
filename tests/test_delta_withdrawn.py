"""#3735: delta review is withdrawn in 5.4. Every way into it is refused, with one message,
before anything is launched or written."""
import contextlib
import io
import json
import os
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
import scripts.phases.synthesize as synthesize_phase
import scripts.run_manifest as run_manifest
import scripts.synthesize as synthesize

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WITHDRAWN = "delta review is withdrawn in 5.4 (#3735): "
ADVICE = ("Run a whole-repository review, or scope one with -f, -d, -g or --files. Delta "
          "review returns when it has been rebuilt and measured.")

# Each flag on its own, as an operator types it, and how the refusal names it.
DRIVER = (("--pr", ["--pr", "7"]), ("--changes (-c)", ["--changes"]), ("--changes (-c)", ["-c"]),
          ("--base", ["--base", "main"]), ("--gate-scope", ["--gate-scope", "on-diff"]),
          ("--gate-scope", ["--gate-scope", "all"]), ("--diff-context", ["--diff-context", "5"]))


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
        for name, flags in (("--pr", ["--pr", "7"]), ("--base", ["--base", "main"])):
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
        self.assertEqual(1, err.count("delta review is withdrawn"))

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
        nothing written, for every verb that takes the flags."""
        with tempfile.TemporaryDirectory() as empty:
            for argv in (["loop", ".", "--pr", "7"], ["run", ".", "-c"],
                         ["readiness", ".", "--base", "main"],
                         ["persist", "scout-app", "--pr", "7", "."]):
                with self.subTest(argv=argv):
                    done = subprocess.run(
                        [sys.executable, os.path.join(ROOT, "skill", "scripts", "driver.py")] + argv,
                        cwd=empty, capture_output=True, text=True, timeout=120, check=False)
                    self.assertEqual(2, done.returncode, done.stderr)
                    self.assertIn("delta review is withdrawn in 5.4 (#3735)", done.stderr)
                    self.assertEqual([], os.listdir(empty))


class TestARunStartedAsADeltaReviewIsNotResumed(unittest.TestCase):
    """A bare `driver run` or `driver loop` resumed whatever the manifest said, so a
    run started with `-c` went on as a delta run with no flag typed at all."""

    DELTA = ({"scope": {"mode": "changed", "target": None}}, {"base": "main"}, {"pr": 7},
             {"pr_base": "main"}, {"worktree": "/tmp/pr-7"})

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
        for fields in self.DELTA:
            for verb in ("run", "loop", "persist"):
                argv = [verb] + (["scout-app"] if verb == "persist" else []) + ["x"]
                with self.subTest(verb=verb, fields=fields), \
                        mock.patch.object(runio, "resolve_review_root",
                                          return_value=("/root", None, None)), \
                        mock.patch.object(run_manifest, "load_manifest",
                                          return_value=dict(fields, run_id="R")), \
                        mock.patch("scripts.orchestrate.main_verb") as loop, \
                        mock.patch.object(driver, "run") as run, \
                        mock.patch("scripts.host_probes.run_probes") as probes:
                    out, err = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        code = driver.main(argv)
                    said = err.getvalue() if verb == "persist" else out.getvalue()
                    self.assertEqual(2 if verb == "persist" else 1, code)
                    self.assertIn(WITHDRAWN + "this run folder was started as a delta review "
                                  "and cannot be resumed (--reset discards it and starts a "
                                  "whole-repository run). " + ADVICE, said)
                    for touched in (loop, run, probes):
                        touched.assert_not_called()

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
                                  "review is withdrawn in 5.4 (#3735); `--reset` starts a "
                                  "whole-repository run", row["detail"])


class TestTheChildScriptsRefuseThemToo(unittest.TestCase):
    """`discovery.py` writes the hunk map and `synthesize.py` reads it. The driver runs
    both as children; a host agent can run either by hand."""

    def test_discovery_refuses_each_flag_and_writes_nothing(self):
        cases = (("--scope-changed", ["--scope-changed"]), ("--base", ["--base", "main"]),
                 ("--base", ["--scope-files", "a.py", "--base", "main"]),
                 ("--pr-base", ["--pr-base", "main"]), ("--pr-worktree", ["--pr-worktree"]),
                 ("--diff-context", ["--diff-context", "5"]))
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
                 ("--diff-context", ["--diff-context", "5"]))        # the default, typed
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


if __name__ == "__main__":
    unittest.main()

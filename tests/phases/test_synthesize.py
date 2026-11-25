"""Tests for scripts.phases.synthesize: the synthesize child and host-usage collection.
"""
import contextlib
import hashlib
import html
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

from scripts import hosts
from tests._test_helpers import adopt_panopticon, only, our_manifest, write_host_evidence
import scripts.config_schema as config_schema
import scripts.evidence as evidence
import scripts.group_runner as group_runner
import scripts.phases.runio as runio
import scripts.phases.discovery as discovery_phase
import scripts.phases.requests as requests
import scripts.phases.review as review_phase
import scripts.phases.tools as tools_phase
import scripts.phases.verify as verify_phase
import scripts.phases.verify_tools as verify_tools
import scripts.run_manifest as run_manifest
import scripts.synthesize as syn
import scripts.synth.validate_schema as validate_schema_mod
import scripts.phases.synthesize as synthesize

import scripts.driver as driver

_UL_PROVEN = {hosts.USAGE_LEDGER: hosts.PROVEN}


def _write_passing_synthesize_report(cmd, **_kwargs):
    with open(cmd[cmd.index("--out") + 1], "w", encoding="utf-8") as fh:
        json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
    return mock.Mock(returncode=0, stdout="", stderr="")


class TestTheRunIdThePhaseSends(unittest.TestCase):
    """#3766: the synthesize child decides whether a tools manifest and its receipt
    are required from `--run-id`, so what the phase sends for a run manifest that
    carries no run_id is part of that decision. Behaviour, not source text."""

    def _argv(self, manifest):
        calls = []

        def child(cmd, **kwargs):
            calls.append(list(cmd))
            if "--out" in cmd:
                return _write_passing_synthesize_report(cmd, **kwargs)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as d, \
                mock.patch("scripts.phases.child._run_child", side_effect=child), \
                mock.patch.object(synthesize, "_usable_report", return_value=True), \
                contextlib.redirect_stderr(io.StringIO()):
            write_host_evidence(d, _UL_PROVEN)
            try:
                synthesize.synthesize_execute(d, manifest)
            except Exception:                    # what follows the child is not the subject
                pass
        sent = [cmd for cmd in calls if "--run-id" in cmd]
        self.assertEqual(1, len(sent), calls)
        return sent[0]

    def test_a_run_id_is_sent_as_it_is(self):
        cmd = self._argv({"host": "claude", "run_id": "rid-9",
                          "created": "2026-08-30T15:37:19Z"})
        self.assertEqual("rid-9", cmd[cmd.index("--run-id") + 1])

    def test_a_run_manifest_without_one_sends_the_empty_string(self):
        # ... which the child reads as a run that cannot be bound to its tool output,
        # not as a standalone call (tests/test_synthesize.py).
        for manifest in ({"host": "claude", "created": "2026-08-30T15:37:19Z"},
                         {"host": "claude", "created": "2026-08-30T15:37:19Z",
                          "run_id": None}):
            with self.subTest(manifest=manifest):
                cmd = self._argv(manifest)
                self.assertEqual("", cmd[cmd.index("--run-id") + 1])
                self.assertEqual(1, cmd.count("--run-id"))


class TestHostUsageCollection(unittest.TestCase):
    """#calibration-1: meta.cost.tokens is host-supplied, and only lands if the
    collector runs BETWEEN the last dispatch and synthesize. Leaving that
    ordering to the operator lost the cost ledger on the first external run."""

    def _manifest(self, **kw):
        m = {"host": "claude", "run_id": "r1", "created": "2026-08-30T15:37:19Z"}
        m.update(kw)
        return m

    def test_collects_before_synthesize_with_an_explicit_window(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.child._run_child") as run:
            write_host_evidence(d, _UL_PROVEN)
            run.return_value = mock.Mock(returncode=0)
            synthesize._collect_host_usage(d, self._manifest())
        cmd = run.call_args[0][0]   # the argv passed to _run_child
        self.assertIn("collect_usage.py", " ".join(cmd))
        # --since must be passed explicitly: run-manifest.json is _TOP_LEVEL, so
        # it is NOT in run_dir and the collector's own lookup would miss it and
        # bill the whole session transcript to this run.
        self.assertIn("--since", cmd)
        self.assertEqual(cmd[cmd.index("--since") + 1], "2026-08-30T15:37:19Z")
        # --run-dir must be the per-run folder, not top-level .panopticon
        run_dir = cmd[cmd.index("--run-dir") + 1]
        self.assertEqual(run_dir,
                         os.path.dirname(runio._pano(d, "usage.json")))

    def test_project_dir_is_the_session_not_the_review_root(self):
        # #calibration-2: --project-dir locates the HOST SESSION's transcript.
        # Passing review_root worked for every self-scan (review_root == session
        # cwd) and silently collected NOTHING on the first external target,
        # reintroducing `tokens: null`. It must be the session directory.
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.child._run_child") as run:
            write_host_evidence(d, _UL_PROVEN)
            run.return_value = mock.Mock(returncode=0)
            synthesize._collect_host_usage(d, self._manifest())
        cmd = run.call_args[0][0]
        project_dir = cmd[cmd.index("--project-dir") + 1]
        self.assertEqual(project_dir, os.getcwd())
        self.assertNotEqual(os.path.realpath(project_dir), os.path.realpath(d),
                            "--project-dir must not be the scanned target")

    def test_session_dir_overrides_cwd_for_project_dir(self):
        # #calibration-4 (gotify): getcwd() is the session dir only when the
        # driver was launched FROM it. `cd <target> && driver run .` -- an
        # equally natural invocation -- makes it the scanned repo, the
        # transcript slug does not exist, and meta.cost.tokens silently stays
        # null on a 612M-token run. The operator can now say where the session
        # is, since the driver cannot deduce it.
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.child._run_child") as run:
            write_host_evidence(d, _UL_PROVEN)
            run.return_value = mock.Mock(returncode=0)
            synthesize._collect_host_usage(
                d, self._manifest(session_dir="/somewhere/session"))
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[cmd.index("--project-dir") + 1], "/somewhere/session")

    def test_empty_session_dir_falls_back_to_cwd(self):
        # A blank value must not win over the default -- it would resolve to a
        # slug for "" and reproduce the silent-null it exists to prevent.
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.child._run_child") as run:
            write_host_evidence(d, _UL_PROVEN)
            run.return_value = mock.Mock(returncode=0)
            synthesize._collect_host_usage(d, self._manifest(session_dir=""))
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[cmd.index("--project-dir") + 1], os.getcwd())

    def test_collection_failure_names_the_directory_and_the_flag(self):
        # "produced nothing (rc 1)" alone does not tell the operator that the
        # searched directory was the wrong one, which is the likely cause.
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.child._run_child") as run, \
             contextlib.redirect_stderr(buf):
            write_host_evidence(d, _UL_PROVEN)
            run.return_value = mock.Mock(returncode=1)
            synthesize._collect_host_usage(
                d, self._manifest(session_dir="/somewhere/session"))
        err = buf.getvalue()
        self.assertIn("/somewhere/session", err)
        self.assertIn("--session-dir", err)

    def test_a_collector_that_failed_says_why_and_not_where_to_look(self):
        # #3706 review round 2, item 4: the "searched the wrong directory?" advice is
        # for rc 1, "no transcript found". It was printed for every non-zero exit, so a
        # collector that stopped for another reason (a transcript directory it could
        # not list) had its own reason dropped and the wrong remedy offered.
        reason = ("collect-usage: /tmp/claude-505/p/s/tasks could not be listed: "
                  "Permission denied; usage was not collected\n")
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.child._run_child") as run, \
             contextlib.redirect_stderr(buf):
            write_host_evidence(d, _UL_PROVEN)
            run.return_value = mock.Mock(returncode=2, stderr=reason)
            synthesize._collect_host_usage(d, self._manifest(session_dir="/somewhere/session"))
        self.assertEqual("driver: usage collection failed (rc 2): %s; meta.cost.tokens stays "
                         "null\n" % reason.strip(), buf.getvalue())

    def test_successful_collection_forwards_the_collectors_disclosure(self):
        disclosure = "collect-usage: dropped input; reported total is a FLOOR\n"
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.child._run_child") as run, \
             contextlib.redirect_stderr(io.StringIO()) as err:
            write_host_evidence(d, _UL_PROVEN)
            run.return_value = mock.Mock(returncode=0, stderr=disclosure)
            synthesize._collect_host_usage(d, self._manifest())
        self.assertEqual(err.getvalue(), disclosure)

    def test_run_parser_accepts_session_dir(self):
        args = driver.build_parser().parse_args(
            ["run", ".", "--session-dir", "/s"])
        self.assertEqual(args.session_dir, "/s")
        self.assertIsNone(
            driver.build_parser().parse_args(["run", "."]).session_dir)

    def test_max_per_group_is_threaded_to_discovery(self):
        # #5.2-prep: discovery.py has had --max-per-group since forever, but the
        # driver never exposed it, so every run in practice used the 15-file
        # default. On a mid-size repo that decides whether a scan is possible at
        # all: solidus (3,622 files) shards into 291 subgroups at 15 and 76 at
        # 60, and cells are subgroups x domains -- ~4.3B projected tokens versus
        # ~1.1B.
        parser = driver.build_parser()
        self.assertIsNone(parser.parse_args(["run", "."]).max_per_group)
        self.assertEqual(
            parser.parse_args(["run", ".", "--max-per-group", "60"]).max_per_group, 60)

        class _Args:
            tools = no_tools = include_fixtures = False
            fail_on = severity = gate_scope = diff_context = None
            max_per_group = 60

        flags = driver._cli_flags(_Args())
        self.assertEqual(flags["max_per_group"], 60,
                         "the flag must reach the manifest, or a resume would "
                         "silently re-chunk with a different cap")
        self._assert_discovery_max_per_group({"max_per_group": 60}, ["--max-per-group", "60"])

    def test_max_per_group_absent_leaves_discovery_default_alone(self):
        # Omitting it must not pass the flag at all, so discovery's own default
        # stays the single source of truth for the value.
        class _Args:
            tools = no_tools = include_fixtures = False
            fail_on = severity = gate_scope = diff_context = max_per_group = None

        self.assertIsNone(driver._cli_flags(_Args())["max_per_group"])
        self._assert_discovery_max_per_group({}, [])

    def _assert_discovery_max_per_group(self, flags, expected):
        manifest = self._manifest(scope={"mode": "files", "target": []}, flags=flags)
        with tempfile.TemporaryDirectory() as root, \
             mock.patch.object(runio, "load_committed_groups", return_value=({}, [])), \
             mock.patch("scripts.phases.child._run_child") as child:
            def write_groups(argv, **_kw):
                runio._write_json(argv[argv.index("--out") + 1], {"groups": []})
                return mock.Mock(returncode=0, stdout="", stderr="")
            child.side_effect = write_groups
            discovery_phase.discovery_execute(root, manifest)
            argv = child.call_args.args[0]
        actual = argv[argv.index("--max-per-group"):argv.index("--max-per-group") + 2] \
            if "--max-per-group" in argv else []
        self.assertEqual(actual, expected)

    def test_non_claude_host_is_skipped(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.child._run_child") as run:
            self.assertIsNone(
                synthesize._collect_host_usage(d, self._manifest(host="generic")))
        run.assert_not_called()

    def test_a_host_less_manifest_does_not_collect_usage(self):
        # synthesize.py reads `manifest.get("host")` with NO default, unlike
        # every other posture site (`get("host", "claude")`). Behavior is
        # preserved today only because nothing pins it: add the default and a
        # host-less manifest starts collecting usage from the Claude
        # transcripts, and the whole suite stays green. This is that pin.
        m = self._manifest()
        del m["host"]
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.child._run_child") as run:
            self.assertIsNone(synthesize._collect_host_usage(d, m))
        run.assert_not_called()

    def test_existing_usage_is_never_overwritten_on_resume(self):
        # #1344 F3: without proven evidence this would short-circuit on the
        # posture check above and pass for the WRONG reason, no longer
        # exercising the resume early-return this test names. Prove the
        # capability so the file-exists branch is what actually runs.
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.child._run_child") as run:
            write_host_evidence(d, _UL_PROVEN)
            path = runio._pano(d, "usage.json")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"total": 1}')
            self.assertIsNone(synthesize._collect_host_usage(d, self._manifest()))
        run.assert_not_called()

    def test_a_failed_collection_is_never_fatal(self):
        # An absent number must stay absent -- collection must never fail a run
        # that has already done all its expensive work.
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.child._run_child",
                        side_effect=runio.DriverError("boom")), \
             contextlib.redirect_stderr(io.StringIO()) as err:
            write_host_evidence(d, _UL_PROVEN)
            self.assertIsNone(synthesize._collect_host_usage(d, self._manifest()))
        self.assertIn("meta.cost.tokens stays null", err.getvalue())

    def test_no_transcript_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.child._run_child",
                        return_value=mock.Mock(returncode=1)), \
             contextlib.redirect_stderr(io.StringIO()) as err:
            write_host_evidence(d, _UL_PROVEN)
            synthesize._collect_host_usage(d, self._manifest())
        self.assertIn("produced nothing", err.getvalue())

class TestSynthesizePhase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        adopt_panopticon(self.root)   # #3273 P1: a run of ours (synthesize makes first contact)
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard",
                         "flags": {"fail_on": "high"}}

    def test_builds_report_via_verdicts_dir_form(self):
        captured = {}
        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "A", "findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            result = synthesize.synthesize_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(synthesize.synthesize_done(self.root, self.manifest))
        cmd = captured["cmd"]
        self.assertIn("--verdicts-dir", cmd)
        self.assertNotIn("--emit-verify-queue", cmd)
        self.assertIn("--fail-on", cmd)
        self.assertEqual(cmd[cmd.index("--out") + 1],
                         runio._pano(self.root, "report.json"))
        self.assertEqual(cmd[cmd.index("--run-id") + 1], "R")   # §5.1: X0X provenance

    def test_target_name_crosses_the_child_argv_parser_boundary(self):
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        cases = (
            ("original target, distinct PR worktree",
             {"target": os.path.join(self.root, "original-project"),
              "review_root": os.path.join(self.root, "pr-worktree")},
             "original-project"),
            ("legacy manifest fallback", {}, os.path.basename(self.root)),
            ("trailing separators and dot", {"target": self.root + "/project/./"},
             "project"),
            ("leading hyphen and HTML characters",
             {"target": os.path.join(self.root, "-<unsafe>&")}, "-<unsafe>&"),
            ("filesystem root", {"target": os.path.sep}, os.path.sep),
        )
        for label, fields, expected in cases:
            with self.subTest(label=label):
                manifest = dict(self.manifest, **fields)
                with mock.patch("scripts.phases.child._run_child", side_effect=fake_run) as run:
                    synthesize.synthesize_execute(self.root, manifest)
                argv = run.call_args.args[0][2:]
                parsed = syn.build_parser().parse_args(argv)
                self.assertEqual(parsed.target, expected)
                self.assertEqual(argv.count("--target") +
                                 sum(a.startswith("--target=") for a in argv), 1)

    def test_real_child_reports_the_original_target_in_json_and_html(self):
        name = "-<original&target>"
        manifest = dict(self.manifest,
                        target=os.path.join(self.root, name),
                        review_root=os.path.join(self.root, "pr-worktree"))
        runio._write_json(runio._pano(self.root, "groups.json"), {"mode": "repo", "groups": []})

        synthesize.synthesize_execute(self.root, manifest)

        report_path = runio._pano(self.root, "report.json")
        report = runio._load_json(report_path)
        self.assertEqual(report["meta"]["target"], name)
        with open(report_path + ".html", encoding="utf-8") as fh:
            page = fh.read()
        escaped = html.escape(name)
        self.assertIn(f"<title>Panopticon — {escaped}</title>", page)
        self.assertIn(f"<h1>{escaped}</h1>", page)
        self.assertNotIn(f"<h1>{name}</h1>", page)

    def test_real_child_grades_the_review_root_not_the_display_name(self):
        # #3163: a PR worktree must measure its files, even when the original
        # checkout has the same filenames with different contents.
        original = os.path.join(self.root, "original-project")
        os.makedirs(original)
        with open(os.path.join(original, "app.py"), "w") as fh:
            fh.write("original = 1\n" * 9)
        with open(os.path.join(self.root, "app.py"), "w") as fh:
            fh.write("first = 1\n\nsecond = 2\n")
        runio._write_json(runio._pano(self.root, "groups.json"), {"mode": "repo",
            "groups": [{"name": "app", "files": ["app.py"]}]})

        for target in (self.root, original):
            with self.subTest(target=target):
                manifest = dict(self.manifest, target=target, review_root=self.root)
                result = synthesize.synthesize_execute(self.root, manifest)
                report = runio._load_json(runio._pano(self.root, "report.json"))
                self.assertEqual(result.kind, "advanced")
                self.assertEqual(report["meta"]["target"], os.path.basename(target))
                self.assertEqual(report["summary"]["health"]["total_loc"], 2)
                self.assertEqual(report["summary"]["overall_grade"], "S")

    def _assert_real_child_refuses_artifact_leaf(
            self, leaf, action, expected_files, plant=None, still_planted=None,
            detail=None):
        """Drive one planted output leaf through synthesize_execute's real child."""
        with tempfile.TemporaryDirectory() as directory:
            root = os.path.realpath(directory)
            os.makedirs(runio._pano(root))
            adopt_panopticon(root)   # #3273 P1: a run of ours
            runio._write_json(runio._pano(root, "groups.json"), {"mode": "repo", "groups": []})
            report = runio._report_out(root)
            paths = {
                "report": report,
                "x0x": report.replace(".json", "-x0x.json"),
                "failure": report.replace(".json", "-x0x-failures.json"),
                "html": report + ".html",
            }
            (plant or (lambda path, _root: os.makedirs(path)))(paths[leaf], root)
            manifest = {"run_id": "R", "host": "generic",
                        "security_mode": "standard", "flags": {"fail_on": "high"}}

            with contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(runio.DriverError) as caught:
                synthesize.synthesize_execute(root, manifest)

            refusal = str(caught.exception)
            self.assertIn("rc=4", refusal)
            self.assertIn("synthesize: artifact path refused:", refusal)
            if action:
                self.assertIn("cannot %s artifact" % action, refusal)
            if detail:
                self.assertIn(detail, refusal)
            self.assertIn(os.path.basename(paths[leaf]), refusal)
            self.assertNotIn("Traceback", refusal)
            self.assertTrue(
                (still_planted or os.path.isdir)(paths[leaf]),
                "the refused leaf was modified",
            )
            self.assertEqual(
                {name: os.path.isfile(path) for name, path in paths.items()},
                expected_files,
            )
            self.assertFalse(
                [name for name in os.listdir(os.path.dirname(report))
                 if name.endswith(".tmp")],
                "a refused publication left a staging file",
            )

    def test_real_child_refuses_a_directory_at_the_report_path(self):
        self._assert_real_child_refuses_artifact_leaf(
            "report", "publish",
            {"report": False, "x0x": False, "failure": False, "html": False},
        )

    def test_real_child_refuses_a_directory_at_the_x0x_path(self):
        self._assert_real_child_refuses_artifact_leaf(
            "x0x", "publish",
            {"report": True, "x0x": False, "failure": False, "html": False},
        )

    def test_real_child_refuses_a_directory_at_the_stale_failure_log_path(self):
        self._assert_real_child_refuses_artifact_leaf(
            "failure", "remove",
            {"report": True, "x0x": False, "failure": False, "html": False},
        )

    def test_real_child_refuses_a_directory_at_the_html_path(self):
        self._assert_real_child_refuses_artifact_leaf(
            "html", "write",
            {"report": True, "x0x": True, "failure": False, "html": False},
        )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_real_child_refuses_a_fifo_at_the_html_path_without_blocking(self):
        self._assert_real_child_refuses_artifact_leaf(
            "html", "write",
            {"report": True, "x0x": True, "failure": False, "html": False},
            plant=lambda path, _root: os.mkfifo(path),
            still_planted=lambda path: stat.S_ISFIFO(os.lstat(path).st_mode),
        )

    def _assert_real_child_halts_on_a_planted_html_link(self, plant):
        """#3273 P1: a link planted in `.panopticon/` is refused at the child's
        first contact (H3), before any writer runs and before anything is
        published. The writer's own refusal of the same links is pinned
        directly in `tests/test_artifact_write_symlinks.py::TestHtmlReport`."""
        with tempfile.TemporaryDirectory() as directory:
            root = os.path.realpath(directory)
            os.makedirs(runio._pano(root))
            adopt_panopticon(root)
            runio._write_json(runio._pano(root, "groups.json"), {"mode": "repo", "groups": []})
            report = runio._report_out(root)
            plant(report + ".html", root)
            manifest = {"run_id": "R", "host": "generic",
                        "security_mode": "standard", "flags": {"fail_on": "high"}}
            with contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(runio.DriverError) as caught:
                synthesize.synthesize_execute(root, manifest)
            refusal = str(caught.exception)
            self.assertIn("rc=2", refusal)
            self.assertIn("synthesize: .panopticon/%s is a symlink"
                          % os.path.relpath(report + ".html", runio._pano(root)), refusal)
            self.assertNotIn("Traceback", refusal)
            self.assertTrue(os.path.islink(report + ".html"), "the planted link was touched")
            self.assertFalse(os.path.lexists(report))
            self.assertFalse(os.path.lexists(report.replace(".json", "-x0x.json")))

    def test_real_child_halts_on_a_dangling_html_symlink(self):
        self._assert_real_child_halts_on_a_planted_html_link(
            lambda path, root: os.symlink(os.path.join(root, "missing"), path))

    def test_real_child_halts_on_an_html_symlink_to_a_directory(self):
        def plant(path, root):
            target = os.path.join(root, "outside-directory")
            os.mkdir(target)
            os.symlink(target, path)

        self._assert_real_child_halts_on_a_planted_html_link(plant)

    @unittest.skipIf(getattr(os, "geteuid", lambda: 0)() == 0,
                     "root bypasses parent write permissions")
    def test_real_child_refuses_a_read_only_report_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = os.path.realpath(directory)
            pano = runio._pano(root)
            os.makedirs(pano)
            adopt_panopticon(root)   # #3273 P1: a run of ours
            groups = runio._pano(root, "groups.json")
            runio._write_json(groups, {"mode": "repo", "groups": []})
            report = runio._report_out(root)
            cmd = [
                sys.executable, runio._script("synthesize.py"),
                "--target", "probe", "--groups", groups, "--run-dir", pano,
                "--out", report,
            ]
            os.chmod(pano, 0o500)
            try:
                proc = synthesize.child._run_child(
                    cmd, review_root=root, phase="synthesize", timeout=30)
            finally:
                os.chmod(pano, 0o700)

            self.assertEqual(proc.returncode, validate_schema_mod.ARTIFACT_INVALID)
            self.assertIn("synthesize: artifact path refused:", proc.stderr)
            self.assertIn("report.json", proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
            self.assertFalse(os.path.exists(report))

    def test_forwards_the_manifest_verify_cap_including_zero(self):
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        for cap in (None, 0, 1, 3):
            with self.subTest(cap=cap):
                self.manifest["flags"]["max_verify"] = cap
                with mock.patch("scripts.phases.child._run_child",
                                side_effect=fake_run) as run:
                    synthesize.synthesize_execute(self.root, self.manifest)
                cmd = run.call_args.args[0]
                if cap is None:
                    self.assertNotIn("--max-verify", cmd)
                else:
                    self.assertEqual(cmd[cmd.index("--max-verify") + 1], str(cap))
                    self.assertEqual(syn.build_parser().parse_args(
                        ["--max-verify", str(cap)]).max_verify, cap)

    def test_committed_cap_refusal_and_explicit_cli_override_reach_manifest(self):
        parsed = config_schema.parse_settings({"settings": {"max_verify": 1}})
        parser = driver.build_parser()
        for argv, expected in ((["run", "."], None),
                               (["run", ".", "--max-verify", "2"], 2)):
            with self.subTest(argv=argv):
                args = parser.parse_args(argv)
                with mock.patch("scripts.phases.runio.committed_settings",
                                return_value=parsed), \
                     contextlib.redirect_stderr(io.StringIO()):
                    resolved = driver._resolve_config(args, self.root)
                flags = driver._cli_flags(args, self.root, resolution=resolved)
                manifest = run_manifest.build_manifest(
                    target=self.root, review_root=self.root, host="generic",
                    security_mode="standard", flags=flags, config=resolved,
                    run_id="R")
                self.assertEqual(manifest["flags"]["max_verify"], expected)
                if expected is None:
                    self.assertEqual([r["key"] for r in resolved.refused],
                                     ["max_verify"])
                else:
                    self.assertTrue(any("command line" in d
                                        for d in resolved.disclosures))

    def test_real_child_reports_combined_queue_cut_and_dispatched_tool_id(self):
        def result(rule, line, level):
            return {"ruleId": rule, "level": level,
                    "message": {"text": rule}, "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "src/app.py"},
                        "region": {"startLine": line}}}]}

        os.makedirs(os.path.join(self.root, "src"))
        with open(os.path.join(self.root, "src", "app.py"), "w") as fh:
            fh.write("a = 1\nb = 2\nc = 3\n")
        runio._write_json(runio._pano(self.root, "groups.json"),
                         {"mode": "repo", "groups": [{"name": "app", "files": ["src/app.py"]}]})
        runio._write_json(runio._pano(self.root, "coverage-app.json"),
                         {"group": "app", "floor": [], "effective": [],
                          "run_id": "R"})
        runio._write_json(runio._pano(self.root, "findings-app-SEC.json"), {
            "findings": [{"domain": "SEC", "code": "SEC-A1A",
                          "severity": "CRITICAL", "title": "panel claim",
                          "category": "authz", "location": {
                              "file": "src/app.py", "line_start": 3}}],
            "_panopticon": {"run_id": "R", "role": "domain_panel",
                             "domain": "SEC", "group": "app"}})
        os.makedirs(runio._pano(self.root, "tools"))
        runio._write_json(runio._pano(self.root, "tools", "semgrep.sarif"),
                         {"runs": [{"tool": {"driver": {"name": "semgrep",
                                                           "rules": []}},
                                    "results": [result("high", 1, "error"),
                                                result("low", 2, "note")]}]})
        runio._write_json(runio._pano(self.root, "tools-ran.json"),
                         {"ran": True, "run_id": "R"})
        # #2070: the driver queue and child synth bind to this run's receipt.
        runio._write_json(runio._pano(self.root, "tools-manifest.json"),
                         {"schema_version": 1, "run_id": "R",
                          "selected": ["semgrep"], "produced": ["semgrep"],
                          "missing": [], "outputs": ["semgrep.sarif"]})
        manifest = {"run_id": "R", "host": "generic", "security_mode": "standard",
                    "flags": {"max_verify": 2, "fail_on": "high"}}
        dispatched = verify_tools._tool_verify_queue(self.root, manifest)
        self.assertEqual(len(dispatched), 1)
        qid, dispatched_finding = dispatched[0]
        os.makedirs(runio._pano(self.root, "verdicts"))
        runio._write_json(runio._pano(self.root, "verdicts", qid + ".json"),
                         {"finding_id": dispatched_finding["id"],
                          "verdict": "CONFIRMED", "reasoning": "checked"})

        synthesize.synthesize_execute(self.root, manifest)  # real child subprocess
        report = runio._load_json(runio._pano(self.root, "report.json"))
        verdicts = report["meta"]["coverage"]["verdicts"]
        self.assertEqual((verdicts["queued"], verdicts["cut"]), (2, 1))
        self.assertEqual(verdicts["matched"], 1)
        tool_findings = [f for f in report["findings"]
                         if evidence.is_tool_sourced(f)]
        self.assertEqual(len(tool_findings), 2)
        dispatched_report = next(f for f in tool_findings
                                 if f["id"] == dispatched_finding["id"])
        omitted_report = next(f for f in tool_findings
                              if f["id"] != dispatched_finding["id"])
        self.assertEqual(dispatched_report["fingerprint"], qid)
        self.assertEqual(dispatched_report["evidence"]["status"], "tool_confirmed")
        self.assertEqual(omitted_report["evidence"]["status"], "tool_reported")

    def test_real_child_advances_with_bidi_controls_in_x0x_paths(self):
        # The direct synthesize test pins rc=0. This pins the other half of the
        # live boundary: the driver phase runs that child and advances instead
        # of turning a target-chosen filename into a terminal scan error.
        points = (
            0x061C,
            0x200E, 0x200F,
            0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
            0x2066, 0x2067, 0x2068, 0x2069,
        )
        findings = [{
            "id": "SE-%03d" % (index + 1),
            "domain": "SEC",
            "code": "SEC-X0X",
            "severity": "LOW",
            "confidence": "POSSIBLE",
            "title": "catalog gap %d" % index,
            "short_title": "catalog gap %d" % index,
            "category": "catalog-gap",
            "panel": "security",
            "location": {"file": "src/x%sy.py" % chr(point), "line_start": 1},
        } for index, point in enumerate(points)]
        runio._write_json(
            runio._pano(self.root, "groups.json"),
            {"mode": "repo", "groups": [{"name": "app", "files": []}]},
        )
        runio._write_json(
            runio._pano(self.root, "findings-app-SEC.json"),
            {"findings": findings,
             "_panopticon": {"run_id": "R", "role": "domain_panel",
                              "domain": "SEC", "group": "app"}},
        )

        result = synthesize.synthesize_execute(
            self.root, dict(self.manifest, host="generic"))
        x0x_path = runio._report_out(self.root).replace(".json", "-x0x.json")
        x0x = runio._load_json(x0x_path)

        self.assertEqual(result.kind, "advanced")
        self.assertEqual(
            validate_schema_mod.schema_errors(
                x0x, validate_schema_mod.X0X_SCHEMA),
            [],
        )
        self.assertEqual(
            {occurrence["file"]
             for candidate in x0x["candidates"]
             for occurrence in candidate["occurrences"]},
            {"src/x\\u%04xy.py" % point for point in points},
        )

    def test_real_child_advances_and_discloses_a_locus_free_x0x_discard(self):
        # #2713 revised owner ruling, driver half: the candidate-bearing X0X
        # and main artifacts complete, while the sidecar, stderr disclosure,
        # and phase status all name the one discarded locus-free finding.
        locus_free = {
            "id": "SE-077",
            "domain": "SEC",
            "code": "SEC-X0X",
            "severity": "LOW",
            "confidence": "POSSIBLE",
            "title": "repo-wide dependency gap",
            "short_title": "dependency gap",
            "category": "catalog-gap",
            "panel": "security",
            "location": {},
        }
        located = dict(
            locus_free,
            id="SE-076",
            title="located dependency gap",
            short_title="located gap",
            location={"file": "src/app.py", "line_start": 7},
        )
        runio._write_json(
            runio._pano(self.root, "groups.json"),
            {"mode": "repo", "groups": [{"name": "app", "files": []}]},
        )
        runio._write_json(
            runio._pano(self.root, "findings-app-SEC.json"),
            {"findings": [located, locus_free],
             "_panopticon": {"run_id": "R", "role": "domain_panel",
                              "domain": "SEC", "group": "app"}},
        )
        report_path = runio._report_out(self.root)
        x0x_path = report_path.replace(".json", "-x0x.json")
        failure_path = x0x_path.replace(".json", "-failures.json")

        with contextlib.redirect_stderr(io.StringIO()) as err:
            result = synthesize.synthesize_execute(
                self.root, dict(self.manifest, host="generic"))

        self.assertEqual(result.kind, "advanced")
        self.assertTrue(synthesize.synthesize_done(self.root, self.manifest))
        self.assertEqual(syn.validate_artifacts(report_path, x0x_path), [])
        self.assertTrue(os.path.isfile(report_path + ".html"))
        candidate = only(runio._load_json(x0x_path)["candidates"], "candidate")
        self.assertEqual(
            only(candidate["occurrences"], "occurrence")["file"], "src/app.py")
        failure = only(
            runio._load_json(failure_path)["discarded_findings"],
            "discarded finding",
        )
        self.assertEqual(failure["reason"], "no file locus")
        self.assertIn("driver: X0X discarded 1 locus-free", err.getvalue())
        self.assertIn(failure_path, err.getvalue())
        self.assertIn("X0X discarded 1 locus-free", result.message)
        self.assertIn(failure_path, result.message)

    def test_discard_signal_survives_a_successful_child_stderr_flood(self):
        report_path = runio._report_out(self.root)
        x0x_path = report_path.replace(".json", "-x0x.json")
        failure_path = x0x_path.replace(".json", "-failures.json")

        def fake_run(cmd, **_kwargs):
            with open(cmd[cmd.index("--out") + 1], "w", encoding="utf-8") as fh:
                json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
            runio._write_json(failure_path, {
                "discarded_findings": [{
                    "finding_id": "SE-077",
                    "reason": "no file locus",
                    "diagnostic": "bounded diagnostic",
                }],
            })
            return mock.Mock(returncode=0, stdout="", stderr="FLOOD" * 2000)

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            result = synthesize.synthesize_execute(self.root, self.manifest)

        self.assertIn("X0X discarded 1 locus-free", err.getvalue())
        self.assertIn(failure_path, err.getvalue())
        self.assertNotIn("FLOOD", err.getvalue())
        self.assertIn("X0X discarded 1 locus-free", result.message)
        self.assertIn(failure_path, result.message)
        self.assertNotIn("FLOOD", result.message)

    def test_passes_the_committed_exclude_paths_as_tools_exclude(self):
        # #1740 fix round 1 (controller addition): the report-side gate reads
        # the tool findings through `synthesize.py`, so the committed policy
        # has to reach THAT ingest too -- otherwise a redteam run gates on the
        # very corpus `exclude_paths:` scoped out.
        with open(os.path.join(self.root, "panopticon.yml"), "w",
                  encoding="utf-8") as fh:
            fh.write("version: 1\nexclude_paths:\n  - 'tests/fixtures/**'\n")
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            synthesize.synthesize_execute(self.root, self.manifest)
        cmd = captured["cmd"]
        got = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--tools-exclude"]
        self.assertEqual(got, ["tests/fixtures/**"])

    def test_no_committed_globs_means_no_tools_exclude_flag(self):
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            synthesize.synthesize_execute(self.root, self.manifest)
        self.assertNotIn("--tools-exclude", captured["cmd"])

    def test_tools_dir_added_when_tools_ran(self):
        runio._write_json(runio._pano(self.root, "tools-ran.json"),
                           {"ran": True, "run_id": "R"})
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run) as rm_:
            synthesize.synthesize_execute(self.root, self.manifest)
        self.assertIn("--tools-dir", rm_.call_args[0][0])

    def test_tools_dir_added_for_an_attempt_with_an_empty_receipt(self):
        # #2070: synthesis must validate the receipt even when no bound output
        # exists; otherwise a missing receipt with no stale file escapes notice.
        runio._write_json(runio._pano(self.root, "tools-ran.json"),
                          {"ran": False, "run_id": "R", "outputs": [],
                           "unbound_tool_outputs": []})

        with mock.patch(
                "scripts.phases.child._run_child",
                side_effect=_write_passing_synthesize_report) as run:
            synthesize.synthesize_execute(self.root, self.manifest)
        self.assertIn("--tools-dir", run.call_args[0][0])

    def _cmd_for(self, marker, tools):
        runio._write_json(runio._pano(self.root, "tools-ran.json"), marker)
        manifest = dict(self.manifest, flags=dict(self.manifest.get("flags") or {}, tools=tools))
        with mock.patch("scripts.phases.child._run_child",
                        side_effect=_write_passing_synthesize_report) as run:
            synthesize.synthesize_execute(self.root, manifest)
        return run.call_args[0][0]

    def test_a_no_tools_run_hands_over_its_tools_dir_as_skipped(self):
        # #3197: so a planted capture is NAMED unbound rather than never looked at
        # Keyed on the CONTROLLER's flags, never the target-writable marker: a
        # marker that does not say `skipped` changes nothing.
        for marker in ({"ran": False, "skipped": True, "run_id": "R", "note": tools_phase.NO_TOOLS_NOTE},
                       {"ran": False, "run_id": "R", "note": tools_phase.NO_TOOLS_NOTE}):
            with self.subTest(marker=marker):
                cmd = self._cmd_for(marker, tools=False)
                self.assertIn("--tools-skipped", cmd)
                self.assertEqual(runio._pano(self.root, "tools"), cmd[cmd.index("--tools-dir") + 1])

    def test_a_downgrade_after_a_real_scan_keeps_its_own_outputs_bound(self):
        # The coordinator's case: tools RAN, then `--no-tools` was recorded
        # mid-run. `tools_done` stops at `ran`, so the marker is never rewritten
        # as a skip, and synthesis ingests this run's own receipt-bound outputs
        # exactly as on main -- they are never read as a plant.
        cmd = self._cmd_for({"ran": True, "run_id": "R", "outputs": ["semgrep.sarif"]},
                            tools=False)
        self.assertIn("--tools-dir", cmd)
        self.assertNotIn("--tools-skipped", cmd)
        self.assertTrue(tools_phase.tools_done(self.root, dict(
            self.manifest, flags={"tools": False}, invocation="I")))

    def test_a_tools_enabled_run_never_says_skipped(self):
        for marker in ({"ran": True, "run_id": "R"}, {"ran": False, "run_id": "R"},
                       {"ran": False, "skipped": True, "run_id": "R"}):     # a marker saying so
            with self.subTest(marker=marker):
                self.assertNotIn("--tools-skipped", self._cmd_for(marker, tools=True))

    def test_gate_fail_nonzero_still_advances_when_report_present(self):
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "F", "findings": [], "summary": {"gate": "FAIL"}}, fh)
            return mock.Mock(returncode=2, stdout="", stderr="gate failed")  # non-zero
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            result = synthesize.synthesize_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")

    def test_an_invalid_artifact_ends_the_run_in_error(self):
        # #1639 P15 ruling 2: a report that does not satisfy its own published
        # schema is NOT a gate verdict -- it is the artifact failing to be what
        # it claims to be, and the run's terminal status says so. The report
        # file exists and parses (that is the point: JSON-parseable and
        # schema-valid are different questions), so the existing
        # "report absent" guard cannot catch it.
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "A", "findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=validate_schema_mod.ARTIFACT_INVALID,
                             stdout="", stderr="artifact invalid: 3 schema errors")
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            with self.assertRaises(runio.DriverError) as ctx:
                synthesize.synthesize_execute(self.root, self.manifest)
        self.assertIn("artifact invalid", str(ctx.exception))

    def test_missing_report_redacts_complete_key_before_head_limit(self):
        key_type = "PRIVATE KEY"
        key = (f"-----BEGIN {key_type}-----\n" + "A" * 80
               + f"\n-----END {key_type}-----")
        stderr = "x" * 360 + key + " trailing diagnostic"
        with mock.patch("scripts.phases.child._run_child",
                        return_value=mock.Mock(returncode=1, stdout="", stderr=stderr)):
            with self.assertRaises(runio.DriverError) as caught:
                synthesize.synthesize_execute(self.root, self.manifest)
        error = str(caught.exception)
        self.assertIn("[REDACTED_PRIVATE_KEY]", error)
        self.assertNotIn("-----BEGIN PRIVATE", error)
        self.assertEqual(runio._error_status(error)["status"], "error")

    def test_missing_report_redacts_dangling_key(self):
        key_type = "PRIVATE KEY"
        key = (f"-----BEGIN {key_type}-----\n" + "A" * 2000)
        stderr = "x" * 360 + key + " trailing diagnostic"
        with mock.patch("scripts.phases.child._run_child",
                        return_value=mock.Mock(returncode=1, stdout="", stderr=stderr)):
            with self.assertRaises(runio.DriverError) as caught:
                synthesize.synthesize_execute(self.root, self.manifest)
        error = str(caught.exception)
        self.assertIn("[REDACTED_PRIVATE_KEY]", error)
        self.assertNotIn("-----BEGIN PRIVATE", error)
        self.assertEqual(runio._error_status(error)["status"], "error")

    def test_invalid_artifact_redacts_complete_jwt_before_tail_limit(self):
        jwt = "eyJ" + "a" * 20 + ".eyJ" + "b" * 20 + "." + "c" * 24
        stderr = "diagnostic " + jwt + " " + "z" * 360

        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=validate_schema_mod.ARTIFACT_INVALID,
                             stdout="", stderr=stderr)

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            with self.assertRaises(runio.DriverError) as caught:
                synthesize.synthesize_execute(self.root, self.manifest)
        error = str(caught.exception)
        self.assertIn("[REDACTED_JWT]", error)
        self.assertNotIn("eyJ", error)
        status = runio._error_status(error)
        self.assertEqual(status["status"], "error")
        self.assertNotIn("eyJ", str(status))

    def test_invalid_artifact_redacts_dangling_key_before_tail_limit(self):
        key_type = "PRIVATE KEY"
        key = f"-----BEGIN {key_type}-----\n" + "A" * 2000
        stderr = "diagnostic " + key + " " + "z" * 360

        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=validate_schema_mod.ARTIFACT_INVALID,
                             stdout="", stderr=stderr)

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            with self.assertRaises(runio.DriverError) as caught:
                synthesize.synthesize_execute(self.root, self.manifest)
        error = str(caught.exception)
        self.assertIn("[REDACTED_PRIVATE_KEY]", error)
        self.assertNotIn("AAAA", error)
        status = runio._error_status(error)
        self.assertEqual(status["status"], "error")
        self.assertNotIn("AAAA", str(status))

    def test_an_invalid_artifact_still_repoints_the_compat_path_at_this_run(self):
        # #1639 P15 I3: `.panopticon/report.json` is the documented
        # backward-compat path. Raising before the relink left it pointing at
        # the PREVIOUS run's report -- complete, valid, possibly PASS -- so a
        # CI consumer reading it after a failed run silently read someone
        # else's result. The tag-named report this run wrote is the honest
        # artifact: it exists, it carries meta.schema_errors, and the run's
        # status says `error` beside it.
        with open(os.path.join(self.root, ".panopticon", "run-manifest.json"),
                  "w", encoding="utf-8") as fh:
            json.dump({"review_root": self.root, "run_id": "r1d2e3f4a5b6",
                       "host": "claude", "security_mode": "standard",
                       "scope": {"mode": "repo"},
                       "started_at": "2026-09-16T00:00:00Z"}, fh)
        compat = runio._pano(self.root, "report.json")
        stale = os.path.join(self.root, ".panopticon", "previous-run-report.json")
        with open(stale, "w") as fh:
            json.dump({"summary": {"gate": "PASS"}, "findings": []}, fh)
        os.symlink("previous-run-report.json", compat)

        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "A", "findings": [], "summary": {"gate": "PASS"},
                           "meta": {"schema_errors": 1}}, fh)
            return mock.Mock(returncode=validate_schema_mod.ARTIFACT_INVALID,
                             stdout="", stderr="artifact invalid: 1 schema errors")

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            with self.assertRaises(runio.DriverError):
                synthesize.synthesize_execute(self.root, self.manifest)
        tag = runio._run_tag(self.root)
        self.assertTrue(tag, "the fixture has no run tag to relink onto")
        self.assertEqual(os.readlink(compat), "%s-report.json" % tag)
        with open(compat) as fh:
            self.assertEqual(json.load(fh)["meta"]["schema_errors"], 1)

    def test_absent_report_raises(self):
        with mock.patch("scripts.phases.child._run_child",
                        return_value=mock.Mock(returncode=1, stdout="", stderr="boom")):
            with self.assertRaises(runio.DriverError):
                synthesize.synthesize_execute(self.root, self.manifest)


class TestAMidRunToolsDowngradeReachesSynthesize(unittest.TestCase):
    """#1637 P08 F2: the driver holds the manifest, so it is the driver that
    tells synthesize this run had its scan switched off in flight.

    Threaded on the argv rather than re-read by the child: run-manifest.json is
    a TOP_LEVEL artifact, so it is NOT under the `--run-dir` every other run
    artifact resolves against, and a direct `synthesize.py` invocation
    legitimately has no driver to ask."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)

    def _cmd(self, manifest):
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            synthesize.synthesize_execute(self.root, manifest)
        return captured["cmd"]

    def test_the_flag_is_passed_when_the_manifest_records_the_change(self):
        cmd = self._cmd({"run_id": "R", "security_mode": "standard", "flags": {},
                         "flag_changes": [{"flag": "tools", "from": None,
                                           "to": False, "at": "2026-09-15T00:00:00Z"}]})
        self.assertIn("--tools-disabled-mid-run", cmd)

    def test_a_run_that_was_no_tools_from_the_start_is_not_a_downgrade(self):
        # `flags.tools is False` is equally true of a run that never had tools;
        # only the recorded CHANGE means this run's later panels lost an input.
        cmd = self._cmd({"run_id": "R", "security_mode": "standard",
                         "flags": {"tools": False}})
        self.assertNotIn("--tools-disabled-mid-run", cmd)

    def test_a_prior_run_of_another_host_reaches_the_report(self):
        # #3271 ruling D2: first contact recorded it on the manifest; the same
        # argv route carries it to synthesize, and parses back to meta.prior_run.
        import scripts.synthesize as synthesize_cli
        cmd = self._cmd({"run_id": "R", "security_mode": "standard", "flags": {},
                         "first_contact": {"prior_run": {"host": "claude", "run_id": "0a1b2c3d"}}})
        self.assertEqual("claude:0a1b2c3d", cmd[cmd.index("--prior-run") + 1])
        parsed = synthesize_cli.build_parser().parse_args(cmd[2:])
        self.assertEqual("claude:0a1b2c3d", parsed.prior_run)
        self.assertNotIn("--prior-run", self._cmd({"run_id": "R", "security_mode": "standard",
                                                   "flags": {}, "first_contact": {"files": 3}}))

    def test_the_child_gates_on_the_manifests_threshold_or_the_default(self):
        # #3673: the manifest keeps "no opinion" as null and the child applies the default,
        # so a run started before the default existed resumes with no flag drift. `off`
        # travels as itself and parses to the OFF gate.
        import scripts.synthesize as synthesize_cli
        for recorded, parsed_as in ((None, "critical"), ("high", "high"), ("low", "low"),
                                    ("off", None)):
            with self.subTest(recorded=recorded):
                cmd = self._cmd({"run_id": "R", "security_mode": "standard",
                                 "flags": {"fail_on": recorded}})
                if recorded is None:
                    self.assertNotIn("--fail-on", cmd)
                else:
                    self.assertEqual(recorded, cmd[cmd.index("--fail-on") + 1])
                self.assertEqual(parsed_as, synthesize_cli.build_parser().parse_args(
                    cmd[2:]).fail_on)

    def test_the_matrix_record_reaches_the_report(self):
        # #3651: where the matrix came from, off the manifest, by the same argv route.
        import scripts.synthesize as synthesize_cli
        sha = "sha256:" + "ab" * 32
        cmd = self._cmd({"run_id": "R", "security_mode": "standard", "flags": {},
                         "matrix": {"origin": "working_tree", "config": "panopticon.yml",
                                    "config_sha256": sha, "setup_draft": "unchanged"}})
        parsed = synthesize_cli.build_parser().parse_args(cmd[2:])
        self.assertEqual(("working_tree", sha, "unchanged"),
                         (parsed.matrix_origin, parsed.matrix_config_sha256,
                          parsed.matrix_setup_draft))
        self.assertNotIn("panopticon.yml", cmd[cmd.index("--matrix-origin"):][:6])
        # Only what was recorded is passed; nothing is invented for a manifest without it.
        partial = self._cmd({"run_id": "R", "security_mode": "standard", "flags": {},
                             "matrix": {"origin": "committed", "config_sha256": None,
                                        "setup_draft": None}})
        self.assertEqual("committed", partial[partial.index("--matrix-origin") + 1])
        self.assertNotIn("--matrix-config-sha256", partial)
        self.assertNotIn("--matrix-setup-draft", partial)
        for absent in ({}, {"matrix": None}, {"matrix": "committed"}, {"matrix": {"origin": 3}}):
            cmd = self._cmd(dict({"run_id": "R", "security_mode": "standard", "flags": {}},
                                 **absent))
            self.assertFalse([arg for arg in cmd if arg.startswith("--matrix-")])

    def test_the_scanned_commit_reaches_the_report(self):
        # #3560: the manifest's provenance (#1492) rides the same argv route and parses back.
        import scripts.synthesize as synthesize_cli
        sha = "0123456789abcdef0123456789abcdef01234567"
        for dirty, spelled in ((False, "false"), (True, "true")):
            with self.subTest(dirty=dirty):
                cmd = self._cmd({"run_id": "R", "security_mode": "standard", "flags": {},
                                 "target_commit": sha, "target_dirty": dirty})
                self.assertEqual(sha, cmd[cmd.index("--target-commit") + 1])
                self.assertEqual(spelled, cmd[cmd.index("--target-dirty") + 1])
                parsed = synthesize_cli.build_parser().parse_args(cmd[2:])
                self.assertEqual((sha, spelled), (parsed.target_commit, parsed.target_dirty))

    def test_the_strict_state_reaches_the_report(self):
        # #3582 (#3627 review 4): the manifest's model_strict rides the same argv route.
        import scripts.synthesize as synthesize_cli
        for strict, spelled in ((False, "false"), (True, "true")):
            with self.subTest(strict=strict):
                cmd = self._cmd({"run_id": "R", "security_mode": "standard", "flags": {},
                                 "model_strict": strict})
                self.assertEqual(spelled, cmd[cmd.index("--model-strict") + 1])
                self.assertEqual(spelled, synthesize_cli.build_parser().parse_args(
                    cmd[2:]).model_strict)
        for unrecorded in (None, "yes"):
            self.assertNotIn("--model-strict", self._cmd(
                {"run_id": "R", "security_mode": "standard", "flags": {},
                 "model_strict": unrecorded}))

    def test_an_unrecorded_commit_or_dirtiness_passes_nothing(self):
        # Not a Git checkout, or a refused status probe: null in the manifest, so the
        # report leaves the key absent rather than reading unknown as clean.
        cmd = self._cmd({"run_id": "R", "security_mode": "standard", "flags": {},
                         "target_commit": None, "target_dirty": None})
        self.assertNotIn("--target-commit", cmd)
        self.assertNotIn("--target-dirty", cmd)
        cmd = self._cmd({"run_id": "R", "security_mode": "standard", "flags": {},
                         "target_commit": "0" * 40, "target_dirty": "no"})
        self.assertIn("--target-commit", cmd)
        self.assertNotIn("--target-dirty", cmd)


class TestTheMidRunFlagParitiesWithSynthesizesParser(unittest.TestCase):
    """The driver-side pin above proves the flag is EMITTED; nothing proved
    the child accepts it. `tests/synth/helpers._cli_args` sets the attribute
    directly, bypassing argparse, so renaming or dropping the option in
    `synthesize.py` alone left every test green while the real child would
    exit 2 -- the #1602 no-parity-test class, reproduced.

    So this asserts the two halves against each other: the exact argv token
    the driver emits, parsed by synthesize's own parser."""

    def test_the_driver_argv_token_is_a_flag_synthesize_accepts(self):
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as d:
            root = os.path.realpath(d)
            os.makedirs(runio._pano(root))
            with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
                synthesize.synthesize_execute(
                    root, {"run_id": "R", "security_mode": "standard",
                           "flags": {},
                           "flag_changes": [{"flag": "tools", "from": None,
                                             "to": False, "at": "2026-09-15T00:00:00Z"}]})
        flags = [a for a in captured["cmd"] if a.startswith("--tools-disabled")]
        self.assertEqual(len(flags), 1, captured["cmd"])
        # The child's OWN parser, not a hand-built Namespace: an unknown
        # option here is a SystemExit(2), which is what the real child does.
        parsed = syn.build_parser().parse_args(flags)
        self.assertIs(parsed.tools_disabled_mid_run, True)


class TestTheSuppressedGitDriversReachTheChild(unittest.TestCase):
    """#2013: the manifest is the disclosure of record, and the REPORT is where
    an operator meets it.

    `run-manifest.json` is a top-level artifact, outside the `--run-dir` the
    synthesize child resolves everything against, so the driver threads the
    fact in on the argv -- the same route `--tools-disabled-mid-run` takes, and
    for the same reason.
    """

    def setUp(self):
        self.root = os.path.realpath(
            self.enterContext(tempfile.TemporaryDirectory()))
        os.makedirs(runio._pano(self.root))

    def _cmd(self, manifest):
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            synthesize.synthesize_execute(self.root, manifest)
        return captured["cmd"]

    def _manifest(self, suppressed):
        return {"run_id": "R", "security_mode": "standard", "flags": {},
                "git_drivers_suppressed": suppressed}

    def test_the_pairs_are_passed_when_the_manifest_records_them(self):
        cmd = self._cmd(self._manifest(
            [{"repo": ".", "key": "filter.lfs.clean"},
             {"repo": "vendor/sub", "key": "diff.external"}]))
        self.assertIn("--git-drivers-suppressed", cmd)
        value = cmd[cmd.index("--git-drivers-suppressed") + 1]
        self.assertEqual(json.loads(value),
                         [{"repo": ".", "key": "filter.lfs.clean"},
                          {"repo": "vendor/sub", "key": "diff.external"}])

    def test_a_clean_target_passes_nothing(self):
        self.assertNotIn("--git-drivers-suppressed", self._cmd(self._manifest([])))

    def test_a_manifest_predating_the_field_passes_nothing(self):
        self.assertNotIn("--git-drivers-suppressed",
                         self._cmd({"run_id": "R", "security_mode": "standard",
                                    "flags": {}}))

    def test_the_driver_argv_token_is_a_flag_synthesize_accepts(self):
        # The #1602 parity rule: the emitted token, parsed by the CHILD's own
        # parser, because `_cli_args` sets attributes and argparse never runs.
        cmd = self._cmd(self._manifest([{"repo": ".", "key": "filter.lfs.clean"}]))
        index = cmd.index("--git-drivers-suppressed")
        parsed = syn.build_parser().parse_args(cmd[index:index + 2])
        self.assertEqual(json.loads(parsed.git_drivers_suppressed),
                         [{"repo": ".", "key": "filter.lfs.clean"}])


class TestTheDispatchPlanObligationReachesTheChild(unittest.TestCase):
    """SEC-377944137 (#1832): the child cannot tell a deleted driver plan from a
    run that never had one, so the driver -- which holds the manifest -- says.

    The anchor is the manifest's `driver_plan` STAMP, written by the writer at
    the moment it writes the plan (`requests._write_driver_plan` ->
    `run_manifest.claim_artifact`). Fix round 1 replaced an inference off the
    rolling `dispatch_request` slot with it: that slot is overwritten per
    checkpoint, so it read `verify` on every run that verified anything, and the
    tamper itself could roll it BACKWARD to `scout` (deleting
    `coverage-<group>.json` makes `coverage_done` False and the coverage phase
    re-dispatches scout). It also could not tell a tool-advisor `verify` dispatch
    from a review one, so an honest ZERO-CELL run that verified a tool finding
    read INCONCLUSIVE.

    The manifest is the anchor rather than the plan because a plan cannot attest
    to its own existence, and it is the better-defended of the two files
    (#1727) -- better-defended, not out of reach: where the write guard mediates
    `Write` no dispatched agent may write `run-manifest.json`, and
    `runio._foreign_manifest` discards a git-tracked or foreign-stamped one. It
    is threaded on the argv like `--tools-disabled-mid-run`, because
    `run-manifest.json` is a _TOP_LEVEL artifact outside the `--run-dir` the
    child resolves everything else against.
    """

    def setUp(self):
        self.root = os.path.realpath(
            self.enterContext(tempfile.TemporaryDirectory()))
        os.makedirs(runio._pano(self.root))
        adopt_panopticon(self.root)   # #3273 P1: a run of ours (synthesize makes first contact)
        # No groups => `_driver_plan_entries` declares no cells => this phase
        # writes NO dispatch-plan-driver.json. That is the on-disk state a
        # deletion leaves, reached without tampering with the tree. The
        # cells-declared shape is exercised by the class below.
        runio._write_json(runio._pano(self.root, "groups.json"), {"mode": "repo", "groups": []})

    def _manifest(self, **kw):
        # `fail_on` so the gate is ARMED: with no findings its base verdict is
        # PASS, which the integrity failure then raises to INCONCLUSIVE. An
        # unarmed run reports OFF and preserves it, so the gate assertions
        # below would say nothing.
        m = {"run_id": "R", "security_mode": "standard",
             "flags": {"fail_on": "high"}}
        m.update(kw)
        return m

    def _cmd(self, manifest):
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            synthesize.synthesize_execute(self.root, manifest)
        return captured["cmd"]

    def _report(self, manifest):
        """The REAL child, so the flag is proved to reach the artifact."""
        with contextlib.redirect_stderr(io.StringIO()):
            synthesize.synthesize_execute(self.root, manifest)
        self.assertFalse(os.path.exists(
            runio._pano(self.root, "dispatch-plan-driver.json")))
        return runio._load_json(runio._pano(self.root, "report.json"))

    def _stamped(self, sha256="a" * 64, **kw):
        return self._manifest(**dict(
            kw, **{run_manifest.DRIVER_PLAN: {"sha256": sha256, "at": "t"}}))

    def test_a_stamped_plan_that_is_gone_is_a_deletion(self):
        report = self._report(self._stamped())
        integrity = report["meta"]["integrity"]
        self.assertIs(integrity["dispatch_plan_missing"], True)
        self.assertEqual(integrity["plans_seen"], 0)
        self.assertIs(report["summary"]["coverage_certified"], False)
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")

    def test_an_unstamped_manifest_owes_no_plan(self):
        report = self._report(self._manifest())
        integrity = report["meta"]["integrity"]
        self.assertIs(integrity["dispatch_plan_missing"], False)
        self.assertEqual(integrity["plans_seen"], 0)
        # The same armed gate the case above raises to INCONCLUSIVE stays PASS
        # here, so that assertion is about this key and not about the fixture.
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_an_honest_zero_cell_run_that_verified_a_tool_finding_still_passes(self):
        # Fix round 1, I2. `verify_tools` records `checkpoint="verify"` for tool
        # findings ALONE, independently of review cells, and the record does not
        # keep the `group="tools"` discriminator -- so the old checkpoint
        # inference read a plan as owed on a run that correctly wrote none.
        report = self._report(self._manifest(
            **{run_manifest.DISPATCH_REQUEST:
               {"checkpoint": "verify", "sha256": "c" * 64, "at": "t"}}))
        self.assertIs(report["meta"]["integrity"]["dispatch_plan_missing"], False)
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_a_rolled_back_dispatch_record_cannot_un_owe_the_plan(self):
        # Fix round 1, I1. The tamper that makes the plan un-creatable (rm the
        # coverage file) also makes `coverage_done` False, and the coverage
        # phase re-dispatches scout -- rewriting the rolling slot to `scout` on
        # a run that had dispatched every review cell. The stamp is MONOTONE, so
        # it survives that.
        report = self._report(self._stamped(
            **{run_manifest.DISPATCH_REQUEST:
               {"checkpoint": "scout", "sha256": "d" * 64, "at": "t"}}))
        self.assertIs(report["meta"]["integrity"]["dispatch_plan_missing"], True)

    def test_the_flag_is_emitted_only_when_the_plan_is_owed(self):
        self.assertIn("--plan-owed", self._cmd(self._stamped()))
        self.assertNotIn("--plan-owed", self._cmd(self._manifest()))

    def test_the_stamped_hash_is_threaded_beside_the_flag(self):
        cmd = self._cmd(self._stamped(sha256="b" * 64))
        self.assertEqual(cmd[cmd.index("--plan-sha256") + 1], "b" * 64)
        # A stamp with no usable hash still owes the plan -- the boolean is the
        # gate, the hash only strengthens it (the #493 R2 ack reads the same way).
        self.assertNotIn("--plan-sha256", self._cmd(self._stamped(sha256=None)))

    def test_the_snapshot_stamp_hash_is_threaded_to_synthesis(self):
        manifest = self._stamped(**{
            run_manifest.OUT_FILE_SNAPSHOT: {"sha256": "c" * 64, "at": "t"}})
        cmd = self._cmd(manifest)
        self.assertEqual(cmd[cmd.index("--snapshot-sha256") + 1], "c" * 64)
        parsed = syn.build_parser().parse_args(
            cmd[cmd.index("--snapshot-sha256"):cmd.index("--snapshot-sha256") + 2])
        self.assertEqual(parsed.snapshot_sha256, "c" * 64)

        legacy = self._stamped(**{
            run_manifest.OUT_FILE_SNAPSHOT: {"cells": 1, "at": "t"}})
        self.assertNotIn("--snapshot-sha256", self._cmd(legacy))

    def test_the_driver_argv_tokens_are_flags_synthesize_accepts(self):
        # The #1602 parity rule: `tests/synth/helpers._cli_args` builds a
        # Namespace directly, so argparse never runs and a renamed option would
        # stay green here while the real child exits 2.
        cmd = self._cmd(self._stamped(sha256="b" * 64))
        index = cmd.index("--plan-owed")
        parsed = syn.build_parser().parse_args(cmd[index:index + 3])
        self.assertIs(parsed.plan_owed, True)
        self.assertEqual(parsed.plan_sha256, "b" * 64)

    def test_a_garbled_stamp_owes_nothing(self):
        # The manifest lives inside the reviewed tree, so every field on it is a
        # value a target can choose. A non-dict is not this driver's stamp, so it
        # asserts nothing -- and must not raise out of a predicate that decides
        # a flag.
        for planted in ("yes", ["yes"], 7, None, {}):
            with self.subTest(planted=planted):
                self.assertFalse(synthesize._plan_owed(
                    {run_manifest.DRIVER_PLAN: planted}))
        self.assertFalse(synthesize._plan_owed({}))
        self.assertFalse(synthesize._plan_owed(None))


class TestTheOwedPlanOnTheLiveDriverPath(unittest.TestCase):
    """Fix round 1, C1 + I4: the same four rows over a run that DECLARED CELLS,
    through the real `synthesize_execute` and the real child.

    Every phase-level case above uses a zero-group fixture, which is the only
    shape that leaves no plan without touching the tree -- and that is exactly
    why the re-creation went unnoticed: `synthesize_execute` opens by calling
    `requests._write_driver_plan` and `requests._snapshot_review_out_files`,
    both of which used to re-arm the moment their file was deleted. The plan was
    re-created and the snapshot re-taken OVER THE SUBSTITUTED BYTES, so the
    substitution became its own baseline and #1208's guard did not fire either.
    """

    RUN_ID = "RID"

    def setUp(self):
        self.root = os.path.realpath(
            self.enterContext(tempfile.TemporaryDirectory()))
        os.makedirs(os.path.join(self.root, "src"))
        with open(os.path.join(self.root, "src", "app.py"), "w") as fh:
            fh.write("def f():\n    return 1\n")
        os.makedirs(runio._pano(self.root))
        adopt_panopticon(self.root)   # #3273 P1: a run of ours (synthesize makes first contact)
        self.manifest = run_manifest.build_manifest(
            target=self.root, review_root=self.root, host="claude",
            security_mode="standard", run_id=self.RUN_ID,
            flags={"fail_on": "high"})
        run_manifest.write_manifest(self.root, our_manifest(self.root, self.manifest))
        write_host_evidence(self.root, {c: hosts.PROVEN for c in hosts.CAPABILITIES})
        runio._write_json(runio._pano(self.root, "groups.json"),
                          {"mode": "repo", "groups": [{"name": "app", "files": ["src/app.py"]}]})
        with open(os.path.join(self.root, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\ngroups:\n  app:\n    match: ['src/**']\n")
        runio._write_json(runio._pano(self.root, "coverage-app.json"),
                          {"group": "app", "floor": ["QAL"],
                           "effective": ["QAL"], "run_id": self.RUN_ID})
        self.plan = runio._pano(self.root, "dispatch-plan-driver.json")
        self.snapshot = runio._pano(self.root, "out-file-hashes.json")
        self.cell = runio._pano(self.root, "findings-app-QAL.json")

    def _drive_to_the_snapshot(self):
        """review -> verify, self-writing each declared cell, as the driver does."""
        result = review_phase.review_execute(self.root, self.manifest)
        self.assertEqual(result.checkpoint, "review")
        for entry in requests.load_dispatch_request(self.root)["entries"]:
            runio._write_json(entry["out_file"], {
                "findings": [{"title": "nit", "severity": "LOW", "domain": "QAL",
                              "code": "QAL-A1A", "category": "style",
                              "location": {"file": "src/app.py", "line_start": 1}}],
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": "QAL", "group": "app"}})
        self.assertTrue(review_phase.review_done(self.root, self.manifest))
        verify_phase.verify_execute(self.root, self.manifest)   # takes the snapshot
        self.assertTrue(os.path.isfile(self.plan))
        self.assertTrue(os.path.isfile(self.snapshot))

    def _substitute(self):
        """Drop the finding AFTER the snapshot -- the tamper #1208 detects."""
        runio._write_json(self.cell, {
            "findings": [],
            "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                            "domain": "QAL", "group": "app"}})

    def _synthesize(self):
        with contextlib.redirect_stderr(io.StringIO()):
            synthesize.synthesize_execute(self.root, self.manifest)
        report = runio._load_json(runio._pano(self.root, "report.json"))
        return report["meta"]["integrity"], report["summary"]

    def test_row_1_an_honest_run_certifies(self):
        self._drive_to_the_snapshot()
        integrity, summary = self._synthesize()
        self.assertEqual(integrity["content_mismatched_files"], [])
        self.assertIs(integrity["dispatch_plan_missing"], False)
        self.assertIs(integrity["dispatch_plan_mismatched"], False)
        self.assertNotEqual(summary["gate"], "INCONCLUSIVE")
        self.assertIs(summary["coverage_certified"], True)

    def test_row_2_a_substitution_with_the_evidence_intact_is_caught(self):
        self._drive_to_the_snapshot()
        self._substitute()
        integrity, summary = self._synthesize()
        self.assertTrue(integrity["content_mismatched_files"])
        self.assertEqual(summary["gate"], "INCONCLUSIVE")

    def test_row_3_deleting_the_snapshot_does_not_launder_the_substitution(self):
        # #1208's row, on the LIVE path. The snapshot must NOT be re-taken: it
        # would hash the substituted bytes and report a clean run.
        self._drive_to_the_snapshot()
        self._substitute()
        os.remove(self.snapshot)
        integrity, summary = self._synthesize()
        self.assertFalse(os.path.exists(self.snapshot), "the snapshot was re-taken")
        self.assertIs(integrity["content_snapshot_missing"], True)
        self.assertEqual(summary["gate"], "INCONCLUSIVE")

    def test_row_4_deleting_the_plan_too_does_not_launder_it_either(self):
        # THE FINDING's row. The plan must NOT be re-created: `plans_seen` would
        # go back to 1 and every plan-keyed check would read benign again.
        self._drive_to_the_snapshot()
        self._substitute()
        os.remove(self.snapshot)
        os.remove(self.plan)
        integrity, summary = self._synthesize()
        self.assertFalse(os.path.exists(self.plan), "the plan was re-created")
        self.assertEqual(integrity["plans_seen"], 0)
        self.assertIs(integrity["dispatch_plan_missing"], True)
        self.assertEqual(summary["gate"], "INCONCLUSIVE")
        self.assertIs(summary["coverage_certified"], False)

    def test_row_5_replacing_the_snapshot_with_forged_hashes_is_caught(self):
        """#2115: the manifest binds the exact snapshot bytes the driver wrote."""
        self._drive_to_the_snapshot()
        self._substitute()
        group_runner.snapshot_out_files(
            [{"out_file": self.cell}], out_path=self.snapshot)
        integrity, summary = self._synthesize()
        self.assertEqual(integrity["content_mismatched_files"], [])
        self.assertIs(integrity["content_snapshot_mismatched"], True)
        self.assertEqual(summary["gate"], "INCONCLUSIVE")

    def test_row_6_a_preplanted_snapshot_has_no_driver_binding(self):
        """#2115 amendment: a present snapshot is not proof the driver wrote it."""
        result = review_phase.review_execute(self.root, self.manifest)
        self.assertEqual(result.checkpoint, "review")
        self._substitute()
        group_runner.snapshot_out_files(
            [{"out_file": self.cell}], out_path=self.snapshot)
        for entry in requests.load_dispatch_request(self.root)["entries"]:
            runio._write_json(entry["out_file"], {
                "findings": [{"title": "nit", "severity": "LOW", "domain": "QAL",
                              "code": "QAL-A1A", "category": "style",
                              "location": {"file": "src/app.py", "line_start": 1}}],
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": "QAL", "group": "app"}})
        self.assertTrue(review_phase.review_done(self.root, self.manifest))
        verify_phase.verify_execute(self.root, self.manifest)
        self.assertIsNone(run_manifest.artifact_stamp(
            self.manifest, run_manifest.OUT_FILE_SNAPSHOT))
        self._substitute()
        integrity, summary = self._synthesize()
        self.assertEqual(integrity["content_mismatched_files"], [])
        self.assertIs(integrity["content_snapshot_mismatched"], True)
        self.assertEqual(summary["gate"], "INCONCLUSIVE")

    # #3741 ------------------------------------------------------------------
    # A driver killed after the snapshot was written and before its manifest stamp
    # left "file present, no stamp", which is also what a pre-planted snapshot looks
    # like (row 6). The re-run completed NOT CERTIFIED, "substituted or pre-planted
    # evidence". What tells the two apart is whether THE DRIVER BEGAN the write: it
    # records that in the manifest before it opens the file.

    def _land_the_cells(self):
        result = review_phase.review_execute(self.root, self.manifest)
        self.assertEqual(result.checkpoint, "review")
        for entry in requests.load_dispatch_request(self.root)["entries"]:
            runio._write_json(entry["out_file"], {
                "findings": [{"title": "nit", "severity": "LOW", "domain": "QAL",
                              "code": "QAL-A1A", "category": "style",
                              "location": {"file": "src/app.py", "line_start": 1}}],
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": "QAL", "group": "app"}})
        self.assertTrue(review_phase.review_done(self.root, self.manifest))

    def _killed_during(self, target, name):
        """The first verify pass, killed at `target.name`; then the next process's
        manifest, read off disk."""
        with mock.patch.object(target, name, side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            verify_phase.verify_execute(self.root, self.manifest)
        self.manifest = run_manifest.load_manifest(self.root)

    def _stamp(self):
        return run_manifest.artifact_stamp(run_manifest.load_manifest(self.root),
                                           run_manifest.OUT_FILE_SNAPSHOT)

    def test_row_7_a_driver_killed_between_the_snapshot_and_its_stamp_recovers(self):
        self._land_the_cells()
        real = run_manifest.record_artifact_stamp

        def killed(review_root, manifest, key, *args, **kwargs):
            if key == run_manifest.OUT_FILE_SNAPSHOT:
                raise KeyboardInterrupt
            return real(review_root, manifest, key, *args, **kwargs)

        with mock.patch.object(run_manifest, "record_artifact_stamp", side_effect=killed), \
                self.assertRaises(KeyboardInterrupt):
            verify_phase.verify_execute(self.root, self.manifest)
        self.assertTrue(os.path.isfile(self.snapshot))
        self.assertIsNone(self._stamp())
        self.manifest = run_manifest.load_manifest(self.root)
        self.assertTrue(run_manifest.artifact_interrupted(self.manifest,
                                                          run_manifest.OUT_FILE_SNAPSHOT))
        verify_phase.verify_execute(self.root, self.manifest)          # the re-run
        with open(self.snapshot, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), self._stamp()["sha256"])
        self.assertFalse(run_manifest.artifact_interrupted(
            run_manifest.load_manifest(self.root), run_manifest.OUT_FILE_SNAPSHOT))
        integrity, summary = self._synthesize()
        # It was: content_snapshot_mismatched, INCONCLUSIVE, not certified.
        self.assertIs(integrity["content_snapshot_mismatched"], False)
        self.assertEqual(integrity["content_mismatched_files"], [])
        self.assertNotEqual(summary["gate"], "INCONCLUSIVE")
        self.assertIs(summary["coverage_certified"], True)

    def test_row_8_killed_after_it_began_and_before_the_file_exists_recovers_too(self):
        self._land_the_cells()
        self._killed_during(group_runner, "snapshot_out_files")
        self.assertFalse(os.path.exists(self.snapshot))
        self.assertTrue(run_manifest.artifact_interrupted(self.manifest,
                                                          run_manifest.OUT_FILE_SNAPSHOT))
        verify_phase.verify_execute(self.root, self.manifest)
        self.assertTrue(os.path.isfile(self.snapshot))
        integrity, summary = self._synthesize()
        self.assertIs(integrity["content_snapshot_mismatched"], False)
        self.assertIs(summary["coverage_certified"], True)

    def test_the_driver_says_it_has_begun_before_it_opens_the_snapshot(self):
        self._land_the_cells()
        seen = []
        real = group_runner.snapshot_out_files

        def snapshot(plan, out_path):
            on_disk = run_manifest.load_manifest(self.root)
            seen.append((os.path.exists(out_path),
                         run_manifest.artifact_interrupted(on_disk, run_manifest.OUT_FILE_SNAPSHOT),
                         run_manifest.artifact_stamp(on_disk, run_manifest.OUT_FILE_SNAPSHOT)))
            return real(plan, out_path=out_path)

        with mock.patch.object(group_runner, "snapshot_out_files", side_effect=snapshot):
            verify_phase.verify_execute(self.root, self.manifest)
        # Durable in the manifest ON DISK, with no file yet and no stamp yet.
        self.assertEqual([(False, True, None)], seen)

    def test_row_9_a_snapshot_planted_over_the_interrupted_one_is_replaced_by_the_drivers(self):
        """The driver had begun, so whatever is at the path on the re-run is replaced
        by its own snapshot of the cells as they are, before any advisor runs. A
        forged one put there in between buys nothing: the substitution it was forged
        for is caught against the driver's."""
        self._land_the_cells()
        real = run_manifest.record_artifact_stamp
        with mock.patch.object(run_manifest, "record_artifact_stamp",
                               side_effect=lambda rr, m, key, *a, **k: (_ for _ in ()).throw(
                                   KeyboardInterrupt) if key == run_manifest.OUT_FILE_SNAPSHOT
                               else real(rr, m, key, *a, **k)), \
                self.assertRaises(KeyboardInterrupt):
            verify_phase.verify_execute(self.root, self.manifest)
        with open(self.cell, "rb") as fh:
            honest = fh.read()
        self._substitute()                                          # the forgery's content
        group_runner.snapshot_out_files([{"out_file": self.cell}], out_path=self.snapshot)
        with open(self.cell, "wb") as fh:
            fh.write(honest)                                        # put back for the boundary
        self.manifest = run_manifest.load_manifest(self.root)
        verify_phase.verify_execute(self.root, self.manifest)          # the driver's own snapshot
        self._substitute()                                          # the substitution it was for
        integrity, summary = self._synthesize()
        self.assertTrue(integrity["content_mismatched_files"])
        self.assertEqual(summary["gate"], "INCONCLUSIVE")

    def test_row_6_again_a_snapshot_the_driver_never_began_is_left_as_it_is(self):
        # The pre-plant, seen from the driver: no "begun" record is written for a
        # file that was there first, and the file is not replaced.
        self._land_the_cells()
        with open(self.snapshot, "w") as fh:
            fh.write('{"planted": "0"}')
        verify_phase.verify_execute(self.root, self.manifest)
        on_disk = run_manifest.load_manifest(self.root)
        self.assertFalse(run_manifest.artifact_interrupted(on_disk, run_manifest.OUT_FILE_SNAPSHOT))
        self.assertNotIn(run_manifest.ARTIFACT_BEGUN[run_manifest.OUT_FILE_SNAPSHOT], on_disk)
        self.assertIsNone(run_manifest.artifact_stamp(on_disk, run_manifest.OUT_FILE_SNAPSHOT))
        with open(self.snapshot) as fh:
            self.assertEqual('{"planted": "0"}', fh.read())
        integrity, summary = self._synthesize()
        self.assertIs(integrity["content_snapshot_mismatched"], True)
        self.assertEqual(summary["gate"], "INCONCLUSIVE")

    def test_a_stamped_snapshot_that_is_gone_is_still_never_re_taken(self):
        # Row 3's rule is untouched by the "begun" record, which is still in the manifest.
        self._drive_to_the_snapshot()
        on_disk = run_manifest.load_manifest(self.root)
        self.assertIn(run_manifest.ARTIFACT_BEGUN[run_manifest.OUT_FILE_SNAPSHOT], on_disk)
        self.assertFalse(run_manifest.artifact_interrupted(on_disk, run_manifest.OUT_FILE_SNAPSHOT))
        os.remove(self.snapshot)
        with contextlib.redirect_stderr(io.StringIO()):
            verify_phase.verify_execute(self.root, on_disk)
        self.assertFalse(os.path.exists(self.snapshot))

    def test_replacing_the_plan_is_caught_as_well_as_deleting_it(self):
        # The stamp carries the plan's canonical content hash, so a plan that is
        # PRESENT but is not the one this run wrote reads as tamper -- otherwise
        # re-writing the plan would be a cheaper `rm`.
        #
        # `enforced` is the field flipped here BECAUSE nothing else notices it:
        # the plan stays contract-valid (so `invalid_dispatch_plans` is empty)
        # and declares the same out_file (so reconcile agrees), while
        # `plan.derive_tool_policy_mode` reads it to report the run's tool-policy
        # posture -- flipping it makes an UNENFORCED run's report claim it was
        # enforced. The hash is the only thing standing in the way.
        self._drive_to_the_snapshot()
        plan = runio._load_json(self.plan)
        self.assertIs(plan[0]["enforced"], True)
        plan[0]["enforced"] = False
        runio._write_json(self.plan, plan)
        integrity, summary = self._synthesize()
        self.assertIs(integrity["dispatch_plan_mismatched"], True)
        self.assertEqual(integrity["invalid_dispatch_plans"], [])
        self.assertEqual(integrity["missing_planned_files"], [])
        self.assertEqual(summary["gate"], "INCONCLUSIVE")

    def test_the_vacuous_verify_fallback_still_takes_the_first_snapshot(self):
        # #5.0-16: when the verify phase is vacuously done no agent ran, so
        # synthesize takes the FIRST snapshot. Nothing is owed yet, so the
        # owed-once refusal must not break it.
        result = review_phase.review_execute(self.root, self.manifest)
        for entry in requests.load_dispatch_request(self.root)["entries"]:
            runio._write_json(entry["out_file"], {
                "findings": [],
                "_panopticon": {"run_id": self.RUN_ID, "role": "domain_panel",
                                "domain": "QAL", "group": "app"}})
        self.assertEqual(result.checkpoint, "review")
        self.assertFalse(os.path.exists(self.snapshot))
        integrity, summary = self._synthesize()
        self.assertTrue(os.path.isfile(self.snapshot))
        self.assertGreaterEqual(integrity["content_hashes_checked"], 1)
        self.assertNotEqual(summary["gate"], "INCONCLUSIVE")


class TestSynthesizeDonePredicate(unittest.TestCase):
    """#1643 ruling 3: the last parse-only done predicate in the run loop.

    Nothing downstream reads the report into an `all(...)`, so there is no
    vacuous-completion chain here -- but the phase's own schema validation (the
    `error` on ARTIFACT_INVALID) only runs when the phase RUNS, and a report
    artifact that merely parses used to skip it.
    """

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard"}

    def _write(self, doc):
        runio._write_json(runio._report_out(self.root), doc)

    def test_an_empty_report_object_is_not_done(self):
        self._write({})
        self.assertFalse(synthesize.synthesize_done(self.root, self.manifest))

    def test_a_report_with_a_summary_is_done(self):
        self._write({"schema_version": 1, "summary": {"gate": "PASS"}, "findings": []})
        self.assertTrue(synthesize.synthesize_done(self.root, self.manifest))

    def test_the_execute_side_fails_loudly_rather_than_letting_the_engine_spin(self):
        # The guard and the predicate are the same test: a report this phase
        # would refuse to call done must not be returned as "advanced", or the
        # engine re-selects the run's most expensive phase every step.
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": []}, fh)          # parses; no summary
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            with self.assertRaises(runio.DriverError) as cm:
                synthesize.synthesize_execute(self.root, self.manifest)
        self.assertIn("no usable report.json", str(cm.exception))

    def test_the_message_quotes_the_end_of_what_the_child_said(self):
        # #3741: it quoted the first 400 characters of stderr, which are warnings.
        # The cause is the last thing the child printed.
        warnings = "".join("synthesize: warning %03d: a line about nothing\n" % n for n in range(40))

        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": []}, fh)
            return mock.Mock(returncode=0, stdout="",
                             stderr=warnings + "synthesize: THE CAUSE: the report has no summary\n")
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            with self.assertRaises(runio.DriverError) as cm:
                synthesize.synthesize_execute(self.root, self.manifest)
        message = str(cm.exception)
        self.assertIn("THE CAUSE: the report has no summary", message)
        self.assertNotIn("warning 000", message)
        self.assertLessEqual(len(message), len("synthesize produced no usable report.json (rc=0): ") + 400)
        # With nothing on stderr it is the end of stdout.
        def quiet(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": []}, fh)
            return mock.Mock(returncode=0, stdout="x" * 500 + "the last words", stderr="")
        with mock.patch("scripts.phases.child._run_child", side_effect=quiet):
            with self.assertRaises(runio.DriverError) as cm:
                synthesize.synthesize_execute(self.root, self.manifest)
        self.assertTrue(str(cm.exception).endswith("the last words"))


class TestTheConfigResolutionSeam(unittest.TestCase):
    """#1681 Plan 2 (final review M5): the PHASE writes the config resolution
    through `runio._pano`, and the synthesize CHILD reads it with
    `config_schema.load_resolution(run_dir)` -- where `run_dir` is the folder
    of the `--groups` path this same phase hands it. Two independent
    derivations of one location, and nothing fails if they part: `meta.config`
    just goes quietly empty, and the report stops saying that the reviewed
    repository tried to move its own review's settings.
    """

    def _synthesize(self, root, manifest):
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            synthesize.synthesize_execute(root, manifest)
        return captured["cmd"]

    def test_the_phase_writes_the_artifact_where_the_child_reads_it(self):
        settings = config_schema.resolve_settings({}, config_schema.parse_settings(
            {"settings": {"max_per_group": 5000, "allow_unenforced": True}}))
        with tempfile.TemporaryDirectory() as d:
            root = os.path.realpath(d)
            manifest = run_manifest.build_manifest(
                target=root, review_root=root, host="claude",
                security_mode="standard", config=settings, run_id="R")
            run_manifest.write_manifest(root, manifest)
            cmd = self._synthesize(root, manifest)
            groups_path = cmd[cmd.index("--groups") + 1]
            # synthesize.py: `run_dir = args.run_dir or dirname(--groups)`.
            self.assertNotIn("--run-dir", cmd)
            loaded = config_schema.load_resolution(os.path.dirname(groups_path))
        # The per-run folder, not flat `.panopticon`: the seam only has a
        # failure mode at all because these paths differ once a run exists.
        self.assertIn(os.path.join("runs", run_manifest.run_tag(manifest)),
                      groups_path)
        self.assertEqual(loaded["effective"], {"max_per_group": 48})
        self.assertEqual(loaded["clamped"][0]["requested"], 5000)
        self.assertEqual([r["key"] for r in loaded["refused"]], ["allow_unenforced"])
        self.assertTrue(loaded["disclosures"])


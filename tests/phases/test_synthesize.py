"""Tests for scripts.phases.synthesize: the synthesize child and host-usage collection.
"""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from scripts import hosts
from conftest import write_host_evidence
import scripts.phases.runio as runio
import scripts.phases.synthesize as synthesize

import scripts.driver as driver

_UL_PROVEN = {hosts.USAGE_LEDGER: hosts.PROVEN}


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
             mock.patch("scripts.phases.runio._run_child") as run:
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
             mock.patch("scripts.phases.runio._run_child") as run:
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
             mock.patch("scripts.phases.runio._run_child") as run:
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
             mock.patch("scripts.phases.runio._run_child") as run:
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
             mock.patch("scripts.phases.runio._run_child") as run, \
             contextlib.redirect_stderr(buf):
            write_host_evidence(d, _UL_PROVEN)
            run.return_value = mock.Mock(returncode=1)
            synthesize._collect_host_usage(
                d, self._manifest(session_dir="/somewhere/session"))
        err = buf.getvalue()
        self.assertIn("/somewhere/session", err)
        self.assertIn("--session-dir", err)

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

    def test_max_per_group_absent_leaves_discovery_default_alone(self):
        # Omitting it must not pass the flag at all, so discovery's own default
        # stays the single source of truth for the value.
        class _Args:
            tools = no_tools = include_fixtures = False
            fail_on = severity = gate_scope = diff_context = max_per_group = None

        self.assertIsNone(driver._cli_flags(_Args())["max_per_group"])

    def test_non_claude_host_is_skipped(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.runio._run_child") as run:
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
             mock.patch("scripts.phases.runio._run_child") as run:
            self.assertIsNone(synthesize._collect_host_usage(d, m))
        run.assert_not_called()

    def test_existing_usage_is_never_overwritten_on_resume(self):
        # #1344 F3: without proven evidence this would short-circuit on the
        # posture check above and pass for the WRONG reason, no longer
        # exercising the resume early-return this test names. Prove the
        # capability so the file-exists branch is what actually runs.
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.runio._run_child") as run:
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
             mock.patch("scripts.phases.runio._run_child",
                        side_effect=runio.DriverError("boom")), \
             contextlib.redirect_stderr(io.StringIO()) as err:
            write_host_evidence(d, _UL_PROVEN)
            self.assertIsNone(synthesize._collect_host_usage(d, self._manifest()))
        self.assertIn("meta.cost.tokens stays null", err.getvalue())

    def test_no_transcript_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("scripts.phases.runio._run_child",
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
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard",
                         "flags": {"fail_on": "high"}}

    def test_builds_report_via_verdicts_dir_form(self):
        captured = {}
        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "A", "findings": []}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("subprocess.run", side_effect=fake_run):
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

    def test_tools_dir_added_only_when_tools_ran(self):
        runio._write_json(runio._pano(self.root, "tools-ran.json"),
                           {"ran": True, "run_id": "R"})
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": []}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("subprocess.run", side_effect=fake_run) as rm_:
            synthesize.synthesize_execute(self.root, self.manifest)
        self.assertIn("--tools-dir", rm_.call_args[0][0])

    def test_gate_fail_nonzero_still_advances_when_report_present(self):
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "F", "findings": []}, fh)
            return mock.Mock(returncode=2, stdout="", stderr="gate failed")  # non-zero
        with mock.patch("subprocess.run", side_effect=fake_run):
            result = synthesize.synthesize_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")

    def test_absent_report_raises(self):
        with mock.patch("subprocess.run",
                        return_value=mock.Mock(returncode=1, stdout="", stderr="boom")):
            with self.assertRaises(runio.DriverError):
                synthesize.synthesize_execute(self.root, self.manifest)

    def test_diff_context_forwarded_when_set(self):
        manifest = dict(self.manifest,
                        flags={"fail_on": "high", "diff_context": 5})
        captured = {}
        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "A", "findings": []}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("subprocess.run", side_effect=fake_run):
            synthesize.synthesize_execute(self.root, manifest)
        cmd = captured["cmd"]
        self.assertIn("--diff-context", cmd)
        self.assertEqual(cmd[cmd.index("--diff-context") + 1], "5")

    def test_diff_context_absent_when_unset(self):
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "A", "findings": []}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("subprocess.run", side_effect=fake_run) as run:
            synthesize.synthesize_execute(self.root, self.manifest)
        self.assertNotIn("--diff-context", run.call_args.args[0])

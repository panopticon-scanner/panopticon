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
import scripts.config_schema as config_schema
import scripts.evidence as evidence
import scripts.phases.runio as runio
import scripts.phases.verify_tools as verify_tools
import scripts.run_manifest as run_manifest
import scripts.synthesize as syn
import scripts.synth.validate_schema as validate_schema_mod
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
                         {"groups": [{"name": "app", "files": ["src/app.py"]}]})
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

    def test_tools_dir_added_only_when_tools_ran(self):
        runio._write_json(runio._pano(self.root, "tools-ran.json"),
                           {"ran": True, "run_id": "R"})
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run) as rm_:
            synthesize.synthesize_execute(self.root, self.manifest)
        self.assertIn("--tools-dir", rm_.call_args[0][0])

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

    def test_diff_context_forwarded_when_set(self):
        manifest = dict(self.manifest,
                        flags={"fail_on": "high", "diff_context": 5})
        captured = {}
        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "A", "findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run):
            synthesize.synthesize_execute(self.root, manifest)
        cmd = captured["cmd"]
        self.assertIn("--diff-context", cmd)
        self.assertEqual(cmd[cmd.index("--diff-context") + 1], "5")

    def test_diff_context_absent_when_unset(self):
        def fake_run(cmd, **kw):
            with open(cmd[cmd.index("--out") + 1], "w") as fh:
                json.dump({"grade": "A", "findings": [], "summary": {"gate": "PASS"}}, fh)
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("scripts.phases.child._run_child", side_effect=fake_run) as run:
            synthesize.synthesize_execute(self.root, self.manifest)
        self.assertNotIn("--diff-context", run.call_args.args[0])


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

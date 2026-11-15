"""#3673: the gate is armed at CRITICAL unless told otherwise.

Owner rulings, 2026-11-15:

1. With no `--fail-on` and no committed `fail_on`, the gate is CRITICAL.
2. Tightening (`high`, `medium`, `low`) is silent.
3. Turning it off is LOUD, on the terminal summary, in the JSON summary and in the HTML.

And the coordinator's: only the operator's `--fail-on off` turns the gate off. A committed
`fail_on: off` is written by the repository under review, so the ratchet refuses it like any
other loosening, and that refusal is just as loud.
"""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.config_schema as cs
import scripts.driver as driver
import scripts.evidence as evidence_mod
import scripts.html_report as html_report
import scripts.loop_progress as loop_progress
import scripts.orchestrate as orchestrate
import scripts.phases.runio as runio
import scripts.run_manifest as run_manifest
import scripts.synth.findings as findings_mod
import scripts.synth.render as render_mod
import scripts.synth.validate_schema as validate_schema
import scripts.synthesize as syn
from tests._test_helpers import adopt_panopticon, all_proven_artifact, docker_probe_runner
from tests.orchestrate_helpers import FakeRunner, LoopCase
from tests.synth.helpers import _agentic, _chdir

OFF_NOTICE = ("GATE DISABLED BY OPERATOR (`--fail-on off`): no finding can fail this run. "
              "Gate OFF is not a PASS")
REFUSED = ("the repository's own config asked to turn the gate off; REFUSED: the gate stays at "
           "CRITICAL. Only the operator's `--fail-on off` disables it")
REFUSED_NOTICE = "GATE-OFF REQUEST REFUSED: " + REFUSED


def _resolution(settings, **cli):
    """What the driver resolves from a committed `settings:` block and the command line."""
    return cs.resolve_settings(cli, cs.parse_settings({"settings": settings}))


class _Synthesized(unittest.TestCase):
    """One real `synthesize.py` run over agent findings an advisor has confirmed."""

    def _run(self, *flags, severities=(), settings=None):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            adopt_panopticon(d)
            run_dir = os.path.join(d, ".panopticon")
            findings = [_agentic(fid="AG-%03d" % n, sev=sev, code="SEC-A1A", domain="SEC",
                                 exploit_scenario="a request reaches it",
                                 location={"file": "app.py", "line_start": 10 * n})
                        for n, sev in enumerate(severities, 1)]
            cell = os.path.join(run_dir, "findings-g1-SEC.json")
            with open(cell, "w", encoding="utf-8") as fh:
                json.dump({"findings": findings}, fh)
            verdicts = os.path.join(run_dir, "verdicts")
            os.makedirs(verdicts)
            for finding in findings:
                with open(os.path.join(
                        verdicts, "%s.json" % evidence_mod.finding_fingerprint(finding)),
                        "w", encoding="utf-8") as fh:
                    json.dump({"finding_id": evidence_mod.matrix_finding_id(
                                   findings_mod.normalize_finding(finding)),
                               "verdict": "CONFIRMED", "reasoning": "verified"}, fh)
            if settings is not None:
                resolved = _resolution(settings)
                with open(os.path.join(run_dir, cs.RESOLUTION_NAME), "w", encoding="utf-8") as fh:
                    json.dump({"schema_version": cs.RESOLUTION_SCHEMA_VERSION,
                               "requested": resolved.requested, "effective": resolved.effective,
                               "refused": resolved.refused, "clamped": resolved.clamped,
                               "disclosures": resolved.disclosures}, fh)
                # What `driver._cli_flags` composes: the file's contribution, when it has one.
                if resolved.effective.get("fail_on"):
                    flags += ("--fail-on", resolved.effective["fail_on"])
            out = os.path.join(d, "report.json")
            terminal = io.StringIO()
            with contextlib.redirect_stdout(terminal), contextlib.redirect_stderr(io.StringIO()):
                code = syn.main(["--repo", "--run-dir", run_dir, "--verdicts-dir", verdicts,
                                 "--out", out, *flags, cell])
            with open(out, encoding="utf-8") as fh:
                report = json.load(fh)
            with open(out + ".html", encoding="utf-8") as fh:
                page = fh.read()
        self.assertEqual(0, report["meta"]["schema_errors"], "the report fails its own schema")
        self.assertEqual(["advisor_confirmed"] * len(severities),
                         [f["evidence"]["status"] for f in report["findings"]])
        return code, report, terminal.getvalue(), page


class TestTheDefaultGateIsCritical(_Synthesized):
    def test_the_parsers_say_so(self):
        self.assertEqual("critical", syn.build_parser().parse_args([]).fail_on)
        # The driver's own flag stays "no opinion", so a committed setting can still answer
        # and the manifest records what the operator typed.
        self.assertIsNone(driver.build_parser().parse_args(["run", "."]).fail_on)
        self.assertEqual("critical", cs.DEFAULTS["fail_on"])

    def test_no_flag_fails_on_a_confirmed_critical(self):
        code, report, _terminal, _page = self._run(severities=("CRITICAL",))
        self.assertEqual((1, "FAIL"), (code, report["summary"]["gate"]))
        self.assertEqual({"fail_on": "CRITICAL", "in_play": ["CRITICAL"],
                          "contributing": ["CRITICAL"]}, report["summary"]["gate_severities"])

    def test_no_flag_passes_a_confirmed_high(self):
        # The default is CRITICAL, not "everything": a HIGH is below the threshold.
        code, report, _terminal, _page = self._run(severities=("HIGH",))
        self.assertEqual((0, "PASS"), (code, report["summary"]["gate"]))
        self.assertEqual("CRITICAL", report["summary"]["gate_severities"]["fail_on"])

    def test_no_flag_and_the_explicit_default_are_one_gate(self):
        for severities in ((), ("HIGH",), ("CRITICAL", "LOW")):
            with self.subTest(severities=severities):
                bare = self._run(severities=severities)
                spelled = self._run("--fail-on", "critical", severities=severities)
                self.assertEqual(bare[0], spelled[0])
                self.assertEqual(bare[1]["summary"]["gate"], spelled[1]["summary"]["gate"])
                self.assertEqual(bare[1]["summary"]["gate_severities"],
                                 spelled[1]["summary"]["gate_severities"])


class TestTheExitCodeTable(_Synthesized):
    """The before and after the CHANGELOG states, for a run with no `--fail-on`. "Before" is
    what `--fail-on off` still does: no flag used to mean exactly that."""

    def test_a_clean_result(self):
        self.assertEqual((0, "OFF"), self._gate("--fail-on", "off"))
        self.assertEqual((0, "PASS"), self._gate())

    def test_a_confirmed_critical(self):
        self.assertEqual((0, "OFF"), self._gate("--fail-on", "off", severities=("CRITICAL",)))
        self.assertEqual((1, "FAIL"), self._gate(severities=("CRITICAL",)))

    def test_a_gate_relevant_coverage_gap(self):
        # A queued finding with no verdict is the gap: verification did not complete.
        self.assertEqual((0, "OFF"), self._unanswered("--fail-on", "off"))
        self.assertEqual((2, "INCONCLUSIVE"), self._unanswered())

    def _gate(self, *flags, severities=()):
        code, report, _terminal, _page = self._run(*flags, severities=severities)
        return code, report["summary"]["gate"]

    def _unanswered(self, *flags):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            adopt_panopticon(d)
            cell = os.path.join(d, ".panopticon", "findings-g1-SEC.json")
            with open(cell, "w", encoding="utf-8") as fh:
                json.dump({"findings": [_agentic(sev="HIGH")]}, fh)
            verdicts = os.path.join(d, ".panopticon", "verdicts")
            os.makedirs(verdicts)
            out = os.path.join(d, "report.json")
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = syn.main(["--repo", "--verdicts-dir", verdicts, "--out", out,
                                 *flags, cell])
            with open(out, encoding="utf-8") as fh:
                report = json.load(fh)
        self.assertEqual(1, report["meta"]["coverage"]["verdicts"]["unanswered"])
        return code, report["summary"]["gate"]


class TestTurningTheGateOffIsLoud(_Synthesized):
    def _off(self, *flags):
        return self._run("--fail-on", "off", *flags, severities=("CRITICAL",))

    def test_off_is_spelled_off_and_only_off(self):
        self.assertIsNone(syn.build_parser().parse_args(["--fail-on", "off"]).fail_on)
        self.assertIsNone(syn.build_parser().parse_args(["--fail-on", "OFF"]).fail_on)
        self.assertEqual("off", driver.build_parser().parse_args(
            ["run", ".", "--fail-on", "OFF"]).fail_on)
        for parser, argv in ((syn.build_parser(), []), (driver.build_parser(), ["run", "."])):
            for word in ("none", "no", "false", "0", ""):
                with self.subTest(word=word), self.assertRaises(SystemExit), \
                        contextlib.redirect_stderr(io.StringIO()):
                    parser.parse_args(argv + ["--fail-on", word])

    def test_the_gate_is_off_and_nothing_fails(self):
        code, report, _terminal, _page = self._off()
        self.assertEqual((0, "OFF"), (code, report["summary"]["gate"]))
        self.assertEqual({"fail_on": None, "in_play": [], "contributing": []},
                         report["summary"]["gate_severities"])

    def test_the_json_summary_says_who_disabled_it(self):
        _code, report, _terminal, _page = self._off()
        self.assertEqual({"disabled_by_operator": True, "source": "--fail-on off"},
                         report["summary"]["gate_disabled"])

    def test_the_terminal_summary_says_it_before_the_grade(self):
        _code, _report, terminal, _page = self._off()
        lines = terminal.splitlines()
        notice = lines.index("**%s**" % OFF_NOTICE)
        grade = next(n for n, line in enumerate(lines) if line.startswith("**Grade:**"))
        self.assertLess(notice, grade)
        self.assertIn("**Gate:** OFF", lines[grade])

    def test_the_html_carries_a_banner_before_the_badges(self):
        _code, report, _terminal, page = self._off()
        banner = "<div class='gate-notice' role='alert'>%s</div>" % html_report._escape(OFF_NOTICE)
        self.assertEqual(1, page.count(banner))
        self.assertLess(page.index(banner), page.index("<div class='badges'>"))
        self.assertIn(banner, html_report._render_compare_summary("A", report))

    def test_the_report_schema_pins_the_field(self):
        _code, report, _terminal, _page = self._off()
        self.assertEqual([], validate_schema.schema_errors(report))
        for wrong in ({"disabled_by_operator": False, "source": "--fail-on off"},
                      {"disabled_by_operator": True, "source": "panopticon.yml"},
                      {"disabled_by_operator": True}, {"source": "--fail-on off"},
                      {"disabled_by_operator": True, "source": "--fail-on off", "by": "x"},
                      True, "off"):
            with self.subTest(wrong=wrong):
                broken = dict(report, summary=dict(report["summary"], gate_disabled=wrong))
                self.assertTrue(validate_schema.schema_errors(broken))
        armed = dict(report, summary=dict(report["summary"], gate="PASS", gate_disabled=None))
        self.assertEqual([], validate_schema.schema_errors(armed))

    def test_every_surface_reads_one_definition(self):
        self.assertEqual(OFF_NOTICE, cs.GATE_OFF_NOTICE)
        self.assertEqual("--fail-on off", cs.GATE_OFF_SOURCE)

    def test_an_off_gate_cannot_be_reported_without_the_disclosure(self):
        # Read off the verdict, not off a flag that could be dropped on the way.
        self.assertIsNone(cs.gate_disabled("PASS"))
        self.assertIsNone(cs.gate_disabled("FAIL"))
        self.assertIsNone(cs.gate_disabled("INCONCLUSIVE"))
        self.assertEqual({"disabled_by_operator": True, "source": "--fail-on off"},
                         cs.gate_disabled("OFF"))
        self.assertEqual([OFF_NOTICE], cs.gate_notices({"gate": "OFF"}, None))


class TestTighteningIsSilent(_Synthesized):
    def _assert_silent(self, result):
        _code, report, terminal, page = result
        self.assertIsNone(report["summary"]["gate_disabled"])
        self.assertEqual([], report["meta"]["config"]["refused"])
        for surface in (terminal, page):
            self.assertNotIn("GATE DISABLED", surface)
            self.assertNotIn("REFUSED", surface)
            self.assertNotIn("<div class='gate-notice'", surface)
        self.assertNotIn("**Target config:**", terminal)

    def test_no_flag_at_all_says_nothing(self):
        self._assert_silent(self._run(severities=("CRITICAL",)))

    def test_a_tighter_flag_says_nothing(self):
        for level in ("critical", "high", "medium", "low"):
            with self.subTest(level=level):
                result = self._run("--fail-on", level, severities=("LOW",))
                self._assert_silent(result)
                self.assertEqual(level.upper(),
                                 result[1]["summary"]["gate_severities"]["fail_on"])

    def test_a_tighter_committed_setting_is_honoured_and_says_nothing(self):
        for level in ("high", "medium", "low"):
            with self.subTest(level=level):
                result = self._run(severities=("LOW",), settings={"fail_on": level})
                self._assert_silent(result)
                self.assertEqual(level.upper(),
                                 result[1]["summary"]["gate_severities"]["fail_on"])
                self.assertEqual({"fail_on": level}, result[1]["meta"]["config"]["effective"])


class TestACommittedOffIsRefusedLoudly(_Synthesized):
    def _committed_off(self):
        return self._run(severities=("CRITICAL",), settings={"fail_on": "off"})

    def test_the_ratchet_treats_off_as_looser_than_the_default(self):
        self.assertLess(cs._rank("fail_on", "off"), cs._rank("fail_on", "critical"))
        self.assertEqual("off", cs.STRICTNESS["fail_on"][0])
        resolved = _resolution({"fail_on": "off"})
        self.assertEqual({}, resolved.effective)
        self.assertEqual([{"key": "fail_on", "value": "off", "reason": REFUSED}],
                         resolved.refused)
        self.assertEqual(["target config asked for `fail_on: off`; refused (%s)" % REFUSED],
                         resolved.disclosures)

    def test_off_is_matched_as_the_enum_it_is(self):
        for spelled in ("OFF", " off ", "Off"):
            with self.subTest(spelled=spelled):
                self.assertEqual(REFUSED, _resolution({"fail_on": spelled}).refused[0]["reason"])
        # YAML reads a bare `off` as the boolean false. That is the natural spelling, so it
        # is the same request and gets the same loud refusal -- not a type error about a typo.
        resolved = _resolution({"fail_on": False})
        self.assertEqual({}, resolved.effective)
        self.assertEqual([{"key": "fail_on", "value": "off", "reason": REFUSED}],
                         resolved.refused)
        # `on`/true is no severity, and neither is false for any other key.
        self.assertEqual("expected one of critical, high, medium, low, off",
                         _resolution({"fail_on": True}).refused[0]["reason"])
        # Only the boolean false is YAML's `off`. The other falsy values are typos like any
        # other: the loud refusal is for a request to turn the gate off, and these are not one.
        for typo in (None, "", 0, 0.0):
            with self.subTest(typo=typo):
                resolved = _resolution({"fail_on": typo})
                self.assertEqual({}, resolved.effective)
                self.assertEqual("expected one of critical, high, medium, low, off",
                                 resolved.refused[0]["reason"])
                self.assertFalse(cs.gate_off_refused({"refused": resolved.refused}))
        self.assertEqual("expected one of all, critical, high, medium",
                         _resolution({"severity": False}).refused[0]["reason"])

    def test_the_other_committed_values_keep_their_meaning(self):
        self.assertEqual({}, _resolution({"fail_on": "critical"}).effective)
        self.assertIn("already the built-in default", _resolution(
            {"fail_on": "critical"}).disclosures[0])
        self.assertEqual({"fail_on": "high"}, _resolution({"fail_on": "high"}).effective)
        self.assertEqual([], _resolution({"fail_on": "high"}).refused)

    def test_the_loud_reason_is_for_off_alone(self):
        # Under today's default `off` is the only loosening there is. Were the default
        # tighter, a committed `critical` would loosen it too, and that is the ratchet's
        # ordinary refusal: nobody asked to turn the gate off.
        resolved = cs.resolve_settings(
            {}, cs.parse_settings({"settings": {"fail_on": "critical"}}),
            defaults={"fail_on": "high"})
        self.assertEqual("loosens the built-in default `high`", resolved.refused[0]["reason"])
        self.assertFalse(cs.gate_off_refused({"refused": resolved.refused}))

    def test_the_operators_flag_wins_in_both_directions(self):
        # The command line is the operator's: it is never clamped and never refused.
        off_over_high = _resolution({"fail_on": "high"}, fail_on="off")
        self.assertEqual(({}, []), (off_over_high.effective, off_over_high.refused))
        high_over_off = _resolution({"fail_on": "off"}, fail_on="high")
        self.assertEqual(({}, []), (high_over_off.effective, high_over_off.refused))
        self.assertIn("the command line's `high` wins", high_over_off.disclosures[0])

    def test_the_gate_stays_at_critical(self):
        code, report, _terminal, _page = self._committed_off()
        self.assertEqual((1, "FAIL"), (code, report["summary"]["gate"]))
        self.assertEqual("CRITICAL", report["summary"]["gate_severities"]["fail_on"])
        self.assertIsNone(report["summary"]["gate_disabled"])

    def test_the_json_carries_the_refusal_and_its_reason(self):
        _code, report, _terminal, _page = self._committed_off()
        self.assertEqual([{"key": "fail_on", "value": "off", "reason": REFUSED}],
                         report["meta"]["config"]["refused"])
        self.assertTrue(cs.gate_off_refused(report["meta"]["config"]))

    def test_the_terminal_summary_says_it_before_the_grade(self):
        _code, _report, terminal, _page = self._committed_off()
        lines = terminal.splitlines()
        notice = lines.index("**%s**" % REFUSED_NOTICE)
        grade = next(n for n, line in enumerate(lines) if line.startswith("**Grade:**"))
        self.assertLess(notice, grade)
        self.assertNotIn("GATE DISABLED", terminal)

    def test_the_html_carries_a_banner_before_the_badges(self):
        _code, report, _terminal, page = self._committed_off()
        banner = ("<div class='gate-notice' role='alert'>%s</div>"
                  % html_report._escape(REFUSED_NOTICE))
        self.assertEqual(1, page.count(banner))
        self.assertLess(page.index(banner), page.index("<div class='badges'>"))
        self.assertNotIn("GATE DISABLED", page)
        self.assertIn(banner, html_report._render_compare_summary("A", report))

    def test_the_refusal_says_the_four_things_it_owes(self):
        for owed in ("the repository's own config asked to turn the gate off", "REFUSED",
                     "the gate stays at CRITICAL", "`--fail-on off`"):
            self.assertIn(owed, cs.GATE_OFF_REFUSED_NOTICE)
        self.assertEqual(REFUSED_NOTICE, cs.GATE_OFF_REFUSED_NOTICE)

    def test_only_this_refusal_raises_the_banner(self):
        # Any other refused key, and a `fail_on` refused for another reason, keep the
        # ordinary "Target config" line and no banner.
        self.assertFalse(cs.gate_off_refused(None))
        self.assertFalse(cs.gate_off_refused({"refused": "not a list"}))
        self.assertFalse(cs.gate_off_refused(
            {"refused": [{"key": "severity", "value": "critical", "reason": REFUSED}]}))
        self.assertFalse(cs.gate_off_refused(
            {"refused": [{"key": "fail_on", "value": "x", "reason": "expected one of ..."}]}))
        self.assertEqual([], cs.gate_notices({"gate": "PASS"}, {"refused": []}))
        _code, report, terminal, page = self._run(settings={"severity": "critical"})
        self.assertEqual(1, len(report["meta"]["config"]["refused"]))
        self.assertIn("**Target config:**", terminal)
        self.assertNotIn("gate-notice'", page)


class TestRenderingAnOlderReport(unittest.TestCase):
    """A report written before `summary.gate_disabled` existed still renders, and an OFF one
    still gets the banner: the notice is read off `summary.gate`."""

    def _report(self, gate):
        return {"meta": {"target": "t"}, "summary": {
            "gate": gate, "risk_level": "LOW", "overall_grade": "A", "evidence_stats": {},
            "stats": {}}, "groups": [], "findings": []}

    def test_an_off_report_without_the_field_is_still_loud(self):
        self.assertIn("**%s**" % OFF_NOTICE, render_mod.render_summary(self._report("OFF")))
        self.assertIn(html_report._escape(OFF_NOTICE),
                      html_report._render_header(self._report("OFF")))

    def test_an_armed_report_without_the_field_is_still_silent(self):
        self.assertNotIn("GATE", render_mod.render_summary(self._report("PASS")).split(
            "**Grade:**")[0])
        self.assertNotIn("gate-notice'", html_report._render_header(self._report("PASS")))


def setUpModule():
    global _patches
    _patches = (mock.patch("scripts.host_probes.run_probes",
                           side_effect=lambda host, target, **kw: all_proven_artifact(host)),
                mock.patch("scripts.phases.readiness_checks.DOCKER_RUNNER",
                           docker_probe_runner()))
    for patch in _patches:
        patch.start()


def tearDownModule():
    for patch in _patches:
        patch.stop()


class TestTheDriverLoop(LoopCase):
    """The same rulings through `driver loop`: the flag as the operator types it, the config
    as the repository commits it, and the report the run publishes."""

    def _loop(self, d, floor, *flags):
        """(status, what the terminal showed) for one `driver loop` with exactly `flags`."""
        args = driver.build_parser().parse_args(["loop", d, "--no-tools", *flags])
        err = io.StringIO()
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda root: self._seed_coverage(root, floor)), \
                mock.patch("scripts.runners.base.runner_for", return_value=FakeRunner()), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            # Under the wrapper `driver loop` runs under, so the summary reaches the terminal.
            status = loop_progress.stamped_call(True, orchestrate.loop, args)
        self.assertEqual("complete", status["status"], status)
        return status, err.getvalue()

    def _published(self, d, status):
        with open(runio._report_out(d), encoding="utf-8") as fh:
            report = json.load(fh)
        with open(status["artifacts"]["html"], encoding="utf-8") as fh:
            return report, fh.read()

    def _summary_lines(self, terminal):
        marker = loop_progress.SUMMARY_PREFIX
        return [line.split(marker, 1)[1] for line in terminal.splitlines() if marker in line]

    def _commit(self, d, setting):
        with open(os.path.join(d, "panopticon.yml"), "a", encoding="utf-8") as fh:
            fh.write("settings:\n  fail_on: %s\n" % setting)

    def test_no_flag_and_no_config_gates_at_critical(self):
        d, floor = self._repo()
        status, terminal = self._loop(d, floor)
        report, page = self._published(d, status)
        self.assertIsNone(run_manifest.load_manifest(d)["flags"]["fail_on"])
        self.assertEqual("CRITICAL", report["summary"]["gate_severities"]["fail_on"])
        # FakeRunner's one confirmed finding is a HIGH: below the default threshold.
        self.assertEqual("PASS", report["summary"]["gate"])
        self.assertIsNone(report["summary"]["gate_disabled"])
        for surface in (terminal, page):
            self.assertNotIn("GATE DISABLED", surface)
            self.assertNotIn("REFUSED", surface)

    def test_a_run_whose_manifest_recorded_no_threshold_resumes_and_gates_at_critical(self):
        # A run started before #3673 wrote `fail_on: null`, and so does one started after:
        # the default is not a flag. So the resume is not flag drift, and it gates.
        d, floor = self._repo()
        args = driver.build_parser().parse_args(["run", d, "--no-tools"])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            first = driver.run(args)
        self.assertNotEqual("error", first["status"], first)
        before = run_manifest.load_manifest(d)
        self.assertIsNone(before["flags"]["fail_on"])
        status, _terminal = self._loop(d, floor)
        report, _page = self._published(d, status)
        self.assertEqual(before["run_id"], run_manifest.load_manifest(d)["run_id"])
        self.assertEqual("CRITICAL", report["summary"]["gate_severities"]["fail_on"])
        self.assertEqual("PASS", report["summary"]["gate"])

    def test_tightening_is_recorded_and_silent(self):
        d, floor = self._repo()
        status, terminal = self._loop(d, floor, "--fail-on", "high")
        report, page = self._published(d, status)
        self.assertEqual("high", run_manifest.load_manifest(d)["flags"]["fail_on"])
        self.assertEqual("FAIL", report["summary"]["gate"])     # the HIGH now counts
        for surface in (terminal, page):
            self.assertNotIn("GATE DISABLED", surface)
            self.assertNotIn("gate-notice'", surface)

    def test_the_operators_off_is_loud_on_all_three_surfaces(self):
        d, floor = self._repo()
        status, terminal = self._loop(d, floor, "--fail-on", "off")
        report, page = self._published(d, status)
        self.assertEqual("off", run_manifest.load_manifest(d)["flags"]["fail_on"])
        self.assertEqual("OFF", report["summary"]["gate"])
        self.assertEqual({"disabled_by_operator": True, "source": "--fail-on off"},
                         report["summary"]["gate_disabled"])
        self.assertIn("**%s**" % OFF_NOTICE, self._summary_lines(terminal))
        self.assertIn("<div class='gate-notice' role='alert'>%s</div>"
                      % html_report._escape(OFF_NOTICE), page)

    def test_a_committed_off_is_refused_on_all_three_surfaces(self):
        for spelled in ("off", "'off'"):       # YAML's boolean, and the quoted string
            with self.subTest(spelled=spelled):
                d, floor = self._repo()
                self._commit(d, spelled)
                status, terminal = self._loop(d, floor)
                report, page = self._published(d, status)
                manifest = run_manifest.load_manifest(d)
                # The gate the run used: the default, and nothing the file asked for.
                self.assertIsNone(manifest["flags"]["fail_on"])
                self.assertEqual([{"key": "fail_on", "value": "off", "reason": REFUSED}],
                                 manifest["config_refused"])
                self.assertEqual("CRITICAL", report["summary"]["gate_severities"]["fail_on"])
                self.assertEqual("PASS", report["summary"]["gate"])
                self.assertIsNone(report["summary"]["gate_disabled"])
                # JSON, terminal (at run start and in the summary), HTML.
                self.assertEqual(manifest["config_refused"], report["meta"]["config"]["refused"])
                self.assertIn("driver: target config asked for `fail_on: off`; refused (%s)"
                              % REFUSED, terminal)
                self.assertIn("**%s**" % REFUSED_NOTICE, self._summary_lines(terminal))
                self.assertIn("<div class='gate-notice' role='alert'>%s</div>"
                              % html_report._escape(REFUSED_NOTICE), page)

    def test_a_committed_off_does_not_outrank_the_operators_flag(self):
        d, floor = self._repo()
        self._commit(d, "off")
        status, terminal = self._loop(d, floor, "--fail-on", "high")
        report, page = self._published(d, status)
        self.assertEqual("FAIL", report["summary"]["gate"])
        self.assertEqual([], report["meta"]["config"]["refused"])
        self.assertNotIn("gate-notice'", page)
        self.assertIn("the command line's `high` wins", terminal)


if __name__ == "__main__":
    unittest.main()

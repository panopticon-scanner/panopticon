"""#1732 part 1: the ONE launch that proves an advertised flag's SHAPE.

`probe_cli_flags` reads `<cli> --help` and answers whether the flag is
ADVERTISED. That is a read of the flag's NAME, and run 14 proved a name is not
a contract: `claude --help` advertises `--json-schema`, the driver handed it
the schema's PATH, and the CLI wants its TEXT. Every `return_json` entry of
every checkpoint then exited 1 in ~120 ms with no envelope -- 309 launches and
~35 minutes on one wrong argv token, while the posture line said "5 of 5
capabilities proven".

So one real launch, once per run, through the family's own `run_entry`.
"""
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import scripts.hosts as hosts
import scripts.probes.shape as shape_probe
import scripts.runners.base as base
import scripts.runners.outage as outage


class _Runner(base.HostRunner):
    """A family whose CLI takes an output-schema flag, and whose `run_entry`
    answers with whatever the test handed it -- through the injected `runner`
    seam, so the argv it would really have launched is observable."""

    host = "fake"
    mode = "headless"
    CLI = "fake-cli"
    OUTPUT_SCHEMA_FLAG = ("--json-schema",)

    def __init__(self, host="fake", result=None, raises=None, launch=True,
                 inline=False):
        super().__init__(host)
        self.result, self.raises, self.launch, self.inline = result, raises, launch, inline
        self.prepared, self.argv, self.entries, self.env = [], [], [], []
        self.max_turns, self.entry_timeout = 60, 1800
        self.runner = self._launcher

    def _launcher(self, cmd, **_kw):
        self.argv.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def prepare(self, run_dir, review_root):
        self.prepared.append((run_dir, review_root))

    def run_entry(self, entry, env):
        self.entries.append(dict(entry))
        self.env.append(dict(env))
        if self.launch:
            self.runner([self.CLI, *self._schema_argv(entry), entry["prompt"]])
        if self.raises is not None:
            raise self.raises
        return self.result

    def _schema_argv(self, entry):
        import scripts.runners.schema as schema_rules
        return schema_rules.schema_argv(self.OUTPUT_SCHEMA_FLAG, entry, inline=self.inline)


def _ok(text='{"ok": true}', usage=None, cost=None):
    return base.RunResult(entry_id=shape_probe.PROBE_ENTRY_ID, ok=True, text=text,
                          usage=usage or {}, cost_usd=cost, model=None,
                          session_id=None, denials=[], error=None)


def _failed(error, **kw):
    return base.RunResult.failed(shape_probe.PROBE_ENTRY_ID, error, **kw)


class ShapeProofTest(unittest.TestCase):

    def _prove(self, runner, elapsed_ms=120, **kw):
        """`prove` with the clock pinned, so a verdict that turns on a
        duration is a fact about the rule rather than about the test host."""
        ticks = iter([0.0, elapsed_ms / 1000.0])
        with tempfile.TemporaryDirectory() as run_dir, \
                tempfile.TemporaryDirectory() as review_root, \
                mock.patch.object(shape_probe.time, "monotonic",
                                  side_effect=lambda: next(ticks)):
            return shape_probe.prove("fake", run_dir, review_root, runner=runner, **kw)

    # ---- the three verdicts ------------------------------------------------

    def test_an_accepted_launch_proves_the_shape(self):
        runner = _Runner(result=_ok())
        verdict = self._prove(runner)
        self.assertEqual(hosts.SHAPE_PROVEN, verdict[hosts.SHAPE])
        self.assertEqual(1, len(runner.entries))

    def test_an_instant_entry_class_failure_with_no_envelope_refutes_it(self):
        runner = _Runner(result=_failed("fake-cli printed no JSON envelope (exit 1)",
                                        stderr="--json-schema is not valid JSON: "
                                               "Unrecognized token '/'"))
        verdict = self._prove(runner, elapsed_ms=120)
        self.assertEqual(hosts.SHAPE_REFUTED, verdict[hosts.SHAPE])
        detail = verdict[hosts.SHAPE_DETAIL]
        self.assertIn("120", detail)                       # the duration
        self.assertIn("exit 1", detail)                    # the exit, as the family spells it
        self.assertIn("Unrecognized token", detail)        # the stderr

    def test_the_refutation_detail_is_redacted(self):
        runner = _Runner(result=_failed("exit 1", stderr="key sk-ant-api03-AAAABBBBCCCCDDDD"))
        verdict = self._prove(runner)
        self.assertEqual(hosts.SHAPE_REFUTED, verdict[hosts.SHAPE])
        self.assertNotIn("sk-ant-", verdict[hosts.SHAPE_DETAIL])

    def test_a_slow_failure_is_the_cli_accepting_the_argv(self):
        # It got far enough to do work, so whatever went wrong is not the argv.
        runner = _Runner(result=_failed("fake-cli exited 1: the agent gave up"))
        verdict = self._prove(runner, elapsed_ms=shape_probe.SHAPE_PROOF_REFUTE_MS)
        self.assertEqual(hosts.SHAPE_PROVEN, verdict[hosts.SHAPE])

    def test_an_instant_failure_that_carries_an_envelope_accepts_the_argv(self):
        # The CLI printed something back: it parsed its argv, started, and then
        # failed for a reason of its own.
        runner = _Runner(result=_failed("fake-cli reported is_error", text='{"partial": 1}'))
        verdict = self._prove(runner, elapsed_ms=50)
        self.assertEqual(hosts.SHAPE_PROVEN, verdict[hosts.SHAPE])

    def test_a_host_class_failure_is_unmeasured(self):
        runner = _Runner(result=_failed("fake-cli exited 1: 403 Forbidden",
                                        host_error="provider.auth_error: 403 Forbidden"))
        verdict = self._prove(runner)
        self.assertEqual(hosts.SHAPE_UNMEASURED, verdict[hosts.SHAPE])
        self.assertEqual(outage.HOST_FAILURE,
                         runner.result.failure_class)      # really host-class
        self.assertIn("host", verdict[hosts.SHAPE_DETAIL])

    def test_a_timeout_is_unmeasured(self):
        runner = _Runner(result=_failed("fake-cli timed out after 30s"))
        verdict = self._prove(runner, elapsed_ms=30000)
        self.assertEqual(hosts.SHAPE_UNMEASURED, verdict[hosts.SHAPE])
        self.assertIn("timed out", verdict[hosts.SHAPE_DETAIL])

    def test_a_launch_refusal_is_unmeasured_however_it_arrives(self):
        # The suite's own guard, and it reaches a caller two ways: raised (the
        # kimi family re-raises it) or folded into a failed result's message
        # (claude and codex catch every Exception, as spec 4.4 requires).
        raised = _Runner(raises=base.LaunchRefused("no real CLI in the suite"))
        self.assertEqual(hosts.SHAPE_UNMEASURED, self._prove(raised)[hosts.SHAPE])
        folded = _Runner(result=_failed(
            "fake-cli launch raised LaunchRefused: no real CLI in the suite"))
        self.assertEqual(hosts.SHAPE_UNMEASURED, self._prove(folded)[hosts.SHAPE])

    def test_a_failure_that_never_reached_the_cli_is_unmeasured(self):
        # A family's own precondition (codex refuses an entry with no explicit
        # model) fails instantly and entry-class, and refuting the CLI's argv
        # over it would be a measurement of this driver, not of the CLI.
        runner = _Runner(result=_failed("ValueError: requires an explicit entry model"),
                         launch=False)
        verdict = self._prove(runner)
        self.assertEqual(hosts.SHAPE_UNMEASURED, verdict[hosts.SHAPE])
        self.assertIn("never started", verdict[hosts.SHAPE_DETAIL])

    def test_no_usable_runner_is_unmeasured_and_launches_nothing(self):
        with mock.patch.object(shape_probe.runners_base, "runner_for",
                               side_effect=ValueError("no headless runner for host 'x'")):
            verdict = shape_probe.prove("x", "/nope", "/nope")
        self.assertEqual(hosts.SHAPE_UNMEASURED, verdict[hosts.SHAPE])
        self.assertIn("no headless runner", verdict[hosts.SHAPE_DETAIL])

    def test_a_family_that_declares_no_flag_is_unmeasured_and_launches_nothing(self):
        class Bare(_Runner):
            OUTPUT_SCHEMA_FLAG = ()
        runner = Bare()
        verdict = self._prove(runner)
        self.assertEqual(hosts.SHAPE_UNMEASURED, verdict[hosts.SHAPE])
        self.assertEqual([], runner.entries)

    # ---- the launch itself -------------------------------------------------

    def test_the_probe_entry_is_bounded_and_self_contained(self):
        runner = _Runner(result=_ok())
        with tempfile.TemporaryDirectory() as run_dir, \
                tempfile.TemporaryDirectory() as review_root:
            shape_probe.prove("fake", run_dir, review_root, runner=runner)
            entry = runner.entries[0]
            self.assertEqual(shape_probe.PROBE_ENTRY_ID, entry["id"])
            self.assertFalse(entry["enforced"])
            self.assertIsNone(entry["model"])
            self.assertEqual("return_json", entry["delivery"])
            self.assertEqual([(run_dir, review_root)], runner.prepared)
            # the out_file is inside the run folder and is NEVER written
            self.assertTrue(entry["out_file"].startswith(run_dir + os.sep))
            self.assertFalse(os.path.exists(entry["out_file"]))
        self.assertEqual(shape_probe.PROBE_MAX_TURNS, runner.max_turns)
        self.assertEqual(shape_probe.PROBE_ENTRY_TIMEOUT, runner.entry_timeout)
        # the entry binding every family's launch path checks
        self.assertEqual(shape_probe.PROBE_ENTRY_ID,
                         runner.env[0][base.ENV_ENTRY_ID])

    def test_the_probe_schema_is_one_panopticon_publishes(self):
        import scripts.runners.schema as schema_rules
        runner = _Runner(result=_ok())
        self._prove(runner)
        named = runner.entries[0]["output_schema"]
        self.assertIsNotNone(schema_rules.published_schema(named),
                             "the probe schema must be inside skill/reference/")

    def test_the_argv_carries_the_schema_the_way_this_family_takes_it(self):
        # claude takes the schema's TEXT, codex its PATH, and the probe must
        # go through the same `schema_argv` a real entry does -- otherwise it
        # proves a shape no entry will ever launch with.
        inline = _Runner(result=_ok(), inline=True)
        self._prove(inline)
        self.assertIn("--json-schema", inline.argv[0])
        handed = inline.argv[0][inline.argv[0].index("--json-schema") + 1]
        self.assertIn('"ok"', handed)                      # the schema TEXT
        by_path = _Runner(result=_ok(), inline=False)
        self._prove(by_path)
        handed = by_path.argv[0][by_path.argv[0].index("--json-schema") + 1]
        self.assertTrue(os.path.isfile(handed))            # the schema PATH

    def test_the_spend_is_recorded_in_the_detail_not_in_a_ledger_row(self):
        # ruling 5: a ledger row would be counted as a cell by usage.json.
        runner = _Runner(result=_ok(usage={"input_tokens": 31, "output_tokens": 7},
                                    cost=0.0004))
        detail = self._prove(runner)[hosts.SHAPE_DETAIL]
        self.assertIn("31", detail)
        self.assertIn("7", detail)
        self.assertIn("0.0004", detail)

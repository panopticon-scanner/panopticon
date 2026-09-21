"""#1732 part 1: the ONE launch that proves an advertised flag's SHAPE.

`probe_cli_flags` reads `<cli> --help` and answers whether the flag is
ADVERTISED. That is a read of the flag's NAME, and run 14 proved a name is not
a contract: `claude --help` advertises `--json-schema`, the driver handed it
the schema's PATH, and the CLI wants its TEXT. Every `return_json` entry of
every checkpoint then exited 1 in ~120 ms with no envelope -- 309 launches and
~35 minutes on one wrong argv token, while the posture line said "5 of 5
capabilities proven".

So one real launch, once per run, through the family's own `run_entry` --
driven from `loop_batch.prove_output_schema_shape` inside the loop, after the
batch's guards are armed. This module is the MEASUREMENT: what the entry looks
like, and what a result means.
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
        self.bounds = []
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
        self.bounds.append((self.max_turns, self.entry_timeout))
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


CELL = {"id": "review-app-SEC", "delivery": "return_json",
        "output_schema": "/published/findings-envelope-schema.json",
        "agent": "panopticon-domain-panel", "enforced": True,
        "model": "claude-sonnet-5",
        "out_file": "/r/.panopticon/runs/t/findings-app-SEC.json"}


class ShapeProofTest(unittest.TestCase):

    def _prove(self, runner, elapsed_ms=120, entry=None, env=None):
        """`prove` with the clock pinned, so a verdict that turns on a
        duration is a fact about the rule rather than about the test host."""
        ticks = iter([0.0, elapsed_ms / 1000.0])
        if entry is None:
            with tempfile.TemporaryDirectory() as run_dir:
                entry = shape_probe.probe_entry(CELL, run_dir)
        with mock.patch.object(shape_probe.time, "monotonic",
                               side_effect=lambda: next(ticks)):
            return shape_probe.prove("fake", runner, entry,
                                     env if env is not None else
                                     {base.ENV_ENTRY_ID: shape_probe.PROBE_ENTRY_ID})

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
        # Never an exception out of here: a structural refusal is a
        # measurement that was not made, not a run that ends.
        raised = _Runner(raises=base.LaunchRefused("no real CLI in the suite"))
        self.assertEqual(hosts.SHAPE_UNMEASURED, self._prove(raised)[hosts.SHAPE])
        folded = _Runner(result=_failed(
            "fake-cli launch raised LaunchRefused: no real CLI in the suite"))
        self.assertEqual(hosts.SHAPE_UNMEASURED, self._prove(folded)[hosts.SHAPE])

    def test_a_failure_that_never_reached_the_cli_is_unmeasured(self):
        # A family's own precondition fails instantly and entry-class, and
        # refuting the CLI's argv over it would be a measurement of this
        # driver, not of the CLI.
        runner = _Runner(result=_failed("ValueError: requires an explicit entry model"),
                         launch=False)
        verdict = self._prove(runner)
        self.assertEqual(hosts.SHAPE_UNMEASURED, verdict[hosts.SHAPE])
        self.assertIn("never started", verdict[hosts.SHAPE_DETAIL])

    def test_a_family_that_declares_no_flag_is_unmeasured_and_launches_nothing(self):
        class Bare(_Runner):
            OUTPUT_SCHEMA_FLAG = ()
        runner = Bare()
        verdict = self._prove(runner)
        self.assertEqual(hosts.SHAPE_UNMEASURED, verdict[hosts.SHAPE])
        self.assertEqual([], runner.entries)

    def test_an_entry_with_no_schema_is_unmeasured_and_launches_nothing(self):
        runner = _Runner(result=_ok())
        verdict = self._prove(runner, entry={"id": "x", "prompt": "p"})
        self.assertEqual(hosts.SHAPE_UNMEASURED, verdict[hosts.SHAPE])
        self.assertEqual([], runner.entries)

    # ---- the entry, and the launch ----------------------------------------

    def test_the_probe_entry_clones_the_cells_binding(self):
        # This is what makes the measurement a measurement: the probe goes out
        # under the same registered shell, the same enforcement posture and
        # the same model a real entry will. A bare unenforced entry was
        # refused by codex for want of a model and a shell before it ever
        # reached its CLI, so that family could never be measured at all.
        with tempfile.TemporaryDirectory() as run_dir:
            entry = shape_probe.probe_entry(CELL, run_dir)
            self.assertEqual(shape_probe.PROBE_ENTRY_ID, entry["id"])
            self.assertEqual(CELL["agent"], entry["agent"])
            self.assertEqual(CELL["enforced"], entry["enforced"])
            self.assertEqual(CELL["model"], entry["model"])
            self.assertEqual("return_json", entry["delivery"])
            self.assertEqual(shape_probe.PROBE_PROMPT, entry["prompt"])
            # ...but NOT the cell's schema, and NOT the cell's out_file
            self.assertNotEqual(CELL["output_schema"], entry["output_schema"])
            self.assertTrue(entry["out_file"].startswith(run_dir + os.sep))
            self.assertFalse(os.path.exists(entry["out_file"]))

    def test_the_probes_out_file_is_never_in_the_batchs_write_allowlist(self):
        # A probe that wrote anything would be a probe with a side effect. The
        # entry id is not one the loop armed, so the write guard denies it --
        # the correct outcome rather than an accident.
        import scripts.write_guard_hook as write_guard_hook
        with tempfile.TemporaryDirectory() as run_dir:
            entry = shape_probe.probe_entry(CELL, run_dir)
            granted = write_guard_hook.allowlist_from_plan([CELL])
            self.assertNotIn(entry["id"], granted)
            self.assertNotIn(entry["out_file"],
                             write_guard_hook.union_paths(granted))

    def test_the_probe_schema_is_one_panopticon_publishes(self):
        import scripts.runners.schema as schema_rules
        with tempfile.TemporaryDirectory() as run_dir:
            entry = shape_probe.probe_entry(CELL, run_dir)
        self.assertIsNotNone(schema_rules.published_schema(entry["output_schema"]),
                             "the probe schema must be inside skill/reference/")

    def test_an_unpublished_probe_schema_builds_no_entry_at_all(self):
        with mock.patch.object(shape_probe.runners_schema, "published_schema",
                               return_value=None):
            self.assertIsNone(shape_probe.probe_entry(CELL, "/run"))

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

    def test_the_launch_is_bounded_and_the_bounds_are_put_back(self):
        # One turn and thirty seconds for THIS launch, and not a character of
        # it for the batch the loop is about to run: a probe that left
        # max_turns at 1 would cap every cell of the run at one turn.
        runner = _Runner(result=_ok())
        runner.max_turns, runner.entry_timeout = 60, 1800
        self._prove(runner)
        self.assertEqual([(shape_probe.PROBE_MAX_TURNS,
                           shape_probe.PROBE_ENTRY_TIMEOUT)], runner.bounds)
        self.assertEqual((60, 1800), (runner.max_turns, runner.entry_timeout))

    def test_the_bounds_are_put_back_even_when_the_launch_raises(self):
        runner = _Runner(raises=base.LaunchRefused("no"))
        runner.max_turns, runner.entry_timeout = 60, 1800
        self._prove(runner)
        self.assertEqual((60, 1800), (runner.max_turns, runner.entry_timeout))

    def test_the_injected_launcher_is_restored(self):
        # The probe wraps it to see whether the CLI really started; the loop
        # then launches the whole batch through the same attribute.
        runner = _Runner(result=_ok())
        launcher = runner.runner
        self._prove(runner)
        self.assertIs(launcher, runner.runner)

    def test_the_env_is_handed_through_untouched(self):
        runner = _Runner(result=_ok())
        env = {base.ENV_ENTRY_ID: shape_probe.PROBE_ENTRY_ID,
               base.ENV_WRITE_ALLOWLIST: "/run/write-allowlist.json",
               base.ENV_READ_SCOPE: "/run/read-scope.json"}
        self._prove(runner, env=env)
        self.assertEqual(env, runner.env[0])

    def test_the_spend_is_recorded_in_the_detail_not_in_a_ledger_row(self):
        # ruling 5: a ledger row would be counted as a cell by usage.json.
        runner = _Runner(result=_ok(usage={"input_tokens": 31, "output_tokens": 7},
                                    cost=0.0004))
        detail = self._prove(runner)[hosts.SHAPE_DETAIL]
        self.assertIn("31", detail)
        self.assertIn("7", detail)
        self.assertIn("0.0004", detail)

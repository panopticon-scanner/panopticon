"""Loop launch failure, budget, and output schema tests."""
import contextlib
import copy
import io
import os
import time
from unittest import mock


import scripts.orchestrate as orchestrate
import scripts.phases.runio as runio
import scripts.runners.base as base
import scripts.runners.outage as outage
import scripts.probes.shape as shape_probe
from tests._test_helpers import (all_proven_artifact as _all_proven_artifact)
from tests._test_helpers import docker_probe_runner, write_host_evidence
from scripts import hosts


from tests.orchestrate_helpers import (_MidBatchGated, FakeRunner, LoopCase, _ALL_PROVEN)

def setUpModule():
    global _patch, _readiness_docker_patch
    _patch = mock.patch("scripts.host_probes.run_probes",
                        side_effect=lambda host, target, **kw: _all_proven_artifact(host))
    _patch.start()
    # #1637 P08: the `readiness` phase leads PHASES and fails closed on a
    # missing tools image, so every loop below would stop there instead of at
    # the checkpoint it is about. A fake runner, never a real daemon.
    _readiness_docker_patch = mock.patch(
        "scripts.phases.readiness_checks.DOCKER_RUNNER", docker_probe_runner())
    _readiness_docker_patch.start()


def tearDownModule():
    _patch.stop()
    _readiness_docker_patch.stop()


class TestAUniformInstantFailure(LoopCase):
    """#1732 part 2: the whole batch refused before any entry did any work.

    Run 14's tool-verify checkpoint launched 103 entries and every one exited
    non-zero in ~120 ms with `claude -p printed no JSON envelope (exit 1)`,
    because `--json-schema` had been handed the schema's PATH where the CLI
    wants its TEXT. Nothing in the loop could tell that from 103 entries each
    failing on its own account, so the driver launched all 103 three times --
    309 launches, ~35 minutes -- to reach the per-entry cap on a defect its
    first two results had already proved.
    """

    FLOOR = ("SEC", "COD", "ARC", "TST", "QAL", "AGT", "DAT", "OPS", "ACC", "LNG")
    MESSAGE = "claude -p printed no JSON envelope (exit 1)"
    WIDTH = 2

    class Refused(FakeRunner):
        """Every launch fails instantly with the SAME message.

        Gated exactly as `TestAMidBatchHostOutage.Gated` is, and for the same
        reason: from index two on, a launch does not come back until the LOOP
        has ledgered every result before it, so "what the short-circuit
        stopped" is a fact rather than a thread race. One worker turnover is
        still not pinnable (the loop persists, ledgers and counts a result
        before it asks `stop`), which is the explicit `+ 1` in the bound.
        """

        def __init__(self, floor, message, per_entry=False):
            super().__init__()
            self.order = ["review-app-%s" % d for d in floor]
            self.message, self.per_entry = message, per_entry

        def _await_ledger(self, lines):
            path = os.path.join(self.run_dir, base.LEDGER_FILE)
            for _ in range(2000):
                try:
                    with open(path, "rb") as fh:   # bytes: a poisoned line must not
                        if sum(1 for line in fh if line.strip()) >= lines:  # raise here
                            return
                except OSError:
                    pass
                time.sleep(0.005)
            raise AssertionError("the loop never ledgered %d results" % lines)

        def _result(self, eid):
            return base.RunResult.failed(
                eid, self.message + (": " + eid if self.per_entry else ""))

        def run_entry(self, entry, env):
            eid = entry["id"]
            index = self.order.index(eid) if eid in self.order else None
            if index is not None and index >= 2:
                self._await_ledger(index)
            self.launched.append(eid)
            return self._result(eid)

    class HostRefused(Refused):
        """The same instant, identical batch -- but host-class. The existing
        outage path must still own it (regression pin)."""

        def _result(self, eid):
            return base.RunResult.failed(eid, self.message,
                                         host_error="provider.auth_error: 403 Forbidden")

    def _run(self, d, floor, runner, *extra):
        err = io.StringIO()
        with contextlib.ExitStack() as es:
            es.enter_context(mock.patch.object(
                orchestrate, "_after_first_run",
                side_effect=lambda rr: self._seed_coverage(rr, floor)))
            es.enter_context(mock.patch("scripts.runners.base.runner_for", return_value=runner))
            es.enter_context(contextlib.redirect_stdout(io.StringIO()))
            es.enter_context(contextlib.redirect_stderr(err))
            status = orchestrate.loop(self._args(d, "--concurrency", str(self.WIDTH), *extra))
        return status, err.getvalue()

    def _reviews(self, runner):
        return [x for x in runner.launched if x.startswith("review-")]

    def test_the_batch_stops_instead_of_burning_every_entrys_budget(self):
        d, floor = self._repo(floor=self.FLOOR)
        runner = self.Refused(self.FLOOR, self.MESSAGE)
        status, err = self._run(d, floor, runner)
        self.assertEqual("paused", status["status"], status)
        reviews = self._reviews(runner)
        self.assertLess(len(reviews), len(self.FLOOR), reviews)
        # the corroboration the stop waits for (max(2, width)) + the pool that
        # was already running (width) + the one worker that can turn over while
        # the loop is still persisting the result that trips the stop
        self.assertLessEqual(len(reviews), max(2, self.WIDTH) + self.WIDTH + 1, reviews)
        self.assertIn("the first %d launches of this batch all failed in under %d ms"
                      % (max(2, self.WIDTH), outage.UNIFORM_FAST_MS), status["message"])
        self.assertIn(self.MESSAGE, status["message"])
        self.assertIn("driver loop: stopped launching after %d identical instant failure(s)"
                      % max(2, self.WIDTH), err)
        self.assertNotIn("host-class failure(s)", err)

    def test_it_charges_nobody_so_a_healthy_re_run_dispatches_every_cell(self):
        d, floor = self._repo(floor=self.FLOOR)
        status, _err = self._run(d, floor, self.Refused(self.FLOOR, self.MESSAGE))
        self.assertEqual("paused", status["status"], status)
        attempts = runio._load_json(runio._pano(d, "cell-attempts.json")) or {}
        self.assertEqual([], [k for k, v in attempts.items() if v], attempts)
        healthy = FakeRunner()
        again = self._run_loop(d, floor, healthy, "--concurrency", str(self.WIDTH), seed=False)
        self.assertEqual("complete", again["status"], again)
        self.assertEqual(sorted("review-app-%s" % x for x in self.FLOOR),
                         sorted(x for x in healthy.launched if x.startswith("review-")))

    def test_the_message_is_composed_once_not_per_entry(self):
        # Run 14 printed its identical failure once per entry per checkpoint,
        # three checkpoints deep, which is how a defect two results had
        # already proved stayed unreadable.
        d, floor = self._repo(floor=self.FLOOR)
        status, err = self._run(d, floor, self.Refused(self.FLOOR, self.MESSAGE))
        self.assertEqual(1, (err + status["message"]).count(
            "the first %d launches of this batch" % max(2, self.WIDTH)))

    def test_different_messages_charge_exactly_as_before(self):
        # Ten cells each failing for their OWN reason is not one launch being
        # refused, and the rules that already bound it are untouched: every
        # cell is charged for every launch it really got, and the review
        # phase's own three-dispatch retry budget is what ends the run --
        # `complete`, with those cells named as exhausted. No pause, no
        # give-back, no uniform line.
        d, floor = self._repo(floor=self.FLOOR)
        runner = self.Refused(self.FLOOR, self.MESSAGE, per_entry=True)
        status, err = self._run(d, floor, runner)
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(len(self.FLOOR), status["cells_exhausted"])
        self.assertNotIn("identical instant failure", err)
        self.assertNotIn("paused", err)
        attempts = runio._load_json(runio._pano(d, "cell-attempts.json")) or {}
        self.assertEqual(sorted("app/%s" % x for x in self.FLOOR), sorted(attempts))
        self.assertEqual([], [k for k, v in attempts.items() if v != 3], attempts)

    def test_an_instant_identical_batch_that_is_host_class_is_still_an_outage(self):
        d, floor = self._repo(floor=self.FLOOR)
        runner = self.HostRefused(self.FLOOR, self.MESSAGE)
        status, err = self._run(d, floor, runner)
        self.assertEqual("paused", status["status"], status)
        self.assertIn(outage.HOST_OUTAGE_CLAUSE, status["message"])
        self.assertNotIn("identical instant failure", err)
        self.assertIn("host-class failure(s)", err)


class _MidBatchFixture:
    Gated = _MidBatchGated


TestAMidBatchHostOutage = _MidBatchFixture


class TestABudgetCapMidBatch(LoopCase):
    """#1760 (AGT-4265600920): the cap is re-read after every entry lands, not
    once per checkpoint.

    `--max-budget-usd` was compared with the ledger exactly once per `while`
    iteration, at the top and ahead of `guards.arm` -- and a checkpoint is ONE
    batch, so a whole review round (every pending cell, all of it charged)
    launched before the cap was looked at a second time. The guide meanwhile
    promises it "stops launching once the ledger's cumulative reported cost
    crosses it". Ten cells at `FakeRunner`'s $0.01 apiece against a $0.03 cap
    is the shape: the third result reaches it, and what launches after that
    must be the pool, not the checkpoint.
    """

    FLOOR = ("SEC", "COD", "ARC", "TST", "QAL", "AGT", "DAT", "OPS", "ACC", "LNG")
    WIDTH = 2
    BUDGET = "0.03"          # three of FakeRunner's $0.01 entries, exactly
    # Written by hand, exactly as `json.dumps` with its defaults emits it: the
    # decoder ACCEPTS the bare `NaN` token, which is how an unreadable cost
    # reaches a budget comparison (#1648). `money.ledger_text` never writes one.
    POISON = ('{"cost_usd": NaN, "entry_id": "review-app-SEC", "error": null, '
              '"ok": true, "phase": "review", "usage": {}}')

    class Paid(TestAMidBatchHostOutage.Gated):
        """Every cell answers and is charged `FakeRunner`'s $0.01.

        Subclassed off `TestAMidBatchHostOutage.Gated` rather than gated a
        third time by hand: from index two on, a launch does not come back
        until the LOOP has ledgered every result before it, so "what the
        short-circuit stopped" is a fact rather than a thread race -- two
        workers answering instantly outrun a consumer that persists, ledgers
        and counts each reply. The one worker turnover the loop allows between
        a result's ledger line and the `stop` question after it is the explicit
        `+ 1` in the bound below.

        `poison` is an unreadable cost appended from INSIDE the batch, while it
        is in flight: the pre-loop seam is `SeededLedger`'s, already covered.
        """

        def __init__(self, floor, poison=None):
            super().__init__(floor, None)
            self.poison = poison

        def run_entry(self, entry, env):
            index = self._index(entry)
            if index is not None and index >= 2:
                self._await_ledger(index)
            result = super().run_entry(entry, env)
            if self.poison and entry["id"] == self.order[0]:
                path = os.path.join(self.run_dir, base.LEDGER_FILE)
                if isinstance(self.poison, bytes):      # a byte the decoder refuses
                    with open(path, "ab") as fh:
                        fh.write(self.poison + b"\n")
                else:
                    with open(path, "a", encoding="utf-8") as fh:
                        fh.write(self.poison + "\n")
            return result

    def _run(self, d, floor, runner, *extra):
        """`LoopCase._run_loop` with this run's stderr kept and the cap set --
        the same seam `TestAMidBatchHostOutage._run` uses, because the stop
        announces itself there and `_run_loop`'s own redirect throws it away."""
        err = io.StringIO()
        with contextlib.ExitStack() as es:
            es.enter_context(mock.patch.object(
                orchestrate, "_after_first_run",
                side_effect=lambda rr: self._seed_coverage(rr, floor)))
            es.enter_context(mock.patch("scripts.runners.base.runner_for", return_value=runner))
            es.enter_context(contextlib.redirect_stdout(io.StringIO()))
            es.enter_context(contextlib.redirect_stderr(err))
            status = orchestrate.loop(self._args(
                d, "--concurrency", str(self.WIDTH),
                "--max-budget-usd", self.BUDGET, *extra))
        return status, err.getvalue()

    def _reviews(self, runner):
        return [x for x in runner.launched if x.startswith("review-")]

    def test_the_cap_stops_the_batch_instead_of_launching_the_checkpoint(self):
        d, floor = self._repo(floor=self.FLOOR)
        runner = self.Paid(self.FLOOR)
        status, err = self._run(d, floor, runner)
        reviews = self._reviews(runner)
        self.assertEqual(sorted(reviews), sorted(set(reviews)), "a cell was launched twice")
        self.assertLess(len(reviews), len(self.FLOOR), reviews)
        # the three $0.01 results that reach $0.03 + the pool that was already
        # running (width) + the one worker that can turn over while the loop is
        # still persisting, ledgering and counting the result that trips it
        self.assertLessEqual(len(reviews), 3 + self.WIDTH + 1, reviews)
        unlaunched = len(self.FLOOR) - len(reviews)
        self.assertGreaterEqual(unlaunched, 2, reviews)
        # the stop's own line says which of the three rules fired, and a cap is
        # not a failure: "0 host-class failure(s)" would send the operator to
        # wait out a host that is perfectly healthy
        self.assertIn("driver loop: stopped launching after the --max-budget-usd cap; "
                      "%d of %d entries not launched" % (unlaunched, len(self.FLOOR)), err)
        self.assertNotIn("host-class failure(s)", err)
        self.assertNotIn("identical instant failure", err)
        # ...and the run still ends on the gate that always ended it, one
        # iteration later, once the batch has drained
        self.assertEqual("error", status["status"], status)
        self.assertIn("--max-budget-usd %s reached" % self.BUDGET, status["message"])
        self.assertIn("dispatch-ledger.jsonl", status["message"])

    def test_a_cost_it_cannot_read_stops_launching_rather_than_carrying_on(self):
        # `iter_batch` reads a `stop` that RAISES as "carry on", so the
        # `LedgerCorrupt` the top-of-iteration gate turns into an `error`
        # status has to answer True here instead of escaping: a predicate that
        # raised would be swallowed and the rest of the checkpoint launched and
        # paid for -- #1648's fail-open again, one level down.
        d, floor = self._repo(floor=self.FLOOR)
        runner = self.Paid(self.FLOOR, poison=self.POISON)
        status, err = self._run(d, floor, runner)
        reviews = self._reviews(runner)
        self.assertLess(len(reviews), len(self.FLOOR), reviews)
        # No tight upper bound here, unlike the case above: the unreadable row
        # is itself a ledger LINE, and the fixture's gate counts lines, so it
        # is one looser for as long as that row is on disk.
        self.assertGreaterEqual(len(self.FLOOR) - len(reviews), 2, reviews)
        self.assertIn("stopped launching after an unreadable ledger cost", err)
        self.assertNotIn("--max-budget-usd cap", err)
        self.assertEqual("error", status["status"], status)
        self.assertIn("ledger corrupt at line", status["message"])
        self.assertIn("refusing to spend past an unreadable cost", status["message"])

    def test_a_cost_it_cannot_decode_stops_launching_rather_than_carrying_on(self):
        # The catch has to be as wide as the promise: a non-UTF-8 byte in the
        # ledger raises UnicodeDecodeError out of `total_cost`, not
        # LedgerCorrupt, and `iter_batch` would read that raise as "carry on"
        # -- the gate failing OPEN for exactly the case it exists for.
        d, floor = self._repo(floor=self.FLOOR)
        runner = self.Paid(self.FLOOR, poison=b'{"cost_usd": "0.01", "entry_id": "\xff"}')
        status, err = self._run(d, floor, runner)
        reviews = self._reviews(runner)
        self.assertLess(len(reviews), len(self.FLOOR), reviews)
        self.assertGreaterEqual(len(self.FLOOR) - len(reviews), 2, reviews)
        self.assertIn("stopped launching after an unreadable ledger cost", err)
        self.assertNotIn("--max-budget-usd cap", err)
        self.assertEqual("error", status["status"], status)


class TestTheOutputSchemaShapeProof(LoopCase):
    """#1732 part 1, where it belongs: inside the loop, under the guards.

    `probe_cli_flags` reads `<cli> --help` and answers whether the flag is
    ADVERTISED. Run 14 proved a name is not a contract: the CLI advertised
    `--json-schema`, the driver handed it the schema's PATH where it wants the
    TEXT, and 309 launches went to that gap. The other half is one real launch
    — and it happens HERE, after `Guards.arm(pending)`, so it is confined by
    this batch's own read scope and write allowlist and the settings file its
    argv names has been written. At posture time it would have been an
    unconfined turn naming a file that did not exist yet.
    """

    FLOOR = ("SEC", "COD")
    ADVERTISED = {hosts.OUTPUT_SCHEMA: {"flag": "--json-schema", "advertised": True,
                                        "detail": "`claude --help` advertises it"}}
    POSTURE = dict(_ALL_PROVEN, **{hosts.ARTIFACT_WRITE_GUARD: hosts.UNKNOWN})

    def _repo(self, floor=FLOOR, cli_flags=None):
        d, floor = super()._repo(floor=floor)
        # What the `--help` READ found. Driven through `run_probes` for the
        # whole loop, because `driver.run` re-probes on every iteration and
        # would otherwise overwrite a seeded answer with whatever this
        # machine's PATH holds -- a different measurement, tested in
        # tests/probes/test_common.py, and not the subject here.
        # DEEP copies, both here and in `_posture`: `prove_output_schema_shape`
        # writes its verdict INTO the fact it read, so a fixture that handed
        # out the class constant itself would carry one test's verdict into
        # every later test in this class.
        self.flags = copy.deepcopy(self.ADVERTISED if cli_flags is None else cli_flags)
        write_host_evidence(d, self.POSTURE, cli_flags=copy.deepcopy(self.flags))
        return d, floor

    def _posture(self, *_a, **_k):
        """A posture whose write guard is NOT proven, which is what makes a
        review cell `return_json` (`requests.delivery`: a template that grants
        Write, on a host that cannot prove it mediates one, returns its
        findings instead of self-writing). That is the shape run 14 failed in
        -- its 103 tool advisors return their verdicts -- and the only shape
        in which an entry carries `output_schema` at all."""
        return {"schema_version": 1, "host": "claude", "probed_at": "2026-09-20T00:00:00Z",
                "capabilities": {c: {"state": self.POSTURE[c], "by": "fixture",
                                     "detail": "fixture"}
                                 for c in hosts.CAPABILITIES},
                hosts.CLI_FLAGS: copy.deepcopy(self.flags)}

    class Schemed(FakeRunner):
        """A family whose CLI takes the flag, and whose probe launch answers
        however the test says. Every launch records the entry it saw, so what
        reached the argv is a fact rather than an inference."""

        OUTPUT_SCHEMA_FLAG = ("--json-schema",)

        def __init__(self, verdict="ok", host="claude"):
            super().__init__(host)
            self.verdict = verdict
            self.seen = []
            self.bounds = []
            # The two per-launch bounds a real family carries: the loop only
            # SETS them when the operator passed a flag, so a fake that did
            # not declare them could not show that the probe's own bounds are
            # put back.
            self.max_turns, self.entry_timeout = 60, 1800
            self.runner = lambda *a, **k: None      # the injected launcher seam

        def run_entry(self, entry, env):
            self.seen.append(dict(entry))
            self.bounds.append((self.max_turns, self.entry_timeout))
            if entry["id"] != shape_probe.PROBE_ENTRY_ID:
                return super().run_entry(entry, env)
            self.runner(["claude", "-p"])           # the CLI really started
            if self.verdict == "ok":
                return base.RunResult(entry_id=entry["id"], ok=True, text='{"ok": true}',
                                      usage={}, cost_usd=None, model=None,
                                      session_id=None, denials=[], error=None)
            if self.verdict == "refuse":
                return base.RunResult.failed(
                    entry["id"], "claude -p printed no JSON envelope (exit 1)",
                    stderr="--json-schema is not valid JSON")
            raise base.LaunchRefused("the suite must never launch the real claude")

        def probe_launches(self):
            return [e for e in self.seen if e["id"] == shape_probe.PROBE_ENTRY_ID]

        def cells(self):
            return [e for e in self.seen if e["id"] != shape_probe.PROBE_ENTRY_ID]

    def _run(self, d, floor, runner, *extra, seed=True):
        err = io.StringIO()
        with contextlib.ExitStack() as es:
            es.enter_context(mock.patch.object(
                orchestrate, "_after_first_run",
                side_effect=lambda rr: seed and self._seed_coverage(rr, floor)))
            es.enter_context(mock.patch("scripts.runners.base.runner_for", return_value=runner))
            es.enter_context(mock.patch("scripts.host_probes.run_probes",
                                        side_effect=self._posture))
            es.enter_context(contextlib.redirect_stdout(io.StringIO()))
            es.enter_context(contextlib.redirect_stderr(err))
            return orchestrate.loop(self._args(d, "--allow-unenforced", *extra)), err.getvalue()

    def _fact(self, d):
        return runio._load_json(
            runio._pano(d, runio.HOST_CAPABILITIES))[hosts.CLI_FLAGS][hosts.OUTPUT_SCHEMA]

    def test_the_proof_launches_once_and_records_its_verdict(self):
        d, floor = self._repo()
        runner = self.Schemed()
        status, _err = self._run(d, floor, runner)
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(1, len(runner.probe_launches()))
        self.assertEqual(hosts.SHAPE_PROVEN, self._fact(d)[hosts.SHAPE])

    def test_the_probe_is_launched_under_the_armed_guards(self):
        # The whole reason it moved here. `armed_at_launch` is written by the
        # fake from the guard files themselves, so this is the real arming
        # state at the moment of the probe's launch, not a claim about it.
        d, floor = self._repo()
        runner = self.Schemed()
        self._run(d, floor, runner)
        self.assertEqual((True, True), runner.armed_at_launch[0])
        # ...and its own entry is NOT one of the armed grants, so the out_file
        # it names could not be written even if it tried
        probe = runner.probe_launches()[0]
        self.assertNotIn(probe["id"], [e["id"] for e in runner.cells()])
        self.assertFalse(os.path.exists(probe["out_file"]))

    def test_the_probe_clones_a_real_cells_binding_and_its_own_bounds(self):
        d, floor = self._repo()
        runner = self.Schemed()
        self._run(d, floor, runner)
        probe, cell = runner.probe_launches()[0], runner.cells()[0]
        self.assertEqual(cell["agent"], probe["agent"])
        self.assertEqual(cell["enforced"], probe["enforced"])
        self.assertEqual(cell["model"], probe["model"])
        self.assertEqual(shape_probe.PROBE_ENTRY_ID, probe["id"])
        # one turn for the probe, and the batch's own bound put back after it
        self.assertEqual((shape_probe.PROBE_MAX_TURNS, shape_probe.PROBE_ENTRY_TIMEOUT),
                         runner.bounds[0])
        self.assertNotEqual(shape_probe.PROBE_MAX_TURNS, runner.bounds[1][0])

    def test_a_refutation_strips_the_flag_off_this_very_batch(self):
        # The point of proving it before the first `iter_batch` rather than
        # after: the cells this batch is about to launch must not carry an
        # argv the CLI has just refused.
        d, floor = self._repo()
        runner = self.Schemed(verdict="refuse")
        status, err = self._run(d, floor, runner)
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(hosts.SHAPE_REFUTED, self._fact(d)[hosts.SHAPE])
        self.assertEqual([], [c for c in runner.cells() if c.get("output_schema")],
                         "a cell launched with the flag the CLI had just refused")
        self.assertIn("REFUSED it on one probe launch", err)
        self.assertEqual(1, err.count("REFUSED it on one probe launch"))

    def test_a_refuted_run_writes_no_schema_into_later_requests(self):
        d, floor = self._repo()
        runner = self.Schemed(verdict="refuse")
        self._run(d, floor, runner)
        # every later checkpoint regenerated its request through
        # `_materialize_prompts`, which consults the recorded shape
        self.assertEqual([], [c for c in runner.cells() if c.get("output_schema")])
        self.assertEqual(1, len(runner.probe_launches()), "it probed more than once")

    def test_a_proven_run_keeps_stamping(self):
        d, floor = self._repo()
        runner = self.Schemed()
        self._run(d, floor, runner)
        self.assertTrue([c for c in runner.cells() if c.get("output_schema")],
                        "a proven shape stopped the driver stamping")

    def test_it_never_probes_twice_not_even_across_a_resume(self):
        d, floor = self._repo()
        first = self.Schemed()
        self._run(d, floor, first)
        self.assertEqual(1, len(first.probe_launches()))
        again = self.Schemed()
        self._run(d, floor, again, seed=False)
        self.assertEqual([], again.probe_launches(), "a resume re-spent the probe launch")

    def test_a_flag_that_is_not_advertised_is_never_probed(self):
        d, floor = self._repo(cli_flags={hosts.OUTPUT_SCHEMA: {
            "flag": "--json-schema", "advertised": False, "detail": "does not advertise"}})
        runner = self.Schemed()
        self._run(d, floor, runner)
        self.assertEqual([], runner.probe_launches())
        self.assertNotIn(hosts.SHAPE, self._fact(d))

    def test_a_host_that_was_never_interrogated_is_never_probed(self):
        d, floor = self._repo(cli_flags={})
        runner = self.Schemed()
        self._run(d, floor, runner)
        self.assertEqual([], runner.probe_launches())
        self.assertEqual({}, runio._load_json(
            runio._pano(d, runio.HOST_CAPABILITIES))[hosts.CLI_FLAGS])

    def test_a_family_with_no_flag_is_never_probed(self):
        d, floor = self._repo()
        runner = FakeRunner()                       # OUTPUT_SCHEMA_FLAG is ()
        self._run(d, floor, runner)
        self.assertNotIn(hosts.SHAPE, self._fact(d))

    def test_a_batch_with_no_schema_carrying_entry_is_never_probed(self):
        # A checkpoint of self-writing cells has no binding to clone and no
        # flag to measure; it waits for one that does.
        d, floor = self._repo()
        runner = self.Schemed()
        real = orchestrate.loop_batch.prove_output_schema_shape
        seen = []

        def spy(run_dir, host, runner_, pending, env_for):
            for entry in pending:
                entry.pop("output_schema", None)     # self-writing batch
            seen.append(len(pending))
            return real(run_dir, host, runner_, pending, env_for)

        with mock.patch.object(orchestrate.loop_batch, "prove_output_schema_shape", spy):
            self._run(d, floor, runner)
        self.assertTrue(seen)
        self.assertEqual([], runner.probe_launches())
        self.assertNotIn(hosts.SHAPE, self._fact(d))

    def test_a_structural_launch_refusal_is_unmeasured_not_an_exception(self):
        # tests/conftest.py swaps every family's DEFAULT_RUNNER for a
        # LaunchRefused. Reaching it must cost one `unmeasured` verdict, never
        # a run that ends `error`.
        d, floor = self._repo()
        runner = self.Schemed(verdict="refused-launch")
        status, _err = self._run(d, floor, runner)
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(hosts.SHAPE_UNMEASURED, self._fact(d)[hosts.SHAPE])
        self.assertTrue([c for c in runner.cells() if c.get("output_schema")],
                        "an unmeasured shape must change no stamping")

    def test_session_mode_never_probes(self):
        d, floor = self._repo()
        runner = self.Schemed()
        with mock.patch.object(orchestrate.loop_batch, "prove_output_schema_shape") as probe:
            self._run(d, floor, runner, "--mode", "session",
                      "--session-dir", self._session_root(d))
        self.assertEqual(0, probe.call_count)


class TestTheLaunchBackoff(LoopCase):
    """#2506: the automatic loop waits before re-launching an entry whose last
    launch failed.

    `skill/docs/guide/driver-run-loop.md` bounds a failed launch by a per-entry
    cap of 3, and only a host-CLASS failure pauses the run. Nothing slept
    between iterations, so a transient hiccup nobody recognised -- a reset
    connection, a CLI that lost a socket -- burned an entry's three launches
    inside a second or two and parked a cell that would have answered.
    """

    ENTRY = "verify-app-SEC-primary"

    class Flaky(FakeRunner):
        """`FAILURES` launches of `ENTRY` fail transiently, then it answers."""

        FAILURES = 2
        ENTRY = "verify-app-SEC-primary"

        def run_entry(self, entry, env):
            if (entry["id"] != self.ENTRY
                    or self.launched.count(self.ENTRY) >= self.FAILURES):
                return super().run_entry(entry, env)
            self.launched.append(entry["id"])
            return base.RunResult.failed(entry["id"], "connection reset by peer")

    def _loop(self, d, floor, runner):
        """The loop with both backoff seams injected into the real method --
        the schedule under test is the shipped one; only the sleeping and the
        jitter are the test's."""
        slept, real = [], outage.FailureTally.pause_before_launch

        def recording(tally, mode, pending, sleep=None, jitter=None):
            return real(tally, mode, pending, sleep=slept.append,
                        jitter=lambda low, high: 0.0)

        with mock.patch.object(outage.FailureTally, "pause_before_launch", recording):
            return self._run_loop(d, floor, runner), slept

    def test_a_flaky_entry_gets_the_backoff_and_its_third_launch_lands(self):
        d, floor = self._repo()
        runner = self.Flaky()
        status, slept = self._loop(d, floor, runner)
        self.assertEqual("complete", status["status"], status)
        self.assertEqual([2.0, 4.0], slept)
        self.assertEqual(3, runner.launched.count(self.ENTRY))

    def test_the_cap_still_parks_a_stuck_entry_and_never_sleeps_again(self):
        # The schedule may not buy a fourth launch, and the parked iteration
        # may not sleep for it: `exhausted` is read before anything is armed.
        d, floor = self._repo()
        runner = self.Flaky()
        runner.FAILURES = 99
        status, slept = self._loop(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("3 consecutive launches", status["message"])
        self.assertEqual([2.0, 4.0], slept)
        self.assertEqual(orchestrate.MAX_ENTRY_FAILURES,
                         runner.launched.count(self.ENTRY))

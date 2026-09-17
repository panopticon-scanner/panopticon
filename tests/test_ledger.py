"""The dispatch ledger's own behaviour (#1648): a non-finite cost never
reaches the file, a line that cannot be read back as money raises
`money.LedgerCorrupt` rather than being summed past, and `usage_document`
counts what `total_cost` refuses.

Split out of tests/test_orchestrate.py alongside `Ledger` itself (item 21b,
a pure move -- the class's own tests, unchanged in substance). The loop
tests that merely READ a ledger row to check what a run wrote stay in
tests/test_orchestrate.py, now through `ledger_mod.Ledger` too.
"""
import contextlib
import io
import json
import os
import time
from unittest import mock

import scripts.ledger as ledger_mod
import scripts.money as money
import scripts.runners.base as base
from test_orchestrate import LoopCase


class TestLedgerMoney(LoopCase):
    """#1648: the ledger is the budget gate's only evidence, so it stores
    nothing it cannot read back as money, and refuses to sum past a line it
    cannot read at all."""

    def _ledger(self):
        d, _floor = self._repo()
        return ledger_mod.Ledger(d)

    def _result(self, cost, error=None):
        return base.RunResult(entry_id="e", ok=True, text="", usage={}, cost_usd=cost,
                              model=None, session_id=None, denials=[], error=error)

    def test_a_non_finite_cost_never_enters_the_ledger(self):
        ledger = self._ledger()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            ledger.record({"id": "e"}, "review", self._result(float("inf")),
                          "headless", "claude")
        row = ledger.lines()[0]
        self.assertIsNone(row["cost_usd"])
        self.assertIn("cost_usd non-finite (inf) dropped", row["error"])
        with open(ledger.path, encoding="utf-8") as fh:
            self.assertNotIn("Infinity", fh.read())
        self.assertIn("cost_usd non-finite", err.getvalue())
        self.assertEqual(money.ZERO, ledger.total_cost())

    def test_a_dropped_cost_keeps_the_launch_error_it_was_written_with(self):
        ledger = self._ledger()
        with contextlib.redirect_stderr(io.StringIO()):
            ledger.record({"id": "e"}, "review", self._result(float("nan"), "is_error"),
                          "headless", "claude")
        row = ledger.lines()[0]
        self.assertIn("is_error", row["error"])
        self.assertIn("cost_usd non-finite (nan) dropped", row["error"])

    def test_a_good_cost_is_ledgered_and_summed_unchanged(self):
        ledger = self._ledger()
        for _ in range(3):
            ledger.record({"id": "e"}, "review", self._result(0.15), "headless", "claude")
        self.assertEqual([0.15] * 3, [row["cost_usd"] for row in ledger.lines()])
        self.assertEqual(money._money("0.45"), ledger.total_cost())

    def test_total_cost_refuses_a_ledger_line_it_cannot_read(self):
        ledger = self._ledger()
        with open(ledger.path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"cost_usd": 0.1, "phase": "review", "usage": {}}) + "\n")
            fh.write('{"cost_usd": NaN, "phase": "review", "usage": {}}\n')
        with self.assertRaises(money.LedgerCorrupt) as caught:
            ledger.total_cost()
        self.assertEqual(2, caught.exception.line_no)

    def test_a_ledger_that_is_there_but_unreadable_is_a_fault_not_a_zero(self):
        # Fix round 1, M2: `except OSError: return []` answered "nothing spent"
        # for a ledger that EXISTS and cannot be read -- the one answer that is
        # certainly wrong, and the gate went on launching. A directory in its
        # place is the portable way to make the read fail (a chmod 000 file is
        # vacuous for root); a permission change mid-run is the real case.
        ledger = self._ledger()
        os.makedirs(ledger.path)
        with self.assertRaises(money.LedgerCorrupt) as caught:
            ledger.total_cost()
        self.assertIn("ledger unreadable", str(caught.exception))
        self.assertNotIn("line 0", str(caught.exception))   # file-level, not a line
        self.assertEqual([], ledger.lines())                # other readers: still tolerant
        self.assertEqual(1, ledger.usage_document()["corrupt_rows"])

    def test_an_absent_ledger_is_still_nothing_spent(self):
        # The other half of the M2 split: a run that has launched nothing has a
        # ledger that is not there, and that is not a fault.
        ledger = self._ledger()
        self.assertFalse(os.path.exists(ledger.path))
        self.assertEqual(money.ZERO, ledger.total_cost())
        self.assertEqual([], ledger.lines())
        self.assertEqual(0, ledger.usage_document()["corrupt_rows"])

    def test_lines_still_tolerates_a_bad_line_for_every_other_reader(self):
        ledger = self._ledger()
        with open(ledger.path, "w", encoding="utf-8") as fh:
            fh.write("not json\n")
            fh.write(json.dumps({"entry_id": "e", "cost_usd": 0.1}) + "\n")
        self.assertEqual(["e"], [row["entry_id"] for row in ledger.lines()])

    def test_usage_document_counts_the_corrupt_rows_it_tolerated(self):
        # The tokens were really spent (M2), so a row whose MONEY is unreadable
        # still contributes its usage -- and the document says how many such
        # rows it read, rather than quietly under-reporting the run.
        ledger = self._ledger()
        with open(ledger.path, "w", encoding="utf-8") as fh:
            fh.write('{"cost_usd": NaN, "phase": "review", "usage": {"input_tokens": 9}}\n')
            fh.write(json.dumps({"phase": "review", "cost_usd": "NaN",
                                 "usage": {"input_tokens": 5}}) + "\n")
            fh.write(json.dumps({"phase": "verify", "cost_usd": 0.1,
                                 "usage": {"input_tokens": 3}}) + "\n")
        doc = ledger.usage_document()
        self.assertEqual(2, doc["corrupt_rows"])     # the unparseable line and the string NaN
        self.assertEqual(8, doc["total"])            # the readable rows' tokens, both of them
        self.assertEqual(5, doc["by_phase"]["review"])
        with self.assertRaises(money.LedgerCorrupt):
            ledger.total_cost()

    def test_a_clean_run_reports_no_corrupt_rows(self):
        ledger = self._ledger()
        ledger.record({"id": "e"}, "review", self._result(0.1), "headless", "claude")
        self.assertEqual(0, ledger.usage_document()["corrupt_rows"])


class TestCancelledRows(LoopCase):
    """#1662: what a Ctrl-C cut is written into the run's history, through
    `Ledger.record` -- the ledger's ONE writer -- and never by a second one.
    The row carries no cost, because nothing was spent on an entry that never
    ran, and a null cost must not trip the money reader that the budget gate
    fails closed on."""

    def _ledger(self):
        d, _floor = self._repo()
        return ledger_mod.Ledger(d)

    def _cancel(self, ledger, entry_id="review-app-SEC"):
        ledger.record({"id": entry_id}, "review",
                      base.RunResult.failed(entry_id, "cancelled"),
                      "headless", "claude", status=ledger_mod.CANCELLED,
                      rolled_back=True)
        return ledger.lines()[0]

    def test_a_cancelled_row_says_so_and_carries_the_interrupt_stamp(self):
        ledger = self._ledger()
        row = self._cancel(ledger)
        self.assertEqual("cancelled", row["status"])
        self.assertIs(True, row["rolled_back"])
        self.assertFalse(row["ok"])
        self.assertIsNone(row["cost_usd"])
        self.assertRegex(row["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_a_cancelled_row_does_not_trip_the_budget_gate(self):
        # `money.cost_fault` reads a null cost as "no cost", not as a fault:
        # the gate fails CLOSED on an unreadable one, so a cancelled row that
        # looked unreadable would end every interrupted run with "refusing to
        # spend past an unreadable cost" instead of the interrupt's own
        # message.
        ledger = self._ledger()
        row = self._cancel(ledger)
        self.assertIsNone(money.cost_fault(row, None))
        self.assertEqual(money.ZERO, ledger.total_cost())
        self.assertEqual(0, ledger.usage_document()["corrupt_rows"])

    def test_a_handled_entry_gets_a_rolled_back_marker_row(self):
        # The spec clause "tagged `rolled_back: true` on those rows" applied to
        # the rows carrying the KEPT spend as well -- and the ledger is
        # append-only with exactly one writer, so the tag arrives as its own
        # marker row rather than as a retro-edit of the paid one. Without it no
        # reader can tell which paid rows bought artifacts that were then
        # taken back.
        ledger = self._ledger()
        paid = base.RunResult(entry_id="e1", ok=True, text="", usage={"input_tokens": 100},
                              cost_usd=0.01, model="m", session_id="s", denials=[],
                              error=None)
        ledger.record({"id": "e1"}, "review", paid, "headless", "claude")
        ledger.rollback_rows([{"id": "e1"}, {"id": "e2"}], {"e1"},
                             "review", "headless", "claude")
        rows = ledger.lines()
        self.assertEqual([None, "rolled_back", "cancelled"],
                         [row.get("status") for row in rows])
        marker = rows[1]
        self.assertIs(True, marker["rolled_back"])
        self.assertEqual(("e1", False, None, {}),
                         (marker["entry_id"], marker["ok"], marker["cost_usd"],
                          marker["usage"]))
        self.assertIn("rolled back", marker["error"])

    def test_the_marker_rows_are_invisible_to_every_ledger_reader(self):
        ledger = self._ledger()
        paid = base.RunResult(entry_id="e1", ok=True, text="",
                              usage={"input_tokens": 100, "output_tokens": 10},
                              cost_usd=0.25, model="m", session_id="s", denials=[],
                              error=None)
        ledger.record({"id": "e1"}, "review", paid, "headless", "claude")
        before = (ledger.total_cost(), ledger.usage_document())
        ledger.rollback_rows([{"id": "e1"}, {"id": "e2"}], {"e1"},
                             "review", "headless", "claude")
        self.assertEqual(before, (ledger.total_cost(), ledger.usage_document()))
        self.assertEqual(0, ledger.usage_document()["corrupt_rows"])
        # the usage probe's own read filters on `ok`, so neither row is
        # counted as a launch whose envelope carried no usage
        import scripts.probes.claude as claude_probe
        verdict, how = claude_probe._ledger_carries_usage(ledger.path)
        self.assertIs(True, verdict)
        # "1 of 1": the one real launch. The two rows the interrupt appended
        # are `ok: false`, so the probe never counts them as launches whose
        # envelope carried no usage -- which would have REFUTED the capability.
        self.assertIn("1 of 1 successful launch", how)

    def test_a_completed_row_gains_neither_key(self):
        # The format of a COMPLETED row is unchanged (#1662 ruling 5): only
        # the rows the interrupt writes carry `status`/`rolled_back`, so every
        # existing reader of the older shape sees exactly what it always did.
        ledger = self._ledger()
        ledger.record({"id": "e"}, "review",
                      base.RunResult(entry_id="e", ok=True, text="", usage={},
                                     cost_usd=0.01, model=None, session_id=None,
                                     denials=[], error=None),
                      "headless", "claude")
        row = ledger.lines()[0]
        self.assertNotIn("status", row)
        self.assertNotIn("rolled_back", row)


class TestLedgerRowTime(LoopCase):
    """#1685: when the row says it was written, and why that is the entry's own
    finish rather than a second clock read.

    The per-entry row carries `ts` (the row's write time) and `started_at` /
    `finished_at` (measured inside the worker around `run_entry`). All three
    are second-resolution ISO strings, and `ts` came from its own
    `time.gmtime()`. Two reads that straddle a second boundary truncate to
    different seconds, so a row could -- and on CI did -- say it was written
    one second BEFORE the entry it records started. The ordering the test
    asserted was not one the code guaranteed; now `ts` IS `finished_at`, so it
    holds by construction rather than by luck.
    """

    TIMING = {"started_at": "2026-09-16T18:27:42Z",
              "finished_at": "2026-09-16T18:27:43Z", "duration_ms": 900}

    def _record(self, timing=None, frozen=None):
        ledger = ledger_mod.Ledger(self._repo()[0])
        with contextlib.ExitStack() as stack:
            if frozen is not None:
                stack.enter_context(mock.patch.object(ledger_mod.time, "gmtime",
                                                      return_value=frozen))
            ledger.record({"id": "review-app-SEC"}, "review",
                          base.RunResult.failed("review-app-SEC", "x"),
                          "headless", "claude", timing=timing)
        return ledger.lines()[0]

    def test_the_row_time_is_the_entry_s_finish_whatever_the_wall_clock_says(self):
        # The clock is frozen at the epoch across the record call: any row that
        # read it again would stamp 1970 and land before its own start.
        row = self._record(timing=self.TIMING, frozen=time.gmtime(0))
        self.assertEqual(self.TIMING["finished_at"], row["ts"])
        self.assertLessEqual(row["started_at"], row["ts"])

    def test_a_row_with_no_timing_still_stamps_the_write_time(self):
        # The interrupt's rows (`rollback_rows`) pass no timing, and `ts` there
        # is the interrupt's own moment. That path is deliberately unchanged.
        row = self._record(timing=None, frozen=time.gmtime(0))
        self.assertEqual("1970-01-01T00:00:00Z", row["ts"])
        self.assertIsNone(row["started_at"])

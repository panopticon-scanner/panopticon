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

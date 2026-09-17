"""scripts.money: exact dollars for the dispatch ledger and the budget gate (#1648).

The helpers only. The ledger rows and the loop behaviour they buy are in
tests/test_orchestrate.py; the CLI refusal is in tests/test_driver.py.
"""
import argparse
import decimal
import json
import unittest

import scripts.money as money


class TestReadingMoney(unittest.TestCase):
    def test_it_reads_int_float_str_and_decimal_exactly(self):
        for value, expected in ((1, "1"), (0, "0"), (0.1, "0.1"), ("0.30", "0.30"),
                                (" 2.5 ", "2.5"), (decimal.Decimal("0.1"), "0.1")):
            with self.subTest(value=value):
                self.assertEqual(decimal.Decimal(expected), money._money(value))

    def test_three_fifteen_cent_rows_reach_a_forty_five_cent_budget(self):
        # THE case #1648 is about, and the one a float gate gets wrong: three
        # ledgered $0.15 rows sum to 0.44999999999999996 as floats, which misses
        # a $0.45 budget by one ulp and keeps launching paid entries.
        #
        # The float half is ASSERTED, not assumed, and computed BOTH ways: from
        # CPython 3.12 `sum()` over floats is compensated (Neumaier) while `+=`
        # in a loop is not, so a case picked against one of them only is not a
        # case at all -- the suite runs on 3.11 too. Three dimes against $0.30
        # is the classic example and is NOT one of these: 0.30000000000000004
        # crosses $0.30 under float as well.
        rows = [0.15] * 3
        running = 0.0
        for value in rows:
            running += value
        self.assertLess(sum(rows), 0.45)                         # float: budget missed
        self.assertLess(running, 0.45)                           # ...either way it is summed
        total = sum((money._money(0.15) for _ in rows), money.ZERO)
        self.assertEqual(decimal.Decimal("0.45"), total)         # exact: budget reached
        self.assertGreaterEqual(total, money._money("0.45"))

    def test_it_refuses_bool_non_finite_and_nonsense(self):
        # bool explicitly: `isinstance(True, int)` is True, so an unguarded
        # numeric reader counts a flag as a dollar.
        for value in (True, False, float("nan"), float("inf"), float("-inf"),
                      "nan", "Infinity", "-Infinity", "abc", "", None, {}, [1], b"1"):
            with self.subTest(value=value):
                self.assertIsNone(money._money(value))

    def test_is_non_finite_names_the_numbers_that_are_not_money(self):
        for value in (float("nan"), float("inf"), float("-inf"), "nan",
                      "Infinity", "-inf", decimal.Decimal("NaN")):
            with self.subTest(value=value):
                self.assertTrue(money.is_non_finite(value))
        # Not a number at all is not this guard's business: `record` stores it
        # and `sum_costs` refuses it as an unreadable cost.
        for value in (None, 0, 1, 0.1, "0.1", True, "abc", {}, [1]):
            with self.subTest(value=value):
                self.assertFalse(money.is_non_finite(value))


class TestLedgerJson(unittest.TestCase):
    def test_dumps_refuses_to_write_a_non_finite_token(self):
        with self.assertRaises(ValueError):
            money.dumps({"cost_usd": float("nan")})
        self.assertEqual('{"cost_usd": 0.1}', money.dumps({"cost_usd": 0.1}))

    def test_loads_refuses_the_three_non_finite_constants(self):
        # Python's default decoder ACCEPTS all three; that acceptance is how a
        # NaN cost reached the budget comparison and made it false.
        for text in ('{"cost_usd": NaN}', '{"cost_usd": Infinity}',
                     '{"cost_usd": -Infinity}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                money.loads(text)
        self.assertEqual({"cost_usd": 0.1}, money.loads('{"cost_usd": 0.1}'))

    def test_ledger_text_drops_a_non_finite_cost_and_says_so(self):
        text, note = money.ledger_text({"entry_id": "e", "cost_usd": float("inf"),
                                        "error": "timeout"})
        row = json.loads(text)
        self.assertNotIn("Infinity", text)
        self.assertIsNone(row["cost_usd"])
        self.assertIn("timeout", row["error"])                   # the real error is kept
        self.assertIn("cost_usd non-finite (inf) dropped", row["error"])
        self.assertIn("non-finite", note)

    def test_ledger_text_leaves_good_money_alone(self):
        text, note = money.ledger_text({"cost_usd": 0.1, "error": None})
        self.assertIsNone(note)
        self.assertEqual(0.1, json.loads(text)["cost_usd"])
        self.assertIsNone(json.loads(text)["error"])

    def test_ledger_text_still_writes_a_row_whose_non_finite_is_elsewhere(self):
        # The allow_nan=False backstop: no line this module writes can carry a
        # NaN token, whatever a future writer puts in a field that is not money.
        text, note = money.ledger_text({"cost_usd": None, "error": None,
                                        "usage": {"input_tokens": float("nan")}})
        self.assertNotIn("NaN", text)
        self.assertIsNone(json.loads(text)["usage"]["input_tokens"])
        self.assertIn("non-finite", note)

    def test_ledger_text_still_writes_a_row_with_an_unserializable_field(self):
        # Fix round 1, L3: the backstop caught ValueError only, so a field json
        # cannot encode at all (a set -- `denials` comes off a host envelope)
        # raised TypeError out of `record` and lost the row for a launch that
        # had already been paid for.
        text, note = money.ledger_text({"cost_usd": 0.15, "error": None,
                                        "denials": {"Write"}})
        row = json.loads(text)
        self.assertEqual(0.15, row["cost_usd"])          # the money is untouched
        self.assertIn("Write", row["denials"])           # ...and the field is kept as text
        self.assertIn("unserializable", note)
        self.assertIn("unserializable", row["error"])

    def test_read_rows_reports_the_line_number_it_could_not_read(self):
        rows = list(money.read_rows(iter(['{"a": 1}\n', "\n", "not json\n",
                                          '{"cost_usd": NaN}\n', "[]\n"])))
        self.assertEqual([1, 3, 4, 5], [n for n, _row, _why in rows])  # blank skipped, count kept
        self.assertEqual({"a": 1}, rows[0][1])
        self.assertIsNone(rows[0][2])
        for line_no, row, reason in rows[1:]:
            with self.subTest(line_no=line_no):
                self.assertIsNone(row)
                self.assertTrue(reason)


class TestSummingTheLedger(unittest.TestCase):
    def test_it_sums_exactly_and_skips_a_null_cost(self):
        self.assertEqual(decimal.Decimal("0.3"),
                         money.sum_costs([(1, {"cost_usd": None}, None),
                                          (2, {}, None),
                                          (3, {"cost_usd": 0.1}, None),
                                          (4, {"cost_usd": "0.2"}, None)]))

    def test_it_refuses_to_add_past_a_line_it_could_not_read(self):
        with self.assertRaises(money.LedgerCorrupt) as caught:
            money.sum_costs([(1, {"cost_usd": 0.1}, None), (2, None, "bad json")])
        self.assertEqual(2, caught.exception.line_no)
        self.assertIn("ledger corrupt at line 2", str(caught.exception))
        self.assertIn("bad json", str(caught.exception))

    def test_it_refuses_a_cost_that_parses_as_json_but_not_as_money(self):
        for value in ("NaN", "inf", "abc", {}, True):
            with self.subTest(value=value), self.assertRaises(money.LedgerCorrupt):
                money.sum_costs([(1, {"cost_usd": value}, None)])

    def test_it_refuses_a_negative_cost_instead_of_crediting_it(self):
        # Fix round 1, M1: a negative cost was SUBTRACTED from the total, so one
        # `{"cost_usd": -1000}` row buys an unbounded number of paid entries --
        # the #1648 fail-open again, with arithmetic instead of NaN.
        with self.assertRaises(money.LedgerCorrupt) as caught:
            money.sum_costs([(1, {"cost_usd": 0.15}, None), (2, {"cost_usd": -1000}, None)])
        self.assertEqual(2, caught.exception.line_no)
        self.assertIn("non-negative", str(caught.exception))
        self.assertIsNotNone(money.cost_fault({"cost_usd": -0.01}, None))
        self.assertIsNone(money.cost_fault({"cost_usd": 0}, None))

    def test_it_refuses_a_cost_the_decimal_context_cannot_add(self):
        # Fix round 1, L2: `Decimal("1E+999999999")` is finite, so it passes
        # `_money` and overflows on the `+`. Unwrapped, that reached the loop's
        # catch-all as `driver loop: Overflow: [<class 'decimal.Overflow'>]`
        # instead of the budget gate's own refusal.
        with self.assertRaises(money.LedgerCorrupt) as caught:
            money.sum_costs([(1, {"cost_usd": "1E+999999999"}, None)])
        self.assertIn("out of range", str(caught.exception))

    def test_cost_fault_is_the_one_definition_both_readers_use(self):
        self.assertIsNone(money.cost_fault({"cost_usd": 0.1}, None))
        self.assertIsNone(money.cost_fault({"cost_usd": None}, None))
        self.assertIn("bad json", money.cost_fault(None, "bad json"))
        self.assertIn("cost_usd", money.cost_fault({"cost_usd": "NaN"}, None))


class TestBudgetArg(unittest.TestCase):
    def test_it_refuses_what_type_float_accepted(self):
        for text in ("nan", "NaN", "inf", "-inf", "Infinity", "-1", "-0.01", "abc", ""):
            with self.subTest(text=text), self.assertRaises(argparse.ArgumentTypeError):
                money.budget_arg(text)

    def test_it_returns_an_exact_decimal(self):
        self.assertEqual(decimal.Decimal("0.45"), money.budget_arg("0.45"))
        self.assertEqual(decimal.Decimal("0"), money.budget_arg("0"))
        self.assertEqual(decimal.Decimal("0.45"), money.budget_arg("0.15") * 3)


if __name__ == "__main__":
    unittest.main()

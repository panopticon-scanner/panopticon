"""#3626: cross-run disclosure of model fallbacks and strict state.

Synthetic report metas only; no run data is read."""
import unittest

import scripts.model_disclosure as md

SUB = {"entry": "review-g-SEC", "role": "domain_panel", "requested": "gemini-4-carbon-high",
       "bound": "gemini-4-argon-high", "route": "key", "rung": 1,
       "reason": "not listed on route key"}


def _ran(sub):
    return {k: sub[k] for k in ("role", "requested", "bound", "rung", "route", "reason")}


class TestOneRun(unittest.TestCase):
    def test_a_run_before_3582_is_not_recorded_never_strict_or_clean(self):
        for meta in ({}, {"model_strict": "yes"}, None):
            with self.subTest(meta=meta):
                got = md.run_models(meta)
                self.assertEqual((None, None, 0, False), (got["strict"], got["substitutions"],
                                                          got["dropped"], got["malformed"]))

    def test_a_recorded_run_with_no_key_ran_every_dispatch_as_requested(self):
        for strict in (True, False):
            with self.subTest(strict=strict):
                got = md.run_models({"model_strict": strict})
                self.assertEqual((strict, []), (got["strict"], got["substitutions"]))

    def test_malformed_records_are_counted_never_silently_dropped(self):
        bad = [dict(SUB, rung=0), dict(SUB, rung=True), dict(SUB, rung="1"),
               dict(SUB, bound=""), dict(SUB, entry=None), dict(SUB, route=""),
               dict(SUB, reason=""), dict(SUB, role=""), dict(SUB, requested=""), "x", None]
        got = md.run_models({"model_strict": False, "model_substitutions": bad + [SUB]})
        self.assertEqual([SUB], got["substitutions"])
        self.assertEqual(len(bad), got["dropped"])
        # A list without model_strict still says what fell back.
        self.assertEqual([SUB], md.run_models({"model_substitutions": [SUB]})["substitutions"])

    def test_a_list_that_is_not_a_list_is_unreadable_not_empty(self):
        for raw in ({"entry": "x"}, "review-g-SEC", 7):
            with self.subTest(raw=raw):
                got = md.run_models({"model_strict": True, "model_substitutions": raw})
                self.assertIsNone(got["substitutions"])
                self.assertTrue(got["malformed"])

    def test_a_duplicate_entry_keeps_the_first_record_as_the_producer_does(self):
        later = dict(SUB, bound="gemini-3.8-flash-medium", rung=2)
        got = md.run_models({"model_strict": False, "model_substitutions": [SUB, later]})
        self.assertEqual([SUB], got["substitutions"])
        self.assertEqual(0, got["dropped"])


class TestAcrossRuns(unittest.TestCase):
    def test_identical_recorded_runs_disclose_nothing(self):
        got = md.compare_models([{"model_strict": True}, {"model_strict": True}])
        self.assertEqual((False, False, [], True, False, [0, 0]),
                         (got["disclose"], got["strict_differs"], got["entries"],
                          got["recorded"], got["partial"], got["unreadable"]))

    def test_differing_strict_states_are_disclosed(self):
        for a, b in ((True, False), (True, None), (False, None)):
            with self.subTest(a=a, b=b):
                metas = [{"model_strict": a} if a is not None else {},
                         {"model_strict": b} if b is not None else {}]
                got = md.compare_models(metas)
                self.assertTrue(got["disclose"])
                self.assertTrue(got["strict_differs"])
                self.assertEqual([a, b], got["strict"])
                self.assertEqual(None in (a, b), got["partial"])

    def test_one_run_fell_back_the_other_ran_as_requested(self):
        got = md.compare_models([{"model_strict": False, "model_substitutions": [SUB]},
                                 {"model_strict": False}])
        self.assertTrue(got["disclose"])
        self.assertFalse(got["strict_differs"])
        self.assertEqual([{"entry": "review-g-SEC", "role": "domain_panel",
                           "requested": "gemini-4-carbon-high", "same": False,
                           "routes_differ": False,
                           "runs": [_ran(SUB), md.AS_REQUESTED]}], got["entries"])

    def test_both_fell_back_the_same_way_is_still_disclosed_but_same(self):
        got = md.compare_models([{"model_strict": False, "model_substitutions": [SUB]}] * 2)
        self.assertTrue(got["disclose"])
        self.assertTrue(got["entries"][0]["same"])

    def test_requested_and_role_are_per_run_and_a_different_request_differs(self):
        # #3633 review 1: run1 asked argon and ran flash, run2 asked carbon and ran flash.
        a = dict(SUB, requested="gemini-4-argon-high", bound="gemini-3.8-flash-medium")
        b = dict(SUB, requested="gemini-4-carbon-high", bound="gemini-3.8-flash-medium",
                 role="domain_advisor")
        row = md.compare_models([{"model_strict": False, "model_substitutions": [a]},
                                 {"model_strict": False, "model_substitutions": [b]}])["entries"][0]
        self.assertIsNone(row["requested"])
        self.assertIsNone(row["role"])
        self.assertFalse(row["same"])
        self.assertEqual(["gemini-4-argon-high", "gemini-4-carbon-high"],
                         [r["requested"] for r in row["runs"]])

    def test_different_rungs_or_routes_differ(self):
        for change in ({"bound": "gemini-3.8-flash-medium", "rung": 2}, {"route": "signin"}):
            with self.subTest(change=change):
                row = md.compare_models([
                    {"model_strict": False, "model_substitutions": [SUB]},
                    {"model_strict": False, "model_substitutions": [dict(SUB, **change)]}
                ])["entries"][0]
                self.assertFalse(row["same"])
                self.assertEqual("route" in change, row["routes_differ"])

    def test_an_unrecorded_run_beside_a_fallback_is_not_recorded_not_as_requested(self):
        got = md.compare_models([{"model_strict": False, "model_substitutions": [SUB]}, {}])
        self.assertIsNone(got["entries"][0]["runs"][1])
        self.assertFalse(got["entries"][0]["same"])
        self.assertTrue(got["partial"])

    def test_unreadable_records_are_disclosed_per_run(self):
        got = md.compare_models([{"model_strict": True, "model_substitutions": "garbage"},
                                 {"model_strict": True, "model_substitutions": [{"entry": 1}]}])
        self.assertEqual(["all", 1], got["unreadable"])
        self.assertTrue(got["disclose"])
        self.assertTrue(got["recorded"])
        self.assertTrue(got["partial"])                 # run1's fallbacks are unknown

    def test_unreadable_records_alone_count_as_recorded(self):
        # #3633 r2 N9: neither run records strict; one carries only an unreadable record.
        got = md.compare_models([{"model_substitutions": [5]}, {}])
        self.assertTrue(got["recorded"])
        self.assertEqual([1, 0], got["unreadable"])

    def test_a_run_with_dropped_records_is_maybe_not_as_requested(self):
        # #3633 r2 item 3: its missing entry may be one of the dropped records.
        got = md.compare_models([{"model_strict": False, "model_substitutions": [SUB]},
                                 {"model_strict": False, "model_substitutions": ["junk"]}])
        row = got["entries"][0]
        self.assertEqual(md.MAYBE_UNREADABLE, row["runs"][1])
        self.assertFalse(row["same"])
        self.assertTrue(got["partial"])
        self.assertEqual("ran as requested, or its record is unreadable",
                         md.ran_word(md.MAYBE_UNREADABLE))
        both = md.compare_models([{"model_strict": False, "model_substitutions": [SUB, "junk"]},
                                  {"model_strict": False, "model_substitutions": [SUB]}])
        self.assertEqual(_ran(SUB), both["entries"][0]["runs"][0])

    def test_fallbacks_without_a_strict_state_still_count_as_recorded(self):
        got = md.compare_models([{"model_substitutions": [SUB]}, {"model_substitutions": [SUB]}])
        self.assertTrue(got["recorded"])
        self.assertTrue(got["disclose"])
        self.assertEqual([None, None], got["strict"])

    def test_no_run_recorded_anything(self):
        got = md.compare_models([{}, {}])
        self.assertEqual((False, False), (got["disclose"], got["recorded"]))

    def test_entries_are_sorted_and_one_row_per_entry(self):
        a = dict(SUB, entry="verify-g-SEC-primary", role="domain_advisor")
        got = md.compare_models([{"model_strict": False, "model_substitutions": [a, SUB, SUB]},
                                 {"model_strict": False, "model_substitutions": [SUB]}])
        self.assertEqual(["review-g-SEC", "verify-g-SEC-primary"],
                         [r["entry"] for r in got["entries"]])

    def test_the_words_an_operator_reads(self):
        ran = _ran(SUB)
        self.assertEqual(["fallbacks off (strict)", "fallbacks on", "not recorded"],
                         [md.strict_word(v) for v in (True, False, None)])
        self.assertEqual("ran gemini-4-argon-high (fallback rung 1: not listed on route key)",
                         md.ran_word(ran))
        self.assertEqual("requested gemini-4-carbon-high, ran gemini-4-argon-high via route key "
                         "(fallback rung 1: not listed on route key)",
                         md.ran_word(ran, with_requested=True, with_route=True))
        self.assertEqual("as domain_panel, ran gemini-4-argon-high (fallback rung 1: not listed "
                         "on route key)", md.ran_word(ran, with_role=True))
        self.assertEqual(["ran as requested", "not recorded"],
                         [md.ran_word(md.AS_REQUESTED), md.ran_word(None)])
        self.assertEqual(["", "1 fallback record unreadable", "2 fallback records unreadable",
                          "fallback records unreadable (not a list)"],
                         [md.unreadable_word(v) for v in (0, 1, 2, "all")])


if __name__ == "__main__":
    unittest.main()

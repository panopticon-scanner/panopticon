"""#3626: cross-run disclosure of model fallbacks and strict state.

Synthetic report metas only; no run data is read."""
import unittest

import scripts.model_disclosure as md

SUB = {"entry": "review-g-SEC", "role": "domain_panel", "requested": "gemini-4-carbon-high",
       "bound": "gemini-4-argon-high", "route": "key", "rung": 1,
       "reason": "not listed on route key"}


class TestOneRun(unittest.TestCase):
    def test_a_run_before_3582_is_not_recorded_never_strict_or_clean(self):
        self.assertEqual({"strict": None, "substitutions": None}, md.run_models({}))
        self.assertEqual({"strict": None, "substitutions": None},
                         md.run_models({"model_strict": "yes"}))
        self.assertEqual({"strict": None, "substitutions": None}, md.run_models(None))

    def test_a_recorded_run_with_no_key_ran_every_dispatch_as_requested(self):
        for strict in (True, False):
            with self.subTest(strict=strict):
                self.assertEqual({"strict": strict, "substitutions": []},
                                 md.run_models({"model_strict": strict}))

    def test_only_well_formed_records_are_read(self):
        bad = [dict(SUB, rung=0), dict(SUB, rung=True), dict(SUB, rung="1"),
               dict(SUB, bound=""), dict(SUB, entry=None), "x", None]
        got = md.run_models({"model_strict": False, "model_substitutions": bad + [SUB]})
        self.assertEqual([SUB], got["substitutions"])
        # A list without model_strict still says what fell back.
        self.assertEqual({"strict": None, "substitutions": [SUB]},
                         md.run_models({"model_substitutions": [SUB]}))


class TestAcrossRuns(unittest.TestCase):
    def test_identical_recorded_runs_disclose_nothing(self):
        got = md.compare_models([{"model_strict": True}, {"model_strict": True}])
        self.assertEqual((False, False, [], True),
                         (got["disclose"], got["strict_differs"], got["entries"], got["recorded"]))

    def test_differing_strict_states_are_disclosed(self):
        for a, b in ((True, False), (True, None), (False, None)):
            with self.subTest(a=a, b=b):
                metas = [{"model_strict": a} if a is not None else {},
                         {"model_strict": b} if b is not None else {}]
                got = md.compare_models(metas)
                self.assertTrue(got["disclose"])
                self.assertTrue(got["strict_differs"])
                self.assertEqual([a, b], got["strict"])

    def test_one_run_fell_back_the_other_ran_as_requested(self):
        got = md.compare_models([{"model_strict": False, "model_substitutions": [SUB]},
                                 {"model_strict": False}])
        self.assertTrue(got["disclose"])
        self.assertFalse(got["strict_differs"])
        self.assertEqual([{"entry": "review-g-SEC", "role": "domain_panel",
                           "requested": "gemini-4-carbon-high", "same": False,
                           "runs": [{"bound": "gemini-4-argon-high", "rung": 1, "route": "key",
                                     "reason": "not listed on route key"},
                                    md.AS_REQUESTED]}], got["entries"])

    def test_both_fell_back_the_same_way_is_still_disclosed_but_same(self):
        got = md.compare_models([{"model_strict": False, "model_substitutions": [SUB]}] * 2)
        self.assertTrue(got["disclose"])
        self.assertTrue(got["entries"][0]["same"])

    def test_different_rungs_differ(self):
        other = dict(SUB, bound="gemini-3.8-flash-medium", rung=2)
        got = md.compare_models([{"model_strict": False, "model_substitutions": [SUB]},
                                 {"model_strict": False, "model_substitutions": [other]}])
        self.assertFalse(got["entries"][0]["same"])

    def test_an_unrecorded_run_beside_a_fallback_is_not_recorded_not_as_requested(self):
        got = md.compare_models([{"model_strict": False, "model_substitutions": [SUB]}, {}])
        self.assertIsNone(got["entries"][0]["runs"][1])
        self.assertFalse(got["entries"][0]["same"])

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
        self.assertEqual(["fallbacks off (strict)", "fallbacks on", "not recorded"],
                         [md.strict_word(v) for v in (True, False, None)])
        self.assertEqual("ran gemini-4-argon-high (fallback rung 1: not listed on route key)",
                         md.ran_word({"bound": "gemini-4-argon-high", "rung": 1,
                                      "reason": "not listed on route key"}))
        self.assertEqual(["ran as requested", "not recorded"],
                         [md.ran_word(md.AS_REQUESTED), md.ran_word(None)])


if __name__ == "__main__":
    unittest.main()

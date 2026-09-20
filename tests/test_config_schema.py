"""#1681 Plan 2: the `settings:` trust classes, the clamp and the ratchet."""
import argparse
import json
import os
import tempfile
import unittest

import scripts.config_schema as cs
import scripts.discovery as discovery
import scripts.driver as driver
import scripts.run_manifest as run_manifest
# conftest puts tests/ on sys.path, so the literal ratchet's regex is
# importable by name (see test_the_module_never_spells_a_config_filename).
import test_repo_config_literals as lit


class TestTheTrustClassTable(unittest.TestCase):
    def test_every_key_is_in_exactly_one_class(self):
        keys = list(cs.GRAIN_KEYS) + list(cs.GATE_KEYS) + list(cs.OPERATOR_ONLY_KEYS)
        self.assertEqual(len(keys), len(set(keys)), "a key is in two classes")
        self.assertEqual(set(keys), set(cs.CLASS_OF))

    def test_every_gate_key_has_a_direction_and_a_default(self):
        for key in cs.GATE_KEYS:
            self.assertIn(key, cs.DEFAULTS, key)
            self.assertTrue(key == "max_verify" or key in cs.STRICTNESS, key)
            self.assertNotIn(key, cs.CLAMPS, "a gate key is ratcheted, not clamped")

    def test_the_two_bands_are_the_owner_s_and_the_cap_is_the_engine_s(self):
        self.assertEqual(cs.CLAMPS["max_per_group"], (8, discovery.DEFAULT_MAX_PER_GROUP))
        self.assertEqual(cs.CLAMPS["max_groups"], (4, 64))
        for key, (low, high) in cs.CLAMPS.items():
            self.assertEqual(cs.CLASS_OF[key], "grain", key)
            self.assertLess(low, high, key)

    def test_every_run_flag_is_classified(self):
        """Spec §4: a new `driver run` flag cannot land unclassified."""
        parser = driver.build_parser()
        subs = [a for a in parser._actions
                if isinstance(a, argparse._SubParsersAction)][0]
        dests = set()
        for verb in ("run", "loop"):
            dests |= {a.dest for a in subs.choices[verb]._actions if a.dest != "help"}
        self.assertEqual(sorted(dests - set(cs.CLASS_OF)), [],
                         "classify these in config_schema.CLASS_OF")

    def test_every_anti_drift_flag_is_classified(self):
        for key in run_manifest._FLAG_KEYS:
            self.assertIn(key, cs.CLASS_OF, key)

    def test_the_module_never_spells_a_config_filename(self):
        # tests/test_repo_config_literals.py owns the rule; this says WHY the
        # run artifact is called config-resolution.json and not config.json.
        self.assertIsNone(lit.LITERALS.search(cs.RESOLUTION_NAME))
        with open(cs.__file__, encoding="utf-8") as fh:
            self.assertIsNone(lit.LITERALS.search(fh.read()))


class TestParseSettings(unittest.TestCase):
    def test_no_settings_section_is_empty_and_quiet(self):
        p = cs.parse_settings({"version": 1, "groups": {}})
        self.assertEqual((p.requested, p.typed, p.refused, p.disclosures), ({}, {}, [], []))

    def test_well_typed_grain_and_gate_values_are_typed(self):
        p = cs.parse_settings({"settings": {"max_per_group": 20, "security": "REDTEAM",
                                            "tools": True}})
        self.assertEqual(p.typed, {"max_per_group": 20, "security": "redteam", "tools": True})
        self.assertEqual(p.refused, [])
        self.assertEqual(p.requested["security"], "REDTEAM")   # verbatim

    def test_an_operator_only_key_is_refused_and_counted(self):
        p = cs.parse_settings({"settings": {"allow_unenforced": True, "diff_context": 9}})
        self.assertEqual(p.typed, {})
        self.assertEqual(sorted(r["key"] for r in p.refused), ["allow_unenforced", "diff_context"])
        self.assertTrue(all("operator-only" in r["reason"] for r in p.refused))
        self.assertIn("target config asked for `allow_unenforced: true`", p.disclosures[0])

    def test_an_unknown_key_is_refused_and_exclude_paths_gets_a_hint(self):
        p = cs.parse_settings({"settings": {"nonsense": 1, "exclude_paths": ["a/**"]}})
        self.assertEqual(p.typed, {})
        reasons = {r["key"]: r["reason"] for r in p.refused}
        self.assertIn("unknown key", reasons["nonsense"])
        self.assertIn("TOP-LEVEL", reasons["exclude_paths"])

    def test_bad_types_are_refused_with_the_shape_they_wanted(self):
        p = cs.parse_settings({"settings": {"max_per_group": 0, "max_groups": "40",
                                            "max_verify": True, "tools": "yes",
                                            "security": "paranoid"}})
        self.assertEqual(p.typed, {})
        reasons = {r["key"]: r["reason"] for r in p.refused}
        self.assertIn("positive integer", reasons["max_per_group"])
        self.assertIn("positive integer", reasons["max_groups"])
        self.assertIn("positive integer", reasons["max_verify"])   # True is not 1
        self.assertIn("true or false", reasons["tools"])
        self.assertIn("standard, redteam", reasons["security"])

    def test_a_non_scalar_value_never_reaches_requested(self):
        p = cs.parse_settings({"settings": {"max_per_group": {"nested": 1}}})
        self.assertEqual(p.requested, {})
        self.assertEqual(p.refused[0]["reason"], "value is not a scalar")

    def test_a_non_mapping_settings_section_refuses_the_whole_section(self):
        p = cs.parse_settings({"settings": [1, 2]})
        self.assertEqual(p.typed, {})
        self.assertIn("mapping", p.refused[0]["reason"])


def _resolve(settings, cli=None, defaults=None):
    return cs.resolve_settings(cli or {}, cs.parse_settings({"settings": settings}),
                               defaults=defaults)


class TestTheClamp(unittest.TestCase):
    def test_an_in_band_value_passes_through_unchanged(self):
        r = _resolve({"max_per_group": 20, "max_groups": 12})
        self.assertEqual(r.effective, {"max_per_group": 20, "max_groups": 12})
        self.assertEqual(r.clamped, [])

    def test_an_above_band_value_is_clamped_to_the_upper_bound(self):
        r = _resolve({"max_per_group": 5000})
        self.assertEqual(r.effective["max_per_group"], 48)
        self.assertEqual(r.clamped, [{"key": "max_per_group", "requested": 5000,
                                      "effective": 48}])
        self.assertIn("clamped to 48", r.disclosures[0])
        self.assertIn("target config asked for `max_per_group: 5000`", r.disclosures[0])

    def test_a_below_band_value_is_clamped_to_the_lower_bound(self):
        r = _resolve({"max_groups": 1})
        self.assertEqual(r.effective["max_groups"], 4)
        self.assertEqual(r.clamped[0]["requested"], 1)

    def test_a_clamp_is_not_a_refusal(self):
        r = _resolve({"max_per_group": 5000})
        self.assertEqual(r.refused, [])

    def test_the_cli_is_never_clamped_and_always_wins(self):
        r = _resolve({"max_per_group": 5000}, cli={"max_per_group": 900})
        self.assertNotIn("max_per_group", r.effective)
        self.assertEqual(r.clamped, [])
        self.assertIn("the command line's `900` wins", r.disclosures[0])


class TestTheRatchet(unittest.TestCase):
    def test_a_tightening_gate_value_is_honoured(self):
        for key, value in (("security", "redteam"), ("fail_on", "high"),
                           ("gate_scope", "all")):
            r = _resolve({key: value})
            self.assertEqual(r.effective.get(key), value, key)
            self.assertEqual(r.refused, [], key)

    def test_a_loosening_gate_value_is_refused_and_disclosed(self):
        for key, value, base in (("severity", "high", "all"),
                                 ("tools", False, "true"),
                                 ("max_verify", 5, "null")):
            r = _resolve({key: value})
            self.assertNotIn(key, r.effective, key)
            self.assertEqual(r.refused[0]["key"], key)
            self.assertIn("loosens the built-in default", r.refused[0]["reason"])
            self.assertIn("refused", r.disclosures[0])
            self.assertIn(base, r.refused[0]["reason"])

    def test_a_value_equal_to_the_default_is_a_disclosed_no_op(self):
        r = _resolve({"security": "standard", "tools": True})
        self.assertEqual(r.effective, {"security": "standard", "tools": True})
        self.assertEqual(r.refused, [])
        self.assertTrue(any("already the built-in default" in d for d in r.disclosures))

    def test_max_verify_is_refused_against_the_uncapped_default(self):
        # Spec Amendments finding 1: the built-in default is None = uncapped,
        # which is STRICTER than any number, so no committed cap survives the
        # ratchet. Pinned so the day the baseline changes, this test says so.
        self.assertIsNone(cs.DEFAULTS["max_verify"])
        r = _resolve({"max_verify": 1000})
        self.assertNotIn("max_verify", r.effective)
        self.assertIn("null", r.refused[0]["reason"])

    def test_max_verify_tightens_against_a_finite_baseline(self):
        defaults = dict(cs.DEFAULTS, max_verify=10)
        self.assertEqual(_resolve({"max_verify": 30}, defaults=defaults)
                         .effective["max_verify"], 30)
        self.assertEqual(_resolve({"max_verify": 4}, defaults=defaults).effective, {})

    def test_a_partial_defaults_dict_still_ratchets_every_key_it_omits(self):
        # A caller overriding only `security` must not blow away the built-in
        # baseline for every OTHER gate key: `tools` still ratchets against
        # the real default (True), and the named override actually takes.
        r = _resolve({"tools": False, "security": "standard"},
                     defaults={"security": "redteam"})
        self.assertNotIn("tools", r.effective)
        self.assertNotIn("security", r.effective)
        reasons = {x["key"]: x["reason"] for x in r.refused}
        self.assertIn("true", reasons["tools"])
        self.assertIn("redteam", reasons["security"])

    def test_the_cli_wins_over_a_tightening_gate_value_too(self):
        r = _resolve({"security": "redteam"}, cli={"security": "standard"})
        self.assertEqual(r.effective, {})
        self.assertIn("the command line's `standard` wins", r.disclosures[0])

    def test_refusals_from_the_parse_layer_are_carried_through(self):
        r = _resolve({"allow_unenforced": True, "nonsense": 1})
        self.assertEqual(sorted(x["key"] for x in r.refused),
                         ["allow_unenforced", "nonsense"])
        self.assertEqual(r.effective, {})

    def test_requested_is_what_the_file_asked_for_including_refusals(self):
        r = _resolve({"security": "redteam", "allow_unenforced": True})
        self.assertEqual(r.requested, {"security": "redteam", "allow_unenforced": True})

    def test_an_empty_document_resolves_to_nothing(self):
        r = cs.resolve_settings({}, cs.EMPTY_PARSED)
        self.assertEqual((r.effective, r.requested, r.refused, r.clamped, r.disclosures),
                         ({}, {}, [], [], []))

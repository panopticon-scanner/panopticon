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

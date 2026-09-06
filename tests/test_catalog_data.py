"""Shipped catalog data must be COMPLETE (spec §3, §8): every entry carries
definition, boundary, >=2 examples and evidence; names are valid group ids;
no alias resolves to two entries; reserved names are absent. Loader tests use
minimal fixtures; this file is the only place the shipped prose is checked."""
import os
import unittest

import yaml

import scripts.groups_schema as groups_schema
import scripts.setup_proposal as sp

DATA = os.path.join(os.path.dirname(__file__), "..", "skill", "data")
CAPABILITIES = os.path.join(DATA, "capability_vocabulary.yml")
LAYERS = os.path.join(DATA, "layer_vocabulary.yml")


def _raw_entries(path, root_key):
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return doc[root_key], doc


class _CatalogCompleteness:
    path = None
    root_key = None
    loader = None
    min_entries = 1

    def test_loader_is_clean(self):
        catalog, errors = self.loader(self.path)
        self.assertEqual(errors, [])
        self.assertGreaterEqual(len(catalog["names"]), self.min_entries)

    def test_every_entry_is_complete(self):
        entries, doc = _raw_entries(self.path, self.root_key)
        self.assertRegex(str(doc.get("version")), r"^\d+\.\d+\.\d+$")
        for e in entries:
            name = e.get("name")
            with self.subTest(entry=name):
                self.assertRegex(name, groups_schema._GROUP_NAME_RE)
                self.assertNotIn(name, sp.RESERVED_GROUP_NAMES)
                for field in ("definition", "boundary"):
                    self.assertIsInstance(e.get(field), str)
                    self.assertTrue(e[field].strip(), "%s: empty %s" % (name, field))
                self.assertIsInstance(e.get("aliases"), list)
                for a in e["aliases"]:
                    self.assertIsInstance(a, str)
                    self.assertNotIn(sp.alias_key(a),
                                     {sp.alias_key(r) for r in sp.RESERVED_GROUP_NAMES})
                examples = e.get("examples")
                self.assertIsInstance(examples, list)
                self.assertGreaterEqual(len(examples), 2, "%s: needs >=2 examples" % name)
                for ex in examples:
                    self.assertEqual(set(ex), {"repo", "path"})
                    self.assertTrue(ex["repo"].strip() and ex["path"].strip())
                self.assertIsInstance(e.get("evidence"), dict)
                self.assertTrue(e["evidence"], "%s: empty evidence" % name)
                for glob in e.get("hints") or []:
                    self.assertIsInstance(glob, str)
                for ref in e.get("see_also") or []:
                    self.assertIn(ref, {x["name"] for x in entries},
                                  "%s: see_also %r is not an entry" % (name, ref))

    def test_no_alias_collides_across_entries(self):
        entries, _ = _raw_entries(self.path, self.root_key)
        owners = {}
        for e in entries:
            for label in [e["name"]] + list(e.get("aliases") or []):
                key = sp.alias_key(label)
                self.assertNotIn(key, {k for k, o in owners.items() if o != e["name"]},
                                 "alias %r of %s already owned by %s"
                                 % (label, e["name"], owners.get(key)))
                owners[key] = e["name"]


class TestLayerCatalog(_CatalogCompleteness, unittest.TestCase):
    path = LAYERS
    root_key = "layers"
    loader = staticmethod(sp.load_layers)
    min_entries = 9

    def test_the_nine_layers(self):
        layers, _ = sp.load_layers(LAYERS)
        self.assertEqual(layers["names"], ["API", "Service", "Data", "UI", "Client",
                                           "Worker", "Middleware", "CLI", "Integration"])

    def test_synonym_folds_from_the_panel(self):
        layers, _ = sp.load_layers(LAYERS)
        for alias, canonical in (("controller", "API"), ("handlers", "API"),
                                 ("routes", "API"), ("migrations", "Data"),
                                 ("model", "Data"), ("repository", "Data"),
                                 ("jobs", "Worker"), ("queue", "Worker"),
                                 ("scheduler", "Worker")):
            self.assertEqual(sp.canonicalize(alias, layers), canonical, alias)

    def test_not_layers(self):
        layers, _ = sp.load_layers(LAYERS)
        for not_a_layer in ("tests", "config", "docs", "Core"):
            self.assertIsNone(sp.canonicalize(not_a_layer, layers), not_a_layer)

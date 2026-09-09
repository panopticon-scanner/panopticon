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
    provenances = frozenset()      # the provenance values this catalog may carry

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
                self.assertTrue(groups_schema._GROUP_NAME_RE.match(name), name)
                self.assertNotIn(name, sp.RESERVED_GROUP_NAMES)
                self.assertIn(e.get("provenance"), self.provenances,
                              "%s: provenance %r" % (name, e.get("provenance")))
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
    provenances = frozenset({"panel-5.2.0"})

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


R1_NAMES = ["Auth", "Accounts", "Checkout", "Billing", "Catalog", "Search", "Fulfillment",
            "Notifications", "Reporting", "Admin", "API", "Platform", "UI"]


class TestCapabilityCatalog(_CatalogCompleteness, unittest.TestCase):
    path = CAPABILITIES
    root_key = "capabilities"
    loader = staticmethod(sp.load_vocabulary)
    min_entries = 45
    provenances = frozenset({"r1", "panel-5.2.0"})

    def test_r1_roster_is_kept_verbatim(self):
        catalog, _ = sp.load_vocabulary(self.path)
        for name in R1_NAMES:
            self.assertIn(name, catalog["names"])
            self.assertEqual(catalog["entries"][name].get("provenance"), "r1")
        self.assertEqual(catalog["names"][:13], R1_NAMES, "R1 entries stay first, in R1 order")

    def test_integrations_is_a_layer_not_a_capability(self):
        catalog, _ = sp.load_vocabulary(self.path)
        self.assertNotIn("Integrations", catalog["names"])
        self.assertIsNone(sp.canonicalize("integrations", catalog))

    def test_new_entries_carry_panel_provenance(self):
        catalog, _ = sp.load_vocabulary(self.path)
        new = [n for n in catalog["names"] if n not in R1_NAMES]
        self.assertEqual(len(new), 32)
        for name in new:
            e = catalog["entries"][name]
            self.assertEqual(e.get("provenance"), "panel-5.2.0", name)
            self.assertEqual(e["evidence"].get("round"), "2026-08-21-5.2.0-vocab-panel", name)
            self.assertGreaterEqual(e["evidence"].get("repos_present", 0), 10, name)

    def test_panel_folds(self):
        catalog, _ = sp.load_vocabulary(self.path)
        for raw, canonical in [("authentication", "Auth"), ("Identity & Access", "Auth"),
                               ("administration", "Admin"), ("subscriptions", "Billing"),
                               ("MCP", "AI"), ("user-management", "Accounts"),
                               ("access_control", "Permissions"), ("i18n", "Localization"),
                               ("telemetry", "Observability"), ("mail", "Email"),
                               ("teams", "Organizations"), ("stock", "Inventory")]:
            self.assertEqual(sp.canonicalize(raw, catalog), canonical, raw)

    def test_deferred_block_lists_the_five_to_nine_tier(self):
        with open(self.path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        deferred = doc.get("deferred")
        self.assertIsInstance(deferred, list)
        self.assertGreaterEqual(len(deferred), 10)
        names = set(catalog_name for catalog_name in sp.load_vocabulary(self.path)[0]["names"])
        for row in deferred:
            self.assertIsInstance(row, dict)
            self.assertNotIn(row["name"], names, "deferred names are not entries")
            self.assertGreaterEqual(row["repos_present"], 5)
            self.assertLess(row["repos_present"], 10)

    def test_reserved_names_are_neither_entries_nor_aliases(self):
        catalog, _ = sp.load_vocabulary(self.path)
        for reserved in sp.RESERVED_GROUP_NAMES:
            self.assertNotIn(reserved, catalog["names"])
            self.assertIsNone(sp.canonicalize(reserved, catalog), reserved)

    def test_no_alias_or_hint_names_a_layer(self):
        # A capability alias that is also a LAYER alias (`gateways`,
        # `providers`) would fold a role name into a capability; a hint on a
        # ubiquitous directory (`**/hooks/**`, `**/config/**`) claims files
        # that belong to a layer or to Commons.
        catalog, _ = sp.load_vocabulary(self.path)
        layers, _ = sp.load_layers(LAYERS)
        for name, entry in catalog["entries"].items():
            for alias in entry.get("aliases") or []:
                # `API` and `UI` are deliberately both (R1 capability, panel
                # layer); their aliases may fold to the same name.
                self.assertIn(sp.canonicalize(alias, layers), (None, name),
                              "%s: alias %r is a layer alias" % (name, alias))
        hints = {g for hs in catalog["hints"].values() for g in hs}
        for ubiquitous in ("**/hooks/**", "**/gateways/**", "**/config/**", "**/public/**",
                           "**/home/**", "**/setup/**", "**/images/**", "**/files/**",
                           "**/pages/**", "**/channels/**"):
            self.assertNotIn(ubiquitous, hints)

    def test_no_shipped_hint_is_a_glob_the_compiler_refuses(self):
        # #1501: a hint the compiler cannot translate would be handed to the
        # setup agent as a suggestion that can only ever match nothing.
        catalog, _ = sp.load_vocabulary(self.path)
        for name, globs in catalog["hints"].items():
            for glob in globs:
                with self.subTest(entry=name, glob=glob):
                    self.assertIsNone(groups_schema.glob_defect(glob))

"""Groups.yml format-reconciliation tests."""
import os
import tempfile
import textwrap
import unittest

from discovery_test_helpers import orchestrator, setup_flow


class TestGroupsFormatReconciliation(unittest.TestCase):
    """Task 5: groups.yml mapping form is canonical; load_catalog reads a
    legacy list form (with a one-time notice) so old seeded files still
    load instead of silently collapsing to {} on raw.items()."""

    def _repo(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        return d

    def test_seed_writes_mapping_form_that_load_catalog_reads(self):
        # _seed_groups_manifest lives in setup_flow.py (orchestrator only ever
        # re-exported it); load_catalog is the discovery primitive this test
        # actually guards.
        d = self._repo()
        for sub in ("src", "tests"):
            os.makedirs(os.path.join(d, sub))
            with open(os.path.join(d, sub, "a.py"), "w", encoding="utf-8") as fh:
                pass
        path, created, names = setup_flow._seed_groups_manifest(d)
        self.assertTrue(created)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("- name:", text)          # not the legacy list form
        catalog = orchestrator.load_catalog(d)
        self.assertTrue(catalog)                    # actually loads (was silent {})
        self.assertEqual(catalog["src"]["match"], ["src/**"])

    def test_load_catalog_normalizes_legacy_list_form(self):
        d = self._repo()
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write(textwrap.dedent("""\
                groups:
                  - name: src
                    match:
                      - src/**
            """))
        catalog = orchestrator.load_catalog(d)
        self.assertIn("src", catalog)
        self.assertEqual(catalog["src"]["match"], ["src/**"])

    def test_assignment_identical_across_forms(self):
        files = ["src/a.py", "tests/b.py", "docs/c.md"]
        mapping = {"src": {"match": ["src/**"]}, "tests": {"match": ["tests/**"]}}
        assigned, leftovers = orchestrator.assign_by_catalog(files, mapping)
        self.assertEqual(assigned, {"src": ["src/a.py"], "tests": ["tests/b.py"]})
        self.assertEqual(leftovers, ["docs/c.md"])

    def test_tests_globs_claim_files_into_their_group(self):
        catalog = {"Auth": {"match": ["src/auth/**"], "tests": ["tests/auth/**"]}}
        assigned, leftovers = orchestrator.assign_by_catalog(
            ["src/auth/login.py", "tests/auth/test_login.py", "misc/x.py"], catalog)
        self.assertIn("src/auth/login.py", assigned["Auth"])
        self.assertIn("tests/auth/test_login.py", assigned["Auth"])   # was a leftover before
        self.assertEqual(leftovers, ["misc/x.py"])

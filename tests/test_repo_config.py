"""#1681 Plan 1: the one resolver/reader for the root config file."""
import os
import tempfile
import unittest

import scripts.repo_config as rc


def _write(root, name, text):
    path = os.path.join(root, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


GOOD = "version: 1\ngroups:\n  App:\n    match: ['src/**']\n"


class TestResolve(unittest.TestCase):
    def test_no_config_resolves_none_with_no_disclosure(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(rc.resolve(d), rc.Resolution(None, []))

    def test_undotted_alone(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "panopticon.yml", GOOD)
            self.assertEqual(rc.resolve(d), rc.Resolution(p, []))

    def test_dotted_alone_is_the_read_only_alias(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, ".panopticon.yml", GOOD)
            self.assertEqual(rc.resolve(d), rc.Resolution(p, []))

    def test_both_present_undotted_wins_and_is_disclosed(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "panopticon.yml", GOOD)
            _write(d, ".panopticon.yml", GOOD)
            res = rc.resolve(d)
            self.assertEqual(res.path, p)
            self.assertEqual(len(res.disclosures), 1)
            self.assertIn("both `panopticon.yml` and `.panopticon.yml` present", res.disclosures[0])

    def test_symlink_at_either_name_is_refused_not_followed(self):
        with tempfile.TemporaryDirectory() as d:
            real = _write(d, "elsewhere.yml", GOOD)
            os.symlink(real, os.path.join(d, "panopticon.yml"))
            res = rc.resolve(d)
            self.assertIsNone(res.path)
            self.assertIn("symlink", res.disclosures[0])
            os.unlink(os.path.join(d, "panopticon.yml"))
            os.symlink(real, os.path.join(d, ".panopticon.yml"))
            self.assertIsNone(rc.resolve(d).path)

    def test_a_directory_at_the_name_is_not_a_config(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "panopticon.yml"))
            self.assertIsNone(rc.resolve(d).path)


class TestReadDocument(unittest.TestCase):
    def test_good_document(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "panopticon.yml", GOOD)
            doc = rc.read_document(d)
            self.assertEqual(doc.errors, [])
            self.assertEqual(doc.doc["groups"]["App"]["match"], ["src/**"])

    def test_no_config_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            doc = rc.read_document(d)
            self.assertIsNone(doc.doc)
            self.assertEqual(doc.errors, [])

    def test_missing_version_is_authored_but_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "panopticon.yml", "groups:\n  App:\n    match: ['src/**']\n")
            doc = rc.read_document(d)
            self.assertIsNone(doc.doc)
            self.assertIn("version: 1", doc.errors[0])

    def test_wrong_version_is_authored_but_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "panopticon.yml", "version: 2\ngroups: {}\n")
            self.assertIsNone(rc.read_document(d).doc)

    def test_non_mapping_is_authored_but_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "panopticon.yml", "- a\n- b\n")
            doc = rc.read_document(d)
            self.assertIsNone(doc.doc)
            self.assertIn("mapping", doc.errors[0])

    def test_unreadable_yaml_is_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "panopticon.yml", "version: 1\ngroups: [\n")
            self.assertTrue(rc.read_document(d).errors)

    def test_over_cap_is_refused_before_parse(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "panopticon.yml", GOOD + "#" * rc.MAX_CONFIG_BYTES)
            doc = rc.read_document(d)
            self.assertIsNone(doc.doc)
            self.assertIn("1048576", doc.errors[0])

    def test_unknown_top_level_keys_are_disclosed_and_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "panopticon.yml", GOOD + "colour: blue\n")
            doc = rc.read_document(d)
            self.assertEqual(doc.errors, [])
            self.assertNotIn("colour", doc.doc)
            self.assertIn("colour", doc.disclosures[0])

    def test_legacy_file_with_no_root_config_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            _write(d, rc.LEGACY_GROUPS_PATH, "groups: {}\n")
            doc = rc.read_document(d)
            self.assertIsNone(doc.doc)
            self.assertEqual(doc.errors, [rc.legacy_message(d)])
            self.assertIn("migrate-config", doc.errors[0])
            self.assertTrue(rc.legacy_present(d))

    def test_legacy_file_beside_a_root_config_is_ignored_with_a_disclosure(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            _write(d, rc.LEGACY_GROUPS_PATH, "groups: {}\n")
            _write(d, "panopticon.yml", GOOD)
            doc = rc.read_document(d)
            self.assertEqual(doc.errors, [])
            self.assertTrue(any("no longer read" in s for s in doc.disclosures))

    def test_stale_config_json_is_disclosed(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(rc.stale_config_json(d))
            os.makedirs(os.path.join(d, ".panopticon"))
            _write(d, rc.LEGACY_CONFIG_JSON, "{}")
            self.assertIn("config.json", rc.stale_config_json(d))

    def test_draft_path_is_at_the_root(self):
        self.assertEqual(rc.draft_path("/r"), "/r/panopticon.yml.draft")

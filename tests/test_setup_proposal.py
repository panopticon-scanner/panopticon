import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skill", "scripts"))
import setup_proposal as sp

DATA = os.path.join(os.path.dirname(__file__), "..", "skill", "data")
VOCAB = os.path.join(DATA, "capability_vocabulary.yml")
AFFINITY = os.path.join(DATA, "capability_affinity.yml")


class TestLoaders(unittest.TestCase):
    def test_vocabulary_loads_fixture(self):
        vocab, errors = sp.load_vocabulary(VOCAB)
        self.assertEqual(errors, [])
        self.assertIn("Checkout", vocab["names"])
        self.assertIn("**/checkout/**", vocab["hints"]["Checkout"])

    def test_affinity_loads_fixture_and_validates_domains(self):
        vocab, _ = sp.load_vocabulary(VOCAB)
        affinity, errors = sp.load_affinity(AFFINITY, vocab)
        self.assertEqual(errors, [])
        self.assertEqual(affinity["Checkout"], ["SEC", "DAT", "ACC", "OPS"])
        # every fixture affinity key is a known vocabulary capability
        self.assertTrue(set(affinity).issubset(set(vocab["names"])))

    def test_vocabulary_flags_duplicate_and_empty_names(self):
        import tempfile
        doc = "capabilities:\n  - name: A\n  - name: A\n  - hints: [x]\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        _v, errors = sp.load_vocabulary(p)
        os.unlink(p)
        self.assertTrue(any("duplicate" in e for e in errors))
        self.assertTrue(any("name" in e for e in errors))

    def test_affinity_flags_unknown_domain_and_capability(self):
        import tempfile
        vocab = {"names": ["Auth"], "hints": {"Auth": []}}
        doc = "affinity:\n  Auth: [SEC, ZZZ]\n  Ghost: [SEC]\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        _a, errors = sp.load_affinity(p, vocab)
        os.unlink(p)
        self.assertTrue(any("ZZZ" in e and "domain" in e for e in errors))
        self.assertTrue(any("Ghost" in e and "capability" in e for e in errors))

    # Regression tests for robustness guards

    def test_vocabulary_scalar_hints_produces_error_no_char_explosion(self):
        import tempfile
        doc = 'capabilities:\n  - name: Auth\n    hints: "**/auth/**"\n'
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        vocab, errors = sp.load_vocabulary(p)
        os.unlink(p)
        # Must have error about hints needing to be list
        self.assertTrue(any("hints must be a list" in e for e in errors))
        # Must NOT have char-exploded hints (no single-char entries)
        self.assertEqual(vocab["hints"]["Auth"], [])

    def test_vocabulary_bare_string_entry_produces_error_no_crash(self):
        import tempfile
        doc = "capabilities:\n  - Auth\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        vocab, errors = sp.load_vocabulary(p)
        os.unlink(p)
        # Must have error about capability entry being a mapping
        self.assertTrue(any("must be a mapping" in e for e in errors))
        # No capability should be added
        self.assertEqual(vocab["names"], [])

    def test_vocabulary_non_mapping_doc_produces_error(self):
        import tempfile
        doc = "capabilities"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        vocab, errors = sp.load_vocabulary(p)
        os.unlink(p)
        self.assertTrue(any("root must be a mapping" in e for e in errors))
        self.assertEqual(vocab["names"], [])

    def test_vocabulary_non_list_capabilities_produces_error(self):
        import tempfile
        doc = "capabilities: {Auth: {hints: []}}\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        vocab, errors = sp.load_vocabulary(p)
        os.unlink(p)
        self.assertTrue(any("capabilities must be a list" in e for e in errors))
        self.assertEqual(vocab["names"], [])

    def test_affinity_scalar_domains_produces_error_no_char_explosion(self):
        import tempfile
        vocab = {"names": ["Auth"], "hints": {"Auth": []}}
        doc = "affinity:\n  Auth: SEC\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        affinity, errors = sp.load_affinity(p, vocab)
        os.unlink(p)
        # Must have error about domains needing to be list
        self.assertTrue(any("domains must be a list" in e for e in errors))
        # Must NOT have char-exploded domains (no single-char entries like 'S', 'E', 'C')
        self.assertEqual(affinity.get("Auth"), [])

    def test_affinity_non_mapping_doc_produces_error(self):
        import tempfile
        vocab = {"names": ["Auth"], "hints": {"Auth": []}}
        doc = "affinity"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        affinity, errors = sp.load_affinity(p, vocab)
        os.unlink(p)
        self.assertTrue(any("root must be a mapping" in e for e in errors))
        self.assertEqual(affinity, {})

    def test_affinity_non_mapping_affinity_block_produces_error(self):
        import tempfile
        vocab = {"names": ["Auth"], "hints": {"Auth": []}}
        doc = "affinity: [SEC]\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        affinity, errors = sp.load_affinity(p, vocab)
        os.unlink(p)
        self.assertTrue(any("affinity must be a mapping" in e for e in errors))
        self.assertEqual(affinity, {})

    def test_affinity_unknown_capability_excluded_from_result(self):
        import tempfile
        vocab = {"names": ["Auth"], "hints": {"Auth": []}}
        doc = "affinity:\n  Auth: [SEC]\n  Ghost: [SEC]\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        affinity, errors = sp.load_affinity(p, vocab)
        os.unlink(p)
        # Ghost should not be in returned affinity dict
        self.assertNotIn("Ghost", affinity)
        self.assertIn("Auth", affinity)
        self.assertTrue(any("Ghost" in e for e in errors))


if __name__ == "__main__":
    unittest.main()

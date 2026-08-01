import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
import scripts.tools.eslint_security as es
from scripts.tools import ADAPTERS


class TestEslintSecurityAdapter(unittest.TestCase):
    def test_adapter_metadata(self):
        adapter = es.EslintSecurityAdapter()
        self.assertEqual(adapter.name, "eslint-security")
        self.assertEqual(adapter.prefix, "ESS")

    def test_prefix_does_not_collide_with_legacy_eslint(self):
        # Legacy eslint SARIF adapter uses the "ES" prefix; eslint-security must
        # use a distinct prefix to avoid finding-ID collisions.
        self.assertNotEqual(es.EslintSecurityAdapter().prefix, "ES")

    def test_is_applicable_is_false_placeholder(self):
        self.assertFalse(es.EslintSecurityAdapter().is_applicable("."))

    def test_invoke_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            es.EslintSecurityAdapter().invoke(".")

    def test_parse_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            es.EslintSecurityAdapter().parse(b"{}", "g1")

    def test_registry_contains_adapter(self):
        self.assertIn("eslint-security", ADAPTERS)
        self.assertIsInstance(ADAPTERS["eslint-security"], es.EslintSecurityAdapter)


if __name__ == "__main__":
    unittest.main()

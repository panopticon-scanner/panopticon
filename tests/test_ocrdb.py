import json
import os
import tempfile
import unittest

import scripts.ocrdb as ocrdb


class TestOcrdb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = ocrdb.load_bundle()   # the vendored 0.3.1 file

    def test_vendored_bundle_loads_with_ten_domains(self):
        self.assertIsNotNone(self.bundle, "vendored ocrdb-0.3.1.json must load")
        self.assertEqual(self.bundle["version"], "0.3.1")
        self.assertEqual(len(self.bundle["domains"]), 10)

    def test_domain_menu_returns_sorted_entries(self):
        menu = ocrdb.domain_menu(self.bundle, "SEC")
        self.assertTrue(menu)
        codes = [m["code"] for m in menu]
        self.assertEqual(codes, sorted(codes))
        first = menu[0]
        self.assertEqual(set(first), {"code", "name", "severity", "cwe"})
        self.assertTrue(first["code"].startswith("SEC-"))

    def test_domain_menu_unknown_domain_is_empty(self):
        self.assertEqual(ocrdb.domain_menu(self.bundle, "ZZZ"), [])
        self.assertEqual(ocrdb.domain_menu(None, "SEC"), [])

    def test_validate_code(self):
        real = ocrdb.domain_menu(self.bundle, "SEC")[0]["code"]
        self.assertTrue(ocrdb.validate_code(self.bundle, real))
        self.assertFalse(ocrdb.validate_code(self.bundle, "SEC-ZZZ"))
        self.assertFalse(ocrdb.validate_code(self.bundle, "garbage"))
        self.assertFalse(ocrdb.validate_code(self.bundle, ""))

    def test_domain_of_and_fallback(self):
        self.assertEqual(ocrdb.domain_of("SEC-A1A"), "SEC")
        self.assertIsNone(ocrdb.domain_of("garbage"))
        self.assertEqual(ocrdb.domain_fallback("SEC"), "SEC-X0X")

    def test_domain_to_panel_covers_ten_domains(self):
        self.assertEqual(set(ocrdb.DOMAIN_TO_PANEL), set(self.bundle["domains"]))

    def test_absent_bundle_returns_none(self):
        self.assertIsNone(ocrdb.load_bundle("/no/such/ocrdb.json"))

    def test_corrupt_bundle_raises(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.json")
            with open(p, "w") as fh:
                fh.write("{ not json")
            with self.assertRaises(ValueError):
                ocrdb.load_bundle(p)

    def test_malformed_bundle_missing_domains_raises(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "nodomains.json")
            with open(p, "w") as fh:
                json.dump({"version": "0.3.1"}, fh)
            with self.assertRaises(ValueError):
                ocrdb.load_bundle(p)


if __name__ == "__main__":
    unittest.main()

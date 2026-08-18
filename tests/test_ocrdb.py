"""Tests for OCRDb domain catalog loading, validation, and domain-to-panel mapping."""
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
        # every bundle domain maps to a panel; "ZZZ" is the #1034 domainless
        # sentinel (UNKNOWN_DOMAIN_FALLBACK), not a real bundle domain.
        self.assertEqual(set(ocrdb.DOMAIN_TO_PANEL) - {"ZZZ"},
                         set(self.bundle["domains"]))
        expected_mappings = {
            "SEC": "security",
            "COD": "code",
            "ARC": "architecture",
            "TST": "test",
            "DAT": "database",
            "QAL": "code",
            "AGT": "code",
            "OPS": "code",
            "ACC": "code",
            "LNG": "code",
            "ZZZ": "code",
        }
        for domain, panel in expected_mappings.items():
            self.assertEqual(ocrdb.DOMAIN_TO_PANEL.get(domain), panel, f"Domain {domain} mismatch")
        self.assertEqual(ocrdb.domain_of(ocrdb.UNKNOWN_DOMAIN_FALLBACK), "ZZZ")

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


class TestDomainMenuSeverity(unittest.TestCase):
    """#1034: domain_menu flags an assumed severity rather than silently
    fabricating 'MEDIUM' for a bundle entry that omits default_severity."""

    def test_menu_flags_assumed_severity(self):
        bundle = {"domains": {"XXX": {"entries": {
            "XXX-A1A": {"name": "no-sev"},                       # no default_severity
            "XXX-A1B": {"name": "has-sev", "default_severity": "HIGH"}}}}}
        menu = {e["code"]: e for e in ocrdb.domain_menu(bundle, "XXX")}
        self.assertEqual(menu["XXX-A1A"]["severity"], "MEDIUM")
        self.assertTrue(menu["XXX-A1A"]["severity_assumed"])
        self.assertEqual(menu["XXX-A1B"]["severity"], "HIGH")
        self.assertNotIn("severity_assumed", menu["XXX-A1B"])   # real severity
        # default_severity() stays None for the absent case (the two agree)
        self.assertIsNone(ocrdb.default_severity(bundle, "XXX-A1A"))

    def test_real_bundle_menu_has_no_assumed_severities(self):
        # every pinned-bundle entry carries a real severity -> no marker today
        b = ocrdb.load_bundle()
        for dom in b["domains"]:
            for entry in ocrdb.domain_menu(b, dom):
                self.assertNotIn("severity_assumed", entry, entry["code"])


class TestDomainCriteria(unittest.TestCase):
    """#1035: domain_criteria returns only the codes that carry criteria text."""

    def test_real_bundle_has_criteria_across_domains(self):
        b = ocrdb.load_bundle()
        total = sum(len(ocrdb.domain_criteria(b, d)) for d in b["domains"])
        self.assertGreater(total, 100)   # 114 in 0.3.1, every domain represented
        for d in b["domains"]:
            for c in ocrdb.domain_criteria(b, d):
                self.assertEqual(set(c), {"code", "name", "criteria"})
                self.assertTrue(c["criteria"])
                self.assertTrue(c["code"].startswith(d + "-"))

    def test_gated_on_presence(self):
        bundle = {"domains": {"XXX": {"entries": {
            "XXX-A1A": {"name": "has", "criteria": "must X"},
            "XXX-A1B": {"name": "none"}}}}}
        crit = ocrdb.domain_criteria(bundle, "XXX")
        self.assertEqual([c["code"] for c in crit], ["XXX-A1A"])   # A1B omitted

    def test_empty_on_bad_or_criteria_less(self):
        self.assertEqual(ocrdb.domain_criteria(None, "SEC"), [])
        self.assertEqual(ocrdb.domain_criteria({}, "SEC"), [])
        self.assertEqual(ocrdb.domain_criteria(ocrdb.load_bundle(), "ZZZ"), [])


if __name__ == "__main__":
    unittest.main()

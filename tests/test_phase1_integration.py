import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill", "scripts"))
import ingest_tools as it
from tools import ADAPTERS


class TestPhase1Integration(unittest.TestCase):
    def test_pip_audit_finds_requests_cve(self):
        target = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable-python")
        adapter = ADAPTERS["pip-audit"]
        if not adapter.is_applicable(target):
            self.skipTest("pip-audit not applicable to fixture")
        try:
            raw, rc = adapter.invoke(target)
        except FileNotFoundError:
            self.skipTest("pip-audit not installed")
        if rc not in (0, 1):
            self.skipTest(f"pip-audit failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(any("CVE-" in str(f.get("citations")) for f in findings),
                        f"expected CVE citation, got {findings}")

    def test_npm_audit_finds_lodash_vulnerability(self):
        target = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable-node")
        adapter = ADAPTERS["npm-audit"]
        if not adapter.is_applicable(target):
            self.skipTest("npm-audit not applicable to fixture")
        try:
            raw, rc = adapter.invoke(target)
        except FileNotFoundError:
            self.skipTest("npm not installed")
        if rc not in (0, 1):
            self.skipTest(f"npm audit failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected npm-audit findings for lodash")
        self.assertTrue(all(f.get("source") == "tool:npm-audit" for f in findings))

    def test_osv_scanner_parses_raw_output(self):
        adapter = ADAPTERS["osv-scanner"]
        raw = json.dumps({
            "results": [
                {
                    "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-35jh-r3h4-6jhm",
                            "aliases": ["CVE-2021-23337"],
                            "severity": "HIGH",
                            "summary": "Command Injection in lodash",
                        }
                    ],
                }
            ]
        }).encode()
        findings = adapter.parse(raw, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source"], "tool:osv-scanner")
        self.assertEqual(findings[0]["citations"]["cve"], ["CVE-2021-23337"])

    def test_ingest_dir_routes_osv_scanner_output(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "osv-scanner.json"), "wb") as fh:
                fh.write(json.dumps({"results": []}).encode())
            findings = it.ingest_dir(d, "g1")
            self.assertEqual(findings, [])

    def test_eslint_security_finds_eval(self):
        target = os.path.join(os.path.dirname(__file__), "fixtures", "insecure-js")
        adapter = ADAPTERS["eslint-security"]
        if not adapter.is_applicable(target):
            self.skipTest("eslint-security not applicable to fixture")
        try:
            raw, rc = adapter.invoke(target)
        except FileNotFoundError:
            self.skipTest("eslint not installed")
        if rc not in (0, 1):
            self.skipTest(f"eslint failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected eslint-security findings for eval usage")
        self.assertTrue(all(f.get("source") == "tool:eslint-security" for f in findings))

    def test_ingest_dir_routes_adapter_output(self):
        target = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable-python")
        adapter = ADAPTERS["pip-audit"]
        try:
            raw, _ = adapter.invoke(target)
        except FileNotFoundError:
            self.skipTest("pip-audit not installed")
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pip-audit.json"), "wb") as fh:
                fh.write(raw)
            findings = it.ingest_dir(d, "g1")
            self.assertTrue(findings)
            self.assertTrue(all(f.get("source") == "tool:pip-audit" for f in findings))


if __name__ == "__main__":
    unittest.main()

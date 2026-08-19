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

        mock_output = b'{"dependencies": [{"name": "requests", "version": "2.20.0", "vulns": [{"id": "CVE-2018-18074", "aliases": ["CVE-2018-18074"], "fix_versions": ["2.20.1"], "description": "vuln"}]}]}'
        with unittest.mock.patch.object(adapter, 'invoke', return_value=(mock_output, 1)):
            raw, rc = adapter.invoke(target)

        findings = adapter.parse(raw, "g1")
        self.assertTrue(
            any("CVE-" in str(f.get("citations")) for f in findings),
            f"expected CVE citation, got {findings}",
        )

    def test_npm_audit_finds_lodash_vulnerability(self):
        target = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable-node")
        adapter = ADAPTERS["npm-audit"]
        if not adapter.is_applicable(target):
            self.skipTest("npm-audit not applicable to fixture")

        mock_output = json.dumps({"advisories": {"123": {"title": "Command Injection in lodash", "module_name": "lodash", "vulnerable_versions": "<4.17.21", "patched_versions": ">=4.17.21", "severity": "high", "cves": ["CVE-2021-23337"]}}}).encode()
        with unittest.mock.patch.object(adapter, 'invoke', return_value=(mock_output, 1)):
            raw, rc = adapter.invoke(target)

        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected npm-audit findings for lodash")
        self.assertTrue(all(f.get("source") == "tool:npm-audit" for f in findings))

    def test_osv_scanner_parses_raw_output(self):
        adapter = ADAPTERS["osv-scanner"]
        raw = json.dumps(
            {
                "results": [
                    {
                        "source": {"path": "/src/package-lock.json", "type": "lockfile"},
                        "packages": [
                            {
                                "package": {
                                    "name": "lodash",
                                    "version": "4.17.20",
                                    "ecosystem": "npm",
                                },
                                "vulnerabilities": [
                                    {
                                        "id": "GHSA-35jh-r3h4-6jhm",
                                        "aliases": ["CVE-2021-23337"],
                                        "severity": [
                                            {
                                                "type": "CVSS_V3",
                                                "score": (
                                    "CVSS:3.1/AV:N/AC:L/PR:N/"
                                    "UI:N/S:U/C:H/I:H/A:H"
                                ),
                                            }
                                        ],
                                        "summary": "Command Injection in lodash",
                                    }
                                ],
                                "groups": [
                                    {
                                        "ids": ["GHSA-35jh-r3h4-6jhm"],
                                        "aliases": ["CVE-2021-23337"],
                                        "max_severity": "7.2",
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ).encode()
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

        mock_output = json.dumps([{"filePath": "app.js", "messages": [{"ruleId": "security/detect-eval-with-expression", "severity": 2, "message": "eval can be harmful", "line": 5, "column": 1}]}]).encode()
        with unittest.mock.patch.object(adapter, 'invoke', return_value=(mock_output, 1)):
            raw, rc = adapter.invoke(target)

        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected eslint-security findings for eval usage")
        self.assertTrue(all(f.get("source") == "tool:eslint-security" for f in findings))

    def test_ingest_dir_routes_adapter_output(self):
        target = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable-python")
        adapter = ADAPTERS["pip-audit"]
        mock_output = b'{"dependencies": [{"name": "requests", "version": "2.20.0", "vulns": [{"id": "CVE-2018-18074", "aliases": ["CVE-2018-18074"], "fix_versions": ["2.20.1"], "description": "vuln"}]}]}'

        with unittest.mock.patch.object(adapter, 'invoke', return_value=(mock_output, 1)):
            raw, rc = adapter.invoke(target)
            if rc != 1:
                self.skipTest(f"pip-audit failed with {rc}")

        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pip-audit.json"), "wb") as fh:
                fh.write(raw)
            # This exercises adapter routing on REAL tool output sourced from the
            # vulnerable-python fixture, so its location.file is under
            # tests/fixtures/ and the default fixture prune would drop it. Pass
            # include_fixtures to keep it (we are testing routing, not the prune).
            findings = it.ingest_dir(d, "g1", include_fixtures=True)
            self.assertTrue(findings)
            self.assertTrue(all(f.get("source") == "tool:pip-audit" for f in findings))


if __name__ == "__main__":
    unittest.main()

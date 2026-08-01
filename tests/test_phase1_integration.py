import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
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
            self.assertTrue(all(f.get("source") == "tool:pip-audit" for f in findings))


if __name__ == "__main__":
    unittest.main()

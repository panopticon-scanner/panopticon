import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
import scripts.tools.cargo_audit as ca

CARGO_AUDIT_SAMPLE = json.dumps({
    "vulnerabilities": {
        "list": [
            {
                "advisory": {
                    "id": "RUSTSEC-2021-0073",
                    "title": "Double-free in Foo crate",
                    "cvss": None,
                    "url": "https://rustsec.org/advisories/RUSTSEC-2021-0073",
                },
                "package": {"name": "foo", "version": "1.2.3"},
                "versions": {"patched": ["1.2.4"]},
            }
        ]
    }
}).encode()


class TestCargoAuditAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        findings = ca.CargoAuditAdapter().parse(CARGO_AUDIT_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:cargo-audit")
        self.assertEqual(f["tool_evidence"]["package_name"], "foo")

    def test_is_applicable_when_cargo_toml_present(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("Cargo.toml")):
            self.assertTrue(ca.CargoAuditAdapter().is_applicable("/tmp/fake"))

    def test_invoke_runs_cargo_audit(self):
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"", returncode=0))
        with mock.patch("scripts.tools.cargo_audit.subprocess.run", fake_run):
            stdout, rc = ca.CargoAuditAdapter().invoke("/tmp/fake")
        self.assertEqual(rc, 0)
        fake_run.assert_called_once_with(
            ["cargo", "audit", "--format", "json"],
            capture_output=True, timeout=300, cwd="/tmp/fake",
        )

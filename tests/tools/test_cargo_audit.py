import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "skill"))
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

    def test_parse_includes_provenance(self):
        findings = ca.CargoAuditAdapter().parse(CARGO_AUDIT_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["provenance"]["discovered_by"], "tool:cargo-audit")
        self.assertEqual(findings[0]["provenance"]["confirmation_status"], "TOOL")

    def test_invoke_runs_cargo_audit(self):
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"", returncode=0))
        with mock.patch("scripts.tools.base.subprocess.run", fake_run):
            stdout, rc = ca.CargoAuditAdapter().invoke("/tmp/fake")
        self.assertEqual(rc, 0)
        fake_run.assert_called_once_with(
            ["cargo", "audit", "--no-fetch", "--format", "json"],
            capture_output=True, timeout=300, cwd="/tmp/fake",
        )

    def test_cvss_v3_score_scope_unchanged_known_vector(self):
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H - a textbook "network, no auth,
        # full CIA impact" vector. Hand-computed via the CVSS v3.1 base-score
        # formula; NVD's own calculator rounds this to 9.8 (this function
        # does not implement the official round-up step - see plan Q4).
        score = ca._cvss_v3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertAlmostEqual(score, 9.760161495, places=6)

    def test_cvss_v3_score_scope_changed_caps_at_ten(self):
        # AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H - the Log4Shell (CVE-2021-44228)
        # vector, whose published NVD base score is 10.0. Exercises the S:C
        # scope-changed branch (the 1.08 multiplier).
        score = ca._cvss_v3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        self.assertEqual(score, 10.0)

    def test_cvss_v3_score_scope_unchanged_medium_vector(self):
        # A lower-impact vector to confirm the function isn't just always
        # landing near the ceiling.
        score = ca._cvss_v3_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N")
        self.assertAlmostEqual(score, 4.24765473, places=6)

    def test_cvss_v3_score_malformed_vector_returns_none(self):
        self.assertIsNone(ca._cvss_v3_score("garbage"))

    def test_cvss_v3_score_exception_path_returns_none(self):
        # A stray extra colon makes dict(p.split(":") for p in ...) raise
        # ValueError (a 3-element split where a 2-tuple is required); the
        # bare `except Exception: return None` must swallow it, not raise.
        score = ca._cvss_v3_score("CVSS:3.1/AV:N/AC:N:X/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertIsNone(score)

    def test_parse_string_cvss_field_produces_critical_severity(self):
        # Exercises the isinstance(cvss, str) branch in parse() end-to-end,
        # confirming a real string-form CVSS vector reaches the right bucket.
        sample = json.dumps({
            "vulnerabilities": {"list": [{
                "advisory": {
                    "id": "RUSTSEC-2021-0072",
                    "title": "RCE in bar crate",
                    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "url": "https://rustsec.org/advisories/RUSTSEC-2021-0072",
                },
                "package": {"name": "bar", "version": "0.1.0"},
                "versions": {"patched": ["0.1.1"]},
            }]}
        }).encode()
        findings = ca.CargoAuditAdapter().parse(sample, "g1")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

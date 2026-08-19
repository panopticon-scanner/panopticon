import json
import unittest
from unittest import mock

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
        self.assertEqual(f["severity"], "HIGH")

    def test_is_applicable_when_cargo_toml_present(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("Cargo.toml")):
            self.assertTrue(ca.CargoAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_when_cargo_toml_absent(self):
        with mock.patch("os.path.exists", return_value=False):
            self.assertFalse(ca.CargoAuditAdapter().is_applicable("/tmp/fake"))

    def test_parse_includes_provenance(self):
        findings = ca.CargoAuditAdapter().parse(CARGO_AUDIT_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["provenance"]["discovered_by"], "tool:cargo-audit")
        self.assertEqual(findings[0]["provenance"]["confirmation_status"], "TOOL")

    def test_parse_empty_findings(self):
        findings = ca.CargoAuditAdapter().parse(b"{}", "g1")
        self.assertEqual(findings, [])
        findings = ca.CargoAuditAdapter().parse(b'{"vulnerabilities": {"list": []}}', "g1")
        self.assertEqual(findings, [])

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
        # full CIA impact" vector. NVD's published base score is 9.8; the
        # v3.1 Roundup step (#475) is what lifts the raw 9.7601... to it.
        score = ca._cvss_v3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(score, 9.8)

    def test_cvss_v3_score_rounds_up_low_vector(self):
        # A low-severity vector exercising Roundup away from the ceiling cap.
        score = ca._cvss_v3_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
        self.assertEqual(score, 1.8)

    def test_cvss_v3_score_scope_changed_caps_at_ten(self):
        # AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H - the Log4Shell (CVE-2021-44228)
        # vector, whose published NVD base score is 10.0. Exercises the S:C
        # scope-changed branch (the 1.08 multiplier).
        score = ca._cvss_v3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        self.assertEqual(score, 10.0)

    def test_cvss_v3_score_scope_unchanged_medium_vector(self):
        # A lower-impact vector -- and the ceiling-vs-nearest proof: the raw
        # score is 4.2477, which round-NEAREST would land on 4.2; the v3.1
        # Roundup (ceiling to one decimal, #475) gives 4.3, matching NVD.
        score = ca._cvss_v3_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N")
        self.assertEqual(score, 4.3)

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


if __name__ == "__main__":
    unittest.main()


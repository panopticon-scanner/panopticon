import json
import os
import unittest
from unittest import mock

from _test_helpers import FakePopen, first
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
        self.assertEqual(f["severity"], "LOW")

    def test_parse_missing_cvss_defaults_to_low(self):
        # #run7 review: an unscored (no-CVSS) cargo advisory floors at LOW, not
        # INFO -- a real vuln stays a visible finding the agent can downgrade,
        # not dismissed noise. (Both are gate-weight 0; this is about honesty.)
        sample = json.dumps({
            "vulnerabilities": {"list": [{
                "advisory": {
                    "id": "RUSTSEC-2021-0099",
                    "title": "Unspecified issue in norcvss crate",
                    "cvss": None,
                    "url": "https://rustsec.org/advisories/RUSTSEC-2021-0099",
                },
                "package": {"name": "norcvss", "version": "0.9.0"},
                "versions": {"patched": ["0.9.1"]},
            }]}
        }).encode()
        findings = ca.CargoAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "LOW")

    def test_is_applicable_when_cargo_lock_present(self):
        # #run7 COD-C2A: applicability keys on Cargo.lock (what `cargo audit
        # --no-fetch` actually reads), not Cargo.toml.
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("Cargo.lock")):
            self.assertTrue(ca.CargoAuditAdapter().is_applicable("/tmp/fake"))

    def test_not_applicable_with_only_cargo_toml(self):
        # a Cargo.toml-only (library) repo has no lockfile -> not applicable
        # (osv-scanner still covers it); avoids a "selected but unproduced" gap.
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("Cargo.toml")):
            self.assertFalse(ca.CargoAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_when_cargo_toml_absent(self):
        with mock.patch("os.path.exists", return_value=False):
            self.assertFalse(ca.CargoAuditAdapter().is_applicable("/tmp/fake"))

    def test_parse_includes_provenance(self):
        findings = ca.CargoAuditAdapter().parse(CARGO_AUDIT_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(first(findings)["provenance"]["discovered_by"], "tool:cargo-audit")
        self.assertEqual(first(findings)["provenance"]["confirmation_status"], "TOOL")

    def test_parse_empty_findings(self):
        findings = ca.CargoAuditAdapter().parse(b"{}", "g1")
        self.assertEqual(findings, [])
        findings = ca.CargoAuditAdapter().parse(b'{"vulnerabilities": {"list": []}}', "g1")
        self.assertEqual(findings, [])

    def test_invoke_runs_cargo_audit_binary_directly(self):
        # #1742 (SEC-E3A): `cargo audit` goes through cargo's DISPATCHER,
        # which honours the target's own `.cargo/config.toml` [alias] table
        # -- a target can alias `audit` to `cargo run` and get its own code
        # (build.rs included) executed inside the scanner. The fix invokes
        # the external subcommand BINARY directly, so cargo's alias/config
        # resolution is never consulted, and names the lockfile explicitly.
        fake_run = FakePopen(stdout=b"", stderr=b"", returncode=0)
        seen_cwd = {}

        def record_and_return(cmd, **kwargs):
            seen_cwd["cwd"] = kwargs.get("cwd")
            # The scratch cwd must exist WHILE the tool is invoked.
            seen_cwd["existed_during_call"] = (
                kwargs.get("cwd") is not None and os.path.isdir(kwargs["cwd"])
            )
            return fake_run

        with mock.patch("scripts.tools.base.subprocess.Popen",
                        side_effect=record_and_return) as popen_mock:
            stdout, rc = ca.CargoAuditAdapter().invoke("/tmp/fake")
        self.assertEqual(rc, 0)
        popen_mock.assert_called_once()
        called_args, called_kwargs = popen_mock.call_args
        cmd = called_args[0]
        self.assertEqual(cmd[0], "cargo-audit")
        self.assertEqual(cmd[1], "audit")
        self.assertIn("--file", cmd)
        lockfile = cmd[cmd.index("--file") + 1]
        self.assertEqual(lockfile, os.path.join("/tmp/fake", "Cargo.lock"))
        self.assertTrue(os.path.isabs(lockfile))
        # cwd is a scratch dir, never the target or inside it.
        cwd = called_kwargs.get("cwd")
        self.assertIsNotNone(cwd)
        self.assertNotEqual(cwd, "/tmp/fake")
        self.assertFalse(cwd.startswith("/tmp/fake" + os.sep))
        self.assertTrue(seen_cwd["existed_during_call"])
        # ... and is cleaned up afterward.
        self.assertFalse(os.path.isdir(cwd))

    def test_invoke_rc_2_prints_stderr_and_returns_failure(self):
        import contextlib, io
        fake_run = FakePopen(stdout=b"audit error output",
                             stderr=b"cargo audit failed", returncode=2)
        buf = io.StringIO()
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake_run), \
             contextlib.redirect_stderr(buf):
            stdout, rc = ca.CargoAuditAdapter().invoke("/tmp/fake")
        self.assertEqual(rc, 2)
        self.assertEqual(stdout, b"audit error output")
        self.assertIn("tool cargo-audit exited 2", buf.getvalue())
        self.assertIn("cargo audit failed", buf.getvalue())

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
        self.assertEqual(first(findings)["severity"], "CRITICAL")

    def test_parse_dict_cvss_field_uses_score_bucket(self):
        # Exercises the isinstance(cvss, dict) branch: a dict with numeric
        # score should be bucketed by cvss_bucket, not default to HIGH (#1196).
        sample = json.dumps({
            "vulnerabilities": {"list": [{
                "advisory": {
                    "id": "RUSTSEC-2021-0074",
                    "title": "Info leak in baz crate",
                    "cvss": {"score": 5.5},
                    "url": "https://rustsec.org/advisories/RUSTSEC-2021-0074",
                },
                "package": {"name": "baz", "version": "0.2.0"},
                "versions": {"patched": ["0.2.1"]},
            }]}
        }).encode()
        findings = ca.CargoAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_parse_dict_cvss_missing_score_defaults_to_low(self):
        # A dict-shaped cvss without an explicit score defaults to 0, which
        # cvss_bucket maps to LOW (#1196).
        sample = json.dumps({
            "vulnerabilities": {"list": [{
                "advisory": {
                    "id": "RUSTSEC-2021-0075",
                    "title": "Issue in qux crate",
                    "cvss": {},
                    "url": "https://rustsec.org/advisories/RUSTSEC-2021-0075",
                },
                "package": {"name": "qux", "version": "0.3.0"},
                "versions": {"patched": ["0.3.1"]},
            }]}
        }).encode()
        findings = ca.CargoAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "LOW")


if __name__ == "__main__":
    unittest.main()


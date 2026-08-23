import json
import subprocess
import unittest

import scripts.smoke_adapters as sa
from scripts.run_tools import recommendable_tools
from scripts.smoke_adapters import PROBES


class TestSmokeAdaptersParity(unittest.TestCase):
    """#1115 residual: PROBES must stay locked to the adapter registry."""

    def test_probe_keys_match_recommendable_tools(self):
        self.assertSetEqual(set(recommendable_tools()), set(PROBES))


def _runner(returncode=0, stdout=b"", stderr=b""):
    """A subprocess.run stand-in returning a fixed CompletedProcess."""
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)
    return run


_GOOD_SARIF = b'{"version":"2.1.0","runs":[{"results":[]}]}'
_SARIF_WITH_FINDINGS = b'{"version":"2.1.0","runs":[{"results":[{"ruleId":"x"}]}]}'


class TestCheckSemgrepScan(unittest.TestCase):
    def test_clean_scan_passes(self):
        ok, msg = sa.check_semgrep_scan(runner=_runner(0, _GOOD_SARIF))
        self.assertTrue(ok, msg)

    def test_findings_present_exit1_still_passes(self):
        # semgrep exits 1 when it HAS findings; that is a clean run, not a fault.
        ok, msg = sa.check_semgrep_scan(runner=_runner(1, _SARIF_WITH_FINDINGS))
        self.assertTrue(ok, msg)

    def test_empty_output_fails_the_455_crash(self):
        # The exact #455 signature: exit 1 (indistinguishable from findings) but
        # ZERO bytes of stdout. The output check, not the exit code, catches it.
        ok, msg = sa.check_semgrep_scan(
            runner=_runner(1, b"", b"PermissionError: '/home/scanner/.semgrep'"))
        self.assertFalse(ok)
        self.assertIn("EMPTY", msg)
        self.assertIn(".semgrep", msg)          # the stderr hint is surfaced

    def test_whitespace_only_output_fails(self):
        ok, msg = sa.check_semgrep_scan(runner=_runner(0, b"   \n"))
        self.assertFalse(ok)
        self.assertIn("EMPTY", msg)

    def test_non_json_output_fails(self):
        ok, msg = sa.check_semgrep_scan(runner=_runner(0, b"not json at all"))
        self.assertFalse(ok)
        self.assertIn("not valid SARIF", msg)

    def test_json_without_runs_fails(self):
        ok, msg = sa.check_semgrep_scan(runner=_runner(0, b'{"errors":["boom"]}'))
        self.assertFalse(ok)
        self.assertIn("no 'runs'", msg)

    def test_unexpected_exit_code_fails(self):
        ok, msg = sa.check_semgrep_scan(
            runner=_runner(2, b"", b"fatal: bad rule syntax"))
        self.assertFalse(ok)
        self.assertIn("exited 2", msg)
        self.assertIn("bad rule syntax", msg)

    def test_binary_missing_fails(self):
        def run(argv, **kwargs):
            raise FileNotFoundError()
        ok, msg = sa.check_semgrep_scan(runner=run)
        self.assertFalse(ok)
        self.assertIn("not found", msg)

    def test_timeout_fails(self):
        def run(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, sa.PROBE_TIMEOUT)
        ok, msg = sa.check_semgrep_scan(runner=run)
        self.assertFalse(ok)
        self.assertIn("no response", msg)

    def test_uses_the_real_adapter_argv(self):
        # The gate must run the SAME command the adapter runs, or it proves
        # nothing about the real scan path.
        seen = {}
        def run(argv, **kwargs):
            seen["argv"] = argv
            return subprocess.CompletedProcess(argv, 0, _GOOD_SARIF, b"")
        sa.check_semgrep_scan(runner=run)
        self.assertEqual(seen["argv"][:6], sa.SEMGREP_SCAN[:6])
        self.assertEqual(seen["argv"][:2], ["semgrep", "scan"])
        self.assertIn("--sarif", seen["argv"])
        self.assertTrue(seen["argv"][-1].endswith("probe.py"))   # the fixture


def _roslyn_runner(rule_id=None, returncode=0, bad_json=False, no_file=False):
    """Return a runner that fakes `dotnetarium-scs` by writing the SARIF file
    the probe expects at the `--export=` path."""
    def run(argv, **kwargs):
        # argv layout: ["dotnetarium-scs", csproj, "--export=<sarif>", ...]
        export_arg = next(a for a in argv if a.startswith("--export="))
        sarif = export_arg.split("=", 1)[1]
        if no_file:
            return subprocess.CompletedProcess(argv, returncode, b"", b"")
        results = []
        if rule_id is not None:
            results.append({"ruleId": rule_id})
        data = {"version": "2.1.0", "runs": [{"results": results}]}
        payload = b"not json" if bad_json else json.dumps(data).encode("utf-8")
        with open(sarif, "wb") as fh:
            fh.write(payload)
        return subprocess.CompletedProcess(argv, returncode, b"", b"")
    return run


class TestCheckRoslynSecGuardBuild(unittest.TestCase):
    def test_scs_finding_passes(self):
        ok, msg = sa.check_roslyn_secguard_build(
            runner=_roslyn_runner(rule_id="SCS0001"))
        self.assertTrue(ok, msg)

    def test_no_sarif_output_fails(self):
        ok, msg = sa.check_roslyn_secguard_build(
            runner=_roslyn_runner(rule_id="SCS0001", no_file=True))
        self.assertFalse(ok)
        self.assertIn("no SARIF output produced", msg)

    def test_invalid_sarif_json_fails(self):
        ok, msg = sa.check_roslyn_secguard_build(
            runner=_roslyn_runner(bad_json=True))
        self.assertFalse(ok)
        self.assertIn("not valid JSON", msg)

    def test_no_scs_findings_fails(self):
        ok, msg = sa.check_roslyn_secguard_build(
            runner=_roslyn_runner(rule_id="CS0001"))
        self.assertFalse(ok)
        self.assertIn("no DotnetariumSCS", msg)

    def test_binary_missing_fails(self):
        def run(argv, **kwargs):
            raise FileNotFoundError()
        ok, msg = sa.check_roslyn_secguard_build(runner=run)
        self.assertFalse(ok)
        self.assertIn("not found", msg)

    def test_timeout_fails(self):
        def run(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, sa.PROBE_TIMEOUT)
        ok, msg = sa.check_roslyn_secguard_build(runner=run)
        self.assertFalse(ok)
        self.assertIn("no response", msg)

    def test_os_error_fails(self):
        def run(argv, **kwargs):
            raise OSError(8, "Exec format error")
        ok, msg = sa.check_roslyn_secguard_build(runner=run)
        self.assertFalse(ok)
        self.assertIn("failed to exec", msg)

    def test_uses_the_real_scanner_argv(self):
        seen = {}
        def run(argv, **kwargs):
            seen["argv"] = argv
            return _roslyn_runner(rule_id="SCS0001")(argv, **kwargs)
        sa.check_roslyn_secguard_build(runner=run)
        self.assertEqual(seen["argv"][:1], ["dotnetarium-scs"])
        self.assertTrue(any(a.startswith("--export=") for a in seen["argv"]))
        self.assertIn("--ignore-msbuild-errors", seen["argv"])
        self.assertIn("--no-banner", seen["argv"])


if __name__ == "__main__":
    unittest.main()

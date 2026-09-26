import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

import scripts.smoke_adapters as sa
from scripts.tools import legacy_sarif
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
_MISSING = object()


def _bandit_entry(provider="bandit",
                  target="bandit.formatters.sarif:report"):
    return SimpleNamespace(
        name="sarif", value=target,
        dist=SimpleNamespace(name=provider),
    )


def _bandit_sarif(version="test-runtime", semantic_version="test-runtime",
                  results=None, driver_name="Bandit",
                  sarif_version="2.1.0"):
    if results is None:
        results = [{"ruleId": "B105", "message": {"text": "finding"}}]
    driver = {"name": driver_name}
    if version is not None:
        driver["version"] = version
    if semantic_version is not None:
        driver["semanticVersion"] = semantic_version
    document = {
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }
    if sarif_version is not _MISSING:
        document["version"] = sarif_version
    return json.dumps(document).encode("utf-8")


def _capture(output, ok=True, msg=""):
    def capture(name, argv, **kwargs):
        return ok, msg, output
    return capture


class TestCheckBanditSarif(unittest.TestCase):
    def test_real_output_shape_passes(self):
        seen = {}

        def capture(name, argv, **kwargs):
            seen["name"] = name
            seen["argv"] = argv
            seen["kwargs"] = kwargs
            with open(argv[-1], encoding="utf-8") as fh:
                seen["fixture"] = fh.read()
            return True, "", _bandit_sarif()

        ok, msg = sa.check_bandit_sarif(
            entry_points=[_bandit_entry()], runtime_version="test-runtime",
            capture=capture)
        self.assertTrue(ok, msg)
        self.assertEqual(seen["argv"][:-1], sa.BANDIT_SARIF_SCAN)
        self.assertEqual(seen["argv"][-3:-1], ["-f", "sarif"])
        self.assertIn("password", seen["fixture"])
        self.assertEqual(seen["kwargs"]["accepted_returncodes"], (0, 1))
        self.assertFalse(seen["kwargs"]["include_output_hint"])

    def test_duplicate_sarif_entry_points_fail_before_scan(self):
        capture = mock.Mock(side_effect=AssertionError("must not scan"))
        ok, msg = sa.check_bandit_sarif(
            entry_points=[_bandit_entry(), _bandit_entry("other")],
            runtime_version="test-runtime", capture=capture)
        self.assertFalse(ok)
        self.assertIn("exactly one", msg)
        self.assertIn("found 2", msg)
        capture.assert_not_called()

    def test_missing_sarif_entry_point_fails_before_scan(self):
        capture = mock.Mock(side_effect=AssertionError("must not scan"))
        ok, msg = sa.check_bandit_sarif(
            entry_points=[], runtime_version="test-runtime", capture=capture)
        self.assertFalse(ok)
        self.assertIn("found 0", msg)
        capture.assert_not_called()

    def test_wrong_provider_fails_before_scan(self):
        capture = mock.Mock(side_effect=AssertionError("must not scan"))
        ok, msg = sa.check_bandit_sarif(
            entry_points=[_bandit_entry("bandit-sarif-formatter")],
            runtime_version="test-runtime", capture=capture)
        self.assertFalse(ok)
        self.assertIn("Bandit's native", msg)
        self.assertIn("bandit-sarif-formatter", msg)
        capture.assert_not_called()

    def test_wrong_native_target_fails_before_scan(self):
        ok, msg = sa.check_bandit_sarif(
            entry_points=[_bandit_entry(target="other.module:report")],
            runtime_version="test-runtime", capture=mock.Mock())
        self.assertFalse(ok)
        self.assertIn("bandit.formatters.sarif:report", msg)

    def test_missing_or_wrong_version_metadata_fails(self):
        cases = (
            (None, "test-runtime", "driver.version"),
            ("wrong", "test-runtime", "driver.version"),
            ("test-runtime", None, "driver.semanticVersion"),
            ("test-runtime", "wrong", "driver.semanticVersion"),
        )
        for version, semantic_version, field in cases:
            with self.subTest(version=version,
                              semantic_version=semantic_version):
                ok, msg = sa.check_bandit_sarif(
                    entry_points=[_bandit_entry()],
                    runtime_version="test-runtime",
                    capture=_capture(_bandit_sarif(
                        version=version, semantic_version=semantic_version)))
                self.assertFalse(ok)
                self.assertIn(field, msg)
                self.assertIn("runtime", msg)

    def test_missing_or_wrong_sarif_version_fails(self):
        for value in (_MISSING, None, "2.0.0", 2.1, {}, []):
            with self.subTest(value=value):
                ok, msg = sa.check_bandit_sarif(
                    entry_points=[_bandit_entry()],
                    runtime_version="test-runtime",
                    capture=_capture(_bandit_sarif(sarif_version=value)))
                self.assertFalse(ok)
                self.assertEqual(msg,
                                 "bandit SARIF: scan output is not SARIF 2.1.0")

    def test_missing_or_wrong_result_message_fails(self):
        for value in (_MISSING, None, "finding", 7, [], ["finding"]):
            with self.subTest(value=value):
                result = {"ruleId": "B105"}
                if value is not _MISSING:
                    result["message"] = value
                ok, msg = sa.check_bandit_sarif(
                    entry_points=[_bandit_entry()],
                    runtime_version="test-runtime",
                    capture=_capture(_bandit_sarif(results=[result])))
                self.assertFalse(ok)
                self.assertEqual(msg,
                                 "bandit SARIF: scan result has no message object")

    def test_missing_wrong_or_empty_message_text_fails(self):
        for value in (_MISSING, None, 7, [], {}, "", " \t\n"):
            with self.subTest(value=value):
                message = {}
                if value is not _MISSING:
                    message["text"] = value
                ok, msg = sa.check_bandit_sarif(
                    entry_points=[_bandit_entry()],
                    runtime_version="test-runtime",
                    capture=_capture(_bandit_sarif(
                        results=[{"ruleId": "B105", "message": message}])))
                self.assertFalse(ok)
                self.assertEqual(
                    msg,
                    "bandit SARIF: scan result has no nonempty message text")

    def test_every_emitted_result_needs_a_valid_message(self):
        results = [
            {"ruleId": "B105", "message": {"text": "finding"}},
            {"ruleId": "B101", "message": "malformed"},
        ]
        ok, msg = sa.check_bandit_sarif(
            entry_points=[_bandit_entry()], runtime_version="test-runtime",
            capture=_capture(_bandit_sarif(results=results)))
        self.assertFalse(ok)
        self.assertEqual(msg, "bandit SARIF: scan result has no message object")

    def test_wrong_result_or_rule_id_shape_fails(self):
        cases = (
            (["not-an-object"], "scan result is not an object"),
            ([{}], "scan result has no string ruleId"),
            ([{"ruleId": None}], "scan result has no string ruleId"),
            ([{"ruleId": []}], "scan result has no string ruleId"),
            ([{"ruleId": ""}], "scan result has no string ruleId"),
        )
        for results, diagnostic in cases:
            with self.subTest(results=results):
                ok, msg = sa.check_bandit_sarif(
                    entry_points=[_bandit_entry()],
                    runtime_version="test-runtime",
                    capture=_capture(_bandit_sarif(results=results)))
                self.assertFalse(ok)
                self.assertEqual(msg, "bandit SARIF: " + diagnostic)

    def test_malformed_output_fails_without_echoing_it(self):
        payload = b"not-json-control-output"
        ok, msg = sa.check_bandit_sarif(
            entry_points=[_bandit_entry()], runtime_version="test-runtime",
            capture=_capture(payload))
        self.assertFalse(ok)
        self.assertIn("not valid JSON", msg)
        self.assertNotIn(payload.decode(), msg)

    def test_empty_output_fails(self):
        ok, msg = sa.check_bandit_sarif(
            entry_points=[_bandit_entry()], runtime_version="test-runtime",
            capture=_capture(b""))
        self.assertFalse(ok)
        self.assertIn("empty output", msg)

    def test_unexpectedly_successful_empty_scan_fails(self):
        ok, msg = sa.check_bandit_sarif(
            entry_points=[_bandit_entry()], runtime_version="test-runtime",
            capture=_capture(_bandit_sarif(results=[])))
        self.assertFalse(ok)
        self.assertIn("no findings", msg)

    def test_missing_expected_finding_fails(self):
        ok, msg = sa.check_bandit_sarif(
            entry_points=[_bandit_entry()], runtime_version="test-runtime",
            capture=_capture(_bandit_sarif(results=[{
                "ruleId": "B101", "message": {"text": "finding"},
            }])))
        self.assertFalse(ok)
        self.assertIn("B105", msg)

    def test_capture_failure_is_returned_without_parsing(self):
        ok, msg = sa.check_bandit_sarif(
            entry_points=[_bandit_entry()], runtime_version="test-runtime",
            capture=_capture(b"ignored", ok=False,
                             msg="bandit SARIF scan: exited 2"))
        self.assertFalse(ok)
        self.assertEqual(msg, "bandit SARIF scan: exited 2")


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
        self.assertEqual(seen["argv"][:-1], legacy_sarif.TOOL_CMD["semgrep"][:-1])
        self.assertEqual(legacy_sarif.TOOL_CMD["semgrep"][-1], "/src")
        self.assertTrue(seen["argv"][-1].endswith("probe.py"))   # the fixture


class TestWritableProbe(unittest.TestCase):
    def test_writable_directory_cleans_its_probe(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as path:
            ok, detail = sa.check_writable(path, "needed for output")
            self.assertTrue(ok)
            self.assertEqual(detail, "")
            self.assertEqual(os.listdir(path), [])

    def test_missing_directory_explains_failure(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as parent:
            path = os.path.join(parent, "missing")
            ok, detail = sa.check_writable(path, "needed for output")
            self.assertFalse(ok)
            self.assertIn(path, detail)
            self.assertIn("needed for output", detail)
            self.assertIn("not writable", detail)

    def test_permission_denial_explains_failure(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as path:
            original_open = sa.os.open

            def denied(name, flags, mode=0o777):
                if str(name).startswith(path + os.sep + ".panopticon-write-probe-"):
                    raise PermissionError(13, "Permission denied", name)
                return original_open(name, flags, mode)

            with mock.patch.object(sa.os, "open", side_effect=denied):
                ok, detail = sa.check_writable(path, "needed for output")
            self.assertFalse(ok)
            self.assertIn(path, detail)
            self.assertIn("Permission denied", detail)
            self.assertIn("needed for output", detail)
            self.assertEqual(os.listdir(path), [])


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


class TestProbeOutputIsBounded(unittest.TestCase):
    """#1576 (run-13 OPS-2542050329, tool-confirmed): run_probe buffered a
    probe's combined stdout/stderr with no byte cap.

    A version probe emits a line. A malfunctioning or unexpectedly verbose
    scanner can emit at line rate for the whole 180-second timeout, and the
    image build retained every byte of it before so much as checking the exit
    code -- enough to take out a CI worker. The cap keeps the head and drains
    the rest, so the child never blocks on a full pipe either.
    """

    # ~2 MB at once, then a non-zero exit: verbose AND failing, the case whose
    # diagnostic tail the caller actually reads.
    _NOISY = ("import sys\n"
              "sys.stdout.buffer.write(b'x' * 2_000_000)\n"
              "sys.stdout.buffer.write(b'\\nlast line here\\n')\n"
              "sys.stdout.flush()\n"
              "raise SystemExit(3)\n")

    def test_a_flood_is_truncated_not_buffered(self):
        err = io.StringIO()
        with mock.patch.object(sa, "PROBE_OUTPUT_MAX_BYTES", 4096), \
                contextlib.redirect_stderr(err):
            ok, msg = sa.run_probe("noisy", [sys.executable, "-c", self._NOISY])
        self.assertFalse(ok)
        self.assertIn("exited 3", msg)
        self.assertIn("truncated", msg)
        self.assertIn("PROBE_OUTPUT_MAX_BYTES", err.getvalue())

    def test_the_bounded_read_keeps_the_head_and_drains_the_rest(self):
        import io as _io
        stream = _io.BytesIO(b"head" + b"z" * 100_000)
        kept, truncated = sa._read_capped(stream, 4)
        self.assertEqual(kept, b"head")
        self.assertTrue(truncated)
        self.assertEqual(stream.read(), b"")      # drained to EOF, never left full

    def test_a_quiet_probe_is_untouched(self):
        ok, msg = sa.run_probe("quiet", [sys.executable, "-c", "print('v1.2.3')"])
        self.assertTrue(ok, msg)
        self.assertEqual(msg, "")

    def test_a_failing_probe_still_reports_its_last_line(self):
        ok, msg = sa.run_probe(
            "bad", [sys.executable, "-c",
                    "import sys; print('boom: no such config'); sys.exit(2)"])
        self.assertFalse(ok)
        self.assertIn("exited 2", msg)
        self.assertIn("boom: no such config", msg)
        self.assertNotIn("truncated", msg)

    def test_a_missing_binary_still_reads_as_missing(self):
        ok, msg = sa.run_probe("nope", ["panopticon-no-such-binary-1576"])
        self.assertFalse(ok)
        self.assertIn("binary not found", msg)

    def test_a_hung_probe_is_killed_at_the_timeout(self):
        with mock.patch.object(sa, "PROBE_TIMEOUT", 1):
            ok, msg = sa.run_probe(
                "hung", [sys.executable, "-c", "import time; time.sleep(30)"])
        self.assertFalse(ok)
        self.assertIn("no response in 1s", msg)


if __name__ == "__main__":
    unittest.main()

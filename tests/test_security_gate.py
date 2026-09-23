import contextlib
import io
import json
import os
import tempfile
import unittest

import scripts.ingest_tools as ingest_tools
import scripts.security_gate as gate


def _sarif(level=None):
    results = []
    if level:
        results.append({
            "ruleId": "test.rule",
            "level": level,
            "message": {"text": "test finding"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "/src/app.py"},
                "region": {"startLine": 1}}}],
        })
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": []}},
        "results": results,
    }]}


class TestSecurityGate(unittest.TestCase):
    def _write(self, root, manifest, sarif=None):
        tools = os.path.join(root, "tools")
        os.makedirs(tools)
        if sarif is not None:
            with open(os.path.join(tools, "semgrep.sarif"), "w") as fh:
                json.dump(sarif, fh)
        manifest_path = os.path.join(root, "manifest.json")
        with open(manifest_path, "w") as fh:
            json.dump(manifest, fh)
        return tools, manifest_path

    def test_complete_clean_scan_passes(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"],
                       "missing": []}, _sarif())
            findings, dispositions, failures, high, _sup = gate.evaluate(tools, manifest)
        self.assertEqual(findings, [])
        self.assertEqual(dispositions["semgrep"]["status"], "empty")
        self.assertEqual(failures, [])
        self.assertEqual(high, [])

    def test_missing_selected_scanner_fails_coverage(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": [],
                       "missing": ["semgrep"]})
            _, _, failures, _, _ = gate.evaluate(tools, manifest)
        self.assertEqual(failures, ["semgrep: no output"])

    def test_high_finding_fails_gate(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"],
                       "missing": []}, _sarif("error"))
            _, _, failures, high, _ = gate.evaluate(tools, manifest)
        self.assertEqual(failures, [])
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0]["severity"], "HIGH")

    def test_empty_selection_is_invalid(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": [], "produced": [], "missing": []})
            with self.assertRaisesRegex(ValueError, "selected no tools"):
                gate.evaluate(tools, manifest)

    def test_excluded_scope_scanner_does_not_fail_coverage(self):
        # An adapter demoted to excluded_scope is NOT in selected/missing, so a
        # clean scan passes even though the adapter produced no output.
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"],
                       "missing": [], "excluded_scope": ["eslint-security"]},
                _sarif())
            _, _, failures, high, _ = gate.evaluate(tools, manifest, ["tests/fixtures/*"])
        self.assertEqual(failures, [])
        self.assertEqual(high, [])

    def test_excluded_scope_backward_compatible_absent(self):
        # A manifest without the excluded_scope key still loads (older producer).
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"],
                       "missing": []}, _sarif())
            data = gate.load_manifest(manifest)
        self.assertEqual(data["excluded_scope"], [])

    def test_network_exclusion_is_lost_coverage_even_when_scope_excluded(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"],
                       "missing": [], "excluded_scope": ["pip-audit"],
                       "network": {"pip-audit": "excluded:online egress unavailable"}}, _sarif())
            _, _, failures, _, _ = gate.evaluate(tools, manifest)
        self.assertEqual(failures, ["pip-audit: excluded:online egress unavailable"])

    def test_excluded_scope_overlapping_selected_is_invalid(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"],
                       "missing": [], "excluded_scope": ["semgrep"]})
            with self.assertRaisesRegex(ValueError, "excluded_scope overlaps"):
                gate.evaluate(tools, manifest)

    def test_unexpected_scanner_output_recorded_as_failure(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"], "missing": []},
                _sarif())
            # Add an extra tool output file not declared in the manifest
            bandit_file = os.path.join(tools, "bandit.json")
            with open(bandit_file, "w", encoding="utf-8") as fh:
                json.dump({"results": []}, fh)
            _, _, failures, _, _ = gate.evaluate(tools, manifest)
        self.assertTrue(any("unexpected scanner output: bandit" in f for f in failures))

    def test_large_sarif_file_loading(self):
        # Generate a large SARIF file with many findings to verify performance and scaling
        results = [
            {
                "ruleId": f"rule.{i}",
                "level": "warning" if i % 10 != 0 else "error",
                "message": {"text": f"Finding description {i}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"/src/module_{i % 50}.py"},
                        "region": {"startLine": (i * 3) % 1000 + 1},
                    }
                }],
            }
            for i in range(1000)
        ]
        large_sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "semgrep", "rules": []}},
                "results": results,
            }],
        }
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"], "missing": []},
                large_sarif,
            )
            findings, dispositions, failures, high, _sup = gate.evaluate(tools, manifest)
        self.assertEqual(len(findings), 1000)
        self.assertEqual(dispositions["semgrep"]["status"], "ok")
        self.assertEqual(dispositions["semgrep"]["findings"], 1000)
        self.assertEqual(failures, [])
        self.assertEqual(len(high), 100)  # 1000 / 10 = 100 error/high findings

    def test_manifest_not_object_raises(self):
        with tempfile.TemporaryDirectory() as root:
            _, manifest = self._write(root, "not-a-dict")
            with self.assertRaisesRegex(ValueError, "scanner manifest is not an object"):
                gate.load_manifest(manifest)

    def test_manifest_missing_selected_raises(self):
        # Missing `selected` means the list-validation check fires first.
        with tempfile.TemporaryDirectory() as root:
            _, manifest = self._write(root, {"produced": [], "missing": []})
            with self.assertRaisesRegex(ValueError, "scanner manifest lists are malformed"):
                gate.load_manifest(manifest)

    def test_manifest_malformed_lists_raises(self):
        with tempfile.TemporaryDirectory() as root:
            _, manifest = self._write(
                root, {"selected": "semgrep", "produced": [], "missing": []})
            with self.assertRaisesRegex(ValueError, "scanner manifest lists are malformed"):
                gate.load_manifest(manifest)

    def test_manifest_missing_file_raises(self):
        with tempfile.TemporaryDirectory() as root:
            missing = os.path.join(root, "missing-manifest.json")
            with self.assertRaisesRegex(ValueError, "cannot read scanner manifest"):
                gate.load_manifest(missing)

    def test_missing_tools_dir_fails_coverage(self):
        # A missing tools directory yields no dispositions, so every selected
        # scanner is reported as missing output (#1196).
        with tempfile.TemporaryDirectory() as root:
            _, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"], "missing": []},
                _sarif())
            missing_tools = os.path.join(root, "no-such-tools")
            _, _, failures, _, _ = gate.evaluate(missing_tools, manifest)
        self.assertEqual(failures, ["semgrep: no output"])


def _vendored_sarif(level="error", uri="app/vendor/patched_auth.rb"):
    """One suppressible finding: a HIGH hardcoded credential under *uri*.

    #1578 owner ruling 2026-09-22 (policy C): the redteam gate re-admits a
    suppressed finding only when it is CRITICAL or SECRET-CLASS, so the rule
    now carries the CWE its message has always described. Every test below is
    about WHICH DROP CLASS reaches the gate, not about the severity rule --
    they need a finding that is gate-eligible once it gets there, and a
    credential is what a "planted payload under `vendor/`" has always meant
    here. The severity rule itself is pinned by
    `TestPolicyCNarrowsTheRedteamGate`.
    """
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "semgrep",
                            "rules": [{"id": "test.rule",
                                       "properties": {"tags": ["CWE-798"]}}]}},
        "results": [{"ruleId": "test.rule", "level": level,
                     "message": {"text": "hardcoded credential"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": uri},
                         "region": {"startLine": 1}}}]}]}]}


class TestVendoredSuppressionAndTheGate(unittest.TestCase):
    """#1578 (SEC-G2B): this gate blocks merges, and it inherited the
    vendored-path exclusion by sharing `ingest_dir_detailed`'s defaults.

    A HIGH/CRITICAL under any path segment literally named `vendor`,
    `node_modules`, `third_party`, ... was dropped before `evaluate` ever saw
    it, so a payload landed as `app/vendor/patched_auth.rb` passed the gate
    outright with no per-file audit trail. The ruling: the report may still
    suppress it -- that is what makes tool output usable -- but the GATE must
    not lose a finding to a directory name under redteam, and in standard mode
    the number it dropped is printed next to the gate line rather than left to
    an aggregate stderr note nobody reads.
    """

    def _repo(self, root, sarif):
        tools = os.path.join(root, "tools")
        os.makedirs(tools)
        with open(os.path.join(tools, "semgrep.sarif"), "w", encoding="utf-8") as fh:
            json.dump(sarif, fh)
        manifest_path = os.path.join(root, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump({"selected": ["semgrep"], "produced": ["semgrep"],
                       "missing": []}, fh)
        return tools, manifest_path

    def test_redteam_gates_on_a_suppressed_critical(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, _vendored_sarif())
            _f, _d, failures, high, suppressed = gate.evaluate(
                tools, manifest, security_mode="redteam")
        self.assertEqual(failures, [])
        self.assertEqual(len(high), 1, "the gate lost a HIGH to a directory name")
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(suppressed[0]["suppressed"], "vendor")

    def test_standard_still_suppresses_it_and_discloses_the_count(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, _vendored_sarif())
            findings, _d, _failures, high, suppressed = gate.evaluate(tools, manifest)
        self.assertEqual(findings, [])
        self.assertEqual(high, [])
        self.assertEqual(len(suppressed), 1)

    def test_the_standard_mode_gate_line_says_how_many_it_dropped(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, _vendored_sarif())
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = gate.main(["--tools-dir", tools, "--manifest", manifest])
        self.assertEqual(rc, 0)
        self.assertIn("1 suppressed", buf.getvalue())
        self.assertIn("vendor", buf.getvalue())

    def test_redteam_mode_fails_the_run_the_default_passes(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, _vendored_sarif())
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(0, gate.main(
                    ["--tools-dir", tools, "--manifest", manifest]))
                self.assertEqual(1, gate.main(
                    ["--tools-dir", tools, "--manifest", manifest,
                     "--security", "redteam"]))

    def test_an_ordinary_finding_is_unaffected_by_the_mode(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, _vendored_sarif(uri="app/auth.rb"))
            for mode in ("standard", "redteam"):
                _f, _d, _failures, high, suppressed = gate.evaluate(
                    tools, manifest, security_mode=mode)
                self.assertEqual(len(high), 1, mode)
                self.assertEqual(suppressed, [], mode)


def _secret_sarif(tool="semgrep", uri="app/vendor/patched_auth.rb", cwe=None):
    """One hardcoded-credential result under *uri*, optionally CWE-tagged.

    `sarif_to_findings` scrapes the CWE out of the rule's `tags`, which is
    exactly the channel `gates_when_suppressed` reads.

    A SECRET adapter's result carries no `level`, because real gitleaks output
    carries none (fix round 1, review C1: setting `"level": "error"` here was a
    field the tool never emits, and it hid the fact that every real gitleaks
    finding arrived MEDIUM). `sarif_utils.SECRET_ADAPTERS` is what grades it,
    not the fixture -- and the end-to-end proof of that runs off the committed
    capture in `TestRealGitleaksOutputReachesTheGate` below.
    """
    rules = ([{"id": "test.rule", "properties": {"tags": [cwe]}}] if cwe else [])
    result = {"ruleId": "test.rule",
              "message": {"text": "hardcoded credential"},
              "locations": [{"physicalLocation": {
                  "artifactLocation": {"uri": uri},
                  "region": {"startLine": 1}}}]}
    if tool not in ingest_tools.SECRET_ADAPTERS:
        result["level"] = "error"
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": tool, "rules": rules}},
        "results": [result]}]}


def _critical_osv(uri="app/vendor/package-lock.json"):
    """One CRITICAL (CVSS 9.8) dependency finding whose location is *uri*.

    The SARIF path cannot express CRITICAL at all (`LEVEL_TO_SEV` tops out at
    HIGH for `level: error`), so the CRITICAL arm of policy C needs a
    CVSS-scored adapter.
    """
    return {"results": [{"source": {"path": uri}, "packages": [{
        "package": {"name": "left-pad", "version": "1.0.0", "ecosystem": "npm"},
        "groups": [{"ids": ["GHSA-rce"], "max_severity": "9.8"}],
        "vulnerabilities": [{"id": "GHSA-rce", "summary": "remote code execution"}]}]}]}


def _lint_sarif(uri="app/vendor/util.js"):
    """A HIGH with no secret evidence: a scanner OPINION about bundled code.

    Its own helper because the payload has to match the claim (review M3):
    `_secret_sarif`'s message is "hardcoded credential", so a test named "a
    lint finding no longer gates" reading THAT pinned the opposite of what it
    meant. CWE-1321 (prototype pollution) is a real CWE and deliberately not a
    credential one, so this also exercises the non-secret-CWE path end to end.
    """
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "detect-object-injection",
             "properties": {"tags": ["security", "CWE-1321"]}}]}},
        "results": [{"ruleId": "detect-object-injection", "level": "error",
                     "message": {"text": "variable assigned to an object injection sink"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": uri},
                         "region": {"startLine": 1}}}]}]}]}


def _below_high_secret_sarif(uri="app/vendor/legacy.py"):
    """A secret-class finding its adapter graded BELOW the gate floor.

    bandit's B105 at `level: warning` is MEDIUM and carries CWE-259 -- the
    exact shape the schema-parity fixture uses, and the one that proves the
    #1578 rule is a floor of its own: a secret-class finding gates regardless
    of the grade the tool put on it (fix round 1, ruling 2). Before that
    ruling `evaluate` re-applied `GATE_SEVERITIES` to the policy-admitted set
    and threw this one away after admitting it.
    """
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "bandit", "rules": [
            {"id": "B105", "properties": {"tags": ["security", "CWE-259"]}}]}},
        "results": [{"ruleId": "B105", "level": "warning",
                     "message": {"text": "possible hardcoded password"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": uri},
                         "region": {"startLine": 1}}}]}]}]}


class TestPolicyCNarrowsTheRedteamGate(unittest.TestCase):
    """#1578 owner ruling 2026-09-22 (policy C): what redteam re-admits.

    The first cut of the redteam gate counted the WHOLE suppressed set on
    severity alone (option B), so a vendor-heavy tree hard-FAILed a merge on
    bundled-library lint noise -- the noise the suppression exists to keep out
    (calibration-5/solidus: 592 of eslint-security's 623 messages were one
    rule firing on jQuery under `vendor/`). C re-admits only what an operator
    would want a merge blocked for: a CRITICAL, or a secret-class finding.

    This gate and the driver's own report gate ask the one predicate
    (`ingest_tools.gates_when_suppressed`), so the two verdicts cannot diverge.
    """

    def _repo(self, root, payloads):
        """A tools dir holding `{tool: parsed-output}`, plus its manifest."""
        tools = os.path.join(root, "tools")
        os.makedirs(tools)
        for tool, doc in payloads.items():
            suffix = "json" if tool == "osv-scanner" else "sarif"
            with open(os.path.join(tools, "%s.%s" % (tool, suffix)), "w",
                      encoding="utf-8") as fh:
                json.dump(doc, fh)
        manifest_path = os.path.join(root, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump({"selected": sorted(payloads), "produced": sorted(payloads),
                       "missing": []}, fh)
        return tools, manifest_path

    def _gate(self, payloads, mode="redteam"):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, payloads)
            _f, _d, failures, high, suppressed = gate.evaluate(
                tools, manifest, security_mode=mode)
        self.assertEqual(failures, [])
        return high, suppressed

    def test_a_suppressed_high_lint_finding_no_longer_gates(self):
        # The B behaviour this ruling reverses: a HIGH with no secret evidence
        # is a scanner opinion about bundled code, and it may not block a merge.
        high, suppressed = self._gate({"semgrep": _lint_sarif()})
        self.assertEqual(high, [])
        self.assertEqual([f["suppressed"] for f in suppressed], ["vendor"])

    def test_a_suppressed_critical_gates(self):
        high, suppressed = self._gate({"osv-scanner": _critical_osv()})
        self.assertEqual([f["severity"] for f in high], ["CRITICAL"])
        self.assertEqual([f["suppressed"] for f in suppressed], ["vendor"])

    def test_a_suppressed_gitleaks_high_gates(self):
        high, _s = self._gate({"gitleaks": _secret_sarif(tool="gitleaks")})
        self.assertEqual(len(high), 1)

    def test_a_suppressed_secret_cwe_gates_whichever_adapter_found_it(self):
        high, _s = self._gate({"semgrep": _secret_sarif(cwe="CWE-798")})
        self.assertEqual(len(high), 1)

    def test_standard_mode_gates_none_of_them(self):
        # Byte-identical to before the ruling: standard keeps every name-based
        # suppression, and the count is disclosed beside the gate line.
        for name, payload in (("lint", {"semgrep": _lint_sarif()}),
                              ("critical", {"osv-scanner": _critical_osv()}),
                              ("gitleaks", {"gitleaks": _secret_sarif(tool="gitleaks")})):
            with self.subTest(payload=name):
                high, suppressed = self._gate(payload, mode="standard")
                self.assertEqual(high, [])
                self.assertEqual(len(suppressed), 1)

    def test_an_unsuppressed_lint_high_still_gates_in_both_modes(self):
        # The oracle: policy C narrows the SUPPRESSED set and nothing else.
        for mode in ("standard", "redteam"):
            with self.subTest(mode=mode):
                high, suppressed = self._gate(
                    {"semgrep": _lint_sarif(uri="app/lib/util.js")},
                    mode=mode)
                self.assertEqual(len(high), 1)
                self.assertEqual(suppressed, [])

    def test_the_gate_line_says_how_many_it_counted_and_how_many_it_withheld(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, {
                "semgrep": _secret_sarif(),
                "gitleaks": _secret_sarif(tool="gitleaks")})
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = gate.main(["--tools-dir", tools, "--manifest", manifest,
                                "--security", "redteam"])
        line = buf.getvalue()
        self.assertEqual(rc, 1)
        self.assertIn("2 suppressed by directory name", line)
        self.assertIn("1 GATED", line)
        self.assertIn("1 disclosed only", line)


GOLDEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "goldens", "tool-raw")


def _relocated_gitleaks_golden(prefix):
    """The committed gitleaks capture with its hit paths moved under *prefix*.

    REAL output, per tests/goldens/tool-raw/README.md: the rules, the absent
    `level`, the message shapes and the envelope are all the scanner's own.
    Only `artifactLocation.uri` moves, and it has to: the capture's own hits sit
    in `.env` and under `.panopticon/`, and the run-artifact exclusion drops
    those before the name-based suppression this test is about can see them.
    """
    with open(os.path.join(GOLDEN_DIR, "gitleaks.raw"), encoding="utf-8") as fh:
        sarif = json.load(fh)
    for n, res in enumerate(sarif["runs"][0]["results"]):
        (res["locations"][0]["physicalLocation"]["artifactLocation"]
         ["uri"]) = "%s/leaked%d.py" % (prefix, n)
    return sarif


class TestRealGitleaksOutputReachesTheGate(unittest.TestCase):
    """#1578 fix round 1 (review C1), end to end on the committed capture.

    The review reproduced two committed API keys and a private key under
    `app/vendor/`, under `--security redteam`, with the gate printing "3 GATED"
    and exiting 0 -- because real gitleaks SARIF states no `level`, so every
    one of them arrived MEDIUM and `GATE_SEVERITIES` threw them away directly
    after the policy admitted them. The same capture at a NON-vendored path
    exposed the larger, pre-existing hole behind it: this gate could not fail
    on any gitleaks finding at all.

    Both halves are now closed -- `sarif_utils.SECRET_ADAPTERS` grades them at
    the parse, and `evaluate` no longer re-applies the floor to the
    policy-admitted set -- and both are pinned here rather than on a fixture
    that supplies the field the tool omits.
    """

    def _repo(self, root, sarif):
        tools = os.path.join(root, "tools")
        os.makedirs(tools)
        with open(os.path.join(tools, "gitleaks.sarif"), "w", encoding="utf-8") as fh:
            json.dump(sarif, fh)
        manifest_path = os.path.join(root, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump({"selected": ["gitleaks"], "produced": ["gitleaks"],
                       "missing": []}, fh)
        return tools, manifest_path

    def test_standard_mode_fails_on_committed_secrets_at_a_project_path(self):
        # The pre-existing hole, closed: not a suppression question at all --
        # these are ordinary kept findings, and before the severity
        # normalization the gate reported 0 HIGH/CRITICAL and exited 0.
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(
                root, _relocated_gitleaks_golden("app/config"))
            findings, _d, failures, high, suppressed = gate.evaluate(tools, manifest)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = gate.main(["--tools-dir", tools, "--manifest", manifest])
        self.assertEqual(failures, [])
        self.assertEqual(len(findings), 3)
        self.assertEqual(suppressed, [])
        self.assertEqual(len(high), 3, "the gate cannot fail on a leaked secret")
        self.assertEqual(rc, 1)
        self.assertIn("3 HIGH/CRITICAL", buf.getvalue())

    def test_redteam_gates_them_under_vendor_and_the_count_is_what_gated(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(
                root, _relocated_gitleaks_golden("app/vendor"))
            findings, _d, failures, high, suppressed = gate.evaluate(
                tools, manifest, security_mode="redteam")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = gate.main(["--tools-dir", tools, "--manifest", manifest,
                                "--security", "redteam"])
        line = buf.getvalue()
        self.assertEqual(failures, [])
        self.assertEqual(findings, [])                       # none kept
        self.assertEqual([f["suppressed"] for f in suppressed], ["vendor"] * 3)
        self.assertEqual(len(high), 3)
        self.assertEqual(rc, 1, "3 GATED beside rc=0 is the defect")
        # The printed count is what REACHED the gate, not what the policy
        # admitted -- the two differed by construction before this fix.
        self.assertIn("3 GATED", line)
        self.assertIn("0 disclosed only", line)

    def test_standard_mode_still_suppresses_the_same_capture(self):
        # The mode is still the only thing that re-admits them: the severity
        # normalization must not turn a suppressed secret into a standard-mode
        # gate failure.
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(
                root, _relocated_gitleaks_golden("app/vendor"))
            findings, _d, _f, high, suppressed = gate.evaluate(tools, manifest)
        self.assertEqual(findings, [])
        self.assertEqual(high, [])
        self.assertEqual(len(suppressed), 3)


class TestThePolicyIsTheFloorForTheSuppressedSet(unittest.TestCase):
    """#1578 fix round 1, ruling 2: what the predicate admits, the gate counts.

    `evaluate` used to build one list and then re-apply `GATE_SEVERITIES` to
    all of it, so a secret-class finding whose adapter graded it below HIGH was
    admitted by the policy and dropped by the next line -- and `main` printed
    it as GATED anyway. Passing `gates_when_suppressed` IS the floor for the
    suppressed set: a CRITICAL clears the severity test regardless, and a
    secret-class finding gates whatever grade its tool put on it.
    """

    def _repo(self, root, payloads):
        tools = os.path.join(root, "tools")
        os.makedirs(tools)
        for tool, doc in payloads.items():
            with open(os.path.join(tools, "%s.sarif" % tool), "w",
                      encoding="utf-8") as fh:
                json.dump(doc, fh)
        manifest_path = os.path.join(root, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump({"selected": sorted(payloads), "produced": sorted(payloads),
                       "missing": []}, fh)
        return tools, manifest_path

    def test_a_secret_class_medium_gates_under_redteam(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, {"bandit": _below_high_secret_sarif()})
            _f, _d, failures, high, suppressed = gate.evaluate(
                tools, manifest, security_mode="redteam")
        self.assertEqual(failures, [])
        self.assertEqual([f["severity"] for f in suppressed], ["MEDIUM"])
        self.assertEqual(len(high), 1,
                         "the policy admitted it and the floor threw it away")

    def test_the_same_medium_is_not_gated_in_standard_mode(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, {"bandit": _below_high_secret_sarif()})
            findings, _d, _f, high, suppressed = gate.evaluate(tools, manifest)
        self.assertEqual(findings, [])
        self.assertEqual(high, [])
        self.assertEqual(len(suppressed), 1)

    def test_an_unsuppressed_medium_still_does_not_gate_in_either_mode(self):
        # The floor still applies to everything the gate KEEPS: policy C is
        # about the suppressed set, and only about it.
        for mode in ("standard", "redteam"):
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory() as root:
                    tools, manifest = self._repo(
                        root, {"bandit": _below_high_secret_sarif(
                            uri="app/lib/legacy.py")})
                    findings, _d, _f, high, suppressed = gate.evaluate(
                        tools, manifest, security_mode=mode)
                self.assertEqual(len(findings), 1)
                self.assertEqual(suppressed, [])
                self.assertEqual(high, [], mode)

    def test_the_printed_count_equals_what_reached_the_gate(self):
        # A mixed tree: one secret-class MEDIUM and one lint HIGH, both under
        # `vendor/`. The line must say 1 GATED / 1 disclosed only, and the
        # verdict must rest on exactly that one.
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, {
                "bandit": _below_high_secret_sarif(),
                "semgrep": _lint_sarif()})
            _f, _d, _fail, high, suppressed = gate.evaluate(
                tools, manifest, security_mode="redteam")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = gate.main(["--tools-dir", tools, "--manifest", manifest,
                                "--security", "redteam"])
        line = buf.getvalue()
        self.assertEqual(len(suppressed), 2)
        self.assertEqual([f["severity"] for f in high], ["MEDIUM"])
        self.assertEqual(rc, 1)
        self.assertIn("2 suppressed by directory name", line)
        self.assertIn("1 GATED", line)
        self.assertIn("1 disclosed only", line)


class TestEveryNameBasedDropReachesTheRedteamGate(unittest.TestCase):
    """#1740 (ARC-F2A): the #1578 invariant is stated for ALL of them.

    Lines 14-18 of the module say that under `--security redteam` a finding may
    not be dropped because of the DIRECTORY NAME it sits under. The
    compensating control was wired for one name list (`_vendored_segment`).
    `app/venv/`, `lib/site-packages/` and the fixture corpus are the same
    evidence -- a conventional name, no marker, no provenance -- and their
    drops never reached `suppressed`, so `high` stayed empty for a payload
    parked under any of them.

    What must still be silent is the other kind of drop: a `pyvenv.cfg` beside
    the tree, the scanner's own `.panopticon/` artifacts, generated bytecode.
    Those rest on evidence, not on a name, and re-gating a previous run's own
    discarded report is the compounding noise run-10 D1 removed.
    """

    def _repo(self, root, uri, marker_dir=None, nested=False):
        """A tools dir holding one HIGH under *uri*, plus its manifest.

        `nested` puts the tools dir at `<root>/.panopticon/tools`, which is how
        `_target_root_for` finds a tree to stat a `pyvenv.cfg` in -- the CI
        gate's own layout points at a bare temp directory, where no marker can
        be confirmed and the NAME is all there is.
        """
        tools = (os.path.join(root, ".panopticon", "tools") if nested
                 else os.path.join(root, "tools"))
        os.makedirs(tools)
        if marker_dir:
            os.makedirs(os.path.join(root, marker_dir), exist_ok=True)
            with open(os.path.join(root, marker_dir, "pyvenv.cfg"), "w") as fh:
                fh.write("home = /usr/bin\n")
        with open(os.path.join(tools, "semgrep.sarif"), "w", encoding="utf-8") as fh:
            json.dump(_vendored_sarif(uri=uri), fh)
        manifest_path = os.path.join(root, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump({"selected": ["semgrep"], "produced": ["semgrep"],
                       "missing": []}, fh)
        return tools, manifest_path

    def test_a_name_only_virtualenv_is_gated_under_redteam(self):
        for uri, segment in (("app/venv/patched_auth.py", "venv"),
                             ("lib/site-packages/requests/api.py", "site-packages")):
            with tempfile.TemporaryDirectory() as root:
                tools, manifest = self._repo(root, uri)
                _f, _d, failures, high, suppressed = gate.evaluate(
                    tools, manifest, security_mode="redteam")
            self.assertEqual(failures, [], uri)
            self.assertEqual(len(high), 1,
                             "the gate lost a HIGH to a directory name: %s" % uri)
            self.assertEqual([f["suppressed"] for f in suppressed], [segment], uri)

    def test_the_same_finding_stays_suppressed_under_standard(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, "app/venv/patched_auth.py")
            findings, _d, _failures, high, suppressed = gate.evaluate(tools, manifest)
        self.assertEqual(findings, [])
        self.assertEqual(high, [])
        self.assertEqual(len(suppressed), 1)

    def test_a_pyvenv_cfg_beside_it_keeps_the_drop_silent(self):
        # Evidence, not a name: the marker says the tree really is installed
        # code, so the finding is dropped in BOTH modes and never gated.
        for mode in ("standard", "redteam"):
            with tempfile.TemporaryDirectory() as root:
                tools, manifest = self._repo(
                    root, "app/venv/patched_auth.py", marker_dir="app/venv",
                    nested=True)
                findings, _d, _failures, high, suppressed = gate.evaluate(
                    tools, manifest, security_mode=mode)
            self.assertEqual(findings, [], mode)
            self.assertEqual(high, [], mode)
            self.assertEqual(suppressed, [], mode)

    def test_the_marker_case_is_not_vacuous(self):
        # MUTATION: the same layout WITHOUT the marker must gate under redteam,
        # so the test above pins the marker rather than the nesting.
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, "app/venv/patched_auth.py",
                                         nested=True)
            _f, _d, _failures, high, _s = gate.evaluate(
                tools, manifest, security_mode="redteam")
        self.assertEqual(len(high), 1)

    def test_a_fixture_corpus_finding_is_gated_under_redteam_only(self):
        # `evaluate` never passes include_fixtures, so the corpus prune applies
        # to the gate too -- on the strength of the directory name alone.
        for mode, gated in (("standard", 0), ("redteam", 1)):
            with tempfile.TemporaryDirectory() as root:
                tools, manifest = self._repo(
                    root, "tests/fixtures/vulnerable-node/app.js")
                _f, _d, _failures, high, suppressed = gate.evaluate(
                    tools, manifest, security_mode=mode)
            self.assertEqual(len(high), gated, mode)
            self.assertEqual([f["suppressed"] for f in suppressed],
                             ["fixture-corpus"], mode)

    def test_the_evidence_backed_classes_are_silent_in_both_modes(self):
        for uri in (".panopticon/runs/t/report-discarded.json",
                    "skill/scripts/__pycache__/driver.cpython-314.pyc"):
            for mode in ("standard", "redteam"):
                with tempfile.TemporaryDirectory() as root:
                    tools, manifest = self._repo(root, uri)
                    findings, _d, _failures, high, suppressed = gate.evaluate(
                        tools, manifest, security_mode=mode)
                self.assertEqual(findings, [], (uri, mode))
                self.assertEqual(high, [], (uri, mode))
                self.assertEqual(suppressed, [], (uri, mode))

    def test_an_operator_exclude_glob_is_never_re_admitted(self):
        # `--exclude` is policy the operator set on this gate, not a guess from
        # a directory name: redteam must not overturn it.
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, "tests/fixtures/x/app.js")
            _f, _d, _failures, high, suppressed = gate.evaluate(
                tools, manifest, exclude_globs=["tests/fixtures/**"],
                security_mode="redteam")
        self.assertEqual(high, [])
        self.assertEqual(suppressed, [])

    def test_the_gate_line_counts_what_the_operator_excluded(self):
        # Fix round 1, ruling 3: the line counted suppressions and said nothing
        # about `--exclude`, so an operator who UN-GATED a payload with
        # `--exclude '**/venv/**'` under redteam saw a clean gate line with no
        # trace of the glob that emptied it.
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, "app/venv/patched_auth.py")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = gate.main(["--tools-dir", tools, "--manifest", manifest,
                                "--exclude", "app/venv/*",
                                "--security", "redteam"])
        line = buf.getvalue()
        self.assertEqual(rc, 0)                    # un-gated, by operator policy
        self.assertIn("1 excluded by --exclude", line)
        self.assertNotIn("suppressed", line)       # it never reached that channel

    def test_the_gate_line_says_nothing_about_globs_that_matched_nothing(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._repo(root, "app/auth.py")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                gate.main(["--tools-dir", tools, "--manifest", manifest,
                           "--exclude", "ops/*"])
        self.assertNotIn("excluded by --exclude", buf.getvalue())

    def test_the_gate_line_names_each_suppression_class_with_its_counts(self):
        with tempfile.TemporaryDirectory() as root:
            tools = os.path.join(root, "tools")
            os.makedirs(tools)
            results = [{"ruleId": "r", "level": "error",
                        "message": {"text": "m"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": 1}}}]}
                       for uri in ("app/vendor/j.js", "app/venv/x.py",
                                   "tests/fixtures/n/app.js")]
            with open(os.path.join(tools, "semgrep.sarif"), "w", encoding="utf-8") as fh:
                json.dump({"version": "2.1.0", "runs": [{
                    "tool": {"driver": {"name": "semgrep", "rules": []}},
                    "results": results}]}, fh)
            manifest = os.path.join(root, "manifest.json")
            with open(manifest, "w", encoding="utf-8") as fh:
                json.dump({"selected": ["semgrep"], "produced": ["semgrep"],
                           "missing": []}, fh)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                rc = gate.main(["--tools-dir", tools, "--manifest", manifest])
        line = buf.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("3 suppressed", line)
        self.assertIn("vendored (vendor: 1)", line)
        self.assertIn("virtualenv-by-name (venv: 1)", line)
        self.assertIn("fixture-corpus (fixture-corpus: 1)", line)
        self.assertIn("NOT gated", line)


def _delta_result(rule="dangerous-subprocess-use-audit", uri="/src/app.py",
                  line=1, message="found subprocess function with user input",
                  level="error"):
    """One SARIF result, every field of the delta identity separately settable."""
    return {"ruleId": rule, "level": level, "message": {"text": message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line}}}]}


def _delta_sarif(*results, tool="semgrep"):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": tool, "rules": []}},
        "results": list(results)}]}


class TestTheDeltaAwareGate(unittest.TestCase):
    """#1790 owner ruling 2026-09-23: what a PRE-MERGE gate is entitled to fail on.

    The strict gate answers one question -- does this tree carry a
    HIGH/CRITICAL tool finding -- and on an already-scanned repository that is
    the wrong question. `#1790`'s severity fix promotes 24 findings on this
    repo's own tree, every one of them already read and dismissed by the owner
    on GitHub's Security tab, so a strict gate would fail every PR from the
    moment it merged, forever, over a standing set nobody disputes and nobody
    can clear by editing their own diff.

    `--baseline-dir` makes the gate DELTA-aware: the base commit's own capture
    (uploaded by `security.yml` on every push to main) is ingested through the
    same call with the same flags, and a head finding that matches one of its
    findings is reported as pre-existing instead of counted. The standing set
    stays governed by what already governs it -- the post-merge zero-alert
    audit (`scripts/code_scanning_audit.py`) and the owner's own
    dismissals. A NEW HIGH/CRITICAL still fails the merge, which is the whole
    point of the gate.
    """

    def _capture(self, root, name, payloads):
        """A `<root>/<name>/` laid out the way the CI artifact is."""
        base = os.path.join(root, name)
        tools = os.path.join(base, "panopticon-tools-output")
        os.makedirs(tools)
        for tool, doc in payloads.items():
            suffix = "json" if tool == "osv-scanner" else "sarif"
            with open(os.path.join(tools, "%s.%s" % (tool, suffix)), "w",
                      encoding="utf-8") as fh:
                json.dump(doc, fh)
        manifest = os.path.join(base, "panopticon-tools-manifest.json")
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump({"selected": sorted(payloads), "produced": sorted(payloads),
                       "missing": []}, fh)
        return tools, manifest

    def _run(self, head, baseline=None, extra=()):
        """(rc, stdout, stderr) from `main`, with or without a baseline."""
        argv = ["--tools-dir", head[0], "--manifest", head[1]]
        if baseline is not None:
            argv += ["--baseline-dir", baseline[0],
                     "--baseline-manifest", baseline[1]]
        argv += list(extra)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = gate.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_a_finding_the_base_commit_already_had_does_not_gate(self):
        with tempfile.TemporaryDirectory() as root:
            same = _delta_sarif(_delta_result())
            head = self._capture(root, "head", {"semgrep": same})
            base = self._capture(root, "base", {"semgrep": same})
            rc, out, _err = self._run(head, base)
        self.assertEqual(rc, 0, out)
        self.assertIn("0 HIGH/CRITICAL new", out)
        self.assertIn("1 HIGH/CRITICAL pre-existing", out)

    def test_it_is_listed_under_a_heading_that_says_what_governs_it(self):
        with tempfile.TemporaryDirectory() as root:
            same = _delta_sarif(_delta_result())
            head = self._capture(root, "head", {"semgrep": same})
            base = self._capture(root, "base", {"semgrep": same})
            _rc, out, _err = self._run(head, base)
        self.assertIn("pre-existing (in the base commit's scan; governed by "
                      "the post-merge audit and GitHub dismissals)", out)
        # The same row shape as a gating finding: nothing about a pre-existing
        # finding is harder to read than the one that failed the build.
        self.assertRegex(out, r"HIGH SG-\d+ app\.py:1 - found subprocess")

    def test_a_finding_the_base_commit_did_not_have_still_fails_the_merge(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result(), _delta_result(uri="/src/new.py"))})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result())})
            rc, out, _err = self._run(head, base)
        self.assertEqual(rc, 1)
        self.assertIn("1 HIGH/CRITICAL new", out)
        self.assertIn("1 HIGH/CRITICAL pre-existing", out)
        self.assertIn("new.py:1", out)

    def test_a_second_identical_hit_in_the_same_file_is_new(self):
        # The multiset rule, and the reason identity alone is not enough: a
        # `subprocess.run` added BESIDE a pre-existing one produces a second
        # finding with the same tool, rule, path and message. Each baseline
        # finding may excuse at most one head finding, so the second gates.
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result(line=1), _delta_result(line=40))})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result(line=1))})
            rc, out, _err = self._run(head, base)
        self.assertEqual(rc, 1)
        self.assertIn("1 HIGH/CRITICAL new", out)
        self.assertIn("1 HIGH/CRITICAL pre-existing", out)

    def test_a_line_shift_does_not_break_a_match(self):
        # Lines are deliberately NOT part of the identity: an unrelated edit
        # above a finding moves every line below it, and a gate that called
        # those NEW would fail on a diff that did not touch them.
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result(line=93))})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result(line=7))})
            rc, out, _err = self._run(head, base)
        self.assertEqual(rc, 0, out)
        self.assertIn("1 HIGH/CRITICAL pre-existing", out)

    def test_the_container_mount_prefix_does_not_break_a_match(self):
        # Semgrep writes `/src/app.py` (the container mount) and bandit writes
        # `app.py`; ingest normalizes both. Matching on INGESTED findings is
        # what makes the two spellings one identity -- raw SARIF would not.
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result(uri="app.py"))})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result(uri="/src/app.py"))})
            rc, out, _err = self._run(head, base)
        self.assertEqual(rc, 0, out)
        self.assertIn("1 HIGH/CRITICAL pre-existing", out)

    def test_a_different_message_at_the_same_place_is_a_different_finding(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result(message="found subprocess function with $TAINTED"))})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result())})
            rc, out, _err = self._run(head, base)
        self.assertEqual(rc, 1)
        self.assertIn("1 HIGH/CRITICAL new", out)
        self.assertIn("0 HIGH/CRITICAL pre-existing", out)

    def test_a_different_rule_at_the_same_place_is_a_different_finding(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result(rule="hooks-path-traversal-python"))})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result())})
            rc, _out, _err = self._run(head, base)
        self.assertEqual(rc, 1)

    def test_the_same_finding_from_a_different_tool_is_a_different_finding(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"bandit": _delta_sarif(
                _delta_result(), tool="bandit")})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result())})
            rc, _out, _err = self._run(head, base)
        self.assertEqual(rc, 1)

    def test_whitespace_in_a_message_is_collapsed_before_matching(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result(message="found subprocess\n  function with user input"))})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result(message="found subprocess function with user input"))})
            rc, out, _err = self._run(head, base)
        self.assertEqual(rc, 0, out)

    def test_a_suppressed_critical_the_baseline_had_is_pre_existing(self):
        # Policy C's population is the one the delta applies to: under redteam
        # a CRITICAL under `vendor/` reaches the gate, and it may be excused
        # for the same reason any other pre-existing finding is.
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"osv-scanner": _critical_osv()})
            base = self._capture(root, "base", {"osv-scanner": _critical_osv()})
            rc, out, _err = self._run(head, base, ("--security", "redteam"))
        self.assertEqual(rc, 0, out)
        self.assertIn("1 HIGH/CRITICAL pre-existing", out)

    def test_a_suppressed_critical_the_baseline_did_not_have_gates(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"osv-scanner": _critical_osv()})
            base = self._capture(root, "base", {"osv-scanner": {"results": []}})
            rc, out, _err = self._run(head, base, ("--security", "redteam"))
        self.assertEqual(rc, 1)
        self.assertIn("1 HIGH/CRITICAL new", out)

    def test_a_missing_baseline_directory_runs_strict_and_says_why(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result())})
            absent = (os.path.join(root, "gone", "panopticon-tools-output"),
                      os.path.join(root, "gone", "panopticon-tools-manifest.json"))
            rc, out, err = self._run(head, absent)
        self.assertEqual(rc, 1, out)          # strict: the finding gates
        self.assertIn("security-gate: baseline unusable", err)
        self.assertIn("1 HIGH/CRITICAL", out)
        self.assertNotIn("pre-existing", out)

    def test_a_malformed_baseline_manifest_runs_strict_and_says_why(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result())})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result())})
            with open(base[1], "w", encoding="utf-8") as fh:
                fh.write("{not json")
            rc, out, err = self._run(head, base)
        self.assertEqual(rc, 1, out)
        self.assertIn("security-gate: baseline unusable", err)
        self.assertNotIn("pre-existing", out)

    def test_an_inconsistent_baseline_manifest_runs_strict_and_says_why(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result())})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result())})
            with open(base[1], "w", encoding="utf-8") as fh:
                json.dump({"selected": ["semgrep"], "produced": [],
                           "missing": []}, fh)
            rc, _out, err = self._run(head, base)
        self.assertEqual(rc, 1)
        self.assertIn("security-gate: baseline unusable", err)

    def test_the_baseline_note_is_one_line(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result())})
            absent = (os.path.join(root, "gone", "panopticon-tools-output"),
                      os.path.join(root, "gone", "panopticon-tools-manifest.json"))
            _rc, _out, err = self._run(head, absent)
        self.assertEqual(
            [line for line in err.splitlines() if "baseline" in line].__len__(), 1,
            err)

    def test_the_baseline_directory_requires_its_manifest(self):
        # The default `<dir>/../panopticon-tools-manifest.json` is NOT assumed:
        # a gate that guesses where the baseline manifest is would silently
        # read the WRONG scan's manifest on any layout but the one it expects.
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result())})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result())})
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    gate.main(["--tools-dir", head[0], "--manifest", head[1],
                               "--baseline-dir", base[0]])
        self.assertEqual(caught.exception.code, 2)

    def test_without_the_flag_the_verdict_line_is_the_one_it_always_was(self):
        # The strict path is byte-identical, not merely equivalent: every
        # other caller of this gate reads that line.
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result())})
            rc, out, _err = self._run(head)
        self.assertEqual(rc, 1)
        self.assertEqual(out.splitlines()[0],
                         "Ingested 1 non-excluded tool findings; 1 HIGH/CRITICAL")

    def test_with_the_flag_the_line_carries_both_counts_and_the_old_note(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result(), _delta_result(uri="/src/new.py"))})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result())})
            _rc, out, _err = self._run(head, base)
        self.assertEqual(out.splitlines()[0],
                         "Ingested 2 non-excluded tool findings; "
                         "1 HIGH/CRITICAL new; 1 HIGH/CRITICAL pre-existing")

    def test_a_coverage_failure_on_the_head_still_exits_two(self):
        # Exit codes are unchanged, and the HEAD is the only side that can
        # raise one: a baseline is an excuse to count LESS, never a reason to
        # refuse to answer.
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result())})
            with open(head[1], "w", encoding="utf-8") as fh:
                json.dump({"selected": ["semgrep", "trivy"],
                           "produced": ["semgrep"], "missing": ["trivy"]}, fh)
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result())})
            rc, _out, err = self._run(head, base)
        self.assertEqual(rc, 2)
        self.assertIn("trivy: no output", err)

    def test_the_baseline_is_ingested_with_the_heads_own_exclusions(self):
        # One definition of "a finding" on both sides. An `--exclude` that
        # applied to the head but not the baseline would leave the baseline
        # carrying findings the head can never produce -- harmless -- while the
        # reverse silently excuses a head finding the operator never scoped
        # out. The same call, the same globs, the same mode.
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result(uri="/src/tests/fixtures/evil.py"))})
            base = self._capture(root, "base", {"semgrep": _delta_sarif()})
            rc, out, _err = self._run(head, base,
                                      ("--exclude", "tests/fixtures/**"))
        self.assertEqual(rc, 0, out)
        self.assertIn("0 HIGH/CRITICAL new", out)
        self.assertIn("1 excluded by --exclude", out)

    def test_a_medium_is_neither_new_nor_pre_existing(self):
        # The delta splits the GATE population and nothing else: a finding
        # below the floor was never counted and does not become countable by
        # being absent from the baseline.
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result(level="note"))})
            base = self._capture(root, "base", {"semgrep": _delta_sarif()})
            rc, out, _err = self._run(head, base)
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.splitlines()[0],
                         "Ingested 1 non-excluded tool findings; "
                         "0 HIGH/CRITICAL new; 0 HIGH/CRITICAL pre-existing")

    # --- fix round 1, I2: an unusable baseline is strict AND audible --------
    #
    # The `isdir` check was the only structural one, and everything past it is
    # tolerant by design: `_capped_output_files` swallows `PermissionError` and
    # returns no files, the SARIF parse skips a file it cannot read rather than
    # raising, and `load_manifest` validates a manifest's INTERNAL consistency
    # without ever asking whether the scan behind it delivered. So three
    # different broken baselines all produced an empty pool, `delta=True`, a
    # verdict line asserting `0 HIGH/CRITICAL pre-existing`, and no stderr line
    # at all. Strict, and therefore not a bypass -- but silently strict, and
    # the line misreported a delta that had not been applied.

    def test_a_baseline_whose_scanner_wrote_garbage_is_unusable(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result())})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result())})
            with open(os.path.join(base[0], "semgrep.sarif"), "w",
                      encoding="utf-8") as fh:
                fh.write("{not json")
            rc, out, err = self._run(head, base)
        self.assertEqual(rc, 1, out)
        self.assertIn("security-gate: baseline unusable", err)
        self.assertIn("semgrep", err)
        self.assertNotIn("pre-existing", out)

    def test_a_baseline_missing_an_adapter_it_selected_is_unusable(self):
        # The review's second probe: a manifest that is internally consistent
        # (`selected == produced`, `missing` empty) while the output file for
        # that adapter is simply not there. `load_manifest` cannot see it --
        # only the ingest's own dispositions can, which is what
        # `lost_required_coverage` reads.
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result())})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result())})
            os.remove(os.path.join(base[0], "semgrep.sarif"))
            rc, out, err = self._run(head, base)
        self.assertEqual(rc, 1, out)
        self.assertIn("security-gate: baseline unusable", err)
        self.assertIn("semgrep: no output", err)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                     "root reads a 0o000 directory regardless of its mode")
    def test_an_unreadable_baseline_directory_is_unusable(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"semgrep": _delta_sarif(
                _delta_result())})
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result())})
            os.chmod(base[0], 0o000)
            try:
                rc, out, err = self._run(head, base)
            finally:
                os.chmod(base[0], 0o755)
        self.assertEqual(rc, 1, out)
        self.assertIn("security-gate: baseline unusable", err)
        self.assertNotIn("pre-existing", out)

    def test_a_usable_baseline_says_nothing_on_stderr_about_being_unusable(self):
        # The oracle for the three above: the note fires on a broken baseline
        # and only on a broken one.
        with tempfile.TemporaryDirectory() as root:
            same = _delta_sarif(_delta_result())
            head = self._capture(root, "head", {"semgrep": same})
            base = self._capture(root, "base", {"semgrep": same})
            rc, _out, err = self._run(head, base)
        self.assertEqual(rc, 0)
        self.assertNotIn("baseline unusable", err)

    def test_a_baseline_finding_under_an_excluded_glob_is_not_in_the_pool(self):
        # M7: the mutant this kills replaces `exclude_globs=exclude_globs or []`
        # with `exclude_globs=[]` in `load_baseline`. Today identity is
        # path-keyed, so an excluded baseline finding can only ever match an
        # excluded head finding and the mutant is equivalent -- but the name of
        # `test_the_baseline_is_ingested_with_the_heads_own_exclusions` and the
        # docstring under it both claim the baseline is scoped, and nothing
        # measured it. Read off `load_baseline` directly, because the claim is
        # about the POOL and not about a verdict that happens to agree.
        # `vendored/**` rather than the CI globs: a path the operator scoped
        # out and NOTHING else did, so the only thing that can drop it from the
        # pool is `exclude_globs` reaching `ingest_dir_detailed`. Under
        # `tests/fixtures/**` the name-based fixture rule drops it anyway and
        # the assertion would hold with the argument deleted.
        with tempfile.TemporaryDirectory() as root:
            base = self._capture(root, "base", {"semgrep": _delta_sarif(
                _delta_result(uri="/src/docs/generated/api.py"),
                _delta_result(uri="/src/app.py"))})
            scoped, why_not = gate.load_baseline(
                base[0], base[1], ["docs/generated/**"])
            unscoped, _why = gate.load_baseline(base[0], base[1])
        self.assertIsNone(why_not)
        self.assertEqual(
            sorted((f.get("location") or {}).get("file") for f in scoped),
            ["app.py"])
        self.assertEqual(
            sorted((f.get("location") or {}).get("file") for f in unscoped),
            ["app.py", "docs/generated/api.py"])

    # --- fix round 1, I3: GATED means "this blocks the merge" ---------------

    def test_the_gated_count_agrees_with_the_exit_code_under_a_delta(self):
        # The bug: `0 HIGH/CRITICAL new ... 1 GATED ... rc=0`. GATED has one
        # meaning in this codebase -- this finding blocks the merge -- and a
        # verdict line that contradicts its own exit code is the defect class
        # #1578 and #1740 spent two rounds removing from this very line.
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"osv-scanner": _critical_osv()})
            base = self._capture(root, "base", {"osv-scanner": _critical_osv()})
            rc, out, _err = self._run(head, base, ("--security", "redteam"))
        self.assertEqual(rc, 0, out)
        self.assertIn("0 GATED", out)
        self.assertIn("1 pre-existing, 0 disclosed only", out)

    def test_a_suppressed_critical_the_baseline_lacks_is_gated_and_counted(self):
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {"osv-scanner": _critical_osv()})
            base = self._capture(root, "base", {"osv-scanner": {"results": []}})
            rc, out, _err = self._run(head, base, ("--security", "redteam"))
        self.assertEqual(rc, 1)
        self.assertIn("1 GATED", out)
        self.assertIn("0 pre-existing, 0 disclosed only", out)

    def test_the_three_suppression_counts_always_sum_to_the_suppressed_total(self):
        # GATED + pre-existing + disclosed-only partitions the suppressed set,
        # so no finding can be counted twice or vanish between the three.
        with tempfile.TemporaryDirectory() as root:
            head = self._capture(root, "head", {
                "osv-scanner": _critical_osv(),
                "semgrep": _lint_sarif()})
            base = self._capture(root, "base", {
                "osv-scanner": _critical_osv(),
                "semgrep": _lint_sarif()})
            rc, out, _err = self._run(head, base, ("--security", "redteam"))
        self.assertEqual(rc, 0, out)
        self.assertIn("2 suppressed by directory name", out)
        self.assertIn("0 GATED (CRITICAL/secret, #1578 policy C), "
                      "1 pre-existing, 1 disclosed only, --security redteam", out)


if __name__ == "__main__":
    unittest.main()

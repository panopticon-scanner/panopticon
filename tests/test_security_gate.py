import contextlib
import io
import json
import os
import tempfile
import unittest

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
    """One HIGH under *uri*, optionally tagged with a CWE on its rule.

    `sarif_to_findings` scrapes the CWE out of the rule's `tags`, which is
    exactly the channel `gates_when_suppressed` reads.
    """
    rules = ([{"id": "test.rule", "properties": {"tags": [cwe]}}] if cwe else [])
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": tool, "rules": rules}},
        "results": [{"ruleId": "test.rule", "level": "error",
                     "message": {"text": "hardcoded credential"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": uri},
                         "region": {"startLine": 1}}}]}]}]}


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
        high, suppressed = self._gate({"semgrep": _secret_sarif()})
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
        for name, payload in (("lint", {"semgrep": _secret_sarif()}),
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
                    {"semgrep": _secret_sarif(uri="app/lib/patched_auth.rb")},
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


if __name__ == "__main__":
    unittest.main()

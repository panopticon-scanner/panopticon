import json
import os
import unittest
from unittest import mock

from _test_helpers import FakePopen, first, only
import scripts.tools.base as base
import scripts.tools.legacy_sarif as legacy
import scripts.tools.sarif_utils as su
from scripts.tools import ADAPTERS
from .conftest import assert_scratch_cwd, scratch_cwd_recorder


SARIF = {
    "runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "sql-injection", "properties": {"tags": ["CWE-89"]}}]}},
        "results": [{
            "ruleId": "sql-injection", "level": "error",
            "message": {"text": "SQL injection"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "app/db.py"},
                "region": {"startLine": 42}}}]}]}]
}


class TestLegacySarifAdapter(unittest.TestCase):
    def test_parse_returns_findings(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        raw = json.dumps(SARIF).encode("utf-8")
        findings = adapter.parse(raw, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:semgrep")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["location"], {"file": "app/db.py", "line_start": 42})
        self.assertTrue(f["id"].startswith("SG-"))
        self.assertIn("CWE-89", f["citations"]["cwe"])

    def test_parse_attaches_tool_provenance(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        raw = json.dumps(SARIF).encode("utf-8")
        findings = adapter.parse(raw, "g1")
        self.assertEqual(len(findings), 1)
        prov = findings[0].get("provenance")
        self.assertIsNotNone(prov)
        self.assertEqual(prov["discovered_by"], "tool:semgrep")
        self.assertEqual(prov["confirmation_status"], "TOOL")

    def test_invoke_runs_tool_command(self):
        adapter = legacy.LegacySarifAdapter("bandit")
        mock_stdout = json.dumps(SARIF).encode("utf-8")
        calls = []
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        side_effect=scratch_cwd_recorder(
                            calls, stdout=mock_stdout, returncode=1)):
            stdout, rc = adapter.invoke("/some/target")
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, mock_stdout)
        launch = only(calls, "bandit launch")
        self.assertIn("/some/target", launch["argv"])
        # #1877: every legacy tool but gosec names its scan root on argv and
        # runs from a scratch, so cwd-relative config is isolated. Gitleaks
        # still reads source-root `.gitleaksignore` independently.
        assert_scratch_cwd(self, launch, "/some/target")

    def test_invoke_runs_gosec_in_target_directory(self):
        adapter = legacy.LegacySarifAdapter("gosec")
        with mock.patch("scripts.tools.base.subprocess.Popen") as popen_mock:
            popen_mock.return_value = FakePopen(
                stdout=b"{}", stderr=b"", returncode=0)
            adapter.invoke("/go/project")
        called_args, called_kwargs = popen_mock.call_args
        # The ONE documented exception (#1877): gosec's argv is the
        # cwd-relative go package pattern `./...`, so the module root has to
        # be the working directory.
        self.assertEqual(called_kwargs.get("cwd"), "/go/project")
        self.assertNotIn("/src", first(called_args))

    def test_invoke_raises_not_implemented_for_unknown_tool(self):
        adapter = legacy.LegacySarifAdapter("unknown")
        with self.assertRaises(NotImplementedError):
            adapter.invoke(".")

    def test_prefix_defaults_to_tl_for_unknown_tool(self):
        adapter = legacy.LegacySarifAdapter("unknown")
        self.assertEqual(adapter.prefix, "TL")

    def test_registry_contains_legacy_adapters(self):
        for name in ("semgrep", "bandit", "trivy", "gitleaks", "gosec"):
            self.assertIn(name, ADAPTERS)
            self.assertIsInstance(ADAPTERS[name], legacy.LegacySarifAdapter)
            self.assertEqual(ADAPTERS[name].name, name)
        self.assertNotIn("eslint", ADAPTERS)

    def test_semgrep_argv_has_offline_flags(self):
        expected = ["semgrep", "scan", "--config", "/opt/semgrep-rules",
                    "--metrics=off", "--disable-version-check",
                    "--sarif", "--quiet", "/src"]
        self.assertEqual(legacy.TOOL_CMD["semgrep"], expected)

    def test_semgrep_argv_suppresses_both_call_home_paths(self):
        # They are separate calls: --metrics=off does not stop the version
        # check, and in a --network none container that check blocks until it
        # times out (measured 2m10s -> 35s on one trivial file).
        argv = legacy.TOOL_CMD["semgrep"]
        self.assertIn("--metrics=off", argv)
        self.assertIn("--disable-version-check", argv)

    def test_trivy_argv_has_offline_flags(self):
        expected = ["trivy", "fs", "--skip-db-update", "--offline-scan",
                    "--format", "sarif", "/src"]
        self.assertEqual(legacy.TOOL_CMD["trivy"], expected)

    def test_gitleaks_argv_redacts_in_the_scanner(self):
        # #1639 P11 ruling 2: scanner-native redaction where it exists. gitleaks
        # masks the matched secret in its OWN report, so the credential never
        # leaves the container -- and it keeps the evidence panopticon actually
        # ingests. v8.18.4 (the Dockerfile pin, ARG GITLEAKS_VERSION=8.18.4):
        #   cmd/root.go   rootCmd.PersistentFlags().Uint("redact", 0, "redact
        #                 secrets from logs and stdout...") with
        #                 rootCmd.Flag("redact").NoOptDefVal = "100", read back
        #                 as `detector.Redact, err = cmd.Flags().GetUint("redact")`
        #                 -- a persistent flag, so `detect` inherits it, and the
        #                 bare form means 100%% (no `=value`, which an older
        #                 Bool spelling would reject).
        #   report/finding.go  func (f *Finding) Redact(percent uint) rewrites
        #                 Line, Match and Secret ONLY; RuleID, File, StartLine
        #                 and the rest are untouched.
        #   report/sarif.go    maps Secret -> region.snippet.text and
        #                 RuleID/File -> ruleId, message.text, physicalLocation,
        #                 so what is masked is exactly the snippet.
        # This is defence in depth, not a replacement: _redact_capture still
        # runs over every capture, including gitleaks'.
        argv = legacy.TOOL_CMD["gitleaks"]
        self.assertIn("--redact", argv)
        self.assertNotIn("--redact=100", argv)   # bare form: NoOptDefVal is 100

    def test_gitleaks_argv_is_pinned_whole(self):
        expected = ["gitleaks", "detect", "--no-git", "--source", "/src",
                    "--report-format", "sarif", "--report-path", "/dev/stdout",
                    "--no-banner", "--redact"]
        self.assertEqual(legacy.TOOL_CMD["gitleaks"], expected)

    def test_bandit_argv_has_noise_suppression_flags(self):
        argv = legacy.TOOL_CMD["bandit"]
        self.assertIn("-s", argv)
        self.assertIn("B101,B404,B110,B112", argv)

    def test_parse_malformed_json_raises(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        with self.assertRaises(json.JSONDecodeError):
            adapter.parse(b"{not valid sarif", "g1")

    def test_parse_empty_runs_returns_empty(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        findings = adapter.parse(json.dumps({"runs": []}).encode(), "g1")
        self.assertEqual(findings, [])

    def test_parse_empty_results_returns_empty(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        sarif = {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}},
                           "results": []}]}
        findings = adapter.parse(json.dumps(sarif).encode(), "g1")
        self.assertEqual(findings, [])

    def test_parse_missing_result_fields_returns_finding(self):
        # SARIF results with minimal fields should still produce a finding,
        # defaulting severity and tolerating absent locations (#1196).
        adapter = legacy.LegacySarifAdapter("semgrep")
        sarif = {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}},
                           "results": [{"ruleId": "bare-rule"}]}]}
        findings = adapter.parse(json.dumps(sarif).encode(), "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        # #run10 COD-C3A: a location-less result keeps the SAME key shape as a
        # located one (empty values, not a missing `file` key), so every consumer
        # that reads location.file sees one shape. Was a bare {}.
        self.assertEqual(findings[0]["location"], {"file": "", "line_start": None})
        self.assertIn("file", findings[0]["location"])

    def test_parse_unknown_level_defaults_to_warning(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        sarif = {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}},
                           "results": [{"ruleId": "weird", "level": "banana"}]}]}
        findings = adapter.parse(json.dumps(sarif).encode(), "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")


class TestGitleaksSuppressionPosture(unittest.TestCase):
    """#1839 (run-14 SEC-284952751): two kinds of in-tree suppression, two rules.

    An inline suppression COMMENT (`gitleaks:allow`) is in the target's SOURCE,
    and under `standard` -- an operator scanning their own repository -- it is
    their reviewed, in-diff decision, so it is HONOURED and the manifest says
    so. This repository's own CI (`security.yml` and the fork-PR
    `security-fork.yml`) scans in `redteam` (#2125), so nothing target-authored
    is honoured on either check. Under `--security redteam` the reviewed tree is
    untrusted and the comment buys nothing.

    The other kind, the source-root `.gitleaksignore`, is NOT this PR's and is
    not this test's either: #1957 owns that measurement and #1924 owns the row.
    What is pinned below is only what these launches carry.
    """

    def _launch(self, **kwargs):
        calls = []
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        side_effect=scratch_cwd_recorder(calls)):
            legacy.LegacySarifAdapter("gitleaks").invoke("/some/target", **kwargs)
        return only(calls, "gitleaks launch")

    def test_no_ignore_path_flag_is_passed_in_either_mode(self):
        # What this pins: our argv carries no `--gitleaks-ignore-path`, in
        # either mode. WHY it carries none is #1957's measurement, and the row
        # is #1924's (see `legacy_sarif.invoke`).
        for mode in ("standard", "redteam"):
            with self.subTest(mode=mode):
                argv = self._launch(security_mode=mode)["argv"]
                self.assertNotIn("--gitleaks-ignore-path", argv)
                self.assertNotIn("-i", argv)

    def test_an_inline_allow_is_ignored_under_redteam(self):
        self.assertIn("--ignore-gitleaks-allow",
                      self._launch(security_mode="redteam")["argv"])

    def test_an_inline_allow_is_honoured_under_standard(self):
        self.assertNotIn("--ignore-gitleaks-allow",
                         self._launch(security_mode="standard")["argv"])

    def test_the_default_mode_is_standard(self):
        # A caller that names no mode gets the conservative one, the same
        # default `run_tools --security` and `partition_venv_dirs` take.
        self.assertNotIn("--ignore-gitleaks-allow", self._launch()["argv"])

    def test_the_adapter_declares_that_it_reads_the_mode(self):
        # `_run_adapter` hands the keyword only to adapters that declare it.
        self.assertTrue(legacy.LegacySarifAdapter("gitleaks").reads_security_mode)

    def test_the_mode_grows_no_flag_on_any_other_tool_here(self):
        # semgrep's and bandit's suppression flags are appended by the
        # DISPATCHER (`run_tools._with_suppression_flags`), which builds their
        # argv; nothing here may add a second copy, and trivy/gosec take none.
        for tool in ("semgrep", "bandit", "trivy"):
            with self.subTest(tool=tool):
                calls = []
                with mock.patch("scripts.tools.base.subprocess.Popen",
                                side_effect=scratch_cwd_recorder(calls)):
                    legacy.LegacySarifAdapter(tool).invoke(
                        "/some/target", security_mode="redteam")
                argv = only(calls, "%s launch" % tool)["argv"]
                self.assertEqual(argv, [("/some/target" if a == "/src" else a)
                                        for a in legacy.TOOL_CMD[tool]])


GOLDEN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "goldens", "tool-raw")


def _golden(name):
    """The committed capture of real `name` output (tests/goldens/tool-raw)."""
    with open(os.path.join(GOLDEN_DIR, "%s.raw" % name), "rb") as fh:
        return fh.read()


class TestSecretAdapterSeverityIsNormalized(unittest.TestCase):
    """#1578 fix round 1 (review C1): a leaked secret has no lesser grade.

    Real gitleaks SARIF carries NO `level` on its results and no
    `defaultConfiguration` on its rules, so `LEVEL_TO_SEV`'s "warning" default
    graded every committed credential MEDIUM -- below
    `security_gate.GATE_SEVERITIES`, which meant the CI gate could not fail on
    ANY gitleaks finding, suppressed or not. `sarif_utils.SECRET_ADAPTERS` now
    normalises the adapters whose output is credentials by construction.

    Driven by the committed capture, never a hand-built SARIF with an invented
    `level`: per tests/goldens/tool-raw/README.md, the contract is that the
    parser handles what the tool genuinely emits, and a fixture that supplies
    the missing field is a fixture that cannot see this defect.
    """

    def test_the_capture_really_omits_the_level_this_test_is_about(self):
        # Non-vacuity, first: if a refreshed golden ever starts carrying
        # `level`, the assertion below stops proving the normalization.
        sarif = json.loads(_golden("gitleaks"))
        run = only(sarif["runs"])
        self.assertTrue(run["results"], "the gitleaks golden holds no results")
        for res in run["results"]:
            self.assertNotIn("level", res)
        for rule in run["tool"]["driver"]["rules"]:
            self.assertNotIn("defaultConfiguration", rule)

    def test_every_real_gitleaks_finding_is_high(self):
        findings = ADAPTERS["gitleaks"].parse(_golden("gitleaks"), "g1")
        self.assertEqual(len(findings), 3)
        self.assertEqual([f["severity"] for f in findings], ["HIGH"] * 3)

    def test_the_normalization_is_scoped_to_the_secret_adapters(self):
        # bandit's capture grades itself, and must keep doing so -- the rule is
        # "this adapter's findings are secrets", not "raise everything".
        findings = ADAPTERS["bandit"].parse(_golden("bandit"), "g1")
        self.assertTrue(findings)
        self.assertTrue({f["severity"] for f in findings} - {"HIGH"},
                        "bandit's own grades were flattened too")


class TestCweFromSarifRelationships(unittest.TestCase):
    """#1578 fix round 1 (review I1): gosec files its CWE where nothing looked.

    `sarif_to_findings` scrapes CWEs out of the rule id, the rule's
    `properties.tags` and the result's `properties` -- which covers bandit
    (`external/cwe/cwe-259`) and semgrep (`CWE-798: ...`) and missed gosec
    entirely: its tags are `["security", "HIGH"]` and the CWE sits at
    `relationships[].target.id` as a bare number under the `CWE` toolComponent.
    So every gosec finding reached the report with no citation, and G101
    ("Potential hardcoded credentials", CWE-798) was invisible to the
    secret-class gate rule -- on the ecosystem whose `vendor/` is THE canonical
    vendoring directory.
    """

    def _by_rule(self):
        return {(f.get("tool_evidence") or {}).get("rule_id"): f
                for f in ADAPTERS["gosec"].parse(_golden("gosec"), "g1")}

    def test_the_capture_hides_its_cwe_from_the_tag_scrape(self):
        # Non-vacuity: the tags really do carry no CWE, so the assertions below
        # pin the relationships channel and not a second path to the same tag.
        sarif = json.loads(_golden("gosec"))
        rules = only(sarif["runs"])["tool"]["driver"]["rules"]
        for rule in rules:
            tags = " ".join(str(t) for t in (rule.get("properties") or {}).get("tags") or [])
            self.assertNotIn("CWE", tags.upper(), rule.get("id"))

    def test_gosecs_hardcoded_credential_rule_cites_cwe_798(self):
        self.assertIn("CWE-798",
                      self._by_rule()["G101"]["citations"]["cwe"])

    def test_the_other_rules_citations_come_through_too(self):
        self.assertIn("CWE-190", self._by_rule()["G115"]["citations"]["cwe"])

    def test_a_relationship_to_another_taxonomy_is_ignored(self):
        rule = {"relationships": [
            {"target": {"id": "798", "toolComponent": {"name": "OWASP"}}},
            {"target": {"id": "259", "toolComponent": {"name": "CWE"}}},
            {"target": {"id": "not-a-number", "toolComponent": {"name": "CWE"}}},
            {"target": "junk"},
            "junk"]}
        self.assertEqual(su.relationship_cwes(rule), ["CWE-259"])

    def test_a_rule_with_no_relationships_contributes_nothing(self):
        for rule in ({}, {"relationships": None}, {"relationships": "junk"},
                     # A SCALAR raised `TypeError` through `or []` until fix
                     # round 2, and `sarif_to_findings` swallowed it by
                     # dropping every result that cited the rule.
                     {"relationships": 5}, {"relationships": True}, "junk"):
            with self.subTest(rule=rule):
                self.assertEqual(su.relationship_cwes(rule), [])


class TestLegacySarifIsApplicable(unittest.TestCase):
    def test_is_always_applicable(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        self.assertTrue(adapter.is_applicable("/any/path"))
        self.assertTrue(adapter.is_applicable("/another/path"))


if __name__ == "__main__":
    unittest.main()


class TestScannerRuleTagsOutrankTheSarifLevel(unittest.TestCase):
    """#1790 (review of the #1964 split, Minor 1): a scanner's own grade wins.

    gosec writes `level: error` on every result -- that is its SARIF envelope,
    not its opinion -- and puts its opinion in the rule tags (`HIGH`, `MEDIUM`,
    `LOW`). Before #1790 the envelope won and a MEDIUM-tagged rule (G112, G301,
    G304, G124 in real gosec output) graded HIGH. Now the tag outranks the
    level, so those grade MEDIUM. Pinned on the real capture's shape, with one
    rule's tag rewritten in memory, because the capture itself holds only
    HIGH-tagged rules -- which the first test proves, so the second cannot pass
    by accident.
    """

    def _sarif(self):
        return json.loads(_golden("gosec"))

    def _fired_rules(self, sarif):
        run = only(sarif["runs"])
        fired = {r["ruleId"] for r in run["results"]}
        return [rule for rule in run["tool"]["driver"]["rules"] if rule["id"] in fired]

    def test_the_capture_is_high_tagged_and_grades_high(self):
        sarif = self._sarif()
        rules = self._fired_rules(sarif)
        self.assertTrue(rules)
        for rule in rules:
            self.assertIn("HIGH", (rule.get("properties") or {}).get("tags") or [], rule.get("id"))
        findings = su.sarif_to_findings(sarif, "gosec", "g1", "GS")
        self.assertTrue(findings)
        for f in findings:
            self.assertEqual("HIGH", f["severity"], f)

    def test_a_medium_tagged_rule_grades_medium_despite_level_error(self):
        sarif = self._sarif()
        run = only(sarif["runs"])
        rule = first(self._fired_rules(sarif))
        rule["properties"]["tags"] = ["security", "MEDIUM"]
        graded = {(f.get("tool_evidence") or {}).get("rule_id"): f["severity"]
                  for f in su.sarif_to_findings(sarif, "gosec", "g1", "GS")}
        self.assertEqual("MEDIUM", graded[rule["id"]])
        self.assertIn("HIGH", graded.values(), "the untouched rules still grade HIGH")
        for res in run["results"]:
            self.assertEqual("error", res.get("level"), "the envelope really says error")


def _suppressed_sarif(*suppressions):
    """Semgrep-shaped SARIF: one suppressed result, one plain control.

    The shape is semgrep 1.177.0's own, measured on the #1839 real-image round:
    a `# nosemgrep`'d finding is REPORTED, carrying
    `"suppressions": [{"kind": "inSource"}]`, and `--disable-nosem` does not
    change that output at the pin. So the argv is not the lever -- the ingest
    is, and this fixture is what the ingest sees in either mode.
    """
    def result(rule, line, suppressions=None):
        res = {"ruleId": rule, "level": "error",
               "message": {"text": rule.replace("-", " ")},
               "locations": [{"physicalLocation": {
                   "artifactLocation": {"uri": "app/%s.py" % rule},
                   "region": {"startLine": line}}}]}
        if suppressions is not None:
            res["suppressions"] = list(suppressions)
        return res
    return {"runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "sql-injection"}, {"id": "weak-hash"}]}},
        "results": [result("sql-injection", 42, suppressions),
                    result("weak-hash", 7)]}]}


class TestAnInSourceSuppressionIsAnIngestDecision(unittest.TestCase):
    """`# nosemgrep` is honoured (or not) where the SARIF is READ (#1839).

    Fix round 1 §B: the pinned scanner marks a nosem-suppressed result and
    reports it anyway, so `--disable-nosem` decides nothing and this converter
    decides everything. Under `standard` an in-source suppression is the
    operator's reviewed decision about their own repository and the result is
    dropped -- counted, never silent. Under `redteam` the tree is untrusted and
    the same result is an ordinary finding.
    """

    def _rules(self, findings):
        return [f["category"] for f in findings]

    def test_standard_drops_the_suppressed_result_and_counts_it(self):
        dropped = []
        findings = su.sarif_to_findings(
            _suppressed_sarif({"kind": "inSource"}), "semgrep", "g1", "SG",
            security_mode="standard", suppressed_in_source=dropped)
        self.assertEqual(["weak-hash"], self._rules(findings))
        self.assertEqual(["sql-injection"], dropped)

    def test_redteam_keeps_it_as_an_ordinary_finding(self):
        dropped = []
        findings = su.sarif_to_findings(
            _suppressed_sarif({"kind": "inSource"}), "semgrep", "g1", "SG",
            security_mode="redteam", suppressed_in_source=dropped)
        self.assertEqual(["sql-injection", "weak-hash"], self._rules(findings))
        self.assertEqual([], dropped)

    def test_a_suppression_the_tool_rejected_never_took_effect(self):
        findings = su.sarif_to_findings(
            _suppressed_sarif({"kind": "inSource", "status": "rejected"}),
            "semgrep", "g1", "SG", security_mode="standard")
        self.assertEqual(["sql-injection", "weak-hash"], self._rules(findings))

    def test_only_the_in_source_kind_is_the_target_s_to_write(self):
        # An `external` suppression comes from a suppression file the SCANNER
        # was given, not from the reviewed repository's source.
        findings = su.sarif_to_findings(
            _suppressed_sarif({"kind": "external"}), "semgrep", "g1", "SG",
            security_mode="standard")
        self.assertEqual(["sql-injection", "weak-hash"], self._rules(findings))

    def test_a_caller_that_names_no_mode_drops_nothing(self):
        # The converter is shared by every SARIF adapter and by callers outside
        # the gate. Naming no mode keeps the pre-#1839 behaviour -- every
        # result ingested -- so a forgotten argument can never silently lose a
        # finding; `ingest_dir_detailed` is the one that defaults to standard.
        findings = su.sarif_to_findings(
            _suppressed_sarif({"kind": "inSource"}), "semgrep", "g1", "SG")
        self.assertEqual(["sql-injection", "weak-hash"], self._rules(findings))


class TestTheAdapterReadsTheIngestPolicy(unittest.TestCase):
    """`parse` takes (raw, group) and nothing else, so the mode travels the way
    the scanned root does (#1649): a ContextVar the ingest sets around the
    parse it performs. The count travels back through the same dict."""

    def _parse(self, mode):
        policy = {"security_mode": mode, "suppressed_in_source": []}
        token = base.ingest_policy_cv.set(policy)
        try:
            raw = json.dumps(_suppressed_sarif({"kind": "inSource"})).encode()
            findings = legacy.LegacySarifAdapter("semgrep").parse(raw, "g1")
        finally:
            base.ingest_policy_cv.reset(token)
        return findings, policy

    def test_standard_drops_and_reports_the_count_back(self):
        findings, policy = self._parse("standard")
        self.assertEqual(["weak-hash"], [f["category"] for f in findings])
        self.assertEqual(["sql-injection"], policy["suppressed_in_source"])

    def test_redteam_keeps_the_result(self):
        findings, policy = self._parse("redteam")
        self.assertEqual(["sql-injection", "weak-hash"],
                         [f["category"] for f in findings])
        self.assertEqual([], policy["suppressed_in_source"])

    def test_no_policy_set_keeps_the_result(self):
        raw = json.dumps(_suppressed_sarif({"kind": "inSource"})).encode()
        findings = legacy.LegacySarifAdapter("semgrep").parse(raw, "g1")
        self.assertEqual(["sql-injection", "weak-hash"],
                         [f["category"] for f in findings])

"""#3231: an unverified heuristic tool claim, and a coverage-absence claim the driver
cannot confirm, are capped at MEDIUM in the active report -- each disclosed on the
finding (`severity_cap`) and in `meta.severity_capped` -- and nothing else moves."""
import copy
import os
import tempfile
import unittest

import scripts.synth.findings as findings_mod
import scripts.synth.plan as plan_mod
import scripts.synth.render as render_mod
import scripts.synth.report as report_mod
import scripts.synth.severity_cap as severity_cap

TS = "2026-10-30T00:00:00Z"


def _tool(fid="SG-001", sev="HIGH", tool="semgrep", **kw):
    f = {"id": fid, "title": "t %s" % fid, "severity": sev, "confidence": "CERTAIN",
         "panel": "security", "category": "python.lang.best-practice.arbitrary-sleep",
         "source": "tool:%s" % tool, "location": {"file": "app.py", "line_start": 3}}
    f.update(kw)
    return f


def _tst(fid="TS-001", sev="HIGH", file="pkg/mod.py", code="TST-A1A"):
    return {"id": fid, "title": "no test covers %s" % file, "severity": sev,
            "confidence": "LIKELY", "panel": "code", "domain": "TST", "code": code,
            "category": "coverage", "location": {"file": file, "line_start": 1}}


class _Run:
    def __init__(self, root=None, gate_unverified=False):
        self.root, self.target, self.gate_unverified = root, root or "t", gate_unverified


def _ev(f, status):
    f["evidence"] = {"status": status}
    return f


def _tree(files):
    d = tempfile.mkdtemp()
    for rel, text in files.items():
        path = os.path.join(d, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return d


class UnverifiedToolCapTest(unittest.TestCase):
    def _apply(self, findings, **run):
        severity_cap.apply(findings, _Run(**run), [])
        return findings

    def test_an_unverified_heuristic_tool_high_is_capped_and_says_from_what(self):
        for status in ("tool_reported", "needs_more_info"):
            with self.subTest(status=status):
                (f,) = self._apply([_ev(_tool(), status)])
                self.assertEqual("MEDIUM", f["severity"])
                self.assertEqual({"from": "HIGH", "reason": "unverified_tool",
                                  "note": severity_cap.NOTE_UNVERIFIED}, f["severity_cap"])

    def test_a_critical_is_capped_too_and_a_medium_is_left_alone(self):
        crit, med = self._apply([_ev(_tool("A", "CRITICAL"), "tool_reported"),
                                 _ev(_tool("B", "MEDIUM"), "tool_reported")])
        self.assertEqual(("MEDIUM", "CRITICAL"), (crit["severity"], crit["severity_cap"]["from"]))
        self.assertEqual(("MEDIUM", None), (med["severity"], med.get("severity_cap")))

    def test_an_advisor_confirmed_tool_claim_keeps_the_scanner_severity(self):
        (f,) = self._apply([_ev(_tool(), "tool_confirmed")])
        self.assertEqual(("HIGH", None), (f["severity"], f.get("severity_cap")))

    def test_secrets_credentials_and_advisories_are_never_capped(self):
        cases = {
            "gitleaks": _tool(tool="gitleaks"),
            "credential CWE": _tool(citations={"cwe": ["CWE-798"]}),
            "credential CWE, enriched shape": _tool(citations={"cwe": [{"id": "CWE-321"}]}),
            "advisory adapter": _tool(tool="pip-audit"),
            "a CVE from a mixed adapter": _tool(tool="trivy", citations={"cve": ["CVE-2026-1"]}),
        }
        for name, f in cases.items():
            with self.subTest(name):
                self._apply([_ev(f, "tool_reported")])
                self.assertEqual(("HIGH", None), (f["severity"], f.get("severity_cap")))

    def test_the_semgrep_hardcoded_key_rule_survives_by_its_cwe_not_its_rule_id(self):
        # The semgrep golden files hard-coded-credential rules under
        # `ai-best-practices`: a rule-id match would downgrade them.
        f = _tool(category="ai.ai-best-practices.anthropic-hardcoded-api-key-python",
                  citations={"cwe": ["CWE-798"]})
        self._apply([_ev(f, "tool_reported")])
        self.assertEqual("HIGH", f["severity"])

    def test_nothing_is_capped_under_gate_unverified(self):
        (f,) = self._apply([_ev(_tool(), "tool_reported")], gate_unverified=True)
        self.assertEqual(("HIGH", None), (f["severity"], f.get("severity_cap")))

    def test_an_agent_finding_is_never_capped_as_a_tool(self):
        f = _ev(_tool(source="agent:sr"), "needs_more_info")
        self._apply([f])
        self.assertEqual("HIGH", f["severity"])


class CoverageAbsenceCapTest(unittest.TestCase):
    def _apply(self, findings, files, groups):
        root = _tree(files)
        self.addCleanup(__import__("shutil").rmtree, root, True)
        severity_cap.apply(findings, _Run(root=root), groups)
        return findings

    def test_a_module_another_groups_test_imports_is_capped_and_names_it(self):
        files = {"pkg/mod.py": "X = 1\n", "tests/test_driver.py": "import pkg.mod\n"}
        groups = [{"name": "Core", "files": ["pkg/mod.py"]},
                  {"name": "Tests", "files": ["tests/test_driver.py"]}]
        (f,) = self._apply([_tst()], files, groups)
        self.assertEqual("MEDIUM", f["severity"])
        self.assertEqual({"from": "HIGH", "reason": "unconfirmed_coverage_absence",
                          "measured": True, "references": 1,
                          "referenced_by": [{"group": "Tests", "file": "tests/test_driver.py"}],
                          "note": "1 assigned test file(s) name or import this module "
                                  "(referenced_by); HIGH needs a confirmed no-test-anywhere"},
                         f["severity_cap"])

    def test_a_test_named_after_the_module_is_a_witness_too(self):
        files = {"pkg/mod.py": "X = 1\n", "tests/test_mod.py": "pass\n"}
        groups = [{"name": "Core", "files": ["pkg/mod.py", "tests/test_mod.py"]}]
        (f,) = self._apply([_tst()], files, groups)
        self.assertEqual(("MEDIUM", 1), (f["severity"], f["severity_cap"]["references"]))

    def test_high_stays_only_on_a_confirmed_no_test_anywhere(self):
        files = {"pkg/mod.py": "X = 1\n", "tests/test_other.py": "import pkg.other\n",
                 "pkg/other.py": "Y = 2\n"}
        groups = [{"name": "Core", "files": ["pkg/mod.py", "pkg/other.py"]},
                  {"name": "Tests", "files": ["tests/test_other.py"]}]
        (f,) = self._apply([_tst()], files, groups)
        self.assertEqual(("HIGH", None), (f["severity"], f.get("severity_cap")))

    def test_a_non_python_module_cannot_be_confirmed_so_it_is_capped(self):
        (f,) = self._apply([_tst(file="web/app.js")], {"web/app.js": "x\n"},
                           [{"name": "Web", "files": ["web/app.js"]}])
        self.assertEqual("MEDIUM", f["severity"])
        self.assertEqual({"from": "HIGH", "reason": "unconfirmed_coverage_absence",
                          "measured": False, "referenced_by": [],
                          "note": "no-test-anywhere can't be measured for this language"},
                         f["severity_cap"])

    def test_a_confirmed_unmeasurable_finding_says_what_was_and_was_not_confirmed(self):
        # R5: a CONFIRMED finding at MEDIUM must not read as a contradiction.
        f = _ev(_tst(file="web/app.go"), "advisor_confirmed")
        self._apply([f], {"web/app.go": "x\n"}, [{"name": "Web", "files": ["web/app.go"]}])
        self.assertEqual("advisor confirmed within this group; no-test-anywhere can't be "
                         "measured for this language", f["severity_cap"]["note"])

    def test_only_the_untested_units_codes_are_read_never_the_text(self):
        files = {"pkg/mod.py": "X = 1\n", "tests/test_mod.py": "pass\n"}
        groups = [{"name": "Core", "files": ["pkg/mod.py", "tests/test_mod.py"]}]
        other = _tst(code="TST-B3A")
        other["title"] = "pkg/mod.py has zero automated test coverage"
        found = self._apply([_tst(code=c) for c in sorted(severity_cap.COVERAGE_ABSENCE_CODES)]
                            + [other], files, groups)
        self.assertEqual(["MEDIUM"] * 4 + ["HIGH"], [f["severity"] for f in found])

    def test_a_planted_escaping_location_imports_nothing(self):
        files = {"tests/test_x.py": "import os\n"}
        (f,) = self._apply([_tst(file="../outside.py")], files,
                           [{"name": "Tests", "files": ["tests/test_x.py"]}])
        self.assertEqual("HIGH", f["severity"])


class InTheReportTest(unittest.TestCase):
    def _report(self, findings, groups=(), root=None, **run):
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target=root or "t", root=root, fail_on="high",
                                     timestamp=TS, **run),
            findings=findings_mod.FindingSet(findings=copy.deepcopy(findings)),
            plan=plan_mod.PlanInputs(groups_meta=list(groups))))

    def test_meta_lists_the_capped_ids_and_the_report_validates(self):
        report = self._report([_tool("SG-001"), _tool("SG-002", tool="gitleaks")])
        capped = report["meta"]["severity_capped"]
        self.assertEqual(["unverified_tool"], sorted(capped))
        self.assertEqual(1, len(capped["unverified_tool"]))
        self.assertEqual([], report_mod.validate_report(report)[0])
        self.assertIn("**Capped at MEDIUM:** 1 unconfirmed claim(s) (unverified tool 1)",
                      render_mod.render_summary(report))

    def test_a_clean_run_carries_no_disclosure(self):
        report = self._report([_tool(sev="MEDIUM")])
        self.assertNotIn("severity_capped", report["meta"])
        self.assertNotIn("**Capped at MEDIUM:**", render_mod.render_summary(report))

    def test_default_policy_health_grade_and_risk_are_unmoved_by_the_tool_cap(self):
        # The cap reaches only claims the default policy already keeps out of
        # gate_eligible, which is all health, grade and risk read.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "app.py"), "w", encoding="utf-8") as fh:
                fh.write("x = 1\n" * 200)
            groups = [{"name": "App", "files": ["app.py"]}]
            capped = self._report([_tool()], groups, root=d)
            from unittest import mock
            with mock.patch.object(severity_cap, "apply", return_value=0):
                uncapped = self._report([_tool()], groups, root=d)
        self.assertEqual("MEDIUM", capped["findings"][0]["severity"])
        self.assertEqual("HIGH", uncapped["findings"][0]["severity"])
        for key in ("health", "overall_grade", "risk_level", "gate"):
            self.assertEqual(uncapped["summary"].get(key), capped["summary"].get(key), key)

    def test_the_cap_runs_after_the_verdict_quality_step_and_the_evidence(self):
        # Ruling R2: after `codes.apply_verdict_quality` (#3330's range clamp and
        # the override discipline, which may move an agent severity) and after the
        # evidence status it reads is derived; before anything partitions or counts.
        from unittest import mock
        import scripts.synth.codes as codes_mod
        import scripts.synth.verdicts as verdicts_mod
        calls = []

        def spy(name, real):
            def wrapped(*a, **k):
                calls.append(name)
                return real(*a, **k)
            return wrapped

        with mock.patch.object(codes_mod, "apply_verdict_quality",
                               spy("quality", codes_mod.apply_verdict_quality)), \
                mock.patch.object(verdicts_mod, "_derive_evidence",
                                  spy("evidence", verdicts_mod._derive_evidence)), \
                mock.patch.object(severity_cap, "apply", spy("cap", severity_cap.apply)), \
                mock.patch.object(verdicts_mod, "_partition_gate",
                                  spy("partition", verdicts_mod._partition_gate)):
            self._report([_tool()])
        self.assertEqual(["quality", "evidence", "cap", "partition"], calls)

"""Finding reconciliation, schema, and OCRDb validation contracts."""

import contextlib
import io
import os
import json
import tempfile
import unittest
from unittest import mock
import scripts.synthesize as syn
import scripts.synth.findings as findings_mod
import scripts.synth.codes as codes_mod
import scripts.synth.report as report_mod
import scripts.evidence as evidence_mod
import scripts.ocrdb as ocrdb
from tests.synth.helpers import DEFAULT_TIMESTAMP, _chdir, _agentic


class TestReconciliation(unittest.TestCase):
    def test_normalize_backfills_title_category(self):
        f = findings_mod.normalize_finding({"description": "First line.\nSecond", "severity": "LOW"})
        self.assertEqual(f["title"], "First line.")
        self.assertEqual(f["category"], "general")

    def test_normalize_untitled_when_no_description(self):
        f = findings_mod.normalize_finding({"severity": "LOW"})
        self.assertEqual(f["title"], "(untitled)")

    def test_normalize_collapses_multiline_title(self):
        f = findings_mod.normalize_finding(
            {"title": "Package: requests\nInstalled: 2.19.0\nCVE-x", "severity": "MEDIUM"}
        )
        self.assertEqual(f["title"], "Package: requests Installed: 2.19.0 CVE-x")

    def test_main_survives_malformed_citation_and_writes_report(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-g1-SEC.json")
            with open(p, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "SE-001",
                                "title": "crit",
                                "severity": "CRITICAL",
                                "confidence": "CERTAIN",
                                "panel": "security",
                                "category": "x",
                                "source": "agent:sr",
                                "location": {"file": "a", "line_start": 1},
                                "cvss": {"score": 9.0, "vector": "v"},
                                "exploit_scenario": "e",
                            },
                            {
                                "id": "SE-002",
                                "title": "bad",
                                "severity": "LOW",
                                "confidence": "POSSIBLE",
                                "panel": "security",
                                "category": "y",
                                "source": "agent:sr",
                                "location": {"file": "b", "line_start": 2},
                                "citations": {"ssvc": "active"},
                            },
                        ]
                    },
                    fh,
                )
            out = os.path.join(d, "report.json")

            buf = io.StringIO()
            # Isolate cwd: main() discovers .panopticon/scout-*.json relative
            # to cwd, and the repo root's own .panopticon carries self-scan
            # leftovers that would otherwise leak "requested_absent" tools
            # into this fixture's tiny finding set.
            with _chdir(d), contextlib.redirect_stdout(buf):
                rc = syn.main(["--target", "t", "--fail-on", "high", "--out", out, p])
            self.assertTrue(os.path.isfile(out))  # report written despite malformed citation
            # Both findings are agentic and carry no verdict -> unverified,
            # which does not gate by default under the two-axis model.
            self.assertEqual(rc, 0)
            with open(out) as _fh:
                report = json.load(_fh)
            self.assertTrue(any(f["title"] == "crit" for f in report["findings"]))

    def test_validate_returns_errors_and_warnings(self):
        # An ABSENT location is the warning case: the schema leaves `location`
        # optional on a finding, so nothing here is a schema error and the
        # hand check's "where is it?" warning is the whole answer. (#1639 P15:
        # a PARTIAL location -- `{}`, or a line with no file -- is a different
        # case and now errors, see the test below.)
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "CD-001",
                        "title": "t",
                        "severity": "LOW",
                        "confidence": "POSSIBLE",
                        "panel": "code",
                        "category": "general",
                    }
                ],
            ),
        ))
        errors, warnings = report_mod.validate_report(report)
        self.assertEqual(errors, [])
        self.assertTrue(any("location" in w for w in warnings))

    def test_schema_layer_rejects_a_location_with_no_file(self):
        # #1639 P15: the published schema requires `file` on a `location` that
        # is present at all, and validate_report never loaded it -- so a
        # finding pointing at nowhere passed with a warning nobody had to
        # read. The hand check still warns; the schema now also errors, and
        # both land in the same list.
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "CD-001",
                        "title": "t",
                        "severity": "LOW",
                        "confidence": "POSSIBLE",
                        "panel": "code",
                        "category": "general",
                        "location": {},
                    }
                ],
            ),
        ))
        errors, warnings = report_mod.validate_report(report)
        self.assertIn("schema: $.findings[0].location: 'file' is a required property",
                      errors)
        self.assertTrue(any("location" in w for w in warnings))

    def test_validate_reports_the_null_sections_the_hand_checks_missed(self):
        """#1639 P15, Codex's repro: `meta`/`summary`/`cross_panel` all null.

        Every key is PRESENT, so the hand checks' `key not in report` test is
        satisfied and the old validate_report returned no error and no warning
        for a report three of whose five sections are nothing at all. Draft 7
        validation rejects all three, and now so does this."""
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=[]),
        ))
        report["meta"] = None
        report["summary"] = None
        report["cross_panel"] = None
        errors, _warnings = report_mod.validate_report(report)
        for section in ("$.meta", "$.summary", "$.cross_panel"):
            self.assertTrue(
                any(e.startswith("schema: %s:" % section) for e in errors),
                "%s not rejected; got %r" % (section, errors))

    def test_a_null_findings_list_is_reported_not_raised(self):
        # `enumerate(None)` is a TypeError, and the hand checks used to reach
        # it on exactly the shape schema validation exists to describe.
        errors, _warnings = report_mod.validate_report(
            {"meta": {}, "summary": {}, "groups": [], "findings": None,
             "cross_panel": {}})
        self.assertTrue(any("$.findings" in e for e in errors), errors)

    def test_tool_security_finding_exempt_from_cvss(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "TR-001",
                        "title": "t",
                        "severity": "HIGH",
                        "confidence": "CERTAIN",
                        "panel": "security",
                        "category": "general",
                        "source": "tool:trivy",
                        "location": {"file": "a", "line_start": 1},
                    }
                ],
            ),
        ))
        errors, _ = report_mod.validate_report(report)
        self.assertEqual(errors, [])

    def test_four_digit_tool_id_is_valid(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "SG-1000",
                        "title": "t",
                        "severity": "LOW",
                        "confidence": "CERTAIN",
                        "panel": "security",
                        "category": "x",
                        "source": "tool:semgrep",
                        "location": {"file": "a", "line_start": 1},
                    }
                ],
            ),
        ))
        errors, _ = report_mod.validate_report(report)
        self.assertFalse(any("id" in e for e in errors))


class TestInternalFieldCleanup(unittest.TestCase):
    def test_build_report_does_not_leak_internal_fields(self):
        # Two findings, not one: f1's REJECTED verdict moves it OUT of
        # report["findings"] and into report["discarded_claims"], so a
        # single-finding fixture leaves exactly one of the two leak-check
        # loops below vacuous no matter which list the finding lands in.
        # f2 carries no verdict and stays in report["findings"], so both
        # lists are guaranteed non-empty and both loops actually run over
        # real data.
        f1 = {
            "id": "SEC-001",
            "title": "SQLi",
            "severity": "HIGH",
            "confidence": "LIKELY",
            "panel": "security",
            "category": "injection",
            "provenance": {"discovered_by": "agent:lens_sweep"},
            "location": {"file": "app.py", "line_start": 10},
            "_group": "backend",
            "_repo_root": "/some/path",
        }
        f2 = {
            "id": "SEC-002",
            "title": "XSS",
            "severity": "MEDIUM",
            "confidence": "LIKELY",
            "panel": "security",
            "category": "xss",
            "provenance": {"discovered_by": "agent:lens_sweep"},
            "location": {"file": "app.py", "line_start": 55},
            "_group": "backend",
            "_repo_root": "/some/path",
        }
        verdicts = {
            evidence_mod.finding_fingerprint(f1): {
                "finding_id": "SEC-001",
                "verdict": "REJECTED",
                "reasoning": "False positive.",
            }
        }
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=[f1, f2], verdicts=verdicts),
        ))
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(len(report.get("discarded_claims", [])), 1)
        for finding in report["findings"]:
            self.assertNotIn("_group", finding)
            self.assertNotIn("_repo_root", finding)
        for finding in report.get("discarded_claims", []):
            self.assertNotIn("_group", finding)
            self.assertNotIn("_repo_root", finding)


class TestSchemaErrorsAreNotSilent(unittest.TestCase):
    def test_report_records_schema_error_count(self):
        bad = _agentic(fid="ag-lower")  # id fails ID_RE
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-03T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[bad]),
        ))
        errors, _ = report_mod.validate_report(report)
        self.assertTrue(errors)
        report_mod.attach_schema_status(report, errors)
        self.assertEqual(report["meta"]["schema_errors"], len(errors))

    def test_clean_report_records_zero(self):
        clean = _agentic(panel="code", category="style", severity="LOW")
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-03T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[clean]),
        ))
        errors, _ = report_mod.validate_report(report)
        report_mod.attach_schema_status(report, errors)
        self.assertEqual(report["meta"]["schema_errors"], 0)


class TestOcrdbValidation(unittest.TestCase):
    """5.0 Slice A Task 3: synthesize auto-loads the OCRDb bundle, stamps
    the version, and validates finding codes against it."""

    def _bundle(self):
        return ocrdb.load_bundle()

    def test_valid_code_kept_and_counted_zero(self):
        b = self._bundle()
        real = ocrdb.domain_menu(b, "SEC")[0]["code"]
        findings = [{"code": real, "domain": "SEC"}]
        cov = codes_mod.validate_finding_codes(findings, b)
        self.assertEqual(findings[0]["code"], real)
        self.assertEqual(cov["invalid_codes"], 0)

    def test_unknown_code_replaced_with_fallback_and_counted(self):
        b = self._bundle()
        findings = [{"code": "SEC-ZZZ", "domain": "SEC"}]
        cov = codes_mod.validate_finding_codes(findings, b)
        self.assertEqual(findings[0]["code"], "SEC-X0X")
        self.assertEqual(cov["invalid_codes"], 1)
        self.assertEqual(cov["fallbacks"].get("SEC"), 1)

    def test_code_without_domain_derives_domain_from_code(self):
        b = self._bundle()
        findings = [{"code": "SEC-ZZZ"}]  # no "domain" key
        cov = codes_mod.validate_finding_codes(findings, b)
        self.assertEqual(findings[0]["code"], "SEC-X0X")  # domain derived via ocrdb.domain_of
        self.assertEqual(cov["invalid_codes"], 1)
        self.assertEqual(cov["fallbacks"].get("SEC"), 1)

    def test_explicit_fallback_counted_as_fallback_not_invalid(self):
        b = self._bundle()
        findings = [{"code": "SEC-X0X", "domain": "SEC"}]
        cov = codes_mod.validate_finding_codes(findings, b)
        self.assertEqual(cov["invalid_codes"], 0)
        self.assertEqual(cov["fallbacks"].get("SEC"), 1)

    def test_bundle_absent_leaves_findings_and_returns_none(self):
        findings = [{"code": "SEC-A1A"}]
        cov = codes_mod.validate_finding_codes(findings, None)
        self.assertIsNone(cov)
        self.assertEqual(findings[0]["code"], "SEC-A1A")  # untouched

    def test_build_report_stamps_ocrdb_version(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[{"title": "t", "severity": "LOW", "code": "SEC-A1A", "domain": "SEC"}],
            ),
        ))
        self.assertEqual(report["meta"]["ocrdb_version"], "0.5.0")
        self.assertIsNotNone(report["meta"]["coverage"]["ocrdb"])

    def test_build_report_bundle_absent_is_null_and_safe(self):
        with mock.patch("scripts.ocrdb.load_bundle", return_value=None):
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
                findings=findings_mod.FindingSet(
                    findings=[{"title": "t", "severity": "LOW", "code": "SEC-A1A", "domain": "SEC"}],
                ),
            ))
        self.assertIsNone(report["meta"]["ocrdb_version"])
        self.assertIsNone(report["meta"]["coverage"]["ocrdb"])
        self.assertEqual(report["findings"][0]["code"], "SEC-A1A")  # untouched, bundle-absent path

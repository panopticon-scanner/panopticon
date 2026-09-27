"""Group rollup, tagging, and summary citation contracts."""

import os
import json
import tempfile
import unittest
import scripts.synth.findings as findings_mod
import scripts.synth.plan as plan_mod
import scripts.synth.report as report_mod
import scripts.synth.render as render_mod
from tests.synth.helpers import DEFAULT_TIMESTAMP, _make_finding


class TestGroupTag(unittest.TestCase):
    def test_test_panel_grade_reflects_test_findings(self):
        # a test-panel finding on a path NOT in group files, tagged by _group.
        # gate_unverified=True: this test verifies _group attribution feeds
        # panel_grades, not the default gating policy (the finding is agentic
        # with no verdict, so it would be excluded from grading otherwise).
        findings = [
            {
                "id": "TS-001",
                "title": "weak test",
                "severity": "HIGH",
                "confidence": "LIKELY",
                "panel": "test",
                "category": "quality",
                "location": {"file": "spec/foo_spec.rb", "line_start": 3},
                "_group": "g1",
            }
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="src",
                fail_on=None,
                timestamp=DEFAULT_TIMESTAMP,
                gate_unverified=True,
            ),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g1", "files": ["app/foo.rb"]}]),
        ))
        self.assertEqual(report["groups"][0]["panel_grades"]["test"], "D")  # not "A"
        # _group scrubbed from emitted findings
        self.assertNotIn("_group", report["findings"][0])


class TestGroupParentRollup(unittest.TestCase):
    """Task 6: report group view rolls subgroups up to their parent
    (group -> subgroup -> file drill-down), byte-identical for flat groups."""

    def test_subgroups_roll_up_to_parent(self):
        findings = [
            _make_finding(
                id="CD-001", severity="HIGH", panel="code",
                location={"file": "src/ui/admin/a.py", "line_start": 1},
                _group="UI:Admin",
            ),
            _make_finding(
                id="CD-002", severity="MEDIUM", panel="code",
                location={"file": "src/ui/components/b.py", "line_start": 1},
                _group="UI:Components",
            ),
        ]
        groups_meta = [
            {"name": "UI:Admin", "files": ["src/ui/admin/a.py"], "parent": "UI"},
            {"name": "UI:Components", "files": ["src/ui/components/b.py"], "parent": "UI"},
        ]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="src",
                fail_on=None,
                timestamp=DEFAULT_TIMESTAMP,
                gate_unverified=True,
            ),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan_mod.PlanInputs(groups_meta=groups_meta),
        ))
        names = [g["name"] for g in report["groups"]]
        self.assertEqual(names, ["UI"])
        ui = report["groups"][0]
        # worst of D (HIGH -> Admin) and C (MEDIUM -> Components)
        self.assertEqual(ui["panel_grades"]["code"], "D")
        sub_names = {s["name"] for s in ui["subgroups"]}
        self.assertEqual(sub_names, {"UI:Admin", "UI:Components"})
        admin = next(s for s in ui["subgroups"] if s["name"] == "UI:Admin")
        components = next(s for s in ui["subgroups"] if s["name"] == "UI:Components")
        self.assertEqual(admin["panel_grades"]["code"], "D")
        self.assertEqual(components["panel_grades"]["code"], "C")
        self.assertEqual(admin["files"], ["src/ui/admin/a.py"])
        self.assertEqual(components["files"], ["src/ui/components/b.py"])
        # both subgroups' files are reachable for file-level drill-down
        self.assertIn("src/ui/admin/a.py", ui["files"])
        self.assertIn("src/ui/components/b.py", ui["files"])
        # The overall letter is health-derived and these files do not exist, so
        # it is unmeasurable here; the per-panel severity rollup asserted above
        # is what this test is actually about.
        self.assertIsNone(report["summary"]["overall_grade"])
        self.assertEqual(report["summary"]["gate"], "OFF")

    def test_flat_self_parented_groups_report_unchanged(self):
        # A flat groups.yml (no subgroups): every group self-parents, and the
        # report's group view must be exactly today's shape -- no "subgroups"
        # key, same fields, same values.
        findings = [_make_finding(severity="HIGH", panel="code")]
        groups_meta = [{"name": "g1", "files": ["a.py"]}]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on="high", timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan_mod.PlanInputs(groups_meta=groups_meta),
        ))
        self.assertEqual(len(report["groups"]), 1)
        g = report["groups"][0]
        self.assertEqual(g["name"], "g1")
        self.assertEqual(g["files"], ["a.py"])
        self.assertEqual(set(g), {"name", "files", "panel_grades", "key_findings"})
        self.assertEqual(g["panel_grades"]["code"], "A")

    def test_flat_groups_with_explicit_self_parent_unchanged(self):
        # Same as above but with an explicit parent==name (as discovery now
        # always writes) -- must still take the leaf/self-parented shape.
        findings = [_make_finding(severity="HIGH", panel="code")]
        groups_meta = [{"name": "g1", "files": ["a.py"], "parent": "g1"}]
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on="high", timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan_mod.PlanInputs(groups_meta=groups_meta),
        ))
        self.assertEqual(len(report["groups"]), 1)
        g = report["groups"][0]
        self.assertEqual(g["name"], "g1")
        self.assertNotIn("subgroups", g)

    def test_load_findings_tags_group_from_filename(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-mygroup-code.json")
            with open(p, "w") as fh:
                json.dump({"findings": [{"severity": "LOW", "panel": "code"}]}, fh)
            out = findings_mod.load_findings([p])
            self.assertEqual(out[0]["_group"], "mygroup")

    def test_load_findings_tags_group_from_new_panel_filenames(self):
        with tempfile.TemporaryDirectory() as d:
            for panel in ["architecture", "database", "redteam"]:
                p = os.path.join(d, "findings-mygroup-%s.json" % panel)
                with open(p, "w") as fh:
                    json.dump({"findings": [{"severity": "LOW", "panel": panel}]}, fh)
                out = findings_mod.load_findings([p])
                self.assertEqual(out[0]["_group"], "mygroup")
                self.assertEqual(out[0]["panel"], panel)

    def test_load_findings_tags_group_from_domain_suffixed_filenames(self):
        # P4 review cells write findings-<group>-<domain>.json (groups_schema.DOMAINS,
        # e.g. "SEC"), no panel_review/lens_sweep suffix -- GROUP_RE must parse this
        # shape too, or _group tagging silently fails for every matrix cell.
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-Auth-SEC.json")
            with open(p, "w") as fh:
                json.dump(
                    {"findings": [{"severity": "LOW", "domain": "SEC", "code": "SEC-X0X"}]}, fh
                )
            out = findings_mod.load_findings([p])
            self.assertEqual(out[0]["_group"], "Auth")


class TestSummaryCitations(unittest.TestCase):
    def test_summary_shows_cwe_and_provenance(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "SG-001",
                        "title": "sqli",
                        "severity": "HIGH",
                        "confidence": "CERTAIN",
                        "panel": "security",
                        "category": "injection",
                        "source": "tool:semgrep",
                        "reinforced": True,
                        "location": {"file": "a.py", "line_start": 1},
                        "citations": {
                            "cwe": [{"id": "CWE-89", "name": "SQLi", "verified": True}],
                            "ssvc": {
                                "decision": "Act",
                                "model": "deployer-reduced",
                                "inputs": {
                                    "exploitation": "active",
                                    "exposure": "open",
                                    "impact": "high",
                                },
                            },
                        },
                    }
                ],
            ),
        ))
        text = render_mod.render_summary(report)
        self.assertIn("CWE-89", text)
        self.assertIn("Act", text)
        # the provenance chip shows the evidence status, not "reinforced". No
        # verdict is supplied here, so P2/#446 means this is tool_reported,
        # not tool_confirmed -- reinforcement alone no longer gates.
        self.assertIn("tool_reported", text)

    def test_summary_shows_panel_label(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(
                findings=[
                    {
                        "id": "SE-001",
                        "title": "x",
                        "severity": "HIGH",
                        "confidence": "CERTAIN",
                        "panel": "security",
                        "category": "novel",
                        "source": "agent:sr",
                        "location": {"file": "a", "line_start": 1},
                        "cvss": {"score": 8, "vector": "v"},
                        "exploit_scenario": "e",
                    }
                ],
            ),
        ))
        self.assertIn("security", render_mod.render_summary(report))

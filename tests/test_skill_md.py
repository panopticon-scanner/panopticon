import os
import unittest

ROOT = os.path.join(os.path.dirname(__file__), os.pardir, "skill")


class TestSkillMd(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as fh:
            self.text = fh.read()

    def test_has_frontmatter_name(self):
        self.assertTrue(self.text.startswith("---"))
        self.assertRegex(self.text, r"(?m)^name:\s*panopticon\s*$")

    def test_references_scripts_and_agents(self):
        for ref in ["scripts/orchestrator.py", "scripts/synthesize.py",
                    "scripts/dispatch.py", "agents/scout.md",
                    "agents/advisor.md"]:
            self.assertIn(ref, self.text, ref)

    def test_documents_bounded_floor_and_gate(self):
        self.assertIn("--full", self.text)
        self.assertIn("--fail-on", self.text)
        self.assertIn("--severity", self.text)

    def test_documents_tool_layer_and_flags(self):
        for token in ["--tools", "--no-tools", "--epss", "scripts/ingest_tools.py"]:
            self.assertIn(token, self.text, token)

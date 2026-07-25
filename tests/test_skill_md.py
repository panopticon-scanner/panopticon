import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)


class TestSkillMd(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as fh:
            self.text = fh.read()

    def test_has_frontmatter_name(self):
        self.assertTrue(self.text.startswith("---"))
        self.assertRegex(self.text, r"(?m)^name:\s*panopticon\s*$")

    def test_references_scripts_and_prompts(self):
        for ref in ["scripts/orchestrator.py", "scripts/synthesize.py",
                    "prompts/scout.md", "prompts/lenses.md",
                    "reference/security-checklists.md"]:
            self.assertIn(ref, self.text, ref)

    def test_documents_bounded_floor_and_gate(self):
        self.assertIn("--full", self.text)
        self.assertIn("--fail-on", self.text)
        self.assertIn("bounded", self.text.lower())

    def test_documents_tool_layer_and_flags(self):
        for token in ["--tools", "--no-tools", "--epss", "run_tools.py",
                      "ingest_tools.py", ":ro", "citations"]:
            self.assertIn(token, self.text, token)

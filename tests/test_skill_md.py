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

    def test_description_is_trigger_only_and_host_neutral(self):
        import re
        m = re.search(r"(?m)^description:\s*(.+)$", self.text)
        self.assertIsNotNone(m)
        desc = m.group(1)
        self.assertTrue(desc.startswith("Use when"), desc)
        self.assertNotIn("Kimi", desc)
        self.assertNotIn("→", desc)  # no workflow summary

    def test_has_host_dispatch_section(self):
        self.assertIn("## Host dispatch", self.text)
        for host in ("Claude Code", "Kimi Code"):
            self.assertIn(host, self.text)

    def test_pins_round1_flags_and_render_advisor(self):
        for token in ["--gate-unverified", "--max-verify", "--render-advisor",
                      "--host", "--verdicts-dir"]:
            self.assertIn(token, self.text, token)

    def test_uniform_return_json_contract(self):
        self.assertIn("every reviewer RETURNS its JSON", self.text)
        self.assertNotIn("their tool policy allows Bash", self.text)

    def test_host_dispatch_is_enforcement_conditional(self):
        for token in ("enforced", "subagent_type", "--agents-dir",
                      "--emit-host-agents"):
            self.assertIn(token, self.text, token)

    def test_clean_tree_check_and_hostile_guidance(self):
        self.assertIn("git status --porcelain", self.text)
        self.assertIn("treat the run as compromised", self.text)
        self.assertIn("enforcement registered", self.text)

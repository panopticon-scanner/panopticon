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

    def test_return_contract_by_role(self):
        # P2 SP-A flips fan-out (panel_review/lens_sweep) to self-write +
        # confirmation-only return; scout and advisor are unchanged (they
        # still RETURN their JSON and the orchestrator persists it).
        self.assertIn("writes its own `entry.out_file`", self.text)
        self.assertIn("short confirmation only", self.text)
        self.assertIn("the scout RETURNS the ScopeProfile JSON", self.text)
        self.assertIn("The advisor RETURNS a", self.text)
        self.assertNotIn("their tool policy allows Bash", self.text)

    def test_host_dispatch_is_enforcement_conditional(self):
        for token in ("enforced", "subagent_type", "--agents-dir",
                      "--emit-host-agents"):
            self.assertIn(token, self.text, token)

    def test_clean_tree_check_and_hostile_guidance(self):
        self.assertIn("git status --porcelain", self.text)
        self.assertIn("treat the run as compromised", self.text)
        self.assertIn("enforcement registered", self.text)

    def test_all_four_roles_have_shell_dispatch_instructions(self):
        for token in ("panopticon-scout", "panopticon-advisor",
                      "tree-baseline.txt"):
            self.assertIn(token, self.text, token)

    def test_all_script_commands_use_repo_root_prefix(self):
        # `python3 scripts/...` is ambiguous: from the repo root it hits the
        # WRONG directory (repo-root scripts/ = file_issues/triage, not the
        # pipeline). Every command must use the repo-root `skill/scripts/` prefix.
        offenders = [ln for ln in self.text.splitlines() if "python3 scripts/" in ln]
        self.assertEqual(offenders, [])

    def test_all_file_mentions_use_skill_prefix(self):
        # File MENTIONS must be repo-root-relative too, not just commands.
        # Both `agents/` and `scripts/` references must be prefixed with `skill/`.
        import re
        bare = [ln for ln in self.text.splitlines()
                if re.search(r"(?<!l)`(scripts|agents)/", ln)]
        self.assertEqual(bare, [], "bare scripts/ or agents/ path (run-from-where?): %r" % bare)

    def test_tool_scan_step_is_deterministic_not_optional(self):
        step4 = self.text.split("4. **Tool scan**")[1].split("5. **")[0]
        self.assertNotIn("optional", step4.lower())
        self.assertIn("run_tools.py", step4)
        self.assertIn("--no-tools", step4)
        self.assertTrue("LOUD" in step4 or "loudly" in step4.lower())

    def test_tools_dir_is_wired_into_synthesize_passes(self):
        # F-2: a scan that runs but is never ingested reads as clean. Pin
        # that the pipeline instructs --tools-dir where synthesize is invoked.
        pipeline = self.text.split("## Pipeline")[1].split("## Host dispatch")[0]
        self.assertIn("--tools-dir .panopticon/tools", pipeline)


class TestReadmeQuickStart(unittest.TestCase):
    """#512: the README Quick start must show real invocation flags, not the
    nonexistent --mode/--target selectors a new adopter would copy-paste."""

    def setUp(self):
        with open(os.path.join(ROOT, os.pardir, "README.md"), encoding="utf-8") as fh:
            self.text = fh.read()

    def _quick_start(self):
        # Scoped to the Quick start section: elsewhere `run_tools.py --target .`
        # is a legitimate internal tool invocation, not skill-invocation syntax.
        return self.text.split("## Quick start")[1].split("## Repository layout")[0]

    def test_no_nonexistent_mode_or_target_flags(self):
        qs = self._quick_start()
        self.assertNotIn("--mode", qs)
        self.assertNotIn("--target", qs)

    def test_quick_start_uses_documented_flags(self):
        qs = self._quick_start()
        for flag in ("-f ", "-d ", "-c", "--pr "):
            self.assertIn(flag, qs, flag)

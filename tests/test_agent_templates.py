import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill", "scripts"))
import dispatch


ROLES = ["scout.md", "panel-review.md", "lens-sweep.md", "advisor.md", "setup-scan.md"]


class TestUntrustedContentPreamble(unittest.TestCase):
    """#631: every reviewer template must tell the model that content read from
    the target repo is untrusted DATA, not instructions — the one integrity
    control host-level tool restriction cannot substitute for. A reviewer
    talked into suppressing a finding writes a legitimately-scoped but falsely
    clean out_file the write-guard has nothing to say about."""

    def test_every_template_carries_the_untrusted_preamble(self):
        for role_file in ROLES:
            _meta, body = dispatch.load_template(role_file)
            low = body.lower()
            self.assertIn("untrusted data", low, role_file)
            self.assertIn("prompt-injection", low, role_file)
            self.assertIn("do not comply", low, role_file)

    def test_finding_roles_route_injections_to_a_finding(self):
        # panel_review / lens_sweep emit findings, so a caught injection must
        # become one (category prompt-injection) rather than a silent miss.
        for role_file in ("panel-review.md", "lens-sweep.md"):
            _meta, body = dispatch.load_template(role_file)
            self.assertIn('category: "prompt-injection"', body, role_file)

    def test_rendered_prompts_include_the_preamble(self):
        # The preamble must survive rendering, not just live in the file.
        panel = dispatch.render_prompt("panel-review.md", {
            "panel": "security", "group": "g1", "file_list": "a.py",
            "security_mode": "standard", "depth": "deep",
            "out_file": ".panopticon/f.json", "lenses": "x"})
        self.assertIn("UNTRUSTED DATA", panel)
        advisor = dispatch.render_prompt("advisor.md", {"claim_json": "{}"})
        self.assertIn("UNTRUSTED DATA", advisor)


class TestTemplateFrontmatter(unittest.TestCase):
    def test_all_templates_parse_with_host_neutral_meta(self):
        for role_file in ROLES:
            meta, body = dispatch.load_template(role_file)
            self.assertTrue(meta["name"], role_file)
            self.assertTrue(meta["description"], role_file)
            self.assertIn("allowed", meta["tool_policy"], role_file)
            self.assertIn("forbidden", meta["tool_policy"], role_file)
            self.assertNotIn("---", body.split("\n", 1)[0], role_file)
            self.assertNotIn("model_preference", body, role_file)

    def test_kimi_dialect_fields_are_gone(self):
        for role_file in ROLES:
            raw = open(os.path.join(dispatch.TEMPLATE_DIR, role_file),
                       encoding="utf-8").read()
            self.assertNotIn("model_preference", raw, role_file)
            self.assertNotIn("disallowedTools", raw, role_file)

    def test_tool_policy_least_privilege(self):
        # scout/advisor/setup-scan are not fan-out roles and stay read-only. panel_review
        # and lens_sweep (#436, spec Decision 3) hold scoped Write so they can
        # self-write their out_file; the write-guard hook (Tasks 4-5) confines
        # that Write to the plan's out_file set. Edit/Bash/Agent stay forbidden
        # for every role.
        read_only = {"scout.md", "advisor.md", "setup-scan.md"}
        scoped_write = {"panel-review.md", "lens-sweep.md"}
        self.assertEqual(read_only | scoped_write, set(ROLES))
        for role_file in read_only:
            meta, _ = dispatch.load_template(role_file)
            self.assertEqual(meta["tool_policy"]["allowed"],
                             ["Read", "Grep", "Glob"], role_file)
            self.assertEqual(meta["tool_policy"]["forbidden"],
                             ["Bash", "Edit", "Write", "Agent"], role_file)
        for role_file in scoped_write:
            meta, _ = dispatch.load_template(role_file)
            self.assertEqual(meta["tool_policy"]["allowed"],
                             ["Read", "Grep", "Glob", "Write"], role_file)
            self.assertEqual(meta["tool_policy"]["forbidden"],
                             ["Bash", "Edit", "Agent"], role_file)

    def test_malformed_frontmatter_fails_fast(self):
        with self.assertRaises(ValueError) as ctx:
            dispatch.parse_template_frontmatter("no frontmatter here", source="x.md")
        self.assertIn("x.md", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            dispatch.parse_template_frontmatter(
                "---\nname: a\n---\nbody", source="y.md")
        self.assertIn("y.md", str(ctx.exception))  # missing tool_policy

    def test_missing_template_fails_fast(self):
        with self.assertRaises(ValueError) as ctx:
            dispatch.load_template("nonexistent.md")
        self.assertIn("nonexistent.md", str(ctx.exception))


class TestSetupScanTemplate(unittest.TestCase):
    def test_renders_with_spine_and_vocabulary(self):
        rendered = dispatch.render_prompt("setup-scan.md", {
            "repo_spine": "src/, tests/, pyproject.toml",
            "vocabulary_labels": "Auth, Checkout, Catalog"})
        self.assertIn("Checkout", rendered)
        self.assertIn("UNTRUSTED DATA", rendered)
        self.assertIn('"capability"', rendered)  # proposal JSON shape present

    def test_is_read_only(self):
        meta, _ = dispatch.load_template("setup-scan.md")
        self.assertEqual(meta["tool_policy"]["allowed"], ["Read", "Grep", "Glob"])
        self.assertEqual(meta["tool_policy"]["forbidden"], ["Bash", "Edit", "Write", "Agent"])


class TestScopeProfileDomains(unittest.TestCase):
    def _schema(self):
        p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "skill", "reference", "scope-profile-schema.json")
        with open(p) as fh:
            return json.load(fh)

    def test_required_has_domains_not_panels(self):
        s = self._schema()
        self.assertIn("domains", s["required"])
        self.assertNotIn("panels", s["required"])

    def test_domains_enum_is_the_ten(self):
        s = self._schema()
        enum = set(s["properties"]["domains"]["items"]["enum"])
        self.assertEqual(enum, {"SEC","COD","ARC","TST","QAL","AGT","DAT","OPS","ACC","LNG"})

    def test_scout_template_emits_domains(self):
        p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "skill", "agents", "scout.md")
        body = open(p).read()
        self.assertIn("domains", body)
        self.assertNotIn("Set `panels`", body)   # the old instruction is gone


if __name__ == "__main__":
    unittest.main()

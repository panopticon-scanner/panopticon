import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill", "scripts"))
import dispatch


ROLES = ["scout.md", "panel-review.md", "lens-sweep.md", "advisor.md"]


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

    def test_tool_policy_uniform_least_privilege(self):
        # Round 3a: every role is read-only; reviewers return JSON and the
        # orchestrator writes all artifacts.
        for role_file in ROLES:
            meta, _ = dispatch.load_template(role_file)
            self.assertEqual(meta["tool_policy"]["allowed"],
                             ["Read", "Grep", "Glob"], role_file)
            self.assertEqual(meta["tool_policy"]["forbidden"],
                             ["Bash", "Edit", "Write", "Agent"], role_file)

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


if __name__ == "__main__":
    unittest.main()

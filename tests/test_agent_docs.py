import os
import unittest

from tests._test_helpers import SKILL_ROOT as ROOT
from tests.doc_helpers import (
    AGENTS_DIR,
)


class TestAdvisorDoc(unittest.TestCase):
    """#469: the advisor template must carry an explicit tool-claim branch --
    it drives tool_axis verdicts (tool_confirmed/rejected) but was written for
    agent claims only."""

    def test_advisor_has_tool_claim_guidance(self):
        with open(os.path.join(ROOT, "agents", "advisor.md"), encoding="utf-8") as fh:
            advisor = fh.read()
        self.assertIn("Tool claims", advisor)
        self.assertIn("tool:*", advisor)
        self.assertIn("pattern", advisor.lower())


class TestScoutDoc(unittest.TestCase):
    """#431: every schema-REQUIRED ScopeProfile field must be named in the
    scout template -- the schema and the prompt drift apart otherwise (the
    live failure: scouts omitted `languages`/`surfaces`)."""

    def test_scout_names_every_schema_required_field(self):
        import json as _json

        with open(
            os.path.join(ROOT, "reference", "scope-profile-schema.json"), encoding="utf-8"
        ) as fh:
            required = _json.load(fh)["required"]
        with open(os.path.join(ROOT, "agents", "scout.md"), encoding="utf-8") as fh:
            scout = fh.read()
        for field in required:
            self.assertIn(field, scout, field)


class TestReviewerScopeFence(unittest.TestCase):
    """#441: reviewer templates carry the scope fence."""

    def test_reviewer_templates_have_fence(self):
        # #run7 TST-A2A: domain-panel.md is the CURRENT 5.x dispatched reviewer;
        # its fence had zero coverage while two retired templates were checked.
        # #run10: those two retired templates are now deleted.
        for name in ("domain-panel.md",):
            with open(os.path.join(ROOT, "agents", name), encoding="utf-8") as fh:
                self.assertIn("Scope fence", fh.read(), name)

    def test_every_confined_role_states_the_enforced_fence(self):
        # Plan 5: the fence is host-enforced on claude (read_guard_hook); each
        # template tells the agent so, in words the denial reason echoes.
        roles = ("domain-panel.md", "domain-advisor.md", "scout.md", "advisor.md")
        self.assertTrue(roles, "a fence check over zero roles proves nothing")
        for name in roles:
            with self.subTest(template=name), open(os.path.join(AGENTS_DIR, name), encoding="utf-8") as fh:
                body = fh.read().replace("**", "")
                self.assertIn("confined", body)
                self.assertIn("Glob is not available", body)
                self.assertIn("grep a file by its path", body)
        with open(os.path.join(AGENTS_DIR, "setup-scan.md"), encoding="utf-8") as fh:
            body = fh.read().replace("**", "")
            self.assertIn("confined to the repository root", body)

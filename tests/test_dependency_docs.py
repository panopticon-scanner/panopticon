import unittest

from tests.doc_helpers import (
    PLAN_LOCATION, SKILL_ROOTS, _read_doc, _read_skill_md, _section,
)

class TestThePlanHasAHome(unittest.TestCase):
    """Whitespace-collapsed on both sides: SKILL.md wraps at 80 columns and the
    guide does not, and a sentence guard that also pinned the line breaks would
    fail on a re-wrap that changed nothing a reader sees."""

    @staticmethod
    def _flat(text):
        return " ".join(text.split())

    def test_skill_md_says_where_the_review_plan_goes(self):
        self.assertIn(PLAN_LOCATION, self._flat(_read_skill_md()))

    def test_the_guide_says_the_same_thing_in_the_same_words(self):
        self.assertIn(PLAN_LOCATION, self._flat(_read_doc()))


class TestTheDependenciesSection(unittest.TestCase):

    def setUp(self):
        self.section = _section(_read_skill_md(), "## Dependencies",
                                "## Installed-flow substitution")

    def test_it_names_all_three_required_sub_skills(self):
        for name in ("superpowers:writing-plans",
                     "superpowers:subagent-driven-development",
                     "superpowers:verification-before-completion"):
            with self.subTest(name=name):
                self.assertIn(name, self.section)

    def test_it_names_the_roots_hosts_typically_look_in(self):
        for root in SKILL_ROOTS:
            with self.subTest(root=root):
                self.assertIn(root, self.section)

    def test_it_says_the_roots_are_read_only(self):
        self.assertIn("read-only", self.section.lower())

    def test_a_missing_sub_skill_is_a_documented_default_not_a_stop(self):
        """The whole point: an absent sub-skill must not send a host hunting
        through plugin trees, and must not silently change what the review
        did. Each of the three has a built-in answer, and the report says the
        sub-skill was unavailable."""
        for phrase in (".panopticon/runs/<tag>/plan.md",
                       "skill/workflows/dispatch.js",
                       "`validate` phase",
                       "Disclose"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.section)

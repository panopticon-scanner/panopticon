import re
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


class TestWhatAnOperatorHadToDiscover(unittest.TestCase):
    """#3233: the gaps the 5.2 redteam ledgers named, in the two documents a host reads first."""

    FLAT_RUN_ARTIFACTS = re.compile(
        r"\.panopticon/(groups\.json|verdicts|tools|diff-hunks|dispatch-request|coverage-)")

    @staticmethod
    def _flat(text):
        return " ".join(text.split())

    def test_the_quick_reference_spells_out_the_executable(self):
        quick = _read_skill_md().split("## Quick reference", 1)[1]
        self.assertIn("`driver` below is short for `python3 skill/scripts/driver.py`", self._flat(quick))

    def test_no_pre_run_path_is_left_undefined(self):
        for name, text in (("SKILL.md", _read_skill_md()), ("PANOPTICON.md", _read_doc())):
            with self.subTest(name):
                self.assertNotIn("scratch/<run>", text)
        fallback = _read_skill_md().split("## Dependencies", 1)[1]
        self.assertIn("`.panopticon/scratch/plan.md`", fallback)

    def test_both_documents_say_which_parts_of_writing_plans_apply(self):
        for name, text in (("SKILL.md", _read_skill_md()), ("PANOPTICON.md", _read_doc())):
            with self.subTest(name):
                flat = self._flat(text)
                self.assertIn("Use only its task breakdown", flat)
                self.assertIn("must never block an autonomous run", flat)

    def test_no_guide_names_a_run_artifact_outside_its_run_folder(self):
        self.assertEqual([], self.FLAT_RUN_ARTIFACTS.findall(_read_doc()))

    def test_both_documents_say_which_copy_to_drive_with(self):
        for name, text in (("SKILL.md", _read_skill_md()), ("guide", _read_doc())):
            with self.subTest(name):
                self.assertIn("the copy you run decides the rules and prompts", self._flat(text))


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

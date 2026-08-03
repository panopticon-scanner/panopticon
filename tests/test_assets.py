import os
import unittest

ROOT = os.path.join(os.path.dirname(__file__), os.pardir, "skill")


class TestAssets(unittest.TestCase):
    def _read(self, rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return fh.read()

    def test_lenses_cover_all_nine(self):
        text = self._read("prompts/lenses.md")
        for lens in ["structure", "correctness", "style", "coverage", "quality",
                     "design", "known_vulns", "injection", "novel"]:
            self.assertIn(lens, text, lens)

    def test_scout_defines_surfaces_and_output(self):
        text = self._read("agents/scout.md")
        self.assertIn("ScopeProfile", text)
        for surface in ["db_sql", "http_web", "auth", "crypto"]:
            self.assertIn(surface, text)

    def test_checklists_cover_languages(self):
        text = self._read("reference/security-checklists.md")
        for lang in ["Ruby", "Python", "JavaScript", "Java", "Go"]:
            self.assertIn(lang, text)

import os
import unittest

from conftest import SKILL_ROOT as ROOT   # #run7 TST-G1B/QAL-D1B: shared path anchor


class TestAssets(unittest.TestCase):
    def _read(self, rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return fh.read()

    def test_lenses_cover_all_nine(self):
        # #run7 TST-B1B: assert the real lens IDENTIFIERS. "quality"/"design"
        # were weak substrings that also occur in "assertion quality"/"schema
        # design", so the check passed even if the test_quality/test_design lens
        # headings were renamed/removed -- decoupled from what it claims to test.
        text = self._read("prompts/lenses.md")
        for lens in ["structure", "correctness", "style", "coverage", "test_quality",
                     "test_design", "known_vulns", "injection", "novel"]:
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
        self.assertNotIn("Brainfuck", text)

    def test_read_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            self._read("agents/does_not_exist.md")

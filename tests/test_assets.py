import os
import unittest

from conftest import SKILL_ROOT as ROOT   # #run7 TST-G1B/QAL-D1B: shared path anchor


class TestAssets(unittest.TestCase):
    def _read(self, rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return fh.read()

    # #run10: test_lenses_cover_all_nine pinned the contents of
    # skill/prompts/lenses.md, the 4.x lens catalog. Its consumers
    # (dispatch._panel_lenses / PANEL_LENSES / depth_planner.plan_lenses, and
    # the scout's `lenses` output field) were retired in #1441/#1440, leaving a
    # shipped asset no code path loaded and a green test pinning it. Both the
    # file and the now-empty skill/prompts/ are gone.

    def test_scout_names_the_surfaces_it_reasons_from(self):
        # Renamed from test_scout_defines_surfaces_and_output: #1440 removed
        # `surfaces` from the scope-profile schema, so these are the reasoning
        # aids the scout uses to choose `domains` -- explicitly "not an output
        # field" (scout.md). The assertions themselves still hold.
        text = self._read("agents/scout.md")
        self.assertIn("ScopeProfile", text)
        for surface in ["db_sql", "http_web", "auth", "crypto"]:
            self.assertIn(surface, text)

    def test_checklists_cover_languages(self):
        text = self._read("reference/security-checklists.md")
        for lang in ["Ruby", "Python", "JavaScript", "Java", "Go"]:
            self.assertIn(lang, text)
        self.assertNotIn("Brainfuck", text)

    def test_security_checklists_reach_the_sec_reviewer(self):
        # The companion to the test above, and the reason it stopped meaning
        # anything: #1441 deleted panel-review.md, the checklist's ONLY
        # consumer, so this asset was still shipped, still asserted, and no
        # longer delivered to any reviewer. Pin DELIVERY, not just contents.
        import scripts.driver as driver

        rendered = driver._render_security_checklist("SEC")
        self.assertIn("security-checklists.md", rendered)
        self.assertTrue(os.path.isfile(
            os.path.join(ROOT, "reference", "security-checklists.md")))
        # and only the SEC cell pays for it
        for domain in ("COD", "TST", "ARC", "DAT"):
            self.assertEqual(driver._render_security_checklist(domain), "", domain)

    def test_read_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            self._read("agents/does_not_exist.md")

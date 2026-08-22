"""Language detection tests for scripts.run_tools."""
import os
import tempfile
import unittest

import scripts.run_tools as rt

from run_tools_test_helpers import _FakeResult


class TestDetectLanguages(unittest.TestCase):
    def test_detects_by_extension_with_pruning(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "pkg"))
            os.makedirs(os.path.join(d, "node_modules", "dep"))
            open(os.path.join(d, "pkg", "app.py"), "w").close()
            open(os.path.join(d, "pkg", "ui.tsx"), "w").close()
            open(os.path.join(d, "node_modules", "dep", "index.js"), "w").close()
            langs = rt.detect_languages(d)
        self.assertIn("python", langs)
        self.assertIn("typescript", langs)
        self.assertNotIn("javascript", langs)  # only under pruned node_modules

    def test_empty_tree_detects_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(rt.detect_languages(d), [])

    def test_foreign_lang_in_vendored_tree_not_detected(self):
        # #1138: a Python project with a vendored/generated/sample .go file must
        # NOT detect Go (and so must NOT select gosec) — that stray file would
        # otherwise inflate the toolset with a tool that produces nothing, reading
        # as a "selected-but-unproduced" tool-coverage gap that can disable the gate.
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "pkg"))
            open(os.path.join(d, "pkg", "app.py"), "w").close()
            for sub in ("vendor", "testdata", "examples", "third_party", "docs"):
                os.makedirs(os.path.join(d, sub))
                open(os.path.join(d, sub, "dep.go"), "w").close()
            langs = rt.detect_languages(d)
            self.assertIn("python", langs)
            self.assertNotIn("go", langs)                  # all .go under pruned trees
            self.assertNotIn("gosec", rt.select_tools(langs, has_deps=False))

    def test_real_test_suite_still_detected(self):
        # Conservative prune: a genuine test suite under tests/ IS legitimate
        # language surface and must still be detected (we prune vendor/generated,
        # not tests/).
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "tests"))
            open(os.path.join(d, "tests", "test_app.py"), "w").close()
            self.assertIn("python", rt.detect_languages(d))

    def test_run_tools_skips_when_output_exceeds_cap(self):
        huge = b"x" * (rt.MAX_TOOL_OUTPUT_BYTES + 10)
        fake = _FakeResult(returncode=0, stdout=huge)
        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            paths = rt.run_tools(d, ["semgrep"], out_dir, runner=lambda cmd, **kw: fake)
            self.assertEqual(paths, [])
            self.assertFalse(os.path.exists(os.path.join(out_dir, "semgrep.sarif")))

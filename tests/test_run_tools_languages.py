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

    def test_run_tools_skips_when_output_exceeds_cap(self):
        huge = b"x" * (rt.MAX_TOOL_OUTPUT_BYTES + 10)
        fake = _FakeResult(returncode=0, stdout=huge)
        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            paths = rt.run_tools(d, ["semgrep"], out_dir, runner=lambda cmd, **kw: fake)
            self.assertEqual(paths, [])
            self.assertFalse(os.path.exists(os.path.join(out_dir, "semgrep.sarif")))

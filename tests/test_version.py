"""Version single-sourcing guard (#439).

Run-2 filed FIXME-9 and run-3 re-confirmed it (issues #502/#503): pyproject
said 3.0.0 while SKILL.md, build_report, and the verify-queue payload said
4.2.0, and citations.py sent a stale panopticon/3.0.0 User-Agent. The single
edit point is skill/scripts/_version.py; everything else must match it, and
this test is what makes drift impossible rather than merely discouraged.
"""
import os
import re
import sys
import tomllib
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
from scripts._version import __version__  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


class TestVersionSingleSourcing(unittest.TestCase):
    def test_version_is_semver(self):
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")

    def test_pyproject_matches(self):
        with open(os.path.join(ROOT, "pyproject.toml"), "rb") as fh:
            data = tomllib.load(fh)
        self.assertEqual(data["project"]["version"], __version__)

    def test_development_md_current_matches(self):
        m = re.search(r"\*\*Current version: ([\d.]+)\*\*", _read("DEVELOPMENT.md"))
        self.assertIsNotNone(m, "DEVELOPMENT.md lost its 'Current version' line")
        self.assertEqual(m.group(1), __version__)

    def test_skill_md_frontmatter_matches(self):
        m = re.search(r'^\s*version:\s*"([\d.]+)"', _read("skill/SKILL.md"),
                      re.MULTILINE)
        self.assertIsNotNone(m, "SKILL.md lost its frontmatter version")
        self.assertEqual(m.group(1), __version__)

    def test_report_meta_uses_the_constant(self):
        import scripts.synthesize as syn
        report = syn.build_report([], [{"name": "g1", "files": ["a.py"]}],
                                  "t", "high", "2026-01-01T00:00:00Z")
        self.assertEqual(report["meta"]["version"], __version__)

    def test_citations_user_agent_uses_the_constant(self):
        src = _read("skill/scripts/citations.py")
        self.assertNotRegex(src, r"panopticon/\d",
                            "citations.py hardcodes a User-Agent version")
        self.assertIn("__version__", src)


if __name__ == "__main__":
    unittest.main()

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
from scripts.tools import ADAPTERS

RAILS_GOAT = "https://github.com/OWASP/railsgoat.git"


class TestRubyIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = os.path.join(self.tmp, "railsgoat")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", RAILS_GOAT, self.repo],
                capture_output=True, timeout=120, check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.tearDown()
            raise unittest.SkipTest(f"Could not clone fixture repo: {e}")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_brakeman_finds_issues(self):
        adapter = ADAPTERS["brakeman"]
        if not adapter.is_applicable(self.repo):
            raise unittest.SkipTest("Fixture does not look like a Rails app")
        try:
            stdout, rc = adapter.invoke(self.repo)
        except FileNotFoundError as e:
            raise unittest.SkipTest(f"Brakeman not installed: {e}")
        self.assertIn(rc, (0, 1))
        findings = adapter.parse(stdout, "railsgoat")
        self.assertTrue(findings, "expected at least one Brakeman finding")
        self.assertTrue(any(f["citations"].get("cwe") for f in findings if f.get("citations")))

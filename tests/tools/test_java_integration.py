import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
from scripts.tools import ADAPTERS

WEBGOAT = "https://github.com/WebGoat/WebGoat.git"


class TestJavaIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.repo = os.path.join(self.tmp, "webgoat")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", WEBGOAT, self.repo],
                capture_output=True, timeout=180, check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.tearDown()
            raise unittest.SkipTest(f"Could not clone fixture repo: {e}")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dependency_check_finds_issues(self):
        adapter = ADAPTERS["dependency-check"]
        if not adapter.is_applicable(self.repo):
            raise unittest.SkipTest("Fixture does not look like a Java project")
        raise unittest.SkipTest("dependency-check integration requires Java runtime and large DB")

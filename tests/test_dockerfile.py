import os
import unittest

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)


class TestDockerfile(unittest.TestCase):
    def test_bundles_core_tools(self):
        with open(os.path.join(ROOT, "Dockerfile"), encoding="utf-8") as fh:
            text = fh.read().lower()
        for tool in ["semgrep", "gitleaks", "trivy", "bandit", "brakeman", "gosec", "eslint"]:
            self.assertIn(tool, text, tool)
        self.assertIn("useradd", text)  # non-root user created

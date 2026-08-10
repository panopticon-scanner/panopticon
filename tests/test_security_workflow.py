import os
import unittest


ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "security.yml")


class TestSecurityWorkflowTrustBoundary(unittest.TestCase):
    def _text(self):
        with open(WORKFLOW, encoding="utf-8") as fh:
            return fh.read()

    def test_controller_and_target_are_separate_checkouts(self):
        text = self._text()
        self.assertIn("pull_request_target:", text)
        self.assertNotIn("\n  pull_request:\n", text)
        self.assertIn("path: controller", text)
        self.assertIn("github.event.pull_request.base.sha", text)
        self.assertIn("path: target", text)
        self.assertIn("github.event.pull_request.head.repo.full_name", text)
        self.assertIn("github.event.pull_request.head.sha", text)
        self.assertGreaterEqual(text.count("persist-credentials: false"), 2)

    def test_only_trusted_controller_runs_gate_and_scanners(self):
        text = self._text()
        self.assertIn("python controller/skill/scripts/run_tools.py", text)
        self.assertIn("python controller/skill/scripts/security_gate.py", text)
        self.assertNotIn("python skill/scripts/run_tools.py", text)
        self.assertNotIn("import scripts.ingest_tools as it", text)

    def test_pr_dockerfile_is_never_built(self):
        text = self._text()
        self.assertIn("docker build -t panopticon-tools controller", text)
        self.assertNotIn("docker build -t panopticon-tools .", text)

    def test_scanner_manifest_is_required(self):
        text = self._text()
        self.assertIn('--manifest "$manifest"', text)
        self.assertIn('--tools-dir "$RUNNER_TEMP/panopticon-tools-output"', text)


if __name__ == "__main__":
    unittest.main()

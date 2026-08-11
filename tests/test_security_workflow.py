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
        self.assertIn("path: controller", text)
        self.assertIn("github.event.pull_request.base.sha", text)
        self.assertIn("path: target", text)
        self.assertIn("github.event.pull_request.head.repo.full_name", text)
        self.assertIn("github.event.pull_request.head.sha", text)
        self.assertGreaterEqual(text.count("persist-credentials: false"), 2)

    def test_fork_isolation_routing_guard(self):
        # Both triggers exist so the required `scan` check always reports, but
        # the job `if` routes each PR to exactly one: forks -> target (tamper-
        # proof base workflow), same-repo -> pull_request (no double run).
        text = self._text()
        self.assertIn("pull_request_target:", text)
        self.assertIn("pull_request:", text)
        self.assertIn("if:", text)
        # fork branch: pull_request_target only when head repo != this repo
        self.assertIn("github.event_name == 'pull_request_target' &&", text)
        self.assertIn("head.repo.full_name != github.repository", text)
        # same-repo branch: pull_request only when head repo == this repo
        self.assertIn("github.event_name == 'pull_request' &&", text)
        self.assertIn("head.repo.full_name == github.repository", text)

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

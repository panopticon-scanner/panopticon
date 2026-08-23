import os
import unittest

import yaml


ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "security.yml")


class TestSecurityWorkflowTrustBoundary(unittest.TestCase):
    def _workflow(self):
        with open(WORKFLOW, encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    def _checkout_steps(self, workflow):
        return [
            step
            for job in workflow.get("jobs", {}).values()
            for step in job.get("steps", [])
            if str(step.get("uses", "")).startswith("actions/checkout")
        ]

    def _run_text(self, workflow):
        return "\n".join(
            step.get("run", "")
            for job in workflow.get("jobs", {}).values()
            for step in job.get("steps", [])
            if "run" in step
        )

    def test_controller_and_target_are_separate_checkouts(self):
        wf = self._workflow()
        # PyYAML 1.1 parses the unquoted `on:` key as the boolean True.
        on = wf.get(True, {})
        triggers = on if isinstance(on, list) else list(on.keys())
        self.assertIn("pull_request_target", triggers)

        checkouts = self._checkout_steps(wf)
        paths = [step.get("with", {}).get("path") for step in checkouts]
        self.assertIn("controller", paths)
        self.assertIn("target", paths)

        for step in checkouts:
            self.assertIs(
                step.get("with", {}).get("persist-credentials"), False
            )

        controller = next(
            s for s in checkouts if s.get("with", {}).get("path") == "controller"
        )
        target = next(
            s for s in checkouts if s.get("with", {}).get("path") == "target"
        )
        self.assertIn(
            "github.event.pull_request.base.sha",
            controller.get("with", {}).get("ref", ""),
        )
        self.assertIn(
            "github.event.pull_request.head.repo.full_name",
            target.get("with", {}).get("repository", ""),
        )
        self.assertIn(
            "github.event.pull_request.head.sha",
            target.get("with", {}).get("ref", ""),
        )

    def test_fork_isolation_routing_guard(self):
        wf = self._workflow()
        # PyYAML 1.1 parses the unquoted `on:` key as the boolean True.
        on = wf.get(True, {})
        triggers = on if isinstance(on, list) else list(on.keys())
        self.assertIn("pull_request_target", triggers)
        self.assertIn("pull_request", triggers)

        job_if = wf["jobs"]["scan"].get("if", "")
        self.assertIn("github.event_name == 'pull_request_target' &&", job_if)
        self.assertIn("head.repo.full_name != github.repository", job_if)
        self.assertIn("github.event_name == 'pull_request' &&", job_if)
        self.assertIn("head.repo.full_name == github.repository", job_if)

    def test_only_trusted_controller_runs_gate_and_scanners(self):
        runs = self._run_text(self._workflow())
        self.assertIn("python controller/skill/scripts/run_tools.py", runs)
        self.assertIn("python controller/skill/scripts/security_gate.py", runs)
        self.assertNotIn("python skill/scripts/run_tools.py", runs)
        self.assertNotIn("import scripts.ingest_tools as it", runs)

    def test_pr_dockerfile_is_never_built(self):
        runs = self._run_text(self._workflow())
        self.assertIn("docker build -t panopticon-tools controller", runs)
        self.assertNotIn("docker build -t panopticon-tools .", runs)

    def test_scanner_manifest_is_required(self):
        runs = self._run_text(self._workflow())
        self.assertIn('--manifest "$manifest"', runs)
        self.assertIn('--tools-dir "$RUNNER_TEMP/${{ env.TOOLS_OUT }}"', runs)

    def test_no_untrusted_github_context_in_run_scripts(self):
        runs = self._run_text(self._workflow())
        untrusted_contexts = [
            "${{ github.event.pull_request.title }}",
            "${{ github.event.pull_request.body }}",
            "${{ github.event.issue.title }}",
            "${{ github.event.issue.body }}",
            "${{ github.event.comment.body }}",
            "${{ github.event.head_commit.message }}",
        ]
        for ctx in untrusted_contexts:
            self.assertNotIn(ctx, runs)


if __name__ == "__main__":
    unittest.main()

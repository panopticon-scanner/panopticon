import os
import unittest

import yaml

from test_workflow_pins import _without_comments


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
        """Every `run:` script in the workflow, WITHOUT its comments.

        The prose in this workflow quotes the commands it explains -- the
        dependency step's own comment names the flags it passes and the shape
        it replaced. Reading comments as script made two assertions here
        satisfiable by documentation: `--require-hashes` stayed "present" with
        the flag deleted from the command, and a reinstated `pip install
        --upgrade pip` would have been hidden by a comment mentioning it. What
        this file asserts is what the gate RUNS.
        """
        return _without_comments("\n".join(
            step.get("run", "")
            for job in workflow.get("jobs", {}).values()
            for step in job.get("steps", [])
            if "run" in step
        ))

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

        # #run9 TST-B1B: the four fragments above can ALL be present in a guard
        # that is still WRONG -- a mis-parenthesization or a swapped ==/!= would
        # route a fork through the trusted pull_request arm. Validate the ASSEMBLED
        # boolean: each route is a parenthesized AND group with the CORRECT
        # operator, the two are OR-combined, and push is OR-joined at the front.
        compact = " ".join(job_if.split())
        self.assertIn(                                  # fork route: FOREIGN head repo
            "(github.event_name == 'pull_request_target' && "
            "github.event.pull_request.head.repo.full_name != github.repository)",
            compact)
        self.assertIn(                                  # same-repo route: SAME head repo
            "(github.event_name == 'pull_request' && "
            "github.event.pull_request.head.repo.full_name == github.repository)",
            compact)
        self.assertIn(") || (", compact)                # the two routes are OR-combined
        self.assertTrue(                                # push always runs, OR-joined first
            compact.startswith("github.event_name == 'push' || ("))

    def test_only_trusted_controller_runs_gate_and_scanners(self):
        runs = self._run_text(self._workflow())
        self.assertIn("python controller/skill/scripts/run_tools.py", runs)
        self.assertIn("python controller/skill/scripts/security_gate.py", runs)
        self.assertNotIn("python skill/scripts/run_tools.py", runs)
        self.assertNotIn("import scripts.ingest_tools as it", runs)

    def test_gate_deps_are_installed_by_digest_from_the_trusted_checkout(self):
        # #1641 (SEC-E2A). Two halves, and the second is the one only this file
        # can state: the gate's dependency digests must come from `controller/`
        # -- on a fork PR the BASE checkout -- because a requirements file read
        # out of `target/` would let the PR choose what the gate installs, which
        # is the same door `test_only_trusted_controller_runs_gate_and_scanners`
        # closes for the scanner code itself.
        runs = self._run_text(self._workflow())
        self.assertIn("--require-hashes", runs)
        self.assertIn("-r controller/.github/requirements-gate.txt", runs)
        self.assertNotIn("target/.github/requirements", runs)
        # The finding itself: the tool that installs the pinned things was not
        # pinned. Nothing may reintroduce an unconstrained upgrade.
        self.assertNotIn("pip install --upgrade pip", runs)

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
            "${{ github.head_ref }}",
            "${{ github.event.pull_request.head.label }}",
            "${{ github.event.review.body }}",
            "${{ github.event.pull_request.head.repo.description }}",
            "${{ github.event.discussion.body }}",
            "${{ github.event.pull_request.user.login }}",
            "${{ github.event.commits[0].message }}",
        ]
        for ctx in untrusted_contexts:
            self.assertNotIn(ctx, runs)

    def test_expanded_untrusted_contexts_are_caught(self):
        # Positive regression: each newly-added context would be flagged if it
        # appeared anywhere in a run script.
        runs = self._run_text(self._workflow())
        newly_untrusted = [
            "${{ github.head_ref }}",
            "${{ github.event.pull_request.head.label }}",
            "${{ github.event.review.body }}",
            "${{ github.event.pull_request.head.repo.description }}",
            "${{ github.event.discussion.body }}",
            "${{ github.event.pull_request.user.login }}",
            "${{ github.event.commits[0].message }}",
        ]
        for ctx in newly_untrusted:
            self.assertNotIn(ctx, runs)

    def test_env_context_is_allowed(self):
        # Negative regression: a benign, non-injectable env context is permitted
        # and present in run scripts.
        runs = self._run_text(self._workflow())
        self.assertIn("${{ env.TOOLS_OUT }}", runs)


class TestTheImagePullIsBounded(unittest.TestCase):
    """#1575 (OPS-A1A): the `scan` job is a required check on every push, every
    same-repo PR and every fork PR, and its image step was
    `if docker pull ...; then ... else <local build> fi`.

    The fallback is selected by EXIT STATUS, so it fires only when the pull
    RETURNS non-zero. A stalled GHCR response -- as opposed to a refused or 404
    one -- makes the pull hang, the `else` branch is never reached, and the
    deliberately-engineered degraded-local-build path is dead in precisely the
    scenario it exists for. The job's `timeout-minutes: 30` is a crash backstop,
    not a call timeout: it converts a fast handled degradation into a hard gate
    failure thirty minutes later, on every PR in the window.

    Two bounds, and both are asserted, because either alone leaves the hole.
    `timeout-minutes` on the STEP ends the job; only the `timeout` wrapper on
    the COMMAND returns non-zero and lets the fallback fire. The repo has
    already adjudicated this argument against itself at
    `docker-build-pr.yml:23-32` (#run10 OPS-A1A), whose fix was a per-call
    deadline for exactly this reason.
    """

    def _pull_step(self):
        with open(WORKFLOW, encoding="utf-8") as fh:
            workflow = yaml.safe_load(fh)
        steps = [step for job in workflow.get("jobs", {}).values()
                 for step in job.get("steps", [])
                 if "docker pull" in (step.get("run") or "")]
        self.assertEqual(len(steps), 1,
                         "expected exactly one docker-pull step, got %d" % len(steps))
        return steps[0]

    def test_the_step_carries_its_own_ceiling(self):
        self.assertEqual(self._pull_step().get("timeout-minutes"), 10)

    def test_the_pull_command_carries_a_deadline_of_its_own(self):
        run = _without_comments(self._pull_step()["run"])
        self.assertRegex(run, r"timeout\s+600\s+docker pull",
                         "a step ceiling ends the JOB; only a command deadline "
                         "returns non-zero and lets the local-build fallback fire")

    def test_the_fallback_is_still_there_to_fire(self):
        run = _without_comments(self._pull_step()["run"])
        self.assertIn("docker build -t panopticon-tools controller", run)


if __name__ == "__main__":
    unittest.main()

import os
import unittest

import yaml

from test_workflow_pins import _without_comments


ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "security.yml")
FORK_WORKFLOW = os.path.join(ROOT, ".github", "workflows", "security-fork.yml")


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

    def _every_run_text(self):
        """The same, over BOTH security workflows.

        #1900 fix round 2 moved the fork scan into `security-fork.yml`, and
        that file -- not this one -- now carries `pull_request_target`, the
        privileged trigger. A rule about what may reach a shell that stopped
        at this file's boundary would be weakest exactly where it matters
        most.
        """
        texts = []
        for path in (WORKFLOW, FORK_WORKFLOW):
            with open(path, encoding="utf-8") as fh:
                texts.append(self._run_text(yaml.safe_load(fh)))
        return "\n".join(texts)

    def test_controller_and_target_are_separate_checkouts(self):
        wf = self._workflow()
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
        # #1900 fix round 2: this file has no untrusted route left, so the
        # controller ref no longer needs (or may have) a base-SHA branch --
        # that expression, and the trust decision inside it, moved to
        # `security-fork.yml`, where the base SHA is unconditional.
        self.assertEqual(
            controller.get("with", {}).get("ref", ""),
            "${{ github.event.pull_request.head.sha || github.sha }}",
        )
        self.assertNotIn(
            "base.sha", controller.get("with", {}).get("ref", ""),
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
        self.assertIn("pull_request", triggers)

        # #1900 fix round 2, and the load-bearing half of this test now: this
        # file must NOT carry `pull_request_target`. A job skipped by an `if:`
        # still posts a check run under its own name and a skipped job reports
        # Success, so a second trigger that could skip `scan` is a second way
        # to post a green `scan` over a real failure -- on same-repo PRs too,
        # where a label applied after a failed gate would have cleared it. The
        # fork scan reports under `fork-scan`, from `security-fork.yml`.
        self.assertNotIn("pull_request_target", triggers)

        job_if = wf["jobs"]["scan"].get("if", "")
        self.assertIn("github.event_name == 'pull_request' &&", job_if)
        self.assertIn("head.repo.full_name == github.repository", job_if)
        self.assertNotIn("pull_request_target", job_if)

        # #run9 TST-B1B: the fragments above can ALL be present in a guard that
        # is still WRONG -- a mis-parenthesization or a swapped ==/!= would
        # route a fork through the trusted arm. Validate the ASSEMBLED boolean.
        compact = " ".join(job_if.split())
        self.assertIn(                                  # same-repo route: SAME head repo
            "(github.event_name == 'pull_request' && "
            "github.event.pull_request.head.repo.full_name == github.repository)",
            compact)
        self.assertTrue(                                # push always runs, OR-joined first
            compact.startswith("github.event_name == 'push' || ("))
        self.assertEqual(                               # and there is no third route
            compact.count("github.event_name"), 2)

    def test_the_pull_request_types_are_the_defaults(self):
        # M3: the same-repo scan only fires on the actions `pull_request`
        # defaults to (opened, synchronize, reopened). Someone narrowing this
        # to `types: [opened]` would leave a new head carrying the previous
        # head's verdict, silently.
        on = self._workflow().get(True, {})
        self.assertIsNone(on["pull_request"].get("types"))

    def test_the_scan_jobs_permissions_are_the_recorded_ones(self):
        # Pinned, not merely present: a later edit that widens them has to
        # come through this line.
        self.assertEqual(
            self._workflow()["jobs"]["scan"]["permissions"],
            {"contents": "read", "packages": "read",
             "security-events": "write"})

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
        runs = self._every_run_text()
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
        runs = self._every_run_text()
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


class TestBothScanStepsCarryBothExclusions(unittest.TestCase):
    """#1578 fix round 2: the scan axis and the gate must scope alike.

    `--exclude` is `action="append"` on both CLIs, and an exclusion present on
    one step and missing from the other makes the two halves disagree about
    what was reviewed -- the gate blocking on a path the report already scoped
    out, or the reverse. `FIXTURE_GLOB` was already mirrored across both steps
    and both workflows for exactly that reason; `GOLDEN_GLOB` joins it.

    `tests/goldens/**` is the one class that cannot be composed away:
    `tool-raw/*.raw` is authentic, trimmed SCANNER OUTPUT -- one payload per
    adapter -- so a secret a scanner once reported is quoted there verbatim and
    gitleaks finds it again on every run. That is captured data, not code this
    repository authors, which is the fixture corpus's own argument. Every other
    in-tree literal was removed at source (tests/_test_helpers.py) rather than
    excluded.
    """

    STEPS = ("Run static-analysis tools",
             "Gate on HIGH/CRITICAL tool findings (unverified-strict policy)")
    WORKFLOWS = (WORKFLOW, FORK_WORKFLOW)

    def _steps(self, path):
        with open(path, encoding="utf-8") as fh:
            workflow = yaml.safe_load(fh)
        return {step.get("name"): _without_comments(step.get("run") or "")
                for job in workflow.get("jobs", {}).values()
                for step in job.get("steps", [])}

    def _env(self, path):
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)["env"]

    def test_both_globs_are_declared_by_both_workflows(self):
        for path in self.WORKFLOWS:
            env = self._env(path)
            self.assertEqual(env["FIXTURE_GLOB"], "tests/fixtures/**", path)
            self.assertEqual(env["GOLDEN_GLOB"], "tests/goldens/**", path)

    def test_both_globs_are_on_the_scanner_and_the_gate_step(self):
        for path in self.WORKFLOWS:
            steps = self._steps(path)
            for name in self.STEPS:
                self.assertIn(name, steps, (path, name))
                run = steps[name]
                for glob in ("FIXTURE_GLOB", "GOLDEN_GLOB"):
                    self.assertIn("--exclude '${{ env.%s }}'" % glob, run,
                                  (path, name, glob))

    def test_nothing_else_is_excluded(self):
        # The exclusions are the gate's blind spots, so the COUNT is pinned,
        # not merely the membership: a third one has to come through this line.
        for path in self.WORKFLOWS:
            steps = self._steps(path)
            for name in self.STEPS:
                self.assertEqual(steps[name].count("--exclude"), 2,
                                 (path, name, steps[name]))


if __name__ == "__main__":
    unittest.main()

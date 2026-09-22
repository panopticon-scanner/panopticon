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
            "github.event.pull_request.head.repo.full_name != github.repository && "
            "github.event.action == 'labeled' && "
            "github.event.label.name == 'safe-to-scan')",
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


class TestTheForkScanIsLabelGated(unittest.TestCase):
    """#1900: a fork PR is scanned only after a maintainer says so.

    `pull_request_target` is not covered by GitHub's "require approval for
    outside collaborators" setting, so until this gate existed anyone who could
    open a PR could run the scanners over a tree of their choosing, in a job
    holding the base repository's token. The gate is the `safe-to-scan` label:
    the scan fires on the `labeled` event, which means it scans the head the
    maintainer was looking at when they applied it.
    """

    def setUp(self):
        with open(WORKFLOW, encoding="utf-8") as fh:
            self.wf = yaml.safe_load(fh)

    def _on(self):
        # PyYAML 1.1 parses the unquoted `on:` key as the boolean True.
        return self.wf.get(True, {})

    def test_pull_request_target_fires_only_on_the_gated_actions(self):
        # `opened` is deliberately absent: the default type set would start a
        # scan the moment a fork PR appeared, before any maintainer saw it.
        # `labeled` is what admits one; `synchronize`/`reopened` exist so the
        # revoke job below can take the label away again.
        self.assertEqual(
            self._on()["pull_request_target"].get("types"),
            ["synchronize", "reopened", "labeled"])

    def test_the_fork_route_requires_the_maintainer_label(self):
        compact = " ".join(self.wf["jobs"]["scan"]["if"].split())
        self.assertIn("github.event.action == 'labeled'", compact)
        self.assertIn("github.event.label.name == 'safe-to-scan'", compact)

    def test_the_scan_jobs_permissions_are_the_recorded_ones(self):
        # Pinned, not merely present: the fork path reaches this job, and the
        # label gate is what bounds these grants. A later edit that widens them
        # has to come through this line.
        self.assertEqual(
            self.wf["jobs"]["scan"]["permissions"],
            {"contents": "read", "packages": "read",
             "security-events": "write"})


class TestTheLabelDiesOnEveryNewHead(unittest.TestCase):
    """#1900: the maintainer approved a HEAD, not a pull request.

    A label that outlived a force-push would be exactly the hole the gate was
    built to close: approve a benign diff, push the payload, and the next
    `labeled`-free event would still be running under an approval nobody gave
    it. So every `synchronize` and `reopened` on a fork PR revokes the label,
    and the PR waits for a maintainer again.

    This job is the one place in the workflow that holds a WRITE grant on a
    fork-triggered event, so its shape is pinned hard: one scope, no checkout,
    no interpolation of event data into shell.
    """

    def setUp(self):
        with open(WORKFLOW, encoding="utf-8") as fh:
            self.wf = yaml.safe_load(fh)
        self.job = self.wf.get("jobs", {}).get("unlabel")
        self.assertIsNotNone(self.job, "no `unlabel` job in the workflow")

    def _run_text(self):
        return _without_comments("\n".join(
            step.get("run", "") for step in self.job.get("steps", [])))

    def test_it_fires_on_a_fork_prs_new_head_and_on_a_reopen(self):
        compact = " ".join(self.job.get("if", "").split())
        self.assertIn("github.event_name == 'pull_request_target'", compact)
        self.assertIn(
            "github.event.pull_request.head.repo.full_name != github.repository",
            compact)
        self.assertIn("github.event.action == 'synchronize'", compact)
        self.assertIn("github.event.action == 'reopened'", compact)

    def test_it_holds_exactly_one_write_scope_and_nothing_else(self):
        # Not `contents`, not `packages`, not `security-events`: this job runs
        # on an untrusted event without the label gate in front of it, so the
        # token it carries must be able to do one thing.
        self.assertEqual(self.job.get("permissions"), {"pull-requests": "write"})

    def test_it_checks_nothing_out(self):
        checkouts = [s for s in self.job.get("steps", [])
                     if str(s.get("uses", "")).startswith("actions/checkout")]
        self.assertEqual(checkouts, [], "the revoke job needs no working tree")

    def test_it_reaches_event_data_only_through_env(self):
        # `test_no_untrusted_github_context_in_run_scripts` names the contexts
        # that are known-injectable; this states the rule positively for the
        # new job -- NO `${{ github.event ... }}` reaches its shell at all.
        self.assertNotIn("${{ github.event", self._run_text())
        envs = {}
        for step in self.job.get("steps", []):
            envs.update(step.get("env") or {})
        self.assertEqual(envs.get("PR_NUMBER"),
                         "${{ github.event.pull_request.number }}")
        self.assertEqual(envs.get("REPO"), "${{ github.repository }}")

    def test_it_deletes_the_label_and_tolerates_its_absence(self):
        run = self._run_text()
        self.assertIn("--method DELETE", run)
        self.assertIn("issues/$PR_NUMBER/labels/safe-to-scan", run)
        # A push to an unlabelled fork PR is the COMMON case and answers 404;
        # a job that failed on it would paint every such PR red.
        self.assertIn("404", run)


class TestTheForkPathHasNothingToReach(unittest.TestCase):
    """#1900, second half: the label gate bounds WHO can start a fork scan;
    this bounds what a started one can touch.

    The scanners read target-controlled configuration by design (#1742, #1877),
    so the fork path is built to be worth little if one of them is turned
    against the runner: no registry credential written to the runner's docker
    config, no dependency scanner reaching a package index, and no SARIF filed
    against the base branch's Security tab.
    """

    OFF_THE_FORK_PATH = "github.event_name != 'pull_request_target'"

    def setUp(self):
        with open(WORKFLOW, encoding="utf-8") as fh:
            self.wf = yaml.safe_load(fh)

    def _step(self, name):
        for job in self.wf.get("jobs", {}).values():
            for step in job.get("steps", []):
                if step.get("name") == name:
                    return step
        self.fail("no step named %r in the workflow" % name)

    def test_the_fork_path_never_logs_into_the_registry(self):
        # The tools image is public and pulls anonymously, and the local-build
        # fallback covers a pull that fails; a login on this path would write
        # GITHUB_TOKEN into the runner's docker config for no gain at all.
        step = self._step("Log in to GitHub Container Registry")
        self.assertEqual(" ".join(step.get("if", "").split()),
                         self.OFF_THE_FORK_PATH)

    def test_deps_is_passed_only_off_the_fork_path(self):
        step = self._step("Run static-analysis tools")
        self.assertEqual(
            (step.get("env") or {}).get("DEPS_FLAG"),
            "${{ github.event_name != 'pull_request_target' && '--deps' || '' }}")
        # `_without_comments`, because the step EXPLAINS the flag it no longer
        # spells: a test satisfiable by its own documentation is the #1641
        # mistake, and this assertion is the one most exposed to it.
        run = _without_comments(step.get("run", ""))
        self.assertNotIn("--deps", run)
        self.assertIn("$DEPS_FLAG", run)

    def test_no_fork_controlled_sarif_reaches_the_security_tab(self):
        # Under pull_request_target the run's `github.ref` is the BASE branch,
        # so an uploaded SARIF is filed against main's Security tab -- fork
        # content writing the base repo's security record.
        step = self._step("Upload SARIF to GitHub Security tab")
        self.assertEqual(" ".join(step.get("if", "").split()),
                         "always() && " + self.OFF_THE_FORK_PATH)


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

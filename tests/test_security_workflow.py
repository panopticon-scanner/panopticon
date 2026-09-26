import os
import re
import unittest

import yaml
import shell_reader

from test_workflow_pins import _without_comments


ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "security.yml")
FORK_WORKFLOW = os.path.join(ROOT, ".github", "workflows", "security-fork.yml")


def _unsafe_run_expressions(script):
    """Bounded allowlist, not an Actions evaluator: only reviewed constant env
    bindings may be substituted into shell source. New expressions need review.
    Comments are included: Actions expands them before the shell sees them.
    Env values themselves and shell expansion are outside this guard's scope.
    """
    allowed = {"env.IMAGE", "env.TOOLS_OUT", "env.FIXTURE_GLOB", "env.GOLDEN_GLOB"}
    return [expression for expression in re.findall(r"\$\{\{(.*?)\}\}", script, re.S)
            if re.sub(r"\s+", "", expression) not in allowed]


def _docker_build_contexts(script):
    contexts = []
    for statement in shell_reader.statements(script):
        for stage in statement.stages:
            argv = shell_reader.command(stage.argv)
            if argv[:2] != ["docker", "build"]:
                continue
            operands = []
            args = iter(argv[2:])
            for arg in args:
                if arg in ("-t", "--tag", "-f", "--file", "--build-arg", "--target"):
                    next(args, None)
                elif not arg.startswith("-"):
                    operands.append(arg)
            contexts.append(operands)
    return contexts


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
            compact.count("github.event_name"), 4)

    def test_the_pull_request_types_are_the_defaults(self):
        # M3: the same-repo scan only fires on the actions `pull_request`
        # defaults to (opened, synchronize, reopened). Someone narrowing this
        # to `types: [opened]` would leave a new head carrying the previous
        # head's verdict, silently.
        on = self._workflow().get(True, {})
        self.assertIsNone(on["pull_request"].get("types"))

    def test_the_scan_jobs_permissions_are_the_recorded_ones(self):
        # Pinned, not merely present: a later edit that widens them has to
        # come through this line. #1790 added `actions: read`, and it is the
        # narrowest grant that can read a base commit run's
        # `raw-scanner-captures` artifact -- see
        # `TestTheDeltaBaselineIsFetchedOnEveryRoute`.
        self.assertEqual(
            self._workflow()["jobs"]["scan"]["permissions"],
            {"contents": "read", "packages": "read",
             "security-events": "write", "actions": "read"})

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
        contexts = _docker_build_contexts(self._every_run_text())
        self.assertTrue(contexts)
        self.assertTrue(all(context == ["controller"] for context in contexts), contexts)

    def test_build_context_guard_ignores_prose_and_reads_reordered_options(self):
        self.assertEqual(_docker_build_contexts('# docker build .\necho "docker build ."'), [])
        for script in ("docker build . -t panopticon-tools",
                       "docker build --tag panopticon-tools target",
                       "docker build --tag=panopticon-tools ."):
            with self.subTest(script=script):
                self.assertNotEqual(_docker_build_contexts(script), [["controller"]])
        self.assertEqual(_docker_build_contexts("docker build controller --tag panopticon-tools"),
                         [["controller"]])

    def test_scanner_manifest_is_required(self):
        runs = self._run_text(self._workflow())
        self.assertIn('--manifest "$manifest"', runs)
        self.assertIn('--tools-dir "$RUNNER_TEMP/${{ env.TOOLS_OUT }}"', runs)

    def test_gate_keeps_raw_inputs_and_reporting_uses_a_separate_directory(self):
        workflow = self._workflow()
        steps = workflow["jobs"]["scan"]["steps"]
        by_name = {step.get("name"): step for step in steps}
        gate = by_name["Gate on HIGH/CRITICAL tool findings (unverified-strict policy)"]
        prepare = by_name["Prepare Security and AI inventory reports"]
        upload = by_name["Upload actionable SARIF to GitHub Security tab"]
        self.assertIn('${{ env.TOOLS_OUT }}', gate["run"])
        self.assertIn("scripts/code_scanning_reports.py", prepare["run"])
        self.assertIn("code-scanning-reports/security",
                      upload["with"]["sarif_file"])
        self.assertLess(steps.index(gate), steps.index(prepare))
        self.assertLess(steps.index(prepare), steps.index(upload))

    def test_reports_and_raw_artifacts_are_attempted_after_a_gate_failure(self):
        steps = {step.get("name"): step
                 for step in self._workflow()["jobs"]["scan"]["steps"]}
        self.assertEqual(steps["Prepare Security and AI inventory reports"]["if"],
                         "always()")
        self.assertEqual(steps["Upload raw scanner captures"]["if"], "always()")
        self.assertIn("steps.prepare-reports.outcome == 'success'",
                      steps["Upload AI inventory"]["if"])
        self.assertIn("steps.prepare-reports.outcome == 'success'",
                      steps["Upload actionable SARIF to GitHub Security tab"]["if"])
        self.assertEqual(steps["Upload raw scanner captures"]["with"][
            "if-no-files-found"], "error")

    def test_inventory_is_visible_in_the_step_summary(self):
        steps = {step.get("name"): step
                 for step in self._workflow()["jobs"]["scan"]["steps"]}
        summary = steps["Publish AI inventory summary"]
        self.assertIn("ai-inventory.md", summary["run"])
        self.assertIn("GITHUB_STEP_SUMMARY", summary["run"])
        self.assertIn("steps.prepare-reports.outcome == 'success'", summary["if"])

    def test_zero_alert_audit_is_bound_to_the_processed_main_upload(self):
        workflow = self._workflow()
        steps = workflow["jobs"]["scan"]["steps"]
        by_name = {step.get("name"): step for step in steps}
        upload = by_name["Upload actionable SARIF to GitHub Security tab"]
        audit = by_name["Audit current main for open code-scanning alerts"]

        self.assertEqual(upload.get("id"), "upload-sarif")
        self.assertEqual(
            upload["uses"],
            "github/codeql-action/upload-sarif@"
            "b96794f015dfd88f77b49b1c93e0fa7110f94c63",
        )
        self.assertNotIn("wait-for-processing", upload.get("with", {}))
        self.assertLess(steps.index(upload), steps.index(audit))
        self.assertEqual(audit.get("timeout-minutes"), 5)

        condition = " ".join(audit["if"].split())
        self.assertEqual(
            condition,
            "always() && github.event_name == 'push' && "
            "github.ref == 'refs/heads/main' && "
            "steps.upload-sarif.outcome == 'success'",
        )
        self.assertEqual(audit["env"], {
            "GH_TOKEN": "${{ github.token }}",
            "SECURITY_SARIF_ID":
                "${{ steps.upload-sarif.outputs.sarif-id }}",
        })
        run = _without_comments(audit["run"])
        self.assertIn("python controller/scripts/code_scanning_audit.py", run)
        self.assertIn('--repository "$GITHUB_REPOSITORY"', run)
        self.assertIn('--server-url "$GITHUB_SERVER_URL"', run)
        self.assertIn('--ref "$GITHUB_REF"', run)
        self.assertIn('--sha "$GITHUB_SHA"', run)
        self.assertIn('--sarif-id "$SECURITY_SARIF_ID"', run)
        self.assertNotIn("sarif-ids", run)

    def test_zero_alert_audit_does_not_widen_permissions_or_replace_raw_gate(self):
        workflow = self._workflow()
        job = workflow["jobs"]["scan"]
        self.assertEqual(job["permissions"], {
            "contents": "read", "packages": "read",
            "security-events": "write", "actions": "read",
        })
        names = [step.get("name") for step in job["steps"]]
        self.assertIn(
            "Gate on HIGH/CRITICAL tool findings (unverified-strict policy)",
            names,
        )
        with open(FORK_WORKFLOW, encoding="utf-8") as fh:
            fork = yaml.safe_load(fh)
        fork_text = "\n".join(
            str(step.get("uses", "")) + "\n" + str(step.get("run", ""))
            for fork_job in fork.get("jobs", {}).values()
            for step in fork_job.get("steps", [])
        )
        self.assertNotIn("upload-sarif", fork_text)
        self.assertNotIn("code_scanning_audit.py", fork_text)

    def test_no_untrusted_github_context_in_run_scripts(self):
        for path in (WORKFLOW, FORK_WORKFLOW):
            with open(path, encoding="utf-8") as fh:
                workflow = yaml.safe_load(fh)
            for job in workflow["jobs"].values():
                for step in job.get("steps", []):
                    with self.subTest(workflow=path, step=step.get("name")):
                        self.assertEqual(_unsafe_run_expressions(step.get("run", "")), [])

    def test_event_fields_whitespace_brackets_compounds_and_comments_are_rejected(self):
        for expression in ("github.head_ref", " github.event.pull_request.head.ref ",
                           "github.event.pull_request.head.label",
                           "github.event.pull_request.head.repo.full_name",
                           "github.event.workflow_run.head_branch",
                           "github.event.head_commit.author.name", "toJSON(github.event)",
                           "github['event']['pull_request']['title']",
                           "github . event . issue . body",
                           "env.IMAGE || github.head_ref", "env.UNREVIEWED"):
            for template in ('echo "${{%s}}"', '# comment ${{%s}}'):
                with self.subTest(expression=expression, template=template):
                    self.assertEqual(len(_unsafe_run_expressions(template % expression)), 1)

    def test_reviewed_env_bindings_and_shell_environment_are_allowed(self):
        self.assertEqual(_unsafe_run_expressions(
            'echo "${{ env.IMAGE }} ${{env.TOOLS_OUT}} $GH_REPO"'), [])


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

    `tests/goldens/tool-raw/**` is the one class that cannot be composed away:
    those `*.raw` files are authentic, trimmed SCANNER OUTPUT -- one payload per
    adapter -- so a secret a scanner once reported is quoted there verbatim and
    gitleaks finds it again on every run. That is captured data, not code this
    repository authors, which is the fixture corpus's own argument. Every other
    in-tree literal was removed at source (tests/_test_helpers.py) rather than
    excluded. The glob is the captures, not the whole `tests/goldens/`
    directory (`scout.rendered.txt` there is rendered panopticon output, not a
    scanner capture): a blind spot is exactly as wide as the argument for it.
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
            self.assertEqual(env["GOLDEN_GLOB"], "tests/goldens/tool-raw/**", path)

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


class TestTheDeltaBaselineIsFetchedOnEveryRoute(unittest.TestCase):
    """#1790 owner ruling 2026-09-23, as amended by the controller's C1 ruling:
    EVERY route is delta-aware, and no route is inert.

    The first cut fetched a baseline on the PR routes only and left the push to
    main strict. That combination was self-defeating, and the review measured
    it: the moment `#1790`'s promotion merged, main's own gate failed on the 24
    findings it promotes; `security.yml` has one job, so the RUN's conclusion
    was `failure`; and the next PR's lookup (`--status success`) therefore found
    no run at its base commit and fell back to strict on all 24 -- which no
    author could clear from their own diff, so main never went green again and
    every subsequent PR inherited the same state.

    So: the push route resolves `github.event.before` (the previous main head)
    and the PR routes resolve `base.sha`, and from whichever sha that is the
    step walks up to five FIRST-PARENT ancestors looking for one with a
    successful run. `--status success` stays -- a red run's capture may be
    partial -- and walking further back only makes the gate stricter (an older
    baseline means more findings read as new), never looser.

    Everything else here is a fail-toward-strictness pin. The gate receives the
    flags only when a download actually happened, and the fetch step degrades to
    strict rather than to red (`continue-on-error: true`, review M3: a step
    timeout on a 5-minute deadline must not fail a required check over a
    missing convenience).
    """

    BASELINE = "Download the base commit's scanner captures"
    GATE = "Gate on HIGH/CRITICAL tool findings (unverified-strict policy)"
    PR_ROUTES = ((WORKFLOW, "scan"), (FORK_WORKFLOW, "fork-scan"))
    ROUTES = PR_ROUTES
    MAX_HOPS = 5

    def _job(self, path, job):
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)["jobs"][job]

    def _step(self, job, name):
        return next((s for s in job.get("steps", []) if s.get("name") == name),
                    None)

    def _budget(self, path, name):
        """Every NUMBER the fetch's bound is made of, parsed out of the script.

        Review N2. The three "bounded" pins this replaces were substring
        assertions, and substrings do not bound anything: `"MAX_HOPS=5"` is a
        substring of `"MAX_HOPS=500"`, `"DEADLINE=300"` of `"DEADLINE=3000"`,
        and a regex for `timeout` + digits matches any cap. All five inflations passed
        the whole suite, and together they put the pathological walk at ~50
        minutes against a job ceiling of 30 -- the step killed, the required
        check red, and every guard test still green. So the values are parsed
        and the ARITHMETIC is asserted, which is the thing that was meant.

        Each pattern must match exactly once: a second `timeout` cap on the
        same command, or a second `MAX_HOPS=`, is an ambiguity this must not
        silently resolve.
        """
        job = self._job(path, name)
        run = _without_comments(self._step(job, self.BASELINE)["run"])
        def one(pattern):
            found = re.findall(pattern, run)
            self.assertEqual(len(found), 1, (pattern, run))
            return int(found[0])
        return {
            "hops": one(r"MAX_HOPS=(\d+)"),
            "deadline": one(r"DEADLINE=(\d+)"),
            "limit": one(r"--limit (\d+)"),
            "list": one(r"timeout (\d+) gh run list"),
            "download": one(r"timeout (\d+) gh run download"),
            "api": one(r"timeout (\d+) gh api"),
            "ceiling": job["timeout-minutes"] * 60,
        }

    def test_both_pull_request_routes_fetch_the_base_commits_captures(self):
        for path, name in self.PR_ROUTES:
            with self.subTest(workflow=path):
                step = self._step(self._job(path, name), self.BASELINE)
                self.assertIsNotNone(step, path)
                self.assertEqual(step.get("id"), "baseline")
                run = _without_comments(step["run"])
                self.assertIn("gh run list --workflow security.yml", run)
                self.assertIn("--status completed", run)   # N1; see below
                self.assertIn("--json databaseId", run)
                self.assertIn("--limit 1", run)
                self.assertIn("gh run download", run)
                self.assertIn("-n raw-scanner-captures", run)
                self.assertIn('-D "$RUNNER_TEMP/baseline"', run)

    def test_each_route_resolves_its_own_base_and_reads_it_through_env(self):
        # One expression, pinned whole. A push to main compares against the
        # PREVIOUS main head (`github.event.before`); a pull request compares
        # against its base -- never its own head, which would carry the PR's
        # own findings and excuse every one of them. Any other event (schedule,
        # dispatch) resolves to the empty string, which the script reads as "no
        # base" and runs strict.
        for path, name in self.ROUTES:
            with self.subTest(workflow=path):
                step = self._step(self._job(path, name), self.BASELINE)
                self.assertEqual(
                    step["env"]["BASE_SHA"],
                    "${{ github.event_name == 'push' && github.event.before"
                    " || github.event.pull_request.base.sha }}")
                self.assertEqual(step["env"]["GH_TOKEN"], "${{ github.token }}")
                self.assertEqual(step["env"]["GH_REPO"], "${{ github.repository }}")
                self.assertNotIn("${{ github.event", _without_comments(step["run"]))

    def test_the_all_zero_sha_is_refused_rather_than_queried(self):
        # A branch creation and a force push report an all-zero `before`.
        # Protected main cannot produce either, which is exactly why the guard
        # is asserted rather than assumed: nothing else would catch its removal.
        for path, name in self.ROUTES:
            with self.subTest(workflow=path):
                run = _without_comments(
                    self._step(self._job(path, name), self.BASELINE)["run"])
                self.assertIn("ZERO_SHA=0000000000000000000000000000000000000000",
                              run)
                self.assertIn('[ "$sha" != "$ZERO_SHA" ]', run)

    def test_the_walk_back_is_bounded_and_first_parent(self):
        # The C1 fix, and the two properties that keep it safe. BOUNDED: a
        # baseline hunt that could walk the whole history would spend a
        # required check's budget on API calls. FIRST-PARENT: on this repo's
        # merge-commit history the first parent is main's own line, so the
        # walk stays on commits `security.yml` actually ran against.
        for path, name in self.ROUTES:
            with self.subTest(workflow=path):
                run = _without_comments(
                    self._step(self._job(path, name), self.BASELINE)["run"])
                self.assertIn('[ "$hops" -ge "$MAX_HOPS" ]', run)
                self.assertIn('gh api "repos/$GH_REPO/commits/$sha"', run)
                self.assertIn(".parents[0].sha", run)
                # Parsed, not matched as a substring (N2): `MAX_HOPS=500`
                # contains `MAX_HOPS=5`.
                self.assertEqual(self._budget(path, name)["hops"], self.MAX_HOPS)

    def test_the_status_filter_admits_a_completed_run(self):
        # Review N1. `--status success` was kept in fix round 1 to stop a
        # partial baseline from excusing head findings -- and by fix round 2
        # that was belt over a working brace: `load_baseline` runs
        # `lost_required_coverage` on the baseline itself and REFUSES a partial
        # or unparseable one loudly and strictly (I2). What the belt still did
        # was create an ABSORBING STATE. A HIGH the owner dismisses on the
        # Security tab rather than removing from tool output reds main's own
        # run; each following commit reaches the last green one a hop further
        # back; at the sixth it is past `MAX_HOPS`, and from then on NOTHING --
        # no PR, no push -- can find a baseline, which is C1 restored with no
        # way out. Six runs lost to a registry outage, or a 90-day artifact
        # expiry on a slow repo, reach the same state with no finding at all.
        #
        # `completed` admits a red run's capture, which `if: always()` has
        # always uploaded. The walk stays for the cases a status filter cannot
        # help with: an expired artifact, and a cancelled run that has none.
        for path, name in self.ROUTES:
            with self.subTest(workflow=path):
                run = _without_comments(
                    self._step(self._job(path, name), self.BASELINE)["run"])
                self.assertIn("--status completed", run)
                # Not merely "the flag changed": the word must be gone from the
                # script, notice text included, or a later edit reads as though
                # the filter were still there.
                self.assertNotIn("success", run)

    def test_the_download_target_is_cleared_before_every_attempt(self):
        # Review N3. Every hop downloads into the SAME directory. A download
        # that fails after extracting part of its archive leaves those files
        # behind, and a later successful hop extracts over them -- a baseline
        # spliced from two different commits, which `lost_required_coverage`
        # cannot see because the surviving manifest is the later run's. Both
        # commits are on main and within five hops, so the blast radius is
        # small; the fix is one line, so the radius is not the argument.
        for path, name in self.ROUTES:
            with self.subTest(workflow=path):
                run = _without_comments(
                    self._step(self._job(path, name), self.BASELINE)["run"])
                self.assertEqual(run.count("rm -rf"), 1)
                # In the `&&` chain, BEFORE the download: a clear that ran
                # after it, or in a branch the download does not share, clears
                # nothing that matters.
                clear = run.index("rm -rf")
                self.assertLess(clear, run.index("gh run download"))
                self.assertGreater(clear, run.index("gh run list"))
                # Guarded by `[ -n "${RUNNER_TEMP:-}" ]`, because this is the one
                # command in the step where an empty value is destructive
                # rather than useless -- and guarded rather than `:?`-expanded,
                # because a `:?` failure aborts the step (rc=1, no `found=`),
                # the one thing the step promises never to do; the guard fails
                # this hop and the run degrades to strict.
                self.assertIn(
                    '[ -n "${RUNNER_TEMP:-}" ] && rm -rf "$RUNNER_TEMP/baseline"',
                    run)
                self.assertNotIn("${RUNNER_TEMP:?}", run)

    def test_the_notice_names_the_sha_the_baseline_came_from(self):
        for path, name in self.ROUTES:
            with self.subTest(workflow=path):
                run = _without_comments(
                    self._step(self._job(path, name), self.BASELINE)["run"])
                self.assertEqual(run.count("::notice::"), 2)   # found, and not
                self.assertIn("hop(s) back from", run)

    def test_the_fetch_precedes_the_gate(self):
        for path, name in self.PR_ROUTES:
            with self.subTest(workflow=path):
                steps = [s.get("name") for s in self._job(path, name)["steps"]]
                self.assertLess(steps.index(self.BASELINE), steps.index(self.GATE))

    def test_the_fetch_degrades_to_strict_without_softening_the_step(self):
        # Review M3, fix round 2. The first answer was `continue-on-error: true`
        # plus `timeout-minutes: 5`, which bought the degradation by making one
        # step's failure invisible -- and `continue-on-error` is refused
        # OUTRIGHT in these two files (`TestNeitherWorkflowSwallowsAFailure`),
        # because it is the one-line edit that turns the gate's own refusal
        # into a pass. Buying a property by weakening that ban is the wrong
        # trade even when this particular step is harmless.
        #
        # So neither key is here. The same property is bought inside the
        # SCRIPT: every `gh` call is wrapped in coreutils `timeout`, every one
        # of them sits in an `if`/`&&` position where `set -e` does not fire,
        # and a `timeout` that fires returns 124 -- a failure like any other,
        # which advances the walk or ends it. A slow or absent `gh` therefore
        # costs the DELTA (no `found=true`, so the gate reads the empty string
        # and runs strict) and can never cost the check.
        for path, name in self.ROUTES:
            with self.subTest(workflow=path):
                step = self._step(self._job(path, name), self.BASELINE)
                self.assertNotIn("continue-on-error", step)
                self.assertNotIn("timeout-minutes", step)
                gate = self._step(self._job(path, name), self.GATE)
                self.assertNotIn("continue-on-error", gate)

    def test_every_gh_call_in_the_fetch_carries_its_own_deadline(self):
        # The half of the trade above that has to be measured rather than
        # asserted in prose: ONE unwrapped `gh` is a step that can hang until
        # the JOB's 30-minute ceiling kills it, which reds the required check
        # exactly as `continue-on-error` was there to prevent.
        for path, name in self.ROUTES:
            with self.subTest(workflow=path):
                run = _without_comments(
                    self._step(self._job(path, name), self.BASELINE)["run"])
                calls = [m.start() for m in re.finditer(r"(?<![\w-])gh\s", run)]
                self.assertEqual(len(calls), 3, run)   # list, download, api
                for pos in calls:
                    self.assertRegex(run[max(0, pos - 24):pos],
                                     r"timeout \d+ $")

    def test_the_whole_walk_is_bounded_well_inside_the_jobs_ceiling(self):
        # Per-call deadlines do not bound the WALK. The pathological path is a
        # completed run at every sha whose download fails: six list calls, six
        # downloads and five parent lookups, which at the shipped caps is
        # 1740s against a job ceiling of 1800 -- inside it by a minute, which
        # is not a bound anyone should rely on. `DEADLINE`, tested at the TOP
        # of the loop, is what bounds it: an iteration may START inside the
        # budget, so the true worst case is the budget plus ONE WHOLE
        # ITERATION's caps (N4: list + download + api, not one call's).
        #
        # Asserted as ARITHMETIC over the values parsed out of the script
        # (N2), so inflating any literal fails here even though each one on its
        # own still "looks" pinned.
        for path, name in self.ROUTES:
            with self.subTest(workflow=path):
                b = self._budget(path, name)
                self.assertIn('[ "$SECONDS" -lt "$DEADLINE" ]',
                              _without_comments(
                                  self._step(self._job(path, name),
                                             self.BASELINE)["run"]))
                iteration = b["list"] + b["download"] + b["api"]
                worst = b["deadline"] + iteration
                # Half the job's budget: the scan itself has to fit in the rest
                # of it, so "under the ceiling" is not the bar -- "nowhere near
                # it" is.
                self.assertLess(worst, b["ceiling"] // 2,
                                "worst-case fetch %ds vs job ceiling %ds: %r"
                                % (worst, b["ceiling"], b))
                # And the un-deadlined walk, which is what `DEADLINE` exists
                # for. Not required to fit -- it is stated so a reader can see
                # why the budget is load-bearing rather than decorative.
                undeadlined = ((b["hops"] + 1) * (b["list"] + b["download"])
                               + b["hops"] * b["api"])
                self.assertGreater(undeadlined, worst)
                self.assertEqual(b["limit"], 1)   # one run id, parsed not matched

    def test_the_step_succeeds_in_both_branches_and_writes_one_output(self):
        for path, name in self.ROUTES:
            with self.subTest(workflow=path):
                step = self._step(self._job(path, name), self.BASELINE)
                run = _without_comments(step["run"])
                self.assertIn("set -euo pipefail", run)
                self.assertIn("else", run)
                self.assertIn("::notice::", run)
                # Both arms write the output the gate reads. A branch that
                # wrote none would leave the gate reading an empty string,
                # which is strict -- but by accident rather than by decision.
                self.assertEqual(run.count('>> "$GITHUB_OUTPUT"'), 1)
                self.assertIn('echo "found=$found" >> "$GITHUB_OUTPUT"', run)

    def test_no_route_skips_the_fetch(self):
        # The `if: github.event_name == 'pull_request'` this replaces is what
        # made the feature inert: it left main strict, main's gate red on the
        # 24 promoted findings, the run's conclusion `failure`, and therefore
        # no successful run for any PR's lookup to find. Every route fetches;
        # which sha it fetches FOR is decided by `BASE_SHA`, and a route with
        # no base resolves to the empty string and runs strict on its own.
        for path, name in self.ROUTES:
            with self.subTest(workflow=path):
                step = self._step(self._job(path, name), self.BASELINE)
                expected = ("github.event_name == 'push' || github.event_name == 'pull_request'"
                            if path == WORKFLOW else None)
                self.assertEqual(step.get("if"), expected)

    def test_the_gate_receives_the_flags_only_when_the_download_succeeded(self):
        for path, name in self.PR_ROUTES:
            with self.subTest(workflow=path):
                gate = self._step(self._job(path, name), self.GATE)
                self.assertEqual(gate["env"]["BASELINE_FOUND"],
                                 "${{ steps.baseline.outputs.found }}")
                run = _without_comments(gate["run"])
                self.assertIn('if [ "$BASELINE_FOUND" = "true" ]; then', run)
                self.assertIn(
                    '--baseline-dir "$RUNNER_TEMP/baseline/panopticon-tools-output"',
                    run)
                self.assertIn(
                    '--baseline-manifest '
                    '"$RUNNER_TEMP/baseline/panopticon-tools-manifest.json"',
                    run)
                # Exactly one invocation of the gate, so the exclusions and the
                # flags cannot drift between a baseline branch and a strict one.
                self.assertEqual(run.count("security_gate.py"), 1)
                self.assertEqual(run.count("--baseline-dir"), 1)

    def test_every_route_fetches_before_it_checks_out_the_scan_target(self):
        # Review M9, widened in fix round 2. This is the only step in either
        # job that exports `GH_TOKEN`, and both jobs now hold `actions: read`,
        # so it runs before ANY scanned content is on disk -- fork-controlled
        # on one route, a PR branch's own on the other. The two files were
        # already identical in the step's CONTENT; this makes them identical in
        # its POSITION too, which is one less thing for a later reader to
        # "reconcile" in the wrong direction.
        for path, name in self.ROUTES:
            with self.subTest(workflow=path):
                steps = [s.get("name") for s in self._job(path, name)["steps"]]
                self.assertLess(steps.index("Checkout trusted scanner controller"),
                                steps.index(self.BASELINE))
                self.assertLess(steps.index(self.BASELINE),
                                steps.index("Checkout scan target"))

    def test_a_skipped_fetch_leaves_the_gate_strict(self):
        # The push-to-main route skips the fetch, and a skipped step's outputs
        # are the empty string -- which is not "true", so no flag is passed.
        # This is the whole mechanism by which one gate command serves both
        # routes; it is asserted rather than assumed because the alternative
        # (a second, strict copy of the command) is what the drift test bans.
        # A fetch that timed out, or one whose walk-back found nothing, never
        # writes `found=true`; the gate tests for that literal, so anything
        # else -- including the empty string a failed step leaves behind --
        # runs strict through the same single command.
        gate = self._step(self._job(WORKFLOW, "scan"), self.GATE)
        run = _without_comments(gate["run"])
        self.assertIn('if [ "$BASELINE_FOUND" = "true" ]; then', run)
        self.assertNotIn('"$BASELINE_FOUND" !=', run)
        self.assertEqual(gate.get("if"), "github.event_name == 'push' || github.event_name == 'pull_request'")

    def test_actions_read_is_the_only_permission_either_file_gained(self):
        # Pinned as whole blocks: `actions: read` is what reads another run's
        # artifacts, and nothing else moved to get it.
        self.assertEqual(
            self._job(WORKFLOW, "scan")["permissions"],
            {"contents": "read", "packages": "read",
             "security-events": "write", "actions": "read"})
        self.assertEqual(
            self._job(FORK_WORKFLOW, "fork-scan")["permissions"],
            {"contents": "read", "packages": "read", "actions": "read"})
        self.assertEqual(
            self._job(FORK_WORKFLOW, "unlabel")["permissions"],
            {"pull-requests": "write"})
        with open(FORK_WORKFLOW, encoding="utf-8") as fh:
            self.assertEqual(yaml.safe_load(fh)["permissions"],
                             {"contents": "read", "packages": "read"})


class TestStrictScheduledBackstop(unittest.TestCase):
    def setUp(self):
        with open(WORKFLOW, encoding="utf-8") as fh:
            self.workflow = yaml.safe_load(fh)
        self.job = self.workflow["jobs"]["scan"]
        self.steps = {s.get("name"): s for s in self.job["steps"]}

    def test_full_events_have_a_distinct_name_even_when_skipped(self):
        self.assertEqual(self.workflow[True]["schedule"], [{"cron": "23 7 * * 1"}])
        self.assertIn("workflow_dispatch", self.workflow[True])
        self.assertEqual(self.job["name"],
                         "${{ (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') && 'strict-full-tree' || 'scan' }}")
        self.assertIn("(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') && github.ref == 'refs/heads/main'",
                      " ".join(self.job["if"].split()))

    def test_full_gate_has_no_baseline_and_reporting_survives_red(self):
        gate = self.steps["Strict full-tree gate"]
        self.assertEqual(gate["if"], "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'")
        self.assertIn("python controller/skill/scripts/security_gate.py", gate["run"])
        self.assertNotIn("baseline", gate["run"])
        self.assertEqual(gate["run"].count("--exclude"), 2)
        for name in ("Publish strict security snapshot and summary", "Upload strict security snapshot"):
            self.assertIn("always()", self.steps[name]["if"])
            self.assertIn("github.event_name == 'schedule'", self.steps[name]["if"])
        self.assertEqual(self.steps["Upload strict security snapshot"]["with"]["name"],
                         "strict-security-snapshot")

    def test_history_lookup_precedes_target_and_has_the_only_new_token(self):
        names = list(self.steps)
        step = self.steps["Download previous scheduled main snapshot"]
        self.assertLess(names.index(step["name"]), names.index("Checkout scan target"))
        self.assertEqual(step["env"]["GH_TOKEN"], "${{ github.token }}")
        self.assertIn("security-backstop.py retrieve", step["run"])
        self.assertNotIn("GH_TOKEN", self.steps["Publish strict security snapshot and summary"].get("env", {}))
        self.assertIn("docker image inspect", self.steps["Record actual scanner image identity"]["run"])

    def test_delta_steps_are_only_for_pr_and_push(self):
        for name in ("Download the base commit's scanner captures",
                     "Gate on HIGH/CRITICAL tool findings (unverified-strict policy)"):
            self.assertEqual(self.steps[name]["if"],
                             "github.event_name == 'push' || github.event_name == 'pull_request'")


if __name__ == "__main__":
    unittest.main()

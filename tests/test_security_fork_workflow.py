"""#1900 fix round 2: the fork scan lives in its OWN workflow.

The gate used to be a second trigger on `security.yml`, and that was unsound
for a reason that is the mirror image of the reason the gate exists. A job
skipped by an `if:` still posts a check run under its own name, and GitHub
reports a skipped job as Success -- so once `pull_request_target` could reach
`security.yml`, ANY label on ANY PR to main produced a run in which `scan`
skipped, posting a green `scan` newer than (and therefore superseding) a real
failure. On a fork PR that erased the refusal; on a same-repo PR it erased a
genuinely failed security gate. The premise the gate relied on is the premise
that broke it.

So: no skipped job may ever carry a required check's name. `security.yml`
keeps `push` + `pull_request` and never runs on a fork head; this file owns
`pull_request_target` and reports under `fork-scan`, a name nothing else
produces. `fork-scan` never skips for a fork PR -- it runs and either refuses
(red) or scans (a real result) -- so the fork PR's verdict under that name is
always something this repo deliberately posted.
"""
import os
import unittest

import yaml

from shell_reader import join_continuations
from shell_reader import without_comments

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
WORKFLOW_DIR = os.path.join(ROOT, ".github", "workflows")
FORK = os.path.join(WORKFLOW_DIR, "security-fork.yml")
BASE = os.path.join(WORKFLOW_DIR, "security.yml")

LABEL = "safe-to-scan"
FOREIGN_HEAD = (
    "github.event.pull_request.head.repo.full_name != github.repository")


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _script(step):
    """One step's `run:`, comments dropped and continuations folded."""
    return join_continuations(without_comments(step.get("run", "")))


def _step(job, name):
    return next((s for s in job.get("steps", []) if s.get("name") == name), None)


class TestTheForkWorkflowsTriggerSurface(unittest.TestCase):
    def setUp(self):
        self.wf = _load(FORK)

    def test_it_is_a_pull_request_target_workflow_and_only_that(self):
        # PyYAML 1.1 parses the unquoted `on:` key as the boolean True.
        on = self.wf.get(True, {})
        self.assertEqual(sorted(on), ["pull_request_target"])
        self.assertEqual(on["pull_request_target"].get("branches"), ["main"])

    def test_every_action_that_can_change_the_verdict_is_a_trigger(self):
        # `opened` IS here, unlike the round-1 shape: `fork-scan` must run (and
        # refuse) the moment a fork PR appears, so the PR carries a real red
        # check rather than no check at all. `labeled` admits it;
        # `synchronize`/`reopened` are what `unlabel` revokes on.
        self.assertEqual(
            self.wf.get(True, {})["pull_request_target"].get("types"),
            ["opened", "synchronize", "reopened", "labeled"])

    def test_the_workflow_level_grant_is_read_only(self):
        self.assertEqual(self.wf.get("permissions"),
                         {"contents": "read", "packages": "read"})

    def test_the_job_set_is_exactly_the_two_this_file_is_for(self):
        # m2: this is the privileged file -- every job in it runs on an event
        # a fork author can raise. A third job added here would be reviewed by
        # nothing except the continue-on-error sweep, so the SET is pinned and
        # adding one is a visible decision with a test to change.
        self.assertEqual(sorted(self.wf["jobs"]), ["fork-scan", "unlabel"])


class TestForkScanNeverSkipsForAFork(unittest.TestCase):
    """The whole point of the second file: under this name a fork PR always
    carries something this repo posted on purpose."""

    def setUp(self):
        self.job = _load(FORK)["jobs"]["fork-scan"]

    def test_its_condition_is_the_fork_event_test_and_nothing_more(self):
        # No LABEL test here: a label test in the job condition would make an
        # unlabelled fork PR SKIP -- Success -- which is the defect this
        # restructure removes. The label is checked by the first STEP, which
        # fails, so the name always carries a deliberate verdict.
        #
        # m4: the event-name conjunct is redundant today (this file has one
        # trigger, pinned above) and is here so the job's own text says what
        # it is for; the foreign-head test alone is true for any event with no
        # pull_request in its payload.
        self.assertEqual(
            " ".join(str(self.job.get("if", "")).split()),
            "github.event_name == 'pull_request_target' && " + FOREIGN_HEAD)

    def test_it_holds_no_write_grant_at_all(self):
        # No security-events (it uploads nothing), no pull-requests (it writes
        # no labels): the only job here that writes anything is `unlabel`.
        # #1790's `actions: read` is READ, and it reads one thing -- the base
        # commit's own `raw-scanner-captures` artifact from `security.yml` on
        # main, which no fork can write.
        self.assertEqual(self.job.get("permissions"),
                         {"contents": "read", "packages": "read",
                          "actions": "read"})


class TestTheLabelGateIsTheFirstThingThatRuns(unittest.TestCase):
    def setUp(self):
        self.job = _load(FORK)["jobs"]["fork-scan"]
        self.gate = self.job["steps"][0]

    def test_the_gate_precedes_every_checkout(self):
        self.assertEqual(self.gate.get("name"), "Gate on the safe-to-scan label")
        uses = [str(s.get("uses", "")) for s in self.job["steps"]]
        self.assertFalse(
            any(u.startswith("actions/") for u in uses[:1]),
            "the first step must be the gate, not an action")

    def test_it_refuses_on_all_three_tests_and_every_branch_exits(self):
        run = _script(self.gate)
        self.assertIn("::error::", run)
        # A scan starts only when a maintainer's deliberate act was applying
        # THIS label. Three tests, and the middle one is the strict closure
        # (#1900 fix round 3): without it, any label applied while a stale
        # `safe-to-scan` stood -- left by a failed revoke, or by the seconds
        # between a push and `unlabel` finishing -- would scan the new head
        # and post a GREEN required check on a head nobody reviewed.
        self.assertIn('"$ACTION" != "labeled"', run)
        self.assertIn('"$LABEL" != "safe-to-scan"', run)
        self.assertIn('"$LABELLED" != "true"', run)
        # m1: each test must carry its OWN exit. Asserting `exit 1` appears
        # somewhere left the first branch neuterable on its own -- and that is
        # the branch that stops a `synchronize` from scanning on a stale
        # label.
        self.assertEqual(run.count("exit 1"), 3)

    def test_it_reads_the_event_only_through_env(self):
        self.assertNotIn("${{ github.event", _script(self.gate))
        env = self.gate.get("env") or {}
        self.assertEqual(env.get("ACTION"), "${{ github.event.action }}")
        self.assertEqual(env.get("LABEL"), "${{ github.event.label.name }}")
        self.assertEqual(
            env.get("LABELLED"),
            "${{ contains(github.event.pull_request.labels.*.name, "
            "'safe-to-scan') }}")

    def test_the_controller_is_always_the_base_sha(self):
        # LITERAL, with no `||` fallback to a head SHA: this file runs only
        # under pull_request_target, so there is no event here whose head is
        # trusted, and an expression with a head branch in it is one edit away
        # from executing the fork's own scanner as the controller.
        controller = next(
            s for s in self.job["steps"]
            if str(s.get("uses", "")).startswith("actions/checkout")
            and (s.get("with") or {}).get("path") == "controller")
        self.assertEqual(controller["with"]["ref"],
                         "${{ github.event.pull_request.base.sha }}")
        self.assertIs(controller["with"].get("persist-credentials"), False)

    def test_the_target_is_the_fork_head_read_only(self):
        target = next(
            s for s in self.job["steps"]
            if str(s.get("uses", "")).startswith("actions/checkout")
            and (s.get("with") or {}).get("path") == "target")
        self.assertIn("head.repo.full_name", target["with"]["repository"])
        self.assertIn("head.sha", target["with"]["ref"])
        self.assertIs(target["with"].get("persist-credentials"), False)


class TestTheForkJobHasNothingToReach(unittest.TestCase):
    def setUp(self):
        self.job = _load(FORK)["jobs"]["fork-scan"]

    def test_it_never_logs_into_a_registry(self):
        uses = " ".join(str(s.get("uses", "")) for s in self.job["steps"])
        self.assertNotIn("docker/login-action", uses)

    def test_it_uploads_no_sarif(self):
        # It holds no security-events grant, so an upload could not work --
        # and it must not be added back with a grant to match: under
        # pull_request_target the run's github.ref is the BASE branch, so the
        # findings would be filed against main's Security tab.
        uses = " ".join(str(s.get("uses", "")) for s in self.job["steps"])
        self.assertNotIn("upload-sarif", uses)

    def test_it_passes_no_dependency_flag(self):
        runs = "\n".join(_script(s) for s in self.job["steps"] if "run" in s)
        self.assertNotIn("--deps", runs)

    def test_it_runs_the_scanners_from_the_trusted_controller(self):
        runs = "\n".join(_script(s) for s in self.job["steps"] if "run" in s)
        self.assertIn("python controller/skill/scripts/run_tools.py", runs)
        self.assertIn("python controller/skill/scripts/security_gate.py", runs)
        self.assertIn("-r controller/.github/requirements-gate.txt", runs)
        self.assertNotIn("target/.github/requirements", runs)
        self.assertNotIn("python target/", runs)


class TestTheLabelDiesOnEveryNewHead(unittest.TestCase):
    """The maintainer approved a HEAD, not a pull request: approve a benign
    diff, push the payload, and a label that survived would be the whole hole.
    """

    def setUp(self):
        self.job = _load(FORK)["jobs"]["unlabel"]

    def test_it_fires_on_a_new_head_and_on_a_reopen_and_only_for_a_fork(self):
        # M2: the ASSEMBLED boolean, not four fragments. `A && B && x || y`
        # passes any set of `in` checks and runs this job on same-repo
        # reopens -- the same lesson TST-B1B taught for the scan routing.
        compact = " ".join(str(self.job.get("if", "")).split())
        self.assertEqual(
            compact,
            "github.event_name == 'pull_request_target' && "
            + FOREIGN_HEAD +
            " && (github.event.action == 'synchronize' || "
            "github.event.action == 'reopened')")

    def test_it_holds_exactly_one_write_scope_and_nothing_else(self):
        self.assertEqual(self.job.get("permissions"),
                         {"pull-requests": "write"})

    def test_it_checks_nothing_out(self):
        self.assertEqual(
            [s for s in self.job.get("steps", [])
             if str(s.get("uses", "")).startswith("actions/checkout")], [])

    def test_it_reaches_event_data_only_through_env(self):
        run = "\n".join(_script(s) for s in self.job["steps"] if "run" in s)
        self.assertNotIn("${{ github.event", run)
        env = {}
        for step in self.job["steps"]:
            env.update(step.get("env") or {})
        self.assertEqual(env.get("PR_NUMBER"),
                         "${{ github.event.pull_request.number }}")
        self.assertEqual(env.get("REPO"), "${{ github.repository }}")

    def test_it_deletes_the_label_and_fails_on_anything_but_a_404(self):
        # M1: `assertIn("404", ...)` was satisfiable by a TRAILING comment --
        # `without_comments` drops whole-line comments only -- so
        # `gh api ... || true  # 404 is fine` would have passed while
        # reintroducing the fail-open. Assert the STRUCTURE instead: the
        # narrow tolerance, the non-zero exit that everything else takes, and
        # the absence of the blanket swallow.
        run = "\n".join(_script(s) for s in self.job["steps"] if "run" in s)
        self.assertIn("--method DELETE", run)
        self.assertIn("issues/$PR_NUMBER/labels/safe-to-scan", run)
        self.assertIn("HTTP 404", run)
        self.assertIn("exit 1", run)
        self.assertNotIn("|| true", run)


class TestTheTwoWorkflowsDoNotDrift(unittest.TestCase):
    """The fork job is a COPY of the trusted job's scanning half. A copy that
    drifts is worse than no copy: the fork path would quietly stop being the
    thing this repo tests on every push to main."""

    def setUp(self):
        self.base = _load(BASE)["jobs"]["scan"]
        self.fork = _load(FORK)["jobs"]["fork-scan"]

    def test_the_scanner_invocation_is_the_same_modulo_the_deps_flag(self):
        base = _script(_step(self.base, "Run static-analysis tools")).split()
        fork = _script(_step(self.fork, "Run static-analysis tools")).split()
        self.assertIn("--deps", base)
        self.assertEqual([t for t in base if t != "--deps"], fork)

    def test_the_gate_command_is_identical(self):
        name = "Gate on HIGH/CRITICAL tool findings (unverified-strict policy)"
        self.assertEqual(_script(_step(self.base, name)).split(),
                         _script(_step(self.fork, name)).split())

    def test_the_baseline_fetch_is_identical(self):
        # Review M6. This class is the only one that compares the two files
        # token for token; the per-file substring pins in
        # `test_security_workflow.py` would all pass with the two copies
        # disagreeing about `--limit`, `--jq`, `--status success`, the hop
        # bound or the `::notice::` text. The fork route is gated on the same
        # terms as the same-repo one or it is not the same gate.
        name = "Download the base commit's scanner captures"
        base, fork = _step(self.base, name), _step(self.fork, name)
        self.assertIsNotNone(base)
        self.assertIsNotNone(fork)
        self.assertEqual(_script(base).split(), _script(fork).split())
        self.assertEqual(base.get("env"), fork.get("env"))
        self.assertEqual(base.get("timeout-minutes"), fork.get("timeout-minutes"))
        self.assertEqual(base.get("continue-on-error"),
                         fork.get("continue-on-error"))

    def test_the_image_step_is_identical(self):
        name = "Pull or build panopticon-tools image"
        base, fork = _step(self.base, name), _step(self.fork, name)
        self.assertEqual(_script(base).split(), _script(fork).split())
        self.assertEqual(base.get("timeout-minutes"),
                         fork.get("timeout-minutes"))

    def test_the_python_version_is_identical(self):
        # m3: the four command pins below would all pass with the two files on
        # different interpreters, which is exactly the drift that makes "the
        # fork path runs what main runs" stop being true.
        name = "Set up Python"
        self.assertEqual(_step(self.base, name)["with"]["python-version"],
                         _step(self.fork, name)["with"]["python-version"])

    def test_the_gate_deps_install_is_identical(self):
        name = "Install Python deps"
        self.assertEqual(_script(_step(self.base, name)).split(),
                         _script(_step(self.fork, name)).split())


class TestNeitherWorkflowSwallowsAFailure(unittest.TestCase):
    """I2: `continue-on-error: true` on the gate step (or on the job) turns a
    refusal into a green check and lets every later step run anyway. It is a
    one-line edit that no other assertion here would catch, so it is refused
    outright -- neither file has any use for it.

    #1790 fix round 1 briefly carved out the baseline fetch, to stop a slow
    `gh run download` from reding a required check. Fix round 2 took the
    exemption back and bought the same degradation inside that step's script
    instead (per-call `timeout`, a wall-clock budget, every call in an
    `if`/`&&` position): a rule that admits its first exception stops being
    read as a rule, and the property was available without one.
    """

    def test_no_continue_on_error_anywhere_in_either_workflow(self):
        offenders = []
        for path in (BASE, FORK):
            wf = _load(path)
            for name, job in (wf.get("jobs") or {}).items():
                if "continue-on-error" in job:
                    offenders.append("%s / job %s" % (os.path.basename(path), name))
                for step in job.get("steps") or []:
                    if "continue-on-error" in step:
                        offenders.append("%s / %s / step %r"
                                         % (os.path.basename(path), name,
                                            step.get("name")))
        self.assertEqual(offenders, [], "continue-on-error turns a refusal "
                                        "into a pass: %s" % offenders)


class TestBothWorkflowsScanInRedteam(unittest.TestCase):
    """Owner ruling 2026-09-26 (relayed by Claude): this repository's own CI
    scans in `redteam` on both routes. Today the mode turns off the
    virtualenv skip and lets the gate re-admit name-suppressed findings
    (policy C); #1839's PR 5 adds the split that motivates the switch, under
    which `standard` honours a target's own `.bandit`, `# nosec`, `# nosemgrep`
    and `gitleaks:allow` and `redteam` honours none. `standard` is an operator
    scanning their own repository; the fork route scans a fork-authored tree
    on the required `fork-scan` check, and the same-repo route must capture
    in the same mode because its captures are the baseline the next PR's gate
    diffs against and nothing records the mode. So the mode is pinned as one
    attached pair on every scanner run, every gate call and the backstop
    snapshot, in both files."""

    GATE = "Gate on HIGH/CRITICAL tool findings (unverified-strict policy)"
    STEPS = {
        BASE: ("scan", ("Run static-analysis tools", GATE, "Strict full-tree gate",
                        "Publish strict security snapshot and summary")),
        FORK: ("fork-scan", ("Run static-analysis tools", GATE)),
    }

    def test_every_scanner_run_gate_and_snapshot_names_redteam(self):
        for path, (job_name, names) in self.STEPS.items():
            job = _load(path)["jobs"][job_name]
            for name in names:
                with self.subTest(workflow=os.path.basename(path), step=name):
                    step = _step(job, name)
                    self.assertIsNotNone(step, name)
                    tokens = _script(step).split()
                    self.assertEqual(tokens.count("--security"), 1, tokens)
                    self.assertEqual(tokens[tokens.index("--security") + 1],
                                     "redteam")


if __name__ == "__main__":
    unittest.main()

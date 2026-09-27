"""Loop checkpoint and request integrity tests."""
import ast
import contextlib
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import pytest

import scripts.driver as driver
import scripts.loop_batch as loop_batch
import scripts.orchestrate as orchestrate
import scripts.phases.review as review
import scripts.phases.runio as runio
import scripts.runners.base as base
from tests._test_helpers import (all_proven_artifact as _all_proven_artifact, refuted_tool_policy_artifact as _refuted_artifact)
from tests._test_helpers import docker_probe_runner, write_host_evidence
from scripts import hosts


from tests.orchestrate_helpers import (FakeRunner, LoopCase, _ALL_PROVEN)

def setUpModule():
    global _patch, _readiness_docker_patch
    _patch = mock.patch("scripts.host_probes.run_probes",
                        side_effect=lambda host, target, **kw: _all_proven_artifact(host))
    _patch.start()
    # #1637 P08: the `readiness` phase leads PHASES and fails closed on a
    # missing tools image, so every loop below would stop there instead of at
    # the checkpoint it is about. A fake runner, never a real daemon.
    _readiness_docker_patch = mock.patch(
        "scripts.phases.readiness_checks.DOCKER_RUNNER", docker_probe_runner())
    _readiness_docker_patch.start()


def tearDownModule():
    _patch.stop()
    _readiness_docker_patch.stop()


class TestTheClaudeRunnerCannotBeReachedByAccident(LoopCase):
    """#1616 item 8, fix round 1 (F1): the guard has to bite on the accident it
    was written for, which is a `driver loop` test that forgets to patch
    `runner_for` -- claude is the default host, so that test builds the real
    family runner and dispatches through `iter_batch`.

    `iter_batch`'s worker converts any `Exception` from `run_entry` into a
    failed RunResult, by contract ("a runner crash is a failed entry, never a
    crashed loop"), so a refusal raised as one is swallowed and the run still
    reports `complete` -- the loop goes green on three launches that reached
    the real runner. The refusal is therefore a BaseException (pytest's own
    `Failed`), which that `except Exception` cannot hold, and it escapes
    `orchestrate.loop` too (it catches `KeyboardInterrupt` and `Exception`).
    """

    def test_a_loop_that_forgets_to_patch_runner_for_fails_the_test(self):
        d, floor = self._repo()
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(pytest.fail.Exception) as cm:
                orchestrate.loop(self._args(d))
        self.assertIn("runner_for", str(cm.exception))      # names the way out


class TestExhaustedReviewCellsAreNamedOnComplete(LoopCase):
    """#1616 item 2: a review cell that spends `MAX_CELL_ATTEMPTS` without
    ever returning an acceptable findings file leaves the phase DONE --
    `review_done` counts exhaustion as done so the run advances rather than
    wedging -- and the run therefore ends `complete`, reading exactly like a
    clean one. The terminal status has to be able to tell them apart."""

    class NeverAcceptable(FakeRunner):
        """Self-writes a findings file the contract rejects, every time: the
        cell never completes, and no LAUNCH ever fails, so the per-entry cap
        never trips and only the per-cell retry budget bounds the run."""

        def run_entry(self, entry, env):
            if not entry["id"].startswith("review-"):
                return super().run_entry(entry, env)
            self.launched.append(entry["id"])
            runio._write_json(entry["out_file"], {"findings": [None]})
            return base.RunResult(entry_id=entry["id"], ok=True, text="written",
                                  usage={}, cost_usd=0.0, model=None,
                                  session_id=None, denials=[], error=None)

    def test_a_cell_that_spends_its_retry_budget_is_named_in_the_terminal_status(self):
        d, floor = self._repo()
        status = self._run_loop(d, floor, self.NeverAcceptable())
        self.assertEqual(status["status"], "complete", status)
        self.assertTrue(review._cell_exhausted(d, "app", "SEC"))
        self.assertEqual(status["cells_exhausted"], 1, status)
        self.assertIn("cells_exhausted: 1", status["message"])
        self.assertIn("app/SEC", status["message"])

    def test_a_clean_run_says_nothing_about_exhausted_cells(self):
        # The other half: the key is absent, not zero, so a clean run's
        # terminal status is byte-for-byte the one every host already parses.
        d, floor = self._repo()
        status = self._run_loop(d, floor, FakeRunner())
        self.assertEqual(status["status"], "complete", status)
        self.assertNotIn("cells_exhausted", status)
        self.assertEqual(status["message"], "all phases complete")


class TestNoRedundantReDeriveOnReview(LoopCase):
    """review round 1, item 2 (plan-mandated bug): `_after_first_run`'s seam
    must gate the second `driver.run` call -- an UNCONDITIONAL one burns a
    cell's cell-attempts.json retry budget on every resume that lands on the
    `review` checkpoint, with zero launches in between."""

    def test_a_review_checkpoint_reached_by_first_run_burns_no_attempt_without_a_launch(self):
        d, floor = self._repo()
        args = self._args(d)
        # Simulate a resume: an earlier process already minted the manifest
        # and got coverage established (e.g. a prior `driver loop` that
        # crashed after coverage but before any review launch), so THIS new
        # orchestrate.loop() call's very first driver.run() lands directly on
        # the review checkpoint. `_after_first_run` is left UNPATCHED here
        # (the production no-op) -- if `loop` still re-derived unconditionally,
        # it would call review_execute a second time with no launch at all,
        # inflating cell-attempts.json.
        driver.run(args)                        # mints the manifest, dispatches the scout
        self._seed_coverage(d, floor)
        runner = FakeRunner(); runner.fail_once.add("review-app-SEC")
        with mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "complete", status)
        attempts = runio._load_json(runio._pano(d, "cell-attempts.json"))
        review_launches = runner.launched.count("review-app-SEC")
        self.assertEqual(review_launches, 2)     # failed once, then a real retry
        self.assertEqual(attempts["app/SEC"], review_launches)


class TestLoopParser(unittest.TestCase):
    """review round 1, item 6: `--max-per-group` (shared with `setup`, for
    symmetry with `--max-groups`) parses on the `loop` verb."""

    def test_max_per_group_and_max_groups_are_both_accepted(self):
        args = driver.build_parser().parse_args(
            ["loop", ".", "--max-per-group", "10", "--max-groups", "5"])
        self.assertEqual(args.max_per_group, 10)
        self.assertEqual(args.max_groups, 5)

    # #1912: `--discard-batch <N>` -- one record's acceptance.

    def test_discard_batch_takes_a_positive_batch_number(self):
        args = driver.parse_cli(["loop", ".", "--discard-batch", "3"])
        self.assertEqual(3, args.discard_batch)
        self.assertIsNone(driver.parse_cli(["loop", "."]).discard_batch)

    def test_discard_batch_refuses_a_number_that_is_not_a_batch(self):
        for value in ("0", "-1", "two", "1.5", ""):
            with self.subTest(value=value):
                with self.assertRaises(SystemExit), \
                        contextlib.redirect_stderr(io.StringIO()):
                    driver.parse_cli(["loop", ".", "--discard-batch", value])

    def test_discard_batch_and_reset_together_are_refused(self):
        # Contradictory: one keeps the run and throws away a record, the other
        # throws the run away. Accepting both would make `--reset` win silently
        # (it skips recovery entirely), which is the opposite of what the
        # operator asked for with the narrower flag.
        err = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
            driver.parse_cli(["loop", ".", "--discard-batch", "1", "--reset"])
        self.assertIn("--discard-batch", err.getvalue())
        self.assertIn("--reset", err.getvalue())

    def test_the_flag_is_the_loops_alone(self):
        # `driver run` keeps no batch record -- the loop writes them -- so the
        # flag would name a file that verb never reads.
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            driver.parse_cli(["run", ".", "--discard-batch", "1"])


class TestScoutRoundTrip(LoopCase):
    def test_the_scout_checkpoint_is_return_persisted_and_advances(self):
        d, _ = self._repo()
        class ScoutRunner(FakeRunner):
            def run_entry(self, entry, env):
                self.launched.append(entry["id"])
                if entry["id"].startswith("scout-"):
                    return base.RunResult(entry_id=entry["id"], ok=True,
                                          text=json.dumps({"domains": ["QAL"], "files": [], "tools": []}),
                                          usage={}, cost_usd=0.0, model=None, session_id=None,
                                          denials=[], error=None)
                return super().run_entry(entry, env)
        runner = ScoutRunner()
        args = self._args(d)
        with mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(runner.launched[0], "scout-app")
        self.assertTrue(os.path.isfile(runio._pano(d, "scout-app.json")))


class TestPendingFilter(unittest.TestCase):
    """Direct unit coverage for `_pending`'s persist.is_done filter (Task 6
    ruling 2's mutation gate: `_pending` returning `entries` unfiltered must
    make a test fail).

    This CANNOT be observed through TestSessionMode's re-entry test: every
    phase's own `execute()` already rebuilds dispatch-request.json with only
    not-yet-done entries on EVERY call (review_execute filters `_cell_done`
    cells before writing, and the request is a single shared path per run --
    verify's rewrite replaces review's entirely), so by the time `loop()`
    reads the request, a just-persisted entry is already absent from it --
    there is nothing left for `_pending` to drop. Confirmed empirically:
    mutating `_pending` to `return entries` left every existing test green.
    Only a direct call, handed a done and a pending entry in the SAME list,
    actually exercises the filter -- so this is the "strengthen the test ...
    until it does" fallback ruling 2 names, done as a dedicated unit test
    rather than inside the integration test (see the Task 6 report)."""

    def test_pending_drops_a_done_entry_and_keeps_a_pending_one(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        done_out = os.path.join(d, "scout-done.json")
        runio._write_json(done_out, {"domains": [], "files": [], "tools": []})
        pending_out = os.path.join(d, "scout-pending.json")   # never written
        done_entry = {"id": "scout-done", "out_file": done_out}
        pending_entry = {"id": "scout-pending", "out_file": pending_out}
        self.assertTrue(orchestrate.persist.is_done(done_entry))
        self.assertFalse(orchestrate.persist.is_done(pending_entry))
        result = loop_batch._pending([done_entry, pending_entry])
        self.assertEqual([e["id"] for e in result], ["scout-pending"])


class TestTheRequestsEnforcedFlagIsDerived(LoopCase):
    """#1720: `enforced` travels in `.panopticon/dispatch-request.json`, inside
    the reviewed tree, and every family read it as the launch's posture. The
    loop re-derives it from THIS run's own capability evidence and refuses the
    whole request when the two disagree -- before the batch opens, so nothing
    launches and nothing is charged. It is a request-integrity refusal, not a
    cell failure."""

    def _tampered(self, **fields):
        """Flip a field on every entry between the phase that wrote the
        request and the loop that reads it -- the on-disk hop the reviewed
        tree could tamper with.

        Patched at `load_bound_request` (#1727 moved the loop's read there) and
        deliberately AFTER its integrity check: these two controls are
        independent. The hash answers "is this the file we wrote"; this one
        answers "does what it says match this run's own evidence", and it has
        to keep holding for a tamper the hash cannot see."""
        real = orchestrate.requests.load_bound_request

        def fake(review_root, namespace=None, expected_sha256=None):
            req, refusal = real(review_root, namespace, expected_sha256)
            for entry in (req or {}).get("entries") or []:
                entry.update(fields)
            return req, refusal

        return mock.patch.object(orchestrate.requests, "load_bound_request", fake)

    def test_a_proven_run_refuses_a_request_that_claims_an_unenforced_launch(self):
        d, floor = self._repo()
        runner = FakeRunner()
        with self._tampered(enforced=False, agent=None):
            status = self._run_loop(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("review-app-SEC", status["message"])
        self.assertIn("claims unenforced launch", status["message"])
        self.assertIn("posture is enforced", status["message"])
        self.assertIn("--reset", status["message"])
        self.assertEqual([], runner.launched)          # nothing launched...
        run_dir = orchestrate.persist.run_dir(d, None)
        self.assertFalse(os.path.exists(os.path.join(run_dir, base.LEDGER_FILE)))
        # ...and no cell was charged a second attempt: the one on disk is the
        # one review_execute booked when it WROTE the request. Asserted as the
        # whole document -- `sorted(set(values)) or [1]` read as green for a
        # missing or empty file, which is every way this could go wrong.
        attempts = runio._load_json(runio._pano(d, "cell-attempts.json"))
        self.assertEqual({"app/SEC": 1}, attempts)

    def test_a_proven_run_refuses_a_request_that_claims_an_enforced_launch_on_a_refuted_host(self):
        d, floor = self._repo()
        runner = FakeRunner()
        with self._tampered(enforced=True):
            status = self._run_loop(d, floor, runner, "--allow-unenforced",
                                    probes=lambda host, target, **kw: _refuted_artifact(host))
        self.assertEqual("error", status["status"], status)
        self.assertIn("claims enforced launch", status["message"])
        self.assertIn("posture is unenforced", status["message"])
        self.assertEqual([], runner.launched)

    def test_an_allow_unenforced_run_launches_bare_exactly_as_before(self):
        d, floor = self._repo()
        runner = FakeRunner()
        status = self._run_loop(d, floor, runner, "--allow-unenforced",
                                probes=lambda host, target, **kw: _refuted_artifact(host))
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(["review-app-SEC", "verify-app-SEC-primary"],
                         sorted(runner.launched))

    def test_an_untampered_proven_run_is_unaffected(self):
        d, floor = self._repo()
        runner = FakeRunner()
        status = self._run_loop(d, floor, runner)
        self.assertEqual("complete", status["status"], status)
        self.assertEqual(["review-app-SEC", "verify-app-SEC-primary"],
                         sorted(runner.launched))


class TestExpectedEnforced(unittest.TestCase):
    """`loop_batch.expected_enforced` on its own: the two postures that are
    NOT read off the capability evidence at all."""

    def _root(self, states):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, ".panopticon"))
        write_host_evidence(d, states)
        return d

    def test_the_setup_namespace_reads_the_same_posture_as_a_run(self):
        # #1737 flips the old "the setup namespace is never enforced"
        # short-circuit. `setup_scan` IS in dispatch.ROLE_FILES now, so a host
        # that has registered its shells enforces this dispatch like any other
        # -- and a machine that has not registered anything reads REFUTED here
        # and goes down the ack-gated unenforced path instead of skipping the
        # question entirely.
        d = self._root(_ALL_PROVEN)
        self.assertTrue(loop_batch.expected_enforced(d, "claude", None))
        self.assertTrue(loop_batch.expected_enforced(d, "claude", "setup"))
        self.assertEqual([], loop_batch.refuse_disagreeing(
            [{"id": "setup-scan", "agent": "panopticon-setup-scan", "enforced": True}],
            loop_batch.expected_enforced(d, "claude", "setup")))

    def test_an_unregistered_machine_is_unenforced_in_the_setup_namespace(self):
        d = self._root({hosts.TOOL_POLICY_ENFORCED: hosts.REFUTED})
        self.assertFalse(loop_batch.expected_enforced(d, "claude", "setup"))

    def test_the_setup_namespace_reads_setups_own_evidence_artifact(self):
        # #1507's class of accident, one file over: `runio.host_evidence`
        # resolves host-capabilities.json through the RUN manifest's tag, so on
        # a tree that already holds a review run it would answer with THAT
        # run's posture. `driver loop --setup` writes and reads the flat one.
        d = self._root(_ALL_PROVEN)                 # flat: setup's own
        runio._write_json(
            driver.run_manifest.manifest_path(d),
            {"schema_version": 1, "run_id": "r1", "host": "claude",
             "created": "2026-09-21T00:00:00Z", "review_root": os.path.abspath(d)})
        # ...and a DIFFERENT posture in the review run's own folder.
        write_host_evidence(d, {hosts.TOOL_POLICY_ENFORCED: hosts.REFUTED})
        self.assertFalse(loop_batch.expected_enforced(d, "claude", None))
        self.assertTrue(loop_batch.expected_enforced(d, "claude", "setup"))

    def test_the_scan_checkpoint_dispatches_the_setup_scan_shell(self):
        # #1727's routing table: `scan` used to accept NO name at all. It
        # dispatches exactly one shell now, so a setup entry naming a scout
        # shell -- a reviewer's charter in a round that only classifies -- is
        # refused, and the entry's own shell is accepted.
        #
        # `out_file` is what makes these ENTRIES: since #1886 the acceptance
        # role is read off the controller-bound output path, so a fixture
        # without one describes nothing the phases build and fails closed on
        # the missing family rather than on the shell under test.
        out_file = "/repo/.panopticon/setup-proposal.json"
        self.assertEqual(("setup_scan",), loop_batch.checkpoint_roles("scan"))
        self.assertEqual([], loop_batch.refuse_misrouted(
            [{"id": "setup-scan", "out_file": out_file,
              "agent": "panopticon-setup-scan", "enforced": True}],
            "scan"))
        self.assertEqual(["setup-scan"], loop_batch.refuse_misrouted(
            [{"id": "setup-scan", "out_file": out_file,
              "agent": "panopticon-scout", "enforced": True}],
            "scan"))
        self.assertIn("panopticon-setup-scan",
                      loop_batch.misroute_refusal(["setup-scan"], "scan"))

    def test_the_unenforced_fallback_host_is_never_enforced(self):
        d = self._root(_ALL_PROVEN)
        self.assertFalse(loop_batch.expected_enforced(d, "generic", None))

    def test_each_posture_state_maps_to_one_answer(self):
        # PROVEN is the only state that enforces. UNKNOWN gates exactly as
        # REFUTED (spec 5.1) -- "we did not measure" grants nothing.
        for state, expected in ((hosts.PROVEN, True), (hosts.REFUTED, False),
                                (hosts.UNKNOWN, False)):
            d = self._root({hosts.TOOL_POLICY_ENFORCED: state})
            self.assertIs(expected, loop_batch.expected_enforced(d, "claude", None), state)

    def test_refuse_disagreeing_names_only_the_entries_that_disagree(self):
        pending = [{"id": "a", "enforced": True}, {"id": "b", "enforced": False},
                   {"id": "c"}, {"id": "d", "enforced": 1}]
        self.assertEqual(["b", "c"], loop_batch.refuse_disagreeing(pending, True))
        self.assertEqual(["a", "d"], loop_batch.refuse_disagreeing(pending, False))


class TestEnforcedIsDerivedInOnePlace(unittest.TestCase):
    """#1720 drift guard. The loop re-derives `enforced` to CHECK the dispatch
    request; the phases derive it to WRITE that request. A second copy of the
    expression is exactly the drift that would make a run refuse itself -- or
    quietly stop refusing -- so every site calls `loop_batch.expected_enforced`
    and none of them spells `hosts.posture(...)[...] == hosts.PROVEN` again.

    AST, not text: the expression is written across two source lines at some
    of these sites, and a grep for it returns a false zero (the `git grep \\b`
    trap, one shape over)."""

    PHASES = os.path.join(os.path.dirname(orchestrate.__file__), "phases")
    # The builders that STAMP `enforced` onto dispatch entries, plus the
    # driver plan that declares it for the same cells. #1737 added `setup.py`:
    # its one entry used to hardcode False, which is the same second copy of
    # the expression by another name.
    SITES = ("coverage.py", "review.py", "verify.py", "verify_tools.py",
             "requests.py", "setup.py")

    def _tree(self, name):
        path = os.path.join(self.PHASES, name)
        with open(path, encoding="utf-8") as fh:
            return path, ast.parse(fh.read(), path)

    def test_every_site_calls_the_loops_derivation(self):
        for name in self.SITES:
            path, tree = self._tree(name)
            calls = {ast.unparse(node.func) for node in ast.walk(tree)
                     if isinstance(node, ast.Call)}
            self.assertIn("loop_batch.expected_enforced", calls, path)

    def test_no_phase_module_keeps_its_own_copy_of_the_expression(self):
        offenders = []
        for name in sorted(os.listdir(self.PHASES)):
            if not name.endswith(".py"):
                continue
            path, tree = self._tree(name)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Compare):
                    continue
                if not isinstance(node.left, ast.Subscript):
                    continue
                inner = node.left.value
                # THIS capability only: the other `hosts.posture(...)[cap]`
                # comparisons in phases/ (artifact_write_guard in
                # requests.delivery, usage_ledger in synthesize) are different
                # decisions with no second owner, and #1720 did not touch them.
                if (isinstance(inner, ast.Call)
                        and ast.unparse(inner.func) == "hosts.posture"
                        and ast.unparse(node.left.slice) == "hosts.TOOL_POLICY_ENFORCED"):
                    offenders.append("%s:%d: %s"
                                     % (path, node.lineno, ast.unparse(node)))
        self.assertEqual([], offenders,
                         "a phase re-derives the enforcement posture instead of "
                         "calling loop_batch.expected_enforced; two copies is the "
                         "drift #1720 closed:\n" + "\n".join(offenders))


class TestTheRequestHashTravelsOnTheStatus(LoopCase):
    """#1727: the phase that WRITES the dispatch request is the only code that
    has seen its bytes before the reviewed tree could touch them. The hash it
    computed travels to the loop in process, on the checkpoint status."""

    def test_the_checkpoint_status_carries_the_hash_of_the_request_it_wrote(self):
        d, _floor = self._repo()
        with contextlib.redirect_stderr(io.StringIO()):
            status = driver.run(self._args(d))
        self.assertEqual(status["status"], "checkpoint", status)
        self.assertEqual(status["checkpoint"], "scout")
        with open(status["dispatch_request"], "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(),
                             status["request_sha256"])
        self.assertEqual(driver.run_manifest.load_manifest(d)["dispatch_request"],
                         {"checkpoint": "scout", "sha256": status["request_sha256"],
                          "at": driver.run_manifest.load_manifest(d)
                          ["dispatch_request"]["at"]})

    def test_every_checkpoint_phase_result_carries_one(self):
        # The anti-drift pin for all six writers (coverage, review, verify x2,
        # verify_tools, setup) and for the seventh somebody adds: a checkpoint
        # that names a dispatch_request and no request_sha256 would reach the
        # loop with nothing to compare, and `load_bound_request` would fall
        # back to the manifest alone -- silently weaker, and nothing would say so.
        phases_dir = os.path.join(os.path.dirname(orchestrate.__file__), "phases")
        missing = []
        for name in sorted(os.listdir(phases_dir)):
            if not name.endswith(".py"):
                continue
            path = os.path.join(phases_dir, name)
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), path)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "PhaseResult"):
                    continue
                kw = {k.arg: k.value for k in node.keywords}
                kind = kw.get("kind")
                if not (isinstance(kind, ast.Constant) and kind.value == "checkpoint"):
                    continue
                if "request_sha256" not in kw:
                    missing.append("%s:%d" % (name, node.lineno))
        self.assertEqual(missing, [],
                         "checkpoint PhaseResult with no request_sha256:\n"
                         + "\n".join(missing))


def _append_a_byte(path):
    """The minimal on-disk tamper: the document still parses and still says
    everything it said, so only the HASH can tell it apart from what the
    driver wrote."""
    with open(path, "ab") as fh:
        fh.write(b" ")


class TestTheLoopRefusesARequestItCannotProveItWrote(LoopCase):
    """#1727: `.panopticon/dispatch-request.json` is written into the reviewed
    tree, and between the phase that writes it and the loop that reads it back
    the target owns that file. The loop checks the bytes against the hash the
    phase handed it in memory and the hash the run manifest recorded, and
    refuses before it arms, launches or spends anything."""

    def _tamper_after_every_run(self, mutate=_append_a_byte):
        real = orchestrate._run

        def fake(args, namespace, resolved=None):
            status = real(args, namespace, resolved)
            path = orchestrate.requests.request_path(args.target, namespace)
            if os.path.isfile(path):
                mutate(path)
            return status

        return mock.patch.object(orchestrate, "_run", fake)

    def _loop_capturing(self, d, floor, runner, *extra, seed=True):
        args = self._args(d, *extra)
        err = io.StringIO()
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: seed and self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(err):
            return orchestrate.loop(args), err.getvalue()

    def test_a_request_altered_after_the_phase_wrote_it_ends_the_run(self):
        d, floor = self._repo()
        runner = FakeRunner()
        armed = []
        with self._tamper_after_every_run(), \
             mock.patch.object(orchestrate.Guards, "arm",
                               side_effect=lambda *a: armed.append(a[-1])):
            status, _err = self._loop_capturing(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("does not match the request this run wrote", status["message"])
        self.assertIn("re-run `driver run`/`driver loop`", status["message"])
        self.assertEqual([], runner.launched)      # nothing launched...
        self.assertEqual([], armed)                # ...and nothing was ever armed
        run_dir = orchestrate.persist.run_dir(d, None)
        self.assertFalse(os.path.exists(os.path.join(run_dir, base.LEDGER_FILE)))

    def test_a_forged_record_is_caught_by_the_hash_the_phase_returned(self):
        # The manifest is inside the reviewed tree as well -- better defended
        # (no dispatched agent may write it, and `_foreign_manifest` discards
        # a planted one), not out of reach. So assume it WAS reached: the loop
        # still holds the hash the PHASE computed, in memory, and that is the
        # value no on-disk edit can reconcile.
        d, floor = self._repo()
        runner = FakeRunner()

        def tamper(path):
            _append_a_byte(path)
            with open(path, "rb") as fh:
                forged = hashlib.sha256(fh.read()).hexdigest()
            manifest = driver.run_manifest.load_manifest(d)
            manifest["dispatch_request"]["sha256"] = forged
            driver.run_manifest._rewrite(d, manifest)

        with self._tamper_after_every_run(tamper):
            status, _err = self._loop_capturing(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("recorded dispatch request hash was altered", status["message"])
        self.assertEqual([], runner.launched)

    def test_a_resume_after_a_tampered_file_regenerates_it_and_completes(self):
        # Nothing to repair by hand: the request is ROLLING, so the next
        # invocation's own phase overwrites both the file and the record.
        d, floor = self._repo()
        with contextlib.redirect_stderr(io.StringIO()):
            first = driver.run(self._args(d))
        self.assertEqual("checkpoint", first["status"], first)
        _append_a_byte(first["dispatch_request"])
        status, err = self._loop_capturing(d, floor, FakeRunner())
        self.assertEqual("complete", status["status"], status)
        # ...and the previous, tampered request was refused as a source of
        # disarm targets rather than acted on (R-P6-6 reads it before the
        # regeneration, by design).
        self.assertIn("ignoring the previous dispatch request", err)
        self.assertIn("does not match the request this run wrote", err)

    def test_a_clean_previous_request_is_still_read_for_the_disarm(self):
        # The negative control for the line above: an untouched re-entry must
        # print nothing and must still hand `loop_batch.disarm_previous` its entries.
        d, floor = self._repo()
        with contextlib.redirect_stderr(io.StringIO()):
            driver.run(self._args(d))
        status, err = self._loop_capturing(d, floor, FakeRunner())
        self.assertEqual("complete", status["status"], status)
        self.assertNotIn("ignoring the previous dispatch request", err)


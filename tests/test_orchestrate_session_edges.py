"""Host and mode resolution, verify completeness, and entry failure caps.

Shared fixtures live in tests/orchestrate_helpers.py. This module owns its
host probe and readiness patches because setUpModule is per module.
"""
import contextlib
import io
import json
from unittest import mock

import scripts.driver as driver
import scripts.ledger as ledger_mod
import scripts.loop_batch as loop_batch
import scripts.orchestrate as orchestrate
import scripts.probes.common as probes_common
import scripts.phases.review as review
import scripts.phases.runio as runio
import scripts.runners.base as base
from tests._test_helpers import docker_probe_runner
from scripts import hosts
from tests._test_helpers import (all_proven_artifact as _all_proven_artifact,
                           write_guard_not_proven as _write_guard_not_proven)
from tests.orchestrate_helpers import FakeRunner, LoopCase


def setUpModule():
    global _patch, _readiness_docker_patch
    _patch = mock.patch("scripts.host_probes.run_probes",
                        side_effect=lambda host, target, **kw: _all_proven_artifact(host))
    _patch.start()
    # #1637 P08, same reason as tests/test_orchestrate.py: readiness leads the
    # phase table now, and a session loop that stops there never reaches the
    # dispatch status these tests read.
    _readiness_docker_patch = mock.patch(
        "scripts.phases.readiness_checks.DOCKER_RUNNER", docker_probe_runner())
    _readiness_docker_patch.start()


def tearDownModule():
    _patch.stop()
    _readiness_docker_patch.stop()


class TestHostAndModeResolution(LoopCase):
    """I5 + I8 (final review): which host the loop dispatches for, and which
    mode it runs in when `--mode` is absent."""

    def _spy(self, calls, runner=None):
        real = base.runner_for

        def _runner_for(host, mode):
            calls.append((host, mode))
            return real(host, mode) if runner is None else runner
        return mock.patch("scripts.runners.base.runner_for", side_effect=_runner_for)

    def _claim_nothing_run(self, d, s):
        """Mint a real run-manifest whose host is the claim-nothing selectable
        one, the way a first `driver loop --host generic` would.

        This was `--host gemini` until gemini was retired from the selectable
        set (#1621, 2026-09-13). The property under test is a property of a
        host that claims nothing and has no headless runner, not of gemini,
        and `generic` is the one such host the driver still accepts.
        """
        args = driver.build_parser().parse_args(
            ["loop", d, "--no-tools", "--fail-on", "high", "--host", "generic",
             "--mode", "session", "--session-dir", s])
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            driver.run(args)
        self.assertEqual(driver.run_manifest.load_manifest(d)["host"], "generic")

    def test_a_resume_without_host_dispatches_for_the_runs_own_host(self):
        # I5: `driver.run` treats an omitted `--host` as manifest-authoritative
        # -- it refuses a contradicting `--host` as flag drift -- so a resume
        # without the flag is still a generic run. The loop resolved its runner
        # off `runio._DEFAULTS["host"]` instead and would have dispatched
        # CLAUDE agents at it, with no refusal anywhere on the path.
        d, _ = self._repo(); s = self._session_root(d)
        self._claim_nothing_run(d, s)
        calls = []
        with self._spy(calls), contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            orchestrate.loop(self._args(d, "--mode", "session", "--session-dir", s))
        self.assertEqual(calls, [("generic", "session")])

    def test_a_resume_whose_host_is_no_longer_selectable_is_an_error(self):
        # #1621: a run STARTED under a host the driver has since retired --
        # gemini here, and the same holds for any row a family PR has not
        # earned back -- resumes off its own manifest, which `driver.run`
        # treats as authoritative. `_resolve_host` handed that name straight
        # to `runner_for`, which builds a SessionRunner for any string at all,
        # so the loop went on dispatching for a host `--host` would now refuse
        # to name. The remedy is the same one the parser gives, plus --reset,
        # because the manifest is what has to change.
        d, _ = self._repo(); s = self._session_root(d)
        self._claim_nothing_run(d, s)
        path = driver.run_manifest.manifest_path(d)
        manifest = runio._load_json(path)
        manifest["host"] = "gemini"
        runio._write_json(path, manifest)
        self.assertFalse(runio._foreign_manifest(manifest, d, path),
                         "fixture precondition: this manifest is the run's own")
        calls = []
        with self._spy(calls), contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            status = orchestrate.loop(self._args(d, "--mode", "session", "--session-dir", s))
        self.assertEqual(status["status"], "error", status)
        self.assertIn("gemini", status["message"])
        self.assertIn("--host generic --reset", status["message"])
        self.assertEqual([], calls, "nothing may be dispatched for it")

    def test_a_resume_whose_host_the_registry_does_not_know_never_dispatches_for_it(self):
        # #1624 fix round 1. The #1621 check above is `host not in
        # driver_hosts()`, which would also catch a name with no ROW at all --
        # and would then tell that operator the host was "registered but no
        # longer driver-selectable", which is false twice over: nothing was
        # ever retired, and `--host generic` is not the specific remedy.
        #
        # It never gets the chance, and that is why the refusal above needs no
        # second branch for it. `run_manifest.load_manifest` discards a
        # manifest naming a host the registry does not know -- UNUSABLE,
        # exactly like a corrupt one, announced on stderr (#1344; the unit
        # test is test_run_manifest.py::test_a_stored_manifest_with_an_
        # unknown_host_is_discarded_not_trusted) -- so `_resolve_host` reads
        # None off it and falls through to the default. This pins the
        # CONSEQUENCE at the entrypoint, which the unit test cannot: delete
        # that branch and the name reaches `runner_for`, which builds a
        # SessionRunner for any string at all, and this fails.
        d, _ = self._repo(); s = self._session_root(d)
        self._claim_nothing_run(d, s)
        path = driver.run_manifest.manifest_path(d)
        manifest = runio._load_json(path)
        manifest["host"] = "nosuchhost"
        runio._write_json(path, manifest)
        self.assertNotIn("nosuchhost", hosts.known_hosts(),
                         "fixture precondition: the registry has no such row")
        self.assertFalse(runio._foreign_manifest(manifest, d, path),
                         "fixture precondition: this manifest is the run's own -- "
                         "a foreign one is discarded for a different reason")
        calls = []
        with self._spy(calls), contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()) as err:
            status = orchestrate.loop(self._args(d, "--mode", "session", "--session-dir", s))
        self.assertIn("discarding run-manifest.json", err.getvalue())
        self.assertIn("nosuchhost", err.getvalue())
        self.assertEqual([], [h for h, _m in calls if h not in hosts.driver_hosts()],
                         "no runner may be built for a host with no registry row")
        self.assertTrue(calls, "guards the guard: the loop must have built one")
        # ...and it is NOT told the retired-host story, which does not apply.
        self.assertNotIn("no longer driver-selectable", status.get("message") or "")

    def test_the_refusal_does_not_fire_for_a_host_that_is_still_selectable(self):
        # The other half, and it has to run the SAME manipulation as the test
        # above or it is not a guard: a resume whose manifest was rewritten to
        # name a different host. The only difference is that the name is the
        # OTHER selectable row, so the loop must resume through it untouched.
        #
        # Re-running `_claim_nothing_run` and re-asserting `("generic",
        # "session")` -- which is what this test did at first -- is a byte
        # copy of test_a_resume_without_host_dispatches_for_the_runs_own_host
        # above: that one mints its host through the CLI and is about manifest
        # AUTHORITY, and it would keep passing if the #1621 check refused
        # every manifest-resolved host that was not the one the CLI minted.
        # Only rewriting the manifest, as the refusal test does, exercises the
        # `driver_hosts()` membership read.
        d, _ = self._repo(); s = self._session_root(d)
        self._claim_nothing_run(d, s)
        path = driver.run_manifest.manifest_path(d)
        manifest = runio._load_json(path)
        self.assertIn("claude", hosts.driver_hosts())
        manifest["host"] = "claude"
        runio._write_json(path, manifest)
        calls = []
        with self._spy(calls), contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            status = orchestrate.loop(self._args(d, "--mode", "session", "--session-dir", s))
        self.assertNotEqual("error", status["status"], status)
        self.assertEqual(calls, [("claude", "session")])

    def test_a_target_committed_manifest_does_not_choose_the_host(self):
        # Fix round 3: I5 reads the run's host off run-manifest.json, but
        # `driver.run` does NOT trust every manifest it finds -- #1093 / #run8
        # AGT-C1A -- because a hostile target can force-commit its own
        # `.panopticon/run-manifest.json`. driver.run discards a foreign one
        # and rebuilds from the real CLI args; `_resolve_host` read it
        # unconditionally, so a committed `"host": "gemini"` steered THIS
        # invocation's runner while the run itself proceeded as claude. The
        # target got to pick which family's agents were dispatched at it.
        # Still spelled `gemini` after the retirement (#1621): the point is a
        # name the registry KNOWS but this invocation never chose, and a
        # foreign manifest is discarded before selectability is ever consulted.
        d, _ = self._repo(); s = self._session_root(d)
        runio._write_json(driver.run_manifest.manifest_path(d),
                          {"schema_version": 1, "run_id": "r" * 8, "host": "gemini",
                           "review_root": "/somewhere/else", "flags": {}})
        calls = []
        with self._spy(calls), contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            orchestrate.loop(self._args(d, "--mode", "session", "--session-dir", s))
        self.assertEqual(calls, [(runio._DEFAULTS["host"], "session")])

    def test_a_host_with_no_headless_runner_degrades_to_session_with_a_reason(self):
        # I8, spec 4.4: "A host with no headless runner registered gets session
        # mode with a stderr line saying so." `--mode` defaulted to headless,
        # so a `driver loop` on such a host errored out instead of degrading.
        # Driven under `generic` since gemini left the selectable set (#1621).
        d, _ = self._repo(); s = self._session_root(d)
        calls = []
        err = io.StringIO()
        with self._spy(calls), contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(err):
            status = orchestrate.loop(
                self._args(d, "--host", "generic", "--session-dir", s))
        self.assertEqual(calls, [("generic", "session")])
        self.assertEqual(status["status"], "dispatch", status)
        self.assertIn("generic", err.getvalue())
        self.assertIn("session mode", err.getvalue())

    def test_an_explicit_headless_on_such_a_host_is_an_error_not_a_traceback(self):
        # I8: "`--mode headless` on such a host is an error" -- the operator
        # asked for a runner that does not exist, which is not something to
        # paper over with a silent downgrade.
        d, _ = self._repo()
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            status = orchestrate.loop(
                self._args(d, "--host", "generic", "--mode", "headless"))
        self.assertEqual(status["status"], "error", status)
        self.assertIn("--mode session", status["message"])

    def test_a_host_with_a_runner_still_defaults_to_headless(self):
        d, floor = self._repo()
        runner = FakeRunner()
        calls = []
        with self._spy(calls, runner), \
             mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(self._args(d))
        self.assertEqual(calls, [("claude", "headless")])
        self.assertEqual(status["status"], "complete", status)

    def test_the_resolved_mode_reaches_the_posture_probe_on_the_very_first_run(self):
        # Writing the resolved mode back onto `args` before `_first_run` is
        # load-bearing, not tidiness. `driver._establish_host_posture` reads
        # `args.mode` to choose WHICH settings file the guard probes measure
        # (spec 5.4: the run folder's in headless mode, the session root's
        # otherwise), and it runs on EVERY driver.run call. If the first call
        # saw the parser's bare default and later calls saw the resolved mode,
        # the two would disagree about artifact_write_guard on any machine
        # whose session root has no settings file (#1493) -- and the run would
        # refuse ITSELF as mid-run posture drift on its second invocation.
        d, floor = self._repo()
        runner = FakeRunner()
        seen = []

        def _probe(host, target, **kw):
            seen.append(kw.get("settings_path"))
            return _all_proven_artifact(host)

        with mock.patch("scripts.host_probes.run_probes", side_effect=_probe), \
             mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(self._args(d))
        self.assertEqual(status["status"], "complete", status)
        self.assertTrue(seen)
        self.assertEqual(set(seen), {probes_common.headless_settings_path(d)})


class TestVerifyBundleCompletenessGatesResume(LoopCase):
    """I3 (final review), the loop half: `_pending` must keep re-launching a
    verify cell the ENGINE still considers pending.

    `persist.is_done` accepted a verdict bundle on shape + stamp alone, while
    the engine's predicate (`verify._verify_cell_done`) also requires every
    dispatched claim to come back adjudicated. A short bundle therefore read
    as done HERE and pending THERE: `_pending` returned [], `run_batch([])`
    launched nothing, and each `driver.run` charged one of the cell's three
    re-dispatch attempts for a round trip that re-ran no advisor. The retry
    budget was spent without a single retry."""

    def test_a_short_verdict_bundle_keeps_the_cell_pending_and_re_launched(self):
        d, floor = self._repo()

        class ShortVerifyRunner(FakeRunner):
            """Self-writes a bundle that adjudicates NONE of the cell's claims
            -- the A2 (run-9) failure, where an advisor re-coded findings and
            returned fewer verdicts than it was handed."""

            def run_entry(self, entry, env):
                if not entry["id"].startswith("verify-"):
                    return super().run_entry(entry, env)
                self.launched.append(entry["id"])
                runio._write_json(entry["out_file"], {
                    "verdicts": [],
                    "_panopticon": {"run_id": entry.get("run_id"),
                                    "role": "domain_advisor",
                                    "domain": entry["domain"], "group": entry["group"],
                                    "stage": entry.get("stage", "primary")}})
                return base.RunResult(entry_id=entry["id"], ok=True, text="written",
                                      usage={}, cost_usd=0.0, model=None,
                                      session_id=None, denials=[], error=None)

        runner = ShortVerifyRunner()
        pending_seen = []
        real_pending = loop_batch._pending

        def _record(entries):
            out = real_pending(entries)
            pending_seen.append([e.get("id") for e in out])
            return out

        args = self._args(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch.object(loop_batch, "_pending", side_effect=_record), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)
        # The bounded A2 budget still terminates the run -- but only after the
        # advisor was actually re-dispatched, which is the whole point of it.
        self.assertEqual(status["status"], "complete", status)
        self.assertGreaterEqual(runner.launched.count("verify-app-SEC-primary"), 2)
        # The defect was an empty pending set on EVERY iteration after the
        # first short bundle: the cell's whole re-dispatch budget spent on
        # round trips that launched nothing. The one empty set that remains is
        # the handoff at the cap -- `verify_execute` bumps to
        # `_MAX_VERIFY_ATTEMPTS` and writes the request in the SAME call, then
        # disowns the cell on the next one, so the loop is right to decline an
        # entry the engine has already given up on.
        self.assertTrue(pending_seen)
        self.assertEqual(pending_seen[-1], [])
        self.assertNotIn([], pending_seen[:-1])


class TestPerEntryFailureCap(LoopCase):
    """Fix round 2: the loop caps CONSECUTIVE failed launches per ENTRY.

    `--max-iterations` bounds the RUN. It does not bound the thing that
    actually goes wrong, which is one entry that cannot advance while the rest
    of the run is fine. Two failure kinds count the same here because from the
    run's point of view they ARE the same -- the runner failed the launch, or
    the launch came back and persist refused the reply -- and neither becomes
    likelier on the fortieth attempt.

    This is what bounds the return-persist path, which the I3 completeness fix
    left uncapped: a refused bundle never reaches disk, so
    `verify._verify_bundle_labeled` stays false, so the phase's own A2 attempt
    budget never bumps. Measured before this cap: 11 launches of one advisor
    at `--max-iterations 12`.
    """

    def test_a_chronically_refused_reply_stops_at_the_cap(self):
        d, floor = self._repo()

        class ShortReturnRunner(FakeRunner):
            """Return-persist advisor that adjudicates none of its claims, every
            time -- the A2 (run-9) re-coding failure, on a host with no proven
            write guard."""

            def run_entry(self, entry, env):
                if not entry["id"].startswith("verify-"):
                    return super().run_entry(entry, env)
                self.launched.append(entry["id"])
                body = {"verdicts": [],
                        "_panopticon": {"run_id": entry.get("run_id"),
                                        "role": "domain_advisor",
                                        "domain": entry["domain"], "group": entry["group"],
                                        "stage": entry.get("stage", "primary")}}
                return base.RunResult(
                    entry_id=entry["id"], ok=True,
                    text="```json\n" + json.dumps(body) + "\n```",
                    usage={"input_tokens": 11, "output_tokens": 2,
                           "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
                    cost_usd=0.002, model="claude-sonnet-5", session_id="s",
                    denials=[], error=None)

        runner = ShortReturnRunner()
        status = self._run_loop(d, floor, runner, "--allow-unenforced",
                                probes=_write_guard_not_proven)
        self.assertEqual(status["status"], "error", status)
        self.assertEqual(runner.launched.count("verify-app-SEC-primary"),
                         orchestrate.MAX_ENTRY_FAILURES)
        self.assertIn("verify-app-SEC-primary", status["message"])
        self.assertIn("3 consecutive launches", status["message"])
        self.assertIn("persist refused", status["message"])
        rows = [r for r in ledger_mod.Ledger(runner.run_dir).lines()
                if r["entry_id"] == "verify-app-SEC-primary"]
        self.assertEqual(len(rows), orchestrate.MAX_ENTRY_FAILURES)
        for row in rows:
            # the runner said ok; the RUN did not advance, and the ledger says so
            self.assertFalse(row["ok"], row)
            self.assertTrue(row["error"].startswith("persist refused"), row["error"])
            self.assertEqual(sum(row["usage"].values()), 13)   # M2: tokens still counted
            self.assertEqual(row["cost_usd"], 0.002)

    def test_a_clean_launch_resets_the_entrys_streak(self):
        d, floor = self._repo()

        class FlakyVerifyRunner(FakeRunner):
            """Fails twice, self-writes a SHORT bundle (a clean launch that does
            not finish the cell), fails twice more, then writes the real one.
            Five launches -- the sixth is never dispatched, because the A2
            attempt budget the short bundle started bumping runs out first and
            the cell is declared done (exhausted) on the iteration that would
            have launched it. Never three consecutive failures either way, so
            the run must reach `complete`; without the reset the third failure
            lands on launch 4 and the cap trips at four."""

            def run_entry(self, entry, env):
                if not entry["id"].startswith("verify-"):
                    return super().run_entry(entry, env)
                self.launched.append(entry["id"])
                n = self.launched.count(entry["id"])
                if n in (1, 2, 4, 5):
                    return base.RunResult.failed(entry["id"], "flaky")
                cell = review._load_cell_findings(
                    self.review_root, {"run_id": entry["run_id"]},
                    entry["group"], entry["domain"])
                runio._write_json(entry["out_file"], {
                    "verdicts": [] if n == 3 else [
                        {"finding_id": cell[0]["id"], "verdict": "CONFIRMED",
                         "reasoning": "v"}],
                    "_panopticon": {"run_id": entry["run_id"], "role": "domain_advisor",
                                    "domain": entry["domain"], "group": entry["group"],
                                    "stage": entry.get("stage", "primary")}})
                return base.RunResult(entry_id=entry["id"], ok=True, text="written",
                                      usage={}, cost_usd=0.0, model=None,
                                      session_id=None, denials=[], error=None)

        runner = FlakyVerifyRunner()
        status = self._run_loop(d, floor, runner)
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(runner.launched.count("verify-app-SEC-primary"), 5)

    def test_repeated_runner_failures_stop_at_the_same_cap(self):
        d, floor = self._repo()

        class AlwaysFailsVerify(FakeRunner):
            def run_entry(self, entry, env):
                if not entry["id"].startswith("verify-"):
                    return super().run_entry(entry, env)
                self.launched.append(entry["id"])
                return base.RunResult.failed(entry["id"], "always")

        runner = AlwaysFailsVerify()
        status = self._run_loop(d, floor, runner)
        self.assertEqual(status["status"], "error", status)
        self.assertEqual(runner.launched.count("verify-app-SEC-primary"),
                         orchestrate.MAX_ENTRY_FAILURES)
        self.assertIn("verify-app-SEC-primary", status["message"])
        self.assertIn("3 consecutive launches", status["message"])
        self.assertIn("last: always", status["message"])

"""driver loop in SESSION mode, and `driver loop --setup` (spec 4.3/4.6).

Split out of tests/test_orchestrate.py, which was approaching the 700-line
module ceiling: these two classes are the whole non-headless half of the
loop's surface and share nothing with the headless cases but the fixtures,
which are imported below rather than duplicated (the `run_probes` patch has
to be re-established here because setUpModule is per-module).
"""
import contextlib
import io
import json
import os
import shutil
import tempfile
from unittest import mock

import scripts.driver as driver
import scripts.host_probes as host_probes
import scripts.orchestrate as orchestrate
import scripts.phases.runio as runio
import scripts.read_guard_hook as read_guard_hook
import scripts.runners.base as base
import scripts.write_guard_hook as write_guard_hook
from test_orchestrate import (FakeRunner, LoopCase, _all_proven_artifact,
                              _write_guard_not_proven)


def setUpModule():
    global _patch
    _patch = mock.patch("scripts.host_probes.run_probes",
                        side_effect=lambda host, target, **kw: _all_proven_artifact(host))
    _patch.start()


def tearDownModule():
    _patch.stop()


class TestSessionMode(LoopCase):
    def _loop(self, d, *extra):
        args = self._args(d, "--mode", "session", *extra)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            status = orchestrate.loop(args)
        return status, out.getvalue()

    def _armed_read_ids(self, s):
        # read_guard_hook.is_armed() answers (armed, COUNT), not the id set
        # (#1493 guard_state has the same shape) -- reach into the private
        # scope file directly, exactly as tests/test_read_guard_hook.py does
        # (e.g. `set(rg._read_scope_file(self.scope_path))`), to assert WHICH
        # ids are armed rather than merely how many.
        _settings, scope_path, _ = read_guard_hook._resolve(None, None, s)
        return set(read_guard_hook._read_scope_file(scope_path))

    def test_the_loop_exits_dispatch_with_the_pending_ids_and_leaves_guards_armed(self):
        d, floor = self._repo(); s = self._session_root(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)):
            status, out = self._loop(d, "--session-dir", s)
        self.assertEqual(status["status"], "dispatch", status)
        self.assertEqual(status["pending"], ["review-app-SEC"])
        printed = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
        self.assertTrue(any(p.get("status") == "dispatch" and p.get("pending") == ["review-app-SEC"]
                            for p in printed))
        self.assertTrue(write_guard_hook.is_armed(session_root=s)[0])
        self.assertTrue(read_guard_hook.is_armed(session_root=s)[0])
        self.assertIn("review-app-SEC", self._armed_read_ids(s))

    def test_the_dispatch_status_and_the_printed_batch_name_the_request_file(self):
        # C2 (final review): a session host is told to cross-reference the
        # printed entries against the dispatch request, so the status has to
        # SAY WHERE that file is. `_dispatch_exit` read `dispatch_request` off
        # the request document itself, which has no such key (schema_version,
        # run_id, checkpoint, group, entries) -- so the field was None on
        # every dispatch, and the path is not guessable: it is per-run
        # (`runs/<tag>/`) for a review and a different file entirely under
        # `--setup`.
        d, floor = self._repo(); s = self._session_root(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)):
            status, out = self._loop(d, "--session-dir", s)
        self.assertEqual(status["status"], "dispatch", status)
        expected = os.path.abspath(orchestrate.requests.request_path(d))
        self.assertEqual(status["dispatch_request"], expected)
        self.assertTrue(os.path.isfile(expected))
        printed = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
        self.assertEqual([p["dispatch_request"] for p in printed], [expected])
        # a review's hints carry no --setup
        self.assertNotIn("--setup", status["message"])
        self.assertNotIn("--setup", printed[0]["then"])
        self.assertNotIn("--setup", printed[0]["persist"])

    def test_re_entry_with_nothing_done_re_emits_the_same_set(self):
        d, floor = self._repo(); s = self._session_root(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)):
            s1, _ = self._loop(d, "--session-dir", s)
        s2, _ = self._loop(d, "--session-dir", s)
        self.assertEqual((s1["status"], s1["pending"]), (s2["status"], s2["pending"]))
        # nothing advanced, so the id must still be armed after the re-entry
        # disarms-then-rearms it (R-P6-6) -- never left armed-over-nothing.
        self.assertIn("review-app-SEC", self._armed_read_ids(s))

    def test_re_entry_after_persisting_every_entry_advances_and_disarms_the_done_ones(self):
        d, floor = self._repo(); s = self._session_root(d)
        # Ruling 1: drive the not-proven write-guard posture (so the review
        # cell is return-persist, not self-write) through the run_probes
        # patch -- never write_host_evidence, which driver.run's own re-probe
        # on every invocation would silently undo.
        with mock.patch("scripts.host_probes.run_probes", side_effect=_write_guard_not_proven), \
             mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)):
            s1, _ = self._loop(d, "--session-dir", s, "--allow-unenforced")
        self.assertEqual(s1["status"], "dispatch")
        self.assertEqual(s1["pending"], ["review-app-SEC"])
        self.assertIn("review-app-SEC", self._armed_read_ids(s))
        req = orchestrate.requests.load_dispatch_request(d)
        entry = next(e for e in req["entries"] if e["id"] == "review-app-SEC")
        body = {"findings": [{"title": "issue", "severity": "HIGH", "domain": "SEC", "code": "SEC-A1A",
                              "category": "authz", "location": {"file": "src/app.py", "line_start": 1}}],
                "_panopticon": {"run_id": entry["run_id"], "role": "domain_panel",
                                "domain": "SEC", "group": "app"}}
        reply = os.path.join(d, "reply.txt")
        with open(reply, "w", encoding="utf-8") as fh:
            fh.write("```json\n" + json.dumps(body) + "\n```")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = driver.main(["persist", "review-app-SEC", "--file", reply, d])
        self.assertEqual(rc, 0)
        with mock.patch("scripts.host_probes.run_probes", side_effect=_write_guard_not_proven):
            s2, _ = self._loop(d, "--session-dir", s, "--allow-unenforced")
        self.assertEqual(s2["status"], "dispatch")
        self.assertEqual(s2["checkpoint"], "verify")                    # advanced past review
        # the persisted entry must not be re-listed as pending, and must be
        # disarmed -- the mutation gate this test exists to catch (Task 6
        # ruling 2): a `_pending` that stopped filtering by persist.is_done
        # would re-list "review-app-SEC" here and never disarm it.
        self.assertNotIn("review-app-SEC", s2["pending"])
        self.assertNotIn("review-app-SEC", self._armed_read_ids(s))
        self.assertIn("verify-app-SEC-primary", s2["pending"])
        self.assertIn("verify-app-SEC-primary", self._armed_read_ids(s))

    def _armed_write_paths(self, s):
        _settings, allowlist_path, _ = write_guard_hook._resolve(None, None, s)
        return set(write_guard_hook._read_allowlist(allowlist_path))

    def test_an_errored_re_entry_leaves_the_previous_dispatchs_grants_armed(self):
        # I4 (final review): session mode is the one mode whose guards stay
        # armed ACROSS invocations -- a `dispatch` exit returns without
        # disarming, by design, because the host has not run the agents yet.
        # So an invocation that errors before it arms anything of its own
        # (flag drift, a bad --pr) must not tear down grants the live fan-out
        # from the PREVIOUS invocation is still writing and reading under.
        # `_finish` used to call the TOTAL `guards.disarm()` on error.
        d, floor = self._repo(); s = self._session_root(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)):
            s1, _ = self._loop(d, "--session-dir", s)
        self.assertEqual(s1["status"], "dispatch", s1)
        self.assertIn("review-app-SEC", self._armed_read_ids(s))
        armed_writes = self._armed_write_paths(s)
        self.assertTrue(armed_writes)

        # a flag this run was not started with -> driver.run refuses as drift
        args = driver.build_parser().parse_args(
            ["loop", d, "--no-tools", "--fail-on", "critical",
             "--mode", "session", "--session-dir", s])
        with contextlib.redirect_stdout(io.StringIO()):
            s2 = orchestrate.loop(args)
        self.assertEqual(s2["status"], "error", s2)
        self.assertIn("flag drift", s2["message"])
        # the first invocation's fan-out is still running: its grants stand
        self.assertTrue(write_guard_hook.is_armed(session_root=s)[0])
        self.assertTrue(read_guard_hook.is_armed(session_root=s)[0])
        self.assertIn("review-app-SEC", self._armed_read_ids(s))
        self.assertEqual(self._armed_write_paths(s), armed_writes)

    def test_an_errored_session_invocation_does_not_clobber_the_hosts_usage_file(self):
        # M9 (final review): in session mode the loop launches nothing, so its
        # dispatch ledger is empty and a ledger-derived usage.json is all
        # zeros. The real figures come from the host's own transcripts
        # (collect_usage, wired into synthesize), which deliberately never
        # overwrites an existing usage.json -- so a `_finish` that writes over
        # it replaces the run's real token counts with zeros. `_finish` is
        # reached with a live ledger in session mode via the catch-all (a
        # `dispatch` exit returns before it), which is what this drives.
        d, floor = self._repo(); s = self._session_root(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)):
            s1, _ = self._loop(d, "--session-dir", s)
        self.assertEqual(s1["status"], "dispatch", s1)
        usage_path = runio._pano(d, "usage.json")
        sentinel = {"schema_version": 1, "total": 4321, "source": "host transcripts"}
        runio._write_json(usage_path, sentinel)
        with mock.patch("scripts.runners.session.SessionRunner.run_batch",
                        side_effect=RuntimeError("boom")):
            s2, _ = self._loop(d, "--session-dir", s)
        self.assertEqual(s2["status"], "error", s2)
        self.assertIn("boom", s2["message"])
        self.assertEqual(runio._load_json(usage_path), sentinel)

    def test_complete_disarms_both_guards_unconditionally(self):
        d, floor = self._repo(); s = self._session_root(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)):
            self._loop(d, "--session-dir", s)
        # drive review + verify to done by self-writing exactly as a session would
        runner = FakeRunner(); runner.prepare(os.path.dirname(runio._pano(d, "x")), d)
        for _ in range(3):
            req = orchestrate.requests.load_dispatch_request(d) or {}
            for e in req.get("entries") or []:
                if not orchestrate.persist.is_done(e):
                    runner.run_entry(e, {})
            status, _ = self._loop(d, "--session-dir", s)
            if status["status"] == "complete":
                break
        self.assertEqual(status["status"], "complete", status)
        self.assertFalse(write_guard_hook.is_armed(session_root=s)[0])
        self.assertFalse(read_guard_hook.is_armed(session_root=s)[0])



class TestSetupSessionMode(LoopCase):
    """`driver loop --setup --mode session`: the setup flow's own checkpoint,
    dispatched by hand. Its request lives in the SETUP namespace, and every
    command it hints at needs `--setup` to find it."""

    def test_the_setup_dispatch_names_its_own_request_and_hints_setup(self):
        # C2 + M4 (final review): setup's request is
        # `.panopticon/setup-dispatch-request.json` (#1507), NOT the per-run
        # `dispatch-request.json` -- and `driver persist setup-scan` without
        # `--setup` looks in the wrong namespace and refuses with "no entry".
        # `_dispatch_exit` took a `namespace` argument and ignored it.
        d, _ = self._repo()
        s = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(s, ignore_errors=True))
        os.makedirs(os.path.join(s, ".claude"))
        with open(os.path.join(s, ".claude", "settings.local.json"), "w") as fh:
            fh.write("{}")
        args = driver.build_parser().parse_args(
            ["loop", d, "--setup", "--mode", "session", "--session-dir", s])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "dispatch", status)
        expected = os.path.abspath(orchestrate.requests.request_path(d, "setup"))
        self.assertTrue(expected.endswith("setup-dispatch-request.json"), expected)
        self.assertEqual(status["dispatch_request"], expected)
        self.assertTrue(os.path.isfile(expected))
        self.assertIn("--setup", status["message"])
        printed = [json.loads(line) for line in out.getvalue().splitlines()
                   if line.startswith("{")]
        self.assertEqual(printed[0]["dispatch_request"], expected)
        self.assertIn("--setup", printed[0]["then"])
        self.assertIn("--setup", printed[0]["persist"])


class TestSetupOnRails(LoopCase):
    def test_setup_scan_is_run_through_the_runner_and_the_loop_stops_at_the_draft(self):
        d, _ = self._repo()

        class SetupRunner(FakeRunner):
            def run_entry(self, entry, env):
                self.launched.append(entry["id"])
                assert entry["id"] == "setup-scan"
                # setup_proposal.validate_proposal requires `groups` to be a
                # LIST of {"capability", "match", ...} mappings (the brief's
                # snippet nested them under a name key instead, which
                # validate_proposal rejects with "'groups' must be a
                # non-empty list" -- deviation, see the task report).
                proposal = {"groups": [{"capability": "custom:App", "match": ["src/**"], "tests": [],
                                        "profile": {"purpose": "app", "surfaces": [], "entry_points": [],
                                                    "trust_boundaries": []}}]}
                return base.RunResult(entry_id="setup-scan", ok=True, text=json.dumps(proposal),
                                      usage={}, cost_usd=0.0, model=None, session_id=None, denials=[], error=None)
        runner = SetupRunner()
        args = driver.build_parser().parse_args(["loop", d, "--setup"])
        with mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(runner.launched, ["setup-scan"])
        self.assertIn("setup-report.md", status["message"])
        self.assertIn("groups.yml.draft", status["message"])
        self.assertTrue(os.path.isfile(runio._pano(d, "setup-proposal.json")))

    def test_setup_vocab_absent_fallback_keeps_its_own_complete_message(self):
        # Fix round 1, item 1: the vocab-absent fallback (phases/setup.py's
        # _scan_fallback) seeds groups.yml directly and writes neither
        # setup-report.md nor groups.yml.draft -- _finish must leave
        # run_setup_flow's own "complete" message alone rather than naming
        # files that were never written.
        d, _ = self._repo()
        args = driver.build_parser().parse_args(["loop", d, "--setup"])
        # M14: `runner_for` patched like every other loop test. The fallback
        # completes without a checkpoint today, so no entry is launched -- but
        # unpatched, this is the one `orchestrate.loop` call in the suite
        # standing between a refactor and a real `claude -p` subprocess.
        with mock.patch("scripts.setup_flow.load_bundled_vocabulary",
                        return_value=({"names": []}, False)), \
             mock.patch("scripts.runners.base.runner_for", return_value=FakeRunner()), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "complete", status)
        self.assertNotIn("groups.yml.draft", status["message"])
        self.assertIn("vocab-absent fallback", status["message"])
        self.assertFalse(os.path.isfile(runio._pano(d, "groups.yml.draft")))
        self.assertTrue(os.path.isfile(runio._pano(d, "groups.yml")))

    def test_setup_never_writes_into_a_stale_review_runs_folder(self):
        # Fix round 1, item 2: a PRIOR review run's run-manifest.json (and its
        # runs/<tag>/ folder) must not steer `driver loop --setup`'s own
        # host-settings.json / dispatch-ledger.jsonl / usage.json into that
        # folder -- setup keeps its own setup-manifest.json and never mints,
        # reads, or should disturb, a run-manifest.json.
        d, floor = self._repo()
        review_runner = FakeRunner()
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=review_runner), \
             contextlib.redirect_stdout(io.StringIO()):
            review_status = orchestrate.loop(self._args(d))
        self.assertEqual(review_status["status"], "complete", review_status)
        review_run_id = driver.run_manifest.load_manifest(d)["run_id"]
        stale_usage_path = runio._pano(d, "usage.json")
        self.assertTrue(os.path.isfile(stale_usage_path))
        with open(stale_usage_path, encoding="utf-8") as fh:
            stale_usage_before = fh.read()

        class SetupRunner(FakeRunner):
            def run_entry(self, entry, env):
                self.launched.append(entry["id"])
                proposal = {"groups": [{"capability": "custom:App", "match": ["src/**"], "tests": []}]}
                return base.RunResult(entry_id=entry["id"], ok=True, text=json.dumps(proposal),
                                      usage={}, cost_usd=0.0, model=None, session_id=None,
                                      denials=[], error=None)
        setup_runner = SetupRunner()
        setup_args = driver.build_parser().parse_args(["loop", d, "--setup"])
        with mock.patch("scripts.runners.base.runner_for", return_value=setup_runner), \
             contextlib.redirect_stdout(io.StringIO()):
            setup_status = orchestrate.loop(setup_args)
        self.assertEqual(setup_status["status"], "complete", setup_status)

        # no NEW run-manifest was minted; the review's own is untouched
        self.assertEqual(driver.run_manifest.load_manifest(d)["run_id"], review_run_id)
        # the stale review run's own usage.json is byte-for-byte untouched
        with open(stale_usage_path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), stale_usage_before)
        # setup's own artifacts land under the FLAT .panopticon/, never the
        # stale review's runs/<tag>/ folder
        flat_settings = os.path.join(d, ".panopticon", "host-settings.json")
        flat_ledger = os.path.join(d, ".panopticon", "dispatch-ledger.jsonl")
        flat_usage = os.path.join(d, ".panopticon", "usage.json")
        self.assertTrue(os.path.isfile(flat_settings))
        self.assertTrue(os.path.isfile(flat_ledger))
        self.assertTrue(os.path.isfile(flat_usage))
        self.assertNotEqual(os.path.realpath(flat_usage), os.path.realpath(stale_usage_path))


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
        self.assertEqual(set(seen), {host_probes.headless_settings_path(d)})

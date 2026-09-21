"""driver loop in SESSION mode, `driver loop --setup`, and the two bounded
FAILURE surfaces the loop has (spec 4.3/4.6).

Split out of tests/test_orchestrate.py, which was approaching the 700-line
module ceiling and is now well past it: everything here shares nothing with
the cases left there but the fixtures, which are imported below rather than
duplicated (the `run_probes` patch has to be re-established here because
setUpModule is per-module).

#1616 item 11 moved `TestVerifyBundleCompletenessGatesResume` and
`TestPerEntryFailureCap` in. Neither is session-mode -- they are the two
classes that drive the loop's per-entry failure cap and the engine's own
verify-completeness predicate, both of which happen to be reached through a
headless runner -- so this file is now "the loop's edges" rather than
strictly its non-headless half.
"""
import contextlib
import hashlib
import io
import json
import os
import shutil
import tempfile
from unittest import mock

import scripts.driver as driver
import scripts.host_disclosure as host_disclosure
import scripts.ledger as ledger_mod
import scripts.loop_batch as loop_batch
import scripts.orchestrate as orchestrate
import scripts.probes.common as probes_common
import scripts.phases.review as review
import scripts.phases.runio as runio
import scripts.read_guard_hook as read_guard_hook
import scripts.repo_config as repo_config
import scripts.runners.base as base
from conftest import docker_probe_runner
from scripts import hosts
import scripts.write_guard_hook as write_guard_hook
from test_orchestrate import (FakeRunner, LoopCase, _all_proven_artifact,
                              _write_guard_not_proven)


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

    def test_the_printed_batch_names_what_the_request_must_hash_to(self):
        # #1727: a session host reads dispatch-request.json ITSELF, out of the
        # reviewed tree. It is handed the anchor the driver checks against, so
        # it can make the same check before it dispatches anything.
        d, floor = self._repo(); s = self._session_root(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)):
            status, out = self._loop(d, "--session-dir", s)
        self.assertEqual(status["status"], "dispatch", status)
        printed = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
        with open(printed[0]["dispatch_request"], "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(digest, printed[0]["request_sha256"])
        # ...and the loop's own dispatch status says the same thing, so a host
        # that parses the status rather than the printed batch is not told the
        # path with no way to check it.
        self.assertEqual(digest, status["request_sha256"])

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

    def test_a_refused_persist_keeps_the_reply_the_operator_piped_in(self):
        # D10 ruling 1, session half: `driver persist` refuses exactly as the
        # loop does, so it has to keep the text exactly as the loop does --
        # otherwise the one mode where a human is holding the reply is the one
        # mode that throws it away.
        d, floor = self._repo(); s = self._session_root(d)
        with mock.patch("scripts.host_probes.run_probes", side_effect=_write_guard_not_proven), \
             mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)):
            self._loop(d, "--session-dir", s, "--allow-unenforced")
        reply = os.path.join(d, "reply.txt")
        with open(reply, "w", encoding="utf-8") as fh:
            # a CONTRADICTING stamp: the one refusal ruling 4 leaves standing
            # (an omitted stamp is now filled from the entry).
            fh.write(json.dumps({"findings": [], "note": "ghp_" + "C" * 36,
                                 "_panopticon": {"group": "a-different-group"}}))
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = driver.main(["persist", "review-app-SEC", "--file", reply, d])
        self.assertEqual(rc, 1)
        run_dir = os.path.dirname(probes_common.headless_settings_path(d))
        kept = os.path.join(run_dir, "rejected", "review-app-SEC-1.json")
        with open(kept, encoding="utf-8") as fh:
            record = json.load(fh)
        self.assertEqual(record["attempt"], 1)
        self.assertIn("_panopticon.group", record["reason"])
        self.assertIn("[REDACTED_TOKEN]", record["reply"])
        # D10 F10: keeping it silently is keeping it from the operator too --
        # the refusal line is the only thing they see, so it says where.
        self.assertIn("(reply kept at %s)" % kept, err.getvalue())

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


    def test_setup_persist_reads_the_setup_manifests_own_record(self):
        # #1727: `--setup` anchors its request in `setup-manifest.json`, not in
        # a review run's manifest. `driver persist --setup` has to find that
        # record -- and refuse a setup request that no longer matches it.
        d, _ = self._repo()
        s = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(s, ignore_errors=True))
        os.makedirs(os.path.join(s, ".claude"))
        with open(os.path.join(s, ".claude", "settings.local.json"), "w") as fh:
            fh.write("{}")
        args = driver.build_parser().parse_args(
            ["loop", d, "--setup", "--mode", "session", "--session-dir", s])
        with contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "dispatch", status)
        proposal = os.path.join(d, "reply.txt")
        with open(proposal, "w", encoding="utf-8") as fh:
            json.dump({"groups": [{"capability": "custom:App", "match": ["src/**"],
                                   "tests": []}]}, fh)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = driver.main(["persist", "setup-scan", "--setup", "--file", proposal, d])
        self.assertEqual(rc, 0)
        # ...and once the request is altered, the same call refuses
        with open(status["dispatch_request"], "ab") as fh:
            fh.write(b" ")
        with contextlib.redirect_stderr(io.StringIO()) as err, \
             contextlib.redirect_stdout(io.StringIO()):
            rc = driver.main(["persist", "setup-scan", "--setup", "--file", proposal, d])
        self.assertEqual(rc, 1)
        self.assertIn("does not match the request this run wrote", err.getvalue())


class _ProposalRunner(FakeRunner):
    """Answers the single `setup-scan` entry with a valid proposal."""

    def run_entry(self, entry, env):
        self.launched.append(entry["id"])
        proposal = {"groups": [{"capability": "custom:App", "match": ["src/**"],
                                "tests": []}]}
        return base.RunResult(entry_id=entry["id"], ok=True, text=json.dumps(proposal),
                              usage={}, cost_usd=0.0, model=None, session_id=None,
                              denials=[], error=None)


class TestSetupEstablishesHostPosture(LoopCase):
    """#1616 item 3: `driver loop --setup --mode headless` arms both guards
    into `.panopticon/host-settings.json`, and `run_setup_flow` never ran the
    posture step -- so nothing had probed the file the runner was about to arm,
    and the evidence a review run left behind (or the absence of any) stood in
    for a measurement of this invocation."""

    def _setup_loop(self, d, runner=None, **patches):
        args = driver.build_parser().parse_args(["loop", d, "--setup"])
        with contextlib.ExitStack() as es:
            for target, patch in patches.items():
                es.enter_context(mock.patch(target, **patch))
            es.enter_context(mock.patch("scripts.runners.base.runner_for",
                                        return_value=runner or _ProposalRunner()))
            es.enter_context(contextlib.redirect_stdout(io.StringIO()))
            es.enter_context(contextlib.redirect_stderr(io.StringIO()))
            return orchestrate.loop(args)

    def test_the_setup_flow_probes_before_the_runner_arms_anything(self):
        d, _ = self._repo()
        seen = []

        def _probes(host, target, **kw):
            seen.append(host)
            return _all_proven_artifact(host)

        status = self._setup_loop(d, **{"scripts.host_probes.run_probes":
                                        {"side_effect": _probes}})
        self.assertEqual(status["status"], "complete", status)
        # Once per INVOCATION, exactly as `driver run` probes -- this flow is
        # re-entered after the batch, and posture is not a once-per-run fact
        # (spec 5.2: a hook uninstalled mid-run would read `proven` for ever).
        self.assertEqual(seen, ["claude"] * len(seen))
        self.assertTrue(seen, "driver loop --setup armed its guards without a probe")

    def test_a_posture_refusal_stops_the_setup_flow(self):
        # The refusal is the point of probing at all: a posture that moved
        # mid-run, a planted shadow shell. Before this it could not reach the
        # setup flow to stop anything.
        d, _ = self._repo()
        status = self._setup_loop(d, **{"scripts.driver._establish_host_posture":
                                        {"return_value": "posture drift: nope"}})
        self.assertEqual(status["status"], "error", status)
        self.assertIn("posture drift: nope", status["message"])

    def test_setup_writes_its_evidence_flat_and_leaves_a_review_runs_alone(self):
        # The sibling of `test_setup_never_writes_into_a_stale_review_runs_folder`
        # below, for the artifact this step writes: `host-capabilities.json`
        # resolves per-RUN, so a repo that already holds a review run-manifest
        # would have had setup's own probe overwrite that run's evidence.
        d, floor = self._repo()
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=FakeRunner()), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(orchestrate.loop(self._args(d))["status"], "complete")
        per_run = runio._pano(d, runio.HOST_CAPABILITIES)       # runs/<tag>/...
        flat = os.path.join(d, ".panopticon", runio.HOST_CAPABILITIES)
        self.assertNotEqual(os.path.realpath(per_run), os.path.realpath(flat))
        with open(per_run, encoding="utf-8") as fh:
            before = fh.read()
        os.remove(flat)                       # the fixture's; setup must write its own
        self.assertEqual(self._setup_loop(d)["status"], "complete")
        self.assertTrue(os.path.isfile(flat), "setup wrote no evidence of its own")
        with open(per_run, encoding="utf-8") as fh:
            self.assertEqual(before, fh.read(),
                             "setup overwrote the review run's own evidence")


    def test_the_fallback_notice_is_printed_once_per_invocation(self):
        # Fix round 1, F4: `run_setup_flow` prints the fallback notice itself
        # ("once per `driver setup` call") and the injected posture step
        # prints it again for the same resolved host -- so wiring the step in
        # made `driver loop --setup --host generic` say it twice per
        # invocation.
        d, _ = self._repo()
        # #1737: `generic` registers no shells, so the setup dispatch is
        # shell-less and the operator has to say so. The acceptance is what
        # this test is NOT about -- it is about the notice being printed once
        # -- so it is given here rather than worked around.
        args = driver.build_parser().parse_args(
            ["loop", d, "--setup", "--host", "generic", "--mode", "session",
             "--allow-unenforced", "--session-dir", self._session_root(d)])
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(err):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "dispatch", status)
        self.assertEqual(1, err.getvalue().count(host_disclosure.GENERIC_FALLBACK_NOTICE))

    def test_a_posture_change_between_two_setup_invocations_is_not_drift(self):
        # Fix round 1, F2: the drift refusal is a statement about ONE RUN --
        # "entries already dispatched were built under the previous posture" --
        # and `driver loop --setup` is not a run. Its one `setup-scan` entry is
        # dispatched and consumed inside the invocation, and the flat
        # host-capabilities.json it compares against outlives every one of
        # them. The bootstrap sequence itself moves a GATING capability:
        # tool_policy_enforced is refuted before the operator emits the host
        # agents and proven after. Refusing would wedge the verb, and the
        # remedy the refusal names (--reset) did not clear the file.
        d, _ = self._repo()
        self.assertEqual(self._setup_loop(d)["status"], "complete")
        status = self._setup_loop(d, **{"scripts.host_probes.run_probes":
                                        {"side_effect": _write_guard_not_proven}})
        self.assertEqual(status["status"], "complete", status)
        # ...and the record on disk is this invocation's, not the first one's.
        stored = runio._load_json(os.path.join(d, ".panopticon",
                                               runio.HOST_CAPABILITIES))
        self.assertEqual(hosts.UNKNOWN,
                         stored["capabilities"][hosts.ARTIFACT_WRITE_GUARD]["state"])

    def test_the_guard_probes_measure_the_file_setup_really_arms(self):
        # #1616 item 10: `headless_settings_path(review_root)` without the
        # namespace resolves THROUGH the run-manifest, so on a repo that
        # already holds a review run's manifest the guard probes measured
        # `runs/<tag>/host-settings.json` while the runner armed the flat
        # `.panopticon/host-settings.json`. The verdict is unaffected (the
        # probe measures the directory's writability), and the path the
        # evidence NAMES -- rendered on three disclosure surfaces -- was a
        # file this invocation never touches.
        d, floor = self._repo()
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=FakeRunner()), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(orchestrate.loop(self._args(d))["status"], "complete")
        seen = []

        def _probes(host, target, **kw):
            seen.append(kw.get("settings_path"))
            return _all_proven_artifact(host)

        status = self._setup_loop(d, **{"scripts.host_probes.run_probes":
                                        {"side_effect": _probes}})
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(set(seen), {probes_common.headless_settings_path(d, "setup")})
        self.assertEqual(set(seen),
                         {os.path.abspath(os.path.join(d, ".panopticon",
                                                       base.SETTINGS_FILE))})


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
        self.assertIn(repo_config.DRAFT_NAME, status["message"])
        self.assertTrue(os.path.isfile(runio._pano(d, "setup-proposal.json")))

    def test_setup_vocab_absent_fallback_keeps_its_own_complete_message(self):
        # Fix round 1, item 1: the vocab-absent fallback (phases/setup.py's
        # _scan_fallback) seeds the root config directly and writes neither
        # setup-report.md nor a draft -- _finish must leave
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
        self.assertNotIn(repo_config.DRAFT_NAME, status["message"])
        self.assertIn("vocab-absent fallback", status["message"])
        self.assertFalse(os.path.isfile(repo_config.draft_path(d)))
        self.assertEqual(os.path.join(d, repo_config.CONFIG_NAMES[0]),
                         repo_config.resolve(d).path)

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

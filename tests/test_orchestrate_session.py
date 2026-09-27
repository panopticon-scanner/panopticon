"""Session-mode and setup loop integration tests.

Shared fixtures live in tests/orchestrate_helpers.py. This module owns its
host probe and readiness patches because setUpModule is per module.
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
import scripts.orchestrate as orchestrate
import scripts.probes.common as probes_common
import scripts.phases.runio as runio
import scripts.read_guard_hook as read_guard_hook
import scripts.repo_config as repo_config
import scripts.runners.base as base
from tests._test_helpers import docker_probe_runner
from scripts import hosts
import scripts.write_guard_hook as write_guard_hook
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
        # EVERY call, deliberately (#1603 fix round 1): readiness runs on this
        # path now and must not take a posture of its own -- one that named no
        # settings file would land here as a `None` and disclose `unknown` for
        # capabilities this invocation proved. It renders the envelope the
        # posture step established instead, so the population stays exactly
        # the posture step's calls.
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

    def test_setup_on_rails_carries_the_readiness_clause_too(self):
        # #1603. `_finish` supersedes run_setup_flow's completion message with
        # the on-rails promotion wording whenever a draft exists -- and that
        # message is the ONLY one a `driver loop --setup` operator reads, so
        # dropping the readiness clause there would leave 5.1's surface 4
        # reachable by `driver setup` alone, which is the hole this issue
        # exists to close. The fallback branch has always kept its own message
        # (the test below); this is the same guarantee for the draft branch.
        d, _ = self._repo()

        class SetupRunner(FakeRunner):
            def run_entry(self, entry, env):
                self.launched.append(entry["id"])
                proposal = {"groups": [{"capability": "custom:App", "match": ["src/**"],
                                        "tests": [],
                                        "profile": {"purpose": "app", "surfaces": [],
                                                    "entry_points": [],
                                                    "trust_boundaries": []}}]}
                return base.RunResult(entry_id="setup-scan", ok=True,
                                      text=json.dumps(proposal), usage={}, cost_usd=0.0,
                                      model=None, session_id=None, denials=[], error=None)
        checks = [("docker", False, "docker unavailable -- install/start Docker "
                                    "or run with --no-tools"),
                  ("nvd-api-key", None, "absent -- dependency-check will be skipped")]
        args = driver.build_parser().parse_args(["loop", d, "--setup"])
        with mock.patch("scripts.runners.base.runner_for", return_value=SetupRunner()), \
             mock.patch("scripts.setup_flow.readiness", return_value=checks), \
             contextlib.redirect_stdout(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "complete", status)
        # the promotion wording is still what it was...
        self.assertIn(repo_config.DRAFT_NAME, status["message"])
        # ...and the disclosure rides with it, gap and limitation alike.
        self.assertIn("readiness gaps: docker (fix before running a review)",
                      status["message"])
        self.assertIn("nvd-api-key", status["message"])

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

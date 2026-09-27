"""Shared loop test runners, fixtures, and inert constants."""
import contextlib
import io
import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock


import scripts.driver as driver
import scripts.ledger as ledger_mod
import scripts.loop_batch as loop_batch
import scripts.orchestrate as orchestrate
import scripts.phases.review as review
import scripts.runners.batch as batch_mod
import scripts.phases.runio as runio
import scripts.read_guard_hook as read_guard_hook
import scripts.runners.base as base
import scripts.write_guard_hook as write_guard_hook
from tests._test_helpers import (dead_pid,
                           write_guard_not_proven as _write_guard_not_proven)
from tests._test_helpers import write_host_evidence
from scripts import hosts


_ALL_PROVEN = {c: hosts.PROVEN for c in hosts.CAPABILITIES}


class FakeRunner(base.HostRunner):
    """Answers entries like a well-behaved agent: self-writes findings/verdicts
    under the write guard (a real agent's Write would be mediated; here the
    fake writes directly, and the test asserts the guard WAS armed around it),
    returns JSON text for return-persist entries, and can be told to drop or
    fail an entry once."""
    host = "claude"; mode = "headless"; default_concurrency = 4

    def __init__(self, host="claude"):
        super().__init__(host)
        self.launched = []
        self.drop_once = set()
        self.fail_once = set()
        self.seen_env = {}
        self.armed_at_launch = []

    def prepare(self, run_dir, review_root):
        self.run_dir, self.review_root = run_dir, review_root
        self.settings_path = os.path.join(run_dir, base.SETTINGS_FILE)

    def run_entry(self, entry, env):
        eid = entry["id"]
        self.launched.append(eid)
        self.seen_env[eid] = dict(env)
        self.armed_at_launch.append((
            write_guard_hook.is_armed(self.settings_path, os.path.join(self.run_dir, "write-allowlist.json"))[0],
            read_guard_hook.is_armed(self.settings_path, os.path.join(self.run_dir, "read-scope.json"))[0]))
        if eid in self.drop_once:
            self.drop_once.discard(eid)
            return base.RunResult.failed(eid, "concurrency cap")
        if eid in self.fail_once:
            self.fail_once.discard(eid)
            # M2: a failed entry still BURNED tokens -- `claude -p` reports
            # usage on an is_error envelope exactly as it does on success --
            # so the fake reports them too, and the usage assertions below can
            # tell a document that counts them from one that drops them.
            return base.RunResult(entry_id=eid, ok=False, text="",
                                  usage={"input_tokens": 70, "output_tokens": 3,
                                         "cache_read_input_tokens": 0,
                                         "cache_creation_input_tokens": 0},
                                  cost_usd=0.004, model="claude-sonnet-5",
                                  session_id="s-" + eid, denials=[], error="is_error")
        run_id = entry.get("run_id")
        if eid.startswith("review-"):
            body = {"findings": [{"title": "issue", "severity": "HIGH", "domain": entry["domain"],
                                  "code": entry["domain"] + "-A1A", "category": "authz",
                                  "location": {"file": "src/app.py", "line_start": 1}}],
                    "_panopticon": {"run_id": run_id, "role": "domain_panel",
                                    "domain": entry["domain"], "group": entry["group"]}}
        elif eid.startswith("verify-"):
            cell = review._load_cell_findings(self.review_root, {"run_id": run_id},
                                              entry["group"], entry["domain"])
            body = {"verdicts": [{"finding_id": cell[0]["id"], "verdict": "CONFIRMED",
                                  "reasoning": "verified"}],
                    "_panopticon": {"run_id": run_id, "role": "domain_advisor",
                                    "domain": entry["domain"], "group": entry["group"],
                                    "stage": entry.get("stage", "primary")}}
        else:
            raise AssertionError("unexpected entry %s" % eid)
        if entry.get("delivery") == "return_json":
            text = "```json\n" + json.dumps(body) + "\n```"
        else:
            runio._write_json(entry["out_file"], body)
            text = "written"
        return base.RunResult(entry_id=eid, ok=True, text=text,
                              usage={"input_tokens": 100, "output_tokens": 10,
                                     "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
                              cost_usd=0.01, model="claude-sonnet-5", session_id="s-" + eid,
                              denials=[], error=None)


class SeededLedger(FakeRunner):
    """A runner that leaves ledger lines on disk before the loop's first budget
    check -- `prepare` is the last thing the loop does before it constructs the
    Ledger and enters the while loop, so this is the seam for a ledger the
    process did not write itself (a resumed run, or a host that reported a
    cost this repo would now refuse to store)."""

    LINES = ()

    def prepare(self, run_dir, review_root):
        super().prepare(run_dir, review_root)
        os.makedirs(run_dir, exist_ok=True)
        with open(os.path.join(run_dir, base.LEDGER_FILE), "w", encoding="utf-8") as fh:
            fh.write("".join(x + "\n" for x in self.LINES))


class PoisonedLedger(SeededLedger):
    # Written by hand, exactly as `json.dumps` with its defaults emits it.
    LINES = ('{"cost_usd": NaN, "entry_id": "review-app-SEC", "error": null, '
             '"ok": true, "phase": "review", "usage": {}}',)


class ACreditedLedger(SeededLedger):
    # Fix round 1, M1: one negative cost, which a plain sum treats as a credit.
    LINES = ('{"cost_usd": -1000, "entry_id": "e0", "error": null, '
             '"ok": true, "phase": "review", "usage": {}}',)


class FifteenCentRows(SeededLedger):
    LINES = tuple('{"cost_usd": 0.15, "entry_id": "e%d", "error": null, '
                  '"ok": true, "phase": "review", "usage": {}}' % i for i in range(3))


class LoopCase(unittest.TestCase):
    def _repo(self, floor=("SEC",)):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "src"))
        with open(os.path.join(d, "src", "app.py"), "w") as fh:
            fh.write("def f():\n    return 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        write_host_evidence(d, _ALL_PROVEN)
        runio._write_json(runio._pano(d, "groups.json"),
                          {"groups": [{"name": "app", "files": ["src/app.py"]}]})
        # #1681: `panopticon.yml` is a committed ROOT file now, so it is an
        # ordinary repo file discovery sees. Excluded here so this fixture keeps
        # its one-group/one-file shape (the loop's entry ids are pinned).
        matrix = ("groups:\n  app:\n    match: ['src/**']\n"
                  "exclude_paths: ['panopticon.yml']\n")
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n" + matrix)
        return d, list(floor)

    def _args(self, d, *extra):
        return driver.build_parser().parse_args(
            ["loop", d, "--no-tools", "--fail-on", "high", *extra])

    def _session_root(self, d):
        # session mode arms the SESSION root's settings file (spec 5.1); the
        # tests point it at a sandbox via --session-dir so the real file is
        # never touched, and pre-create the file install() requires (#1493).
        s = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(s, ignore_errors=True))
        os.makedirs(os.path.join(s, ".claude"))
        with open(os.path.join(s, ".claude", "settings.local.json"), "w") as fh:
            fh.write("{}")
        return s

    def _run_loop(self, d, floor, runner, *extra, probes=None, seed=True):
        """One whole `driver loop` against `runner`, with the engine's own
        phases real. `seed=False` is the RESUME shape: coverage is already on
        disk, so the second driver.run the seam exists for would only re-charge
        the review checkpoint's per-cell attempt marker (see
        `_after_first_run`)."""
        args = self._args(d, *extra)
        with contextlib.ExitStack() as es:
            if probes is not None:
                es.enter_context(mock.patch("scripts.host_probes.run_probes",
                                            side_effect=probes))
            es.enter_context(mock.patch.object(
                orchestrate, "_after_first_run",
                side_effect=lambda rr: seed and self._seed_coverage(rr, floor)))
            es.enter_context(mock.patch("scripts.runners.base.runner_for",
                                        return_value=runner))
            es.enter_context(contextlib.redirect_stdout(io.StringIO()))
            es.enter_context(contextlib.redirect_stderr(io.StringIO()))
            return orchestrate.loop(args)

    def _seed_coverage(self, d, floor):
        # discovery/coverage would dispatch a scout; seed coverage so the first
        # checkpoint is review (the scout path is covered by TestScoutRoundTrip).
        # Returns True: this seam mutated review_root, so `loop` must re-derive
        # `status` with a second driver.run call to see the review checkpoint
        # (production's `_after_first_run` always returns False -- see its
        # docstring for why an unconditional second call would be a bug).
        manifest = driver.run_manifest.load_manifest(d)
        runio._write_json(runio._pano(d, "coverage-app.json"),
                          {"group": "app", "floor": floor, "effective": floor,
                           "run_id": manifest["run_id"]})
        return True


class _HeadlessLoopCase(LoopCase):
    # #1912 (review round 1, finding 1): the two hardware ids the owner-stamp
    # cases STATE rather than read off whatever machine the suite is running on.
    # `uuid.getnode()` answers differently per host and falls back to a random
    # multicast value where it finds no hardware address -- and every owner
    # verdict asserted below has to be the same verdict on every machine.
    MACHINE = "acde48001122"            # "this machine", because the test says so
    OTHER_MACHINE = "00deadbeef00"      # ...and somebody else's

    def _run(self, d, floor, runner, *extra):
        args = self._args(d, *extra)
        # first driver.run mints the manifest; seed coverage right after (the
        # loop's first iteration will then see the review checkpoint)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda review_root: self._seed_coverage(review_root, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()):
            return orchestrate.loop(args)

    def _return_persist(self, d, floor, runner, *extra):
        """`self._run` in the posture where review/verify replies come back as
        JSON for the LOOP to persist (artifact_write_guard not proven, so
        `requests.delivery` says return_json). A persisted out_file is then
        evidence about the loop, not about the fake agent's own Write."""
        with mock.patch("scripts.host_probes.run_probes",
                        side_effect=_write_guard_not_proven):
            return self._run(d, floor, runner, "--allow-unenforced", *extra)

    def _peer_artifacts(self, runner, peer_id, timeout=10):
        """What is on disk for `peer_id`, polled from INSIDE another entry's
        run_entry -- so the answer describes what the loop had persisted while
        this batch was still running, which is the whole of P07."""
        req = orchestrate.requests.load_dispatch_request(runner.review_root) or {}
        peer = next(e for e in req.get("entries") or [] if e.get("id") == peer_id)
        usage_path = os.path.join(runner.run_dir, "usage.json")
        seen = {"reply": False, "ledger": False, "usage": False}
        deadline = time.monotonic() + timeout
        while True:
            seen["reply"] = os.path.exists(peer["out_file"])
            seen["ledger"] = any(row.get("entry_id") == peer_id
                                 for row in ledger_mod.Ledger(runner.run_dir).lines())
            seen["usage"] = bool((runio._load_json(usage_path) or {}).get("total"))
            if all(seen.values()) or time.monotonic() >= deadline:
                return seen
            time.sleep(0.02)

    def _gate_on_peer(self, runner, blocked_id, peer_id, then=None):
        """Make `blocked_id` sit inside run_entry until `peer_id`'s reply,
        ledger row and usage total exist; return what it saw."""
        seen, inner = {}, runner.run_entry

        def gated(entry, env):
            if entry["id"] == blocked_id and not seen:
                seen.update(self._peer_artifacts(runner, peer_id))
                if then is not None:
                    then()
            return inner(entry, env)

        runner.run_entry = gated
        return seen

    def _manifests(self, run_dir):
        return sorted(f for f in os.listdir(run_dir)
                      if f.startswith(batch_mod.MANIFEST_PREFIX) and f.endswith(".json"))

    def _interrupt_mid_batch(self, d, floor, runner):
        """Interrupt the review batch the moment its first entry has landed."""
        def interrupt():
            raise KeyboardInterrupt

        seen = self._gate_on_peer(runner, "review-app-ACC", "review-app-SEC",
                                  then=interrupt)
        return self._return_persist(d, floor, runner), seen

    def _stamp_crash_owner(self, run_dir, **fields):
        """Rewrite every leftover crash record's owner stamp (#1698).

        The suite models a crash IN THIS PROCESS, so the record it leaves
        names a pid that is very much alive -- which is exactly what recovery
        now refuses to touch. A test about a CRASHED loop has to say the
        process is gone, and a reaped child's pid is the honest way to say it.
        """
        for name in self._manifests(run_dir):
            path = os.path.join(run_dir, name)
            doc = runio._load_json(path)
            doc.update(fields)
            runio._write_json(path, doc)

    def _crash_record(self, run_dir):
        return runio._load_json(os.path.join(run_dir, self._manifests(run_dir)[0]))

    def _untouched(self, d, run_dir):
        """Everything a refused recovery must leave exactly as it found it."""
        doc = self._crash_record(run_dir)
        return (sorted(self._manifests(run_dir)),
                [p for row in doc["entries"] for p in row["artifacts"] if os.path.exists(p)],
                ledger_mod.Ledger(run_dir).lines(),
                runio._load_json(runio._pano(d, review._ATTEMPTS_FILE)))

    def _leave_crashed_batch(self, d, floor):
        runner = FakeRunner()
        # Model a process that never reached its interrupt rollback. The
        # finished peer's artifact, real paid row and batch record survive.
        with mock.patch.object(loop_batch, "rolled_back",
                               return_value="simulated process loss"):
            self._interrupt_mid_batch(d, floor, runner)
        # ...and that process is GONE: the record it left names a dead pid.
        self._stamp_crash_owner(runner.run_dir, pid=dead_pid())
        return runner

    def _foreign(self, run_dir):
        """Make every leftover record read as another machine's: both ids."""
        self._stamp_crash_owner(run_dir, host="some-other-box",
                                machine=self.OTHER_MACHINE)

    def _accepted(self, run_dir):
        return runio._load_json(os.path.join(run_dir, batch_mod.DISCARDED_BATCHES))

    def _second_record(self, run_dir):
        """Split the crash record in two, one entry each.

        Two records may not claim the same entry (recovery refuses that), so a
        second record has to be carved out of the first. Both then validate
        against the same bound request, which is what makes this a test about
        the FLAG's scope rather than about validation.
        """
        first = os.path.join(run_dir, self._manifests(run_dir)[0])
        doc = runio._load_json(first)
        self.assertEqual(2, len(doc["entries"]), "the fixture lost an entry")
        second = dict(doc, batch=2, entries=[doc["entries"][1]])
        runio._write_json(batch_mod.manifest_path(run_dir, 2), second)
        runio._write_json(first, dict(doc, entries=[doc["entries"][0]]))
        return sorted(self._manifests(run_dir))

    def _obstruct(self, d, entry_id):
        """Make `entry_id`'s artifact un-removable: a non-empty directory
        where the reply file was. `os.remove` raises, which is what a
        rollback with PROBLEMS looks like."""
        req = orchestrate.requests.load_dispatch_request(d) or {}
        out = next(e for e in req["entries"] if e["id"] == entry_id)["out_file"]
        os.remove(out)
        os.makedirs(out)
        with open(os.path.join(out, "keep.txt"), "w") as fh:
            fh.write("keep")
        return out

    def _rejected(self, runner):
        folder = os.path.join(runner.run_dir, orchestrate.persist.REJECTED_DIR)
        return sorted(os.listdir(folder)) if os.path.isdir(folder) else []

    def _guards_armed(self, runner):
        settings = os.path.join(runner.run_dir, base.SETTINGS_FILE)
        return (write_guard_hook.is_armed(
                    settings, os.path.join(runner.run_dir, "write-allowlist.json"))[0],
                read_guard_hook.is_armed(
                    settings, os.path.join(runner.run_dir, "read-scope.json"))[0])

    def _interrupt_the_rollback(self, where):
        """Patch `where` so the SECOND Ctrl-C lands inside the rollback itself
        -- the operator holding the key down, or hitting it again because the
        first one did not seem to do anything."""
        if where == "ledger":
            real = ledger_mod.Ledger.record

            def record(self, *args, **kwargs):
                if kwargs.get("status"):        # only the interrupt's own rows
                    raise KeyboardInterrupt
                return real(self, *args, **kwargs)

            return mock.patch.object(ledger_mod.Ledger, "record", record)
        if where == "artifacts":
            return mock.patch.object(batch_mod.Batch, "roll_back",
                                     side_effect=KeyboardInterrupt)
        return mock.patch.object(orchestrate.persist, "rollback_markers",
                                 side_effect=KeyboardInterrupt)



class _MidBatchGated(FakeRunner):
    """Behaviour keyed on the cell's index in the batch's pending list --
    which is its LAUNCH order, the pool being FIFO -- not on a counter, so
    no thread interleaving can change which cell does what. And from index
    two on, a launch does not come back until the LOOP has ledgered every
    result before it: two workers answering instantly outrun a consumer
    that persists and ledgers each reply, and "what the short-circuit
    stopped" would be a race rather than a fact. The chain always makes
    progress (a launch waits only on results from launches before it) and
    every wait is deadlined.

    One worker turnover is NOT pinned and cannot be: the loop persists,
    ledgers and counts a result before it asks `stop`, so a worker freed by
    that result's own ledger line can start one more entry in between. That
    is a real property of the loop, not the fixture's, which is why the
    bound below carries it as an explicit `+ 1` rather than being flaky.
    """

    def __init__(self, floor, host_error, refusal=None):
        super().__init__()
        self.order = ["review-app-%s" % d for d in floor]
        self.failure, self.refusal = host_error, refusal

    def _index(self, entry):
        eid = entry["id"]
        return self.order.index(eid) if eid in self.order else None

    def _host_failure(self, eid):
        return base.RunResult.failed(eid, "kimi -p exited 1: " + self.failure,
                                     host_error=self.failure)

    def _await_ledger(self, lines):
        path = os.path.join(self.run_dir, base.LEDGER_FILE)
        for _ in range(2000):
            try:
                with open(path, "rb") as fh:   # bytes: a poisoned line must not
                    if sum(1 for line in fh if line.strip()) >= lines:  # raise here
                        return
            except OSError:
                pass
            time.sleep(0.005)
        raise AssertionError("the loop never ledgered %d results" % lines)

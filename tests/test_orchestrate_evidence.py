"""Loop evidence retention and bound read tests."""
import ast
import contextlib
import io
import json
import os
import unittest
from unittest import mock


import scripts.ledger as ledger_mod
import scripts.loop_batch as loop_batch
import scripts.orchestrate as orchestrate
import scripts.phases.runio as runio
import scripts.runners.base as base
from tests._test_helpers import (all_proven_artifact as _all_proven_artifact, write_guard_not_proven as _write_guard_not_proven)
from tests._test_helpers import docker_probe_runner


from tests.orchestrate_helpers import (FakeRunner, LoopCase)

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


class TestRefusedRepliesAreRetained(LoopCase):
    """D10 ruling 1, loop side: the reply the loop refuses is kept.

    Before this the refusal printed a reason to stderr and dropped the text on
    the floor -- so run-13's eight failed attempts left nothing to look at and
    nothing for the retry to quote.

    The refusal used here is a CONTRADICTING stamp, deliberately: a reply that
    merely OMITS `_panopticon` -- run-13's actual failure, 7 times out of 8 --
    is no longer refused at all (ruling 4 fills it from the entry). What is
    left to refuse is a reply making a different claim than the entry, and that
    one is never overwritten.
    """

    class RefusingRunner(FakeRunner):
        """A return-persist reviewer that stamps its findings for a cell it was
        not dispatched for, and leaks a token-shaped literal while it is at
        it."""

        SECRET = "ghp_" + "B" * 36

        def __init__(self, host="claude"):
            super().__init__(host)
            self.prompts, self.priors = [], []

        def run_entry(self, entry, env):
            if not entry["id"].startswith("review-"):
                return super().run_entry(entry, env)
            self.launched.append(entry["id"])
            self.prompts.append(entry["prompt"])
            self.priors.append(entry.get("prior_rejection"))
            body = {"findings": [{"title": "issue at " + self.SECRET, "severity": "HIGH",
                                  "domain": entry["domain"], "code": entry["domain"] + "-A1A",
                                  "category": "authz",
                                  "location": {"file": "src/app.py", "line_start": 1}}],
                    "_panopticon": {"run_id": entry.get("run_id"), "role": "domain_panel",
                                    "domain": entry["domain"], "group": "a-different-group"}}
            return base.RunResult(
                entry_id=entry["id"], ok=True, text=json.dumps(body),
                usage={"input_tokens": 5, "output_tokens": 1, "cache_read_input_tokens": 0,
                       "cache_creation_input_tokens": 0},
                cost_usd=0.001, model="claude-sonnet-5", session_id="s", denials=[], error=None)

    def _run_loop(self, d, floor, runner):
        args = self._args(d, "--allow-unenforced")
        with mock.patch("scripts.host_probes.run_probes", side_effect=_write_guard_not_proven), \
             mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            return orchestrate.loop(args)

    def test_every_refusal_writes_its_own_record_and_the_ledger_row_names_it(self):
        d, floor = self._repo()
        runner = self.RefusingRunner()
        # `complete`, not `error`: the REVIEW phase's own per-cell attempt
        # budget gives up on the cell before the loop's per-entry cap sees it
        # pending a fourth time (TestPerEntryFailureCap covers the cap itself,
        # on the verify round, where the phase has no such budget). Either way
        # the reply was refused three times, and this is about what survives.
        status = self._run_loop(d, floor, runner)
        self.assertEqual(status["status"], "complete", status)
        self.assertEqual(runner.launched, ["review-app-SEC"] * 3)
        rejected = os.path.join(runner.run_dir, "rejected")
        self.assertEqual(sorted(os.listdir(rejected)),
                         ["review-app-SEC-%d.json" % n
                          for n in range(1, orchestrate.MAX_ENTRY_FAILURES + 1)])
        rows = [r for r in ledger_mod.Ledger(runner.run_dir).lines()
                if r["entry_id"] == "review-app-SEC"]
        self.assertEqual([r["rejected_file"] for r in rows],
                         [os.path.join(rejected, "review-app-SEC-%d.json" % n)
                          for n in range(1, orchestrate.MAX_ENTRY_FAILURES + 1)])
        with open(os.path.join(rejected, "review-app-SEC-1.json"), encoding="utf-8") as fh:
            record = json.load(fh)
        self.assertIn("_panopticon.group is 'a-different-group'", record["reason"])
        self.assertIn("[REDACTED_TOKEN]", record["reply"])
        self.assertNotIn(self.RefusingRunner.SECRET, record["reply"])

    def test_the_next_launch_of_a_refused_entry_is_told_why(self):
        # D10 ruling 2, end to end: the retry goes out through the ordinary
        # `driver.run` -> `write_dispatch_request` path, so the only way the
        # agent hears about the refusal is the prompt the loop hands it.
        d, floor = self._repo()
        runner = self.RefusingRunner()
        self._run_loop(d, floor, runner)
        self.assertEqual(3, len(runner.prompts))
        self.assertNotIn("refused", runner.prompts[0])
        self.assertIsNone(runner.priors[0])
        self.assertIn("_panopticon.group is 'a-different-group'", runner.prompts[1])
        self.assertIn("attempt 1", runner.prompts[1])
        self.assertEqual(1, runner.priors[1]["attempt"])
        self.assertEqual(2, runner.priors[2]["attempt"])

    def test_a_clean_run_writes_no_records_at_all(self):
        d, floor = self._repo()
        runner = FakeRunner()
        status = self._run_loop(d, floor, runner)
        self.assertEqual(status["status"], "complete", status)
        self.assertFalse(os.path.exists(os.path.join(runner.run_dir, "rejected")))


class TestATimedOutEntryKeepsItsEvidence(LoopCase):
    """D10 ruling 5, loop side: a failed launch that printed something keeps
    it, and the ledger row names both the tokens and the file."""

    PARTIAL = '{"findings": [{"title": "half a finding, key ghp_' + "D" * 36 + '"'

    class TimesOutOnce(FakeRunner):
        def __init__(self, host="claude"):
            super().__init__(host)
            self.priors = []

        def run_entry(self, entry, env):
            if entry["id"] in self.fail_once:
                self.fail_once.discard(entry["id"])
                self.launched.append(entry["id"])
                return base.RunResult.failed(
                    entry["id"], "claude -p timed out after 1800s",
                    usage={"input_tokens": 7000, "output_tokens": 0,
                           "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
                    text=TestATimedOutEntryKeepsItsEvidence.PARTIAL)
            return super().run_entry(entry, env)

    def test_the_partial_output_is_retained_and_the_tokens_are_counted(self):
        d, floor = self._repo()
        runner = self.TimesOutOnce()
        runner.fail_once.add("review-app-SEC")
        args = self._args(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "complete", status)
        kept = os.path.join(runner.run_dir, "rejected", "review-app-SEC-1.json")
        with open(kept, encoding="utf-8") as fh:
            record = json.load(fh)
        self.assertIn("timed out after", record["reason"])
        self.assertIn("[REDACTED_TOKEN]", record["reply"])
        self.assertTrue(record["reply"].startswith('{"findings"'), record["reply"])
        row = next(r for r in ledger_mod.Ledger(runner.run_dir).lines()
                   if r["entry_id"] == "review-app-SEC" and not r["ok"])
        self.assertEqual(kept, row["rejected_file"])
        self.assertEqual(7000, sum(row["usage"].values()))
        usage = runio._load_json(os.path.join(runner.run_dir, "usage.json"))
        self.assertGreaterEqual(usage["by_phase"]["review"], 7000)

    def test_a_self_writing_entry_is_not_told_its_reply_was_refused(self):
        # D10 F4: this cell SELF-WRITES (the write guard is proven here), so a
        # timeout is not a format refusal and there is no reply to "return
        # again". The partial output is still kept; the prompt must not gain a
        # word.
        d, floor = self._repo()
        runner = self.TimesOutOnce()
        runner.fail_once.add("review-app-SEC")
        prompts = []

        class Recording(self.TimesOutOnce):
            def run_entry(self, entry, env):
                prompts.append(entry["prompt"])
                self.priors.append(entry.get("prior_rejection"))
                return super().run_entry(entry, env)

        runner = Recording()
        runner.fail_once.add("review-app-SEC")
        args = self._args(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            status = orchestrate.loop(args)
        self.assertEqual(status["status"], "complete", status)
        review = [p for p in prompts if "SEC` domain reviewer" in p]
        self.assertEqual(2, len(review))                   # timed out, then ran
        self.assertEqual(review[0], review[1])             # byte-identical
        self.assertNotIn("refused", review[1])
        self.assertEqual([None, None], runner.priors[:2])
        # ...and the partial output was still kept (ruling 5 is untouched)
        self.assertTrue(os.path.exists(os.path.join(
            runner.run_dir, "rejected", "review-app-SEC-1.json")))

    def test_a_failure_that_printed_nothing_keeps_nothing(self):
        d, floor = self._repo()
        runner = FakeRunner()
        runner.drop_once.add("review-app-SEC")          # RunResult.failed, no text
        args = self._args(d)
        with mock.patch.object(orchestrate, "_after_first_run",
                               side_effect=lambda rr: self._seed_coverage(rr, floor)), \
             mock.patch("scripts.runners.base.runner_for", return_value=runner), \
             contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            orchestrate.loop(args)
        self.assertFalse(os.path.exists(os.path.join(runner.run_dir, "rejected")))
        row = next(r for r in ledger_mod.Ledger(runner.run_dir).lines() if not r["ok"])
        self.assertIsNone(row["rejected_file"])


class TestTheEntrysShellIsBoundToItsCheckpoint(LoopCase):
    """#1727 second half. `agent` is a registered-shell NAME, and #1720 made
    sure it is one of the four -- but any of the four passed for any
    checkpoint, so a `verify` entry could name `panopticon-domain-panel` and
    get a reviewer's WRITE-granting charter in a round that only adjudicates.
    The loop owns the routing table and refuses a misrouted entry before it
    arms anything."""

    def _misrouted(self, agent):
        real = orchestrate.requests.load_bound_request

        def fake(review_root, namespace=None, expected_sha256=None):
            req, refusal = real(review_root, namespace, expected_sha256)
            for entry in (req or {}).get("entries") or []:
                entry["agent"] = agent
            return req, refusal

        return mock.patch.object(orchestrate.requests, "load_bound_request", fake)

    def test_checkpoint_roles_has_a_row_for_every_checkpoint_kind(self):
        self.assertEqual(sorted(loop_batch.CHECKPOINT_ROLES),
                         sorted(runio.CHECKPOINT_KINDS))

    def test_every_role_named_is_a_dispatch_role(self):
        import scripts.dispatch as dispatch
        for kind, roles in loop_batch.CHECKPOINT_ROLES.items():
            for role in roles:
                self.assertIn(role, dispatch.ROLE_FILES, (kind, role))

    def test_no_role_can_be_added_to_one_side_of_the_routing_tables_only(self):
        # #1886's `OUTPUT_ROLES` and `dispatch.ROLE_FILES` are two halves of
        # ONE statement: the second says which shells exist, the first says
        # which output family may carry each. #1737 registered `setup_scan`
        # in the second and not the first, and every enforced setup entry was
        # refused -- `role_of` resolved to a family with no row, so `expected`
        # came out None and no name could match it. The failure mode is
        # SILENT (an entry that is simply never accepted, on a path that only
        # runs once the shells are emitted), so the two sides are pinned
        # against each other rather than left to the next reader.
        import scripts.dispatch as dispatch
        import scripts.phases.persist as persist
        self.assertEqual(sorted(dispatch.ROLE_FILES),
                         sorted(set(loop_batch.OUTPUT_ROLES.values())))
        # One family per role would be wrong in the other direction too:
        # `verify` has two roles with different charters and one file family
        # each, so a value used twice means two families share a shell.
        self.assertEqual(len(loop_batch.OUTPUT_ROLES),
                         len(set(loop_batch.OUTPUT_ROLES.values())))
        # ...and every KEY is an out_file family `persist.role_of` can really
        # return -- read out of its AST rather than restated here, since a
        # duplicated list is the thing that drifts. A key it never produces is
        # a row nothing reaches; a family it produces with no row fails closed.
        with open(persist.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), "persist.py")
        fn = next(node for node in ast.walk(tree)
                  if isinstance(node, ast.FunctionDef) and node.name == "role_of")
        families = set()
        for node in ast.walk(fn):
            if not isinstance(node, ast.Return):
                continue
            # The returned expression only -- walking the whole Return would
            # also collect the `startswith` argument in its ternary's test.
            returned = ([node.value.body, node.value.orelse]
                        if isinstance(node.value, ast.IfExp) else [node.value])
            families |= {n.value for n in returned
                         if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        self.assertEqual(sorted(loop_batch.OUTPUT_ROLES), sorted(families))

    def test_the_table_matches_the_shells_the_phases_actually_assign(self):
        # Read out of the phase modules rather than trusted: each builder
        # spells its shell as `dispatch.registered_agent_name("<role>.md")`,
        # and the table has to name the role that file maps to. A builder
        # retargeted without this row moving would dispatch a shell the loop
        # then refuses -- or, worse, the row would quietly widen.
        import scripts.dispatch as dispatch
        by_file = {f: role for role, f in dispatch.ROLE_FILES.items()}
        phase_checkpoint = {"coverage.py": "scout", "review.py": "review",
                            "verify.py": "verify", "verify_tools.py": "verify",
                            "setup.py": "scan"}
        phases_dir = os.path.join(os.path.dirname(orchestrate.__file__), "phases")
        seen = {kind: set() for kind in runio.CHECKPOINT_KINDS}
        for name, kind in phase_checkpoint.items():
            with open(os.path.join(phases_dir, name), encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), name)
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "registered_agent_name"
                        and node.args and isinstance(node.args[0], ast.Constant)):
                    seen[kind].add(by_file[node.args[0].value])
        for kind in runio.CHECKPOINT_KINDS:
            self.assertEqual(seen[kind], set(loop_batch.CHECKPOINT_ROLES[kind]), kind)

    def test_an_unhashable_checkpoint_is_a_refusal_not_a_caught_crash(self):
        # `checkpoint` is read off the same target-writable file as `agent`, so
        # it arrives as whatever JSON says -- and `CHECKPOINT_ROLES.get([])`
        # raises `TypeError: unhashable type`. `loop` catches everything, so
        # that became an `error` naming a Python type instead of the routing
        # refusal it is. Reachable only through a forged record plus a planted
        # file; a named refusal either way.
        for checkpoint in ([], {}, ["verify"], {"a": "verify"}, 7, None):
            with self.subTest(checkpoint=checkpoint):
                self.assertEqual((), loop_batch.checkpoint_roles(checkpoint))
                self.assertEqual(
                    ["e"], loop_batch.refuse_misrouted(
                        [{"id": "e", "enforced": True, "agent": "panopticon-advisor"}],
                        checkpoint))
                message = loop_batch.misroute_refusal(["e"], checkpoint)
                self.assertIn("does not dispatch", message)
                self.assertIn("no enforcement shell", message)
                self.assertNotIn("TypeError", message)

    def test_a_misrouted_shell_ends_the_run_before_anything_is_armed(self):
        d, floor = self._repo()
        runner = FakeRunner()
        armed = []
        with self._misrouted("panopticon-domain-advisor"), \
             mock.patch.object(orchestrate.Guards, "arm",
                               side_effect=lambda *a: armed.append(a[-1])), \
             contextlib.redirect_stderr(io.StringIO()):
            status = self._run_loop(d, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("review-app-SEC", status["message"])
        self.assertIn("does not dispatch", status["message"])
        self.assertIn("panopticon-domain-panel", status["message"])
        self.assertEqual([], runner.launched)
        self.assertEqual([], armed)

    def test_an_unenforced_entry_that_names_a_shell_is_misrouted_too(self):
        # The mirror of #1720's `enforced` check: an unenforced entry carries
        # `agent: None` by construction, so a name on one is a claim the run
        # never made.
        d, floor = self._repo()
        runner = FakeRunner("generic")
        with self._misrouted("panopticon-domain-panel"), \
             contextlib.redirect_stderr(io.StringIO()):
            status = self._run_loop(d, floor, runner, "--host", "generic",
                                    "--allow-unenforced")
        self.assertEqual("error", status["status"], status)
        self.assertIn("does not dispatch", status["message"])
        self.assertEqual([], runner.launched)

    def test_the_loop_hands_the_runner_the_checkpoints_roles(self):
        seen = []

        class Recording(FakeRunner):
            def run_entry(self, entry, env):
                seen.append((entry["id"], self.roles))
                return super().run_entry(entry, env)

        d, floor = self._repo()
        with contextlib.redirect_stderr(io.StringIO()):
            status = self._run_loop(d, floor, Recording())
        self.assertEqual("complete", status["status"], status)
        self.assertIn(("review-app-SEC", ("domain_panel",)), seen)
        self.assertIn(("verify-app-SEC-primary", ("advisor", "domain_advisor")), seen)

    def test_verify_shells_are_bound_to_each_entries_output_family(self):
        outputs = (("/run/verdicts/abc123.json", "panopticon-advisor"),
                   ("/run/verdicts/verdicts-app-SEC-primary.json", "panopticon-domain-advisor"))
        for path, expected in outputs:
            for shell in ("panopticon-advisor", "panopticon-domain-advisor"):
                with self.subTest(path=path, shell=shell):
                    entry = {"id": "verify-e", "out_file": path,
                             "enforced": True, "agent": shell}
                    self.assertEqual([] if shell == expected else ["verify-e"],
                                     loop_batch.refuse_misrouted([entry], "verify"))

    def test_unknown_output_role_fails_closed(self):
        entry = {"id": "e", "out_file": "/run/rejected/verdicts-app-SEC.json",
                 "enforced": True, "agent": "panopticon-domain-advisor"}
        self.assertEqual(["e"], loop_batch.refuse_misrouted([entry], "verify"))

    def test_a_role_with_no_registered_shell_is_a_refusal_not_a_key_error(self):
        # `_allowed_shells` skips a role `ROLE_FILES` does not hold; the
        # acceptance side has to agree, or the two disagree exactly where a
        # half-added role lands -- and a KeyError out of `refuse_misrouted` is
        # `loop`'s catch-all reporting a Python type instead of the routing
        # refusal it is (the same shape as the unhashable checkpoint above).
        # The drift guard forbids this pair in production; the code must still
        # fail closed if it ever holds.
        entry = {"id": "setup-scan", "out_file": "/repo/.panopticon/setup-proposal.json",
                 "enforced": True, "agent": "panopticon-setup-scan"}
        with mock.patch.dict(loop_batch.OUTPUT_ROLES, {"setup-scan": "unregistered"}), \
             mock.patch.dict(loop_batch.CHECKPOINT_ROLES, {"scan": ("unregistered",)}):
            self.assertEqual(["setup-scan"], loop_batch.refuse_misrouted([entry], "scan"))
            self.assertIn("no enforcement shell",
                          loop_batch.misroute_refusal(["setup-scan"], "scan", [entry]))

    def test_the_refusal_names_the_shell_the_entry_should_have_carried(self):
        # The operator gets the checkpoint's whole list either way, and on
        # `verify` that list holds both advisor shells -- so it does not say
        # WHICH one this entry's output family was owed. The refusal is the
        # only place that answer surfaces, and reading it off the same
        # `expected_shell` the refusal was made with is what keeps the message
        # from becoming a second opinion.
        entry = {"id": "verify-e", "out_file": "/run/verdicts/abc123.json",
                 "enforced": True, "agent": "panopticon-domain-advisor"}
        self.assertEqual(["verify-e"], loop_batch.refuse_misrouted([entry], "verify"))
        message = loop_batch.misroute_refusal(["verify-e"], "verify", [entry])
        self.assertIn("its output role expects panopticon-advisor;", message)
        self.assertIn("panopticon-domain-advisor", message)   # the checkpoint's list

    def test_the_refusal_says_when_the_output_family_is_owed_no_shell(self):
        # The fail-closed half: a family no rule knows (a retained record) is
        # owed nothing, and claiming it "expects" some shell would name a
        # remedy that is not one.
        entry = {"id": "e", "out_file": "/run/rejected/verdicts-app-SEC.json",
                 "enforced": True, "agent": "panopticon-domain-advisor"}
        message = loop_batch.misroute_refusal(["e"], "verify", [entry])
        self.assertIn("its output role expects no shell this checkpoint dispatches",
                      message)

    def test_the_refusal_claims_nothing_about_an_entry_it_was_not_given(self):
        # `pending` is optional, and the clause is DROPPED rather than guessed
        # when the caller passes none: an "expects ..." sentence derived from
        # no entry is a statement about a request nobody read.
        message = loop_batch.misroute_refusal(["e"], "verify")
        self.assertNotIn("its output role expects", message)
        self.assertIn("does not dispatch", message)

    def test_swapping_advisor_shells_stops_the_loop_before_verify_launches(self):
        root, floor = self._repo()
        runner = FakeRunner()
        real = orchestrate.requests.load_bound_request

        def swap(review_root, namespace=None, expected_sha256=None):
            request, refusal = real(review_root, namespace, expected_sha256)
            if (request or {}).get("checkpoint") == "verify":
                for entry in request["entries"]:
                    entry["agent"] = "panopticon-advisor"
            return request, refusal

        with mock.patch.object(orchestrate.requests, "load_bound_request", swap), \
                contextlib.redirect_stderr(io.StringIO()):
            status = self._run_loop(root, floor, runner)
        self.assertEqual("error", status["status"], status)
        self.assertIn("output role", status["message"])
        self.assertTrue(runner.launched)
        self.assertFalse(any(entry_id.startswith("verify-") for entry_id in runner.launched))


class TestNoDriverReaderTakesTheUnboundRead(unittest.TestCase):
    """#1727 drift guard. `requests.load_dispatch_request` proves NOTHING about
    who wrote the file it parses; `load_bound_request` is the read every driver
    reader takes. Three call sites moved across in this change (the loop's own,
    the re-entry read, `persist.find_entry`) and a fourth followed
    (`readiness._existing_run_row`), so the unbound name now has zero callers
    under `skill/scripts/` -- and the way this control comes undone is somebody
    reaching for the shorter name in a new reader, which no test would notice.

    The function itself stays: it is the documented UNBOUND accessor, used by
    tests and by anything inspecting a request document rather than trusting
    it. Kept honest by this pin rather than by its docstring.

    AST, not grep: a call written across two source lines returns a false zero
    from `git grep` (the `\\b` trap, one shape over).
    """

    SCRIPTS = os.path.dirname(orchestrate.__file__)

    def _modules(self):
        for folder, _dirs, files in os.walk(self.SCRIPTS):
            for name in sorted(files):
                if name.endswith(".py"):
                    yield os.path.join(folder, name)

    def test_nothing_under_skill_scripts_calls_the_unbound_read(self):
        offenders = []
        for path in self._modules():
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), path)
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and ast.unparse(node.func).endswith("load_dispatch_request")):
                    offenders.append("%s:%d" % (os.path.relpath(path, self.SCRIPTS),
                                                node.lineno))
        self.assertEqual(offenders, [],
                         "a driver reader took the UNBOUND dispatch-request read; use "
                         "requests.load_bound_request:\n" + "\n".join(offenders))

    def test_the_bound_reader_does_not_delegate_to_it_either(self):
        # It reads the file as BYTES and hashes them; routing through the
        # unbound reader would hash one read and parse another.
        source = os.path.join(self.SCRIPTS, "phases", "requests.py")
        with open(source, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), source)
        bound = next(n for n in ast.walk(tree)
                     if isinstance(n, ast.FunctionDef) and n.name == "load_bound_request")
        self.assertEqual([], [ast.unparse(n.func) for n in ast.walk(bound)
                              if isinstance(n, ast.Call)
                              and ast.unparse(n.func).endswith("load_dispatch_request")])


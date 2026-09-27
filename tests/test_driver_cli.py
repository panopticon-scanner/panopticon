"""Driver host selection, persistence, and loop CLI tests."""
import contextlib
import dataclasses
import decimal
import glob as _glob
import io
import os
import shutil
import tempfile
import unittest
from unittest import mock

import scripts.phases.runio as runio
import scripts.phases.requests as requests

import scripts.driver as driver
import scripts.run_manifest as run_manifest
from scripts import hosts

from tests.tools.git_repo import make_git_repo


from tests.driver_helpers import start_module_patches

def setUpModule():
    global _run_probes_patch, _readiness_docker_patch
    _run_probes_patch, _readiness_docker_patch = start_module_patches()


def tearDownModule():
    _run_probes_patch.stop()
    _readiness_docker_patch.stop()


class TestHostChoicesComeFromTheRegistry(unittest.TestCase):
    # R3: parser._subparsers._group_actions[0] is unverified; walk parser._actions
    # for the (single) action whose .choices is a dict -- that is the subparsers
    # action -- then read each subcommand's --host action off of it.
    def _host_choices(self):
        """Every subcommand's --host choices, by subcommand name."""
        parser = driver.build_parser()
        found = {}
        for action in parser._actions:
            if not isinstance(getattr(action, "choices", None), dict):
                continue                      # not the subparser action
            for name, sub in action.choices.items():
                for act in sub._actions:
                    if act.dest == "host":
                        found[name] = tuple(sorted(act.choices))
        return found

    def test_run_and_setup_offer_the_same_hosts(self):
        found = self._host_choices()
        self.assertIn("run", found)
        self.assertIn("setup", found)
        self.assertEqual(found["run"], found["setup"],
                         "run and setup must not disagree about hosts")

    def test_they_are_exactly_the_registry_selectable_hosts(self):
        for name, choices in self._host_choices().items():
            with self.subTest(subcommand=name):
                self.assertEqual(tuple(sorted(hosts.driver_hosts())), choices)

    def test_the_helper_actually_found_something(self):
        # Guards the guard: an empty dict would pass the loop above over
        # nothing.
        self.assertGreaterEqual(len(self._host_choices()), 2)

    def test_kimi_and_codex_are_both_selectable_now(self):
        # This was "kimi and codex are still not selectable". Task 4 migrated
        # five call sites from `host == "claude"` to `hosts.declares(host,
        # hosts.TOOL_POLICY_ENFORCED)`; kimi and codex both CLAIM
        # TOOL_POLICY_ENFORCED in the registry, so declares() already returned
        # True for them and only `driver_selectable=False` kept those sites
        # from granting an ENFORCED run on an unverified claim -- the
        # silent-unenforced-run bug this epic (#1344) exists to kill.
        #
        # The interlock lasted until F3 replaced declares() with verified
        # posture checks. F3 is shipped, and the owner authorized each family
        # PR to retire the stale pin alongside its own probes: the Codex family
        # PR for `codex`, the Kimi family PR for `kimi`. Both now ship the
        # probes and the runner that make the claim measured, so the five sites
        # grant neither of them anything unverified. The pin stays, inverted:
        # it fails loudly the day a family's flag is flipped back or a third
        # host is flipped on without that work.
        for name in ("kimi", "codex"):
            with self.subTest(host=name):
                self.assertIn(name, hosts.driver_hosts())
        choices_by_command = self._host_choices()
        self.assertTrue(choices_by_command)
        for command, choices in choices_by_command.items():
            for name in ("kimi", "codex"):
                with self.subTest(command=command, host=name):
                    self.assertIn(name, choices)


class TestARegisteredButUnselectableHostGetsARemedy(unittest.TestCase):
    """#1621: `choices` alone answers a real host name with a list.

    One host is registered-but-unselectable on this tree: gemini, which
    stopped being selectable when its family PR failed the gate. kimi and
    codex were in this set until their own family PRs (#1620, #1619) flipped
    their rows with the probes to back them, which is exactly the exit this
    class describes -- the set is read off the registry, so a row that earns
    selection simply drops out of it. An operator who spells a name still in
    the set has named a host this repo genuinely knows and there IS something
    to do about it, so the parser says what: `--host generic`, the
    permanent fallback path for any host without a family runner. A name
    the registry has never heard of is a typo, and argparse's own
    invalid-choice list is the right answer for it -- so `choices` must still
    be the thing that rejects it.
    """

    def _stderr_of(self, argv):
        err = io.StringIO()
        with self.assertRaises(SystemExit) as caught, \
             contextlib.redirect_stderr(err):
            driver.parse_cli(argv)
        return caught.exception.code, err.getvalue()

    def test_every_unselectable_registered_host_names_the_remedy(self):
        # Read off the registry, not a literal list: a family PR that flips
        # its own row simply drops out of this set -- which is what kimi
        # (#1620) and codex (#1619) did, leaving gemini. gemini is asserted by
        # name so the loop below can never become vacuous; the rest is
        # whatever the registry says today.
        unselectable = [h for h in hosts.known_hosts()
                        if h not in hosts.driver_hosts()]
        self.assertIn("gemini", unselectable)
        for host in unselectable:
            for verb in ("run", "loop", "setup"):
                with self.subTest(host=host, verb=verb):
                    code, err = self._stderr_of([verb, ".", "--host", host])
                    self.assertNotEqual(0, code)
                    self.assertIn(
                        "--host %s is registered but not driver-selectable "
                        "(it proves no enforcement capability); use --host "
                        "generic (session mode, unenforced, ack-gated)" % host,
                        err)

    def test_an_unknown_host_still_gets_the_ordinary_invalid_choice_error(self):
        # The `type=` callable must let an unknown name through so `choices`
        # rejects it: swallowing it here would trade a list of the real
        # answers for a remedy that does not apply.
        code, err = self._stderr_of(["run", ".", "--host", "nosuchhost"])
        self.assertNotEqual(0, code)
        self.assertIn("invalid choice", err)
        self.assertNotIn("registered but not driver-selectable", err)

    def test_a_selectable_host_still_parses(self):
        for host in hosts.driver_hosts():
            for verb in ("run", "loop", "setup"):
                with self.subTest(host=host, verb=verb):
                    self.assertEqual(host,
                                     driver.parse_cli([verb, ".", "--host", host]).host)

    def test_the_helper_decides_from_the_registry_not_a_host_name(self):
        # The remedy must follow the table. Patch a fictional row in as
        # selectable and the helper stops objecting to it; nothing about the
        # decision is spelled against a host's name.
        row = dataclasses.replace(hosts.spec("gemini"), name="ghost")
        with mock.patch.dict(hosts.HOSTS, {"ghost": row}):
            self._stderr_of(["run", ".", "--host", "ghost"])
        with mock.patch.dict(hosts.HOSTS,
                             {"ghost": dataclasses.replace(row, driver_selectable=True)}):
            self.assertEqual("ghost",
                             driver.parse_cli(["run", ".", "--host", "ghost"]).host)


class TestDriverRunRefusesAnUnselectableManifestHost(unittest.TestCase):
    """#1624: the manifest is authoritative on resume, and `driver run` never
    asked whether the host it names is still one the driver may pick.

    `driver loop` has refused this since #1621. `driver run` -- the single-step
    primitive an operator drives by hand to debug a phase -- read
    `manifest.get("host")`, probed it to all-unknown and went on emitting
    dispatch entries for a host `--host` would now refuse to name. The
    selectable set was consulted in `driver.py` only inside the argparse
    `type=`/`choices`, which a resume never reaches: a resume passes no
    `--host` (passing a contradicting one is refused as flag drift), so the
    CLI boundary cannot be where this is caught.

    Keyed on the registry, never on a host name: `gemini` is asserted by name
    only as today's witness that the unselectable set is non-empty, exactly as
    `TestARegisteredButUnselectableHostGetsARemedy` above does.
    """

    def _repo(self):
        return make_git_repo(
            test_case=self,
            files={"src/app.py": "def f():\n    return 1\n"},
            groups_yml="groups:\n  Core:\n    match: ['src/**']\n    panels: [COD]\n",
            branch="main",
            user_email="t@t",
            user_name="t",
        )

    def _mint(self, d):
        """A real run whose manifest names a host the driver still accepts.

        Minting through the CLI rather than hand-writing a manifest is the
        point: the manifest under test has to be one a real run wrote, or
        `_foreign_manifest` discards it before the host is ever read and both
        tests below pass over nothing.

        Minted under `claude` -- which CLAIMS every capability -- so that the
        pair below can tell selectability from claims. The near-miss this
        guards is named in `hosts.is_unenforced_fallback`'s own docstring:
        gemini claims nothing AND is unselectable, so a refusal keyed on the
        claim set passes for exactly the wrong reason. `_untouched` therefore
        resumes as `generic`, the row that claims nothing and IS selectable,
        which a claims-keyed refusal would wrongly stop.
        """
        args = driver.build_parser().parse_args(
            ["run", d, "--no-tools", "--host", "claude"])
        with contextlib.redirect_stderr(io.StringIO()):
            status = driver.run(args)
        self.assertEqual("checkpoint", status["status"], status)
        self.assertEqual("claude", run_manifest.load_manifest(d)["host"])

    def _requests(self, d):
        """Every dispatch request anywhere under this tree's `.panopticon/`.

        Globbed rather than read off `requests.request_path`, which resolves
        the CURRENT manifest's per-run folder (`runs/<tag>/`) -- and `<tag>`
        embeds the host, so rewriting the manifest's host moves the path. A
        single-path assertion would therefore have held vacuously: the file
        the refusal must not write is at a name the pre-rewrite path never
        had. De-duplicated by `realpath` because `runs/latest` is a symlink
        to one of the run folders, so every request matches twice.
        """
        return sorted({os.path.realpath(hit) for hit in
                       _glob.glob(os.path.join(d, ".panopticon", "**",
                                               "dispatch-request.json"),
                                  recursive=True)})

    def _retire_the_requests(self, d):
        """Remove what the MINTING invocation dispatched.

        A resume with nothing serviced re-emits the same checkpoint (see
        `test_resume_reemits_same_checkpoint_before_dispatch`), so an empty
        set afterwards is a statement about THIS invocation rather than a
        leftover from the last one.
        """
        minted = self._requests(d)
        self.assertTrue(minted,
                        "fixture precondition: minting emitted a dispatch request")
        for path in minted:
            os.remove(path)

    def _rewrite_host(self, d, host):
        path = run_manifest.manifest_path(d)
        manifest = runio._load_json(path)
        manifest["host"] = host
        runio._write_json(path, manifest)
        self.assertFalse(runio._foreign_manifest(manifest, d, path),
                         "fixture precondition: this manifest is the run's own")

    def _resume(self, d):
        # No `--host`: the resume `driver run` is documented for, and the only
        # shape in which the manifest gets to choose the host.
        args = driver.build_parser().parse_args(["run", d, "--no-tools"])
        with contextlib.redirect_stderr(io.StringIO()):
            return driver.run(args)

    def test_a_resume_whose_manifest_host_is_no_longer_selectable_is_an_error(self):
        d = self._repo()
        self._mint(d)
        unselectable = [h for h in hosts.known_hosts()
                        if h not in hosts.driver_hosts()]
        self.assertIn("gemini", unselectable,
                      "guards the guard: the unselectable set must be non-empty")
        self._retire_the_requests(d)
        self._rewrite_host(d, "gemini")
        status = self._resume(d)
        self.assertEqual("error", status["status"], status)
        self.assertIn("gemini", status["message"])
        self.assertIn("--host generic --reset", status["message"])
        self.assertEqual([], self._requests(d),
                         "nothing may be dispatched for it")

    def test_a_resume_whose_manifest_host_is_still_selectable_is_untouched(self):
        # The other half, and it runs the SAME manipulation -- only the name
        # differs -- or it is not a guard: a refusal that fired for every
        # manifest-resolved host would leave the test above green.
        d = self._repo()
        self._mint(d)
        self.assertIn("generic", hosts.driver_hosts())
        self.assertFalse(hosts.spec("generic").claims,
                         "fixture precondition: generic claims nothing and is "
                         "selectable anyway -- claims are not selectability")
        self._retire_the_requests(d)
        self._rewrite_host(d, "generic")
        status = self._resume(d)
        self.assertNotEqual("error", status["status"], status)
        self.assertEqual("checkpoint", status["status"], status)
        self.assertTrue(self._requests(d),
                        "a still-selectable host's resume dispatches as before")

    def test_a_resume_whose_manifest_host_has_no_registry_row_never_dispatches_for_it(self):
        # #1624 fix round 1. The refusal above reads `host in known_hosts()
        # and host not in driver_hosts()`, and the `known_hosts()` half is
        # what keeps a name with NO ROW out of it -- such a name was never
        # retired, so "registered but no longer driver-selectable" would be
        # false and `--host generic` would not be its remedy.
        #
        # Dropping that half to catch it anyway would be dead code, and this
        # test is the proof. `run_manifest.load_manifest` -- which
        # `driver.run` calls before `_establish_host_posture` ever sees a host
        # -- discards a manifest naming a host the registry does not know:
        # UNUSABLE, exactly like a corrupt one, announced on stderr (#1344).
        # `driver.run` then clears the derived artifacts and rebuilds from the
        # real CLI args, so the run resumes under a SELECTABLE host and the
        # unknown name reaches no probe and no dispatch entry.
        #
        # Pinned at the entrypoint because the unit test
        # (test_run_manifest.py::test_a_stored_manifest_with_an_unknown_host_
        # is_discarded_not_trusted) covers `load_manifest` and this covers the
        # consequence: delete that branch and the name flows straight into the
        # posture probes and the run tag.
        d = self._repo()
        self._mint(d)
        self.assertNotIn("nosuchhost", hosts.known_hosts(),
                         "fixture precondition: the registry has no such row")
        self._retire_the_requests(d)
        self._rewrite_host(d, "nosuchhost")
        args = driver.build_parser().parse_args(["run", d, "--no-tools"])
        with contextlib.redirect_stderr(io.StringIO()) as err:
            status = driver.run(args)
        self.assertIn("discarding run-manifest.json", err.getvalue())
        self.assertIn("nosuchhost", err.getvalue())
        # Rebuilt from the CLI args, under a host the driver may actually pick.
        self.assertIn(run_manifest.load_manifest(d)["host"], hosts.driver_hosts())
        # It is not told the retired-host story, which does not apply to it.
        self.assertNotIn("no longer driver-selectable", status.get("message") or "")
        # Whatever the rebuilt run dispatches, none of it is filed under the
        # unknown name -- the run tag embeds the host, so a request under a
        # `nosuchhost-*` folder is exactly what "dispatched for it" looks like.
        self.assertTrue(self._requests(d), "guards the guard: it did dispatch")
        self.assertEqual([], [r for r in self._requests(d) if "nosuchhost" in r])


class TestAllowUnenforcedHelpNamesTheCapability(unittest.TestCase):
    """`--help` is a contract too, and this one encoded the pre-F1 "claude is
    special" model #1344 retired.

    The refusal `--allow-unenforced` overrides is keyed on the MEASURED
    `artifact_write_guard` posture for THIS invocation (phases.requests.
    require_unenforced_ack), not on the host's name: a claude run on a machine
    where the probe refutes -- no settings file at the path the host would arm
    -- is refused on identical terms. "unmediated on a non-claude host" is a
    sentence the code stopped implementing at F3a.

    The parser walk follows TestHostChoicesComeFromTheRegistry's: find the one
    action whose `.choices` is a dict (the subparsers action) rather than
    reaching into `_subparsers._group_actions[0]`.
    """

    def _flag_help(self):
        for action in driver.build_parser()._actions:
            if not isinstance(getattr(action, "choices", None), dict):
                continue                      # not the subparser action
            for act in action.choices["run"]._actions:
                if "--allow-unenforced" in (act.option_strings or ()):
                    return act.help
        self.fail("--allow-unenforced is no longer a `driver run` flag")

    def test_it_names_the_capability_rather_than_a_host(self):
        text = self._flag_help()
        self.assertIn(hosts.ARTIFACT_WRITE_GUARD, text)
        # Catches "non-claude" and any other host-specific rewording. The
        # capability is the whole point: it is what the refusal reads.
        self.assertNotIn("claude", text)

    def test_it_still_says_where_the_acceptance_is_recorded(self):
        # The half of the old string that was true. An operator who passes this
        # flag needs to know something durable records it.
        self.assertIn("unenforced-ack.json", self._flag_help())

    def test_the_string_reaches_driver_run_help(self):
        # Proves the two tests above are asserting on text an operator can
        # actually read, not on a dead attribute.
        buf = io.StringIO()
        # Pin the width: argparse wraps help through textwrap, which splits
        # long words by default, and the capability name is one long word. On
        # a narrow terminal an unpinned assertion would fail on formatting
        # rather than on content. (The old string wrapped as "non-\nclaude".)
        with mock.patch.dict(os.environ, {"COLUMNS": "100"}), \
                contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
            driver.build_parser().parse_args(["run", "--help"])
        rendered = buf.getvalue()
        self.assertIn("--allow-unenforced", rendered)
        self.assertIn(hosts.ARTIFACT_WRITE_GUARD, rendered)


class TestDriverPersistCLI(unittest.TestCase):
    def _repo(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, ".panopticon", "runs", "t"))
        # #1727: `driver persist` reads the dispatch request out of the
        # reviewed tree and now checks it against the hash the run recorded,
        # so the fixture needs the run this request belongs to.
        driver.run_manifest.write_manifest(d, {
            "schema_version": 1, "run_id": "0123456789abcdef", "host": "claude",
            "security_mode": "standard", "created": "2026-09-20T00:00:00Z",
            "review_root": d, "target": d})
        return d

    def _request(self, d, entries):
        # Through the REAL writer: a hand-written file is exactly what the
        # verb refuses now, and a fixture that forges one proves nothing.
        return requests.write_dispatch_request(d, "RID", "scout", None, entries)

    def test_persist_writes_the_named_entry_from_a_file(self):
        d = self._repo()
        out = os.path.join(d, ".panopticon", "runs", "t", "scout-app.json")
        self._request(d, [{"id": "scout-app", "out_file": out, "delivery": "return_json"}])
        reply = os.path.join(d, "reply.txt")
        with open(reply, "w", encoding="utf-8") as fh:
            fh.write('```json\n{"domains": [], "files": [], "tools": []}\n```')
        rc = driver.main(["persist", "scout-app", "--file", reply, d])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.isfile(out))

    def test_persist_accepts_the_target_after_the_options_on_every_python(self):
        # CI (Python 3.11): argparse < 3.12 binds the optional `target`
        # positional when it first sees `entry_id`, so a target given AFTER
        # `--file`/`--pr` -- the documented `driver persist ENTRY_ID [--file
        # PATH] ... [target]` order -- came back "unrecognized arguments".
        # `driver.parse_cli` folds one trailing bare word into `target` on
        # the persist verb only, so both orders parse on 3.11 and 3.14 alike.
        a = driver.parse_cli(["persist", "scout-app", "--file", "/dev/null", "/tmp/t"])
        self.assertEqual((a.verb, a.entry_id, a.file, a.target),
                         ("persist", "scout-app", "/dev/null", "/tmp/t"))
        b = driver.parse_cli(["persist", "scout-app", "/tmp/t", "--file", "/dev/null"])
        self.assertEqual(b.target, "/tmp/t")
        c = driver.parse_cli(["persist", "scout-app", "--pr", "42", "--base", "origin/main", "/tmp/t"])
        self.assertEqual((c.pr, c.base, c.target), (42, "origin/main", "/tmp/t"))
        # a second bare word is still an error, and so is any leftover on
        # another verb -- the fold is persist-only and one word wide
        with self.assertRaises(SystemExit):
            driver.parse_cli(["persist", "scout-app", "/tmp/t", "/tmp/u"])
        with self.assertRaises(SystemExit):
            driver.parse_cli(["run", ".", "--host", "claude", "extra"])

    def test_persist_reaches_a_pr_runs_review_root(self):
        # I6 (plan 6 final review): a `--pr` run's review root is the PR
        # WORKTREE, not the operator's checkout -- `driver run` resolves it
        # with base/pr and pins it in the manifest. `driver persist` resolved
        # `args.target` alone, so on a `--pr` run it looked for the dispatch
        # request in the wrong tree and refused every entry with "no entry in
        # the current dispatch request". The persist verb had no way to say
        # which run it meant.
        parser_args = driver.parse_cli(
            ["persist", "scout-app", "--pr", "42", "--base", "origin/main", "."])
        self.assertEqual((parser_args.pr, parser_args.base), (42, "origin/main"))
        d = self._repo()
        self._request(d, [])
        with mock.patch("scripts.phases.runio.resolve_review_root",
                        return_value=(d, None, None)) as rr, \
             contextlib.redirect_stderr(io.StringIO()):
            driver.main(["persist", "scout-app", "--pr", "42", "--base", "origin/main", d])
        self.assertEqual(rr.call_args.args, (d,))
        self.assertEqual(rr.call_args.kwargs, {"base": "origin/main", "pr": 42})

    def test_persist_refuses_a_request_that_does_not_match_its_record(self):
        # #1727: `driver persist` is a SEPARATE process reading a file in the
        # reviewed tree, and it writes whatever that file's entry names as
        # `out_file`. A tampered request must not reach that write.
        d = self._repo()
        out = os.path.join(d, ".panopticon", "runs", "t", "scout-app.json")
        path = self._request(d, [{"id": "scout-app", "out_file": out,
                                  "delivery": "return_json", "prompt": "p"}])
        with open(path, "ab") as fh:
            fh.write(b" ")
        reply = os.path.join(d, "reply.txt")
        with open(reply, "w", encoding="utf-8") as fh:
            fh.write('```json\n{"domains": [], "files": [], "tools": []}\n```')
        with contextlib.redirect_stderr(io.StringIO()) as err:
            rc = driver.main(["persist", "scout-app", "--file", reply, d])
        self.assertEqual(rc, 1)
        self.assertIn("driver persist: dispatch-request.json does not match the "
                      "request this run wrote", err.getvalue())
        self.assertFalse(os.path.exists(out))      # nothing written

    def test_persist_still_names_the_unknown_entry_when_the_request_is_sound(self):
        # The two refusals stay distinct: "this file is not ours" is not the
        # same answer as "this id is not in it", and an operator chasing a
        # typo must not be told the request was tampered with.
        d = self._repo()
        self._request(d, [{"id": "scout-app", "out_file": "/tmp/x.json",
                           "delivery": "return_json", "prompt": "p"}])
        with contextlib.redirect_stderr(io.StringIO()) as err:
            rc = driver.main(["persist", "scout-other", "--file", os.devnull, d])
        self.assertEqual(rc, 1)
        self.assertIn("no entry 'scout-other' in the current dispatch request",
                      err.getvalue())
        self.assertNotIn("does not match", err.getvalue())

    def test_persist_refuses_an_unknown_entry_with_exit_1(self):
        d = self._repo()
        self._request(d, [])
        with contextlib.redirect_stderr(io.StringIO()) as err:
            rc = driver.main(["persist", "scout-app", "--file", os.devnull, d])
        self.assertEqual(rc, 1)
        self.assertIn("scout-app", err.getvalue())


class TestDriverLoopCLI(unittest.TestCase):
    def test_policy_options_match_synthesizer_for_run_and_loop(self):
        accepted = {"--fail-on": ("critical", "high", "medium", "low"),
                    "--severity": ("all", "medium", "high", "critical"),
                    "--gate-scope": ("on-diff", "all")}
        for verb in ("run", "loop"):
            omitted = driver.build_parser().parse_args([verb, "x"])
            self.assertEqual((omitted.fail_on, omitted.severity, omitted.gate_scope),
                             (None, None, None))
            for flag, values in accepted.items():
                attr = flag[2:].replace("-", "_")
                for value in values:
                    with self.subTest(verb=verb, flag=flag, value=value):
                        supplied = value if flag == "--gate-scope" else value.upper()
                        parsed = driver.build_parser().parse_args([verb, "x", flag, supplied])
                        self.assertEqual(getattr(parsed, attr), value)
                invalid = "ALL" if flag == "--gate-scope" else "invalid"
                with self.subTest(verb=verb, flag=flag, value=invalid):
                    with self.assertRaises(SystemExit) as caught, \
                         contextlib.redirect_stderr(io.StringIO()):
                        driver.main([verb, "x", flag, invalid])
                    self.assertEqual(caught.exception.code, 2)

    def test_invalid_policy_option_stops_before_any_startup_work(self):
        for verb in ("run", "loop"):
            with self.subTest(verb=verb), \
                 mock.patch.object(runio, "resolve_review_root") as resolve, \
                 mock.patch("scripts.orchestrate.main_verb") as loop, \
                 mock.patch("scripts.host_probes.run_probes") as probes, \
                 contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    driver.main([verb, "x", "--severity", "bogus"])
                resolve.assert_not_called()
                loop.assert_not_called()
                probes.assert_not_called()

    def test_malformed_model_env_stops_run_and_loop_before_startup_work(self):
        key = "PANOPTICON_MODEL_DOMAIN_PANEL"
        with mock.patch.dict(os.environ, {key: '{"model": "secret-sentinel",}'},
                             clear=False):
            for verb in ("run", "loop"):
                with self.subTest(verb=verb), \
                     mock.patch.object(runio, "resolve_review_root") as resolve, \
                     mock.patch("scripts.orchestrate.main_verb") as loop, \
                     mock.patch("scripts.host_probes.run_probes") as probes, \
                     contextlib.redirect_stdout(io.StringIO()) as out:
                    rc = driver.main([verb, "x"])
                    self.assertEqual(rc, 1)
                    self.assertIn(key, out.getvalue())
                    self.assertNotIn("secret-sentinel", out.getvalue())
                    resolve.assert_not_called()
                    loop.assert_not_called()
                    probes.assert_not_called()

    def test_loop_accepts_every_run_flag_plus_its_own(self):
        args = driver.build_parser().parse_args(
            ["loop", "x", "--host", "claude", "--security", "redteam", "--no-tools", "-g", "Auth",
             "--mode", "session", "--concurrency", "4", "--max-iterations", "7",
             "--max-budget-usd", "2.5", "--max-turns", "30", "--entry-timeout", "600"])
        self.assertEqual(args.verb, "loop")
        self.assertEqual((args.mode, args.concurrency, args.max_iterations, args.max_budget_usd,
                          args.max_turns, args.entry_timeout, args.scope_group),
                         ("session", 4, 7, 2.5, 30, 600, "Auth"))
        # I8: no literal default -- the parser leaves `--mode` unset and
        # `orchestrate.loop` resolves it from the host (headless where a
        # runner exists, session where none does). A "headless" default here
        # is what made `driver loop --host generic` an error instead of the
        # documented degrade to session mode.
        self.assertIsNone(driver.build_parser().parse_args(["loop", "x"]).mode)

    def test_max_budget_usd_refuses_a_non_finite_or_negative_amount(self):
        # #1648: `type=float` accepted `nan`, `inf` and `-1`. A NaN budget made
        # every `spent >= budget` comparison False -- the gate was off and said
        # nothing -- and a negative one stopped the run before it began.
        for text in ("nan", "NaN", "inf", "-inf", "Infinity", "-1", "-0.01", "abc"):
            with self.subTest(text=text), self.assertRaises(SystemExit), \
                 contextlib.redirect_stderr(io.StringIO()):
                driver.build_parser().parse_args(["loop", "x", "--max-budget-usd", text])

    def test_max_budget_usd_is_parsed_once_as_an_exact_decimal(self):
        args = driver.build_parser().parse_args(["loop", "x", "--max-budget-usd", "0.1"])
        self.assertEqual(decimal.Decimal("0.1"), args.max_budget_usd)
        # ...exactly, which is the whole point: eight of these reach $0.80 and
        # eight floats do not (0.7999999999999999).
        self.assertEqual(decimal.Decimal("0.8"), args.max_budget_usd * 8)

    def test_no_loop_only_flag_is_an_anti_drift_key(self):
        # M15 (plan 6 final review): spec 4.3/5.4 -- the loop's own knobs say
        # HOW this invocation runs entries, not WHAT the run is, so a resume
        # must be free to change concurrency, the budget or the timeouts
        # without `conflicting_flags` refusing it as drift. Nothing enforced
        # that; a later flag added to `_cli_flags` by habit would have wedged
        # every resume that spelled it differently.
        loop_only = ("mode", "concurrency", "max_iterations", "max_budget_usd",
                     "max_turns", "entry_timeout", "setup", "max_groups")
        overlap = sorted(set(loop_only) & set(driver.run_manifest._FLAG_KEYS))
        self.assertEqual(overlap, [])
        # and they really are loop-only: `driver run` does not take them
        run_args = driver.build_parser().parse_args(["run", "x"])
        for flag in loop_only:
            with self.subTest(flag=flag):
                self.assertFalse(hasattr(run_args, flag), flag)

    def test_loop_modes_match_the_runner_seam(self):
        import scripts.runners.base as runners_base
        self.assertEqual(tuple(driver.hosts_runner_modes()), runners_base.MODES)

    def test_run_has_no_mode_flag(self):
        with self.assertRaises(SystemExit):
            driver.build_parser().parse_args(["run", "x", "--mode", "session"])
        self.assertFalse(hasattr(driver.build_parser().parse_args(["run", "x"]), "mode"))

    def test_loop_verb_dispatches_into_orchestrate(self):
        with mock.patch("scripts.orchestrate.loop", return_value={"status": "complete"}) as lp, \
             contextlib.redirect_stdout(io.StringIO()):
            rc = driver.main(["loop", "x"])
        self.assertEqual(rc, 0)
        self.assertEqual(lp.call_args.args[0].verb, "loop")


"""#1344 F1: one table that knows what a host is.

The registry is data. Its tests are therefore about TOTALITY and about
matching today's behavior exactly -- not about any host doing anything.
"""
import ast
import unittest

import scripts.driver as driver
import scripts.orchestrate as orchestrate
from scripts import host_disclosure, host_probes, hosts


class TestTotality(unittest.TestCase):
    def test_the_table_is_not_empty(self):
        # Guards the guard: every assertion below iterates HOSTS, so an empty
        # table would let all of them pass over nothing.
        self.assertGreaterEqual(len(hosts.HOSTS), 5)

    def test_every_row_is_a_hostspec_keyed_by_its_own_name(self):
        for name, row in hosts.HOSTS.items():
            with self.subTest(host=name):
                self.assertIsInstance(row, hosts.HostSpec)
                self.assertEqual(name, row.name)

    def test_every_claim_is_a_real_capability(self):
        for name, row in hosts.HOSTS.items():
            with self.subTest(host=name):
                unknown = sorted(set(row.claims) - set(hosts.CAPABILITIES))
                self.assertEqual([], unknown,
                                 "%s claims capabilities that do not exist: %s"
                                 % (name, unknown))

    def test_a_host_that_registers_shells_says_where_and_in_what_format(self):
        for name, row in hosts.HOSTS.items():
            with self.subTest(host=name):
                self.assertEqual(bool(row.registration_dir),
                                 bool(row.shell_format),
                                 "%s must declare both a registration dir and a "
                                 "shell format, or neither" % name)


class TestQueries(unittest.TestCase):
    def test_spec_returns_none_for_an_unknown_host(self):
        self.assertIsNone(hosts.spec("no-such-host"))

    def test_declares_is_false_for_an_unknown_host(self):
        self.assertFalse(
            hosts.declares("no-such-host", hosts.TOOL_POLICY_ENFORCED))

    def test_declares_is_false_for_an_unknown_capability(self):
        self.assertFalse(hosts.declares("claude", "teleportation"))

    def test_driver_hosts_is_a_subset_of_known_hosts(self):
        self.assertTrue(set(hosts.driver_hosts()) <= set(hosts.known_hosts()))

    def test_only_generic_is_deprecated(self):
        # D4. gemini also claims nothing, and after #1621 is not selectable
        # either -- but it is still not the deprecated FALLBACK, which is a
        # distinct role: `is_deprecated` gates the run-time NOTICE, and a
        # predicate broadened to "claims nothing" (or to "not selectable")
        # would print that notice for rows it does not describe.
        self.assertTrue(hosts.is_deprecated("generic"))
        for host in hosts.known_hosts():
            if host != "generic":
                with self.subTest(host=host):
                    self.assertFalse(hosts.is_deprecated(host))
        self.assertFalse(hosts.is_deprecated("no-such-host"))


class TestDriverHostCapabilities(unittest.TestCase):
    """Pin the supported hosts and the capabilities their family PRs earned.

    The owner authorized retiring the F1/F2-only expectations as each
    first-class-host family PR landed -- Codex in #1619, Kimi in #1620; a
    family that has not landed yet keeps its claims and selection unchanged.
    """

    def test_the_driver_accepts_exactly_the_hosts_it_accepts_today(self):
        # codex and kimi joined the selectable set in their own family PRs
        # (#1619, #1620), each shipping its probes and runner in the same PR.
        # gemini went the other way: #1621 retired it (2026-09-13) because its
        # family PR failed the gate twice, so the row stays REGISTERED --
        # known_hosts() lists it, spec() resolves it, it still claims nothing
        # -- and only `driver_selectable` flipped. A Gemini operator runs
        # `--host generic`.
        self.assertEqual(("claude", "codex", "generic", "kimi"),
                         tuple(sorted(hosts.driver_hosts())))
        self.assertIn("gemini", hosts.known_hosts())
        self.assertIsNotNone(hosts.spec("gemini"))
        self.assertEqual(frozenset(), hosts.spec("gemini").claims)

    def test_claude_codex_and_kimi_declare_tool_policy_enforcement(self):
        # F3 routes enforcement through proven posture, not a bare claim;
        # Codex and Kimi each now supply their own tool-surface probe.
        enforcing = [h for h in hosts.driver_hosts()
                     if hosts.declares(h, hosts.TOOL_POLICY_ENFORCED)]
        # codex declares it since its family PR proved the effective V8 tool
        # surface (codex-effective-tools); kimi since its family PR proved the
        # shells on the effective surface (kimi-shell-surface).
        self.assertEqual(["claude", "codex", "kimi"], enforcing)

    def test_claude_and_kimi_declare_a_usage_ledger_among_driver_hosts(self):
        # phases/synthesize.py:35 -- `if manifest.get("host") != "claude"`.
        ledgered = [h for h in hosts.driver_hosts()
                    if hosts.declares(h, hosts.USAGE_LEDGER)]
        # kimi's ledger is the per-child wire file (kimi-usage-wire probe).
        self.assertEqual(["claude", "kimi"], ledgered)

    def test_kimi_and_codex_are_registrable_and_now_driver_selectable(self):
        # This was "registrable but not driver-selectable": dispatch.py could
        # emit their shells while driver.py's --host refused to pick them, and
        # preserving that split is what kept F2 behavior-free. Each family PR
        # then earned the flip with the probes to back it -- Codex in #1619,
        # Kimi in #1620 -- so the split is closed on both rows and this pin
        # records the state it closed into rather than the state before.
        for name in ("kimi", "codex"):
            with self.subTest(host=name):
                self.assertTrue(hosts.spec(name).registration_dir)
                self.assertIn(name, hosts.driver_hosts())

    def test_claude_codex_and_kimi_claim_read_scope_confinement(self):
        # Spec §7.2 / plan 5: claude ships the read guard; every other host's
        # family PR must bring its own primitive before claiming this. The
        # kimi family PR (#1344) brought the per-run-home hook and its probe.
        claiming = [h for h in hosts.known_hosts()
                    if hosts.declares(h, hosts.READ_SCOPE_CONFINED)]
        self.assertEqual(["claude", "codex", "kimi"], claiming)

    def test_codex_is_selectable_with_exactly_its_probed_security_claims(self):
        row = hosts.spec("codex")
        expected = {
            hosts.TOOL_POLICY_ENFORCED: "codex-effective-tools",
            hosts.READ_SCOPE_CONFINED: "codex-read-scope",
        }
        self.assertTrue(row.registration_dir)
        self.assertTrue(row.driver_selectable)
        self.assertIn("codex", hosts.driver_hosts())
        self.assertEqual(frozenset(expected), row.claims)
        self.assertEqual(expected, row.probes)
        for capability, probe_id in expected.items():
            with self.subTest(capability=capability):
                self.assertIn(probe_id, host_probes.PROBE_IDS)
                self.assertEqual(capability, host_probes.PROBE_CAPABILITY[probe_id])


class TestPostureFailsClosed(unittest.TestCase):
    """Defined in F1, consumed in F3. The rules are testable now and the
    fail-closed one is the whole design, so it is pinned before anything
    depends on it."""

    def test_no_evidence_means_every_capability_is_unknown(self):
        result = hosts.posture("claude", None)
        self.assertEqual(sorted(hosts.CAPABILITIES), sorted(result))
        self.assertEqual({hosts.UNKNOWN}, set(result.values()))

    def test_empty_evidence_is_the_same_as_none(self):
        self.assertEqual(hosts.posture("claude", None),
                         hosts.posture("claude", {}))

    def test_a_claim_without_evidence_is_never_proven(self):
        # The test that would have caught setup_flow's hardcoded
        # ("enforced-shells", True) for codex.
        self.assertIn(hosts.TOOL_POLICY_ENFORCED,
                      hosts.spec("claude").claims)
        self.assertEqual(hosts.UNKNOWN,
                         hosts.posture("claude", {})[hosts.TOOL_POLICY_ENFORCED])

    def test_evidence_is_read_for_capabilities_the_host_claims(self):
        evidence = {hosts.TOOL_POLICY_ENFORCED: {"state": hosts.PROVEN}}
        self.assertEqual(hosts.PROVEN,
                         hosts.posture("claude", evidence)[hosts.TOOL_POLICY_ENFORCED])

    def test_proven_evidence_for_an_unclaimed_capability_is_refused(self):
        # gemini claims nothing. Evidence asserting otherwise must not be
        # honoured -- the artifact is written by us, but a stale one from a
        # different host's run must not grant a capability.
        evidence = {hosts.TOOL_POLICY_ENFORCED: {"state": hosts.PROVEN}}
        self.assertEqual(hosts.UNKNOWN,
                         hosts.posture("gemini", evidence)[hosts.TOOL_POLICY_ENFORCED])

    def test_refuted_evidence_survives_the_unclaimed_mask(self):
        # I5. The mask above is written for the GRANTING direction, but it was
        # applied symmetrically and so threw refutations away too. §7.3 makes
        # `refuted` the STRONGER answer, and a refutation grants nothing, so
        # letting it through is strictly non-permissive. Latent only because
        # every selectable host had empty project_scope_dirs. It went LIVE
        # when the family PRs flipped codex (#1619) and kimi (#1620), which
        # carry scope dirs of their own; gemini and generic, the two rows
        # below, still claim nothing -- and F5's entry-criterion test reads
        # posture(), so a genuinely refuted host would read `unknown` and
        # fail the bar for the wrong stated reason.
        evidence = {hosts.TOOL_POLICY_ENFORCED: {"state": hosts.REFUTED}}
        for host in ("gemini", "generic"):
            with self.subTest(host=host):
                self.assertFalse(hosts.declares(host, hosts.TOOL_POLICY_ENFORCED))
                self.assertEqual(
                    hosts.REFUTED,
                    hosts.posture(host, evidence)[hosts.TOOL_POLICY_ENFORCED])

    def test_refuted_survives_the_mask_for_a_host_the_registry_never_heard_of(self):
        # The `not row` half of the same condition -- a different branch, and
        # the one a stale artifact from a retired host name lands on.
        evidence = {hosts.TOOL_POLICY_ENFORCED: {"state": hosts.REFUTED}}
        self.assertIsNone(hosts.spec("no-such-host"))
        self.assertEqual(
            hosts.REFUTED,
            hosts.posture("no-such-host", evidence)[hosts.TOOL_POLICY_ENFORCED])

    def test_an_unrecognised_state_is_unknown_not_trusted(self):
        evidence = {hosts.TOOL_POLICY_ENFORCED: {"state": "probably-fine"}}
        self.assertEqual(hosts.UNKNOWN,
                         hosts.posture("claude", evidence)[hosts.TOOL_POLICY_ENFORCED])

    def test_unproven_lists_everything_not_proven(self):
        posture = hosts.posture("claude", {
            hosts.TOOL_POLICY_ENFORCED: {"state": hosts.PROVEN},
            hosts.USAGE_LEDGER: {"state": hosts.REFUTED}})
        self.assertNotIn(hosts.TOOL_POLICY_ENFORCED, hosts.unproven(posture))
        self.assertIn(hosts.USAGE_LEDGER, hosts.unproven(posture))
        self.assertIn(hosts.READ_SCOPE_CONFINED, hosts.unproven(posture))

    def test_unproven_is_sorted_so_messages_are_stable(self):
        posture = hosts.posture("gemini", None)
        self.assertEqual(sorted(hosts.unproven(posture)),
                         hosts.unproven(posture))

    def test_a_malformed_per_capability_entry_is_unknown_not_a_crash(self):
        # F3 feeds this from runs/<tag>/host-capabilities.json -- a file on
        # disk, i.e. untrusted input. A truncated or tampered artifact whose
        # entry is not a dict must resolve to UNKNOWN. Crashing the run is not
        # failing closed; it is failing.
        for bad in ("a string", ["a", "list"], 7, None, True):
            with self.subTest(entry=bad):
                result = hosts.posture(
                    "claude", {hosts.TOOL_POLICY_ENFORCED: bad})
                self.assertEqual({hosts.UNKNOWN}, set(result.values()))

    def test_an_entry_dict_without_a_state_key_is_unknown(self):
        self.assertEqual(
            hosts.UNKNOWN,
            hosts.posture("claude", {hosts.TOOL_POLICY_ENFORCED: {}})[
                hosts.TOOL_POLICY_ENFORCED])

    def test_a_non_dict_evidence_container_is_unknown_not_a_crash(self):
        for bad in ("not-a-dict", ["a", "list"], 7, True, object()):
            with self.subTest(evidence=bad):
                result = hosts.posture("claude", bad)
                self.assertEqual(sorted(hosts.CAPABILITIES), sorted(result))
                self.assertEqual({hosts.UNKNOWN}, set(result.values()))


class TestTheModuleStaysPure(unittest.TestCase):
    """hosts.py is imported by phases/*; host_disclosure.py formats hosts.py's
    output for four rendering surfaces (#1344 F3b spec 5.1). Both must stay
    cheap and I/O-free, for the same reason and by the same argument -- so
    this parameterises over both modules rather than forking a second,
    copy-pasted class. A copy invites exactly the drift this repo keeps
    finding: nothing stops a second class from silently going stale the first
    time one of the two source files changes shape and nobody remembers to
    update the twin.

    AST-based, deliberately. The first draft of this guard was a substring
    search, and it failed on the module it was guarding: hosts.py's own
    docstring explains why `subprocess` belongs in host_probes.py, so
    `assertNotIn("subprocess", source)` fired on the prose. This repo has now
    made that mistake three times (#1557's grep guard flagged its own
    docstring; the strict-skip marker matched a comment). Read tokens, never
    text.
    """

    _FORBIDDEN_MODULES = {"subprocess", "shutil", "socket", "urllib", "json"}
    _FORBIDDEN_CALLS = {"open", "listdir", "isfile", "isdir", "exists",
                        "makedirs", "walk", "run", "popen"}
    # (module, an import name it must contain, a call name it must contain)
    # -- guards the guard PER module: an analyser returning empty sets would
    # pass every assertion below over nothing, and that failure is invisible
    # unless each module supplies its own known-present sentinel.
    _TARGETS = ((hosts, "os", "expanduser"),
               (host_disclosure, "hosts", "get"))

    def _tree(self, module):
        with open(module.__file__, encoding="utf-8") as fh:
            return ast.parse(fh.read())

    def _imported(self, module):
        names = set()
        for node in ast.walk(self._tree(module)):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module.split(".")[0])
        return names

    def _called(self, module):
        names = set()
        for node in ast.walk(self._tree(module)):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            names.add(fn.attr if isinstance(fn, ast.Attribute)
                      else getattr(fn, "id", ""))
        return names

    def test_it_imports_no_io_module(self):
        for module, _, _ in self._TARGETS:
            with self.subTest(module=module.__name__):
                offenders = sorted(self._imported(module) & self._FORBIDDEN_MODULES)
                self.assertEqual([], offenders,
                                 "%s must stay pure data; %s belongs in "
                                 "host_probes.py (F3)"
                                 % (module.__name__, ", ".join(offenders)))

    def test_it_calls_no_io_function(self):
        for module, _, _ in self._TARGETS:
            with self.subTest(module=module.__name__):
                offenders = sorted(self._called(module) & self._FORBIDDEN_CALLS)
                self.assertEqual([], offenders,
                                 "%s must stay pure data; %s belongs in "
                                 "host_probes.py (F3)"
                                 % (module.__name__, ", ".join(offenders)))

    def test_the_analyser_actually_sees_the_module(self):
        # Guards the guard: an analyser returning empty sets would pass both
        # assertions above over nothing.
        for module, import_sentinel, call_sentinel in self._TARGETS:
            with self.subTest(module=module.__name__):
                self.assertIn(import_sentinel, self._imported(module))
                self.assertIn(call_sentinel, self._called(module))


class TestTheRegistryNamesItsProbes(unittest.TestCase):
    """#1344 F3a: a capability a host claims must say how it would be proved."""

    def test_claude_names_a_probe_for_every_security_capability_it_claims(self):
        row = hosts.spec("claude")
        # Assert the exact probes map, not just existence and truthiness.
        # This catches typos and swapped probe IDs.
        self.assertEqual(
            {hosts.TOOL_POLICY_ENFORCED: "registered-shell-tools",
             hosts.ARTIFACT_WRITE_GUARD: "write-guard-armed",
             hosts.MODEL_BINDING: "entry-model-bound",
             hosts.USAGE_LEDGER: "usage-source",
             hosts.READ_SCOPE_CONFINED: "read-guard-armed"},
            row.probes)

    def test_probe_ids_are_strings_not_callables(self):
        # hosts.py must never import host_probes -- that is what keeps it
        # I/O-free and keeps TestTheModuleStaysPure satisfiable.
        for name in hosts.known_hosts():
            for capability, probe_id in (hosts.spec(name).probes or {}).items():
                with self.subTest(host=name, capability=capability):
                    self.assertIsInstance(probe_id, str)

    def test_every_probed_capability_is_a_real_capability(self):
        for name in hosts.known_hosts():
            for capability in (hosts.spec(name).probes or {}):
                with self.subTest(host=name, capability=capability):
                    self.assertIn(capability, hosts.CAPABILITIES)

    def test_a_host_only_probes_what_it_claims(self):
        # Probing a capability you do not claim is incoherent: posture() would
        # report unknown regardless, so the probe could never change an answer.
        for name in hosts.known_hosts():
            row = hosts.spec(name)
            for capability in (row.probes or {}):
                with self.subTest(host=name, capability=capability):
                    self.assertIn(capability, row.claims)

    def test_the_probes_table_is_not_empty(self):
        # Guards the guard: a renamed constant must not make the loops above
        # pass over nothing.
        self.assertTrue(any(hosts.spec(n).probes for n in hosts.known_hosts()))


class TestRefutedBeatsProven(unittest.TestCase):
    """#1344 F3a, spec 7.3: two probes can touch one capability, so the
    precedence has to be written down rather than left to dict order."""

    def test_a_single_state_is_itself(self):
        for state in hosts.STATES:
            with self.subTest(state=state):
                self.assertEqual(state, hosts.resolve_state([state]))

    def test_refuted_beats_proven(self):
        self.assertEqual(hosts.REFUTED,
                         hosts.resolve_state([hosts.PROVEN, hosts.REFUTED]))
        self.assertEqual(hosts.REFUTED,
                         hosts.resolve_state([hosts.REFUTED, hosts.PROVEN]))

    def test_refuted_beats_unknown(self):
        # The key case: shell probe is inconclusive (UNKNOWN) while shadow
        # scan refutes. Refutation survives uncertainty.
        self.assertEqual(hosts.REFUTED,
                         hosts.resolve_state([hosts.REFUTED, hosts.UNKNOWN]))
        self.assertEqual(hosts.REFUTED,
                         hosts.resolve_state([hosts.UNKNOWN, hosts.REFUTED]))

    def test_proven_beats_unknown(self):
        self.assertEqual(hosts.PROVEN,
                         hosts.resolve_state([hosts.UNKNOWN, hosts.PROVEN]))

    def test_nothing_at_all_is_unknown(self):
        self.assertEqual(hosts.UNKNOWN, hosts.resolve_state([]))

    def test_an_unrecognised_state_is_ignored_not_trusted(self):
        self.assertEqual(hosts.UNKNOWN, hosts.resolve_state(["banana"]))
        self.assertEqual(hosts.PROVEN, hosts.resolve_state(["banana", hosts.PROVEN]))


class TestTheUnselectableRefusalIsOneSentence(unittest.TestCase):
    """#1624: two entrypoints refuse the same manifest, so the registry owns
    the sentence they refuse it with.

    `driver loop` has refused a manifest naming a registered-but-unselectable
    host since #1621; #1624 gave `driver run` the same refusal on the same
    resume path. The obvious way to do that is to copy the paragraph, and a
    copy is a thing that drifts -- one of them gains a clause, the other does
    not, and an operator who moves between the two entrypoints is told two
    different stories about one registry fact. The VERB is the only thing the
    call site gets to supply; everything after the colon is a property of the
    `driver_selectable` field, which lives here.
    """

    # The two entrypoints that read a manifest's host and may have to refuse
    # it, each with a call name it is already known to make -- guards the
    # guard, since an AST walk returning an empty set would pass
    # `test_both_entrypoints_call_it` over nothing.
    _CALL_SITES = ((orchestrate, "_status"), (driver, "_establish_host_posture"))

    def _calls(self, module):
        with open(module.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        names = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            names.add(fn.attr if isinstance(fn, ast.Attribute)
                      else getattr(fn, "id", ""))
        return names

    def _string_constants(self, module):
        # AST, not text: a COMMENT explaining why the sentence moved here is
        # welcome at either call site, and this repo has flagged its own prose
        # with a text scan three times now (see TestTheRegistryStaysPureData).
        with open(module.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        return [node.value for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)]

    def test_the_two_verbs_produce_the_same_sentence(self):
        run = hosts.unselectable_host_message("gemini", "run")
        loop = hosts.unselectable_host_message("gemini", "loop")
        self.assertEqual(run, loop.replace("driver loop:", "driver run:"))
        # ...and the verb is really in there, so the assertion above cannot
        # be satisfied by a function that ignores its second argument.
        self.assertTrue(loop.startswith("driver loop:"), loop)
        self.assertTrue(run.startswith("driver run:"), run)
        self.assertNotEqual(run, loop)

    def test_it_names_the_host_and_the_remedy(self):
        message = hosts.unselectable_host_message("gemini", "run")
        self.assertIn("gemini", message)
        self.assertIn("registered but no longer driver-selectable", message)
        self.assertIn("--host generic --reset", message)

    def test_the_host_comes_from_the_argument(self):
        # hosts.py is data, and this is the one function in it that formats
        # prose -- which is exactly where a host-name literal would hide.
        other = hosts.unselectable_host_message("ghost", "run")
        self.assertIn("ghost", other)
        self.assertNotIn("gemini", other)

    def test_both_entrypoints_call_it(self):
        for module, sentinel in self._CALL_SITES:
            with self.subTest(module=module.__name__):
                calls = self._calls(module)
                self.assertIn(sentinel, calls, "the walk did not see the module")
                self.assertIn("unselectable_host_message", calls)

    def test_neither_entrypoint_still_spells_the_sentence_itself(self):
        # The anti-drift half. `driver.py` legitimately carries the PARSER's
        # different sentence ("registered but not driver-selectable"), so pin
        # the clause only this one has.
        for module, _ in self._CALL_SITES:
            with self.subTest(module=module.__name__):
                offenders = [s for s in self._string_constants(module)
                             if "no longer driver-selectable" in s]
                self.assertEqual([], offenders,
                                 "%s spells the refusal itself instead of "
                                 "asking the registry for it" % module.__name__)


class TestTheCliBinaryIsPinnedToTheRunner(unittest.TestCase):
    """#1637 P10: `HostSpec.cli_binary` is a SECOND name for `HostRunner.CLI`.

    It exists because `driver readiness` has to ask "is this host's binary on
    PATH" and must not import `scripts.runners` to find out. Not a layout rule:
    test_layout pins the REVERSE edge (`runners/* -> phases`), so the import
    would pass today. The reason is that the runners package is host LAUNCH
    machinery and the verb's whole promise is that it starts nothing -- so the
    registry, which is this repo's single pure source of static host facts,
    carries the name instead.

    A registry row that drifted from its runner would make the preflight report
    on a binary no family launches, which is worse than reporting nothing, so
    the two are pinned to each other exactly as `cli_flag_facts` is pinned to
    `OUTPUT_SCHEMA_FLAG`.
    """

    def test_every_row_names_its_runner_s_cli_and_only_those_rows(self):
        import scripts.runners.base as runners_base
        for host in hosts.known_hosts():
            try:
                cli = runners_base.runner_for(host, "headless").CLI
            except Exception:                     # no headless runner at all
                cli = ""
            with self.subTest(host=host):
                self.assertEqual(cli, hosts.spec(host).cli_binary)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

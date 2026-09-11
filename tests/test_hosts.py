"""#1344 F1: one table that knows what a host is.

The registry is data. Its tests are therefore about TOTALITY and about
matching today's behavior exactly -- not about any host doing anything.
"""
import ast
import unittest

from scripts import hosts


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


class TestTodaysBehaviourIsPreserved(unittest.TestCase):
    """The whole point of F1/F2: the table must encode what the code does
    today, so routing consumers through it changes nothing."""

    def test_the_driver_accepts_exactly_the_hosts_it_accepts_today(self):
        self.assertEqual(("claude", "gemini", "generic"),
                         tuple(sorted(hosts.driver_hosts())))

    def test_only_claude_declares_tool_policy_enforcement_among_driver_hosts(self):
        # `enforced = host == "claude"` at 5 sites. Any other driver-selectable
        # host declaring it would flip those sites when they read the registry.
        enforcing = [h for h in hosts.driver_hosts()
                     if hosts.declares(h, hosts.TOOL_POLICY_ENFORCED)]
        self.assertEqual(["claude"], enforcing)

    def test_only_claude_declares_a_usage_ledger_among_driver_hosts(self):
        # phases/synthesize.py:35 -- `if manifest.get("host") != "claude"`.
        ledgered = [h for h in hosts.driver_hosts()
                    if hosts.declares(h, hosts.USAGE_LEDGER)]
        self.assertEqual(["claude"], ledgered)

    def test_kimi_and_codex_are_registrable_but_not_driver_selectable(self):
        # dispatch.py can emit their shells; driver.py's --host cannot pick
        # them. Preserving that split is what keeps F2 behavior-free.
        for name in ("kimi", "codex"):
            with self.subTest(host=name):
                self.assertTrue(hosts.spec(name).registration_dir)
                self.assertNotIn(name, hosts.driver_hosts())

    def test_no_host_claims_read_scope_confinement(self):
        # Spec §7.2: no host has this control today, Claude included.
        claiming = [h for h in hosts.known_hosts()
                    if hosts.declares(h, hosts.READ_SCOPE_CONFINED)]
        self.assertEqual([], claiming)


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

    def test_evidence_for_an_unclaimed_capability_is_refused(self):
        # gemini claims nothing. Evidence asserting otherwise must not be
        # honoured -- the artifact is written by us, but a stale one from a
        # different host's run must not grant a capability.
        evidence = {hosts.TOOL_POLICY_ENFORCED: {"state": hosts.PROVEN}}
        self.assertEqual(hosts.UNKNOWN,
                         hosts.posture("gemini", evidence)[hosts.TOOL_POLICY_ENFORCED])

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
    """hosts.py is imported by phases/*; it must stay cheap and I/O-free.

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

    def _tree(self):
        with open(hosts.__file__, encoding="utf-8") as fh:
            return ast.parse(fh.read())

    def _imported(self):
        names = set()
        for node in ast.walk(self._tree()):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module.split(".")[0])
        return names

    def _called(self):
        names = set()
        for node in ast.walk(self._tree()):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            names.add(fn.attr if isinstance(fn, ast.Attribute)
                      else getattr(fn, "id", ""))
        return names

    def test_it_imports_no_io_module(self):
        offenders = sorted(self._imported() & self._FORBIDDEN_MODULES)
        self.assertEqual([], offenders,
                         "hosts.py must stay pure data; %s belongs in "
                         "host_probes.py (F3)" % ", ".join(offenders))

    def test_it_calls_no_io_function(self):
        offenders = sorted(self._called() & self._FORBIDDEN_CALLS)
        self.assertEqual([], offenders,
                         "hosts.py must stay pure data; %s belongs in "
                         "host_probes.py (F3)" % ", ".join(offenders))

    def test_the_analyser_actually_sees_the_module(self):
        # Guards the guard: an analyser returning empty sets would pass both
        # assertions above over nothing.
        self.assertIn("os", self._imported())
        self.assertIn("expanduser", self._called())


class TestTheRegistryNamesItsProbes(unittest.TestCase):
    """#1344 F3a: a capability a host claims must say how it would be proved."""

    def test_claude_names_a_probe_for_every_security_capability_it_claims(self):
        row = hosts.spec("claude")
        # Assert the exact probes map, not just existence and truthiness.
        # This catches typos and swapped probe IDs.
        self.assertEqual(
            {hosts.TOOL_POLICY_ENFORCED: "registered-shell-tools",
             hosts.ARTIFACT_WRITE_GUARD: "write-guard-armed",
             hosts.USAGE_LEDGER: "transcript-dir"},
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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

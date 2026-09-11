"""#1344 F2/F3: the seven sites that decide a run's posture read ONE source.

F2 pinned that source as `hosts.declares()` -- the bare claim -- and said
this file would be rewritten once probe evidence landed. F3 (this file's
current state) is that rewrite: the seven sites now read `hosts.posture()`,
which is proof, not a claim, and every class below was updated to match:

* `TestNoSiteTestsAHostName` is the one class F3 does not touch. No site
  compares a host NAME either before or after; the guard stays green
  unchanged, and if it ever fails it means this task added a name comparison
  it should not have.
* `TestTheAnswersAreUnchangedGivenProof` (renamed from `...AreUnchanged`) is
  the direct consequence of F3's whole point: the seven sites' answers for
  "claude" are unchanged ONLY when a probe has proven the capability, not
  merely claimed it. A claude run with no evidence now answers the opposite
  way -- that reversal is spec §7.1, and it is the bug this epic exists to
  fix, not a regression. Keeping the old name after wiring it to prove-then-
  match would have told a future reader the F1/F2 answers survived
  unconditionally, which is no longer true.
* `TestTheThreeCapabilitiesAreNotInterchangeable` survives F3 by adding one
  fixture write (an all-PROVEN host-capabilities.json in `setUp`): its
  synthetic single-capability probe hosts already made TOOL_POLICY_ENFORCED,
  ARTIFACT_WRITE_GUARD and USAGE_LEDGER non-co-extensive by CLAIM, and
  `posture()` requires the claim AND the evidence, so proving everything
  leaves the claim doing all the same discriminating it always did.

The guard below is AST-based, not text-based. Two text-based versions were
tried and rejected in review: a raw regex scan flags requests.py's own
docstring, which quotes the idiom while explaining it, and a token scan that
blanks string-bearing lines flags nothing at all -- every instance of the
idiom carries a string literal on the same line, so blanking the line blanks
the evidence. An `ast.Compare` walk cannot see prose and cannot be fooled by
the literal it is looking for.
"""
import ast
import os
import shutil
import tempfile
import unittest
from unittest import mock

from conftest import REPO_ROOT
from scripts import hosts
import scripts.ocrdb as ocrdb
import scripts.phases.coverage as coverage
import scripts.phases.requests as requests
import scripts.phases.review as review
import scripts.phases.runio as runio
import scripts.phases.synthesize as synthesize
import scripts.phases.verify as verify

PHASES = os.path.join(REPO_ROOT, "skill", "scripts", "phases")

_HOST_NAMES = frozenset(hosts.known_hosts())


def _host_name_comparisons(path):
    """Every real comparison against a host-name literal in one file.

    AST, not text. Two text-based versions were tried and were wrong in
    opposite directions: a raw scan flags `requests.py`'s own docstring, which
    quotes the idiom while explaining it, and a token scan that blanks
    string-bearing lines flags nothing at all -- every instance of the idiom
    carries a string literal on the same line, so blanking the line blanks the
    evidence. An `ast.Compare` walk cannot see prose and cannot be fooled by
    the literal it is looking for.
    """
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    lines = source.splitlines()
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left] + list(node.comparators)
        flat = []
        for operand in operands:
            if isinstance(operand, (ast.Tuple, ast.List, ast.Set)):
                flat.extend(operand.elts)   # `host in ("claude", "kimi")`
            else:
                flat.append(operand)
        if any(isinstance(o, ast.Constant) and isinstance(o.value, str)
               and o.value in _HOST_NAMES for o in flat):
            found.append((node.lineno, lines[node.lineno - 1].strip()))
    return found


def _offenders():
    """Every host-name comparison left anywhere in `phases/`."""
    found = []
    for name in sorted(os.listdir(PHASES)):
        if name.endswith(".py"):
            found.extend(
                "%s:%d %s" % (name, lineno, text)
                for lineno, text in _host_name_comparisons(
                    os.path.join(PHASES, name)))
    return sorted(found)


class TestNoSiteTestsAHostName(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_the_scanner_reads_the_directory(self):
        # Guards the guard.
        names = [n for n in os.listdir(PHASES) if n.endswith(".py")]
        self.assertGreater(len(names), 5)

    def test_no_phase_decides_posture_from_a_host_name(self):
        self.assertEqual(
            [], _offenders(),
            "posture comes from hosts.declares(), not from a name:\n%s"
            % "\n".join(_offenders()))

    def test_the_guard_can_actually_flag_something(self):
        # Guards the guard. One earlier version of this scanner flagged prose;
        # another, measured, flagged nothing at all in any file.
        probe = os.path.join(self.tmp, "probe.py")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write('host = "x"\nenforced = host == "claude"\n')
        self.assertEqual(1, len(_host_name_comparisons(probe)))

    def test_the_guard_cannot_see_prose(self):
        # requests.py's docstring quotes `host == "claude"` while explaining
        # the idiom being removed. A text scan flags it; this must not.
        probe = os.path.join(self.tmp, "prose.py")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write('def f():\n'
                     '    """`enforced` is `host == "claude"` in the driver."""\n'
                     '    return 1  # host == "claude" once lived here\n')
        self.assertEqual([], _host_name_comparisons(probe))


class TestTheAnswersAreUnchangedGivenProof(unittest.TestCase):
    """F2 pinned these four answers against `hosts.declares()` -- the bare
    claim. F3 moved the seven sites to `hosts.posture()`, so the SAME four
    answers now hold only when a probe has PROVEN the capability, not merely
    when claude claims it; the final test below pins the other half, that
    absent a probe the answer flips. Renamed from `TestTheAnswersAreUnchanged`,
    which would otherwise assert unconditional parity that no longer exists --
    exactly the lie spec section 7.1 exists to end."""

    @staticmethod
    def _proof(**states):
        """A `posture()` evidence mapping proving exactly the given states."""
        return {name: {"state": state, "by": "fixture", "detail": "fixture"}
                for name, state in states.items()}

    def test_claude_enforces_and_nothing_else_the_driver_accepts_does(self):
        proof = self._proof(**{hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN})
        self.assertEqual(
            hosts.PROVEN,
            hosts.posture("claude", proof)[hosts.TOOL_POLICY_ENFORCED])
        for name in ("generic", "gemini"):
            with self.subTest(host=name):
                self.assertNotEqual(
                    hosts.PROVEN,
                    hosts.posture(name, proof)[hosts.TOOL_POLICY_ENFORCED])

    def test_only_claude_collects_usage(self):
        proof = self._proof(**{hosts.USAGE_LEDGER: hosts.PROVEN})
        self.assertEqual(
            hosts.PROVEN, hosts.posture("claude", proof)[hosts.USAGE_LEDGER])
        for name in ("generic", "gemini"):
            with self.subTest(host=name):
                self.assertNotEqual(
                    hosts.PROVEN, hosts.posture(name, proof)[hosts.USAGE_LEDGER])

    def test_an_absent_host_key_is_treated_as_claude(self):
        # requests.py reads `manifest.get("host", "claude")`. Preserve that
        # default exactly -- a manifest written before the key existed must
        # keep resolving the same way, given proof.
        proof = self._proof(**{hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN})
        self.assertEqual(
            hosts.PROVEN,
            hosts.posture({}.get("host", "claude"), proof)[hosts.TOOL_POLICY_ENFORCED])

    def test_only_claude_has_a_write_guard(self):
        # requests.py:185 -- require_unenforced_ack returns early when the
        # host's hook mediates Write AND a probe has proven it. Same answer
        # as before the migration, given proof.
        proof = self._proof(**{hosts.ARTIFACT_WRITE_GUARD: hosts.PROVEN})
        self.assertEqual(
            hosts.PROVEN,
            hosts.posture("claude", proof)[hosts.ARTIFACT_WRITE_GUARD])
        for name in ("generic", "gemini"):
            with self.subTest(host=name):
                self.assertNotEqual(
                    hosts.PROVEN,
                    hosts.posture(name, proof)[hosts.ARTIFACT_WRITE_GUARD])

    def test_claude_with_no_evidence_answers_the_opposite_way(self):
        # Spec 7.1, the reason this class was renamed: absent a probe,
        # "claude enforces" no longer holds for any of the three capabilities
        # the sites above read. A class still called "...AreUnchanged" that
        # only ever supplied proof would hide this from a future reader.
        for capability in (hosts.TOOL_POLICY_ENFORCED, hosts.ARTIFACT_WRITE_GUARD,
                           hosts.USAGE_LEDGER):
            with self.subTest(capability=capability):
                self.assertNotEqual(
                    hosts.PROVEN, hosts.posture("claude", {})[capability])


class TestTheThreeCapabilitiesAreNotInterchangeable(unittest.TestCase):
    """The capability->site mapping, pinned.

    Over the hosts that exist today the three capabilities are extensionally
    IDENTICAL: `claude` claims all three, `gemini` and `generic` claim none.
    So every migrated site could carry any of the three and the whole suite
    stayed green -- swapping USAGE_LEDGER for TOOL_POLICY_ENFORCED at
    synthesize.py:36 and ARTIFACT_WRITE_GUARD for TOOL_POLICY_ENFORCED at
    requests.py:187 left 2801 tests passing. F2's entire claim is that these
    sites were never asking the same question, and nothing tested it.

    Three synthetic registry rows make the capabilities non-co-extensive, and
    each site is then called through its own real entry point. A site wired to
    the wrong capability answers the wrong way for exactly one probe host.
    """

    PROBE_TPE = "probe-tpe"      # tool policy enforcement only
    PROBE_AWG = "probe-awg"      # artifact write guard only
    PROBE_UL = "probe-ul"        # usage ledger only

    PROBES = {
        PROBE_TPE: hosts.HostSpec(
            name=PROBE_TPE, claims=frozenset({hosts.TOOL_POLICY_ENFORCED})),
        PROBE_AWG: hosts.HostSpec(
            name=PROBE_AWG, claims=frozenset({hosts.ARTIFACT_WRITE_GUARD})),
        PROBE_UL: hosts.HostSpec(
            name=PROBE_UL, claims=frozenset({hosts.USAGE_LEDGER})),
    }

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        # #1344 F3: every site below now reads posture(), which requires
        # PROVEN evidence as well as the claim. An all-proven artifact makes
        # the probe hosts' single-capability CLAIMS keep doing all the
        # discriminating -- the whole point of this class -- while evidence
        # merely stops blocking it. No manifest is written in this class, so
        # this lands at the flat top-level path, exactly where
        # `runio.host_evidence` will look for it below too.
        # #1344 F3: every site below now reads posture(), which requires
        # PROVEN evidence as well as the claim. An all-proven artifact makes
        # the probe hosts' single-capability CLAIMS keep doing all the
        # discriminating -- the whole point of this class -- while evidence
        # merely stops blocking it. No manifest is written in this class, so
        # this lands at the flat top-level path, exactly where
        # `runio.host_evidence` will look for it below too.
        runio._write_json(
            runio._pano(self.root, runio.HOST_CAPABILITIES),
            {"schema_version": 1, "host": "probe", "probed_at": "2026-09-10T00:00:00Z",
             "capabilities": {name: {"state": hosts.PROVEN, "by": "fixture",
                                     "detail": "fixture"}
                              for name in hosts.CAPABILITIES}})
        self.files = ["src/pay.py"]
        self.cell = [{"id": "F1", "code": "SEC-A1A", "severity": "HIGH",
                      "title": "t", "category": "SEC",
                      "location": {"file": self.files[0], "line": 1},
                      "description": "d"}]
        self.bundle = ocrdb.load_bundle()
        self._patch = mock.patch.dict(hosts.HOSTS, self.PROBES)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def _manifest(self, host):
        return {"run_id": "R", "security_mode": "standard", "host": host,
                "flags": {}}

    def test_the_probes_make_the_capabilities_non_co_extensive(self):
        # Guards the fixture. Without this, a probe row that silently failed to
        # install would make every assertion below vacuously agree.
        for host, capability in ((self.PROBE_TPE, hosts.TOOL_POLICY_ENFORCED),
                                 (self.PROBE_AWG, hosts.ARTIFACT_WRITE_GUARD),
                                 (self.PROBE_UL, hosts.USAGE_LEDGER)):
            with self.subTest(host=host):
                self.assertEqual(
                    {capability},
                    {c for c in hosts.CAPABILITIES if hosts.declares(host, c)})

    # --- the five `enforced` builders: TOOL_POLICY_ENFORCED, nothing else ---

    def _enforced_by_site(self, host):
        """{site name -> the `enforced` field it produced for this host}."""
        runio._write_json(runio._pano(self.root, "groups.json"),
                          {"groups": [{"name": "Auth", "files": self.files}]})
        runio._write_json(runio._pano(self.root, "coverage-Auth.json"),
                          {"effective": ["SEC"]})
        manifest = self._manifest(host)
        plan = requests._driver_plan_entries(self.root, manifest)
        self.assertEqual(1, len(plan))            # the fixture produced a cell
        return {
            "coverage._scout_entry": coverage._scout_entry(
                self.root, manifest, "Auth", self.files, host,
                registry_tools=["semgrep"])["enforced"],
            "review._cell_entry": review._cell_entry(
                self.root, manifest, "Auth", "SEC", self.files, [], host,
                self.bundle)["enforced"],
            "verify._verify_entry": verify._verify_entry(
                self.root, manifest, "Auth", "SEC", self.files, self.cell,
                host, self.bundle, "primary")["enforced"],
            "verify._tool_verify_entry": verify._tool_verify_entry(
                self.root, manifest, "q1",
                {"id": "T-1", "severity": "HIGH"}, host)["enforced"],
            "requests._driver_plan_entries": plan[0]["enforced"],
        }

    def test_the_enforced_builders_read_tool_policy_enforcement(self):
        for site, enforced in self._enforced_by_site(self.PROBE_TPE).items():
            with self.subTest(site=site):
                self.assertTrue(enforced)

    def test_the_enforced_builders_ignore_the_write_guard(self):
        # A host that can mediate Write but cannot enforce a tool policy is
        # NOT enforced. Wire any of these five to ARTIFACT_WRITE_GUARD and this
        # is the assertion that catches it.
        for site, enforced in self._enforced_by_site(self.PROBE_AWG).items():
            with self.subTest(site=site):
                self.assertFalse(enforced)

    def test_the_enforced_builders_ignore_the_usage_ledger(self):
        for site, enforced in self._enforced_by_site(self.PROBE_UL).items():
            with self.subTest(site=site):
                self.assertFalse(enforced)

    # --- the write-capable gate: ARTIFACT_WRITE_GUARD, nothing else ---

    ACK_ENTRIES = [{"group": "Auth", "domain": "SEC", "enforced": False,
                    "out_file": "/abs/findings-Auth-SEC.json"}]

    def _ack_manifest(self, host):
        return {"host": host, "flags": {"allow_unenforced": False}}

    def test_the_write_gate_takes_its_early_return_for_the_write_guard_only(self):
        self.assertIsNone(requests.require_unenforced_ack(
            self.root, self._ack_manifest(self.PROBE_AWG), self.ACK_ENTRIES))
        self.assertFalse(os.path.exists(
            runio._pano(self.root, requests.UNENFORCED_ACK)))

    def test_the_write_gate_refuses_tool_policy_enforcement_and_usage_ledger(self):
        # Enforcing a tool POLICY is not the same as being able to mediate a
        # Write, and neither is keeping a usage ledger. Both must still be
        # refused without --allow-unenforced.
        for host in (self.PROBE_TPE, self.PROBE_UL):
            with self.subTest(host=host):
                with self.assertRaises(runio.DriverError):
                    requests.require_unenforced_ack(
                        self.root, self._ack_manifest(host), self.ACK_ENTRIES)

    # --- the usage gate: USAGE_LEDGER, nothing else ---

    def _usage_ran(self, host):
        with mock.patch("scripts.phases.runio._run_child") as run:
            run.return_value = mock.Mock(returncode=0)
            synthesize._collect_host_usage(
                self.root, {"host": host, "run_id": "r1",
                            "created": "2026-09-10T00:00:00Z",
                            "session_dir": self.root})
        return run.called

    def test_usage_is_collected_for_the_usage_ledger_host_only(self):
        self.assertTrue(self._usage_ran(self.PROBE_UL))
        for host in (self.PROBE_TPE, self.PROBE_AWG):
            with self.subTest(host=host):
                self.assertFalse(self._usage_ran(host))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

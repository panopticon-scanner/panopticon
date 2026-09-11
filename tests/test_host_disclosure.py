import unittest
from unittest import mock

from scripts import host_disclosure, hosts


def envelope(host="claude", **states):
    """A host-capabilities.json envelope with a MIXED posture.

    Mixed on purpose (plan Global Constraints): a surface that hard-codes one
    capability passes an all-proven or all-unknown fixture and fails this one.
    """
    caps = {}
    for cap, (state, by, detail) in states.items():
        caps[cap] = {"state": state, "by": by, "detail": detail}
    return {"schema_version": 1, "host": host, "probed_at": "T", "capabilities": caps}


# The brief's MIXED fixture named only three of the five capabilities and left
# `model_binding` / `read_scope_confined` absent from `capabilities` entirely.
# `hosts.posture()` still resolves all five (an absent entry -> UNKNOWN), so
# that fixture was never actually 3-wide -- it was 5-wide with two capabilities
# hiding as accidental UNKNOWNs, and the unproven count it produces is 4, not
# 2. Defined here explicitly instead, still genuinely mixed: one proven
# (artifact_write_guard), one refuted (tool_policy_enforced), and three
# unknown (model_binding, read_scope_confined, usage_ledger) -- on different
# capabilities, per the plan's Global Constraint.
MIXED = envelope(
    **{hosts.TOOL_POLICY_ENFORCED: (hosts.REFUTED, "shadow-shell-scan",
                                    "the reviewed tree ships .claude/agents/panopticon-scout.md"),
       hosts.ARTIFACT_WRITE_GUARD: (hosts.PROVEN, "write-guard-armed", "round-trip denied"),
       hosts.USAGE_LEDGER: (hosts.UNKNOWN, None, "no transcript directory"),
       hosts.READ_SCOPE_CONFINED: (hosts.UNKNOWN, None,
                                   "no host implements a read-confinement control yet"),
       hosts.MODEL_BINDING: (hosts.UNKNOWN, None,
                             "dispatch entries carry model=None until F4 binds them")})


class TestTheWordingRule(unittest.TestCase):
    def test_every_line_names_capability_host_probe_and_remedy(self):
        # 5.1: "name the capability, the host, the probe, and the remedy.
        # 'unenforced' alone is not a disclosure; it is a mood."
        out = host_disclosure.lines(MIXED)
        self.assertTrue(out)
        for line in out:
            self.assertIn("claude", line)                       # the host
            cap = [c for c in hosts.CAPABILITIES if c in line]
            self.assertTrue(cap, "no capability named in %r" % line)
            self.assertIn("fix:", line)                         # the remedy

    def test_a_refuted_line_names_the_probe_that_refuted_it(self):
        line = [x for x in host_disclosure.lines(MIXED)
                if hosts.TOOL_POLICY_ENFORCED in x][0]
        self.assertIn("shadow-shell-scan", line)

    def test_an_unknown_capability_says_nobody_looked_not_that_it_failed(self):
        line = [x for x in host_disclosure.lines(MIXED)
                if hosts.USAGE_LEDGER in x][0]
        self.assertIn("unknown", line)
        self.assertNotIn("refuted", line)

    def test_a_proven_capability_produces_no_line(self):
        self.assertFalse([x for x in host_disclosure.lines(MIXED)
                          if hosts.ARTIFACT_WRITE_GUARD in x])


class TestTheInverseCarriesEqualWeight(unittest.TestCase):
    def test_an_all_proven_host_says_so_explicitly(self):
        # 5.1: absence of warnings must mean "measured and proven", never
        # "nobody looked".
        #
        # No host in today's registry actually claims `read_scope_confined`
        # (spec 7.2 -- no host implements read-confinement yet), so
        # `hosts.posture()`'s claim-mask forces it to UNKNOWN for every real
        # host no matter what the evidence says. That is a fact about today's
        # registry, not a fact host_disclosure should be judged against: this
        # test needs a posture that genuinely has no gaps to prove ALL_PROVEN
        # fires, so it patches in a host that claims all five capabilities
        # rather than asserting something the real registry cannot produce.
        #
        # Patched on `host_disclosure.hosts`, not the `hosts` imported here:
        # host_disclosure.py does a bare `import hosts`, which -- because
        # conftest.py puts skill/scripts/ on sys.path for standalone-script
        # compatibility -- resolves to a DIFFERENT sys.modules entry than
        # `from scripts import hosts` does in this file. They are two loads
        # of the same source with two independent `HOSTS` dicts; patching the
        # wrong one is a silent no-op, not a failure.
        all_claims = hosts.HostSpec(name="proves-everything",
                                    claims=frozenset(hosts.CAPABILITIES))
        with mock.patch.dict(host_disclosure.hosts.HOSTS,
                             {"proves-everything": all_claims}):
            env = envelope(host="proves-everything",
                           **{c: (hosts.PROVEN, "p", "d") for c in hosts.CAPABILITIES})
            self.assertEqual([], host_disclosure.lines(env))
            self.assertEqual(host_disclosure.ALL_PROVEN, host_disclosure.headline(env))

    def test_no_evidence_is_distinguishable_from_all_proven(self):
        self.assertEqual(host_disclosure.NO_EVIDENCE, host_disclosure.headline({}))
        self.assertNotEqual(host_disclosure.ALL_PROVEN, host_disclosure.NO_EVIDENCE)

    def test_a_malformed_envelope_reads_as_nobody_looked(self):
        # The artifact is a FILE ON DISK and therefore untrusted.
        for bad in ([1, 2], "hello", 5, {"capabilities": 7}, None):
            with self.subTest(bad=bad):
                self.assertEqual(host_disclosure.NO_EVIDENCE,
                                 host_disclosure.headline(bad))


class TestTheHeadline(unittest.TestCase):
    def test_it_counts_the_unproven_and_names_the_host(self):
        head = host_disclosure.headline(MIXED)
        self.assertIn("claude", head)
        self.assertIn("4", head)          # refuted + 3 unknown, not the proven one

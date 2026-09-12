import contextlib
import html
import io
import subprocess
import unittest
from unittest import mock

from scripts import host_disclosure, hosts
import scripts.driver as driver
import scripts.host_probes as host_probes
import scripts.html_report as html_report
import scripts.setup_flow as setup_flow
import scripts.synth.findings as findings_mod
import scripts.synth.render as render_mod
import scripts.synth.report as report_mod


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

    def test_every_capability_has_a_real_remedy(self):
        # The one thing nothing else in this file can check. `remedy()` falls
        # back to "no remedy recorded for <capability>", which satisfies every
        # other assertion here: `assertIn("fix:", line)` still passes, and so
        # does the cross-surface `assertIn(remedy(capability, "claude"), text)`
        # below -- because that test asks remedy() for the same fallback string
        # it then looks for. Deleting the READ_SCOPE_CONFINED entry from
        # _REMEDY left all 2976 tests green while every surface rendered
        # "fix: no remedy recorded for read_scope_confined".
        #
        # 5.1's wording rule is "name the capability, the host, the probe, and
        # THE REMEDY". "No remedy recorded" is the absence of one, and the
        # consistency tests only prove the surfaces agree -- not that what they
        # agree on is a disclosure.
        # Totality first: every capability has an ENTRY.
        self.assertEqual(sorted(hosts.CAPABILITIES),
                         sorted(host_disclosure._REMEDY))
        # ...then that the entry is worth having. Membership alone is half a
        # guard, and this test was shipped as that half: given the assertEqual
        # above, `remedy()`'s "no remedy recorded" fallback can never fire, so
        # an `assertNotIn` on it proved nothing. Measured -- set
        # _REMEDY[READ_SCOPE_CONFINED] = "" and all 2996 tests passed while
        # every surface rendered "... fix: " with nothing after it. A guard
        # written to close the "assertion that cannot fail" class must not be
        # one itself.
        remedies = {}
        for capability in hosts.CAPABILITIES:
            with self.subTest(capability=capability):
                text = host_disclosure.remedy(capability, "claude")
                self.assertTrue(text.strip(), "blank remedy")
                # Long enough to be an instruction. The shortest real one is 93
                # characters ("nothing to do in this release: ..."), so 30 is a
                # floor a placeholder -- "", " ", "TODO", "-", "n/a" -- cannot
                # clear and no genuine remedy is near.
                self.assertGreater(
                    len(text.strip()), 30,
                    "remedy for %s is a placeholder, not an instruction: %r"
                    % (capability, text))
                remedies[capability] = text.strip()
        # Five DISTINCT strings. One remedy pasted across all five satisfies
        # every per-capability check above while telling four of them to do the
        # wrong thing -- and the cross-surface test would still pass, because it
        # asks remedy() for whatever string it then looks for.
        self.assertEqual(len(hosts.CAPABILITIES), len(set(remedies.values())),
                         "two capabilities share a remedy: %r" % (remedies,))

    def test_the_model_binding_remedy_names_the_real_fix(self):
        # Until F4 the remedy honestly said "nothing to do in this release".
        # Now there is something to do, and "nothing to do" would be false.
        text = host_disclosure.remedy(hosts.MODEL_BINDING, "claude")
        self.assertNotIn("nothing to do", text)
        self.assertIn("--emit-host-agents claude", text)
        self.assertIn("PANOPTICON_MODEL_", text)

    def test_the_generic_deprecation_says_what_and_when(self):
        # D4: "deprecate now, remove when the families land". The line must
        # name the flag, say it is deprecated, say why it is unsafe to rely on,
        # and name the bar that removes it.
        text = host_disclosure.GENERIC_DEPRECATION
        for token in ("--host generic", "deprecated", "unenforced",
                      "retirement bar", "test_generic_retirement_bar"):
            self.assertIn(token, text, token)
        self.assertLess(len(text), 400, "one line, not a paragraph")


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
        # Patched on the canonical `hosts.HOSTS` imported here. host_disclosure
        # now imports `hosts` via the repo's `try: from scripts import hosts /
        # except ImportError: import hosts` convention (model_resolver.py etc),
        # so under pytest (conftest.py puts skill/ on sys.path) the try arm
        # resolves and `host_disclosure.hosts is hosts` here is True -- one
        # module, one HOSTS dict. (Before that fix, host_disclosure.py's bare
        # `import hosts` created a second, non-identical module and patching
        # this `hosts.HOSTS` would have been a silent no-op.)
        all_claims = hosts.HostSpec(name="proves-everything",
                                    claims=frozenset(hosts.CAPABILITIES))
        assert host_disclosure.hosts is hosts, (
            "host_disclosure's hosts import has drifted from the canonical "
            "scripts.hosts module again -- patching hosts.HOSTS below would "
            "be a silent no-op")
        with mock.patch.dict(hosts.HOSTS, {"proves-everything": all_claims}):
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

    def test_capabilities_only_malformed_still_reads_as_nobody_looked(self):
        # `lines()` and `headline()` each guard with `caps is None or host is
        # None`. Every case in test_a_malformed_envelope_reads_as_nobody_looked
        # fails BOTH arms at once -- the envelope is either not a dict at all,
        # or (for {"capabilities": 7}) lacks a "host" key entirely, so host is
        # also None. None of them can catch a regression from `or` to `and`
        # that only breaks the `caps is None` arm. This envelope has a
        # perfectly valid host and only an unusable `capabilities`, so it
        # isolates that arm.
        bad = {"host": "claude", "capabilities": "garbage"}
        self.assertEqual([], host_disclosure.lines(bad))
        self.assertEqual(host_disclosure.NO_EVIDENCE, host_disclosure.headline(bad))

    def test_host_only_malformed_still_reads_as_nobody_looked(self):
        # The mirror of the case above: capabilities is a valid (if empty)
        # dict, and only the host is unusable (not a string). Isolates the
        # `host is None` arm.
        bad = {"host": 123, "capabilities": {}}
        self.assertEqual([], host_disclosure.lines(bad))
        self.assertEqual(host_disclosure.NO_EVIDENCE, host_disclosure.headline(bad))


class TestTheHeadline(unittest.TestCase):
    def test_it_counts_the_unproven_and_names_the_host(self):
        head = host_disclosure.headline(MIXED)
        self.assertIn("claude", head)
        # "4 of 5", not a bare "4": a lone "4" is satisfied by any digit the
        # sentence happens to contain, including the 5 in "of 5" flipping
        # places, so it does not actually pin the count.
        self.assertIn("4 of 5", head)     # refuted + 3 unknown, not the proven one


def _runner_ok(cmd, **kwargs):
    """A `runner` that never touches a real process. The capability probing
    does not take `runner` at all (run_probes is mocked); this only stands in
    for the codex-cli `_probe` call, which the claude path never reaches."""
    return subprocess.CompletedProcess(cmd, 0, "", "")


class TestTheFourSurfacesSayTheSameThing(unittest.TestCase):
    """§5.1 mandates four surfaces. Four hand-written copies of the wording
    rule drift, and each surface's own test keeps passing while they do. This
    reads ONE posture and asserts every surface names the same capability, the
    same probe and the same remedy.

    Surface 2 (`meta.host_capabilities`) is the same envelope the body renders
    from, so it is exercised through the report build here rather than as a
    separate string: the body surface is built by the REAL pipeline
    (build_report -> render_summary), which is what carries
    meta.host_capabilities.
    """

    def _surfaces(self, envelope):
        """{name: rendered text} for every surface, from ONE posture."""
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            driver._emit_posture_disclosure(envelope)
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="target", fail_on="high",
                timestamp="2026-08-03T00:00:00Z",
                host_capabilities=envelope),
            findings=findings_mod.FindingSet(findings=[])))
        with mock.patch.object(host_probes, "run_probes", return_value=envelope):
            rows = setup_flow._check_host_shells("claude", _runner_ok, ".")
        return {"stderr": err.getvalue(),
                "body": render_mod.render_summary(report),
                # The body surface again, in the artifact an operator actually
                # opens. Read through html.unescape: `_escape` is doing its job
                # on the quotes in `on host 'claude'`, and comparing against
                # pre-escaped copies of host_disclosure's strings here would be
                # a second spelling of the wording rule -- the very thing this
                # test exists to forbid.
                "html": html.unescape(html_report.render(report)),
                "readiness": "\n".join(r[2] for r in rows)}

    def test_every_surface_names_the_same_capability_probe_and_remedy(self):
        surfaces = self._surfaces(MIXED)
        self.assertEqual({"stderr", "body", "html", "readiness"}, set(surfaces))
        for name, text in surfaces.items():
            for capability in hosts.unproven(
                    hosts.posture("claude", MIXED["capabilities"])):
                with self.subTest(surface=name, capability=capability):
                    self.assertIn(capability, text)
                    # the REMEDY verbatim -- not a prefix. One surface
                    # paraphrasing the fix is exactly the drift this catches.
                    self.assertIn(host_disclosure.remedy(capability, "claude"), text)
            with self.subTest(surface=name, probe="shadow-shell-scan"):
                self.assertIn("shadow-shell-scan", text)

    def test_no_surface_warns_about_a_proven_capability(self):
        for name, text in self._surfaces(MIXED).items():
            with self.subTest(surface=name):
                self.assertNotIn(hosts.ARTIFACT_WRITE_GUARD, text)

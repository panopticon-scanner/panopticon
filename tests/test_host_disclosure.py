import contextlib
import html
import io
import subprocess
import unittest
from unittest import mock

from _test_helpers import only
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

    def test_the_read_scope_remedy_names_the_real_fix(self):
        # Until plan 5 the remedy honestly said "nothing to do: no host
        # implements a read-confinement control yet". claude ships one now.
        remedy = host_disclosure._REMEDY[hosts.READ_SCOPE_CONFINED] % {"host": "claude"}
        self.assertNotIn("nothing to do", remedy)
        self.assertIn("settings.local.json", remedy)
        self.assertIn("transcript", remedy)

    def test_a_codex_disclosure_never_prints_a_claude_remedy(self):
        # I-4: _REMEDY was keyed by capability alone, so every Codex run told
        # the operator to create `.claude/settings.local.json` and to pass
        # `--session-dir` naming a transcript directory Codex does not have.
        # 5.1's rule is "name the capability, the host, the probe, and the
        # remedy" -- a remedy for the wrong host is not a remedy.
        unclaimed = sorted(set(hosts.CAPABILITIES) - hosts.spec("codex").claims)
        self.assertTrue(unclaimed)
        for capability in unclaimed:
            with self.subTest(capability=capability):
                text = host_disclosure.remedy(capability, "codex")
                self.assertNotIn(".claude/settings.local.json", text)
                self.assertNotIn("--session-dir", text)
                self.assertNotIn("transcript", text)
                self.assertGreater(len(text.strip()), 30)
        codex_lines = "\n".join(host_disclosure.lines(envelope(
            "codex", **{c: (hosts.UNKNOWN, None, "no probe") for c in unclaimed})))
        self.assertTrue(codex_lines)
        self.assertNotIn(".claude/settings.local.json", codex_lines)
        self.assertNotIn("--session-dir", codex_lines)
        # Claude's own remedies are untouched.
        self.assertIn("settings.local.json",
                      host_disclosure.remedy(hosts.ARTIFACT_WRITE_GUARD, "claude"))

    def test_the_generic_fallback_notice_says_what_and_why_it_is_still_here(self):
        # D4 said "deprecate now, remove when the families land", and the line
        # said generic was "removed once every remaining host clears the
        # retirement bar". That became misleading at #1621: the bar is met on
        # this base (claude, codex and kimi are the hosts it examines and
        # all three clear it) and generic is still the only path a Gemini
        # operator has. Owner ruling D1 (spec 8.3 option 1) settled it: keep
        # generic as the permanent ack-gated fallback and retire F5. The line
        # must name the flag, say it is unenforced and ack-gated, say what it
        # is still FOR, and never call it deprecated or promise a removal the
        # bar cannot trigger on its own.
        text = host_disclosure.GENERIC_FALLBACK_NOTICE
        self.assertNotIn("deprecat", text.lower())
        for token in ("--host generic", "unenforced", "ack-gated",
                      "family runner", "gemini", "not going away"):
            self.assertIn(token, text, token)
        self.assertNotIn("removed once every remaining host", text)
        self.assertLess(len(text), 400, "one line, not a paragraph")


class TestALineNeverContradictsItself(unittest.TestCase):
    """#1597: the masked state and the raw row's `by`/`detail` came from two
    different places, and a stale or foreign artifact makes them disagree:

        artifact_write_guard is unknown on host 'gemini' -- probe
        write-guard-armed: round-trip denied

    "unknown" and "round-trip denied" cannot both be true of the same
    measurement. The status is the masked one (`hosts.posture` is the
    fail-closed answer every surface renders); the probe and the detail
    describe a state the operator is NOT being shown, so they are dropped
    rather than printed beside a status that refutes them.
    """

    def _masked_line(self, host, capability, state, by, detail):
        env = envelope(host, **{capability: (state, by, detail)})
        return only([x for x in host_disclosure.lines(env) if capability in x],
                    "line for " + capability)

    def test_a_proven_row_a_host_does_not_claim_drops_its_probe_and_detail(self):
        # gemini claims nothing, so `posture()` masks this PROVEN row to
        # UNKNOWN (a stale artifact must not GRANT anything).
        self.assertNotIn(hosts.ARTIFACT_WRITE_GUARD, hosts.spec("gemini").claims)
        line = self._masked_line("gemini", hosts.ARTIFACT_WRITE_GUARD,
                                 hosts.PROVEN, "write-guard-armed",
                                 "round-trip denied")
        self.assertIn(hosts.UNKNOWN, line)
        self.assertNotIn("write-guard-armed", line)
        self.assertNotIn("round-trip denied", line)
        # #1597's second sanctioned half -- "say plainly that the artifact
        # claims something the host cannot". Naming the recorded state
        # EXPLAINS the suppression; it is the by/detail, which assert a
        # measurement beside a status that refutes it, that may not be shown.
        self.assertIn(repr(hosts.PROVEN), line)
        # Still a disclosure, not a mood: capability, host and remedy survive.
        self.assertIn(hosts.ARTIFACT_WRITE_GUARD, line)
        self.assertIn("gemini", line)
        self.assertIn(host_disclosure.remedy(hosts.ARTIFACT_WRITE_GUARD, "gemini"),
                      line)

    def test_an_unparseable_state_drops_them_too(self):
        # `noscan`-became-`empty` (#1335) in this shape: the row records a
        # state this module cannot read, `posture()` answers UNKNOWN, and the
        # row's own by/detail describe whatever `banana` was supposed to mean.
        line = self._masked_line("claude", hosts.USAGE_LEDGER, "banana",
                                 "usage-source", "envelope carried `usage`")
        self.assertIn(hosts.UNKNOWN, line)
        self.assertNotIn("usage-source", line)
        self.assertNotIn("envelope carried", line)
        # ...and the unreadable token is described, never quoted (R1 Minor 1).
        self.assertNotIn("banana", line)
        self.assertIn("unrecognised", line)

    def test_a_row_that_agrees_with_the_mask_keeps_its_probe_and_detail(self):
        # The other direction, so the fix cannot be "drop by/detail always".
        # REFUTED passes the claim mask untouched (hosts.posture, I5).
        line = self._masked_line("claude", hosts.TOOL_POLICY_ENFORCED,
                                 hosts.REFUTED, "shadow-shell-scan",
                                 "the reviewed tree ships panopticon-scout.md")
        self.assertIn("shadow-shell-scan", line)
        self.assertIn("panopticon-scout.md", line)

    def test_the_stateless_sentence_names_only_what_the_row_holds(self):
        # Re-review nit: the sentence said the artifact "records a probe and a
        # detail" for all three shapes, a false statement about the artifact
        # on the one surface this fix exists to make honest.
        cases = ({"detail": "round-trip denied"}, "a detail but no state"),
        cases += ({"by": "write-guard-armed"}, "a probe but no state"),
        cases += ({"by": "write-guard-armed", "detail": "round-trip denied"},
                  "a probe and a detail but no state"),
        for row, expected in cases:
            with self.subTest(row=row):
                clause = host_disclosure._probe_clause(row, hosts.UNKNOWN)
                self.assertIn(expected, clause)
                if "by" not in row:
                    self.assertNotIn("a probe", clause)
                if "detail" not in row:
                    self.assertNotIn("a detail", clause)

    def test_a_row_with_a_probe_but_no_state_drops_them_too(self):
        # R1 Major. `state` ABSENT is not silence when the row carries a
        # measurement: `posture()` still answers `unknown` for it, so the
        # sentence printed was #1597's reported one, verbatim.
        env = {"schema_version": 1, "host": "gemini", "probed_at": "T",
               "capabilities": {hosts.ARTIFACT_WRITE_GUARD: {
                   "by": "write-guard-armed", "detail": "round-trip denied"}}}
        line = only([x for x in host_disclosure.lines(env)
                     if hosts.ARTIFACT_WRITE_GUARD in x], "write-guard line")
        self.assertIn(hosts.UNKNOWN, line)
        self.assertNotIn("write-guard-armed", line)
        self.assertNotIn("round-trip denied", line)
        self.assertIn("no state", line)

    def test_an_explicit_null_state_behaves_the_same_as_an_absent_one(self):
        env = {"schema_version": 1, "host": "claude", "probed_at": "T",
               "capabilities": {hosts.USAGE_LEDGER: {
                   "state": None, "by": "usage-source",
                   "detail": "envelope carried `usage`; ledger live"}}}
        line = only([x for x in host_disclosure.lines(env)
                     if hosts.USAGE_LEDGER in x], "usage_ledger line")
        self.assertNotIn("usage-source", line)
        self.assertNotIn("ledger live", line)
        # ...and never "no probe ran" beside a detail describing what one found.
        self.assertNotIn("no probe ran", line)

    def test_the_foreign_report_path_renders_no_contradiction_either(self):
        # The reachable route the module docstring names: `--compare` feeds a
        # FOREIGN report, `synth.report` copies its `capabilities` map into
        # `meta.host_capabilities` verbatim, and both renderers rebuild an
        # envelope from it and call `lines()`. A fresh probe always writes
        # `state`; a stale, foreign or truncated artifact need not.
        env = {"schema_version": 1, "host": "gemini", "probed_at": "T",
               "capabilities": {hosts.ARTIFACT_WRITE_GUARD: {
                   "by": "write-guard-armed", "detail": "round-trip denied"}}}
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="target", fail_on="high",
                                     timestamp="2026-09-17T00:00:00Z",
                                     host_capabilities=env),
            findings=findings_mod.FindingSet(findings=[])))
        body = render_mod.render_summary(report)
        page = html.unescape(html_report.render(report))
        for surface, text in (("body", body), ("html", page)):
            with self.subTest(surface=surface):
                self.assertIn(hosts.ARTIFACT_WRITE_GUARD, text)
                self.assertNotIn("write-guard-armed", text)
                self.assertNotIn("round-trip denied", text)

    def test_an_untrusted_state_value_is_never_echoed_raw(self):
        # R1 Minor 1. `state` comes off a file a hostile target can pre-commit.
        # Echoing it put an unbounded, attacker-chosen string on all four
        # surfaces -- measured at 5408 characters for a 5000-character state,
        # the exact unreadability #1601 exists to fix.
        hostile = "A" * 5000
        clause = host_disclosure._probe_clause(
            {"state": hostile, "by": "b", "detail": "d"}, hosts.UNKNOWN)
        self.assertNotIn(hostile, clause)
        self.assertIn("unrecognised", clause)
        self.assertLess(len(clause), 160, clause)

    def test_a_known_state_token_is_still_named(self):
        # The other direction: the three states this module owns ARE the
        # vocabulary, and naming them is what makes the suppression legible.
        clause = host_disclosure._probe_clause(
            {"state": hosts.PROVEN, "by": "b", "detail": "d"}, hosts.UNKNOWN)
        self.assertIn(repr(hosts.PROVEN), clause)
        self.assertNotIn("unrecognised", clause)

    def test_a_row_that_records_no_state_still_says_nobody_looked(self):
        # An ABSENT state is not a contradiction -- the row claims nothing --
        # so the "no probe ran" wording it already had must survive.
        env = {"schema_version": 1, "host": "claude", "probed_at": "T",
               "capabilities": {hosts.USAGE_LEDGER: {}}}
        line = only([x for x in host_disclosure.lines(env)
                     if hosts.USAGE_LEDGER in x], "usage_ledger line")
        self.assertIn("no probe ran", line)


class TestTheInverseCarriesEqualWeight(unittest.TestCase):
    def test_an_all_proven_host_says_so_explicitly(self):
        # 5.1: absence of warnings must mean "measured and proven", never
        # "nobody looked".
        #
        # Claiming a capability is not proving it: even now that claude
        # claims `read_scope_confined` (plan 5) and, incidentally, every
        # other capability in hosts.CAPABILITIES too, `hosts.posture()` still
        # reads its state from the EVIDENCE an envelope reports, not from the
        # claim. This test needs a posture that is genuinely PROVEN across
        # all five to make ALL_PROVEN fire, which depends on a real probe run
        # rather than a claim -- so it patches in a synthetic host and hands
        # it an envelope where every capability already reports PROVEN. The
        # synthetic host is what makes the all-proven case testable without a
        # live run; it is not evidence that no real host claims the capability.
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


class TestReadinessConsumesTheSelectionLinesMakes(unittest.TestCase):
    """#1600: readiness wrote the `hosts.posture()` -> `hosts.unproven()`
    chain itself and then pulled the TEXT for each row out of `lines()` by
    prefix match. `lines()` computed the identical chain internally, so a bug
    confined to its own FILTERING was invisible to readiness -- measured:
    mutating `lines()` to emit a row per capability failed the cross-surface
    guard on stderr and body but not on readiness, 2 of 3 rather than 3 of 3.

    One selection, made once, consumed by both. These tests move it and
    require both surfaces to follow.
    """

    def _selection(self, envelope_):
        posture = hosts.posture("claude", envelope_["capabilities"])
        return [(capability, posture[capability])
                for capability in hosts.CAPABILITIES]

    def _readiness(self, envelope_):
        with mock.patch.object(host_probes, "run_probes", return_value=envelope_):
            return setup_flow._check_host_shells("claude", _runner_ok, ".")

    def test_moving_the_selection_moves_readiness_with_it(self):
        # The drift the old comment admitted, made concrete: a selection that
        # includes the PROVEN capability. `lines()` discloses five; readiness
        # re-derived four and never noticed.
        selection = self._selection(MIXED)
        with mock.patch.object(host_disclosure, "unproven_rows",
                               return_value=selection):
            gaps = host_disclosure.lines(MIXED)
            rows = self._readiness(MIXED)
        named = [c[0] for c in rows if c[0].startswith("host-capability:")]
        self.assertEqual(len(hosts.CAPABILITIES), len(gaps))
        self.assertEqual(len(gaps), len(named),
                         "readiness re-derived its own selection")
        self.assertIn("host-capability:" + hosts.ARTIFACT_WRITE_GUARD, named)

    def test_one_readiness_row_per_disclosure_line_on_the_real_posture(self):
        # The unpatched half: the two surfaces agree row-for-row, in order,
        # on the posture a real probe produces -- so the row carries the whole
        # sentence rather than a prefix match that can miss.
        gaps = host_disclosure.lines(MIXED)
        rows = [c for c in self._readiness(MIXED)
                if c[0].startswith("host-capability:")]
        self.assertEqual(len(gaps), len(rows))
        for (name, _ok, detail), line in zip(rows, gaps):
            with self.subTest(row=name):
                self.assertEqual(line, detail)
                self.assertTrue(line.startswith(name.split(":", 1)[1]))

    def test_the_headline_counts_and_names_the_same_selection(self):
        # R1 Minor 2. `headline()` counted `len(lines(...))` and separately
        # named `hosts.unproven(hosts.posture(...))` -- a second derivation of
        # one fact, inside the module the fix designated as the single place.
        # Measured: "5 of 5 NOT PROVEN ... (model_binding,
        # tool_policy_enforced, usage_ledger)" -- a count and a name-list that
        # disagree in the same sentence.
        selection = self._selection(MIXED)
        with mock.patch.object(host_disclosure, "unproven_rows",
                               return_value=selection):
            head = host_disclosure.headline(MIXED)
            count = len(host_disclosure.lines(MIXED))
        self.assertIn("%d of %d" % (count, len(hosts.CAPABILITIES)), head)
        for capability, _state in selection:
            with self.subTest(capability=capability):
                self.assertIn(capability, head)

    def test_the_headline_no_longer_writes_the_posture_chain_itself(self):
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(host_disclosure.headline))
        called = {ast.unparse(node.func) for node in ast.walk(tree)
                  if isinstance(node, ast.Call)}
        self.assertNotIn("hosts.unproven", called)
        self.assertNotIn("hosts.posture", called)
        self.assertIn("unproven_rows", called)

    def test_readiness_refuses_to_pair_two_lists_that_disagree(self):
        # R1 Minor 3. A plain `zip` truncates to the shorter sequence, so if
        # `lines()` ever grows a filter, readiness would quietly lose rows --
        # the invisible drift #1600 exists to end. `strict=True` makes it loud.
        with mock.patch.object(host_disclosure, "lines",
                               return_value=["one line only"]):
            with mock.patch.object(host_probes, "run_probes",
                                   return_value=MIXED):
                with self.assertRaises(ValueError):
                    setup_flow._check_host_shells("claude", _runner_ok, ".")

    def test_readiness_no_longer_writes_the_posture_chain_itself(self):
        # The structural half (memory: a text guard must read the AST). The
        # re-derivation is deleted, not merely shadowed: `_check_host_shells`
        # may not call `hosts.unproven` or `hosts.posture` at all.
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(setup_flow._check_host_shells))
        called = {ast.unparse(node.func) for node in ast.walk(tree)
                  if isinstance(node, ast.Call)}
        self.assertNotIn("hosts.unproven", called)
        self.assertNotIn("hosts.posture", called)
        self.assertIn("host_disclosure.unproven_rows", called)


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

    def test_every_surface_carries_the_operational_note_too(self):
        # N3: `cli_flags` is not a capability, but it IS a measured fact about
        # this host on this machine, and this module's whole premise is that
        # such a fact is said once and reaches every surface. The fixture
        # never carried the block, so nothing noticed that `meta` dropped it
        # and both report renderers rebuilt an envelope without it.
        envelope_with_fact = dict(MIXED)
        envelope_with_fact[hosts.CLI_FLAGS] = {
            hosts.OUTPUT_SCHEMA: {"flag": "--json-schema", "advertised": False,
                                  "detail": "`/usr/bin/claude --help` does not "
                                            "advertise --json-schema"}}
        for name, text in self._surfaces(envelope_with_fact).items():
            if name == "readiness":
                continue        # readiness lists capability checks, not notes
            with self.subTest(surface=name):
                self.assertIn("not schema-constrained", text)
                self.assertIn("--json-schema", text)


class TestTheConstrainedOutputDisclosure(unittest.TestCase):
    """D10 F1: when the driver omits the output schema, it says so once, on
    the surface that already speaks about this host's measured facts."""

    def _envelope(self, fact):
        body = {"schema_version": 1, "host": "claude", "probed_at": "t",
                "capabilities": {c: {"state": hosts.PROVEN, "by": "fixture",
                                     "detail": "fixture"}
                                 for c in hosts.CAPABILITIES}}
        if fact is not None:
            body[hosts.CLI_FLAGS] = {hosts.OUTPUT_SCHEMA: fact}
        return body

    def test_a_cli_without_the_flag_gets_one_line_naming_it(self):
        lines = host_disclosure.notes(self._envelope(
            {"flag": "--json-schema", "advertised": False,
             "detail": "`/usr/bin/claude --help` does not advertise --json-schema"}))
        self.assertEqual(1, len(lines))
        self.assertIn("--json-schema", lines[0])
        self.assertIn("not schema-constrained", lines[0])

    def test_an_unanswered_read_says_so_rather_than_claiming_a_refusal(self):
        lines = host_disclosure.notes(self._envelope(
            {"flag": "--json-schema", "advertised": None, "detail": "`--help` timed out"}))
        self.assertEqual(1, len(lines))
        self.assertIn("not schema-constrained", lines[0])
        self.assertIn("timed out", lines[0])

    def test_an_advertised_flag_and_an_unasked_host_say_nothing(self):
        for fact in ({"flag": "--json-schema", "advertised": True, "detail": "d"}, None):
            with self.subTest(fact=fact):
                self.assertEqual([], host_disclosure.notes(self._envelope(fact)))

    # ---- #1732: the SHAPE of an advertised flag ---------------------------
    #
    # `advertised` is a read of the flag's NAME. Run 14's CLI advertised
    # `--json-schema` and then refused what the driver put after it, at a cost
    # of 309 launches -- so once a run has spent one launch measuring the
    # shape, every surface says which of the three answers it got.

    def _shaped(self, shape, detail="the probe's own sentence"):
        return host_disclosure.notes(self._envelope(
            {"flag": "--json-schema", "advertised": True, "detail": "advertised",
             hosts.SHAPE: shape, hosts.SHAPE_DETAIL: detail}))

    def test_a_proven_shape_says_one_launch_proved_it(self):
        lines = self._shaped(hosts.SHAPE_PROVEN)
        self.assertEqual(1, len(lines))
        self.assertIn("--json-schema", lines[0])
        self.assertIn("shape proven by one launch", lines[0])

    def test_a_refuted_shape_says_what_the_run_does_instead(self):
        lines = self._shaped(hosts.SHAPE_REFUTED, "failed in 120 ms with no envelope")
        self.assertEqual(1, len(lines))
        self.assertIn("shape REFUTED by one launch", lines[0])
        self.assertIn("failed in 120 ms with no envelope", lines[0])
        self.assertIn("launch without the flag", lines[0])
        self.assertIn("fenced JSON", lines[0])

    def test_an_unmeasured_shape_says_why_and_claims_nothing(self):
        lines = self._shaped(hosts.SHAPE_UNMEASURED, "no `claude` on PATH")
        self.assertEqual(1, len(lines))
        self.assertIn("shape unmeasured: no `claude` on PATH", lines[0])
        self.assertNotIn("REFUTED", lines[0])

    def test_the_shape_never_reaches_the_capability_headline(self):
        # The flag is not a capability, so five stay five whatever the shape
        # says -- `headline` counts `lines()`, which this note is not in.
        for shape in (hosts.SHAPE_PROVEN, hosts.SHAPE_REFUTED, hosts.SHAPE_UNMEASURED):
            with self.subTest(shape=shape):
                body = self._envelope({"flag": "--json-schema", "advertised": True,
                                       "detail": "advertised", hosts.SHAPE: shape})
                self.assertEqual(host_disclosure.ALL_PROVEN, host_disclosure.headline(body))
                self.assertEqual([], host_disclosure.lines(body))
                self.assertIn("5 of 5 capabilities proven",
                              host_disclosure.unchanged_headline(body, "T"))

    def test_an_unadvertised_flag_ignores_a_shape_that_should_not_be_there(self):
        # Nothing writes one, and if something did, the advertised answer is
        # the one that already decides what reaches an argv.
        lines = host_disclosure.notes(self._envelope(
            {"flag": "--json-schema", "advertised": False, "detail": "does not advertise",
             hosts.SHAPE: hosts.SHAPE_PROVEN}))
        self.assertEqual(1, len(lines))
        self.assertIn("not schema-constrained", lines[0])


class TestTheNoteIsNotACapability(unittest.TestCase):
    """N2: `lines()` is read by three consumers as THE list of unproven
    capabilities -- `headline` counts it, `setup_flow._readiness` treats a
    non-ALL_PROVEN headline as a warning, and both report renderers list it
    under "Host capabilities". An operational fact appended to it makes a
    fully-proven host read as "1 of 5 NOT PROVEN () -- see the lines below",
    which names an empty set in the same sentence, and downgrades setup
    readiness from PASS to WARN. The fact gets its own accessor.
    """

    def _envelope(self, states, fact):
        body = {"schema_version": 1, "host": "claude", "probed_at": "T",
                "capabilities": {c: {"state": states.get(c, hosts.PROVEN),
                                     "by": "fixture", "detail": "fixture"}
                                 for c in hosts.CAPABILITIES}}
        body[hosts.CLI_FLAGS] = {hosts.OUTPUT_SCHEMA: fact}
        return body

    _LACKING = {"flag": "--json-schema", "advertised": False,
                "detail": "`/usr/bin/claude --help` does not advertise --json-schema"}

    def test_an_all_proven_host_whose_cli_lacks_the_flag_is_still_all_proven(self):
        envelope = self._envelope({}, self._LACKING)
        self.assertEqual(host_disclosure.ALL_PROVEN, host_disclosure.headline(envelope))
        self.assertEqual([], host_disclosure.lines(envelope))
        self.assertEqual(1, len(host_disclosure.notes(envelope)))

    def test_a_declared_fact_the_probe_did_not_answer_is_disclosed(self):
        # N1: silence is right for a host whose runner declares no flag and
        # for session mode, where nothing is interrogated at all and the block
        # is absent. A block that EXISTS but is missing a fact the host's
        # registry row declares is the third case: the probe did not answer
        # for a host whose runner does take the flag, so the flag will not be
        # passed and nothing else would say so.
        body = {"schema_version": 1, "host": "codex", "probed_at": "T",
                "capabilities": {c: {"state": hosts.PROVEN, "by": "fixture",
                                     "detail": "fixture"}
                                 for c in hosts.CAPABILITIES},
                hosts.CLI_FLAGS: {"some_later_fact": {"advertised": True}}}
        self.assertIn(hosts.OUTPUT_SCHEMA, hosts.spec("codex").cli_flag_facts)
        note = host_disclosure.notes(body)
        self.assertEqual(1, len(note), note)
        self.assertIn("not interrogated", note[0])
        self.assertIn("codex", note[0])

    def test_the_headline_count_equals_the_list_it_names(self):
        envelope = self._envelope({hosts.MODEL_BINDING: hosts.REFUTED}, self._LACKING)
        head = host_disclosure.headline(envelope)
        self.assertIn("1 of %d NOT PROVEN" % len(hosts.CAPABILITIES), head)
        self.assertIn("(model_binding)", head)
        self.assertEqual(1, len(host_disclosure.lines(envelope)))

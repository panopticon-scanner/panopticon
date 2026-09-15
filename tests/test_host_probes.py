import os
import tempfile
import unittest
from unittest import mock

from scripts import host_probes, hosts
import scripts.probes.claude as claude_probes
import scripts.probes.common as probes_common
from tests.probes.helpers import _shell


class TestRunProbesBuildsTheArtifact(unittest.TestCase):

    def test_every_capability_gets_a_row_even_unprobed_ones(self):
        # 5.1: "nobody looked" is written down, never inferred from an absent
        # key. read_scope_confined has a probe now too (read-guard-armed,
        # plan 5); model_binding gained one in F4 (entry-model-bound).
        # `registration_dir` is pinned
        # to an empty temp dir -- not left to default to this machine's real
        # ~/.claude/agents -- so the probe never touches live state and the
        # assertions stay broad (any real STATE) rather than depending on
        # what happens to be registered on whichever machine runs this.
        with tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            art = host_probes.run_probes("claude", target,
                                         registration_dir=registration)
            self.assertEqual(sorted(hosts.CAPABILITIES),
                             sorted(art["capabilities"]))
            for capability in hosts.CAPABILITIES:
                with self.subTest(capability=capability):
                    row = art["capabilities"][capability]
                    self.assertIn(row["state"], hosts.STATES)
                    self.assertTrue(row["detail"])

    def test_the_unprobed_capability_says_why(self):
        # Plan 5 shipped read-guard-armed for claude, so no capability is
        # probe-less by design any more (_NO_PROBE is empty); a host that
        # does not CLAIM one still gets the honest "nothing to prove" row.
        with tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes("gemini", target)
            row = art["capabilities"][hosts.READ_SCOPE_CONFINED]
            self.assertEqual(hosts.UNKNOWN, row["state"])
            self.assertIsNone(row["by"])
            self.assertIn("does not claim", row["detail"])
        self.assertEqual({}, host_probes._NO_PROBE)

    def test_an_unclaimed_capability_is_not_described_as_claimed(self):
        # Minor 1. One sentence covered both no-probe cases and said the host
        # "claims this capability's proof is not shipped yet". gemini claims
        # NOTHING, so its artifact asserted a claim it never made -- for two
        # capabilities -- in the one artifact whose entire purpose is
        # separating claims from proof.
        with tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes("gemini", target)
            unclaimed = [c for c in (hosts.ARTIFACT_WRITE_GUARD,
                                     hosts.USAGE_LEDGER)
                         if not hosts.declares("gemini", c)]
            self.assertEqual(2, len(unclaimed))   # the fixture is the real row
            for capability in unclaimed:
                with self.subTest(capability=capability):
                    detail = art["capabilities"][capability]["detail"]
                    self.assertIn("no probe", detail)
                    self.assertNotIn("claims", detail)
                    self.assertIn("does not claim", detail)

    def test_a_claimed_capability_with_no_probe_still_says_so(self):
        # The other side of the split, and what makes the assertion above
        # non-vacuous: a message that dropped the word "claims" everywhere
        # would pass that test while losing the distinction it exists to draw.
        # A host that DOES claim a capability but ships no probe for it is
        # waiting on the probe, and the artifact has to say that.
        from unittest import mock as _mock
        row = hosts.HostSpec(name="claims-but-unprobed",
                             claims=frozenset({hosts.ARTIFACT_WRITE_GUARD}))
        with _mock.patch.dict(hosts.HOSTS, {"claims-but-unprobed": row}), \
                tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes("claims-but-unprobed", target)
            detail = art["capabilities"][hosts.ARTIFACT_WRITE_GUARD]["detail"]
            self.assertIn("claims", detail)
            self.assertIn("not shipped yet", detail)

    def test_a_shadowed_target_refutes_tool_policy_even_when_shells_are_perfect(self):
        # The precedence rule, end to end: registered-shell-tools may prove it,
        # shadow-shell-scan refutes it, and refuted wins.
        from scripts import dispatch
        with tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            for role in probes_common.DRIVER_ROLES:
                role_file = dispatch.ROLE_FILES[role]
                allowed = dispatch.load_template(role_file)[0]["tool_policy"]["allowed"]
                _shell(registration,
                       dispatch.registered_agent_filename("claude", role_file),
                       allowed)
            shadow = os.path.join(target, ".claude", "agents")
            os.makedirs(shadow)
            with open(os.path.join(shadow, "panopticon-scout.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("x")
            art = host_probes.run_probes("claude", target,
                                         registration_dir=registration)
            row = art["capabilities"][hosts.TOOL_POLICY_ENFORCED]
            self.assertEqual(hosts.REFUTED, row["state"])
            self.assertEqual(probes_common.SHADOW_SHELL_SCAN, row["by"])
            self.assertIn("panopticon-scout.md", row["detail"])

    def test_the_schema_is_stamped_and_the_host_recorded(self):
        with tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            art = host_probes.run_probes("claude", target,
                                         registration_dir=registration)
            self.assertEqual(1, art["schema_version"])
            self.assertEqual("claude", art["host"])
            self.assertTrue(art["probed_at"])

    def test_capabilities_of_ignores_the_timestamp(self):
        # The comparison on resume must not fire merely because time passed.
        with tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            first = host_probes.run_probes("claude", target,
                                           registration_dir=registration)
            second = dict(first, probed_at="1999-01-01T00:00:00Z")
            self.assertEqual(host_probes.capabilities_of(first),
                             host_probes.capabilities_of(second))

    def test_capabilities_of_fails_closed_on_a_truthy_non_mapping_artifact(self):
        # R18: `(artifact or {})` only catches the FALSY case. A truthy
        # non-dict -- a non-empty list, a non-empty string, a nonzero number
        # -- sailed past that `or` unchanged and `.get("capabilities")` on it
        # raised AttributeError. The caller is
        # `driver._establish_host_posture`, feeding this `stored` --
        # `runio._load_json()`'s parse of host-capabilities.json, a file a
        # hostile target can plant or truncate -- so a crash here is a
        # mid-run traceback rather than a refusal. `hosts.posture()` and
        # `runio.host_evidence()` were both hardened against exactly this
        # shape already; this was the spot still missed. The falsy cases
        # ([], 0, "", False, None) already degraded to {} before this fix;
        # they are included here so the fix is proven not to have narrowed
        # that existing behaviour.
        for bad in (["not", "a", "dict"], "not-a-dict", 7,
                    [], 0, "", False, None):
            with self.subTest(artifact=bad):
                self.assertEqual({}, host_probes.capabilities_of(bad))

    def test_capabilities_of_fails_closed_on_a_truthy_non_mapping_entry(self):
        # Fix round 1 / F2: the outer `artifact` shape was hardened above, but
        # `(body or {}).get("state")` was left on its original guard, so a
        # WELL-FORMED artifact whose per-capability VALUE is a truthy non-dict
        # -- {"capabilities": {"tool_policy_enforced": "pwned"}} -- still
        # raised AttributeError. Same untrusted file
        # (host-capabilities.json), same direct caller
        # (driver._establish_host_posture, which reads this function rather
        # than going through hosts.posture()'s own per-entry guard). A
        # malformed entry must resolve to state `None` for that capability,
        # not raise.
        for bad in (["not", "a", "dict"], "not-a-dict", 7):
            with self.subTest(entry=bad):
                artifact = {"capabilities": {hosts.TOOL_POLICY_ENFORCED: bad}}
                self.assertEqual({hosts.TOOL_POLICY_ENFORCED: None},
                                 host_probes.capabilities_of(artifact))

    def test_a_host_the_registry_does_not_know_probes_to_all_unknown(self):
        with tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes("no-such-host", target)
            self.assertEqual({hosts.UNKNOWN},
                             {r["state"] for r in art["capabilities"].values()})
            # `state` alone cannot tell "nothing probed this" from "a probe
            # ran and landed on unknown" -- assert `by` too. The shadow scan
            # runs for every host, even one the registry has never heard of,
            # and reports that it had nowhere to look; nothing else runs.
            self.assertEqual(
                probes_common.SHADOW_SHELL_SCAN,
                art["capabilities"][hosts.TOOL_POLICY_ENFORCED]["by"])
            for capability in hosts.CAPABILITIES:
                if capability == hosts.TOOL_POLICY_ENFORCED:
                    continue
                with self.subTest(capability=capability):
                    self.assertIsNone(art["capabilities"][capability]["by"])

    def test_a_known_host_that_claims_nothing_probes_to_all_unknown(self):
        # Distinct from the unknown-host-NAME case above: "gemini" IS a real
        # row in the registry (unlike "no-such-host"), but it claims no
        # capabilities and maps no probes. This path -- a known host with an
        # empty `probes` mapping -- was otherwise never exercised.
        with tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes("gemini", target)
            self.assertIsNotNone(hosts.spec("gemini"))
            self.assertEqual({hosts.UNKNOWN},
                             {r["state"] for r in art["capabilities"].values()})
            self.assertEqual(
                probes_common.SHADOW_SHELL_SCAN,
                art["capabilities"][hosts.TOOL_POLICY_ENFORCED]["by"])
            for capability in hosts.CAPABILITIES:
                if capability == hosts.TOOL_POLICY_ENFORCED:
                    continue
                with self.subTest(capability=capability):
                    self.assertIsNone(art["capabilities"][capability]["by"])

    def test_when_both_probes_refute_the_first_recorded_wins_the_tie(self):
        # Important-2: an empty registration dir makes registered-shell-tools
        # refute, and an unreadable scope dir makes shadow-shell-scan refute
        # -- both at once. Both facts are true, and BOTH survive into
        # `detail` (joined) -- only `by` picks a single winner (the first
        # recorded, i.e. registered-shell-tools, since run_probes walks the
        # registry's `probes` mapping before the unconditional
        # shadow-shell-scan call). Fix round 1 on #1344 F3a: reporting only
        # the first probe's detail silently dropped the shadow-shell finding
        # from the artifact on exactly the machines (no registered shells)
        # where a hostile target is most likely to be reviewed -- this test
        # must fail if that regresses.
        import getpass
        if getpass.getuser() == "root":
            self.skipTest("running as root, os.listdir ignores permissions")
        with tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            # registration dir exists but is empty -> registered-shell-tools
            # refutes ("no shell at ..." for every driver role).
            shadow = os.path.join(target, ".claude", "agents")
            os.makedirs(shadow)
            os.chmod(shadow, 0o000)
            try:
                art = host_probes.run_probes("claude", target,
                                             registration_dir=registration)
            finally:
                os.chmod(shadow, 0o700)
            row = art["capabilities"][hosts.TOOL_POLICY_ENFORCED]
            self.assertEqual(hosts.REFUTED, row["state"])
            self.assertEqual(probes_common.REGISTERED_SHELL_TOOLS, row["by"])
            # The JOIN, not just the winner. Asserting only on the first
            # probe's text passes whether or not the join exists -- and
            # losing the join is precisely how a shadowing target went
            # undisclosed on a machine with no registered shells (fix round
            # 1). "shadow" appears only in shadow-shell-scan's own detail
            # ("...so shadowing could not be ruled out"), never in
            # registered-shell-tools' "no shell at ..." text, so this fails
            # if the join is reverted to reporting a single winner.
            self.assertIn("no shell at", row["detail"])
            self.assertIn("shadow", row["detail"])
            self.assertEqual(probes_common.REGISTERED_SHELL_TOOLS, row["by"])

    def test_the_registry_mapping_drives_which_capability_a_probe_lands_on(self):
        # Important-4: `HostSpec.probes` must DRIVE dispatch, not just gate a
        # hard-coded capability. Every REAL row in hosts.HOSTS happens to map
        # registered-shell-tools to tool_policy_enforced, so a hard-coded
        # capability would pass every other test in this file. A synthetic
        # row that maps it to usage_ledger instead is the only way to prove
        # the mapping is load-bearing.
        from unittest import mock
        from scripts import dispatch
        mismatched = "probe-mismatch"
        row = hosts.HostSpec(
            name=mismatched, claims=frozenset({hosts.USAGE_LEDGER}),
            shell_format="md",
            probes={hosts.USAGE_LEDGER: probes_common.REGISTERED_SHELL_TOOLS})
        with mock.patch.dict(hosts.HOSTS, {mismatched: row}), \
                tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            for role in probes_common.DRIVER_ROLES:
                role_file = dispatch.ROLE_FILES[role]
                allowed = dispatch.load_template(role_file)[0]["tool_policy"]["allowed"]
                _shell(registration,
                       dispatch.registered_agent_filename(mismatched, role_file),
                       allowed)
            art = host_probes.run_probes(mismatched, target,
                                         registration_dir=registration)
            usage = art["capabilities"][hosts.USAGE_LEDGER]
            self.assertEqual(hosts.PROVEN, usage["state"])
            self.assertEqual(probes_common.REGISTERED_SHELL_TOOLS, usage["by"])
            # And NOT under the hard-coded capability the old code used.
            tpe = art["capabilities"][hosts.TOOL_POLICY_ENFORCED]
            self.assertNotEqual(probes_common.REGISTERED_SHELL_TOOLS, tpe["by"])

    def test_an_unrecognised_probe_id_resolves_to_unknown_with_a_reason(self):
        from unittest import mock
        ghost = "probe-ghost"
        row = hosts.HostSpec(
            name=ghost, claims=frozenset({hosts.ARTIFACT_WRITE_GUARD}),
            probes={hosts.ARTIFACT_WRITE_GUARD: "no-such-probe"})
        with mock.patch.dict(hosts.HOSTS, {ghost: row}), \
                tempfile.TemporaryDirectory() as target:
            art = host_probes.run_probes(ghost, target)
            result = art["capabilities"][hosts.ARTIFACT_WRITE_GUARD]
            self.assertEqual(hosts.UNKNOWN, result["state"])
            self.assertIsNone(result["by"])
            self.assertIn("no implementation", result["detail"])

    def test_run_probes_hands_settings_path_to_both_guard_probes(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(claude_probes, "probe_write_guard_armed",
                               return_value=(hosts.PROVEN, "write-guard-armed", "x")) as w, \
             mock.patch.object(claude_probes, "probe_read_guard_armed",
                               return_value=(hosts.PROVEN, "read-guard-armed", "x")) as r:
            host_probes.run_probes("claude", d, session_root=d, settings_path="/run/host-settings.json",
                                   shadow=(hosts.UNKNOWN, None, "fixture"))
        self.assertEqual(w.call_args.kwargs.get("settings_path"), "/run/host-settings.json")
        self.assertEqual(r.call_args.kwargs.get("settings_path"), "/run/host-settings.json")

    def test_run_probes_hands_settings_path_to_the_usage_probe(self):
        # Claude family PR: the usage probe follows the mode exactly as the two
        # guard probes do (spec 5.4 applied to spec 5.5). Without this, a
        # headless run from a directory with no transcripts refuted
        # usage_ledger while its ledger was exact.
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(claude_probes, "probe_usage_source",
                               return_value=(hosts.PROVEN, "usage-source", "x")) as u:
            host_probes.run_probes("claude", d, session_root=d, settings_path="/run/host-settings.json",
                                   shadow=(hosts.UNKNOWN, None, "fixture"))
        self.assertEqual(u.call_args.kwargs.get("settings_path"), "/run/host-settings.json")


class TestTheEvidenceLoader(unittest.TestCase):

    def test_an_absent_artifact_reads_as_no_evidence(self):
        # Fail-closed by absence (9.2): {} feeds posture(), which returns
        # all-unknown, which means nothing is enforced.
        from scripts.phases import runio
        with tempfile.TemporaryDirectory() as review_root:
            self.assertEqual({}, runio.host_evidence(review_root))
            self.assertEqual(
                {hosts.UNKNOWN},
                set(hosts.posture("claude",
                                  runio.host_evidence(review_root)).values()))

    def test_a_corrupt_artifact_reads_as_no_evidence(self):
        from scripts.phases import runio
        with tempfile.TemporaryDirectory() as review_root:
            path = runio._pano(review_root, runio.HOST_CAPABILITIES)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{ this is not json")
            self.assertEqual({}, runio.host_evidence(review_root))

    def test_a_present_artifact_reads_as_its_capabilities_map_not_the_envelope(self):
        # The trap this task's brief calls out by name: `host_evidence` must
        # return the inner `capabilities` map, not the whole artifact.
        # hosts.posture() reads `evidence.get(capability)` -- handing it the
        # envelope would make every capability resolve UNKNOWN, because the
        # envelope's top level has no key named e.g. tool_policy_enforced (it
        # has "schema_version", "host", "probed_at", "capabilities" instead).
        # Neither of the two tests above can catch this: an absent or corrupt
        # artifact collapses to {} under BOTH the correct and the trap form.
        from scripts.phases import runio
        with tempfile.TemporaryDirectory() as review_root:
            artifact = {
                "schema_version": 1, "host": "claude",
                "probed_at": "2026-09-10T00:00:00Z",
                "capabilities": {
                    hosts.TOOL_POLICY_ENFORCED: {
                        "state": hosts.PROVEN, "by": "registered-shell-tools",
                        "detail": "ok"},
                },
            }
            runio._write_json(runio._pano(review_root, runio.HOST_CAPABILITIES),
                              artifact)
            evidence = runio.host_evidence(review_root)
            self.assertEqual(artifact["capabilities"], evidence)
            self.assertNotIn("schema_version", evidence)
            self.assertEqual(
                hosts.PROVEN,
                hosts.posture("claude", evidence)[hosts.TOOL_POLICY_ENFORCED])

    def test_a_truthy_non_mapping_body_reads_as_no_evidence(self):
        # I3. The docstring promised fail-closed; `or {}` delivered it only for
        # a FALSY parse. A body that parsed to a truthy non-mapping went into
        # `.get` and raised AttributeError -- measured on the pre-fix tree for
        # all three of these -- which is not failing closed, it is failing. The
        # artifact lives at a `.panopticon` path a hostile target can
        # pre-commit, and `requests.require_unenforced_ack` consumes this
        # output raw at requests.py:209.
        from scripts.phases import runio
        for body in ("[1,2]", '"hello"', "5", "true"):
            with self.subTest(body=body):
                with tempfile.TemporaryDirectory() as review_root:
                    path = runio._pano(review_root, runio.HOST_CAPABILITIES)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(body)
                    self.assertEqual({}, runio.host_evidence(review_root))

    def test_a_non_mapping_capabilities_value_reads_as_no_evidence(self):
        # The subtler half: the envelope IS a dict, so the isinstance check on
        # the body alone passes it -- and the pre-fix loader then RETURNED the
        # integer 7 as this run's evidence. `hosts.posture` would go on to call
        # `.get` on it. Both shapes have to be checked, which is why the fix is
        # two isinstance tests rather than one.
        from scripts.phases import runio
        for value in (7, "capabilities", [1, 2], None):
            with self.subTest(value=value):
                with tempfile.TemporaryDirectory() as review_root:
                    runio._write_json(
                        runio._pano(review_root, runio.HOST_CAPABILITIES),
                        {"schema_version": 1, "host": "claude",
                         "capabilities": value})
                    evidence = runio.host_evidence(review_root)
                    self.assertEqual({}, evidence)
                    # and the consumer stays fail-closed on it
                    self.assertEqual(
                        {hosts.UNKNOWN},
                        set(hosts.posture("claude", evidence).values()))


class TestTheOperationalCliFlagsBlock(unittest.TestCase):
    """D10 F1: the constrained-output answer is an OPERATIONAL fact, recorded
    beside `capabilities` rather than inside it.

    Inside, it would be drift-compared: a CLI upgraded between two invocations
    of a resumable loop would refuse the resume and discard everything already
    dispatched, for a flag that gates nothing about enforcement.
    """

    def test_the_artifact_carries_the_block_outside_capabilities(self):
        with tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            art = host_probes.run_probes("claude", target, registration_dir=registration)
        self.assertIn(hosts.CLI_FLAGS, art)
        self.assertIsInstance(art[hosts.CLI_FLAGS], dict)
        self.assertNotIn(hosts.CLI_FLAGS, art["capabilities"])
        self.assertNotIn(hosts.OUTPUT_SCHEMA, art["capabilities"])

    def test_a_flag_that_appears_or_disappears_is_not_posture_drift(self):
        before = {"schema_version": 1, "host": "claude", "probed_at": "t",
                  "capabilities": {}, hosts.CLI_FLAGS: {
                      hosts.OUTPUT_SCHEMA: {"flag": "--json-schema", "advertised": False,
                                            "detail": "d"}}}
        after = dict(before, **{hosts.CLI_FLAGS: {
            hosts.OUTPUT_SCHEMA: {"flag": "--json-schema", "advertised": True,
                                  "detail": "d"}}})
        self.assertEqual(host_probes.capabilities_of(before),
                         host_probes.capabilities_of(after))

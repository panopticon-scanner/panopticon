"""Spec 8.1: F5's entry criterion as a test, shipped AHEAD of the deletion.

    F5 may delete `--host generic` when every host remaining in HOSTS has
    tool_policy_enforced = proven and read_scope_confined = proven, and has
    artifact_write_guard either proven or explicitly bridged by
    delivery: return_json.

"proven" here is the STATIC proxy (plan 4, R-F5-3): the host CLAIMS the
capability and maps it to a SHIPPED probe id. Live proof is per run (spec
5.2); the registry cannot know it, and a claim with no probe is `unknown`
forever, which fails the bar exactly as `refuted` does (spec 8.1).

The write-guard clause is discharged by construction (R-F5-2): after F4 and
#1608 every entry's `delivery` is derived by requests.delivery() and the
bridge fires on any posture that is not PROVEN, so every driver host is
"explicitly bridged". test_the_write_guard_clause_is_bridged_by_construction
proves that once; the per-host shortfall is then the two security
capabilities. model_binding and usage_ledger are excluded by D5.
"""
import dataclasses
import glob
import os
import unittest
from unittest import mock

from scripts import dispatch, hosts, host_probes
import scripts.phases.requests as requests

SECURITY_BAR = (hosts.TOOL_POLICY_ENFORCED, hosts.READ_SCOPE_CONFINED)
DEPRECATED = "generic"


def _statically_proven(row, capability):
    return (capability in row.claims
            and host_probes.PROBE_CAPABILITY.get(row.probes.get(capability)) == capability)


def retirement_shortfalls():
    """{host: [capability, ...]} for every driver-selectable host other than the
    deprecated one that fails a security clause of spec 8.1. Empty means the
    deletion may ship."""
    out = {}
    for name in hosts.driver_hosts():
        if name == DEPRECATED:
            continue
        row = hosts.spec(name)
        missing = [c for c in SECURITY_BAR if not _statically_proven(row, c)]
        if missing:
            out[name] = missing
    return out


class TestGenericRetirementBar(unittest.TestCase):

    def test_generic_retirement_bar(self):
        # The criterion itself. While the deprecated row is present the bar is
        # not yet enforced and the row must be exactly the deprecated shape --
        # claiming nothing, still selectable (D4: ack-gated, not removed).
        # The moment the row is gone, every remaining host must clear the bar.
        examined = [n for n in hosts.driver_hosts() if n != DEPRECATED]
        self.assertTrue(examined, "a bar over zero hosts proves nothing")
        if DEPRECATED in hosts.HOSTS:
            row = hosts.spec(DEPRECATED)
            self.assertEqual(frozenset(), row.claims)
            self.assertTrue(row.driver_selectable)
        else:
            self.assertEqual({}, retirement_shortfalls(),
                             "spec 8.1: --host generic was deleted while a remaining "
                             "host falls short; #1070 must close first (spec 7.2)")

    def test_the_bar_would_refuse_the_deletion_today(self):
        # Simulate F5's one-line change on THIS base. If this ever passes the
        # bar, the shortfall pin below has moved and the deletion is due.
        table = {n: r for n, r in hosts.HOSTS.items() if n != DEPRECATED}
        with mock.patch.dict(hosts.HOSTS, table, clear=True):
            self.assertNotEqual({}, retirement_shortfalls())

    def test_todays_shortfall_is_pinned_so_it_moves_consciously(self):
        # R-F5-5 / plan 5 R-P5-3: claude clears the bar (read-guard-armed
        # shipped); gemini claims nothing. The Gemini family PR edits this
        # expectation in the same PR that ships its probes.
        shortfalls = retirement_shortfalls()
        self.assertNotIn("claude", shortfalls)
        self.assertEqual({"gemini": [hosts.TOOL_POLICY_ENFORCED, hosts.READ_SCOPE_CONFINED]},
                         shortfalls)

    def test_a_claim_without_a_shipped_probe_fails_the_bar_as_unknown(self):
        # spec 8.1's last sentence. A row that CLAIMS both security capabilities
        # but maps only one to a shipped probe falls short on the other -- a
        # claim is not evidence (spec 9.3).
        claimed = dataclasses.replace(
            hosts.spec("gemini"), name="claimant",
            claims=frozenset({hosts.TOOL_POLICY_ENFORCED, hosts.READ_SCOPE_CONFINED}),
            probes={hosts.TOOL_POLICY_ENFORCED: host_probes.REGISTERED_SHELL_TOOLS,
                    hosts.READ_SCOPE_CONFINED: "a-probe-nobody-shipped"})
        with mock.patch.dict(hosts.HOSTS, {"claimant": claimed}):
            self.assertEqual([hosts.READ_SCOPE_CONFINED],
                             retirement_shortfalls()["claimant"])

    def test_a_mismapped_probe_fails_the_bar(self):
        # Item 1: a row cannot satisfy spec 8.1 by mapping a security
        # capability to a shipped probe that measures something else. Both
        # capabilities claim the SAME probe id here -- tool_policy_enforced
        # correctly (registered-shell-tools is what it measures) and
        # read_scope_confined incorrectly (registered-shell-tools does not
        # measure it) -- so only the mismapped one falls into the shortfall.
        claimed = dataclasses.replace(
            hosts.spec("gemini"), name="claimant",
            claims=frozenset({hosts.TOOL_POLICY_ENFORCED, hosts.READ_SCOPE_CONFINED}),
            probes={hosts.TOOL_POLICY_ENFORCED: host_probes.REGISTERED_SHELL_TOOLS,
                    hosts.READ_SCOPE_CONFINED: host_probes.REGISTERED_SHELL_TOOLS})
        with mock.patch.dict(hosts.HOSTS, {"claimant": claimed}):
            self.assertEqual([hosts.READ_SCOPE_CONFINED],
                             retirement_shortfalls()["claimant"])

    def test_the_write_guard_clause_is_bridged_by_construction(self):
        # R-F5-2. Under an all-unknown posture (no evidence), every role file --
        # the four in ROLE_FILES and setup-scan -- resolves to return_json on
        # every driver host, so no host can reach a self-write it has not
        # proven it can guard. This is what makes "explicitly bridged" a
        # property of the shared layer rather than a per-row claim.
        role_files = sorted(os.path.basename(p)
                            for p in glob.glob(os.path.join(dispatch.TEMPLATE_DIR, "*.md")))
        self.assertTrue(role_files)
        driver = hosts.driver_hosts()
        self.assertTrue(driver)
        for host in driver:
            for role_file in role_files:
                with self.subTest(host=host, role_file=role_file):
                    mode, _prefix = requests.delivery(host, {}, role_file, "/abs/out.json")
                    self.assertEqual("return_json", mode)

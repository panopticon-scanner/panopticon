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
import tempfile
import unittest
from unittest import mock

from conftest import write_host_evidence
from scripts import dispatch, hosts, host_probes
import scripts.ocrdb as ocrdb
import scripts.phases.coverage as coverage
import scripts.phases.requests as requests
import scripts.phases.review as review
import scripts.phases.runio as runio
import scripts.phases.setup as setup
import scripts.phases.verify as verify
import scripts.read_guard_hook as read_guard_hook

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


class TestTheReadClauseIsProvenByConstruction(unittest.TestCase):
    """Spec §6: the read analogue of test_the_write_guard_clause_is_bridged_by_
    construction. For every template in `dispatch.TEMPLATE_DIR`, the SAME
    builder the driver dispatches through must emit an entry whose prompt
    begins with ITS OWN marker line and whose `scope` dict has exactly the
    three SCOPE_KEYS -- a sixth role added later fails this test until its
    builder carries marker+scope too (I5)."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        write_host_evidence(self.root, {c: hosts.PROVEN for c in hosts.CAPABILITIES})
        self.manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}
        self.files = ["a.py"]
        self.bundle = ocrdb.load_bundle()
        self.cell = [{"id": "F1", "code": "SEC-A1A", "severity": "HIGH", "title": "t",
                      "category": "SEC", "location": {"file": "a.py", "line": 1},
                      "description": "d"}]

    def _entries_by_role_file(self):
        """{role file: the entry ITS builder produces} -- the driver's own
        table, one builder call per template. A new template with no row here
        fails test_every_template_file_is_covered before it can hide."""
        return {
            "scout.md": coverage._scout_entry(
                self.root, self.manifest, "Auth", self.files, "claude"),
            "domain-panel.md": review._cell_entry(
                self.root, self.manifest, "Auth", "SEC", self.files, [], "claude", self.bundle),
            "domain-advisor.md": verify._verify_entry(
                self.root, self.manifest, "Auth", "SEC", self.files, self.cell, "claude",
                self.bundle, "primary"),
            "advisor.md": verify._tool_verify_entry(
                self.root, self.manifest, "q1",
                {"id": "T-1", "severity": "HIGH",
                 "location": {"file": "a.py", "line_start": 1}}, "claude"),
            "setup-scan.md": setup._setup_scan_entry(self.root, "BRIEF", "claude"),
        }

    def test_every_template_file_is_covered(self):
        # The table's keys must equal the template directory's actual files --
        # a new template file with no builder row fails HERE, loudly, instead
        # of the per-role test below silently iterating one role short.
        role_files = set(os.path.basename(p)
                         for p in glob.glob(os.path.join(dispatch.TEMPLATE_DIR, "*.md")))
        self.assertTrue(role_files)
        self.assertEqual(role_files, set(self._entries_by_role_file()))

    def test_every_role_entry_carries_its_own_marker_and_a_well_shaped_scope(self):
        for role_file, entry in self._entries_by_role_file().items():
            with self.subTest(role_file=role_file):
                self.assertTrue(entry["prompt"].startswith(
                    read_guard_hook.marker_line(entry["id"]) + "\n"))
                self.assertEqual(set(read_guard_hook.SCOPE_KEYS), set(entry["scope"]))

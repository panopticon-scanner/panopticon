"""#1519 (AGT-B1A): the write-capable-on-unenforced-host gate.

The gate reads the host's ARTIFACT_WRITE_GUARD claim -- can its hook mediate a
reviewer's Write? -- not TOOL_POLICY_ENFORCED and not a host name, because the
write-guard is a Claude Code PreToolUse hook and a host can enforce a shell's
tool list while mediating no Write at all. On `--host generic|gemini` -- both
first-class CLI
values -- a domain-panel/domain-advisor `Write` has NO mediation at all: no
registered shell, no hook, only prompt prose. A write outside review_root is
invisible to every integrity check, since validate's clean-tree diff is scoped
to review_root.

dispatch.py used to refuse this by default and record the acceptance; the flag
and its writer were retired in run-10 while write_guard_hook.py went on citing
them as the compensating control. The risk has been taken silently ever since.
"""
import json
import os
import tempfile
import unittest

from conftest import write_host_evidence
import scripts.dispatch as dispatch
from scripts import hosts
import scripts.phases.requests as requests
import scripts.phases.runio as runio
import scripts.synth.integrity as integrity

ENTRIES = [{"group": "Auth", "domain": "SEC", "enforced": False,
            "out_file": "/abs/findings-Auth-SEC.json"}]


def _manifest(host, allow=False):
    return {"host": host, "flags": {"allow_unenforced": allow}}


class TestWriteCapableRoles(unittest.TestCase):
    def test_derived_from_the_templates_not_a_hardcoded_list(self):
        expected = sorted(
            role for role, role_file in dispatch.ROLE_FILES.items()
            if "Write" in (dispatch.load_template(role_file)[0]
                           ["tool_policy"].get("allowed") or []))
        self.assertEqual(sorted(requests.write_capable_roles()), expected)

    def test_todays_write_capable_roles_are_the_two_self_writing_ones(self):
        # A canary: if a THIRD role gains Write, this fails and the gate's
        # blast radius gets re-read rather than silently widening.
        self.assertEqual(sorted(requests.write_capable_roles()),
                         ["domain_advisor", "domain_panel"])


class TestGate(unittest.TestCase):
    def _root(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: None)
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        return d

    def test_claude_is_enforced_and_writes_no_ack(self):
        root = self._root()
        # #1344 F3: the gate now reads posture(), which requires PROVEN
        # evidence, not just claude's claim -- prove the write guard.
        write_host_evidence(root, {hosts.ARTIFACT_WRITE_GUARD: hosts.PROVEN})
        self.assertIsNone(
            requests.require_unenforced_ack(root, _manifest("claude"), ENTRIES))
        self.assertFalse(os.path.exists(
            runio._pano(root, requests.UNENFORCED_ACK)))

    def test_generic_without_the_flag_refuses_loudly(self):
        root = self._root()
        with self.assertRaises(runio.DriverError) as caught:
            requests.require_unenforced_ack(root, _manifest("generic"), ENTRIES)
        message = str(caught.exception)
        self.assertIn("generic", message)
        self.assertIn("--allow-unenforced", message)
        self.assertIn("Write", message)
        # #1344 F3: the "or use one of: --host claude" hint is built from
        # hosts.declares() (a CLAIM), deliberately not posture() -- there is
        # no evidence in `root` for a host this run is not even running, so a
        # posture()-based hint would come back empty. No evidence is written
        # here, so this fails if requests.py:201 is ever swapped to posture().
        self.assertIn("--host claude", message)

    def test_gemini_without_the_flag_refuses_too(self):
        root = self._root()
        with self.assertRaises(runio.DriverError):
            requests.require_unenforced_ack(root, _manifest("gemini"), ENTRIES)

    def test_refusing_writes_no_ack(self):
        # A refusal must not leave an artifact claiming the risk was accepted.
        root = self._root()
        with self.assertRaises(runio.DriverError):
            requests.require_unenforced_ack(root, _manifest("generic"), ENTRIES)
        self.assertFalse(os.path.exists(
            runio._pano(root, requests.UNENFORCED_ACK)))

    def test_no_cells_is_not_a_risk_to_acknowledge(self):
        root = self._root()
        self.assertIsNone(
            requests.require_unenforced_ack(root, _manifest("generic"), []))

    def test_the_flag_records_the_acceptance(self):
        root = self._root()
        path = requests.require_unenforced_ack(
            root, _manifest("generic", allow=True), ENTRIES)
        with open(path, encoding="utf-8") as fh:
            ack = json.load(fh)
        self.assertTrue(ack["acknowledged"])
        self.assertEqual(ack["host"], "generic")
        self.assertFalse(ack["write_guard_covers_bash"])
        self.assertEqual(ack["plan_sha256"], integrity._plan_hash(ENTRIES))
        self.assertIn("no registered shell", ack["note"])


class TestTheAckIsReadableBySynthesize(unittest.TestCase):
    """The reader survived the retirement intact, including its #493 plan-hash
    staleness binding. The writer must satisfy it, or the restored disclosure
    reports `unenforced_acknowledged: false` and is worthless."""

    def test_round_trips_through_read_unenforced_ack(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".panopticon"), exist_ok=True)
            path = requests.require_unenforced_ack(
                root, _manifest("gemini", allow=True), ENTRIES)
            self.assertTrue(integrity.read_unenforced_ack(path))

    def test_the_hash_binding_matches_this_runs_plan(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".panopticon"), exist_ok=True)
            path = requests.require_unenforced_ack(
                root, _manifest("gemini", allow=True), ENTRIES)
            ack = integrity.read_unenforced_ack(path)
            self.assertIn(ack["plan_sha256"], {integrity._plan_hash(ENTRIES)})

    def test_an_ack_from_another_plan_does_not_match(self):
        # The staleness binding is the reason the ack is per-run, not a
        # permanent "this operator accepts the risk" file.
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".panopticon"), exist_ok=True)
            path = requests.require_unenforced_ack(
                root, _manifest("gemini", allow=True), ENTRIES)
            ack = integrity.read_unenforced_ack(path)
            other = [dict(ENTRIES[0], group="Billing")]
            self.assertNotEqual(ack["plan_sha256"], integrity._plan_hash(other))


class TestTheGateSaysWhatItActuallyTests(unittest.TestCase):
    """The AST guard in test_host_posture_wiring.py deliberately cannot see
    prose, so a docstring left describing the retired `host == "claude"` idiom
    can never be caught mechanically. It is also the most misleading kind of
    stale comment: it names a DIFFERENT capability from the one the gate reads,
    so a reader concludes the wrong thing about what a passing gate proved."""

    def test_the_docstring_describes_the_write_guard_not_a_host_name(self):
        doc = requests.require_unenforced_ack.__doc__ or ""
        self.assertNotIn('host == "claude"', doc)
        # Names the capability the gate actually reads, and says it is not the
        # tool-policy one -- the two were extensionally identical, so a reader
        # cannot infer the difference from behaviour.
        self.assertIn(hosts.ARTIFACT_WRITE_GUARD.upper(), doc)
        self.assertIn(hosts.TOOL_POLICY_ENFORCED.upper(), doc)

    def test_the_refusal_explains_write_mediation_not_tool_policy(self):
        root = tempfile.mkdtemp()
        os.makedirs(os.path.join(root, ".panopticon"), exist_ok=True)
        with self.assertRaises(runio.DriverError) as caught:
            requests.require_unenforced_ack(root, _manifest("generic"), ENTRIES)
        message = str(caught.exception)
        self.assertNotIn("tool policy", message)
        self.assertIn("Write", message)
        self.assertIn("--allow-unenforced", message)


class TestWriteGuardDocstringIsNotStale(unittest.TestCase):
    def test_it_no_longer_cites_the_retired_dispatch_flag(self):
        # The docstring claimed dispatch.py refused unenforced plans by default
        # -- retired in run-10. A compensating control named in a docstring but
        # absent from the code is worse than none: it stops people looking.
        import scripts.write_guard_hook as hook
        doc = hook.__doc__ or ""
        self.assertNotIn("``dispatch.py`` refuses", doc)
        self.assertIn("driver", doc.lower())


if __name__ == "__main__":
    unittest.main()


class TestResumeIsGatedToo(unittest.TestCase):
    def test_a_resume_without_the_flag_is_still_refused(self):
        # A resume dispatches cells too. Gating only the first write would let
        # a refused run come back without the flag and proceed.
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".panopticon"), exist_ok=True)
            plan = runio._pano(root, "dispatch-plan-driver.json")
            os.makedirs(os.path.dirname(plan), exist_ok=True)
            with open(plan, "w", encoding="utf-8") as fh:
                json.dump(ENTRIES, fh)
            with self.assertRaises(runio.DriverError):
                requests.require_unenforced_ack(root, _manifest("generic"), ENTRIES)

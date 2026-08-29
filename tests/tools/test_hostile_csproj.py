# tests/tools/test_hostile_csproj.py
"""Containment probe (P1): the hostile fixture's Exec targets run inside the
no-egress container; egress must fail and findings must still parse.

Opt-in only: set PANOPTICON_CONTAINMENT_PROBE=1 to run it. This test
actually executes evil.csproj's hostile MSBuild target (a live curl attempt
and a marker-file write) via `dotnet build`, invoked through plain
subprocess with no sandboxing of its own. It must only be run inside the
no-egress panopticon-tools container, never on a bare host or CI runner —
bare hosts/runners (e.g. ubuntu-latest, which ships the .NET SDK
preinstalled) have no `--network none` to contain the egress attempt, so
running this test there would perform the real curl.

The env var is opt-in *intent*, not proof of containment (issue #1183): a
developer or CI job that sets it on a network-enabled host would execute the
fixture's real egress. So before running the hostile build we independently
*verify* the environment is contained -- if any outbound connection succeeds
the probe refuses to run and fails loudly, rather than trusting the flag."""
import os
from _test_helpers import first
import socket
import unittest

from scripts.tools import ADAPTERS

FIXTURE = os.path.join(os.path.dirname(__file__), os.pardir,
                       "fixtures", "hostile-csproj")

# Outbound endpoints probed to confirm the environment is contained. The
# intended home is `docker run --network none`, where every connect() fails
# instantly (no route). We probe a small, diverse set of public anycast
# resolvers on both DNS (53) and HTTPS (443) so a network that filters one
# port still trips the other; a single success means egress is reachable.
_EGRESS_PROBES = (("1.1.1.1", 53), ("8.8.8.8", 53),
                  ("1.1.1.1", 443), ("8.8.8.8", 443))

_SKIP_MSG = (
    "containment probe is opt-in: it executes hostile build logic and "
    "must only run inside the no-egress panopticon-tools container "
    "(set PANOPTICON_CONTAINMENT_PROBE=1)")
_UNCONTAINED_MSG = (
    "PANOPTICON_CONTAINMENT_PROBE is set but outbound egress is reachable -- "
    "refusing to execute the hostile csproj build. This probe must run only "
    "inside a no-egress container (docker run --network none), never on a "
    "network-enabled host or CI runner.")


def _egress_reachable(timeout=2.0, connect=None):
    """Return True iff an outbound TCP connection to any probe endpoint
    succeeds -- i.e. the host can reach the network and is NOT contained.

    `connect` defaults to socket.create_connection and is injectable for
    tests. Any OSError (ENETUNREACH under --network none, timeout, refusal)
    counts as unreachable for that endpoint; the first success short-circuits.
    """
    if connect is None:
        connect = socket.create_connection
    for host, port in _EGRESS_PROBES:
        try:
            conn = connect((host, port), timeout)
        except OSError:
            continue
        else:
            try:
                conn.close()
            except OSError:
                pass
            return True
    return False


def _containment_decision(probe_enabled, egress_reachable=_egress_reachable):
    """Decide whether it is safe to run the hostile-build probe.

    Pure and injectable (no I/O of its own): `egress_reachable` is a zero-arg
    callable invoked ONLY when the probe is opted in, so a normal (opt-in off)
    run never touches the network.

    Returns None when it is safe to proceed, otherwise a (kind, message) pair:
      ("skip", ...) -- probe not opted in; skip the test.
      ("fail", ...) -- opted in but egress is reachable; refuse and fail loudly
                       (the env var is intent, not proof of containment, #1183).
    """
    if not probe_enabled:
        return ("skip", _SKIP_MSG)
    if egress_reachable():
        return ("fail", _UNCONTAINED_MSG)
    return None


class _FakeConn:
    def close(self):
        pass


class TestHostileCsproj(unittest.TestCase):
    def test_contained_build_still_yields_scs_findings(self):
        decision = _containment_decision(
            probe_enabled=os.environ.get("PANOPTICON_CONTAINMENT_PROBE") == "1")
        if decision is not None:
            kind, msg = decision
            if kind == "skip":
                self.skipTest(msg)
            self.fail(msg)  # kind == "fail": containment could not be verified
        adapter = ADAPTERS["roslyn-secguard"]
        if not os.path.isdir(FIXTURE):
            self.skipTest("hostile-csproj fixture missing")
        if not adapter.is_applicable(FIXTURE):
            self.skipTest("no csproj visible")
        try:
            raw, rc = adapter.invoke(FIXTURE)
        except FileNotFoundError:
            self.skipTest("dotnet not installed on this host")
        self.assertIn(rc, (0, 1))
        findings = adapter.parse(raw, "g")
        self.assertTrue(findings, "expected SCS findings from the hostile csproj")
        # Every finding is SCS (Task 3 filter); the Exec noise never lands.
        for f in findings:
            self.assertTrue(
                f["tool_evidence"]["rule_id"].startswith("SCS"))


class TestContainmentGuard(unittest.TestCase):
    """The containment guard must refuse to execute the hostile build unless
    egress is actually blocked; the env-var opt-in alone is not trusted (#1183)."""

    def test_not_opted_in_skips_without_probing_egress(self):
        def _egress():
            raise AssertionError("egress must not be probed when opt-in is off")
        decision = _containment_decision(probe_enabled=False,
                                         egress_reachable=_egress)
        self.assertIsNotNone(decision)
        self.assertEqual(first(decision), "skip")

    def test_opted_in_but_egress_reachable_refuses(self):
        decision = _containment_decision(probe_enabled=True,
                                         egress_reachable=lambda: True)
        self.assertIsNotNone(decision)
        self.assertEqual(first(decision), "fail")
        self.assertIn("egress", decision[1].lower())

    def test_opted_in_and_contained_is_safe(self):
        self.assertIsNone(_containment_decision(probe_enabled=True,
                                                egress_reachable=lambda: False))

    def test_egress_reachable_true_on_first_success_and_short_circuits(self):
        attempts = []
        def _connect(addr, timeout):
            attempts.append(addr)
            return _FakeConn()
        self.assertTrue(_egress_reachable(connect=_connect))
        self.assertEqual(len(attempts), 1)  # stopped at the first reachable endpoint

    def test_egress_reachable_false_when_every_connect_fails(self):
        attempts = []
        def _connect(addr, timeout):
            attempts.append(addr)
            raise OSError("network unreachable")
        self.assertFalse(_egress_reachable(connect=_connect))
        self.assertEqual(len(attempts), len(_EGRESS_PROBES))  # exhausted every probe


if __name__ == "__main__":
    unittest.main()

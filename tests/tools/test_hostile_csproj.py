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

One lane does opt in (#1655, owner ruling 2026-09-22): the `containment`
job in `.github/workflows/adapter-integration.yml`, daily at 08:00 UTC
and on workflow_dispatch, which runs this file inside the fixtures image
with `docker run --network none` -- the opt-in and the containment set
together, by the same command. Nothing else in the fleet sets the flag,
and `tests/test_workflow_pins.py` pins both halves of that sentence.

The env var is opt-in *intent*, not proof of containment (issue #1183): a
developer or CI job that sets it on a network-enabled host would execute the
fixture's real egress. So before running the hostile build we independently
*verify* the environment is contained -- if any outbound connection succeeds
the probe refuses to run and fails loudly, rather than trusting the flag."""
import os
from _test_helpers import first
import shutil
import socket
import tempfile
import unittest

from _test_helpers import REPO_FIXTURES, fixture_path, skip_or_fail

from scripts.tools import ADAPTERS

# Two roots (#1528), image first. They are NOT the same tree: Dockerfile.fixtures
# copies this fixture in and `dotnet restore`s it, and roslyn-secguard refuses a
# C# target with no restore output -- so the bare checkout is inapplicable and
# the image's copy is the one that can be scanned (#1655). Falls back to the
# repo path so an absent fixture still has a name to report.
_FIXTURE_NAME = "hostile-csproj"
FIXTURE = (fixture_path(_FIXTURE_NAME)
           or os.path.join(REPO_FIXTURES, _FIXTURE_NAME))

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


# --- #1655: four guards, and nowhere they are all required to be met --------
# `test_contained_build_still_yields_scs_findings` below is the only test that
# invokes an adapter on a hostile project, and `adapter.invoke` sits downstream
# of four skips: the opt-in, the fixture, adapter applicability, and `dotnet`.
# Every other test in this file injects the containment outcome or fakes the
# connection, so an ordinary run goes green on the mocks and the
# containment-sensitive build path is never exercised.
#
# The opt-in is not a defect -- this test EXECUTES evil.csproj's hostile
# MSBuild target, and forcing that wherever the integration job runs is exactly
# what must not happen. What the guard below adds is the other half: WHERE
# something has opted in, the remaining three preconditions are a FAILURE
# rather than three more skips, so the probe cannot report green having run
# nothing in the one environment built to run it. Since the owner ruling that
# environment exists in CI as well as on a developer's box: the `containment`
# lane sets the flag, so these three guards are live there.
CONTAINMENT_PROBE_ENV = "PANOPTICON_CONTAINMENT_PROBE"

# Exactly one CI lane sets the opt-in: `adapter-integration.yml`'s
# `containment` job, whose `docker run` carries both `--network none` and the
# flag. Its sibling `integration` job runs this same file WITHOUT the flag, so
# the probe skips there -- the correct answer for a lane that has a network.
# Which lanes opt in, and that every one of them is offline on the same
# command line, are both PINNED by tests/test_workflow_pins.py
# (EXPECTED_CONTAINMENT_LANES, `uncontained_lanes()`) -- the fleet is read with
# PyYAML there because this tree also runs inside the fixtures image, which
# carries none. If the lane moves, is renamed or loses either control, those
# pins fail and this sentence has to be rewritten with them.
_NO_LANE = (
    "%s is not 1 here, so the containment probe is not opted in (#1655). The "
    "lane that does opt in is the `containment` job in "
    ".github/workflows/adapter-integration.yml (daily 08:00 UTC, plus "
    "workflow_dispatch), which runs this file with `docker run --network "
    "none` inside the fixtures image. To run it by hand, do the same: set the "
    "flag inside the no-egress panopticon-tools container; the guard then "
    "requires the fixture, the adapter and dotnet rather than skipping on "
    "them." % CONTAINMENT_PROBE_ENV)


def unmet_preconditions(environ=None, fixture=FIXTURE, adapters=None,
                        which=shutil.which):
    """Every reason the hostile build would NOT execute, in guard order.

    Pure apart from the injectable lookups, so the rule can be exercised on
    both answers without a container, a fixture or a .NET SDK -- and without
    ever reaching `adapter.invoke`, which is the thing that runs hostile build
    logic. Applicability is only asked when the fixture is there; asking an
    adapter about a directory that does not exist reports the wrong guard.
    """
    environ = os.environ if environ is None else environ
    adapters = ADAPTERS if adapters is None else adapters
    unmet = []
    if environ.get(CONTAINMENT_PROBE_ENV) != "1":
        unmet.append("%s is not 1 -- the containment probe is not opted in"
                     % CONTAINMENT_PROBE_ENV)
    if not os.path.isdir(fixture):
        unmet.append("the hostile-csproj fixture is missing: %s" % fixture)
    elif not adapters["roslyn-secguard"].is_applicable(fixture):
        unmet.append("roslyn-secguard is not applicable to %s" % fixture)
    if which("dotnet") is None:
        unmet.append("dotnet is not on PATH")
    return unmet


class _AlwaysApplicable:
    def is_applicable(self, target):
        return True


class _NeverApplicable:
    def is_applicable(self, target):
        return False


class TestTheContainmentProbeIsNotDecorativeWhereItRuns(unittest.TestCase):
    """#1655. The rule runs unconditionally on scratch inputs; the APPLICATION
    of it runs wherever the opt-in is set, and fails there rather than adding
    a fifth skip."""

    def test_every_guard_the_containment_test_stands_behind_is_listed(self):
        unmet = unmet_preconditions(environ={}, fixture="/no/such/fixture",
                                    which=lambda _name: None)
        self.assertEqual(3, len(unmet), unmet)
        joined = " | ".join(unmet)
        self.assertIn(CONTAINMENT_PROBE_ENV, joined)
        self.assertIn("fixture is missing", joined)
        self.assertIn("dotnet", joined)

    def test_applicability_is_the_fourth_guard_once_the_fixture_is_there(self):
        with tempfile.TemporaryDirectory() as present:
            unmet = unmet_preconditions(
                environ={CONTAINMENT_PROBE_ENV: "1"}, fixture=present,
                adapters={"roslyn-secguard": _NeverApplicable()},
                which=lambda _name: "/usr/bin/dotnet")
        self.assertEqual(1, len(unmet), unmet)
        self.assertIn("not applicable", unmet[0])

    def test_nothing_is_unmet_when_every_precondition_holds(self):
        with tempfile.TemporaryDirectory() as present:
            self.assertEqual([], unmet_preconditions(
                environ={CONTAINMENT_PROBE_ENV: "1"}, fixture=present,
                adapters={"roslyn-secguard": _AlwaysApplicable()},
                which=lambda _name: "/usr/bin/dotnet"))

    def test_only_the_exact_opt_in_counts(self):
        with tempfile.TemporaryDirectory() as present:
            for value in ("true", "yes", "", "0", "2"):
                with self.subTest(value=value):
                    unmet = unmet_preconditions(
                        environ={CONTAINMENT_PROBE_ENV: value}, fixture=present,
                        adapters={"roslyn-secguard": _AlwaysApplicable()},
                        which=lambda _name: "/usr/bin/dotnet")
                    self.assertEqual(1, len(unmet), unmet)
                    self.assertIn(CONTAINMENT_PROBE_ENV, unmet[0])

    def test_the_hostile_build_really_runs_wherever_it_is_opted_in(self):
        if os.environ.get(CONTAINMENT_PROBE_ENV) != "1":
            self.skipTest(_NO_LANE)  # strict-skip-exempt: names the lane; see _NO_LANE
        unmet = unmet_preconditions()
        self.assertEqual(
            [], unmet,
            "%s=1 says this environment is meant to execute the hostile "
            "build, but the containment test would skip on:\n  %s\nA probe "
            "that skips where it is opted in is decorative (#1655)."
            % (CONTAINMENT_PROBE_ENV, "\n  ".join(unmet)))


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
                # The containment probe is a deliberate opt-in
                # (PANOPTICON_CONTAINMENT_PROBE=1) because it EXECUTES hostile
                # build logic and must only run inside the no-egress container.
                # Requiring it under integration strictness would force that
                # execution wherever the integration job runs.
                self.skipTest(msg)  # strict-skip-exempt: opt-in containment probe
            self.fail(msg)  # kind == "fail": containment could not be verified
        adapter = ADAPTERS["roslyn-secguard"]
        if not os.path.isdir(FIXTURE):
            skip_or_fail(self, "hostile-csproj fixture missing")
        if not adapter.is_applicable(FIXTURE):
            skip_or_fail(self, "no csproj visible")
        try:
            raw, rc = adapter.invoke(FIXTURE)
        except FileNotFoundError:
            skip_or_fail(self, "dotnet not installed on this host")
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

"""#1515: the unit suite must not launch scanner containers.

`tests/test_driver.py`'s lifecycle tests call `driver.run(...)` without
`--no-tools`, so the run advances into `tools_execute` -> `run_tools`. On the
standard `ubuntu-latest` runner the tools image is absent, `docker_available()`
is false, and the phase no-ops. On a workstation that has built the image it is
TRUE, and a plain `pytest tests/` launches real `docker run --memory 6g --cpus 4`
scanners. A `docker` shim on PATH logged four live launches from one
`tests/test_driver.py` run on main @ 8f871eb.

Two costs, and the second is the one that matters: the unit suite is a resource
event locally, and -- because the two environments take different branches --
the thing CI proves green is not the thing anyone ran. A suite whose execution
path depends on what is installed on the machine is not a regression net.

The fix has two halves, because there are three doors to the daemon and one of
them is not reachable from Python at all:

1. An autouse fixture in `tests/conftest.py` refuses the IN-PROCESS gates --
   `run_tools.docker_available` and `setup_flow`'s preflight probe -- for every
   test not marked `@pytest.mark.docker`.
2. `--no-tools` on the driver lifecycle test that reaches `tools_execute`,
   because that phase spawns `run_tools.py` as a CHILD process and a monkeypatch
   does not cross a process boundary. That door is where the four confirmed
   launches came from; the fixture alone would not have closed them.

This module is the contract for both. Without these assertions they are
invisible plumbing that a later refactor could drop silently, and nothing would
fail until a workstation started pulling 6GB images again.
"""
import os
import tempfile
import unittest
from unittest import mock

import pytest

import scripts.phases.tools as tools_phase
import scripts.run_tools as run_tools
from conftest import REAL_DOCKER_AVAILABLE


class _Res:
    def __init__(self, returncode):
        self.returncode = returncode


def test_the_docker_marker_is_registered(pytestconfig):
    # An unregistered mark is a warning today; under `-W error` it is a
    # collection failure, and `--strict-markers` turns every typo into one.
    # The escape hatch has to be declared to be usable.
    assert any(m.split(":", 1)[0] == "docker"
               for m in pytestconfig.getini("markers")), \
        "the `docker` marker is not declared in pyproject.toml"


class TestUnitSuiteCannotReachTheDaemon(unittest.TestCase):
    def test_the_docker_gate_reads_unavailable(self):
        # Deterministic on every machine: this is the assertion that used to
        # depend on whether `panopticon-tools` happened to be built locally.
        self.assertFalse(run_tools.docker_available())

    def test_an_injected_runner_still_reaches_the_real_probe(self):
        # `tests/test_run_tools_docker.py` unit-tests the gate itself by handing
        # it a fake runner -- that never touches the daemon, so the refusal must
        # not swallow it. A blanket stub would make those tests assert against
        # the stub instead of the code they exist to cover.
        self.assertTrue(
            run_tools.docker_available(runner=lambda *a, **k: _Res(0)))
        self.assertFalse(
            run_tools.docker_available(runner=lambda *a, **k: _Res(1)))


class TestTheEscapeHatch(unittest.TestCase):
    """A test that genuinely needs the daemon opts in with
    `@pytest.mark.docker` and gets the real gate back."""

    @pytest.mark.docker
    def test_a_marked_test_keeps_the_real_gate(self):
        # Assert on the FUNCTION, never on its answer: whether a daemon is
        # actually up is exactly the machine-dependent fact this module exists
        # to keep out of the suite.
        self.assertIs(run_tools.docker_available, REAL_DOCKER_AVAILABLE)

    def test_an_unmarked_test_does_not(self):
        self.assertIsNot(run_tools.docker_available, REAL_DOCKER_AVAILABLE)


class TestTheFixtureCannotCrossAProcessBoundary(unittest.TestCase):
    """Where the four confirmed container launches actually came from.

    `phases/tools.py` runs the scanners by spawning `run_tools.py` as a CHILD
    process, and a conftest monkeypatch does not cross a process boundary. So
    the autouse fixture -- which closes the in-process gate `phases/coverage.py`
    and friends consult -- CANNOT close this one. `--no-tools` on the driver
    tests that do not assert scanner behaviour is the only defence the unit
    suite has here, which is why it is a requirement and not a belt-and-braces
    extra.

    Pinned so the next reader does not assume the fixture is total. If the tools
    phase ever runs in-process, these tests fail and the fixture takes over.
    """

    def _root(self, d):
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        return d

    def test_the_tools_phase_spawns_run_tools_as_a_child(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(tools_phase.runio, "_run_child") as spawn:
                spawn.return_value = mock.Mock(returncode=0, stderr="")
                tools_phase.tools_execute(self._root(d),
                                          {"flags": {}, "run_id": "r"})
            spawn.assert_called_once()
            argv = spawn.call_args.args[0]
        self.assertTrue(any("run_tools.py" in str(a) for a in argv), argv)

    def test_no_tools_returns_before_the_spawn(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(tools_phase.runio, "_run_child") as spawn:
                res = tools_phase.tools_execute(
                    self._root(d), {"flags": {"tools": False}, "run_id": "r"})
            spawn.assert_not_called()
        self.assertIn("skipped", res.message)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

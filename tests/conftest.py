"""Make panopticon's packages importable from any test without per-file
sys.path juggling (#547).

pytest imports this before collecting tests, so a test can do
`import scripts.tools.base` (needs skill/ on the path), `import evidence`
(skill/scripts/), or `import file_issues` (repo-root scripts/) with no
boilerplate. Previously 18 tests/tools/ files each repeated the same
`sys.path.insert(...)` line.
"""
import os
import sys

_TESTS = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_TESTS)
FIXTURE_ROOT = os.environ.get("FIXTURE_ROOT", os.path.join(_TESTS, "fixtures"))

# Public path anchors (#run7 TST-G1B): tests that need the repo or skill root
# previously each re-derived it via nested dirname(__file__) / os.pardir. Import
# these instead: `from conftest import REPO_ROOT` / `SKILL_ROOT`.
REPO_ROOT = _REPO
SKILL_ROOT = os.path.join(_REPO, "skill")
for _p in reversed((_TESTS,
                    os.path.join(_REPO, "skill"),
                    os.path.join(_REPO, "skill", "scripts"),
                    os.path.join(_REPO, "scripts"))):
    if _p in sys.path:
        sys.path.remove(_p)
    sys.path.insert(0, _p)

# Bind tests/tools as the bare `tools` package NOW, while tests/ is at
# sys.path[0]. Entry scripts (skill/scripts/synthesize.py, driver.py,
# score_gate.py) each `sys.path.insert(0, skill/scripts)` when imported, after
# which skill/scripts/tools/ would shadow tests/tools/ for every later
# `from tools.git_repo import ...` (test_diff_map, discovery_test_helpers,
# test_driver). Collection order used to hide this -- tests/synth/ (WS-0 S4)
# sorts before tests/test_*.py and imports scripts.synthesize at module scope,
# so the suite must not depend on which file imports an entry script first.
import tools  # noqa: E402,F401

# --- #1515: no live scanner containers from the unit suite -------------------
# driver.run() advances into tools_execute unless --no-tools; run_tools then
# asks docker_available() whether to launch `docker run --memory 6g --cpus 4`
# scanners. On ubuntu-latest the image is absent so the answer is no; on a
# workstation that has built it the answer is YES, and a plain `pytest tests/`
# becomes a resource event running a DIFFERENT branch from the one CI proves.
# Refuse the daemon by default and make reaching it an explicit, marked choice.
import subprocess  # noqa: E402

import pytest  # noqa: E402

import scripts.run_tools as _run_tools  # noqa: E402
import scripts.setup_flow as _setup_flow  # noqa: E402
from scripts import hosts as _hosts  # noqa: E402
from scripts.phases import runio as _runio  # noqa: E402


# --- #1344 F3: consumers now read posture(), which is proof, not a claim -----
# Every phase test that built a "claude" (or synthetic-probe) manifest and
# expected `enforced: True` / a write-guard early-return / a usage collection
# used to get that answer from the bare claim (`hosts.declares`). Now it also
# needs evidence a probe actually proved the capability, or `posture()`
# reports UNKNOWN and every one of those sites goes the other way. This is the
# one place that writes it, so every phase test states the same fixture the
# same way rather than five near-identical inline JSON blobs.
def write_host_evidence(review_root, states, host="claude"):
    """A host-capabilities.json proving exactly `states` (a
    {capability: state} mapping); every other capability is UNKNOWN. Lands
    wherever `runio.host_evidence(review_root)` will look for it -- the
    per-run folder once a manifest is on disk, the flat top-level path
    otherwise -- so a test needs no manifest just to prove a capability."""
    capabilities = {name: {"state": states.get(name, _hosts.UNKNOWN),
                           "by": "fixture", "detail": "fixture"}
                    for name in _hosts.CAPABILITIES}
    return _runio._write_json(
        _runio._pano(review_root, _runio.HOST_CAPABILITIES),
        {"schema_version": 1, "host": host, "probed_at": "2026-09-10T00:00:00Z",
         "capabilities": capabilities})

REAL_DOCKER_AVAILABLE = _run_tools.docker_available


def _refuse_docker(image="panopticon-tools", runner=None):
    """Answer "no docker here" -- unless the caller injected its own runner.

    tests/test_run_tools_docker.py unit-tests this gate by handing it a fake
    runner, which never touches the daemon. A blanket stub would make those
    tests assert against the stub instead of the code they exist to cover, so
    an explicit runner is delegated to the real probe and everything else --
    every production call site, which passes none -- is refused.
    """
    if runner is not None:
        return REAL_DOCKER_AVAILABLE(image, runner=runner)
    return False


# A SECOND door, found by the shim proof rather than by reading: setup_flow's
# preflight probes `docker version` (and then the tools image) through
# `setup_readiness(..., runner=subprocess.run)`. Tests that inject a runner are
# testing the check and never touch the daemon; tests that leave the default in
# place were probing the real one, so the preflight reported "ok" on a
# workstation and "unavailable" in CI -- machine-dependent again, in the one
# phase whose whole job is to report what is installed.
REAL_CHECK_DOCKER = _setup_flow._check_docker


class _RefusedProbe:
    returncode, stdout, stderr = 1, "", ""


def _refuse_setup_docker(runner):
    """Swap ONLY the un-injected default; an explicit runner is the caller's."""
    if runner is subprocess.run:
        runner = lambda *a, **k: _RefusedProbe()   # noqa: E731
    return REAL_CHECK_DOCKER(runner)


@pytest.fixture(autouse=True)
def _no_live_scanner_containers(request, monkeypatch):
    if "docker" in request.keywords:
        return                      # opted in with @pytest.mark.docker
    monkeypatch.setattr(_run_tools, "docker_available", _refuse_docker)
    monkeypatch.setattr(_setup_flow, "_check_docker", _refuse_setup_docker)

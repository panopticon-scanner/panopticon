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
import shlex
import tempfile

import pytest


def _refuse_repository_temp_root(path, source):
    """Keep disposable test roots outside checkouts without executing Git.

    Resolve symlinks first; a .git directory and a linked-worktree gitfile both
    establish a boundary. Do this before HOME setup or test collection: a
    nominal non-Git fixture inside a checkout otherwise discovers its ancestor.
    """
    if not path:
        return
    resolved = os.path.realpath(os.path.abspath(os.fspath(path)))
    ancestor = resolved
    while True:
        if os.path.lexists(os.path.join(ancestor, ".git")):
            raise pytest.UsageError(
                "%s resolves inside a Git checkout (%s). Use an external temp "
                "directory for TMPDIR and --basetemp before running tests."
                % (source, resolved))
        parent = os.path.dirname(ancestor)
        if parent == ancestor:
            break
        ancestor = parent


def _check_explicit_basetemp(arguments):
    for index, argument in enumerate(arguments):
        if argument.startswith("--basetemp="):
            _refuse_repository_temp_root(argument.split("=", 1)[1], "--basetemp")
        elif argument == "--basetemp" and index + 1 < len(arguments):
            _refuse_repository_temp_root(arguments[index + 1], "--basetemp")


# Import-time checks precede all registry/HOME setup below. The parsed option
# hook also covers addopts from config files and pytest.main([...]) callers.
_refuse_repository_temp_root(tempfile.gettempdir(), "effective tempfile root")
_check_explicit_basetemp(sys.argv[1:])
_check_explicit_basetemp(shlex.split(os.environ.get("PYTEST_ADDOPTS", "")))


def pytest_configure(config):
    _refuse_repository_temp_root(config.getoption("basetemp"), "--basetemp")


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

# --- Family guardrails section 3, Suite: "tests use temp dirs only ... never
# a home directory". The session-mode usage probe resolves
# `~/.claude/projects/<slug>` whenever a caller passes no `home=`, and four
# `run_probes("claude", ...)` calls in the wiring tests did exactly that -- so
# on a workstation whose real home held transcripts for the test's cwd the
# probe answered differently from CI (found by the Claude family PR's review
# workflow). One throwaway home for the whole process rather than four
# `home=` arguments: a future caller cannot reach the real one by forgetting.
# Set HERE, before `scripts.hosts` below expands `~` into the registry's
# registration dirs at import, so those import-time expansions and every
# test-time `expanduser("~")` name the same empty directory (a per-test
# fixture would leave the registry pointing at the real home and the two
# disagreeing). Tests that commit to temp repos set their identity with
# `-c user.name=`, so the operator's global config going out of reach
# changes nothing they measure.
#
# Minted ONCE per process and handed on through the environment: this file
# is imported twice -- as pytest's conftest module and, because tests/ is on
# sys.path, as `conftest` by the tests that `from conftest import
# write_host_evidence` -- and a second mkdtemp here moved HOME out from
# under the registry the first import had already expanded.
import atexit  # noqa: E402
import shutil  # noqa: E402

_TEST_HOME = os.environ.get("PANOPTICON_TEST_HOME")
if not _TEST_HOME:
    _TEST_HOME = tempfile.mkdtemp(prefix="panopticon-test-home-")
    os.environ["PANOPTICON_TEST_HOME"] = _TEST_HOME
    atexit.register(shutil.rmtree, _TEST_HOME, ignore_errors=True)
os.environ["HOME"] = _TEST_HOME
os.environ["USERPROFILE"] = _TEST_HOME        # Windows' spelling of the same thing

# The run_tools unit seams inject a runner and therefore need no Docker
# installation, but executable-provenance resolution deliberately happens
# before that seam. Give hosts without a Docker CLI one harmless external
# candidate so those tests remain about their injected runner. Hostile-PATH
# boundary tests replace PATH explicitly and therefore still exercise the real
# resolver refusal.
if shutil.which("docker") is None:
    _TEST_BIN = tempfile.mkdtemp(prefix="panopticon-test-bin-")
    atexit.register(shutil.rmtree, _TEST_BIN, ignore_errors=True)
    _TEST_DOCKER = os.path.join(_TEST_BIN, "docker")
    with open(_TEST_DOCKER, "w", encoding="utf-8") as _fh:
        _fh.write("#!/bin/sh\nexit 99\n")
    os.chmod(_TEST_DOCKER, 0o700)
    os.environ["PATH"] = os.pathsep.join([_TEST_BIN, os.environ.get("PATH", "")])

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


import scripts.codex_host as _codex_host  # noqa: E402
import scripts.run_tools as _run_tools  # noqa: E402
import scripts.probes.kimi as _kimi_probes  # noqa: E402
import scripts.runners.base as _runners_base  # noqa: E402
import scripts.runners.claude as _claude_runner  # noqa: E402
import scripts.runners.codex as _codex_runner  # noqa: E402
import scripts.runners.kimi as _kimi_runner  # noqa: E402
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
def write_host_evidence(review_root, states, host="claude", cli_flags=None):
    """A host-capabilities.json proving exactly `states` (a
    {capability: state} mapping); every other capability is UNKNOWN. Lands
    wherever `runio.host_evidence(review_root)` will look for it -- the
    per-run folder once a manifest is on disk, the flat top-level path
    otherwise -- so a test needs no manifest just to prove a capability.

    `cli_flags` (D10 F1) seeds the OPERATIONAL block beside `capabilities` --
    e.g. `{hosts.OUTPUT_SCHEMA: {"flag": "--json-schema", "advertised": True}}`.
    Omitted by default, which is the fail-safe "nobody asked the CLI" state
    every entry builder must read as "do not pass a schema"."""
    capabilities = {name: {"state": states.get(name, _hosts.UNKNOWN),
                           "by": "fixture", "detail": "fixture"}
                    for name in _hosts.CAPABILITIES}
    return _runio._write_json(
        _runio._pano(review_root, _runio.HOST_CAPABILITIES),
        {"schema_version": 1, "host": host, "probed_at": "2026-09-10T00:00:00Z",
         "capabilities": capabilities, _hosts.CLI_FLAGS: cli_flags or {}})

REAL_DOCKER_AVAILABLE = _run_tools.docker_available


def _refuse_docker(image="panopticon-tools", runner=None, target=None):
    """Answer "no docker here" -- unless the caller injected its own runner.

    tests/test_run_tools_docker.py unit-tests this gate by handing it a fake
    runner, which never touches the daemon. A blanket stub would make those
    tests assert against the stub instead of the code they exist to cover, so
    an explicit runner is delegated to the real probe and everything else --
    every production call site, which passes none -- is refused.
    """
    if runner is not None:
        return REAL_DOCKER_AVAILABLE(image, runner=runner, target=target)
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
    """Swap ONLY the un-injected default; an explicit runner is the caller's.

    `setup_readiness` now resolves its un-injected default from
    `setup_flow.DEFAULT_RUNNER`, which the launch guard below has already
    replaced with the refusal -- so "un-injected" is either of those two, and
    reading only the first would hand the docker probe a launcher that raises.
    """
    if runner is subprocess.run or runner is _refuse_host_launch:
        runner = lambda *a, **k: _RefusedProbe()   # noqa: E731
    return REAL_CHECK_DOCKER(runner)


@pytest.fixture(autouse=True)
def _no_live_scanner_containers(request, monkeypatch):
    if "docker" in request.keywords:
        return                      # opted in with @pytest.mark.docker
    monkeypatch.setattr(_run_tools, "docker_available", _refuse_docker)
    monkeypatch.setattr(_setup_flow, "_check_docker", _refuse_setup_docker)


# --- #1637 P08: the readiness phase's docker probe ---------------------------
# The readiness phase reuses `setup_flow._check_docker`, so the autouse fixture
# above already refuses it for every test that says nothing -- which is the
# right default and the wrong answer for the dozens of lifecycle tests that
# need the engine to get PAST readiness and on to the phase they are about.
# Those state the environment they mean with this fake runner, which answers
# the two probe argvs and touches no daemon. Handed to `readiness_checks.DOCKER_RUNNER`
# (a module attribute, so one patch reaches it), never to PATH: a `docker` shim
# proof over the whole suite must stay at zero lines.
class _DockerProbe:
    def __init__(self, returncode):
        self.returncode, self.stdout, self.stderr = returncode, "", ""


def docker_probe_runner(daemon=0, image=0):
    """A fake `subprocess.run` answering readiness's two docker probes.

    Defaults to "daemon up, image present". Pass a non-zero `image` for the
    run-13 environment (Docker fine, `panopticon-tools` absent) and a non-zero
    `daemon` for no Docker at all.
    """
    def runner(cmd, **_kwargs):
        if list(cmd[:3]) == ["docker", "image", "inspect"]:
            return _DockerProbe(image)
        return _DockerProbe(daemon)
    return runner


# --- #1344: no live host-CLI launches from the unit suite --------------------
# The guardrails say the suite must never start a host binary, and until now
# that was per-test discipline only: the launch seams defaulted to
# subprocess.run bound as a DEFAULT ARGUMENT, unreachable by a patch, and
# probes.codex._codex_measure mapped any exception to UNKNOWN -- so a test that
# did reach a live CLI and failed would still have passed. Discipline then
# failed twice more: `setup_flow.readiness` probes `codex --version` through
# the same unreachable default (N-M3), and `runners/claude.py` binds its
# launcher the same way.
#
# So the guard is a LIST OF SEAMS, not a list of hosts: every module that
# starts a host CLI exposes a module-level DEFAULT_RUNNER, and each is swapped
# here for a refusal whose own type the probes re-raise rather than swallowing.
# A test that means to exercise a launch injects its own runner= and never sees
# this. tests/test_host_launch_guard.py walks the AST for modules that launch a
# registered host's CLI and fails if one of them is missing from this list, so
# a seventh seam cannot be added silently.
#
# The Claude family PR (#1618) arrived at the same construction for its own
# seam and shipped a claude-only autouse fixture beside it; that fixture is
# FOLDED IN HERE rather than kept, because `_claude_runner` is already in the
# tuple below and two autouse fixtures patching one attribute means whichever
# runs last silently decides what the guarantee is. Its refusal text is the
# one kept -- it names the rule and both ways out, which "test tried to launch
# a real host CLI" did not -- with the binary read off the argv the caller was
# about to spawn rather than hard-coded to `claude`, since one refusal now
# answers for six seams and three different binaries. Both families read the
# text back: tests/runners/test_claude.py off the failed RunResult,
# tests/test_host_probes.py off the raised LaunchRefused.
#
# The kimi family PR (#1620) shipped the same construction a third time, as
# `_no_live_kimi_launches`; it is folded in the same way and for the same
# reason. Its two seams join the tuple: `runners/kimi.py`, and the kimi probe
# module, which is where `run_probes("kimi", ...)` shells out to `kimi
# --version` and `kimi doctor`. #1627 split `host_probes` into
# `scripts/probes/`, so that seam is now `scripts.probes.kimi` -- the ONE
# probe module that starts a host CLI, and therefore the one that carries a
# DEFAULT_RUNNER. The seam is named per module because the walk in
# tests/test_host_launch_guard.py asserts the attribute on whatever module it
# finds the launch in; a sibling's launcher would not satisfy it. The
# guard-hook round-trips inside those probes are deliberately NOT routed
# through it: that subprocess is `sys.executable` running the hook's own
# protocol, and refusing it would delete the proof rather than protect it.
#
# LaunchRefused lives on the runner contract (`runners/base.py`), the one
# module every seam already shares: Codex first needed it and Kimi wrote a
# second class of the same name, and a refusal that two `except` clauses
# disagree about is not a guarantee. `codex_host.LaunchRefused` still names
# it, so every call site that already caught it is unchanged.
LAUNCH_SEAMS = (_codex_host, _codex_runner, _claude_runner, _setup_flow,
                _kimi_probes, _kimi_runner)


def _refused_binary(args):
    """The binary the caller was about to launch, named from its own argv --
    every seam here passes it first and positionally. Anything else (a call
    shape none of them uses) degrades to the generic noun rather than raising
    a second error on top of the refusal."""
    argv = args[0] if args else None
    if isinstance(argv, (list, tuple)) and argv and isinstance(argv[0], str):
        return "`%s` binary" % os.path.basename(argv[0])
    return "host CLI"


def _refuse_host_launch(*args, **_kwargs):
    raise _runners_base.LaunchRefused(
        "the test suite must never launch the real %s (family guardrails "
        "section 3): pass runner=<fake> to Runner(...) or patch "
        "scripts.runners.base.runner_for" % _refused_binary(args))


@pytest.fixture(autouse=True)
def _no_live_host_launches(monkeypatch):
    for seam in LAUNCH_SEAMS:
        monkeypatch.setattr(seam, "DEFAULT_RUNNER", _refuse_host_launch)


# --- #1616 item 8: reaching the claude family's run_entry is LOUD ------------
# The seam swap above is about money and side effects: no real binary starts.
# It is not about noticing. A test that reaches `claude.Runner.run_entry`
# without meaning to gets the refusal INSIDE the runner, where its never-raise
# contract (spec 4.4) turns it into an ordinary failed RunResult -- and a
# failed entry is exactly what most of these tests already have several of, so
# the test goes green, or fails on something three steps downstream. The
# guarantee "no test drives the real claude runner" was per-test discipline:
# patch `runner_for`, or pass `runner=<fake>`, and remember every time.
#
# So the METHOD is replaced, for every test that does not say otherwise. A
# test that really drives this family's own run_entry says so with
# `@pytest.mark.claude_runner` (tests/runners/test_claude.py carries it at
# module level, which is where the family's launch behaviour is tested), the
# same opt-in shape `@pytest.mark.docker` uses above. Claude is the one family
# the suite can reach by accident -- it is the DEFAULT host, so every
# `driver loop` test that forgets to patch `runner_for` builds this runner.


def _refuse_claude_run_entry(self, entry, env):
    # `pytest.fail`, not `LaunchRefused`. Fix round 1 (F1): the refusal has to
    # survive the code it is refusing. `iter_batch`'s worker turns any
    # `Exception` out of `run_entry` into a failed RunResult -- "a runner crash
    # is a failed entry, never a crashed loop", which is the right production
    # contract -- and `LaunchRefused` is a RuntimeError, so a `driver loop` test
    # that forgot to patch `runner_for` swallowed this and still reported
    # `complete`: three launches through the real family runner, green. pytest's
    # `Failed` is a BaseException, which neither that `except Exception` nor
    # `orchestrate.loop`'s own catch-all can hold, so it comes out as a test
    # failure wherever it is reached from. The DEFAULT_RUNNER seam above keeps
    # LaunchRefused, which several `except` clauses in the probes depend on.
    pytest.fail(
        "the test suite must not drive scripts.runners.claude.Runner.run_entry "
        "(family guardrails section 3): patch scripts.runners.base.runner_for "
        "to return a fake runner, or mark the test `@pytest.mark.claude_runner` "
        "if it means to exercise the family's own run_entry with an injected "
        "runner=<fake>. Entry %r" % (entry or {}).get("id"))


@pytest.fixture(autouse=True)
def _no_claude_entries(request, monkeypatch):
    if "claude_runner" in request.keywords:
        return
    monkeypatch.setattr(_claude_runner.Runner, "run_entry", _refuse_claude_run_entry)

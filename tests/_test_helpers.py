"""Shared test helpers used across multiple test modules."""
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest

from conftest import FIXTURE_ROOT, REPO_ROOT  # noqa: E402


# --- #1422: strict mode for the live-tool tests -----------------------------
# Every adapter integration test guards itself on a precondition (fixture
# vendored, toolchain installed, adapter registered). Outside the image none
# hold, so it skips -- correct on a dev machine, and a green tick over zero
# executed assertions in the environment BUILT to run them. #1410 fixed one test
# this way and left the pattern local to that file; these two make it the rule.
REQUIRE_INTEGRATION_ENV = "PANOPTICON_REQUIRE_INTEGRATION"


def require_integration():
    """True when this environment is the one that IS meant to run live tools.

    Read at CALL time, deliberately. A module-level constant is evaluated at
    import, before any test or fixture can set the variable, which makes the
    behaviour both unsettable and untestable without reloading the module.

    Exactly "1" counts: an ambiguous "true"/"yes"/"" must not switch on a mode
    that converts skips into failures.
    """
    return os.environ.get(REQUIRE_INTEGRATION_ENV) == "1"


def skip_or_fail(test_case, reason):
    """Skip on an unmet precondition -- or FAIL, where skipping is the bug."""
    if require_integration():
        test_case.fail("%s=1 but %s" % (REQUIRE_INTEGRATION_ENV, reason))
    test_case.skipTest(reason)


# --- TST-B3A: guarded indexing of a parse/build result -----------------------
# Indexing an adapter's parse result directly (`findings[0]`) turns an
# empty-list REGRESSION into a bare IndexError: the failure names the test's
# plumbing, not the invariant that broke. This class has been re-found by three
# self-scans running (run-8 #1399/#1420, run-9 x3, run-10 x6), so the idiom is
# centralized here and enforced by test_no_unguarded_parse_index.py.

def first(seq, what="finding"):
    """seq[0], asserting the sequence is non-empty first, so an empty parse
    fails as 'expected at least 1 finding, got none' instead of IndexError."""
    assert len(seq) >= 1, "expected at least 1 %s, got none: %r" % (what, seq)
    return seq[0]


def only(seq, what="finding"):
    """The SOLE element, asserting exactly one -- use where the test's premise is
    that the input yields a single result (an extra one is a regression too)."""
    assert len(seq) == 1, "expected exactly 1 %s, got %d: %r" % (what, len(seq), seq)
    return seq[0]


def last(seq, what="finding"):
    """seq[-1], asserting the sequence is non-empty first.

    The same guard as `first`, for the sites whose premise is that something
    happened LAST -- the final payload a recorder saw, the most recent call.
    `first` cannot stand in for those: it would read a different element and
    silently assert the wrong thing rather than fail.
    """
    assert len(seq) >= 1, "expected at least 1 %s, got none: %r" % (what, seq)
    return seq[-1]


class FakeStream:
    """Iterable-chunk fake stdout/stderr for FakePopen."""

    def __init__(self, chunks):
        if chunks is None:
            chunks = []
        elif isinstance(chunks, bytes):
            chunks = [chunks]
        self._chunks = list(chunks)
        self._idx = 0

    def read(self, size=-1):
        if self._idx >= len(self._chunks):
            return b""
        chunk = self._chunks[self._idx]
        self._idx += 1
        return chunk

    def close(self):
        pass


class FakePopen:
    """A Popen-like stand-in for tests that exercise run_tool's bounded
    capture path. Supports both pre-built ``return_value=FakePopen(...)``
    patching and ``side_effect=FakePopen`` construction from run_tool's call
    arguments."""

    def __init__(self, cmd=None, stdout=None, stderr=None, returncode=0,
                 **kwargs):
        self.cmd = list(cmd) if cmd else []
        self._returncode = returncode
        self._killed = False
        # run_tool passes subprocess.PIPE for stdout/stderr; ignore those and
        # let the test provide the byte payload explicitly.
        self.stdout = FakeStream(stdout if stdout not in (None, -1) else None)
        self.stderr = FakeStream(stderr if stderr not in (None, -1) else None)
        self.kwargs = kwargs

    def wait(self, timeout=None):
        if self._killed and self._returncode == 0:
            self._returncode = -9
        return self._returncode

    def kill(self):
        self._killed = True

    def poll(self):
        return self._returncode if self._killed else None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def touch(root, rel, content=""):
    """Create a file at ``root/rel`` with optional content."""
    full = os.path.join(root, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(content)


# --- #1528: fixtures live in TWO places, and only one of them is the image ---
# `FIXTURE_ROOT` is the fixtures image's own corpus: the three goat checkouts it
# clones, plus `vulnerable-rust`, which is COPYed in solely because cargo-audit
# needs a `cargo build` that a read-only mount cannot produce at runtime.
#
# The repo's other fixtures -- insecure-js, vulnerable-node, vulnerable-python --
# are static files that need no build step, so they are NOT copied in; the image
# runs with the repo mounted read-only at /work precisely so the harness uses the
# checkout's own code. Resolving them through FIXTURE_ROOT alone made every
# adapter that targets one fail in strict mode against a fixture sitting three
# directories away (measured: eslint-security, trivy, and two of osv-scanner's
# three ecosystems).
#
# Image first, so a built or cloned copy always wins over the raw source.
REPO_FIXTURES = os.path.join(REPO_ROOT, "tests", "fixtures")
_FIXTURE_ROOTS = (FIXTURE_ROOT, REPO_FIXTURES)


def fixture_path(name):
    """The fixture's directory, or None when neither root carries it."""
    for root in _FIXTURE_ROOTS:
        candidate = os.path.join(root, name)
        if os.path.isdir(candidate):
            return candidate
    return None


def assert_adapter_finds(test_case, adapter_name, target_name, group="g1",
                         ok_codes=(0, 1)):
    """Run an adapter against a fixture and assert it produces findings.

    Skips the test when the fixture directory is not present (the normal case
    outside the fixtures image) -- unless PANOPTICON_REQUIRE_INTEGRATION=1, in
    which case a missing fixture is a FAILURE, because the environment that sets
    it is the one meant to have the fixture (#1422). A non-applicable fixture or
    a tool crash is always a real failure, not a skip that would leave coverage
    silently empty (#583).
    """
    target = fixture_path(target_name)
    if target is None:
        skip_or_fail(
            test_case,
            "%s fixture in neither %s nor %s (run inside the fixtures image)"
            % ((target_name,) + _FIXTURE_ROOTS)
        )
    return assert_adapter_finds_at(test_case, adapter_name, target,
                                   group=group, ok_codes=ok_codes,
                                   label=target_name)


def assert_adapter_finds_at(test_case, adapter_name, target, group="g1",
                            ok_codes=(0, 1), label=None):
    """The same assertions against an ARBITRARY directory.

    Split out for the adapters whose target is generated rather than vendored
    (#1528). Three of the nine need that -- a secret for gitleaks, a Go module
    for gosec, insecure Python for bandit -- and generating them means no
    credential-shaped string is ever committed to a public repo, which after the
    NVD_API_KEY incident is worth more than the convenience of a fixture dir.
    semgrep needs it for a different reason: its default ignore list drops
    `tests/` and `test/` RELATIVE TO THE PROJECT ROOT, so a fixture committed
    under `tests/fixtures/` is invisible to it however it is reached.
    """
    from scripts.tools import ADAPTERS

    label = label or os.path.basename(target.rstrip(os.sep))
    adapter = ADAPTERS[adapter_name]
    test_case.assertTrue(
        adapter.is_applicable(target),
        f"{adapter_name} should apply to the {label} project",
    )
    raw, rc = adapter.invoke(target)
    test_case.assertIn(
        rc, ok_codes, f"{adapter_name} errored (rc {rc}) on {label}"
    )
    findings = adapter.parse(raw, group)
    test_case.assertTrue(findings, f"expected {adapter_name} findings against {label}")
    return findings


# --- #1633: what a real shell makes of a generated hook command --------------
# A registered PreToolUse `command` is a SHELL STRING -- Claude Code and Kimi
# Code both hand it to `sh -c` -- so a path interpolated into one is shell
# SOURCE, not an argument. The only faithful way to ask "what argv does the
# host actually deliver, and does anything ELSE run?" is to let a shell parse
# it, which is why the tests that use this run one on purpose.
#
# The stub below is the ONLY program that command can reach: the interpreter it
# names resolves to a script that prints its own argv and exits, so neither the
# real hook nor any host binary is launched (family guardrails section 3),
# while a substitution that escaped its quotes still lands as a visible side
# effect in `cwd`.

def argv_through_shell(command, cwd, interpreter="python3"):
    """The argv `command` delivers when a shell parses it, as a list.

    `interpreter` (the command's first word) is stubbed in a temporary
    directory placed first on PATH. Fails loudly when the stub did not run or
    printed something no JSON argv can be read out of -- both of which mean the
    command did something other than invoke the hook.
    """
    with tempfile.TemporaryDirectory(prefix="panopticon-hook-stub-") as stub_dir:
        stub = os.path.join(stub_dir, interpreter)
        with open(stub, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\nexec %s -c 'import json, sys;"
                     " print(json.dumps(sys.argv[1:]))' \"$@\"\n"
                     % shlex.quote(sys.executable))
        os.chmod(stub, 0o755)
        env = dict(os.environ)
        env["PATH"] = stub_dir + os.pathsep + env.get("PATH", "")
        proc = subprocess.run(command, shell=True, cwd=cwd, env=env,   # noqa: S602
                              capture_output=True, text=True, timeout=60)
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert lines, ("the stubbed %s printed no argv (rc %s, stderr %r) -- the "
                   "command ran something else: %r"
                   % (interpreter, proc.returncode, proc.stderr, command))
    try:
        return json.loads(lines[-1])
    except ValueError as exc:
        raise AssertionError("the stubbed %s printed no JSON argv (%s): %r"
                             % (interpreter, exc, proc.stdout)) from exc


# --- #1642: the hard-link fixture -------------------------------------------
# Every read broker refuses a multiply-linked regular file that only a
# DIRECTORY grant admits, and the only honest way to test that is to plant a
# real hard link -- a mocked st_nlink would prove the branch, not the rule.
# Some filesystems have no links to plant (FAT/exFAT volumes, a few container
# tmpfs mounts), so the fixture SKIPS with the reason rather than failing a
# suite on the machine's storage. Every caller sits under the default temp
# directory, which is the mount CI actually runs on.

def hard_link_or_skip(target, link):
    """Hard-link `target` at `link` and return `link`, or skip with the reason."""
    try:
        os.link(str(target), str(link))
    except (OSError, NotImplementedError, AttributeError) as exc:
        raise unittest.SkipTest("this filesystem refuses hard links: %s: %s"
                                % (type(exc).__name__, exc))
    return str(link)

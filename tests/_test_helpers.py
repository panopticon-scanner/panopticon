"""Shared test helpers used across multiple test modules."""
import errno
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from conftest import FIXTURE_ROOT, REPO_ROOT  # noqa: E402
from scripts import hosts


def kimi_entry(enforced=True, model="secondary"):
    return {"id": "review-app-SEC", "agent": "panopticon-domain-panel" if enforced else None,
            "enforced": enforced, "model": model,
            "prompt": "panopticon-entry: review-app-SEC\nReview.",
            "out_file": "/r/.panopticon/runs/t/findings-app-SEC.json"}


def kimi_fixture_home(directory, *, include_coding_alias=True):
    """Create a disposable Kimi home, never using the operator's home."""
    home = os.path.join(directory, "real-home")
    os.makedirs(home)
    config = ('default_model = "kimi-code/k3"\n\n'
              '[models."kimi-code/k3"]\nmodel = "k3"\n')
    if include_coding_alias:
        config += ('\n[models."kimi-code/kimi-for-coding"]\n'
                   'model = "kimi-for-coding"\n')
    with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as fh:
        fh.write(config)
    with open(os.path.join(home, "credentials"), "w", encoding="utf-8") as fh:
        fh.write("fixture")
    return home


def prepared_kimi(directory, runner=None, *, include_coding_alias=True):
    """Prepare a Kimi runner while preserving its guarded default launcher."""
    from scripts.runners import kimi as kimi_runner

    home = kimi_fixture_home(directory, include_coding_alias=include_coding_alias)
    with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": home}):
        prepared = kimi_runner.Runner("kimi", runner=runner)
        prepared.prepare(os.path.join(directory, "run"), review_root=directory)
    return prepared


def all_proven_artifact(host="claude"):
    """A fresh host-capabilities.json body with every capability proven."""
    return {"schema_version": 1, "host": host,
            "probed_at": "2026-09-10T00:00:00Z",
            "capabilities": {cap: {"state": hosts.PROVEN, "by": "fixture",
                                   "detail": "fixture"}
                             for cap in hosts.CAPABILITIES}}


def refuted_tool_policy_artifact(host="claude"):
    """A proven artifact with only tool policy explicitly refuted."""
    body = all_proven_artifact(host)
    body["capabilities"][hosts.TOOL_POLICY_ENFORCED] = {
        "state": hosts.REFUTED, "by": "fixture",
        "detail": "fixture: tool policy deliberately refuted"}
    return body


def write_guard_not_proven(host, target, **kw):
    """Probe stand-in with the write guard left unknown."""
    body = all_proven_artifact(host)
    body["capabilities"][hosts.ARTIFACT_WRITE_GUARD] = {
        "state": hosts.UNKNOWN, "by": None,
        "detail": "fixture: write guard deliberately not proven"}
    return body


def assert_fixture_root(root):
    """Accept the in-repo corpus path or the fixtures image's baked path."""
    stripped = root.rstrip(os.sep)
    assert stripped.endswith(os.path.join("tests", "fixtures")) or \
        stripped == "/opt/panopticon-fixtures", (
            "unexpected FIXTURE_ROOT %r -- expected the in-repo tests/fixtures or the "
            "fixtures image's /opt/panopticon-fixtures" % root)


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
    """Finite binary stream for FakePopen, with pipe-like bounded reads."""

    def __init__(self, chunks):
        if chunks is None:
            chunks = []
        elif isinstance(chunks, bytes):
            chunks = [chunks]
        self._chunks = list(chunks)
        self._idx = 0
        self._offset = 0
        self.closed = False

    def read(self, size=-1):
        if self.closed:
            raise ValueError("read of closed file")
        if size == 0:
            return b""
        pieces = []
        remaining = size
        while self._idx < len(self._chunks) and remaining != 0:
            chunk = self._chunks[self._idx]
            piece = chunk[self._offset:] if remaining < 0 else chunk[
                self._offset:self._offset + remaining]
            pieces.append(piece)
            self._offset += len(piece)
            if self._offset == len(chunk):
                self._idx += 1
                self._offset = 0
            if remaining > 0:
                remaining -= len(piece)
        return b"".join(pieces)

    def close(self):
        self.closed = True


class FakePopen:
    """Deterministic run_tool double for finite streams and process exit.

    ``pending=True`` stays running until kill/terminate; a timed wait raises
    TimeoutExpired. No OS PID exists, so process-group signalling cannot target
    an unrelated real process. ``communicate`` is deliberately unsupported.
    """

    def __init__(self, cmd=None, stdout=None, stderr=None, returncode=0,
                 pending=False, **kwargs):
        self.cmd = list(cmd) if cmd else []
        self._exit_code = returncode
        self._pending = pending
        self.returncode = None
        # run_tool passes subprocess.PIPE for stdout/stderr; ignore those and
        # let the test provide the byte payload explicitly.
        self.stdout = FakeStream(stdout if stdout not in (None, -1) else None)
        self.stderr = FakeStream(stderr if stderr not in (None, -1) else None)
        self.kwargs = kwargs

    def wait(self, timeout=None):
        if self.returncode is None and self._pending:
            if timeout is not None:
                raise subprocess.TimeoutExpired(self.cmd, timeout)
            raise RuntimeError("pending FakePopen needs kill() or terminate()")
        return self.poll()

    def kill(self):
        if self.poll() is None:
            self.returncode = -9

    def terminate(self):
        if self.poll() is None:
            self.returncode = -15

    def poll(self):
        if self.returncode is None and not self._pending:
            self.returncode = self._exit_code
        return self.returncode

    @property
    def pid(self):
        raise AttributeError("FakePopen has no OS PID")

    def communicate(self, *args, **kwargs):
        raise NotImplementedError("FakePopen only models run_tool's read/wait path")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stdout.close()
        self.stderr.close()
        self.wait()


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
                         ok_codes=(0, 1), *, matches):
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
                                   label=target_name, matches=matches)


def assert_adapter_finds_at(test_case, adapter_name, target, group="g1",
                            ok_codes=(0, 1), label=None, *, matches):
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
    summary = [
        ((f.get("tool_evidence") or {}).get("rule_id"),
         (f.get("location") or {}).get("file"),
         (f.get("tool_evidence") or {}).get("package_name"))
        for f in findings[:5]
    ]
    test_case.assertTrue(
        any(matches(finding) for finding in findings),
        f"{adapter_name} on {label}: no finding matches expected planted content; "
        f"first five (rule, file, package): {summary!r}",
    )
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
    """Hard-link `target` at `link`; skip only if links are unsupported."""
    try:
        os.link(str(target), str(link))
    except OSError as exc:
        if exc.errno not in (errno.ENOSYS, errno.EOPNOTSUPP, errno.ENOTSUP):
            raise
        _unsupported_hard_link(exc)
    except (NotImplementedError, AttributeError) as exc:
        _unsupported_hard_link(exc)
    return str(link)


def _unsupported_hard_link(exc):
    reason = "this filesystem refuses hard links: %s: %s" % (
        type(exc).__name__, exc)
    if require_integration():
        raise AssertionError("%s=1 but %s" % (REQUIRE_INTEGRATION_ENV, reason)) from exc
    raise unittest.SkipTest(reason) from exc


# --- #1578 fix round 2: composed secret literals -----------------------------
# gitleaks scans this repository's OWN tracked tree in CI, and its `private-key`
# / `aws-access-token` / `jwt` rules are STRUCTURAL: a complete PEM envelope, or
# `AKIA` followed by sixteen upper-alphanumerics, is a hit wherever it sits --
# there is no entropy test that can tell a redaction test's filler from a
# credential someone committed. Since #1578 graded a secret adapter's findings
# HIGH, every one of those hits blocks the merge gate.
#
# So the fake keys these tests need are COMPOSED here: no source line carries a
# whole PEM marker, a whole AWS key id or a whole JWT header, so the structural
# grep the #1578 round-2 ruling names comes back empty outside `tests/goldens`
# (captured scanner output, which cannot be composed, and is excluded on both
# workflow steps instead) and `tests/fixtures` (the deliberately-vulnerable
# corpus, already excluded). The patterns themselves are deliberately NOT
# quoted in this comment -- spelling one out here would be the defect.
#
# Composed rather than allowlisted, deliberately. A `.gitleaksignore` or a path
# exclusion over `tests/` would hide the whole CLASS -- including a credential
# somebody really commits. This removes the false positives and leaves the rule
# armed. The RUNTIME values are unchanged: every assertion that compares against
# one of these calls the same helper.


def pem_begin(kind="RSA "):
    """A PEM BEGIN marker. `kind` is the algorithm WITH its trailing space."""
    return "-----BEGIN " + "%sPRIVATE KEY-----" % kind


def pem_end(kind="RSA "):
    """The matching PEM END marker."""
    return "-----END " + "%sPRIVATE KEY-----" % kind


def fake_pem(body="MIIBsomekey", kind="RSA "):
    """A complete, well-formed, entirely fake PEM private-key block."""
    return "%s\n%s\n%s" % (pem_begin(kind), body, pem_end(kind))


def fake_aws_key(body="IOSFODNN7EXAMPLE"):
    """A well-formed but fake AWS access-key id: the `AKIA` prefix plus 16."""
    return "AKIA" + body


def fake_jwt():
    """A well-formed but fake three-segment JWT (the HS256 spec specimen)."""
    return ("eyJ" + "hbGciOiJIUzI1NiJ9."
            + "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0."
            + "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk")


def fake_uuid():
    """A fixed, fake UUID, split so gitleaks' `generic-api-key` rule cannot
    reach the ten-character run it needs after a `SECRET =` keyword."""
    return "3f2504e0" + "-4f89-11d3-9a0c-0305e82c3301"


# --- #1698 / #1912: a pid the operating system will say is gone --------------
# The batch owner stamp (`runners/batch.owner_state`) is a LIVENESS check, so a
# test about a CRASHED loop has to name a process that really is not running --
# a hard-coded number may belong to something, and `os.kill` is the thing under
# test rather than something to patch. A child spawned and reaped is the honest
# way to say it. Shared because the owner cases live in two modules (the unit
# ones beside `runners/batch.py`, the loop ones in `test_orchestrate.py`) and
# the helper was copied verbatim into both.

def dead_pid():
    """A pid that is certainly not running: a child spawned and reaped."""
    proc = subprocess.Popen([sys.executable, "-c", ""])
    proc.wait()
    return proc.pid

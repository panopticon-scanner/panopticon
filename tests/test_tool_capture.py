"""The capture path's own tests (#1762 ARC-2609514778, ARC-3243338950).

`scripts.tool_capture` was lifted out of `run_tools` whole in split 2 of 3 --
one container run supervised, bounded, classified, redacted and persisted -- so
the centre of this file is a PARITY golden rather than new behaviour. For every
shape a capture can take (clean, exit 1, a refused exit code, a watchdog
timeout, over the byte cap on either truncation branch, empty output, a semgrep
stderr annotation, a redaction hit) the BYTES that land on disk, the rows the
entry point returns and the lines it prints are compared against a golden
captured from the tree BEFORE the move. A pure extraction that changes one
byte, one message or one classification is not a pure extraction.

The rest of the file is the capture tests that came across with the code:
bodies unchanged, only the module they name.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess as sp
import sys
import tempfile
import threading
import unittest
from unittest import mock

import scripts.run_tools as rt
import scripts.tool_capture as tc

from tests._test_helpers import REPO_ROOT
from tests._test_helpers import fake_pem, pem_begin, pem_end
from tests.run_tools_test_helpers import _FakeResult

# --- the capture-parity matrix -----------------------------------------------
# Every case is driven through the PUBLIC entry (`run_tools` with an injected
# runner) except the watchdog, which that entry cannot reach in bounded time:
# `_capture_run` passes no `timeout=`, so the deadline is `TOOL_TIMEOUT` (900s),
# and the watchdog is driven through `_stream_and_write` with a short one --
# exactly as the streaming-deadline test below it already does.
#
# `gosec` and `semgrep` are the two legacy-SARIF tools with no scanner-owned
# config to stage (bandit's ini and trivy's ignorefile are pinned by C1's own
# argv golden), so a case here exercises the capture path and nothing else.
_TOKEN = "ghp_" + "PARITY" + "P" * 30    # a shape redact.py masks; not a secret
_CAP = 200                               # the byte cap for the over-cap cases


def _sarif(secret=None):
    """A minimal SARIF, optionally carrying `secret` in a result message."""
    results = []
    if secret is not None:
        results.append({"ruleId": "github-pat",
                        "message": {"text": "found %s" % secret}})
    return json.dumps({"runs": [{"results": results}]}).encode("utf-8")


def _lines(count):
    """`count` newline-terminated 18-byte lines, so a cap can be landed inside
    one of them (`_whole_lines` then drops the partial tail)."""
    return b"".join(b"line %03d %s\n" % (i, b"z" * 8) for i in range(count))


class _Chunks:
    """A stdout whose `read()` hands back one prepared chunk per call, so a case
    can land the byte cap exactly ON a chunk boundary (`room <= 0`) or INSIDE
    one (`len(chunk) > room`) -- the two truncation branches."""

    def __init__(self, chunks):
        self._chunks = list(chunks)

    def read(self, size=-1):
        return self._chunks.pop(0) if self._chunks else b""

    def close(self):
        pass


class _FakeProc:
    """A Popen-alike: streaming stdout, a finished return code, fixed stderr."""

    def __init__(self, chunks, returncode=0, stderr=b""):
        self.stdout = _Chunks(chunks)
        self.stderr = io.BytesIO(stderr)
        self._rc = returncode

    def wait(self, timeout=None):
        return self._rc

    def poll(self):
        return self._rc

    def kill(self):
        pass


# label -> (tool, returncode, stdout, stderr, cap, runner kind)
_CASES = {
    "clean-exit-0-json":
        ("gosec", 0, [_sarif()], b"", None, "stream"),
    "exit-1-is-still-produced":
        ("gosec", 1, [_sarif()], b"", None, "stream"),
    "exit-2-is-skipped-with-the-excerpt":
        ("gosec", 2, [_sarif()], b"gosec: fatal: boom\n", None, "stream"),
    "empty-stdout-fails-closed":
        ("gosec", 0, [], b"", None, "stream"),
    "blank-stdout-is-written-on-the-streaming-path":
        ("gosec", 0, [b"  \n"], b"", None, "stream"),
    "over-cap-chunk-straddles-the-cap":
        ("gosec", 0, [_lines(22)], b"", _CAP, "stream"),
    "over-cap-lands-on-a-chunk-boundary":
        ("gosec", 0, [b"y" * (_CAP - 1) + b"\n", _lines(4)], b"", _CAP, "stream"),
    "over-cap-with-no-line-break-keeps-the-prefix-as-cut":
        ("gosec", 0, [b"x" * 400], b"", _CAP, "stream"),
    "semgrep-is-annotated-from-its-own-stderr":
        ("semgrep", 0, [_sarif()], b"Ran 412 rules on 3 files.\n", None, "stream"),
    "a-secret-shaped-value-is-masked":
        ("gosec", 0, [_sarif(_TOKEN)], b"", None, "stream"),
    "completed-process-clean":
        ("gosec", 0, _sarif(), b"", None, "completed"),
    "completed-process-exit-2-is-skipped":
        ("gosec", 2, _sarif(), b"gosec: fatal: boom\n", None, "completed"),
    "completed-process-over-cap-is-dropped":
        ("gosec", 0, b"x" * 400, b"", _CAP, "completed"),
    "completed-process-blank-fails-closed":
        ("gosec", 0, b"  \n", b"", None, "completed"),
}
_WATCHDOG = "watchdog-timeout-kills-the-container"
# The watchdog case's two handshakes, recorded for the test body to assert
# rather than compared against the golden (the golden stays the same three keys
# every other case has). It is the one case with a wall-clock dependency, and a
# stall in the timer thread on a loaded runner would otherwise surface as an
# opaque dict mismatch instead of "the container kill never happened".
_HANDSHAKE: dict[str, bool] = {}


def _capture_cases():
    """Every case label, in a fixed order."""
    return sorted(_CASES) + [_WATCHDOG]


def _capture_case(label):
    """Drive one case and return everything observable about the capture: the
    rows the entry point returned (basenames -- the directory is a fresh temp),
    the bytes that landed, and what was printed to stderr."""
    if label == _WATCHDOG:
        return _watchdog_case()
    tool, returncode, payload, stderr, cap, kind = _CASES[label]

    def runner(cmd, **kwargs):
        if kind == "stream":
            return _FakeProc(payload, returncode, stderr)
        return _FakeResult(returncode=returncode, stdout=payload, stderr=stderr)

    err = io.StringIO()
    cap_ctx = (mock.patch.object(tc, "MAX_TOOL_OUTPUT_BYTES", cap) if cap
               else contextlib.nullcontext())
    with tempfile.TemporaryDirectory() as d:
        with contextlib.redirect_stderr(err), cap_ctx:
            written = rt.run_tools(d, [tool], os.path.join(d, "tools"),
                                   runner=runner)
        landed = None
        if written:
            with open(written[0], "rb") as fh:
                landed = fh.read()
    return {"returned": [os.path.basename(p) for p in written],
            "written": landed, "stderr": err.getvalue()}


def _watchdog_case():
    """The deadline and the `--cidfile` container kill.

    A `wait()` that blocks until the kill has been RECORDED, rather than until
    the read unblocks: the watchdog kills the client first and the container
    second, so reading the ledger straight after the return would race the
    timer thread. Nothing about the code under test changes -- `wait()` is
    already called only after the stream ends.

    Both waits are bounded at 5s and both return False rather than raising, so
    the two flags are published in `_HANDSHAKE` for the test to assert: a stall
    has to read as a stall and not as a golden mismatch.
    """
    released = threading.Event()
    reaped = threading.Event()
    killed = []

    class _HangStdout:
        def read(self, size=-1):
            released.wait(5)          # unblocks only when kill() releases it
            return b""

        def close(self):
            pass

    class _HangProc:
        def __init__(self):
            self.stdout = _HangStdout()
            self.stderr = io.BytesIO(b"")
            self._rc = None

        def wait(self, timeout=None):
            reaped.wait(5)
            return -9                 # SIGKILL

        def poll(self):
            return self._rc

        def kill(self):
            self._rc = -9
            released.set()

    def _reap(cmd, **kwargs):
        killed.append([os.path.basename(cmd[0])] + list(cmd[1:]))
        reaped.set()
        return _FakeResult(returncode=0)

    err = io.StringIO()
    with tempfile.TemporaryDirectory() as d:
        cidfile = os.path.join(d, "cid")
        with open(cidfile, "w", encoding="utf-8") as fh:
            fh.write("deadbeefcafe\n")
        docker = os.path.join(d, "docker")
        with contextlib.redirect_stderr(err), \
                mock.patch.object(tc.subprocess, "run", side_effect=_reap):
            out = tc._stream_and_write("tool", "hang", _HangProc(),
                                       os.path.join(d, "hang.sarif"),
                                       timeout=0.3, docker_bin=docker,
                                       cidfile=cidfile,
                                       docker_env={"PATH": d})
    _HANDSHAKE.update(released=released.is_set(), reaped=reaped.is_set())
    return {"returned": [] if out is None else [os.path.basename(out)],
            "written": None, "stderr": err.getvalue(), "killed": killed}


# The golden, captured from the pre-move tree BEFORE anything moved: this file
# copied into a `git archive HEAD | tar -x` export of it with its
# `import scripts.tool_capture as tc` line rewritten to `tc = rt` (where the
# block still lived), then `_capture_case` run for every label. So the golden
# and the assertions below cannot disagree about how a case is driven.
# Machine-emitted, never hand-edited: a future PR that legitimately changes a
# message, a marker or a classification regenerates it the same way from the
# then-current main and says so in its own body.
GOLDEN = {
    "a-secret-shaped-value-is-masked": {
        "returned": ['gosec.sarif'],
        "written": (b'{"runs": [{"results": [{"ruleId": "github-pat", '
                    b'"message": {"text": "found [REDACTED_TOKEN]"}}]}'
                    b']}'),
        "stderr": ('gosec capture carried secret-shaped values; mask'
                   'ed before writing\n'),
    },
    "blank-stdout-is-written-on-the-streaming-path": {
        "returned": ['gosec.sarif'],
        "written": b'  \n',
        "stderr": '',
    },
    "clean-exit-0-json": {
        "returned": ['gosec.sarif'],
        "written": b'{"runs": [{"results": []}]}',
        "stderr": '',
    },
    "completed-process-blank-fails-closed": {
        "returned": [],
        "written": None,
        "stderr": ('tool gosec produced no output on a selected targ'
                   'et; recording as missing (fail-closed, #1051)\n'),
    },
    "completed-process-clean": {
        "returned": ['gosec.sarif'],
        "written": b'{"runs": [{"results": []}]}',
        "stderr": '',
    },
    "completed-process-exit-2-is-skipped": {
        "returned": [],
        "written": None,
        "stderr": 'tool gosec exited 2; skipping — gosec: fatal: boom\n',
    },
    "completed-process-over-cap-is-dropped": {
        "returned": [],
        "written": None,
        "stderr": 'tool gosec output exceeded 200 byte limit; skipping\n',
    },
    "empty-stdout-fails-closed": {
        "returned": [],
        "written": None,
        "stderr": ('tool gosec produced no output on a selected targ'
                   'et; recording as missing (fail-closed, #1051)\n'),
    },
    "exit-1-is-still-produced": {
        "returned": ['gosec.sarif'],
        "written": b'{"runs": [{"results": []}]}',
        "stderr": '',
    },
    "exit-2-is-skipped-with-the-excerpt": {
        "returned": [],
        "written": None,
        "stderr": 'tool gosec exited 2; skipping — gosec: fatal: boom\n',
    },
    "over-cap-chunk-straddles-the-cap": {
        "returned": ['gosec.sarif'],
        "written": (b'line 000 zzzzzzzz\nline 001 zzzzzzzz\nline 002 zzz'
                    b'zzzzz\nline 003 zzzzzzzz\nline 004 zzzzzzzz\nline 0'
                    b'05 zzzzzzzz\nline 006 zzzzzzzz\nline 007 zzzzzzzz\n'
                    b'line 008 zzzzzzzz\nline 009 zzzzzzzz\nline 010 zzz'
                    b'zzzzz\n\n\n[TRUNCATED by panopticon: output exceede'
                    b'd 200 byte limit; only the first 200 bytes were '
                    b'retained]\n'),
        "stderr": ('tool gosec output exceeded 200 byte limit; trunc'
                   'ated and retained with marker\n'),
    },
    "over-cap-lands-on-a-chunk-boundary": {
        "returned": ['gosec.sarif'],
        "written": (b'yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy'
                    b'yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy'
                    b'yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy'
                    b'yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy'
                    b'yyyyyyy\n\n\n[TRUNCATED by panopticon: output excee'
                    b'ded 200 byte limit; only the first 200 bytes wer'
                    b'e retained]\n'),
        "stderr": ('tool gosec output exceeded 200 byte limit; trunc'
                   'ated and retained with marker\n'),
    },
    "over-cap-with-no-line-break-keeps-the-prefix-as-cut": {
        "returned": ['gosec.sarif'],
        "written": (b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
                    b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
                    b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
                    b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
                    b'xxxxxxxx\n\n[TRUNCATED by panopticon: output excee'
                    b'ded 200 byte limit; only the first 200 bytes wer'
                    b'e retained]\n'),
        "stderr": ('tool gosec output exceeded 200 byte limit; trunc'
                   'ated and retained with marker\n'),
    },
    "semgrep-is-annotated-from-its-own-stderr": {
        "returned": ['semgrep.sarif'],
        "written": (b'{"runs": [{"results": [], "properties": {"panopt'
                    b'icon_scanned_files": 3}}]}'),
        "stderr": '',
    },
    "watchdog-timeout-kills-the-container": {
        "returned": [],
        "written": None,
        "stderr": 'tool hang timed out after 0.3s; skipping\n',
        "killed": [['docker', 'kill', 'deadbeefcafe']],
    },
}


class TestTheCapturePathIsUnchangedByTheMove(unittest.TestCase):
    """The parity golden: captured from the tree before `tool_capture` existed,
    by importing the case table above into an export of that tree, so the
    golden and these assertions cannot disagree about how a case is driven.

    A value here is a LITERAL. If a case stops matching, the extraction is
    wrong -- the golden is not the thing to edit. (A future PR that
    legitimately changes a message, a marker or a classification regenerates it
    the same way, from the then-current main, and says so in its own body.)
    """

    def test_every_case_lands_exactly_the_golden_bytes(self):
        for label in _capture_cases():
            with self.subTest(case=label):
                row = _capture_case(label)
                if label == _WATCHDOG:
                    # Before the dict comparison, so a wall-clock stall names
                    # itself instead of arriving as a missing `killed` row.
                    self.assertTrue(
                        _HANDSHAKE["released"],
                        "the watchdog never killed the client: the blocking "
                        "read was released by the 5s bound, not by kill()")
                    self.assertTrue(
                        _HANDSHAKE["reaped"],
                        "the container kill never happened: `wait()` returned "
                        "on its 5s bound with the cidfile kill unrecorded")
                self.assertEqual(row, GOLDEN[label])

    def test_the_golden_covers_the_whole_matrix_and_every_branch(self):
        self.assertEqual(sorted(GOLDEN), sorted(_capture_cases()))
        landed = [row["written"] for row in GOLDEN.values()]
        printed = "".join(row["stderr"] for row in GOLDEN.values())
        self.assertTrue([row for row in GOLDEN.values() if row["returned"]],
                        "no case produced a capture")
        self.assertTrue([row for row in GOLDEN.values() if not row["returned"]],
                        "no case was skipped")
        for evidence in (b"TRUNCATED", b"[REDACTED_TOKEN]",
                         b"panopticon_scanned_files"):
            self.assertTrue(any(b and evidence in b for b in landed),
                            "no case exercises %s" % evidence.decode())
        for message in ("timed out after", "exited 2; skipping",
                        "fail-closed, #1051", "byte limit",
                        "masked before writing"):
            self.assertIn(message, printed)
        self.assertEqual(GOLDEN[_WATCHDOG]["killed"],
                         [["docker", "kill", "deadbeefcafe"]],
                         "the cidfile kill path is not in the golden")


class TestSemgrepScanCount(unittest.TestCase):
    """#1335: a semgrep whose config carries no rules for the target's languages
    scans 0 files and emits an empty-but-valid SARIF -- indistinguishable, in the
    artifact, from a semgrep that genuinely ran clean. The SARIF has no
    scanned-files signal (`invocations` is just executionSuccessful; the driver's
    rule list is the config's, not what matched), so the only evidence is
    semgrep's stderr. Capture it at run time, when it still exists."""

    def test_parses_the_scanned_file_count_from_stderr(self):
        self.assertEqual(tc._semgrep_scanned_files(b"Ran 412 rules on 0 files.\n"), 0)
        self.assertEqual(tc._semgrep_scanned_files(b"ran 8 rules on 137 files: 2 findings."), 137)
        self.assertEqual(
            tc._semgrep_scanned_files(b"noise\nRan 1 rule on 5 files\nmore noise"), 5)

    def test_absent_or_unrecognised_stderr_yields_no_claim(self):
        # Parsing English stderr is brittle across semgrep versions, so the
        # failure mode must be "no signal", never a fabricated 0 -- a false
        # `noscan` would strip real coverage credit.
        for stderr in (b"", b"Scan completed successfully.", b"Ran rules on files",
                       None, b"Ran 5 rules on many files"):
            self.assertIsNone(tc._semgrep_scanned_files(stderr))

    def test_annotation_injects_the_count_into_the_sarif(self):
        payload = json.dumps({"runs": [{"results": []}]}).encode("utf-8")
        annotated = tc._annotate_scanned_files(payload, 0)
        doc = json.loads(annotated)
        self.assertEqual(doc["runs"][0]["properties"]["panopticon_scanned_files"], 0)
        self.assertEqual(doc["runs"][0]["results"], [], "annotation altered the findings")

    def test_annotation_leaves_unparseable_or_shapeless_output_alone(self):
        for payload in (b"{not json", b"[]", b'{"runs": []}', b'{"runs": [123]}'):
            self.assertEqual(tc._annotate_scanned_files(payload, 0), payload)

    def test_semgrep_capture_annotates_from_its_own_stderr(self):
        # End to end through the real streaming writer: the child prints a SARIF
        # on stdout and semgrep's summary line on stderr.
        child = ("import sys; sys.stderr.write('Ran 400 rules on 0 files.\\n'); "
                 "sys.stdout.write('{\"runs\": [{\"results\": []}]}')")
        proc = rt._popen_runner([sys.executable, "-c", child],
                                stdout=sp.PIPE, stderr=sp.PIPE)
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "semgrep.sarif")
            self.assertEqual(
                tc._stream_and_write("tool", "semgrep", proc, out, timeout=8), out)
            with open(out, encoding="utf-8") as fh:
                doc = json.load(fh)
        self.assertEqual(doc["runs"][0]["properties"]["panopticon_scanned_files"], 0)

    def test_other_tools_are_not_annotated(self):
        child = ("import sys; sys.stderr.write('Ran 400 rules on 0 files.\\n'); "
                 "sys.stdout.write('{\"runs\": [{\"results\": []}]}')")
        proc = rt._popen_runner([sys.executable, "-c", child],
                                stdout=sp.PIPE, stderr=sp.PIPE)
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "bandit.sarif")
            tc._stream_and_write("tool", "bandit", proc, out, timeout=8)
            with open(out, encoding="utf-8") as fh:
                doc = json.load(fh)
        self.assertNotIn("properties", doc["runs"][0])


class TestStreamingRunnerAndDeadline(unittest.TestCase):
    """#run7 COD-A2A / #1111: production must STREAM tool output through the
    bounded sink (not buffer it whole and drop), and the streaming read must be
    bounded by a wall-clock deadline the way subprocess.run's timeout was."""

    def test_default_runner_streams_not_buffers(self):
        # With no runner injected, run_tools uses the streaming _popen_runner
        # (a live Popen), NOT subprocess.run (which buffered all output in memory
        # and always took the drop path -- the #1111 guard was unreachable).
        seen = {}

        def fake_capture(label, tool, docker, out_path, runner, **_kwargs):
            seen["runner"] = runner
            return None

        with mock.patch.object(tc, "_capture_run", side_effect=fake_capture):
            with tempfile.TemporaryDirectory() as d:
                rt.run_tools(d, ["semgrep"], os.path.join(d, "out"))
        self.assertIs(seen["runner"]._panopticon_runner, rt._popen_runner)
        self.assertIsNot(seen["runner"]._panopticon_runner, sp.run)
        self.assertTrue(os.path.isabs(seen["runner"]._panopticon_env["PATH"].split(
            os.pathsep)[0]))

    def test_popen_runner_streams_real_subprocess_to_disk(self):
        # The default runner returns a real Popen whose stdout _capture_run
        # routes to _stream_and_write (proc.stdout is a stream, not bytes).
        proc = rt._popen_runner(
            [sys.executable, "-c", "import sys; sys.stdout.write('hello-stream')"],
            stdout=sp.PIPE, stderr=sp.PIPE)
        self.assertIsInstance(proc, sp.Popen)
        self.assertNotIsInstance(proc.stdout, (bytes, type(None)))   # streaming route
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "o.sarif")
            written = tc._stream_and_write("tool", "py", proc, out)
            self.assertEqual(written, out)
            with open(out, "rb") as fh:
                self.assertEqual(fh.read(), b"hello-stream")

    def test_chatty_stderr_does_not_deadlock_the_stdout_capture(self):
        # #1510 (Codex BR-05 = run-11 COD-1902034584): _stream_and_write read
        # stdout to EOF and only THEN proc.stderr.read(). A child that fills the
        # 64KB stderr pipe blocks on write before it ever writes stdout, so the
        # parent waits on stdout the blocked child cannot produce -- deadlock,
        # resolved only by the watchdog burning the whole scan timeout.
        #
        # A real subprocess is mandatory here: a fake stream that returns bytes
        # immediately models no backpressure, so it cannot fail this test.
        child = ("import sys; sys.stderr.write('x' * (2 * 1024 * 1024)); "
                 "sys.stderr.flush(); sys.stdout.write('{}'); sys.stdout.flush()")
        proc = rt._popen_runner([sys.executable, "-c", child],
                                stdout=sp.PIPE, stderr=sp.PIPE)
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stderr(err):
            out = os.path.join(d, "o.sarif")
            written = tc._stream_and_write("tool", "chatty", proc, out, timeout=8)
            self.assertEqual(written, out, "chatty stderr deadlocked the capture")
            with open(out, "rb") as fh:
                self.assertEqual(fh.read(), b"{}")
        self.assertNotIn("timed out", err.getvalue())

    def test_watchdog_kills_hung_tool_and_skips(self):
        # A tool whose stdout.read() BLOCKS (hang) must be killed at the deadline
        # and skipped -- the bound subprocess.run's timeout used to give, now
        # enforced during the streaming read.
        released = threading.Event()

        class _HangStdout:
            def read(self, n=-1):
                released.wait(5)      # unblocks only when kill() releases it
                return b""            # then EOF
            def close(self):
                pass

        class _HangProc:
            def __init__(self):
                self.stdout = _HangStdout()
                self.stderr = io.BytesIO(b"")
                self._rc = None
            def wait(self, timeout=None):
                return -9             # SIGKILL
            def poll(self):
                return self._rc
            def kill(self):
                self._rc = -9
                released.set()

        proc = _HangProc()
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stderr(err):
            out = tc._stream_and_write("tool", "hang", proc,
                                       os.path.join(d, "o.sarif"), timeout=0.3)
        self.assertIsNone(out)                       # hung tool skipped, not hung forever
        self.assertIn("timed out", err.getvalue())
        self.assertTrue(released.is_set())           # the watchdog actually fired


class TestRawCaptureRedaction(unittest.TestCase):
    """#1639 P11: the raw captures under `.panopticon/tools/` are what an operator
    copies into a CI artifact, and nothing redacted them -- the report's pass
    (`redact.redact_tree`, #1634) runs over the REPORT tree and never touches
    these files. Every write path now goes through ONE choke point,
    `_redact_capture`, immediately before `_atomic_write`.

    The marker is `ghp_` + 36 token characters: a shape `scripts/redact.py`
    ALREADY masks, so a survival here is a wiring defect and never a pattern-set
    gap (that is #1572). Not a credential -- 'A'*29 is not a secret.
    """

    MARKER = "ghp_" + "CAPTURE" + "A" * 29
    GOLDENS = os.path.join(REPO_ROOT, "tests", "goldens", "tool-raw")

    def _sarif(self, secret):
        """A gitleaks-shaped SARIF carrying `secret` in the two places a secret
        scanner puts one: the result message and the snippet."""
        return json.dumps({"runs": [{
            "tool": {"driver": {"name": "gitleaks", "rules": [
                {"id": "github-pat"}]}},
            "results": [{
                "ruleId": "github-pat", "level": "error",
                "message": {"text": "github-pat detected: %s" % secret},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "app/settings.py"},
                    "region": {"startLine": 7,
                               "snippet": {"text": "TOKEN = '%s'" % secret}}}}],
            }]}]}).encode("utf-8")

    def _stream(self, payload, tool="gitleaks", out_name="gitleaks.sarif"):
        """Drive the REAL streaming writer over a child that prints `payload`.
        python3 (never a scanner binary, never docker) -- same seam the semgrep
        annotation tests use."""
        child = "import sys; sys.stdout.buffer.write(%r)" % payload
        proc = rt._popen_runner([sys.executable, "-c", child],
                                stdout=sp.PIPE, stderr=sp.PIPE)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        out = os.path.join(d, out_name)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                tc._stream_and_write("tool", tool, proc, out, timeout=30), out)
        with open(out, "rb") as fh:
            return fh.read()

    def test_completed_path_redacts(self):
        """`_write_completed`: the CompletedProcess runner (Codex's repro --
        `_write_completed` saved a credential-shaped value verbatim)."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        out = os.path.join(d, "gitleaks.sarif")
        res = _FakeResult(returncode=1, stdout=self._sarif(self.MARKER))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(tc._write_completed("tool", "gitleaks", res, out), out)
        with open(out, "rb") as fh:
            written = fh.read()
        self.assertNotIn(self.MARKER.encode(), written)
        self.assertIn(b"[REDACTED_TOKEN]", written)

    def test_streamed_path_redacts(self):
        written = self._stream(self._sarif(self.MARKER))
        self.assertNotIn(self.MARKER.encode(), written)
        self.assertIn(b"[REDACTED_TOKEN]", written)

    def test_streamed_path_redacts_after_its_stderr_annotation(self):
        """semgrep's capture is rewritten by `_annotate_from_stderr` on the way
        out; the choke point sits after it, so the annotator can never reopen
        the hole."""
        payload = json.dumps({"runs": [{"results": [], "tool": {"driver": {
            "name": "semgrep"}}}], "leak": self.MARKER}).encode("utf-8")
        written = self._stream(payload, tool="semgrep", out_name="semgrep.sarif")
        self.assertNotIn(self.MARKER.encode(), written)
        self.assertIn(b"[REDACTED_TOKEN]", written)

    def test_truncated_path_redacts_the_retained_prefix(self):
        """The over-cap branch keeps the first MAX_TOOL_OUTPUT_BYTES and appends
        a marker; the retained prefix is redacted too."""
        payload = self._sarif(self.MARKER) + b"z" * 4000
        with mock.patch.object(tc, "MAX_TOOL_OUTPUT_BYTES", 1200):
            written = self._stream(payload)
        self.assertIn(b"TRUNCATED", written)
        self.assertNotIn(self.MARKER.encode(), written)
        self.assertIn(b"[REDACTED_TOKEN]", written)

    def test_every_write_path_goes_through_the_choke_point(self):
        """Structural, over the AST: every `_atomic_write` call in tool_capture.py
        names `_redact_capture` INLINE in the data it hands over. A fourth
        capture path added later cannot land unredacted, and the check reads the
        tree rather than the text -- a grep passes on a call that merely
        mentions the name in a comment or a string.

        Scope, stated so it is not mistaken for more than it is: this guards
        CAPTURE writes, not the tools directory. `write_manifest` writes
        `tools-manifest.json` into the same out-dir with a plain `open()`, and
        deliberately does not go through the choke point -- its payload is
        controller-composed (tool names, produced paths, `run_id`, the
        virtualenv rows the runner's own walk found, `redacted`), never scanner
        text, and `json.dump` escapes any control character a hostile directory
        name could carry, so it needs neither redaction nor `_prompt_safe`
        (which exists to protect PROMPT-LINE structure, and nothing interpolates
        these rows into a prompt). Nor does the directory-walk guard below reach
        it: the driver points `--manifest` at `.panopticon/tools-manifest.json`,
        a sibling of the captures directory rather than a file inside it. If the
        manifest ever starts carrying scanner-derived text, it needs the choke
        point and a guard of its own.
        """
        import ast
        with open(os.path.join(REPO_ROOT, "skill", "scripts", "tool_capture.py"),
                  encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == "_atomic_write"]
        self.assertTrue(calls, "no _atomic_write call sites found -- guard is vacuous")
        unguarded = []
        for call in calls:
            # Inline anywhere in the data expression: the truncation path is
            # `_redact_capture(...) + marker`, because the marker is appended
            # AFTER the pass.
            data = call.args[1] if len(call.args) > 1 else None
            redacted = data is not None and any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "_redact_capture" for n in ast.walk(data))
            if not redacted:
                unguarded.append(call.lineno)
        self.assertEqual(unguarded, [],
                         "unredacted _atomic_write at lines %s" % unguarded)

    def test_run_tools_leaves_no_marker_anywhere_in_the_out_dir(self):
        """The guard by construction: walk everything a run drops in the tools
        directory rather than naming the files, so a future capture path is
        covered without remembering to extend this test."""
        payload = self._sarif(self.MARKER)

        def runner(cmd, **kw):
            return _FakeResult(returncode=0, stdout=payload)

        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        out_dir = os.path.join(d, "tools")
        with contextlib.redirect_stderr(io.StringIO()):
            written = rt.run_tools(d, ["gitleaks", "semgrep", "osv-scanner"],
                                   out_dir, runner=runner)
        self.assertEqual(len(written), 3, written)   # non-vacuous: files exist
        leaked = []
        for root, _dirs, files in os.walk(out_dir):
            for name in sorted(files):
                path = os.path.join(root, name)
                with open(path, "rb") as fh:
                    if self.MARKER.encode() in fh.read():
                        leaked.append(name)
        self.assertEqual(leaked, [], "raw capture kept the marker: %s" % leaked)

    # #1572: the ONE golden a rule legitimately fires on, and exactly what it
    # does to it. pip-audit's capture embeds a CVE advisory about
    # `Proxy-Authorization` leaks, which quotes `https://username:password@proxy:8080`
    # as the shape it is describing. That is a well-formed credential URL, and
    # the URL-userinfo rule masks its password -- correctly: a redactor cannot
    # know that this particular password is the literal word "password".
    #
    # Pinned as a SUBSTITUTION rather than by exempting the file, because the
    # claim this test exists to make is about STRUCTURE. The change is one
    # substring inside one JSON string value; every `ruleId`, `location`,
    # `region` and `level` in the document is still byte-identical, which is
    # what the assertion below now says for this golden and says by identity
    # for the other fourteen.
    EXPECTED_MASKS = {
        "pip-audit.raw": (b"https://username:password@proxy:8080",
                          b"https://username:[REDACTED]@proxy:8080"),
    }

    def test_clean_goldens_are_byte_identical(self):
        """Ruling 1: redaction never changes SARIF STRUCTURE. Every committed
        real-scanner golden -- 15 tools, SARIF, JSON and XML -- comes back
        byte-for-byte through the choke point, so `ruleId`, `locations`,
        `region` line numbers and `level` are provably untouched on output that
        carries no secret -- and, for the one golden that does carry a
        credential shape, changed by exactly the one substitution named in
        EXPECTED_MASKS and nothing else."""
        names = sorted(n for n in os.listdir(self.GOLDENS) if n.endswith(".raw"))
        self.assertIn("gitleaks.raw", names)
        self.assertGreaterEqual(len(names), 15, names)
        self.assertLessEqual(set(self.EXPECTED_MASKS), set(names),
                             "EXPECTED_MASKS names a golden that is gone")
        changed = []
        for name in names:
            with open(os.path.join(self.GOLDENS, name), "rb") as fh:
                raw = fh.read()
            want = raw
            if name in self.EXPECTED_MASKS:
                before, after = self.EXPECTED_MASKS[name]
                self.assertIn(before, raw, "%s no longer carries the specimen "
                              "EXPECTED_MASKS is about" % name)
                want = raw.replace(before, after)
            if tc._redact_capture(name[:-4], raw) != want:
                changed.append(name)
        self.assertEqual(changed, [], "redaction rewrote a clean golden: %s" % changed)


class TestCaptureRedactionKeepsEveryFinding(unittest.TestCase):
    """#1639 P11 fix round 1 (F1): a flat regex pass over a whole JSON capture
    is not structure-safe. Every pattern in `scripts/redact.py` is anchored to a
    character class that excludes `"` -- except the PEM rule, which was `.*?`
    under DOTALL. A capture whose first BEGIN has no END of its own (the
    committed gitleaks golden quotes exactly that: a truncated key snippet) runs
    on until a LATER result's snippet supplies one, and everything in between --
    whole results, their rule ids and their locations -- collapses into one
    token. The output is still valid JSON, so ingest parses it happily and
    simply reports fewer findings, the survivor carrying somebody else's
    location.
    """

    TOKEN = "ghp_" + "POC" + "C" * 33

    def _capture(self):
        """The reviewer's four-result PoC: an unterminated BEGIN in result 2 and
        the END that closes it in result 4, with an unrelated result between."""
        def result(rule, uri, line, snippet):
            return {"ruleId": rule, "level": "error",
                    "message": {"text": "%s detected in %s" % (rule, uri)},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": line,
                                   "snippet": {"text": snippet}}}}]}
        return json.dumps({"runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [
                result("generic-api-key", "a/one.env", 1,
                       "TOKEN=%s" % self.TOKEN),
                result("private-key", "b/two.pem", 2,
                       pem_begin() + "\nMIIBsomekey\n"),
                result("aws-access-token", "c/three.py", 3, "harmless"),
                result("private-key", "d/four.pem", 9,
                       "AB12cd==\n" + pem_end()),
            ]}]}).encode("utf-8")

    def test_no_finding_is_lost_and_no_location_is_re_attributed(self):
        doc = json.loads(tc._redact_capture("gitleaks", self._capture()))
        runs = doc["runs"]
        self.assertEqual(len(runs), 1)
        results = runs[0]["results"]
        self.assertEqual(len(results), 4, "results were swallowed: %s" % results)
        self.assertEqual([r["ruleId"] for r in results],
                         ["generic-api-key", "private-key", "aws-access-token",
                          "private-key"])
        self.assertEqual(
            [(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
              r["locations"][0]["physicalLocation"]["region"]["startLine"])
             for r in results],
            [("a/one.env", 1), ("b/two.pem", 2), ("c/three.py", 3),
             ("d/four.pem", 9)])

    def test_the_secrets_in_that_capture_are_still_masked(self):
        out = tc._redact_capture("gitleaks", self._capture())
        self.assertNotIn(self.TOKEN.encode(), out)
        self.assertIn(b"[REDACTED_TOKEN]", out)

    def test_a_non_json_capture_keeps_the_lines_around_a_pem(self):
        """The XML/plain-text fallback (spotbugs is the one non-JSON golden).
        A complete block spanning lines is still masked -- and an unterminated
        BEGIN earlier in the file no longer eats the records between them."""
        raw = ('<BugInstance type="ONE" file="app/a.java"/>\n'
               '<Snippet>%s\nMIIBtruncated</Snippet>\n'
               '<BugInstance type="TWO" file="app/b.java"/>\n'
               '<Snippet>%s</Snippet>\n'
               % (pem_begin(), fake_pem("MIIBrealkey"))).encode()
        out = tc._redact_capture("spotbugs", raw)
        self.assertIn(b'<BugInstance type="TWO" file="app/b.java"/>', out)
        self.assertIn(b"[REDACTED_PRIVATE_KEY]", out)
        self.assertNotIn(b"MIIBrealkey", out)

    def test_a_non_json_capture_masks_a_pem_quoted_from_source(self):
        """Round 2 N1: a scanner snippet that quotes a key out of C/Java/older-
        Python source -- one double-quoted literal per PEM line -- is the shape
        the round-1 `[^"]` bound stopped masking. The flat pass is what an XML
        capture gets, so the pattern itself has to cover it."""
        raw = ('<BugInstance type="HARDCODED_KEY" file="app/Crypto.java"/>\n'
               '<Snippet>KEY = ("%s\\n"\n'
               '       "MIIEpAIBAAKCAQEAxLEAKEDKEYBODY0123456789abcdef\\n"\n'
               '       "%s");</Snippet>\n'
               % (pem_begin(), pem_end())).encode()
        out = tc._redact_capture("spotbugs", raw)
        self.assertIn(b"[REDACTED_PRIVATE_KEY]", out)
        self.assertNotIn(b"MIIEpAIBAAKCAQEAxLEAKEDKEYBODY", out)
        self.assertIn(b'<BugInstance type="HARDCODED_KEY" file="app/Crypto.java"/>',
                      out)

    def test_a_json_capture_keeps_its_own_formatting(self):
        """Re-serialization is only reached when redaction fired, and it keeps
        the producer's own layout where that is recognisable -- so a capture
        diffed across two runs shows the masked value, not a reformatting of
        every line."""
        doc = {"runs": [{"results": [{"ruleId": "x",
                                      "message": {"text": self.TOKEN}}]}]}
        for style in ({"indent": 1}, {"indent": 2}, {}, {"separators": (",", ":")}):
            raw = json.dumps(doc, **style).encode("utf-8")
            out = tc._redact_capture("gitleaks", raw).decode("utf-8")
            with self.subTest(style=style):
                self.assertNotIn(self.TOKEN, out)
                self.assertEqual(
                    out, json.dumps(json.loads(out), **style),
                    "re-serialized in a different layout than the capture's")


class TestTruncationDoesNotHalfKeepASecret(unittest.TestCase):
    """#1639 P11 fix round 1 (F2): the byte cap is measured on the RAW stream
    (ruling 4 -- it is the only count that bounds memory), so it can land in the
    middle of a token, and the length-anchored pattern no longer matches the
    fragment left behind. Scanner output is line-oriented, so dropping back to
    the last newline before the cap drops the partial value instead of keeping
    half of it."""

    TOKEN = "ghp_" + "CUT" + "Q" * 33

    def _stream(self, payload, cap):
        child = "import sys; sys.stdout.buffer.write(%r)" % payload
        proc = rt._popen_runner([sys.executable, "-c", child],
                                stdout=sp.PIPE, stderr=sp.PIPE)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        out = os.path.join(d, "gitleaks.sarif")
        with contextlib.redirect_stderr(io.StringIO()), \
                mock.patch.object(tc, "MAX_TOOL_OUTPUT_BYTES", cap):
            self.assertEqual(
                tc._stream_and_write("tool", "gitleaks", proc, out, timeout=30), out)
        with open(out, "rb") as fh:
            return fh.read()

    def test_a_token_split_by_the_cap_is_dropped_not_half_kept(self):
        head = b"keep this whole line\n"
        payload = head + b"TOKEN=" + self.TOKEN.encode() + b"\nzzzz\n"
        # Land the cap ten characters into the token.
        written = self._stream(payload, len(head) + len("TOKEN=") + 10)
        self.assertIn(b"keep this whole line", written)
        self.assertIn(b"TRUNCATED", written)
        self.assertNotIn(b"ghp_", written)

    def test_a_capture_with_no_line_break_keeps_its_prefix(self):
        """The trim must never empty a file: single-line output (a compact
        SARIF) has no newline to fall back to, so the prefix is kept as it was
        and the fragment risk is what the marker comment documents."""
        payload = b"x" * 400
        written = self._stream(payload, 100)
        self.assertIn(b"TRUNCATED", written)
        self.assertTrue(written.startswith(b"x" * 100), written[:120])
        self.assertFalse(written.startswith(b"x" * 101), written[:120])

    def test_the_trim_never_discards_a_long_last_line(self):
        """A capture that is one newline followed by an enormous single line
        must not be trimmed back to that first newline -- a line that long is
        not line-oriented output, and the retained evidence matters more than
        the fragment. Bounded by `_TRUNCATE_TRIM_MAX`, so the test is written
        against the constant rather than a number that could drift past it."""
        body = b"y" * (tc._TRUNCATE_TRIM_MAX + 5000)
        written = self._stream(b"{\n" + body, tc._TRUNCATE_TRIM_MAX + 2000)
        self.assertIn(b"TRUNCATED", written)
        self.assertGreater(written.count(b"y"), tc._TRUNCATE_TRIM_MAX)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""One container run, supervised: bounded, classified, redacted, persisted.

Everything between handing a built docker argv to a runner and the capture
landing on disk. The wall-clock watchdog and the `--cidfile` kill it uses to
stop the CONTAINER rather than just the CLI client; the concurrent stderr
drain; the stdout spool under `MAX_TOOL_OUTPUT_BYTES` with its truncation
marker; the exit-code classification (timeout, non-`(0, 1)`, empty-output
fail-closed); the per-tool annotation read off a stderr that exists only while
the child runs; the ONE redaction choke point every capture goes through; and
the atomic write.

`_stream_and_write` is 152 lines and stays ONE function (#1762,
ARC-3243338950). The watchdog and `_kill_container` are bound together by the
cidfile contract -- the timer fires, the client is killed so the blocking read
unblocks at EOF, and the container that client launched is stopped through the
id file its own argv named -- so splitting supervision from the kill path would
separate the two halves of one contract and leave a `--rm` container running on
every timeout.

Separate from `run_tools` because that module was 2215 lines, outside this
repo's own 700-line ratchet, and absorbing every new scanner policy because
nothing pushed back (#1762, ARC-2609514778). This is part 2 of 4 of that split
and it moved the block whole: no string, flag, path, byte, message or exception
changed, and `tests/test_tool_capture.py` compares the bytes this module
writes, the rows the entry point returns and the lines it prints against a
golden captured before the move.

The arrow points ONE way: nothing here imports `run_tools`, which imports this.
That is why the two ceilings live here -- `TOOL_TIMEOUT` is the watchdog's
default and `MAX_TOOL_OUTPUT_BYTES` the spool's cap, both read on this side of
the seam -- while the docker argv, the runner seam and the dispatch loop that
calls `_capture_run` stayed behind (the manifest writer, which reads the cap and
the redaction ledger back, is `tools_manifest`, part 3 of the same split).
`run_tools` binds both ceilings and the redaction ledger back for its own reads
and its importers'. Stdlib-only.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading

from scripts import redact
from scripts import safe_write
from scripts.tools.base import drain_stderr_async

# Max seconds to let a single docker-run tool invocation run before it's killed;
# prevents a hung tool from blocking the whole batch (CD-007).
TOOL_TIMEOUT = 900

MAX_TOOL_OUTPUT_BYTES = 50 * 1024 * 1024


def _capture_run(label, tool, docker, out_path, runner, docker_context=None):
    """Run one docker tool/adapter invocation and land its stdout at out_path.

    Streams stdout into a bounded sink so adversarial/large target output does
    not accumulate unbounded in orchestrator memory (#1111). On exceeding the
    byte cap the output is truncated with a marker and a stderr notice, but the
    file is still written so the tool is recorded as produced rather than
    silently skipped.
    """
    try:
        os.remove(out_path)
    except OSError:
        pass
    # #run9 OPS-D1A: give a `docker run` a --cidfile so _stream_and_write can
    # `docker kill` the real container on a watchdog timeout -- proc.kill() reaches
    # only the CLI client. The cidfile must NOT pre-exist (docker refuses to start),
    # so it lives in a fresh temp dir cleaned up here. Inserted right after `run`.
    docker_bin = cidfile = cid_dir = None
    if (docker_context is not None and len(docker) >= 2
            and docker[0] == docker_context.executable and docker[1] == "run"):
        docker_bin = docker_context.executable
        cid_dir = tempfile.mkdtemp(prefix="pano-cid-")
        cidfile = os.path.join(cid_dir, "cid")
        docker = docker[:2] + ["--cidfile", cidfile] + docker[2:]
    try:
        proc = runner(docker, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      timeout=TOOL_TIMEOUT)
        # Backward compat: tests may inject a CompletedProcess-like runner.
        if hasattr(proc, "stdout") and isinstance(proc.stdout, (bytes, type(None))):
            return _write_completed(label, tool, proc, out_path)
        return _stream_and_write(label, tool, proc, out_path,
                                 docker_bin=docker_bin, cidfile=cidfile,
                                 docker_env=(docker_context.env
                                             if docker_context is not None else None))
    except subprocess.TimeoutExpired:
        print("%s %s timed out after %ss; skipping" % (label, tool, TOOL_TIMEOUT),
              file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print("%s %s failed: %s; skipping" % (label, tool, e), file=sys.stderr)
    finally:
        if cid_dir:
            shutil.rmtree(cid_dir, ignore_errors=True)
    return None


def _write_completed(label, tool, res, out_path):
    """Legacy path for runner callables that return a CompletedProcess."""
    if getattr(res, "returncode", 1) not in (0, 1):
        excerpt = (getattr(res, "stderr", b"") or b"")[-500:].decode(
            "utf-8", errors="replace").strip()
        print("%s %s exited %s; skipping%s" % (
            label, tool, res.returncode,
            (" — " + excerpt) if excerpt else ""), file=sys.stderr)
        return None
    out_bytes = res.stdout or b""
    if len(out_bytes) > MAX_TOOL_OUTPUT_BYTES:
        print("%s %s output exceeded %d byte limit; skipping" % (
            label, tool, MAX_TOOL_OUTPUT_BYTES), file=sys.stderr)
        return None
    if not out_bytes.strip():
        print("%s %s produced no output on a selected target; recording as "
              "missing (fail-closed, #1051)" % (label, tool), file=sys.stderr)
        return None
    return _atomic_write(out_path, _redact_capture(tool, out_bytes))


# #1335: semgrep's SARIF carries NO scanned-files signal -- `invocations` is
# just {executionSuccessful: true}, and tool.driver.rules lists the CONFIG's
# rules whether or not any file matched. So a semgrep whose ruleset covers none
# of the target's languages scans 0 files and emits an artifact byte-identical
# in shape to a genuinely clean run. The one witness is semgrep's own stderr,
# which exists only at run time -- capture it into the artifact while we have it.
_SEMGREP_SCANNED = re.compile(rb"\bran\s+\d+\s+rules?\s+on\s+(\d+)\s+files?\b",
                              re.IGNORECASE)


def _semgrep_scanned_files(stderr):
    """The M in semgrep's `Ran N rules on M files`, or None if it isn't there.

    None means "no claim": semgrep's summary wording is English prose and has
    drifted across versions, so an unrecognised line must leave the artifact
    unannotated and the disposition exactly as it is today. Fabricating a 0
    would strip coverage credit from a scanner that really did run.
    """
    m = _SEMGREP_SCANNED.search(stderr or b"")
    return int(m.group(1)) if m else None


def _annotate_scanned_files(payload, count):
    """Record `count` as runs[0].properties.panopticon_scanned_files.

    Tolerant by design: output that is not a SARIF document with at least one
    run object is returned untouched. This runs on every semgrep capture, and a
    malformed artifact is already handled (and reported) by the ingest walk --
    it must not become a write failure here.
    """
    try:
        doc = json.loads(payload)
        run = doc["runs"][0]
        if not isinstance(run, dict):
            return payload
    except (ValueError, KeyError, IndexError, TypeError):
        return payload
    run.setdefault("properties", {})["panopticon_scanned_files"] = count
    return json.dumps(doc).encode("utf-8")


# Per-tool post-capture annotation, keyed by tool name: signals that exist only
# while the child runs and would otherwise be lost to the artifact.
_STDERR_ANNOTATORS = {"semgrep": _semgrep_scanned_files}


def _annotate_from_stderr(tool, payload, stderr):
    """Apply `tool`'s stderr annotation, if it has one. Identity otherwise."""
    reader = _STDERR_ANNOTATORS.get(tool)
    if reader is None:
        return payload
    count = reader(stderr)
    return payload if count is None else _annotate_scanned_files(payload, count)


def _drain(stream):
    """Read and discard the rest of a stream past the byte cap so the child is
    never left blocked on a full pipe. #run7 QAL-D1A: shared by both truncation
    branches in _stream_and_write (previously an inline duplicate)."""
    while stream.read(64 * 1024):
        pass


def _stream_and_write(label, tool, proc, out_path, timeout=TOOL_TIMEOUT,
                      docker_bin=None, cidfile=None, docker_env=None):
    """Stream stdout from a Popen-like object with an explicit byte cap AND a
    wall-clock deadline.

    The byte cap keeps a large/adversarial target's output from accumulating in
    memory (#1111). The deadline is enforced by a watchdog that kills the child
    at `timeout`: a Popen has no ``timeout=`` of its own, so without it a hung or
    trickle-slow tool would block the streaming ``read()`` (or the post-cap
    ``_drain`` of an infinite producer) forever -- restoring the bound that the
    old buffered ``subprocess.run(timeout=...)`` path provided (#run7 COD-A2A)."""
    timed_out = {"hit": False}

    def _cleanup_diagnostic(reason):
        print("%s %s container cleanup incomplete: %s" % (label, tool, reason),
              file=sys.stderr)

    def _kill_container():
        # #run9 OPS-D1A: proc.kill() SIGKILLs the `docker run` CLI client, which
        # cannot forward the signal to the daemon -- the `--rm` container keeps
        # running (and is never removed). When we recorded its id via --cidfile,
        # stop it directly. Cleanup remains best-effort, but a cidfile or Docker
        # failure is named so an ordinary timeout never implies cleanup succeeded.
        if not (docker_bin and cidfile):
            return
        try:
            with open(cidfile, encoding="utf-8") as fh:
                cid = fh.read().strip()
        except OSError as e:
            _cleanup_diagnostic("container id file could not be read (%s)"
                                % type(e).__name__)
            return
        if not cid:
            _cleanup_diagnostic("container id file was empty")
            return
        try:
            result = subprocess.run(
                [docker_bin, "kill", cid], capture_output=True, timeout=10,
                env=docker_env)
        except (subprocess.SubprocessError, OSError) as e:
            _cleanup_diagnostic("docker kill could not run (%s)" % type(e).__name__)
            return
        if result.returncode:
            raw = result.stderr or b""
            excerpt = (raw[-500:].decode("utf-8", errors="replace")
                       if isinstance(raw, bytes) else str(raw)[-500:])
            excerpt = " ".join(excerpt.split())
            _cleanup_diagnostic(
                "docker kill exited %s%s" % (
                    result.returncode, (" — " + excerpt) if excerpt else ""))

    def _watchdog():
        # Kill the child so the blocking read()/drain unblocks at EOF, and stop the
        # container it launched (OPS-D1A) so a hung tool leaves nothing running.
        timed_out["hit"] = True
        try:
            proc.kill()
        except Exception:
            pass
        _kill_container()

    timer = threading.Timer(timeout, _watchdog)
    timer.daemon = True
    timer.start()
    # #1510: drain stderr concurrently from the start. Reading stdout to EOF
    # first deadlocks against any scanner that fills its 64KB stderr pipe before
    # emitting stdout -- the parent waits on stdout the blocked child cannot
    # write, and only the watchdog breaks it, costing the whole scan timeout and
    # that tool's coverage. Shared with tools/base.run_tool, which already had it.
    join_stderr = drain_stderr_async(proc)
    try:
        with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as spool:
            truncated = False
            try:
                while True:
                    chunk = proc.stdout.read(64 * 1024)
                    if not chunk:
                        break
                    room = MAX_TOOL_OUTPUT_BYTES - spool.tell()
                    if room <= 0:
                        truncated = True
                        _drain(proc.stdout)   # discard remaining stdout, unstored
                        break
                    if len(chunk) > room:
                        spool.write(chunk[:room])
                        truncated = True
                        _drain(proc.stdout)
                        break
                    spool.write(chunk)
                # The watchdog guarantees the child terminates, so wait() is bounded.
                rc = proc.wait()
                stderr = join_stderr()
            finally:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
                try:
                    proc.stderr.close()
                except Exception:
                    pass
                if proc.poll() is None:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    _kill_container()      # OPS-D1A: stop the container, not just the client

            # A watchdog kill lands rc < 0 (signal). Only treat it as a timeout
            # when the child did NOT finish cleanly first -- else a tool that
            # completed a hair before the deadline (rc 0/1) would be misreported.
            if timed_out["hit"] and rc not in (0, 1):
                print("%s %s timed out after %ss; skipping" % (label, tool, timeout),
                      file=sys.stderr)
                return None

            if rc not in (0, 1):
                excerpt = (stderr or b"")[-500:].decode("utf-8", errors="replace").strip()
                print("%s %s exited %s; skipping%s" % (
                    label, tool, rc,
                    (" — " + excerpt) if excerpt else ""), file=sys.stderr)
                return None

            if spool.tell() == 0:
                print("%s %s produced no output on a selected target; recording as "
                      "missing (fail-closed, #1051)" % (label, tool), file=sys.stderr)
                return None

            if truncated:
                # Both numbers describe RAW bytes: the cap is measured on the
                # stream as it arrives (above), which is the only count that
                # bounds memory. `_whole_lines` and `_redact_capture` run after,
                # and either can change the retained prefix's length, so the
                # marker is a statement about what the child produced and what
                # was kept -- not about the size of the file on disk (#1639 P11).
                # Cutting on a raw byte count can also split a token in half,
                # and a fragment matches none of the length-anchored patterns:
                # `_whole_lines` drops the partial last line so the fragment
                # goes with it, EXCEPT on output with no line breaks (a compact
                # single-line SARIF) or a last line over `_TRUNCATE_TRIM_MAX`,
                # where the prefix is kept as cut and a split value can survive
                # as an unmatched fragment.
                marker = (
                    "\n\n[TRUNCATED by panopticon: output exceeded %d byte limit; "
                    "only the first %d bytes were retained]\n" % (
                        MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_OUTPUT_BYTES)
                ).encode("utf-8")
                print("%s %s output exceeded %d byte limit; truncated and retained "
                      "with marker" % (label, tool, MAX_TOOL_OUTPUT_BYTES),
                      file=sys.stderr)
                # Write only up to the cap, redacted, then append the marker for
                # the tail -- appended AFTER the pass so panopticon's own text
                # is never rewritten by it.
                spool.seek(0)
                return _atomic_write(
                    out_path,
                    _redact_capture(
                        tool, _whole_lines(spool.read(MAX_TOOL_OUTPUT_BYTES)))
                    + marker)

            spool.seek(0)
            # Redaction is LAST: the semgrep annotator rewrites the payload on
            # its way out, so a choke point ahead of it could be reopened by it.
            return _atomic_write(
                out_path,
                _redact_capture(tool,
                                _annotate_from_stderr(tool, spool.read(), stderr)))
    finally:
        timer.cancel()


# Which tools' captures this run put through `_redact_capture`. A run_tools()
# call clears it and `write_manifest` reads it back, so the artifact reports what
# the runner OBSERVED itself doing rather than restating an intention (#1639 P11
# F5): replace the choke point with identity and the manifest's claim goes false.
# Module-level because the pass runs three call frames below the run loop --
# threading a ledger through _capture_run/_write_completed/_stream_and_write
# would put plumbing in five signatures to carry one bit.
_REDACTED_CAPTURES: set[str] = set()

# Above this size a capture is re-serialized in json.dumps' default layout
# instead of the producer's own: matching the layout costs one extra
# serialization of the ORIGINAL document to verify the guess, which is free on a
# normal capture and not worth it on a huge one (only reached when redaction
# fired, and every consumer parses the file rather than reading it).
_STYLE_PROBE_MAX_BYTES = 4 * 1024 * 1024
# The producer's indentation, read off the head of the document.
_JSON_INDENT = re.compile(r"[\[{]\n(\x20+)\S")


def _json_style(text):
    """`json.dumps` kwargs guessed from how `text` itself is laid out.

    A guess: the caller VERIFIES it reproduces the original before using it, so
    being wrong costs one comparison rather than a reformatted file.
    """
    head = text[:4096]
    m = _JSON_INDENT.search(head)
    if m:
        return {"indent": len(m.group(1))}
    return {} if '": ' in head or '", "' in head else {"separators": (",", ":")}


# How much of a retained prefix `_whole_lines` may give up to end on a line
# boundary. A last line longer than this is not line-oriented output, and the
# evidence in it is worth more than the fragment risk.
_TRUNCATE_TRIM_MAX = 64 * 1024


def _whole_lines(prefix):
    """Drop a trailing partial line from a capture the byte cap cut (#1639 P11
    F2).

    The cap is measured on the RAW stream -- the only count that bounds memory
    (ruling 4) -- so it can land in the middle of a token, and the length-
    anchored patterns do not match a fragment: `ghp_QQQQQQQQQQ` is not a
    credential but it is not masked either. Scanner output is line-oriented, so
    ending on the last newline drops the split value instead of keeping half of
    it.

    Bounded both ways: a capture with no newline at all (a compact single-line
    SARIF), or whose last line is longer than `_TRUNCATE_TRIM_MAX`, keeps its
    prefix exactly as cut -- the trim must never empty a file or throw away
    megabytes of retained evidence to tidy one line, and for those shapes the
    fragment risk is what the marker comment documents.
    """
    cut = prefix.rfind(b"\n")
    if cut == -1 or len(prefix) - (cut + 1) > _TRUNCATE_TRIM_MAX:
        return prefix
    return prefix[:cut + 1]


def _redact_capture(tool, data):
    """The ONE redaction choke point for a raw scanner capture (#1639 P11).

    `.panopticon/tools/<tool>.sarif|json` is what an operator copies into a CI
    job's artifacts, and nothing masked it: the report's pass
    (`redact.redact_tree`, #1634) walks the REPORT tree, which these files are
    not part of, and a secret scanner's output is a file full of other people's
    credentials by construction. Every write path calls this immediately before
    `_atomic_write`, and `TestRawCaptureRedaction` reads this module's own AST
    to keep it that way for the next path somebody adds.

    Structure is preserved by PARSING, not by trusting the patterns to stay
    inside a string (fix round 1 F1). A JSON capture -- which is every capture
    but spotbugs' XML -- goes through `redact.redact_tree`, the same per-leaf
    walk the report uses since #1661, so a pattern can never span two fields:
    `ruleId`, `locations`, `region` line numbers and `level` survive because the
    walk never sees them as text. The flat pass had no such guarantee, and the
    PEM rule broke it -- an unterminated `-----BEGIN` in one snippet closed on a
    later result's `-----END` and swallowed every result in between. Non-JSON
    captures (spotbugs' XML) still take the flat pass, where every pattern but
    the PEM body is anchored to a character class that cannot cross a `"`, and
    the PEM body -- which has to cross quotes, since source code embeds a key
    one quoted literal per line -- is bounded to 16 KiB and cannot span two
    `-----BEGIN` blocks. So a flat-pass match over a structured document is
    bounded rather than open-ended; it is not the guarantee parsing gives, which
    is why JSON never takes this path. That length bound has a cost worth
    knowing before you publish a capture: a PEM block whose body runs longer
    than 16 KiB is not masked AT ALL -- header included -- so a capture quoting
    one very large key can still carry it verbatim.

    Whichever path runs, it is `scripts/redact.py`'s pattern set -- never a
    second copy: two redactors drift, and the one reached only by raw captures
    would drift silently.

    The tree walk masks string LEAVES, not dict KEYS -- the report's contract
    since #1661, and the right one here: a SARIF key comes from the tool's own
    schema, and the target-derived keys that do exist (npm-audit's per-package
    objects) are identifiers, not quoted secrets. The flat pass did mask a key,
    but only as a side effect of not knowing what a key was, which is the same
    blindness that let it eat three results.

    Bytes in, bytes out, because bytes are what the writer holds. The document
    is re-serialized ONLY when redaction actually fired, in the producer's own
    layout where that is recognisable; a capture with nothing to mask is
    returned as the exact bytes the scanner produced, so all fifteen committed
    real-scanner goldens are byte-identical through this function and a payload
    that is not valid UTF-8 (decoded here with errors="replace") is never
    rewritten by a pass that had nothing to do. When the pass DOES fire on such
    a payload its bytes are not preserved: it was decoded with replacement, so
    every byte that was not valid UTF-8 comes back as U+FFFD alongside the
    masked secret.
    """
    _REDACTED_CAPTURES.add(tool)
    text = data.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except ValueError:
        if tool == "eslint-security":
            # Broken scanner JSON can contain arbitrary source fragments too.
            # Discard it without converting whole-capture failure into a clean scan.
            return b"panopticon: unusable ESLint capture\n"
        masked = redact.redact(text)        # XML/plain-text captures
    else:
        # The parse is bounded by MAX_TOOL_OUTPUT_BYTES, and ingest already
        # parses this same file, so it adds no ceiling the pipeline lacked.
        if tool == "eslint-security":
            from scripts.tools.eslint_security import sanitize_capture
            try:
                # Work on a copy so changed source diagnostics force serialization.
                cleaned = sanitize_capture(json.loads(text))
            except ValueError:
                # Invalid metadata or a malformed neighboring row must not
                # disable parser-text sanitization. No trustworthy document
                # can be retained; publish only an unparseable static marker.
                return b"panopticon: unusable ESLint capture\n"
        else:
            cleaned = parsed
        scrubbed = redact.redact_tree(cleaned)
        if scrubbed == parsed:
            return data
        style = {}
        if len(text) <= _STYLE_PROBE_MAX_BYTES:
            probe = _json_style(text)
            if json.dumps(parsed, **probe) == text:
                style = probe
        masked = json.dumps(scrubbed, **style)
    if masked == text:
        return data
    # Disclosed, not silent: for most scanners a secret in the capture means the
    # scan surface was wrong. Only ever reached when a capture is being written,
    # so it cannot crowd out the driver's no-output failure note (#1317).
    note = ("capture diagnostics or secret-shaped values sanitized before writing"
            if tool == "eslint-security" else
            "capture carried secret-shaped values; masked before writing")
    print("%s %s" % (tool, note), file=sys.stderr)
    return masked.encode("utf-8")


def _atomic_write(out_path, data):
    """Atomically replace out_path with data.

    #1735: every SARIF capture goes through here, and `out_path` is under
    `.panopticon/tools/` in the REVIEWED tree. `mkstemp` leaves no plantable
    staging name, but it stages in `dirname(out_path)` -- so a target that
    commits `.panopticon/tools` as a directory symlink has every capture
    written, and then `os.replace`d, outside the tree. O_NOFOLLOW would never
    see that (it guards the final component only); the whole-path confinement
    is the guard that does.
    """
    safe_write.confine_artifact_path(out_path)
    fd, temp_path = tempfile.mkstemp(
        prefix=".%s-" % os.path.basename(out_path),
        dir=os.path.dirname(out_path) or ".")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, out_path)
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass
    return out_path

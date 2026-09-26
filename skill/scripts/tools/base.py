"""Shared base utilities for tool adapters."""
from __future__ import annotations
import collections
import contextlib
import contextvars
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from collections.abc import Iterator
from typing import Any, Protocol

from scripts.provenance import tool_provenance


# The scanned repo root, set by the INGEST side around the parse it performs
# (#1649). `invoke` and `parse` never run in the same process on a real scan:
# run_tools dispatches each adapter as
# `docker run ... _run_adapter.py <tool>`, which calls only `invoke` and writes
# the raw bytes out, and `ingest_tools` later calls only `parse` on the host.
# So an adapter whose finding LOCATION depends on which manifest it audited
# cannot carry that answer across -- it has to resolve it a second time, from
# the tree, on the side that parses. `ingest_tools` is the one place that both
# parses and holds the root, so it is the one place that sets this.
target_root_cv: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "panopticon_target_root", default=None)


# Adapters may drop results with no actionable location, or synthesize one.
# Each adapter declares its policy explicitly.
DROP_IF_NO_LOCATION = False  # default; adapters override if needed


def omit_none(mapping: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *mapping* with keys whose values are None removed."""
    return {k: v for k, v in mapping.items() if v is not None}


def has_any_file(target: str, *names: str) -> bool:
    """True if any of *names* exists as a regular file directly under *target*."""
    return any(os.path.isfile(os.path.join(target, n)) for n in names)


def as_list(value: Any) -> list:
    """Wrap a single optional value as a one-item list, or [] when falsy."""
    return [value] if value else []


def attach_tool_provenance(finding: dict[str, Any], adapter_name: str,
                           reasoning: str | None = None) -> dict[str, Any]:
    """Attach tool provenance to *finding* and return the finding."""
    finding["provenance"] = tool_provenance(adapter_name, reasoning=reasoning)
    return finding


SEV_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "severe": "HIGH",
    "important": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "none": "INFO",
    # SARIF `level` (#1229). This is the format the pipeline ingests most, and
    # its whole vocabulary used to fall through to the INFO default.
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
}

# Distinct unmapped values already reported, so a scanner that emits one on
# every finding costs one line, not thousands.
_warned_severities: set[str] = set()

ID_RE = re.compile(r"^[A-Z]{2,4}-\d{3,}$")


def normalize_severity(value: str | None) -> str:
    """Map a tool's severity word onto the pipeline's ladder.

    #1229 (COD-C1B): an UNMAPPED value used to become INFO in silence, which
    can bury a genuinely severe finding beneath the gate floor. An unmapped
    value is a gap in SEV_MAP -- not a tool saying "informational" -- so the
    fallback now says which word it could not place. The fallback itself is
    still INFO: changing it moves gate outcomes for every scan, which is an
    owner call, not a side effect of adding a warning.
    """
    if not isinstance(value, str):
        return "INFO"
    key = value.lower().strip()
    if not key:
        return "INFO"                # the tool said nothing; not a map gap
    if key in SEV_MAP:
        return SEV_MAP[key]
    if key not in _warned_severities:
        _warned_severities.add(key)
        print("unmapped tool severity %r; grading it INFO. Add it to "
              "tools.base.SEV_MAP if it means something higher." % value,
              file=sys.stderr, flush=True)
    return "INFO"


def new_finding_id(prefix: str, n: int) -> str:
    return f"{prefix}-{n:03d}"


_ANSI_CSI_RE = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")


def strip_ansi(raw: bytes) -> bytes:
    """Strip ANSI CSI escape sequences (color, cursor, line-erase) that some
    tools interleave with their stdout before the JSON payload — e.g.
    pip-audit's progress spinner, bandit's progress bar. A no-op on clean
    output (no ESC bytes)."""
    return _ANSI_CSI_RE.sub(b"", raw)


def parse_json_bytes(raw: bytes) -> Any:
    """Decode scanner output bytes tolerantly and parse as JSON — the shared
    adapter idiom (one home for the decoding policy). Strips a leading ANSI /
    log preamble and trims to the first JSON start token so decorated stdout
    (progress spinners, banners) still parses; genuinely non-JSON input still
    raises."""
    cleaned = strip_ansi(raw)
    starts = [i for i in (cleaned.find(b"{"), cleaned.find(b"[")) if i != -1]
    if starts:
        cleaned = cleaned[min(starts):]
    return json.loads(cleaned.decode("utf-8", errors="replace"))


def cvss_bucket(score: float) -> str:
    """Map a numeric CVSS score to the pipeline's severity scale."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


_CIA_WEIGHTS = {"N": 0, "L": 0.22, "H": 0.56}


def _cvss_v3_score(vector: str) -> float | None:
    """Calculate CVSS v3.1 base score from a vector string."""
    try:
        metrics = dict(part.split(":") for part in vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/"))
        av = metrics.get("AV", "")
        ac = metrics.get("AC", "")
        pr = metrics.get("PR", "")
        ui = metrics.get("UI", "")
        s = metrics.get("S", "")
        c = metrics.get("C", "")
        i = metrics.get("I", "")
        a = metrics.get("A", "")
        if not all([av, ac, pr, ui, s, c, i, a]):
            return None
        iss = 1 - ((1 - _CIA_WEIGHTS.get(c, 0)) *
                   (1 - _CIA_WEIGHTS.get(i, 0)) *
                   (1 - _CIA_WEIGHTS.get(a, 0)))
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if s == "C" else 6.42 * iss
        av_score = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(av, 0.85)
        ac_score = {"L": 0.77, "H": 0.44}.get(ac, 0.77)
        pr_weights: dict[str, float | dict[str, float]] = {
            "N": 0.85, "L": {"U": 0.62, "C": 0.68}, "H": {"U": 0.27, "C": 0.5}}
        pr_scores = pr_weights.get(pr, 0.85)
        pr_score = pr_scores.get(s, 0.85) if isinstance(pr_scores, dict) else pr_scores
        ui_score = {"N": 0.85, "R": 0.62}.get(ui, 0.85)
        exploitability = 8.22 * av_score * ac_score * pr_score * ui_score
        if impact <= 0:
            score = 0.0
        elif s == "C":
            score = min(1.08 * (impact + exploitability), 10.0)
        else:
            score = min(impact + exploitability, 10.0)
        # CVSS v3.1 spec: Roundup(x) = smallest 1-decimal >= x (#475). Without
        # it every boundary score under-reads (e.g. the textbook 9.8 vector
        # computed 9.76 -> reported 9.7-ish instead of 9.8), skewing severity
        # bucketing at HIGH/CRITICAL thresholds. Epsilon per the spec's
        # reference implementation to dodge float artifacts.
        return math.ceil(score * 10 - 1e-9) / 10 if score else 0.0
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def cve_ids(values: list | None) -> list[str]:
    """Uppercased CVE-* ids from a list of advisory ids/aliases."""
    return [v.upper() for v in values or []
            if isinstance(v, str) and v.upper().startswith("CVE-")]


INERT_TEXT_MAX = 2000        # a label: title, category, a path, a rule id
INERT_BODY_MAX = 20000       # prose: description, impact, remediation
INERT_CUT = "…"         # the cut is MARKED, so a cut value cannot read whole
INERT_KEEP = "\t\n"          # the only control chars that carry a document's
#                              own structure; a label collapses them to a space
# mode -> (what the escape leaves alone, whether whitespace collapses to one
# line). A PATH is the third mode and it keeps neither: a filename's own bytes
# are what every consumer resolves it by, so nothing but a control char may
# change -- `src/a  b.py`, a macOS `Screen\u202fShot.png`, an NBSP or a U+3000
# name must come back identical (#1829 fix round 1: `str.split()` splits on
# EVERY Unicode space, so the label form silently renamed them).
INERT_MODES: dict[str, tuple[str, bool]] = {
    "label": (INERT_KEEP, True),     # title, category, rule id, group name
    "body": (INERT_KEEP, False),     # description, impact, remediation
    "path": ("", False),             # location.file, a probe's relpath
}
# The tail of a cut that would leave one of this module's own escapes half
# written (`\`, `\x`, `\x1`, `\u`, `\u20`, ...). Dropped before the marker.
_INERT_PARTIAL_TAIL = re.compile(r"\\(x[0-9a-f]?|u[0-9a-f]{0,3})?$")


def inert_escape(text: str, keep: str = INERT_KEEP) -> str:
    r"""Render every character that can steer a terminal, a log line or a
    markdown document as an inert `\xNN` / `\uNNNN` escape: C0, DEL, C1 and the
    Unicode line/paragraph separators. Ordinary characters -- non-ASCII
    included -- pass through untouched, so a legitimate path or package name is
    unchanged.

    ESCAPED, not stripped, and that is the whole point (#1829): a stripped
    `\x1b[2J` leaves `[2J` reading as literal text the scanner wrote, while
    `\x1b[2J` says what actually arrived. This is also the ONE spelling of an
    inert control byte in the tree -- `phases/runio._prompt_safe` writes the
    same escapes for the reviewer's prompt (#1190 AGT-A1A), and
    tests/tools/test_base.py pins the two equal rather than letting a second
    spelling appear.
    """
    out = []
    for ch in text:
        o = ord(ch)
        if (o < 0x20 or o == 0x7f or 0x80 <= o <= 0x9f
                or o in (0x2028, 0x2029)) and ch not in keep:
            out.append("\\x%02x" % o if o < 0x100 else "\\u%04x" % o)
        else:
            out.append(ch)
    return "".join(out)


def inert_text(value: Any, *, limit: int = INERT_TEXT_MAX,
               mode: str = "label") -> str:
    """UNTRUSTED tool/target text made safe to render, and bounded.

    The ONE neutralizer for every field a target or its scanner authored, at the
    normalization boundary both finding builders below are (#1829
    SEC-4277410777 / SEC-798292895 / SEC-2200312865, closing the #1752 residual
    filed as #2069): titles, categories, paths, rule ids, impact and
    remediation are built straight from scanned-repo strings (package/gem/crate
    names, dependency filenames, SARIF messages, a filename a target commits),
    and `synth/render.render_summary` prints several of them to an operator's
    terminal. Fixing them HERE is what lets every renderer inherit it instead of
    each one remembering.

    `mode` (see INERT_MODES) is how much of the text's own shape survives. A
    LABEL, the default, is single-line: tabs and newlines survive the escape and
    are then collapsed with the rest of the whitespace, because an ordinary
    multi-line tool message is not an attack and reads better as one line. A
    BODY keeps its line structure; only `\\r`, which moves the cursor back over
    what was already printed, is escaped there too. A PATH keeps every byte a
    real filename may hold -- the collapse would rename it, and `location.file`
    is resolved on disk (`evidence_scope._usable`) and compared for equality
    (`grading`'s group-file match) -- so a tab or newline in a name is escaped
    and nothing else moves. An unknown mode raises rather than defaulting to
    the loosest one.

    Bounded, with the cut MARKED: a SARIF `message.text` is unbounded inside the
    50 MiB ingest cap, and a value that was cut must not read as a whole one.
    The slice before the escape is `8 * limit` because the escape rebuilds the
    string and expands by at most 6 per character, so a wider window cannot
    change the answer (`phases/review._hit_text`'s measurement). The cut itself
    never splits an escape: a marker after `\\x1` would read as text the target
    wrote rather than as the six bytes this function replaced.
    """
    try:
        keep, collapse = INERT_MODES[mode]
    except KeyError:
        raise ValueError("inert_text: unknown mode %r (have %s)"
                         % (mode, ", ".join(sorted(INERT_MODES)))) from None
    cap = max(int(limit), 1)
    text = inert_escape(str(value)[:8 * cap], keep=keep)
    if collapse:
        text = " ".join(text.split())
    if len(text) <= cap:
        return text
    return _INERT_PARTIAL_TAIL.sub("", text[:cap]) + INERT_CUT


def make_finding(adapter: Any, n: int, group: str, *, title: str, severity: str,
                 category: str, location: dict, description: str, impact: str,
                 remediation: str, references: list | None = None,
                 citations: dict | None = None, tool_evidence: dict | None = None,
                 confidence: str = "CERTAIN") -> dict:
    """Assemble the NARF finding envelope every adapter shares.

    NARF -- Normalized Analysis Result Format -- is the shape every finding
    takes once it is ours, whatever produced it: a static analyzer via an
    adapter, a domain panel, or an advisor. SARIF is the closest analogue and
    deliberately the closest name, but SARIF normalizes ANALYZER output, while
    a real run is overwhelmingly reviewer output -- gotify's report held 131
    panel findings to 1 tool finding, in one findings[] array with one shape.
    Hence "Analysis" rather than "Static Analysis": the S would describe the
    minority of what the format carries. Serialized as `.narf.json`.

    Owns the fields downstream stages key on — id, panel, source, _group,
    provenance (reasoning = the tool_evidence rule_id), and the citations rule
    (attached only when a citation list is non-empty) — so a schema change is
    one edit here instead of one per adapter. Adapter-specific content arrives
    via the keyword fields.
    """
    # #run9 SEC-B1C covered title and description; #1829 SEC-4277410777 / #2069
    # covers the rest of what a target or its scanner wrote. A COPY of the
    # location and the tool evidence: the adapter may keep and reuse its own dict
    # (osv/eslint build one per hit), and neutralizing is not ours to do to it.
    if isinstance(location, dict) and isinstance(location.get("file"), str):
        location = dict(location, file=inert_text(location["file"], mode="path"))
    tool_evidence = dict(tool_evidence or {})
    if isinstance(tool_evidence.get("rule_id"), str):
        tool_evidence["rule_id"] = inert_text(tool_evidence["rule_id"])
    finding: dict[str, Any] = {
        "id": new_finding_id(adapter.prefix, n),
        "title": inert_text(title),
        "severity": severity,
        "confidence": confidence,
        "panel": "security",
        # `or ""`: an absent body field is empty, never the word "None" --
        # `normalize_finding` has always guarded it that way.
        "category": inert_text(category or ""),
        "source": f"tool:{adapter.name}",
        "location": location,
        "description": inert_text(description or "", limit=INERT_BODY_MAX, mode="body"),
        "impact": inert_text(impact or "", limit=INERT_BODY_MAX, mode="body"),
        "remediation": inert_text(remediation or "", limit=INERT_BODY_MAX, mode="body"),
        "references": references or [],
        "tool_evidence": tool_evidence,
        "_group": group,
    }
    citations = {k: v for k, v in (citations or {}).items() if v}
    if citations:
        finding["citations"] = citations
    return attach_tool_provenance(finding, adapter.name,
                                  reasoning=finding["tool_evidence"].get("rule_id"))


class ToolAdapter(Protocol):
    name: str

    @property
    def prefix(self) -> str:
        ...

    def is_applicable(self, target: str) -> bool:
        ...

    def invoke(self, target: str) -> tuple[bytes, int]:
        ...

    def parse(self, raw: bytes, group: str) -> list[dict]:
        ...

MAX_TOOL_OUTPUT_BYTES = 50 * 1024 * 1024
# #1576 (run-13 OPS-3272189615 / OPS-2007447947): how often a watched scanner's
# own report is measured while it writes. read_capped_report's ceiling is a
# READ-time bound on a write that has already happened -- by the time it
# refuses an oversize report the temp volume is full and every concurrent scan
# on that worker is already affected. `run_tool(watch_path=...)` polls the path
# the scanner writes to and kills the child at the first poll that finds it over
# `watch_cap`, which defaults to the SAME 50 MiB: a report the reader would
# refuse is not worth letting the scanner finish. A poll is not an instant, so
# the effective ceiling is `watch_cap` plus whatever the scanner can write in
# one interval -- state it rather than imply a precision this cannot have.
#
# A poll rather than RLIMIT_FSIZE in a preexec_fn: RLIMIT_FSIZE caps the
# largest single FILE, not a multi-file report tree, and CPython documents
# preexec_fn as unsafe in the presence of threads -- run_tool already runs a
# watchdog timer and a stderr drain thread.
OUTPUT_WATCH_INTERVAL = 0.5
# #run8 COD-A2A: stderr is only ever excerpted for diagnostics, so its drain
# buffer is capped far below stdout. A tool flooding stderr while writing stdout
# can't grow memory unbounded — the drain keeps reading past the cap (no pipe
# deadlock), it just stops accumulating.
MAX_TOOL_STDERR_BYTES = 1 * 1024 * 1024


def drain_stderr_async(proc, cap=MAX_TOOL_STDERR_BYTES):
    """Drain ``proc.stderr`` to EOF on a daemon thread, retaining ``cap`` bytes.

    Both capture paths need this. A child that fills its stderr pipe (64 KB on
    Linux) blocks on write; a parent that reads stdout to EOF *first* is then
    waiting on stdout the blocked child cannot produce, and only the watchdog
    breaks the tie -- at the cost of the whole scan timeout plus that scanner's
    coverage (#1510 / Codex BR-05, and #K2-1 for the inner runner).

    Draining therefore starts at process start and CONTINUES PAST the retention
    cap: once we stop keeping bytes we must still read them, or the pipe backs
    up and the deadlock returns by another door.

    Retention keeps the TAIL. The buffer exists to diagnose "exited N", and a
    scanner puts its error message last; keeping the head would bound memory
    while discarding the only part worth printing. At least one chunk is always
    retained, so a single read larger than `cap` still yields diagnostics.

    Returns a ``join(timeout=2.0) -> bytes`` callable.
    """
    chunks: collections.deque[bytes] = collections.deque()
    kept = [0]

    def _pump():
        try:
            while True:
                chunk = proc.stderr.read(64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
                kept[0] += len(chunk)
                while kept[0] > cap and len(chunks) > 1:
                    kept[0] -= len(chunks.popleft())
        except Exception:
            pass

    thread = threading.Thread(target=_pump)
    thread.daemon = True
    thread.start()

    def join(timeout=2.0):
        thread.join(timeout)
        return b"".join(chunks)

    return join


def _drain(stream):
    """Read and discard the rest of a stream so the child is never left blocked
    on a full pipe."""
    while stream.read(64 * 1024):
        pass


class OutputCapExceeded(RuntimeError):
    """A watched scanner blew past its write-time output cap and was killed.

    Raised by `run_tool` instead of returning, because there is no partial
    result to hand back: the report on disk is a fragment of one the reader
    would have refused. The adapter turns it into its own bounded failure
    disposition (recorded missing -> INCONCLUSIVE), never a clean empty scan.
    """

    def __init__(self, path, cap, size):
        super().__init__(
            "%s exceeded its write-time output cap (%d bytes written, cap %d)"
            % (path, size, cap))
        self.path, self.cap, self.size = path, cap, size


def _output_size(path, stop=None):
    """Bytes at `path`: a file's size, or the recursive sum of a directory's.

    Never follows symlinks (a scanned tree may link anywhere, and /etc is not
    the scanner's output) and never raises: the tree is changing underneath the
    walk, so an entry that vanished mid-scan is simply not counted. Stops
    adding once `stop` is passed, so one poll of a huge tree costs no more than
    it must to answer "over the cap?".
    """
    total = 0
    stack = [path]
    while stack:
        cur = stack.pop()
        try:
            st = os.lstat(cur)
        except OSError:
            continue
        if stat.S_ISDIR(st.st_mode):
            try:
                with os.scandir(cur) as entries:
                    stack.extend(e.path for e in entries)
            except OSError:
                pass
            continue
        total += st.st_size
        if stop is not None and total > stop:
            return total
    return total


def _kill_process_tree(proc):
    """SIGKILL `proc`, and its whole process group when it leads one.

    A scanner launched through a shell wrapper (dependency-check.sh) leaves the
    real worker as a grandchild that proc.kill() never reaches. Callers that
    pass `start_new_session=True` make the child a group leader, and then the
    group kill lands on the whole tree; without it this is exactly proc.kill().
    """
    try:
        if os.getpgid(proc.pid) == proc.pid:
            os.killpg(proc.pid, signal.SIGKILL)
            return
    except (OSError, AttributeError):
        pass
    try:
        proc.kill()
    except Exception:                      # noqa: BLE001 - already gone is fine
        pass


class _OutputSizeWatcher(threading.Thread):
    """Poll a scanner's output path while it runs; kill it past `cap` (#1576).

    The bound the adapters needed and did not have: a write-time ceiling on a
    report the scanner writes for itself. Polled, so the real ceiling is `cap`
    plus one OUTPUT_WATCH_INTERVAL of the scanner's write throughput -- the
    guarantee is that it STOPS, not that it stops on the exact byte. It announces the kill on stderr as it
    happens -- the operator's only witness that a scan ended for this reason
    rather than any other -- and `run_tool` turns it into OutputCapExceeded.
    """

    def __init__(self, proc, path, cap, label):
        super().__init__(daemon=True)
        self._proc, self._path, self._cap, self._label = proc, path, cap, label
        self._done = threading.Event()
        self.exceeded = False
        self.size = 0

    def run(self):
        while not self._done.wait(OUTPUT_WATCH_INTERVAL):
            size = _output_size(self._path, stop=self._cap)
            if size <= self._cap:
                continue
            self.exceeded, self.size = True, size
            print("tool %s exceeded its write-time output cap: %d bytes at %s "
                  "(cap %d); killing it -- a report this large would be refused "
                  "at read time anyway" % (self._label, size, self._path, self._cap),
                  file=sys.stderr)
            _kill_process_tree(self._proc)
            return

    def stop(self):
        self._done.set()


def _raise_if_output_capped(watcher, path, cap):
    """Turn a watcher that fired into OutputCapExceeded (#1576).

    One helper because run_tool leaves by two doors -- the stdout-truncation
    early return and the normal one -- and both have to answer for the
    write-time cap the same way.
    """
    if watcher is not None and watcher.exceeded:
        raise OutputCapExceeded(path, cap, watcher.size)


@contextlib.contextmanager
def scratch_cwd(prefix: str) -> Iterator[str]:
    """Yield a fresh empty directory to run a scanner FROM, then remove it.

    A scanner's working directory is where its own config and dispatch
    resolution walk from -- `.npmrc`, `.semgrepignore`, `.gitleaksignore`,
    `.cargo/config.toml`, a brakeman/spotbugs/dependency-check ignore file --
    so a cwd inside the scanned tree lets a hostile target silence or redirect
    the scan for free (#1742). Passing no cwd is not neutral either: the tools
    image ends `WORKDIR /src` and `/src` IS the target mount, so "no cwd"
    means "the target" (#1877). Every adapter therefore names its own scratch
    directory here and names the target by absolute path in argv, which makes
    the whole class unreachable through the filesystem rather than only
    through each tool's grammar.

    PRECONDITION, since several adapters pass their `target` straight through
    to argv: the CALLER names the target by absolute path. `_run_adapter.py`
    does so for every dispatched scan; a caller that hands an adapter a
    relative path would have it resolved against this scratch, which by
    construction holds nothing.

    `rmtree(ignore_errors=True)`, never `rmdir` (#1646 F3): this directory
    exists PRECISELY to be where stray writes land -- a build backend's temp
    file, pip's legacy in-cwd artifacts -- so "something wrote there" is the
    expected case. `os.rmdir` raised `Directory not empty`, `_run_adapter`
    caught it and returned FAIL_RC, and pip-audit landed in the manifest's
    `missing`: the coverage gate degraded on a run whose audit had succeeded.
    """
    scratch = tempfile.mkdtemp(prefix=prefix)
    try:
        yield scratch
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def run_tool(cmd, timeout, ok_codes=(0, 1), capture_stderr=False,
             watch_path=None, watch_cap=MAX_TOOL_OUTPUT_BYTES, **kwargs):
    """Run a scanner subprocess, preserving failure diagnostics (F-CAL-1).

    Returns (stdout, returncode) by default, or (stdout, stderr, returncode)
    when *capture_stderr* is True. On exit codes outside ok_codes
    (1 == findings for most scanners; brakeman also uses 2/3), a capped
    stderr excerpt is written to our stderr so 'exited N; skipping' is
    diagnosable.

    Bounded capture: stdout is streamed into a bounded buffer so
    adversarial/large target output does not accumulate unbounded in memory
    (#1111). When the byte cap is exceeded the child is terminated, the output
    is truncated with a marker, and a stderr notice is emitted. The partial
    output is still returned so the truncation is visible downstream.

    Stderr is drained concurrently so a child that fills the stderr pipe while
    still writing stdout cannot deadlock the parent (#K2-1).

    `watch_path` (#1576) is for the adapters whose scanner writes its OWN
    report: the path is polled while the child runs and the child is killed at
    the first poll that finds it over `watch_cap`, raising OutputCapExceeded.
    Polling means the effective ceiling is `watch_cap` plus one
    OUTPUT_WATCH_INTERVAL of the scanner's write throughput, not `watch_cap`
    exactly.
    Pass `start_new_session=True` alongside it when the scanner is launched
    through a shell wrapper, so the kill reaches the worker and not just the
    wrapper.
    """
    popen_kwargs = dict(kwargs)
    popen_kwargs.setdefault("stdout", subprocess.PIPE)
    popen_kwargs.setdefault("stderr", subprocess.PIPE)

    timed_out = {"hit": False}

    def _watchdog():
        # #1576 fix round 1: the GROUP, not just the child. A scanner behind a
        # shell wrapper leaves the real worker as a grandchild holding the
        # inherited stdout pipe; killing the wrapper alone leaves the parent's
        # read blocked on a pipe the orphan still owns, and `timeout=` stops
        # being a bound -- measured at 15 s for a 1-second timeout. Without
        # start_new_session this is exactly proc.kill(), as before.
        timed_out["hit"] = True
        _kill_process_tree(proc)

    proc = subprocess.Popen(cmd, **popen_kwargs)  # nosec B603
    timer = threading.Timer(timeout, _watchdog)
    timer.daemon = True
    timer.start()

    watcher = None
    if watch_path is not None:
        watcher = _OutputSizeWatcher(proc, watch_path, watch_cap, cmd[0])
        watcher.start()

    join_stderr = drain_stderr_async(proc)

    try:
        if proc.stdout is None:
            # `popen_kwargs.setdefault("stdout", PIPE)` above makes this
            # unreachable unless a caller passes stdout=None explicitly. It
            # stays a raise rather than an assert because `python -O` strips
            # the assert, and the next line would be an AttributeError on
            # None instead of this sentence (#1533 review).
            raise RuntimeError("tool stdout must be captured with PIPE")
        chunks: list[bytes] = []
        collected = 0
        truncated = False
        while True:
            chunk = proc.stdout.read(64 * 1024)
            if not chunk:
                break
            room = MAX_TOOL_OUTPUT_BYTES - collected
            if room <= 0:
                truncated = True
                _drain(proc.stdout)
                break
            if len(chunk) > room:
                chunks.append(chunk[:room])
                collected += room
                truncated = True
                _drain(proc.stdout)
                break
            chunks.append(chunk)
            collected += len(chunk)

        if truncated:
            _kill_process_tree(proc)      # the group, for the reason above
            stdout = b"".join(chunks)
            marker = (
                "\n\n[TRUNCATED by panopticon: output exceeded %d byte limit; "
                "only the first %d bytes were retained]\n" % (
                    MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_OUTPUT_BYTES)
            ).encode("utf-8")
            print(
                "tool %s output exceeded %d byte limit; truncated and retained "
                "with marker" % (cmd[0], MAX_TOOL_OUTPUT_BYTES),
                file=sys.stderr,
            )

        rc = proc.wait()
        stderr = join_stderr()

        if truncated:
            # #1576 fix round 1: this early return sits inside the try, so it
            # used to leave the function BEFORE the write-time check below. An
            # adapter whose scanner blew BOTH caps got (partial output, -9) --
            # a partial result from a scan that was killed -- and its
            # `except OutputCapExceeded` never fired. The write-time cap
            # outranks the truncation: there is no usable report either way.
            _raise_if_output_capped(watcher, watch_path, watch_cap)
            if capture_stderr:
                return stdout + marker, stderr, rc
            return stdout + marker, rc
    finally:
        timer.cancel()
        if watcher is not None:
            watcher.stop()
        try:
            if proc.stdout is not None:
                proc.stdout.close()
        except Exception:
            pass
        # Closing stderr wakes the drain thread if it is still blocked.
        join_stderr(0.5)
        try:
            if proc.stderr is not None:
                proc.stderr.close()
        except Exception:
            pass
        if proc.poll() is None:
            _kill_process_tree(proc)      # the group, for the reason above

    # Checked BEFORE the timeout: when the watchdog and the size watcher both
    # fire, the cap is the specific truth and "timed out" is the consequence.
    _raise_if_output_capped(watcher, watch_path, watch_cap)

    if timed_out["hit"] and rc not in (0, 1):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)

    if rc not in ok_codes:
        excerpt = (stderr or b"")[-1000:].decode("utf-8", errors="replace").strip()
        details = f": {excerpt}" if excerpt else ""
        print(f"tool {cmd[0]} exited {rc}{details}", file=sys.stderr)

    if capture_stderr:
        return b"".join(chunks), stderr, rc
    return b"".join(chunks), rc


def read_capped_report(path, cap=MAX_TOOL_OUTPUT_BYTES):
    """Read a scanner's on-disk report under the same byte ceiling run_tool
    applies to stdout capture (#run8 OPS-D1A).

    Adapters whose scanner writes its report to a file (dependency-check JSON,
    roslyn SARIF) bypass run_tool's MAX_TOOL_OUTPUT_BYTES stdout cap entirely --
    an attacker-influenced report of arbitrary size (a build manifest crafted to
    emit a huge dependency/CVE set, a project that drives a scanner to a giant
    SARIF result set) would otherwise be slurped whole into memory. Reads one
    byte past the cap to detect the overflow, then FAILS CLOSED on an oversize
    report (returns None) instead of handing back a truncated, half-parsed blob.

    Returns the report bytes on success, or None when the file is missing,
    unreadable, or exceeds the cap -- the caller substitutes its own empty/
    failure result so downstream ingest sees "no output" rather than a partial
    one. Mirrors the on-disk cap ingest_tools.py already applies to *.sarif/*.json
    it is pointed at."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(cap + 1)
    except OSError as exc:
        print("panopticon: cannot read report %s: %s" % (path, exc), file=sys.stderr)
        return None
    if len(raw) > cap:
        print("panopticon: report %s exceeds the %d-byte cap; refusing"
              % (path, cap), file=sys.stderr)
        return None
    return raw

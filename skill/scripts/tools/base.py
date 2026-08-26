"""Shared base utilities for tool adapters."""
from __future__ import annotations
import json
import math
import os
import re
import subprocess
import sys
import threading
from typing import Any, Protocol

from scripts.provenance import tool_provenance


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
}

ID_RE = re.compile(r"^[A-Z]{2,4}-\d{3,}$")


def normalize_severity(value: str | None) -> str:
    if not isinstance(value, str):
        return "INFO"
    return SEV_MAP.get(value.lower().strip(), "INFO")


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
        pr_scores = {"N": 0.85, "L": {"U": 0.62, "C": 0.68}, "H": {"U": 0.27, "C": 0.5}}.get(pr, 0.85)
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


def make_finding(adapter: Any, n: int, group: str, *, title: str, severity: str,
                 category: str, location: dict, description: str, impact: str,
                 remediation: str, references: list | None = None,
                 citations: dict | None = None, tool_evidence: dict | None = None,
                 confidence: str = "CERTAIN") -> dict:
    """Assemble the invariant tool-finding envelope every adapter shares.

    Owns the fields downstream stages key on — id, panel, source, _group,
    provenance (reasoning = the tool_evidence rule_id), and the citations rule
    (attached only when a citation list is non-empty) — so a schema change is
    one edit here instead of one per adapter. Adapter-specific content arrives
    via the keyword fields.
    """
    finding = {
        "id": new_finding_id(adapter.prefix, n),
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "panel": "security",
        "category": category,
        "source": f"tool:{adapter.name}",
        "location": location,
        "description": description,
        "impact": impact,
        "remediation": remediation,
        "references": references or [],
        "tool_evidence": tool_evidence or {},
        "_group": group,
    }
    citations = {k: v for k, v in (citations or {}).items() if v}
    if citations:
        finding["citations"] = citations
    return attach_tool_provenance(finding, adapter.name,
                                  reasoning=finding["tool_evidence"].get("rule_id"))


class ToolAdapter(Protocol):
    name: str
    prefix: str

    def is_applicable(self, target: str) -> bool:
        ...

    def invoke(self, target: str) -> tuple[bytes, int]:
        ...

    def parse(self, raw: bytes, group: str) -> list[dict]:
        ...

MAX_TOOL_OUTPUT_BYTES = 50 * 1024 * 1024
# #run8 COD-A2A: stderr is only ever excerpted for diagnostics, so its drain
# buffer is capped far below stdout. A tool flooding stderr while writing stdout
# can't grow memory unbounded — the drain keeps reading past the cap (no pipe
# deadlock), it just stops accumulating.
MAX_TOOL_STDERR_BYTES = 1 * 1024 * 1024


def _drain(stream):
    """Read and discard the rest of a stream so the child is never left blocked
    on a full pipe."""
    while stream.read(64 * 1024):
        pass


def run_tool(cmd, timeout, ok_codes=(0, 1), capture_stderr=False, **kwargs):
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
    """
    popen_kwargs = dict(kwargs)
    popen_kwargs.setdefault("stdout", subprocess.PIPE)
    popen_kwargs.setdefault("stderr", subprocess.PIPE)

    timed_out = {"hit": False}

    def _watchdog():
        timed_out["hit"] = True
        try:
            proc.kill()
        except Exception:
            pass

    proc = subprocess.Popen(cmd, **popen_kwargs)  # nosec B603
    timer = threading.Timer(timeout, _watchdog)
    timer.daemon = True
    timer.start()

    stderr_chunks: list[bytes] = []
    stderr_collected = 0

    def _drain_stderr():
        nonlocal stderr_collected
        try:
            while True:
                chunk = proc.stderr.read(64 * 1024)
                if not chunk:
                    break
                if stderr_collected < MAX_TOOL_STDERR_BYTES:
                    stderr_chunks.append(chunk)
                    stderr_collected += len(chunk)
        except Exception:
            pass

    stderr_thread = threading.Thread(target=_drain_stderr)
    stderr_thread.daemon = True
    stderr_thread.start()

    try:
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
            try:
                proc.kill()
            except Exception:
                pass
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
        stderr_thread.join(timeout=2.0)
        stderr = b"".join(stderr_chunks)

        if truncated:
            if capture_stderr:
                return stdout + marker, stderr, rc
            return stdout + marker, rc
    finally:
        timer.cancel()
        try:
            proc.stdout.close()
        except Exception:
            pass
        # Closing stderr wakes the drain thread if it is still blocked.
        stderr_thread.join(timeout=0.5)
        try:
            proc.stderr.close()
        except Exception:
            pass
        if proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass

    if timed_out["hit"] and rc not in (0, 1):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)

    if rc not in ok_codes:
        excerpt = (stderr or b"")[-1000:].decode("utf-8", errors="replace").strip()
        details = f": {excerpt}" if excerpt else ""
        print(f"tool {cmd[0]} exited {rc}{details}", file=sys.stderr)

    if capture_stderr:
        return b"".join(chunks), stderr, rc
    return b"".join(chunks), rc

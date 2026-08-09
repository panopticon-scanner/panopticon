"""Shared base utilities for tool adapters."""
from __future__ import annotations
import json
import os
import re
import sys
import subprocess
from typing import Any, Protocol

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
from scripts.provenance import tool_provenance


def omit_none(mapping: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *mapping* with keys whose values are None removed."""
    return {k: v for k, v in mapping.items() if v is not None}


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


def parse_json_bytes(raw: bytes) -> Any:
    """Decode scanner output bytes tolerantly and parse as JSON — the shared
    adapter idiom (one home for the decoding policy)."""
    return json.loads(raw.decode("utf-8", errors="replace"))


def cvss_bucket(score: float) -> str:
    """Map a numeric CVSS score to the pipeline's severity scale."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


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

def run_tool(cmd, timeout, ok_codes=(0, 1), **kwargs):
    """Run a scanner subprocess, preserving failure diagnostics (F-CAL-1).

    Returns (stdout, returncode) — the adapter invoke() contract. On exit
    codes outside ok_codes (1 == findings for most scanners; brakeman also
    uses 2/3), a capped stderr excerpt is written to our stderr so
    'exited N; skipping' is diagnosable.
    """
    res = subprocess.run(cmd, capture_output=True, timeout=timeout, **kwargs)
    rc = res.returncode
    if rc not in ok_codes:
        excerpt = (res.stderr or b"")[-1000:].decode("utf-8", errors="replace").strip()
        print("tool %s exited %d%s" % (cmd[0], rc,
              (": %s" % excerpt) if excerpt else ""), file=sys.stderr)
    return res.stdout, rc

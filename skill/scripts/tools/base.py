"""Shared base utilities for tool adapters."""
from __future__ import annotations
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

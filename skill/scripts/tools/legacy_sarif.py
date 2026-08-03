"""Adapter that preserves the existing SARIF ingestion for semgrep/bandit/etc."""
from __future__ import annotations
import json
import subprocess

import scripts.tools.sarif_utils as su


# Tools that produce SARIF output and are dispatched through this adapter.
LEGACY_SARIF_TOOLS = {"semgrep", "bandit", "trivy", "gitleaks", "gosec", "eslint"}

# Per-tool argv producing SARIF on stdout. /src is substituted with the actual
# target path at invocation time.
TOOL_CMD = {
    "semgrep": ["semgrep", "scan", "--config", "auto", "--sarif", "--quiet", "/src"],
    "gitleaks": ["gitleaks", "detect", "--no-git", "--source", "/src", "--report-format", "sarif",
                 "--report-path", "/dev/stdout", "--no-banner"],
    "trivy": ["trivy", "fs", "--format", "sarif", "/src"],
    "bandit": ["bandit", "-r", "/src", "-f", "sarif"],
    "gosec": ["gosec", "-fmt=sarif", "./..."],
    "eslint": ["eslint", "-f", "@microsoft/eslint-formatter-sarif", "/src"],
}

# Max seconds to let a single tool invocation run before it's killed.
TOOL_TIMEOUT = 300


class LegacySarifAdapter:
    def __init__(self, name: str):
        self.name = name

    @property
    def prefix(self) -> str:
        return su.PREFIX.get(self.name, "TL")

    def is_applicable(self, target: str) -> bool:
        return True

    def invoke(self, target: str) -> tuple[bytes, int]:
        """Run the legacy SARIF tool against target and return its raw output."""
        if self.name not in TOOL_CMD:
            raise NotImplementedError(f"no command defined for tool {self.name}")
        cmd = [target if arg == "/src" else arg for arg in TOOL_CMD[self.name]]
        # gosec scans relative to the working directory.
        cwd = target if self.name == "gosec" else None
        res = subprocess.run(cmd, capture_output=True, timeout=TOOL_TIMEOUT, cwd=cwd)
        # Most security scanners exit 1 when findings are present; preserve that
        # as a successful scan so the SARIF output can still be ingested.
        return res.stdout, res.returncode

    def parse(self, raw: bytes, group: str) -> list[dict]:
        sarif = json.loads(raw)
        return su.sarif_to_findings(sarif, self.name, group, self.prefix)

"""Adapter that preserves the existing SARIF ingestion for semgrep/bandit/etc."""
from __future__ import annotations
import json

import scripts.tools.sarif_utils as su
from scripts.tools.base import run_tool


# Tools that produce SARIF output and are dispatched through this adapter.
# "eslint" retired (F-CAL-5): eslint >=9 requires a project flat config, so a
# bare invocation can never run on arbitrary targets; JS/TS SAST is the
# eslint-security adapter with its bundled config.
LEGACY_SARIF_TOOLS = {"semgrep", "bandit", "trivy", "gitleaks", "gosec"}

# Per-tool argv producing SARIF on stdout. /src is substituted with the actual
# target path at invocation time.
TOOL_CMD = {
    # --disable-version-check is NOT covered by --metrics=off: they are two
    # separate calls home, and in a --network none container the version check
    # blocks until it times out. Measured on one trivial file: 2m10s with it,
    # 35s without.
    "semgrep": ["semgrep", "scan", "--config", "/opt/semgrep-rules", "--metrics=off",
                "--disable-version-check", "--sarif", "--quiet", "/src"],
    "gitleaks": ["gitleaks", "detect", "--no-git", "--source", "/src", "--report-format", "sarif",
                 "--report-path", "/dev/stdout", "--no-banner"],
    "trivy": ["trivy", "fs", "--skip-db-update", "--offline-scan", "--format", "sarif", "/src"],
    "bandit": ["bandit", "-q", "-r", "/src", "-f", "sarif"],
    "gosec": ["gosec", "-fmt=sarif", "./..."],
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
        # Most security scanners exit 1 when findings are present; run_tool
        # treats (0, 1) as clean and logs a stderr excerpt on anything else.
        return run_tool(cmd, timeout=TOOL_TIMEOUT, cwd=cwd)

    def parse(self, raw: bytes, group: str) -> list[dict]:
        sarif = json.loads(raw)
        return su.sarif_to_findings(sarif, self.name, group, self.prefix)

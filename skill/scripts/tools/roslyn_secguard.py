"""Roslyn Security Guard / SecurityCodeScan adapter for C# security findings."""
from __future__ import annotations
import json
import os
import shutil
import tempfile
from .base import attach_tool_provenance, normalize_severity, new_finding_id, omit_none, run_tool

_ROSLYN_CWE = {
    "SCS0001": "CWE-78",
    "SCS0002": "CWE-89",
    "SCS0007": "CWE-611",
    "SCS0016": "CWE-352",
    "SCS0018": "CWE-22",
    "SCS0026": "CWE-79",
    "SCS0027": "CWE-601",
    "SCS0028": "CWE-502",
    "SCS0041": "CWE-22",
}


class RoslynSecGuardAdapter:
    name = "roslyn-secguard"
    prefix = "RS"

    def is_applicable(self, target: str) -> bool:
        return any(
            f.endswith(".csproj") or f.endswith(".sln")
            for f in os.listdir(target)
            if os.path.isfile(os.path.join(target, f))
        )

    def _build_target(self, target: str) -> str:
        sln_files = []
        csproj_files = []
        for root, _dirs, files in os.walk(target):
            for file in files:
                full_path = os.path.join(root, file)
                if file.endswith(".sln"):
                    sln_files.append(full_path)
                elif file.endswith(".csproj"):
                    csproj_files.append(full_path)
        if sln_files:
            return sorted(sln_files)[0]
        if csproj_files:
            return sorted(csproj_files)[0]
        return target

    def invoke(self, target: str) -> tuple[bytes, int]:
        # Build the target with the SecurityCodeScan analyzer and output SARIF.
        # The project is copied to a temporary directory so read-only mounts and
        # stale incremental build state do not break analysis.
        tmp = tempfile.mkdtemp(prefix="roslyn-")
        try:
            build_target = self._build_target(target)
            rel_target = os.path.relpath(build_target, target)
            tmp_target = os.path.join(tmp, rel_target)
            shutil.copytree(target, tmp, dirs_exist_ok=True)

            sarif = os.path.join(tmp, "out.sarif")
            cmd = [
                "dotnet", "build", tmp_target,
                "-p:TreatWarningsAsErrors=false",
                "-p:ErrorLog=" + sarif + ",version=2.1",
            ]
            _stdout, rc = run_tool(cmd, timeout=600)
            if os.path.exists(sarif):
                with open(sarif, "rb") as fh:
                    return fh.read(), rc
            return b"{}", rc
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _location(self, loc: dict) -> dict:
        # SARIF v1 uses resultFile; v2 uses physicalLocation/artifactLocation.
        if not isinstance(loc, dict):
            loc = {}
        phys = loc.get("physicalLocation", {})
        if phys:
            artifact = phys.get("artifactLocation", {})
            region = phys.get("region", {})
            uri = artifact.get("uri", "")
            line = region.get("startLine", 1)
        else:
            result_file = loc.get("resultFile", {})
            region = result_file.get("region", {})
            uri = result_file.get("uri", "")
            line = region.get("startLine", 1)
        # Strip the file:// scheme and temporary build prefix if present.
        if uri.startswith("file://"):
            uri = uri[7:]
        return {"file": uri, "line_start": line}

    @staticmethod
    def _message_text(result: dict, default: str = "") -> str:
        """Return the message text from a SARIF result.

        SARIF allows ``message`` to be either a plain string or a dict with a
        ``text`` property. Some tools (including older SecurityCodeScan builds)
        emit the string form, so handle both.
        """
        message = result.get("message", default)
        if isinstance(message, dict):
            return message.get("text", default)
        if isinstance(message, str):
            return message
        return default

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for run in data.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                # Only SecurityCodeScan rules are findings. Compiler/restore
                # diagnostics (CS####, NU####, MSB####) are dropped: they are
                # noise from offline builds and can quote file content into
                # the report (the #86 exfiltration channel).
                if not rule_id.startswith("SCS"):
                    continue
                loc = result.get("locations", [{}])[0]
                location = self._location(loc)
                cwe = _ROSLYN_CWE.get(rule_id)
                message = self._message_text(result, rule_id)
                finding = {
                    "id": new_finding_id(self.prefix, n),
                    "title": message,
                    "severity": normalize_severity("HIGH"),
                    "confidence": "LIKELY",
                    "panel": "security",
                    "category": "csharp_security",
                    "source": f"tool:{self.name}",
                    "location": location,
                    "description": message or "No description provided.",
                    "impact": "Potential security issue in C# code.",
                    "remediation": "Review the SecurityCodeScan rule and refactor.",
                    "references": [],
                    "citations": {"cwe": [cwe]} if cwe else None,
                    "tool_evidence": omit_none({"rule_id": rule_id}),
                    "_group": group,
                }
                if not finding["citations"]:
                    finding.pop("citations", None)
                attach_tool_provenance(finding, self.name, reasoning=finding["tool_evidence"].get("rule_id"))
                out.append(finding)
                n += 1
        return out

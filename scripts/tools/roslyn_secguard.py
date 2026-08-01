"""Roslyn Security Guard / SecurityCodeScan adapter for C# security findings."""
from __future__ import annotations
import json
import os
import subprocess
import tempfile
from .base import normalize_severity, new_finding_id, omit_none

_ROSLYN_CWE = {
    "SCS0001": "CWE-89",
    "SCS0026": "CWE-79",
    "SCS0018": "CWE-78",
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

    def invoke(self, target: str) -> tuple[bytes, int]:
        # Experimental: build with SecurityCodeScan analyzer and output SARIF.
        # If the target does not reference the analyzer, this returns few/no findings.
        tmp = tempfile.mkdtemp(prefix="roslyn-")
        sarif = os.path.join(tmp, "out.sarif")
        cmd = [
            "dotnet", "build", target,
            "-p:TreatWarningsAsErrors=false",
            "-p:ErrorLog=" + sarif + ",version=2.1",
        ]
        res = subprocess.run(cmd, capture_output=True, timeout=600)
        if os.path.exists(sarif):
            with open(sarif, "rb") as fh:
                return fh.read(), res.returncode
        return b"{}", res.returncode

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for run in data.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                loc = result.get("locations", [{}])[0]
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                cwe = _ROSLYN_CWE.get(rule_id)
                finding = {
                    "id": new_finding_id(self.prefix, n),
                    "title": result.get("message", {}).get("text", rule_id),
                    "severity": normalize_severity("HIGH"),
                    "confidence": "LIKELY",
                    "panel": "security",
                    "category": "csharp_security",
                    "source": f"tool:{self.name}",
                    "location": {
                        "file": artifact.get("uri", ""),
                        "line_start": region.get("startLine", 1),
                    },
                    "description": result.get("message", {}).get("text", "No description provided."),
                    "impact": "Potential security issue in C# code.",
                    "remediation": "Review the SecurityCodeScan rule and refactor.",
                    "references": [],
                    "citations": {"cwe": [cwe]} if cwe else None,
                    "tool_evidence": omit_none({"rule_id": rule_id}),
                    "_group": group,
                }
                if not finding["citations"]:
                    finding.pop("citations", None)
                out.append(finding)
                n += 1
        return out

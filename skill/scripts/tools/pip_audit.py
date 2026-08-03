"""pip-audit adapter for Python dependency CVEs."""
from __future__ import annotations
import glob
import json
import os
import subprocess
from .base import attach_tool_provenance, normalize_severity, new_finding_id, omit_none


class PipAuditAdapter:
    name = "pip-audit"
    prefix = "PA"

    def __init__(self) -> None:
        self._manifest_path: str | None = None

    def is_applicable(self, target: str) -> bool:
        patterns = ["requirements.txt", "requirements*.txt", "pyproject.toml"]
        for pat in patterns:
            path = os.path.join(target, pat)
            if "*" in pat:
                if glob.glob(path):
                    return True
            elif os.path.exists(path):
                return True
        return False

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = ["pip-audit", "--format=json", "--desc"]
        req = self._find_requirement(target)
        if req:
            self._manifest_path = req
            cmd.extend(["--requirement", req])
        else:
            # pip-audit accepts a project directory as a positional argument or
            # via --path. Use the positional form so pyproject.toml projects are
            # audited without the invalid --requirement flag.
            self._manifest_path = os.path.join(target, "pyproject.toml")
            cmd.append(target)
        res = subprocess.run(cmd, capture_output=True, timeout=300)
        return res.stdout, res.returncode

    def _find_requirement(self, target: str) -> str | None:
        for path in sorted(glob.glob(os.path.join(target, "requirements*.txt"))):
            return path
        return None

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                cves = [a.upper() for a in vuln.get("aliases", []) if a.upper().startswith("CVE-")]
                finding = {
                    "id": new_finding_id(self.prefix, n),
                    "title": f"{dep['name']} {dep['version']}: {vuln.get('id', 'vulnerability')}",
                    "severity": normalize_severity(vuln.get("severity") or "MEDIUM"),
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "dependency_vulnerability",
                    "source": f"tool:{self.name}",
                    "location": {"file": self._manifest_path or "requirements.txt", "line_start": 1},
                    "description": vuln.get("description", "No description provided."),
                    "impact": f"Vulnerable dependency {dep['name']}=={dep['version']} is used.",
                    "remediation": f"Upgrade to a fixed version: {', '.join(vuln.get('fix_versions', [])) or 'see advisory'}",
                    "references": [],
                    "tool_evidence": omit_none({
                        "rule_id": vuln.get("id"),
                        "package_name": dep["name"],
                        "vulnerable_versions": dep["version"],
                        "fixed_version": vuln.get("fix_versions", [None])[0],
                    }),
                    "_group": group,
                }
                if cves:
                    finding["citations"] = {"cve": cves}
                attach_tool_provenance(finding, self.name, reasoning=finding["tool_evidence"].get("rule_id"))
                out.append(finding)
                n += 1
        return out

"""OWASP dependency-check adapter for Java dependency CVEs."""
from __future__ import annotations
import json
import os
import subprocess
import tempfile
from .base import normalize_severity, new_finding_id, omit_none


class DependencyCheckAdapter:
    name = "dependency-check"
    prefix = "DC"

    def is_applicable(self, target: str) -> bool:
        markers = ["pom.xml", "build.gradle", "build.gradle.kts"]
        return any(os.path.exists(os.path.join(target, m)) for m in markers)

    def invoke(self, target: str) -> tuple[bytes, int]:
        out_dir = tempfile.mkdtemp(prefix="dc-")
        dc_home = os.environ.get("DEPENDENCY_CHECK_HOME", "/opt/dependency-check")
        cmd = [
            os.path.join(dc_home, "bin", "dependency-check.sh"),
            "--project", "panopticon",
            "--scan", target,
            "--format", "JSON",
            "--out", out_dir,
            "--noupdate",
        ]
        res = subprocess.run(cmd, capture_output=True, timeout=900)
        out_path = os.path.join(out_dir, "dependency-check-report.json")
        if os.path.exists(out_path):
            with open(out_path, "rb") as fh:
                return fh.read(), res.returncode
        return b"{}", res.returncode

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulnerabilities", []):
                cwe_list = [f"CWE-{c}" for c in vuln.get("cwes", []) if isinstance(c, int)]
                cve = vuln.get("name", "")
                finding = {
                    "id": new_finding_id(self.prefix, n),
                    "title": f"{dep.get('fileName', 'jar')}: {cve}",
                    "severity": normalize_severity(vuln.get("severity")),
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "dependency_vulnerability",
                    "source": f"tool:{self.name}",
                    "location": {"file": dep.get("fileName", "pom.xml"), "line_start": 1},
                    "description": vuln.get("description", "No description provided."),
                    "impact": f"Vulnerable Java dependency {dep.get('fileName', '')} is used.",
                    "remediation": "Upgrade to a fixed version per the advisory.",
                    "references": [],
                    "citations": omit_none({"cve": [cve] if cve.startswith("CVE-") else None, "cwe": cwe_list or None}),
                    "tool_evidence": omit_none({
                        "rule_id": cve,
                        "package_name": dep.get("fileName"),
                    }),
                    "_group": group,
                }
                if not finding["citations"]:
                    finding.pop("citations", None)
                out.append(finding)
                n += 1
        return out

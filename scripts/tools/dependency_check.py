"""OWASP dependency-check adapter for Java dependency CVEs."""
from __future__ import annotations
import json
import os
import shutil
import subprocess
import tempfile
from .base import attach_tool_provenance, normalize_severity, new_finding_id, omit_none


class DependencyCheckAdapter:
    name = "dependency-check"
    prefix = "DC"

    def is_applicable(self, target: str) -> bool:
        markers = ["pom.xml", "build.gradle", "build.gradle.kts"]
        return any(os.path.exists(os.path.join(target, m)) for m in markers)

    def invoke(self, target: str) -> tuple[bytes, int]:
        out_dir = tempfile.mkdtemp(prefix="dc-")
        try:
            dc_home = os.environ.get("DEPENDENCY_CHECK_HOME", "/opt/dependency-check")
            # Dependency-Check 10.x requires an NVD API key to download the
            # vulnerability database. Without a key we keep --noupdate; findings
            # then depend on a pre-seeded DB inside the image or on the host.
            has_nvd_key = bool(os.environ.get("NVD_API_KEY"))
            cmd = [
                os.path.join(dc_home, "bin", "dependency-check.sh"),
                "--project", "panopticon",
                "--scan", target,
                "--format", "JSON",
                "--out", out_dir,
            ]
            if not has_nvd_key:
                cmd.append("--noupdate")
            res = subprocess.run(cmd, capture_output=True, timeout=900)
            out_path = os.path.join(out_dir, "dependency-check-report.json")
            if os.path.exists(out_path):
                with open(out_path, "rb") as fh:
                    return fh.read(), res.returncode
            return b"{}", res.returncode
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)

    @staticmethod
    def _normalize_cwe(cwe: int | str) -> str | None:
        if isinstance(cwe, int):
            return f"CWE-{cwe}"
        if isinstance(cwe, str):
            cwe = cwe.strip()
            if cwe.startswith("CWE-"):
                return cwe
            if cwe.isdigit():
                return f"CWE-{cwe}"
        return None

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulnerabilities", []):
                cwe_list = [
                    normalized
                    for c in vuln.get("cwes", [])
                    if (normalized := self._normalize_cwe(c)) is not None
                ]
                cve = vuln.get("name", "")
                file_name = dep.get("fileName", "jar")
                impact_file = dep.get("fileName")
                impact = (
                    f"Vulnerable Java dependency {impact_file} is used."
                    if impact_file
                    else "A vulnerable Java dependency is used."
                )
                finding = {
                    "id": new_finding_id(self.prefix, n),
                    "title": f"{file_name}: {cve}",
                    "severity": normalize_severity(vuln.get("severity")),
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "dependency_vulnerability",
                    "source": f"tool:{self.name}",
                    "location": {"file": file_name, "line_start": 1},
                    "description": vuln.get("description", "No description provided."),
                    "impact": impact,
                    "remediation": "Upgrade to a fixed version per the advisory.",
                    "references": [],
                    "citations": omit_none({
                        "cve": [cve] if cve.startswith("CVE-") else None,
                        "cwe": cwe_list or None,
                    }),
                    "tool_evidence": omit_none({
                        "rule_id": cve,
                        "package_name": dep.get("fileName"),
                    }),
                    "_group": group,
                }
                if not finding["citations"]:
                    finding.pop("citations", None)
                attach_tool_provenance(finding, self.name, reasoning=finding["tool_evidence"].get("rule_id"))
                out.append(finding)
                n += 1
        return out

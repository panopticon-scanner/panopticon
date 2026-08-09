"""OWASP dependency-check adapter for Java dependency CVEs."""
from __future__ import annotations
import os
import shutil
import tempfile
from .base import make_finding, normalize_severity, omit_none, parse_json_bytes, run_tool


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
            cmd = [
                os.path.join(dc_home, "bin", "dependency-check.sh"),
                "--project", "panopticon",
                "--scan", target,
                "--format", "JSON",
                "--out", out_dir,
                "--noupdate",
                "--data", "/opt/odc-data",
            ]
            _stdout, rc = run_tool(cmd, timeout=900)
            out_path = os.path.join(out_dir, "dependency-check-report.json")
            if os.path.exists(out_path):
                with open(out_path, "rb") as fh:
                    return fh.read(), rc
            return b"{}", rc
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
        data = parse_json_bytes(raw)
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
                out.append(make_finding(
                    self, n, group,
                    title=f"{file_name}: {cve}",
                    severity=normalize_severity(vuln.get("severity")),
                    category="dependency_vulnerability",
                    location={"file": file_name, "line_start": 1},
                    description=vuln.get("description", "No description provided."),
                    impact=impact,
                    remediation="Upgrade to a fixed version per the advisory.",
                    citations={
                        "cve": [cve] if cve.startswith("CVE-") else [],
                        "cwe": cwe_list,
                    },
                    tool_evidence=omit_none({
                        "rule_id": cve,
                        "package_name": dep.get("fileName"),
                    }),
                ))
                n += 1
        return out

"""OSV scanner adapter for cross-ecosystem dependency advisories."""
from __future__ import annotations
import json
import os
import subprocess
from .base import attach_tool_provenance, normalize_severity, new_finding_id, omit_none


class OsvScannerAdapter:
    name = "osv-scanner"
    prefix = "OS"

    def is_applicable(self, target: str) -> bool:
        markers = [
            "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
            "requirements.txt", "pyproject.toml", "Pipfile.lock",
            "go.mod", "go.sum",
            "Cargo.lock", "Cargo.toml",
            "pom.xml", "build.gradle", "gradle.lockfile",
        ]
        return any(os.path.isfile(os.path.join(target, m)) for m in markers)

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = ["osv-scanner", "--format", "json", "--recursive", target]
        res = subprocess.run(cmd, capture_output=True, timeout=300)
        return res.stdout, res.returncode

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for result in data.get("results", []):
            pkg = result.get("package", {})
            for vuln in result.get("vulnerabilities", []):
                cves = [a.upper() for a in vuln.get("aliases", []) if a.upper().startswith("CVE-")]
                finding = {
                    "id": new_finding_id(self.prefix, n),
                    "title": f"{pkg.get('name')} {pkg.get('version')}: {vuln.get('id', 'vulnerability')}",
                    "severity": normalize_severity(vuln.get("severity")),
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "dependency_vulnerability",
                    "source": f"tool:{self.name}",
                    "location": {"file": pkg.get("ecosystem", "manifest"), "line_start": 1},
                    "description": vuln.get("summary", "No description provided."),
                    "impact": f"Vulnerable dependency {pkg.get('name')}=={pkg.get('version')} is used.",
                    "remediation": "Upgrade to a patched version or see the OSV advisory.",
                    "references": [],
                    "tool_evidence": omit_none({
                        "rule_id": vuln.get("id"),
                        "package_name": pkg.get("name"),
                        "vulnerable_versions": pkg.get("version"),
                        "ecosystem": pkg.get("ecosystem"),
                    }),
                    "_group": group,
                }
                if cves:
                    finding["citations"] = {"cve": cves}
                attach_tool_provenance(finding, self.name, reasoning=finding["tool_evidence"].get("rule_id"))
                out.append(finding)
                n += 1
        return out

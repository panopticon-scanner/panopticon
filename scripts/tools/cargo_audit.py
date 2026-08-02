"""cargo-audit adapter for Rust dependency CVEs."""
from __future__ import annotations
import json
import os
import subprocess
from .base import new_finding_id, omit_none


class CargoAuditAdapter:
    name = "cargo-audit"
    prefix = "CA"

    def is_applicable(self, target: str) -> bool:
        return os.path.exists(os.path.join(target, "Cargo.toml"))

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = ["cargo", "audit", "--format", "json"]
        res = subprocess.run(cmd, capture_output=True, timeout=300, cwd=target)
        return res.stdout, res.returncode

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for vuln in data.get("vulnerabilities", {}).get("list", []):
            advisory = vuln.get("advisory", {})
            package = vuln.get("package", {})
            versions = vuln.get("versions", {})
            cvss = advisory.get("cvss")
            severity = "HIGH"
            if cvss:
                score = cvss.get("score", 0)
                severity = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
            finding = {
                "id": new_finding_id(self.prefix, n),
                "title": f"{package.get('name', 'crate')} {package.get('version', '')}: {advisory.get('id', '')}",
                "severity": severity,
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "dependency_vulnerability",
                "source": f"tool:{self.name}",
                "location": {"file": "Cargo.toml", "line_start": 1},
                "description": advisory.get("title", "No description provided."),
                "impact": f"Vulnerable Rust dependency {package.get('name')}=={package.get('version')} is used.",
                "remediation": f"Upgrade to a fixed version: {', '.join(versions.get('patched', [])) or 'see advisory'}",
                "references": [advisory["url"]] if advisory.get("url") else [],
                "tool_evidence": omit_none({
                    "rule_id": advisory.get("id"),
                    "package_name": package.get("name"),
                    "vulnerable_versions": package.get("version"),
                    "advisory_url": advisory.get("url"),
                }),
                "_group": group,
            }
            out.append(finding)
            n += 1
        return out

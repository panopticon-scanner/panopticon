"""npm audit adapter for Node dependency CVEs."""
from __future__ import annotations
import json
import os
import subprocess
from .base import normalize_severity, new_finding_id


class NpmAuditAdapter:
    name = "npm-audit"
    prefix = "NA"

    def is_applicable(self, target: str) -> bool:
        return os.path.isfile(os.path.join(target, "package-lock.json")) or \
               os.path.isfile(os.path.join(target, "npm-shrinkwrap.json"))

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = ["npm", "audit", "--json", "--prefix", target]
        res = subprocess.run(cmd, capture_output=True, timeout=300)
        return res.stdout, res.returncode

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for adv in data.get("advisories", {}).values():
            cves = [c.upper() for c in adv.get("cves", []) if c.upper().startswith("CVE-")]
            finding = {
                "id": new_finding_id(self.prefix, n),
                "title": f"{adv.get('module_name')} {adv.get('vulnerable_versions', '')}: {adv.get('title', 'vulnerability')}",
                "severity": normalize_severity(adv.get("severity")),
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "dependency_vulnerability",
                "source": f"tool:{self.name}",
                "location": {"file": "package-lock.json", "line_start": 1},
                "description": adv.get("overview", "No description provided."),
                "impact": f"Vulnerable Node dependency {adv.get('module_name')} is used.",
                "remediation": f"Upgrade to a fixed version: {adv.get('patched_versions', 'see advisory')}",
                "references": [adv.get("url")] if adv.get("url") else [],
                "tool_evidence": {
                    "rule_id": str(adv.get("id")),
                    "package_name": adv.get("module_name"),
                    "vulnerable_versions": adv.get("vulnerable_versions"),
                    "fixed_version": adv.get("patched_versions"),
                },
                "_group": group,
            }
            if cves:
                finding["citations"] = {"cve": cves}
            out.append(finding)
            n += 1
        return out

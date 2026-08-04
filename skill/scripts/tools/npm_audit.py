"""npm audit adapter for Node dependency CVEs."""
from __future__ import annotations
import json
import os
from .base import attach_tool_provenance, normalize_severity, new_finding_id, omit_none, run_tool


class NpmAuditAdapter:
    name = "npm-audit"
    prefix = "NA"

    def is_applicable(self, target: str) -> bool:
        return os.path.isfile(os.path.join(target, "package-lock.json")) or \
               os.path.isfile(os.path.join(target, "npm-shrinkwrap.json"))

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = ["npm", "audit", "--json", "--prefix", target]
        return run_tool(cmd, timeout=300)

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1

        # Legacy npm audit output (npm < 7 / auditReportVersion 1).
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
                "tool_evidence": omit_none({
                    "rule_id": str(adv.get("id")) if adv.get("id") is not None else None,
                    "package_name": adv.get("module_name"),
                    "vulnerable_versions": adv.get("vulnerable_versions"),
                    "fixed_version": adv.get("patched_versions"),
                }),
                "_group": group,
            }
            if cves:
                finding["citations"] = {"cve": cves}
            attach_tool_provenance(finding, self.name, reasoning=finding["tool_evidence"].get("rule_id"))
            out.append(finding)
            n += 1

        # Current npm audit output (auditReportVersion 2+).
        for vuln in data.get("vulnerabilities", {}).values():
            via = self._primary_via(vuln)
            if via is None:
                continue
            cves = [c.upper() for c in via.get("cves", []) if c.upper().startswith("CVE-")]
            fix = vuln.get("fixAvailable")
            fixed_version = fix.get("version") if isinstance(fix, dict) else None
            finding = {
                "id": new_finding_id(self.prefix, n),
                "title": f"{vuln.get('name')} {vuln.get('range', '')}: {via.get('title', 'vulnerability')}",
                "severity": normalize_severity(via.get("severity") or vuln.get("severity")),
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "dependency_vulnerability",
                "source": f"tool:{self.name}",
                "location": {"file": "package-lock.json", "line_start": 1},
                "description": via.get("title", "No description provided."),
                "impact": f"Vulnerable Node dependency {vuln.get('name')} is used.",
                "remediation": f"Upgrade to a fixed version: {fixed_version or 'see advisory'}",
                "references": [via.get("url")] if via.get("url") else [],
                "tool_evidence": omit_none({
                    "rule_id": str(via.get("source")) if via.get("source") is not None else None,
                    "package_name": vuln.get("name"),
                    "vulnerable_versions": vuln.get("range"),
                    "fixed_version": fixed_version,
                }),
                "_group": group,
            }
            if cves:
                finding["citations"] = {"cve": cves}
            attach_tool_provenance(finding, self.name, reasoning=finding["tool_evidence"].get("rule_id"))
            out.append(finding)
            n += 1

        return out

    def _primary_via(self, vuln: dict) -> dict | None:
        """Return the primary advisory from an npm v2 vulnerability's via list.

        ``via`` may contain either advisory dicts or dependency-name strings.
        Strings are transitive chain markers with no CVE, so they are skipped.
        """
        via = vuln.get("via")
        if isinstance(via, dict):
            return via
        if isinstance(via, list):
            for entry in via:
                if isinstance(entry, dict):
                    return entry
        return None

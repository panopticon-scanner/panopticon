"""npm audit adapter for Node dependency CVEs."""
from __future__ import annotations
import os
from .base import cve_ids, make_finding, normalize_severity, omit_none, parse_json_bytes, run_tool


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
        data = parse_json_bytes(raw)
        out = []
        n = 1

        # Legacy npm audit output (npm < 7 / auditReportVersion 1).
        for adv in data.get("advisories", {}).values():
            out.append(make_finding(
                self, n, group,
                title=f"{adv.get('module_name')} {adv.get('vulnerable_versions', '')}: {adv.get('title', 'vulnerability')}",
                severity=normalize_severity(adv.get("severity")),
                category="dependency_vulnerability",
                location={"file": "package-lock.json", "line_start": 1},
                description=adv.get("overview", "No description provided."),
                impact=f"Vulnerable Node dependency {adv.get('module_name')} is used.",
                remediation=f"Upgrade to a fixed version: {adv.get('patched_versions', 'see advisory')}",
                references=[adv.get("url")] if adv.get("url") else [],
                citations={"cve": cve_ids(adv.get("cves"))},
                tool_evidence=omit_none({
                    "rule_id": str(adv.get("id")) if adv.get("id") is not None else None,
                    "package_name": adv.get("module_name"),
                    "vulnerable_versions": adv.get("vulnerable_versions"),
                    "fixed_version": adv.get("patched_versions"),
                }),
            ))
            n += 1

        # Current npm audit output (auditReportVersion 2+).
        for vuln in data.get("vulnerabilities", {}).values():
            via = self._primary_via(vuln)
            if via is None:
                continue
            fix = vuln.get("fixAvailable")
            fixed_version = fix.get("version") if isinstance(fix, dict) else None
            out.append(make_finding(
                self, n, group,
                title=f"{vuln.get('name')} {vuln.get('range', '')}: {via.get('title', 'vulnerability')}",
                severity=normalize_severity(via.get("severity") or vuln.get("severity")),
                category="dependency_vulnerability",
                location={"file": "package-lock.json", "line_start": 1},
                description=via.get("title", "No description provided."),
                impact=f"Vulnerable Node dependency {vuln.get('name')} is used.",
                remediation=f"Upgrade to a fixed version: {fixed_version or 'see advisory'}",
                references=[via.get("url")] if via.get("url") else [],
                citations={"cve": cve_ids(via.get("cves"))},
                tool_evidence=omit_none({
                    "rule_id": str(via.get("source")) if via.get("source") is not None else None,
                    "package_name": vuln.get("name"),
                    "vulnerable_versions": vuln.get("range"),
                    "fixed_version": fixed_version,
                }),
            ))
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

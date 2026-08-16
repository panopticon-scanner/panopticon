"""npm audit adapter for Node dependency CVEs."""
from __future__ import annotations
from .base import (as_list, cve_ids, has_any_file, make_finding, normalize_severity,
                   omit_none, parse_json_bytes, run_tool)


class NpmAuditAdapter:
    name = "npm-audit"
    prefix = "NA"

    def is_applicable(self, target: str) -> bool:
        return has_any_file(target, "package-lock.json", "npm-shrinkwrap.json")

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = ["npm", "audit", "--json", "--prefix", target]
        return run_tool(cmd, timeout=300)

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = parse_json_bytes(raw)
        out = []
        n = 1

        # Legacy npm audit output (npm < 7 / auditReportVersion 1).
        for adv in data.get("advisories", {}).values():
            out.append(self._finding_from(
                n, group,
                name=adv.get("module_name"),
                versions_title=adv.get("vulnerable_versions", ""),
                versions_evidence=adv.get("vulnerable_versions"),
                severity_raw=adv.get("severity"),
                title=adv.get("title", "vulnerability"),
                description=adv.get("overview", "No description provided."),
                remediation=f"Upgrade to a fixed version: {adv.get('patched_versions', 'see advisory')}",
                url=adv.get("url"),
                cves=adv.get("cves"),
                rule_id=str(adv.get("id")) if adv.get("id") is not None else None,
                fixed_version=adv.get("patched_versions"),
            ))
            n += 1

        # Current npm audit output (auditReportVersion 2+).
        for vuln in data.get("vulnerabilities", {}).values():
            via = self._primary_via(vuln)
            if via is None:
                continue
            fix = vuln.get("fixAvailable")
            fixed_version = fix.get("version") if isinstance(fix, dict) else None
            out.append(self._finding_from(
                n, group,
                name=vuln.get("name"),
                versions_title=vuln.get("range", ""),
                versions_evidence=vuln.get("range"),
                severity_raw=via.get("severity") or vuln.get("severity"),
                title=via.get("title", "vulnerability"),
                description=via.get("title", "No description provided."),
                remediation=f"Upgrade to a fixed version: {fixed_version or 'see advisory'}",
                url=via.get("url"),
                cves=via.get("cves"),
                rule_id=str(via.get("source")) if via.get("source") is not None else None,
                fixed_version=fixed_version,
            ))
            n += 1

        return out

    def _finding_from(self, n, group, *, name, versions_title, versions_evidence,
                       severity_raw, title, description, remediation, url, cves,
                       rule_id, fixed_version) -> dict:
        """Assemble one npm-audit finding shared by both the legacy (v1
        advisories) and current (v2 vulnerabilities) report loops.

        Each caller does its own report-version-specific field extraction and
        passes the resolved values in; this only owns the invariant
        make_finding envelope (title/impact template, location, references,
        citations, tool_evidence) so the two near-identical blocks aren't
        duplicated. versions_title/versions_evidence are kept distinct because
        the original code defaulted the title's version segment to "" but left
        tool_evidence's vulnerable_versions as None-when-absent (so omit_none
        drops it) -- collapsing them to one value would change output.
        """
        return make_finding(
            self, n, group,
            title=f"{name} {versions_title}: {title}",
            severity=normalize_severity(severity_raw),
            category="dependency_vulnerability",
            location={"file": "package-lock.json", "line_start": 1},
            description=description,
            impact=f"Vulnerable Node dependency {name} is used.",
            remediation=remediation,
            references=as_list(url),
            citations={"cve": cve_ids(cves)},
            tool_evidence=omit_none({
                "rule_id": rule_id,
                "package_name": name,
                "vulnerable_versions": versions_evidence,
                "fixed_version": fixed_version,
            }),
        )

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

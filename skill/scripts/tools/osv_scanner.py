"""OSV scanner adapter for cross-ecosystem dependency advisories."""
from __future__ import annotations
import json
import os
from .base import attach_tool_provenance, normalize_severity, new_finding_id, omit_none, run_tool
from .sarif_utils import _norm_uri


def _cvss_bucket(score: float) -> str:
    """Map a numeric CVSS score to the pipeline's severity scale."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


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
        return run_tool(cmd, timeout=300)

    def parse(self, raw: bytes, group: str) -> list[dict]:
        """Parse real osv-scanner --format json output.

        Real shape (verified against a live run, 2026-08-03):
        results[] -> {source: {path}, packages[] -> {package, vulnerabilities[],
        groups[] -> {ids[], max_severity}}}. Severity comes from the numeric
        CVSS in groups[].max_severity (vulnerabilities[].severity is a list of
        CVSS vector dicts, not a label). source.path carries the container
        mount prefix and is normalized like SARIF artifact URIs.
        """
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for result in data.get("results", []):
            src_path = _norm_uri((result.get("source") or {}).get("path") or "")
            for pkg_entry in result.get("packages", []) or []:
                if not isinstance(pkg_entry, dict):
                    continue
                pkg = pkg_entry.get("package", {}) or {}
                sev_by_id = {}
                for grp in pkg_entry.get("groups", []) or []:
                    try:
                        score = float(grp.get("max_severity") or "")
                    except (TypeError, ValueError):
                        continue
                    for vid in grp.get("ids", []) or []:
                        sev_by_id[vid] = score
                for vuln in pkg_entry.get("vulnerabilities", []) or []:
                    if not isinstance(vuln, dict):
                        continue
                    aliases = vuln.get("aliases") or []
                    cves = [a.upper() for a in aliases
                            if isinstance(a, str) and a.upper().startswith("CVE-")]
                    score = sev_by_id.get(vuln.get("id"))
                    if score is not None:
                        severity = _cvss_bucket(score)
                    else:
                        raw_sev = vuln.get("severity")
                        severity = normalize_severity(
                            raw_sev if isinstance(raw_sev, str) else None)
                    finding = {
                        "id": new_finding_id(self.prefix, n),
                        "title": f"{pkg.get('name')} {pkg.get('version')}: {vuln.get('id', 'vulnerability')}",
                        "severity": severity,
                        "confidence": "CERTAIN",
                        "panel": "security",
                        "category": "dependency_vulnerability",
                        "source": f"tool:{self.name}",
                        "location": {"file": src_path or pkg.get("ecosystem", "manifest"),
                                     "line_start": 1},
                        "description": vuln.get("summary")
                        or (vuln.get("details") or "No description provided.")[:500],
                        "impact": f"Vulnerable dependency {pkg.get('name')}=={pkg.get('version')} is used.",
                        "remediation": "Upgrade to a patched version or see the OSV advisory.",
                        "references": [],
                        "tool_evidence": omit_none({
                            "rule_id": vuln.get("id"),
                            "package_name": pkg.get("name"),
                            "vulnerable_versions": pkg.get("version"),
                            "ecosystem": pkg.get("ecosystem"),
                            "cvss_max_severity": score,
                        }),
                        "_group": group,
                    }
                    if cves:
                        finding["citations"] = {"cve": cves}
                    attach_tool_provenance(finding, self.name,
                                           reasoning=finding["tool_evidence"].get("rule_id"))
                    out.append(finding)
                    n += 1
        return out

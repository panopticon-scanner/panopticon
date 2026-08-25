"""OSV scanner adapter for cross-ecosystem dependency advisories."""
from __future__ import annotations
from .base import (cve_ids, cvss_bucket, has_any_file, make_finding,
                   normalize_severity, omit_none, parse_json_bytes, run_tool,
                   _cvss_v3_score)
from .sarif_utils import _norm_uri


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
        return has_any_file(target, *markers)

    def invoke(self, target: str) -> tuple[bytes, int]:
        # v1.8.2 spells it --experimental-offline; re-check when OSV_SCANNER_VERSION bumps
        cmd = ["osv-scanner", "--format", "json", "--experimental-offline", "--recursive", target]
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
        data = parse_json_bytes(raw)
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
                    score = sev_by_id.get(vuln.get("id"))
                    if score is not None:
                        severity = cvss_bucket(score)
                    else:
                        raw_sev = vuln.get("severity") or []
                        severity = None
                        if isinstance(raw_sev, list):
                            for entry in raw_sev:
                                if isinstance(entry, dict) and entry.get("type") == "CVSS_V3":
                                    entry_score = _cvss_v3_score(entry.get("score") or entry.get("score_vector"))
                                    if entry_score is not None:
                                        severity = cvss_bucket(entry_score)
                                        break
                        if severity is None:
                            severity = normalize_severity(None)
                    out.append(make_finding(
                        self, n, group,
                        title=f"{pkg.get('name')} {pkg.get('version')}: {vuln.get('id', 'vulnerability')}",
                        severity=severity,
                        category="dependency_vulnerability",
                        location={"file": src_path or pkg.get("ecosystem", "manifest"),
                                  "line_start": 1},
                        description=vuln.get("summary")
                        or (vuln.get("details") or "No description provided.")[:500],
                        impact=f"Vulnerable dependency {pkg.get('name')}=={pkg.get('version')} is used.",
                        remediation="Upgrade to a patched version or see the OSV advisory.",
                        citations={"cve": cve_ids(vuln.get("aliases"))},
                        tool_evidence=omit_none({
                            "rule_id": vuln.get("id"),
                            "package_name": pkg.get("name"),
                            "vulnerable_versions": pkg.get("version"),
                            "ecosystem": pkg.get("ecosystem"),
                            "cvss_max_severity": score,
                        }),
                    ))
                    n += 1
        return out

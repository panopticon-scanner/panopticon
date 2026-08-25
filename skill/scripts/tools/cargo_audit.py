"""cargo-audit adapter for Rust dependency CVEs."""
from __future__ import annotations
import os
from .base import (as_list, cve_ids, cvss_bucket, make_finding, normalize_severity,
                   omit_none, parse_json_bytes, run_tool, _cvss_v3_score)


class CargoAuditAdapter:
    name = "cargo-audit"
    prefix = "CA"

    def is_applicable(self, target: str) -> bool:
        # #run7 COD-C2A: `cargo audit --no-fetch` reads a RESOLVED Cargo.lock and
        # cannot generate one (parse() even hardcodes location=Cargo.lock). A
        # Cargo.toml-only library repo was marked applicable, then failed at
        # invoke -> "selected but unproduced" coverage loss. Gate on the lockfile
        # (mirrors bundler-audit/Gemfile.lock); osv-scanner still covers
        # Cargo.toml-only repos, so nothing is lost by narrowing here.
        return os.path.exists(os.path.join(target, "Cargo.lock"))

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = ["cargo", "audit", "--no-fetch", "--format", "json"]
        return run_tool(cmd, timeout=300, cwd=target)

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = parse_json_bytes(raw)
        out = []
        n = 1
        for vuln in data.get("vulnerabilities", {}).get("list", []):
            advisory = vuln.get("advisory", {})
            package = vuln.get("package", {})
            versions = vuln.get("versions", {})
            cvss = advisory.get("cvss")
            severity = normalize_severity(None)  # INFO when CVSS is absent
            if isinstance(cvss, dict):
                severity = cvss_bucket(cvss.get("score", 0))
            elif isinstance(cvss, str):
                score = _cvss_v3_score(cvss)
                if score is not None:
                    severity = cvss_bucket(score)
            severity = normalize_severity(severity)
            advisory_id = advisory.get("id", "")
            out.append(make_finding(
                self, n, group,
                title=f"{package.get('name', 'crate')} {package.get('version', '')}: {advisory_id}",
                severity=severity,
                category="dependency_vulnerability",
                location={"file": "Cargo.lock", "line_start": 1},
                description=advisory.get("title", "No description provided."),
                impact=f"Vulnerable Rust dependency {package.get('name')}=={package.get('version')} is used.",
                remediation=f"Upgrade to a fixed version: {', '.join(versions.get('patched', [])) or 'see advisory'}",
                references=as_list(advisory.get("url")),
                citations={
                    "rustsec": [advisory_id] if advisory_id.startswith("RUSTSEC-") else [],
                    "cve": cve_ids(advisory.get("aliases")),
                },
                tool_evidence=omit_none({
                    "rule_id": advisory_id,
                    "package_name": package.get("name"),
                    "vulnerable_versions": package.get("version"),
                    "advisory_url": advisory.get("url"),
                }),
            ))
            n += 1
        return out

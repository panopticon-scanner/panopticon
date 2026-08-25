"""bundler-audit adapter for Ruby dependency CVEs."""
from __future__ import annotations
import os
import re
import sys
from .base import cve_ids, make_finding, normalize_severity, omit_none, parse_json_bytes, run_tool

_BLOCK_RE = re.compile(
    r"Name:\s*(?P<name>[^\n]+)\n"
    r"Version:\s*(?P<version>[^\n]+)\n"
    r"CVE:\s*(?P<cve>[^\n]+)\n"
    r"(?:GHSA:\s*(?P<ghsa>[^\n]+)\n)?"
    r"Criticality:\s*(?P<criticality>[^\n]+)\n"
    r"URL:\s*(?P<url>[^\n]+)\n"
    r"Title:\s*(?P<title>[^\n]+)\n"
    r"Solution:\s*(?P<solution>[^\n]+)",
    re.VERBOSE,
)


class BundlerAuditAdapter:
    name = "bundler-audit"
    prefix = "BA"

    def is_applicable(self, target: str) -> bool:
        return os.path.exists(os.path.join(target, "Gemfile.lock"))

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = ["bundle-audit", "check", "--format", "json", "--no-update"]
        return run_tool(cmd, timeout=300, cwd=target)

    def parse(self, raw: bytes, group: str) -> list[dict]:
        try:
            data = parse_json_bytes(raw)
        except Exception:
            data = None

        if isinstance(data, dict) and "results" in data:
            return self._parse_json(data, group)

        return self._parse_text(raw.decode("utf-8", errors="replace"), group, raw)

    def _parse_json(self, data: dict, group: str) -> list[dict]:
        out = []
        n = 1
        for vuln in data.get("results", []):
            gem = vuln.get("gem") or {}
            advisory = vuln.get("advisory") or {}
            advisory_id = advisory.get("id", "")
            package_name = gem.get("name", "gem")
            package_version = gem.get("version", "")
            title = advisory.get("title", "No description provided.")
            url = advisory.get("url")
            patched = advisory.get("patched_versions", [])
            out.append(make_finding(
                self, n, group,
                title=f"{package_name} {package_version}: {title}",
                severity=normalize_severity(advisory.get("criticality")),
                category="dependency_vulnerability",
                location={"file": "Gemfile.lock", "line_start": 1},
                description=title,
                impact=f"Vulnerable dependency {package_name}=={package_version} is used.",
                remediation=f"Upgrade to a fixed version: {', '.join(patched) or 'see advisory'}",
                references=[url] if url else [],
                citations={"cve": cve_ids([advisory_id])},
                tool_evidence=omit_none({
                    "rule_id": advisory_id or None,
                    "package_name": package_name,
                    "vulnerable_versions": package_version or None,
                    "advisory_url": url,
                }),
            ))
            n += 1
        return out

    def _parse_text(self, text: str, group: str, raw: bytes) -> list[dict]:
        out = []
        n = 1
        for m in _BLOCK_RE.finditer(text):
            cve = m.group("cve").strip()
            out.append(make_finding(
                self, n, group,
                title=f"{m.group('name').strip()} {m.group('version').strip()}: {m.group('title').strip()}",
                severity=normalize_severity(m.group("criticality")),
                category="dependency_vulnerability",
                location={"file": "Gemfile.lock", "line_start": 1},
                description=m.group("title").strip(),
                impact=f"Vulnerable dependency {m.group('name').strip()}=={m.group('version').strip()} is used.",
                remediation=f"Upgrade: {m.group('solution').strip()}",
                references=[m.group("url").strip()],
                citations={"cve": [cve] if cve.upper().startswith("CVE-") else []},
                tool_evidence=omit_none({
                    "rule_id": cve,
                    "package_name": m.group("name").strip(),
                    "vulnerable_versions": m.group("version").strip(),
                    "advisory_url": m.group("url").strip(),
                }),
            ))
            n += 1

        if not out and raw.strip():
            print(
                f"bundler-audit: no advisories parsed from non-empty output ({len(raw)} bytes)",
                file=sys.stderr,
            )
        return out

"""bundler-audit adapter for Ruby dependency CVEs."""
from __future__ import annotations
import os
import re
from .base import attach_tool_provenance, normalize_severity, new_finding_id, omit_none, run_tool

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
        cmd = ["bundle-audit", "check"]
        return run_tool(cmd, timeout=300, cwd=target)

    def parse(self, raw: bytes, group: str) -> list[dict]:
        text = raw.decode("utf-8", errors="replace")
        out = []
        n = 1
        for m in _BLOCK_RE.finditer(text):
            cve = m.group("cve").strip()
            finding = {
                "id": new_finding_id(self.prefix, n),
                "title": f"{m.group('name').strip()} {m.group('version').strip()}: {m.group('title').strip()}",
                "severity": normalize_severity(m.group("criticality")),
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "dependency_vulnerability",
                "source": f"tool:{self.name}",
                "location": {"file": "Gemfile.lock", "line_start": 1},
                "description": m.group("title").strip(),
                "impact": f"Vulnerable dependency {m.group('name').strip()}=={m.group('version').strip()} is used.",
                "remediation": f"Upgrade: {m.group('solution').strip()}",
                "references": [m.group("url").strip()],
                "citations": {"cve": [cve]} if cve.upper().startswith("CVE-") else {},
                "tool_evidence": omit_none({
                    "rule_id": cve,
                    "package_name": m.group("name").strip(),
                    "vulnerable_versions": m.group("version").strip(),
                    "advisory_url": m.group("url").strip(),
                }),
                "_group": group,
            }
            if not finding["citations"]:
                finding.pop("citations", None)
            attach_tool_provenance(finding, self.name, reasoning=finding["tool_evidence"].get("rule_id"))
            out.append(finding)
            n += 1
        return out

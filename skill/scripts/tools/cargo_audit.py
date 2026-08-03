"""cargo-audit adapter for Rust dependency CVEs."""
from __future__ import annotations
import json
import os
import subprocess
from .base import attach_tool_provenance, new_finding_id, omit_none, normalize_severity


def _cvss_v3_score(cvss: str) -> float | None:
    """Approximate CVSS v3.1 base score from a vector string."""
    try:
        metrics = dict(p.split(":") for p in cvss.split("/") if ":" in p)
        av = metrics.get("AV", "")
        ac = metrics.get("AC", "")
        pr = metrics.get("PR", "")
        ui = metrics.get("UI", "")
        s = metrics.get("S", "")
        c = metrics.get("C", "")
        i = metrics.get("I", "")
        a = metrics.get("A", "")
        if not all([av, ac, pr, ui, s, c, i, a]):
            return None
        iss = 1 - ((1 - {"N": 0, "L": 0.22, "H": 0.56}.get(c, 0)) *
                   (1 - {"N": 0, "L": 0.22, "H": 0.56}.get(i, 0)) *
                   (1 - {"N": 0, "L": 0.22, "H": 0.56}.get(a, 0)))
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if s == "C" else 6.42 * iss
        av_score = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(av, 0.85)
        ac_score = {"L": 0.77, "H": 0.44}.get(ac, 0.77)
        pr_scores = {"N": 0.85, "L": {"U": 0.62, "C": 0.68}, "H": {"U": 0.27, "C": 0.5}}.get(pr, 0.85)
        pr_score = pr_scores.get(s, 0.85) if isinstance(pr_scores, dict) else pr_scores
        ui_score = {"N": 0.85, "R": 0.62}.get(ui, 0.85)
        exploitability = 8.22 * av_score * ac_score * pr_score * ui_score
        if impact <= 0:
            score = 0.0
        elif s == "C":
            score = min(1.08 * (impact + exploitability), 10.0)
        else:
            score = min(impact + exploitability, 10.0)
        return score
    except Exception:  # noqa: BLE001
        return None


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
            if isinstance(cvss, dict):
                score = cvss.get("score", 0)
                severity = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
            elif isinstance(cvss, str):
                score = _cvss_v3_score(cvss)
                if score is not None:
                    severity = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
            severity = normalize_severity(severity)
            advisory_id = advisory.get("id", "")
            aliases = [a.upper() for a in advisory.get("aliases", []) if a.upper().startswith("CVE-")]
            citations = {"rustsec": [advisory_id]} if advisory_id.startswith("RUSTSEC-") else {}
            if aliases:
                citations["cve"] = aliases
            finding = {
                "id": new_finding_id(self.prefix, n),
                "title": f"{package.get('name', 'crate')} {package.get('version', '')}: {advisory_id}",
                "severity": severity,
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "dependency_vulnerability",
                "source": f"tool:{self.name}",
                "location": {"file": "Cargo.lock", "line_start": 1},
                "description": advisory.get("title", "No description provided."),
                "impact": f"Vulnerable Rust dependency {package.get('name')}=={package.get('version')} is used.",
                "remediation": f"Upgrade to a fixed version: {', '.join(versions.get('patched', [])) or 'see advisory'}",
                "references": [advisory["url"]] if advisory.get("url") else [],
                "citations": citations or None,
                "tool_evidence": omit_none({
                    "rule_id": advisory_id,
                    "package_name": package.get("name"),
                    "vulnerable_versions": package.get("version"),
                    "advisory_url": advisory.get("url"),
                }),
                "_group": group,
            }
            if not finding["citations"]:
                finding.pop("citations", None)
            attach_tool_provenance(finding, self.name, reasoning=finding["tool_evidence"].get("rule_id"))
            out.append(finding)
            n += 1
        return out

"""cargo-audit adapter for Rust dependency CVEs."""
from __future__ import annotations
import math
import os
from .base import (as_list, cve_ids, cvss_bucket, make_finding, normalize_severity,
                   omit_none, parse_json_bytes, run_tool)


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
        # CVSS v3.1 spec: Roundup(x) = smallest 1-decimal >= x (#475). Without
        # it every boundary score under-reads (e.g. the textbook 9.8 vector
        # computed 9.76 -> reported 9.7-ish instead of 9.8), skewing severity
        # bucketing at HIGH/CRITICAL thresholds. Epsilon per the spec's
        # reference implementation to dodge float artifacts.
        return math.ceil(score * 10 - 1e-9) / 10 if score else 0.0
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


class CargoAuditAdapter:
    name = "cargo-audit"
    prefix = "CA"

    def is_applicable(self, target: str) -> bool:
        return os.path.exists(os.path.join(target, "Cargo.toml"))

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
            severity = "HIGH"
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

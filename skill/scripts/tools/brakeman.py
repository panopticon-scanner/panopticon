"""Brakeman adapter for Ruby on Rails security findings."""
from __future__ import annotations
import os
import sys
from .base import as_list, make_finding, omit_none, parse_json_bytes, run_tool


_CONFIDENCE_MAP = {
    "high": "CERTAIN",
    "medium": "LIKELY",
    "low": "POSSIBLE",
}


def _normalize_confidence(value: str | None) -> str:
    if not isinstance(value, str):
        return "POSSIBLE"
    return _CONFIDENCE_MAP.get(value.lower().strip(), "POSSIBLE")


_BRAKEMAN_CWE = {
    "SQL Injection": "CWE-89",
    "Cross-Site Scripting": "CWE-79",
    "Cross-Site Request Forgery": "CWE-352",
    "Mass Assignment": "CWE-915",
    "Redirect": "CWE-601",
    "Dynamic Render Path": "CWE-22",
    "File Access": "CWE-22",
    "Session Setting": "CWE-614",
    "Basic Auth": "CWE-522",
    "Dangerous Eval": "CWE-94",
    "Command Injection": "CWE-78",
    "Unsafe Reflection": "CWE-470",
}


_BRAKEMAN_SEVERITY = {
    "Remote Code Execution": "CRITICAL",
    "Dangerous Eval": "HIGH",
    "Command Injection": "HIGH",
    "SQL Injection": "HIGH",
    "Cross-Site Scripting": "MEDIUM",
    "Cross-Site Request Forgery": "MEDIUM",
    "Mass Assignment": "MEDIUM",
    "File Access": "MEDIUM",
    "Dynamic Render Path": "MEDIUM",
    "Redirect": "LOW",
    "Session Setting": "LOW",
    "Basic Auth": "LOW",
    "Unsafe Reflection": "MEDIUM",
    # #run7 review: additional warning types. These were a guarded `.update()`
    # whose Command Injection/Unsafe Reflection/Mass Assignment entries were
    # DEAD -- they re-declared keys above with conflicting values (CRITICAL/HIGH
    # vs the effective HIGH/MEDIUM), so the map read one severity while resolving
    # to another. Merged the genuinely-new types in directly; behavior unchanged.
    # (Escalating Command Injection/Unsafe Reflection is a separate calibration
    # decision, deliberately not made here.)
    "SSL Verification Bypass": "MEDIUM",
    "LDAP Injection": "HIGH",
    "Weak Hash": "MEDIUM",
    "Path Traversal": "HIGH",
    "Insecure Cryptography Algorithm": "HIGH",
    "Regex Denial of Service": "MEDIUM",
    "Timing Attack": "LOW",
}


class BrakemanAdapter:
    name = "brakeman"
    prefix = "BK"

    def is_applicable(self, target: str) -> bool:
        markers = ["Gemfile", "config/routes.rb"]
        if any(os.path.exists(os.path.join(target, m)) for m in markers):
            return True
        app_dir = os.path.join(target, "app")
        if os.path.isdir(app_dir):
            return True
        if not os.path.isdir(target):
            return False
        return any(f.endswith(".gemspec") for f in os.listdir(target) if os.path.isfile(os.path.join(target, f)))

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = ["brakeman", "--format", "json", "--quiet", "--run-all-checks", target]
        stdout, rc = run_tool(cmd, timeout=300, ok_codes=(0, 1, 2, 3))
        # Brakeman exits 2 when warnings are found and 3 when warnings plus minor
        # parsing errors occur. Treat both as successful scans so the output is
        # preserved for ingestion.
        if rc in (2, 3):
            rc = 0
        return stdout, rc

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = parse_json_bytes(raw)
        out = []
        n = 1
        for w in data.get("warnings", []):
            wtype = w.get("warning_type", "")
            cwe = _BRAKEMAN_CWE.get(wtype)
            if wtype not in _BRAKEMAN_SEVERITY:
                print(f"brakeman: unmapped warning_type {wtype!r}; using MEDIUM", file=sys.stderr)
            sev = _BRAKEMAN_SEVERITY.get(wtype, "MEDIUM")
            out.append(make_finding(
                self, n, group,
                title=f"{wtype}: {w.get('message', '')}",
                severity=sev,
                confidence=_normalize_confidence(w.get("confidence", "medium")),
                category="rails_security",
                location={
                    "file": w.get("file", ""),
                    "line_start": w.get("line") or 1,
                },
                description=w.get("message", "No description provided."),
                impact=f"Rails security issue of type {wtype}.",
                remediation="Review the linked Brakeman documentation and refactor the affected code.",
                references=as_list(w.get("link")),
                citations={"cwe": as_list(cwe)},
                tool_evidence=omit_none({"rule_id": wtype, "advisory_url": w.get("link")}),
            ))
            n += 1
        return out

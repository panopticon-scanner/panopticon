"""Brakeman adapter for Ruby on Rails security findings."""
from __future__ import annotations
import json
import os
import subprocess
from .base import normalize_severity, new_finding_id, omit_none


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
        res = subprocess.run(cmd, capture_output=True, timeout=300)
        rc = res.returncode
        # Brakeman exits 2 when warnings are found and 3 when warnings plus minor
        # parsing errors occur. Treat both as successful scans so the output is
        # preserved for ingestion.
        if rc in (2, 3):
            rc = 0
        return res.stdout, rc

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for w in data.get("warnings", []):
            wtype = w.get("warning_type", "")
            cwe = _BRAKEMAN_CWE.get(wtype)
            citations = {"cwe": [cwe]} if cwe else {}
            finding = {
                "id": new_finding_id(self.prefix, n),
                "title": f"{wtype}: {w.get('message', '')}",
                "severity": normalize_severity(w.get("confidence", "medium")),
                "confidence": _normalize_confidence(w.get("confidence", "medium")),
                "panel": "security",
                "category": "rails_security",
                "source": f"tool:{self.name}",
                "location": {
                    "file": w.get("file", ""),
                    "line_start": w.get("line") or 1,
                },
                "description": w.get("message", "No description provided."),
                "impact": f"Rails security issue of type {wtype}.",
                "remediation": "Review the linked Brakeman documentation and refactor the affected code.",
                "references": [w["link"]] if w.get("link") else [],
                "citations": citations or None,
                "tool_evidence": omit_none({"rule_id": wtype, "advisory_url": w.get("link")}),
                "_group": group,
            }
            if not finding["citations"]:
                finding.pop("citations", None)
            out.append(finding)
            n += 1
        return out

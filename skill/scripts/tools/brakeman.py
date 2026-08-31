"""Brakeman adapter for Ruby on Rails security findings."""
from __future__ import annotations
import os
import re
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
    # Every remaining warning_type _BRAKEMAN_SEVERITY knows about, plus the
    # types railsgoat actually produces. The fixture asserts a CWE on EVERY
    # finding, and it was failing: railsgoat's top two types (Weak Hash x5,
    # Remote Code Execution x4) had a severity but no CWE, so those findings
    # reached synthesis uncitable -- and citation quality feeds both the report
    # grade and the OCRDb crosswalk.
    "Weak Hash": "CWE-328",
    "Remote Code Execution": "CWE-94",
    "Unscoped Find": "CWE-639",
    "Dangerous Send": "CWE-470",
    "Missing Encryption": "CWE-311",
    "Format Validation": "CWE-20",
    "SSL Verification Bypass": "CWE-295",
    "LDAP Injection": "CWE-90",
    "Path Traversal": "CWE-22",
    "Insecure Cryptography Algorithm": "CWE-327",
    "Regex Denial of Service": "CWE-1333",
    "Timing Attack": "CWE-208",
    # Found by the first real Ruby target (solidus): 8 of its 38 brakeman
    # findings, 21%, were landing uncitable on a default MEDIUM.
    "Denial of Service": "CWE-400",
    "Reverse Tabnabbing": "CWE-1022",
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
    # Types railsgoat emits that had no severity entry either, so parse() was
    # warning "unmapped warning_type" and silently defaulting them to MEDIUM.
    "Unscoped Find": "MEDIUM",
    "Dangerous Send": "MEDIUM",
    "Missing Encryption": "MEDIUM",
    "Format Validation": "LOW",
    "Denial of Service": "MEDIUM",
    "Reverse Tabnabbing": "LOW",
}


class BrakemanAdapter:
    name = "brakeman"
    prefix = "BK"

    def is_applicable(self, target: str) -> bool:
        """True only for an actual RAILS app -- brakeman scans nothing else.

        #calibration-1 (fzf): this used to return True for a bare `Gemfile`, an
        `app/` directory, or any `*.gemspec`. fzf is a Go program that keeps a
        Gemfile for its Ruby test harness, so brakeman was SELECTED, refused to
        run ("Please supply the path to a Rails application", exit 4), produced
        no output, and therefore landed in `tool_manifest.missing` -- which
        gates. A tool that cannot run on the target must not be selected for it:
        the resulting `tools_absent` reads as lost coverage when nothing was
        ever lost.

        Rails markers are the config/ files Rails itself generates, or an
        `app/` tree with the MVC subdirectories brakeman expects, or a Gemfile
        that actually depends on rails. A plain Ruby gem or a Ruby test suite
        is deliberately NOT a brakeman target.
        """
        if not os.path.isdir(target):
            return False
        for marker in ("config/routes.rb", "config/application.rb",
                       "config/environment.rb"):
            if os.path.isfile(os.path.join(target, marker)):
                return True
        app = os.path.join(target, "app")
        if any(os.path.isdir(os.path.join(app, sub))
               for sub in ("controllers", "models", "views")):
            return True
        # A Gemfile only counts when it actually pulls in rails.
        for gemfile in ("Gemfile", "gems.rb"):
            path = os.path.join(target, gemfile)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    body = fh.read(200_000)
            except OSError:
                continue
            for line in body.splitlines():
                line = line.strip()
                if line.startswith("#"):
                    continue
                if re.search(r"""\bgem\s+['"]rails['"]""", line):
                    return True
        return False

    _RAILS_ROOT_MARKERS = ("config/routes.rb", "config/application.rb",
                           "config/environment.rb")

    def _is_canonical_rails_root(self, target: str) -> bool:
        return any(os.path.isfile(os.path.join(target, m))
                   for m in self._RAILS_ROOT_MARKERS)

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = ["brakeman", "--format", "json", "--quiet", "--run-all-checks", target]
        # A Rails ENGINE (or a monorepo of them) has app/controllers and a
        # rails Gemfile but no config/routes.rb, so brakeman refuses it --
        # "Please supply the path to a Rails application" -- writes nothing, and
        # lands in tool_manifest.missing, which GATES. That is the fzf failure
        # (#1452) recurring on a repo shape is_applicable is right to accept.
        #
        # `--force` is exactly the escape hatch brakeman names in that message,
        # and the coverage is real rather than nominal: on solidus it turns 0
        # findings into 38, across 160 controllers and 289 models. Only added
        # when the canonical markers are absent, so a normal Rails app keeps its
        # default, stricter behaviour.
        if not self._is_canonical_rails_root(target):
            cmd.insert(1, "--force")
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

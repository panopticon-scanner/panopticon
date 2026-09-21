"""cargo-audit adapter for Rust dependency CVEs."""
from __future__ import annotations
import os
import shutil
import tempfile
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
        # ---------------------------------------------------------------
        # #1742 (SEC-E3A) -- same class #1646 closed for pip-audit.
        #
        # `cargo audit` runs through `cargo`, which is a DISPATCHER: `audit`
        # is not a cargo built-in, it is an external subcommand, so before
        # cargo hands off to the `cargo-audit` binary it reads
        # `.cargo/config.toml` from the CURRENT WORKING DIRECTORY upward and
        # honours any `[alias]` entry for `audit` -- cargo only refuses an
        # alias that shadows a BUILT-IN command (cargo issue #10049). A
        # target that commits
        #   [alias] audit = ["run", "--manifest-path", "x/Cargo.toml", "--"]
        # plus a writable `[build] target-dir` makes `cargo audit` (with
        # cwd=target) COMPILE AND RUN the target's own crate -- build.rs
        # included -- inside the scanner container. The same cwd also lets
        # cargo-audit read the target's `.cargo/audit.toml`
        # (`[advisories] ignore`, `[database] path`) and silently suppress
        # advisories.
        #
        # The fix: invoke the external subcommand BINARY directly --
        # `cargo-audit`, never `cargo audit` -- so cargo's config/alias
        # resolution is never consulted at all (the image installs it via
        # `cargo install cargo-audit`, on PATH at /usr/local/cargo/bin).
        # `cargo-audit` still expects to see its own subcommand name first
        # (`audit`), exactly as cargo would have passed it. Run it from an
        # EMPTY scratch directory -- never the target mount -- so no
        # `.cargo/*.toml` anywhere in the target tree is reachable, and name
        # the lockfile with an ABSOLUTE `--file` path so nothing here
        # depends on the working directory either.
        # ---------------------------------------------------------------
        lockfile = os.path.abspath(os.path.join(target, "Cargo.lock"))
        cmd = ["cargo-audit", "audit", "--no-fetch", "--format", "json",
               "--file", lockfile]
        scratch = tempfile.mkdtemp(prefix="cargo-audit-cwd-")
        try:
            return run_tool(cmd, timeout=300, cwd=scratch)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = parse_json_bytes(raw)
        out = []
        n = 1
        for vuln in data.get("vulnerabilities", {}).get("list", []):
            advisory = vuln.get("advisory", {})
            package = vuln.get("package", {})
            versions = vuln.get("versions", {})
            cvss = advisory.get("cvss")
            # #run7 review: floor an unscored (no-CVSS) advisory at LOW, not INFO.
            # A RustSec advisory is a real vuln even without a CVSS vector; LOW
            # keeps it a visible finding the reviewing agent can consciously
            # downgrade, rather than INFO (which reads as dismissed noise). Both
            # are gate-weight 0, so this changes honesty/visibility, not gating.
            # (Per-advisory severity overrides are a larger, separate effort.)
            severity = "LOW"
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

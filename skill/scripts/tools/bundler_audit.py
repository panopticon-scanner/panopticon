"""bundler-audit adapter for Ruby dependency CVEs."""
from __future__ import annotations
import os
import re
import sys
from .base import (cve_ids, make_finding, normalize_severity, omit_none,
                   parse_json_bytes, run_tool, scratch_cwd)

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
        # ---------------------------------------------------------------
        # #1742 (SEC-E3A neighbour) -- lesser road than cargo-audit's:
        # `bundle-audit` is a real binary, not a dispatcher with an alias
        # table, so `cwd=target` cannot hand the target code execution. But
        # bundle-audit's `check` command reads a config file, defaulting to
        # `.bundler-audit.yml` resolved against the directory it scans --
        # which used to be `cwd` (the target itself, implicitly, via
        # `Dir.pwd`). A target-committed `.bundler-audit.yml` with an
        # `[ignore]` list silently drops advisories from the report the same
        # way a target's `.cargo/audit.toml` does for cargo-audit.
        #
        # The fix: name the target EXPLICITLY as bundle-audit's positional
        # `dir` argument (absolute, so it does not depend on cwd either),
        # and pin `--config` to a generated, EMPTY config file in a scratch
        # directory the target never controls -- mirroring cargo-audit /
        # pip-audit's scratch-cwd pattern. bundle-audit resolves the
        # Gemfile.lock it audits against the positional `dir`
        # (Scanner#initialize joins `gemfile_lock` onto `root`), so the real
        # lockfile is still read from the target; only the ignore-list
        # config is redirected. Verified against bundler-audit 0.9.3's own
        # source (cli.rb's `check(dir=Dir.pwd)` / scanner.rb's
        # `Scanner#initialize`): `--config`/`-c` exists (default
        # '.bundler-audit.yml'), and an ABSOLUTE config path is used as-is
        # (`File.absolute_path` is a no-op on an already-absolute path), so
        # it is never rejoined onto the target.
        # ---------------------------------------------------------------
        abs_target = os.path.abspath(target)
        with scratch_cwd("bundler-audit-cwd-") as scratch:
            config_path = os.path.join(scratch, "empty-bundler-audit.yml")
            # An empty MAPPING, not an empty file: bundler-audit's config
            # loader requires the parsed YAML root to be a Hash, and rejects
            # a genuinely empty document.
            with open(config_path, "w", encoding="utf-8") as fh:
                fh.write("{}\n")
            json_cmd = ["bundle-audit", "check", abs_target, "--config", config_path,
                        "--format", "json", "--no-update"]
            raw, stderr, rc = run_tool(json_cmd, timeout=300, cwd=scratch,
                                       capture_stderr=True)
            # bundler-audit added --format json in 0.8.0. Older gems reject the
            # switch (Thor prints "Unknown switches '--format'" and exits non-zero).
            # Fall back to the legacy text output and let parse() shape-guard it.
            #
            # #1742 fix round 1 finding 3: the fallback carries NO --config.
            # --config arrived in 0.9.0, the SAME release that added
            # .bundler-audit.yml support -- a gem old enough to reject
            # --format json predates both. Passing --config to a gem that
            # does not recognise it would turn a working fallback into a
            # second "Unknown switches" failure, with no further fallback
            # left. The scratch cwd and the explicit positional target stay
            # (bundle-audit's `dir` argument and its cwd are orthogonal to
            # --config), so the fallback still never reads the target's cwd.
            if rc not in (0, 1) or b"Unknown switches" in stderr:
                return run_tool(["bundle-audit", "check", abs_target, "--no-update"],
                                timeout=300, cwd=scratch)
            return raw, rc

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

"""OWASP dependency-check adapter for Java dependency CVEs."""
from __future__ import annotations
import os
import shutil
import tempfile
from .base import (has_any_file, make_finding, normalize_severity, omit_none,
                   parse_json_bytes, read_capped_report, run_tool)


class DependencyCheckAdapter:
    name = "dependency-check"
    prefix = "DC"

    def is_applicable(self, target: str) -> bool:
        """A JVM build file AND resolved artifacts to actually analyse.

        #1474, the FOURTH instance of one class after #1452 (osv-scanner had no
        RubyGems DB), #1457 (gosec had no Go toolchain) and #1469 (roslyn had no
        restored deps): a scanner selected on a marker that proves the project's
        LANGUAGE rather than the presence of anything it can read, which then
        exits 0 with no findings and CERTIFIES the run.

        A build file proves this is a JVM project. It does not prove there is
        anything to scan -- dependency-check analyses ARTIFACTS (jars on disk),
        not build manifests, and a bare clone has none because dependencies were
        never resolved. On antennapod this was selected, ran 97 seconds, scanned
        exactly one jar (`gradle-wrapper.jar`) and returned zero findings, which
        landed in `tool_manifest.produced`, satisfied `missing: []`, and
        certified the run.

        Declining is the correct outcome: a disclosed `requested_unavailable`
        is non-gating (#1031) and honest, where a silent clean scan is neither.
        """
        markers = ["pom.xml", "build.gradle", "build.gradle.kts"]
        if not has_any_file(target, *markers):
            return False
        return self._has_scannable_artifacts(target)

    @staticmethod
    def _has_scannable_artifacts(target: str) -> bool:
        """True when a jar/war/ear exists that is NOT just the build wrapper.

        `gradle-wrapper.jar` is committed to source control by convention, so it
        is present in every bare Gradle clone and is the one artifact that
        proves nothing. Counting it is exactly the bug: it made a bare tree look
        scannable. Maven's equivalent wrapper jar is excluded for the same
        reason.

        Deliberately a whole-tree walk rather than a check for `target/` or
        `build/`: dependency-check is pointed at the repo root and will find
        artifacts wherever they were resolved to, including a non-standard
        output directory or a vendored lib/ tree.
        """
        wrappers = {"gradle-wrapper.jar", "maven-wrapper.jar"}
        skip = {".git", ".panopticon", ".worktrees", "node_modules"}
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in skip]
            for name in files:
                if name in wrappers:
                    continue
                if name.endswith((".jar", ".war", ".ear")):
                    return True
        return False

    def invoke(self, target: str) -> tuple[bytes, int]:
        out_dir = tempfile.mkdtemp(prefix="dc-")
        try:
            dc_home = os.environ.get("DEPENDENCY_CHECK_HOME", "/opt/dependency-check")
            cmd = [
                os.path.join(dc_home, "bin", "dependency-check.sh"),
                "--project", "panopticon",
                "--scan", target,
                "--format", "JSON",
                "--out", out_dir,
                "--noupdate",
                "--data", "/opt/odc-data",
                # Scans run in a no-egress container, but these three analyzers
                # call out: OSS Index to Sonatype, Node Audit to the npm
                # registry, RetireJS to its CDN-hosted advisory feed. Each
                # failure is logged as [ERROR], and dependency-check exits 14
                # ("one or more fatal errors occurred") no matter how well the
                # offline NVD scan itself went -- which the adapter's ok_codes
                # then reject, discarding a complete report. Measured on
                # WebGoat: rc 14 with them on, rc 0 and 111 CVEs across 42
                # dependencies with them off.
                "--disableOssIndex",
                "--disableNodeAudit",
                "--disableRetireJS",
                # #calibration-6: the Central Analyzer queries Maven Central for
                # POM metadata. With `--network none` -- how every scan runs --
                # it does not fail fast, it HANGS, and the adapter's own 900s
                # timeout kills the whole invocation: no report at all, from a
                # scan that would otherwise have completed. Measured on
                # WebGoat's jars: without this flag exit 124 (timeout) and 9
                # error lines; with it, exit 0 and none.
                #
                # The three flags above were added in #1461 for the same class
                # of problem (they logged [ERROR] and forced exit 14). Central
                # is worse because it costs the entire run rather than the exit
                # code. Offline dependency data comes from the baked NVD set
                # under --data, so nothing is lost by declining to ask Central.
                "--disableCentral",
            ]
            _stdout, rc = run_tool(cmd, timeout=900)
            out_path = os.path.join(out_dir, "dependency-check-report.json")
            if os.path.exists(out_path):
                # #run8 OPS-D1A: the tool writes the report to disk, so this read
                # bypasses run_tool's stdout cap; bound it and fail closed on an
                # oversize (attacker-influenced) report rather than slurp it whole.
                raw = read_capped_report(out_path)
                if raw is not None:
                    return raw, rc
            return b"", (rc if rc != 0 else 1)
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)

    @staticmethod
    def _normalize_cwe(cwe: int | str) -> str | None:
        if isinstance(cwe, int):
            return f"CWE-{cwe}"
        if isinstance(cwe, str):
            cwe = cwe.strip()
            if cwe.startswith("CWE-"):
                return cwe
            if cwe.isdigit():
                return f"CWE-{cwe}"
        return None

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = parse_json_bytes(raw)
        out = []
        n = 1
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulnerabilities", []):
                cwe_list = [
                    normalized
                    for c in vuln.get("cwes", [])
                    if (normalized := self._normalize_cwe(c)) is not None
                ]
                cve = vuln.get("name", "")
                file_name = dep.get("fileName", "jar")
                impact_file = dep.get("fileName")
                impact = (
                    f"Vulnerable Java dependency {impact_file} is used."
                    if impact_file
                    else "A vulnerable Java dependency is used."
                )
                out.append(make_finding(
                    self, n, group,
                    title=f"{file_name}: {cve}",
                    severity=normalize_severity(vuln.get("severity")),
                    category="dependency_vulnerability",
                    location={"file": file_name, "line_start": 1},
                    description=vuln.get("description", "No description provided."),
                    impact=impact,
                    remediation="Upgrade to a fixed version per the advisory.",
                    citations={
                        "cve": [cve] if cve.startswith("CVE-") else [],
                        "cwe": cwe_list,
                    },
                    tool_evidence=omit_none({
                        "rule_id": cve,
                        "package_name": dep.get("fileName"),
                    }),
                ))
                n += 1
        return out

"""OWASP dependency-check adapter for Java dependency CVEs."""
from __future__ import annotations
import contextvars
import os
import shutil
import sys
import tempfile
from .base import (INERT_CUT, OutputCapExceeded, has_any_file, inert_text,
                   make_finding, normalize_severity, omit_none,
                   parse_json_bytes, read_capped_report, run_tool, scratch_cwd,
                   target_root_cv)


# #1576 (run-13 OPS-3272189615): rc returned when the scanner was killed for
# overrunning its write-time report cap. Deliberately outside run_tool's
# ok_codes (0, 1), so the coverage manifest records the tool as missing
# (-> INCONCLUSIVE) instead of reading the empty output as a clean scan.
_OUTPUT_CAP_RC = 2

# The JVM build manifests, in resolution order. ONE tuple, used by
# `is_applicable` to select the scanner and by the resolver below to locate its
# findings, so the file that admitted a scan cannot disagree with the file that
# scan is reported against.
BUILD_MANIFESTS = ("pom.xml", "build.gradle", "build.gradle.kts")

# The manifest THIS invocation audited, TARGET-RELATIVE (pip_audit's shape,
# ARC-2852754506).
#
# #2225 (ARC-1020240040), owner ruling 2026-09-28 -- MANIFEST PROXY. This
# scanner analyses ARTIFACTS, so what it reports against is a jar under the
# build output: `location.file` was `angus-activation-2.0.1.jar`, a name that
# exists nowhere in the reviewed repository, and the absolute `filePath` beside
# it names the scanner host's layout. Neither can be placed, and placing a
# finding is what that field is for -- the delta/`--pr` gate matches it against
# `diff-hunks.json`, the tool-verify advisor's read grant resolves it, grading
# attributes findings to groups by it, every exclude glob matches it. The build
# manifest that declared the dependency is the repo file that stands in for the
# jar, and the shape every sibling dependency adapter already emits.
#
# One window stays open, and it is `tools/pip_audit.py`'s identical ContextVar's
# too: a `parse` in the SAME process after an `invoke` reads THAT invocation's
# manifest, so a caller that invoked target A and then parsed bytes from target B
# would locate B's findings at A's manifest. No caller does that today
# (`capture_goldens` invokes and parses one target at a time, and the
# container/ingest split never shares a process), and closing it belongs to both
# adapters at once rather than to one of them.
_manifest_path_cv: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "dependency_check_manifest_path", default=None)

# The last resort, for a caller that hands over bytes and NO tree (#1649, and
# the goldens, which are captured bytes). Every real route names one: the
# in-process one through `invoke`, ingest through `target_root_cv`.
DEFAULT_MANIFEST = "pom.xml"


def _first_manifest(root: str) -> str | None:
    """The first of BUILD_MANIFESTS that is a file directly under `root`."""
    for name in BUILD_MANIFESTS:
        if os.path.isfile(os.path.join(root, name)):
            return name
    return None


# How many `includedBy` references travel with one finding, and how a cut list
# says so. The strings are bounded one at a time by `inert_text`, but their
# COUNT is the target's to choose, and every reference is carried in the
# finding's envelope into `report.json` -- whose size the split writer measures
# in BYTES -- so the list is bounded too. (Not for the terminal's sake: nothing
# in `synth/render` reads `tool_evidence`.) The marker ends in `INERT_CUT`, the
# same mark a cut string wears, so a shortened list cannot read as a whole one.
INCLUDED_BY_MAX = 16


def _included_by(dep: dict) -> list[str] | None:
    """The `reference` of each `includedBy` entry, inert and bounded, or None.

    What pulled the vulnerable jar in: Maven coordinates
    (`org.owasp.webgoat:webgoat-container:2023.4`) or pURLs. The guarantee here
    is STRUCTURAL, not a claim about what this scanner will always put in the
    field: these values are surfaced as evidence ONLY and are never used as a
    location, whatever the tool emits in them -- `location.file` comes from
    `_located_at` and from nothing else.

    Each reference is neutralized on the way in (`inert_text`, the one
    neutralizer for target-authored text, #1829 SEC-4277410777): `make_finding`
    inerts `rule_id`, `location.file` and the prose, and a per-adapter evidence
    key it has never heard of has to do its own. The filter tests the INERTED
    value, so a whitespace-only reference leaves nothing rather than an empty
    string. A non-string reference is dropped rather than coerced: `inert_text`
    stringifies, and `str(None)` is the forged `"None"`
    `test_a_result_without_a_rule_id_keeps_a_null_rule_id` refuses for a rule id.
    None rather than `[]` so `omit_none` drops the key -- an empty list would
    read as "nothing pulled this in" rather than "the tool did not say".
    """
    entries = dep.get("includedBy")
    if not isinstance(entries, list):
        return None
    refs = [t for e in entries
            if isinstance(e, dict) and isinstance(e.get("reference"), str)
            and (t := inert_text(e["reference"]))]
    if not refs:
        return None
    if len(refs) <= INCLUDED_BY_MAX:
        return refs
    cut = len(refs) - INCLUDED_BY_MAX
    return refs[:INCLUDED_BY_MAX] + ["%d more%s" % (cut, INERT_CUT)]


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
        if not has_any_file(target, *BUILD_MANIFESTS):
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
        # #2225: record the manifest this scan's findings are located at, while
        # the target tree is in hand. `is_applicable` guarantees one of the
        # three is here; the fallback is for a caller that skipped that gate,
        # and keeps this invocation from publishing an earlier target's answer.
        _manifest_path_cv.set(_first_manifest(target) or DEFAULT_MANIFEST)
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
            try:
                # #1576 (OPS-3272189615): watch the report directory WHILE
                # dependency-check writes it. read_capped_report below is the
                # read-time half of the same 50 MiB ceiling, and by the time it
                # refuses an oversize report the work volume is already full --
                # for every concurrent scan on the worker, not just this one.
                # start_new_session so the kill reaches the JVM and not just
                # the dependency-check.sh wrapper.
                #
                # #1877: a FRESH scratch as the cwd -- not `out_dir`, which is
                # the report tree dependency-check writes into, and not the
                # target, whose cwd-relative suppression/config files it would
                # otherwise honour. `--scan` and `--out` are absolute, so argv
                # is byte-unchanged.
                with scratch_cwd("dependency-check-cwd-") as cwd:
                    _stdout, rc = run_tool(cmd, timeout=900, watch_path=out_dir,
                                           start_new_session=True, cwd=cwd)
            except OutputCapExceeded as exc:
                print("dependency-check: %s; recording as failed" % exc,
                      file=sys.stderr)
                return b"", _OUTPUT_CAP_RC
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

    def _located_at(self) -> str:
        """The build manifest this parse's findings are located at (#2225).

        Two routes and a last resort, because a real scan runs `invoke` and
        `parse` in DIFFERENT PROCESSES (#1649): run_tools dispatches the adapter
        as `docker run ... _run_adapter.py`, which only invokes, and
        `ingest_tools` parses the captured bytes back on the host. `invoke`'s own
        choice is used when the two share a process (capture_goldens); otherwise
        the same choice is made again from the target root ingest names around
        its parse. The last resort is for a caller with bytes and no tree at all.
        All three answers are repo-relative, which is the shape `location.file`
        carries everywhere downstream.
        """
        chosen = _manifest_path_cv.get()
        if chosen:
            return chosen
        root = target_root_cv.get()
        if root:
            return _first_manifest(root) or DEFAULT_MANIFEST
        return DEFAULT_MANIFEST

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = parse_json_bytes(raw)
        # Resolved ONCE per parse, not per finding: it stats the target root.
        # Every finding this adapter emits therefore shares one locus, so the
        # ARTIFACT is what keeps two advisories about DIFFERENT jars apart
        # downstream -- and BOTH stages that collapse tool findings key on
        # `tool_evidence.package_name` for it (#2225):
        # `synth/findings.aggregate_tool_findings` first, then
        # `synth/corroborate.dedupe`.
        manifest = self._located_at()
        out = []
        n = 1
        for dep in data.get("dependencies", []):
            included_by = _included_by(dep)
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
                    location={"file": manifest, "line_start": 1},
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
                        "included_by": included_by,
                    }),
                ))
                n += 1
        return out

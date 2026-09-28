"""Roslyn Security Guard / DotnetariumSCS adapter for C# security findings."""
from __future__ import annotations
import json
import os
import shutil
import sys
import tempfile
from .base import (OutputCapExceeded, as_list, make_finding, omit_none,
                   parse_json_bytes, read_capped_report, run_tool, scratch_cwd)
from .sarif_utils import CaptureCoverage, LEVEL_TO_SEV


# #run9 OPS-D1A: the scanned repo is untrusted under redteam. _safe_copytree
# duplicates it into a temp dir before scanning; with no ceiling a hostile C#
# project (a giant generated file, or a huge fan-out of files) can exhaust the
# build volume. Bound the copy by total bytes and file count. Env-overridable for
# a legitimately large repo. (Neighbor of run-8 #1415, which capped the container
# and the report READ but not this host-side copy.)
_MAX_COPY_BYTES = int(os.environ.get("PANOPTICON_ROSLYN_MAX_COPY_BYTES", 2 * 1024 ** 3))
_MAX_COPY_FILES = int(os.environ.get("PANOPTICON_ROSLYN_MAX_COPY_FILES", 200_000))
# #1576 (run-13 OPS-3539258787): the file cap counted only regular files, so an
# arbitrarily broad or deep hierarchy of EMPTY directories passed both caps and
# could exhaust the temp volume's inodes and the traversal itself before the
# scanner's timed run ever started. Directories get their own ceiling; a
# preserved in-tree symlink now counts toward _MAX_COPY_FILES too, because it
# is a destination inode like any other. Same disposition as the file cap: a
# breach raises before the copy that commits it.
_MAX_COPY_DIRS = int(os.environ.get("PANOPTICON_ROSLYN_MAX_COPY_DIRS", 200_000))
# #run9 OPS-E1A: rc returned when the scanner produced no usable SARIF -- NOT in
# run_tool's ok_codes (0, 1), so _capture_run records the tool as missing
# (-> INCONCLUSIVE) rather than a silent "zero findings" clean result.
_NO_OUTPUT_RC = 2


def _safe_copytree(src, dst):
    """Copy src into dst without dereferencing symlinks.

    Out-of-tree symlinks (resolved target escapes src, including dangling
    links) are skipped and counted — a scanned repo must not be able to pull
    /etc/passwd or the mounted scripts dir into the build tree (#86).
    In-tree links are preserved as links. Never follows links while walking,
    so link loops cannot recurse.

    #run9 OPS-D1A: bounded by _MAX_COPY_BYTES / _MAX_COPY_FILES -- an untrusted
    target that would blow past either raises BEFORE the copy that breaches it,
    so the adapter fails closed (recorded missing) rather than exhausting disk.
    #1576: _MAX_COPY_DIRS bounds the directories, which used to be created
    uncounted, and a preserved symlink counts as an entry.
    """
    root = os.path.realpath(src)
    skipped = 0
    total_bytes = 0
    total_files = 0
    total_dirs = 0
    os.makedirs(dst, exist_ok=True)
    for cur, dirs, files in os.walk(src, followlinks=False):
        rel = os.path.relpath(cur, src)
        out_dir = dst if rel == "." else os.path.join(dst, rel)
        total_dirs += 1
        if total_dirs > _MAX_COPY_DIRS:
            raise ValueError(
                "roslyn-secguard: target copy exceeds the directory cap (%d > "
                "%d) -- refusing to reproduce a hierarchy this large from an "
                "untrusted tree" % (total_dirs, _MAX_COPY_DIRS))
        os.makedirs(out_dir, exist_ok=True)
        for name in list(dirs) + files:
            s = os.path.join(cur, name)
            d = os.path.join(out_dir, name)
            if os.path.islink(s):
                real = os.path.realpath(s)
                if real == root or real.startswith(root + os.sep):
                    total_files += 1
                    if total_files > _MAX_COPY_FILES:
                        raise ValueError(
                            "roslyn-secguard: target copy exceeds the entry cap "
                            "(%d > %d) -- refusing to duplicate an untrusted tree "
                            "this large" % (total_files, _MAX_COPY_FILES))
                    os.symlink(os.readlink(s), d)
                else:
                    skipped += 1
                if name in dirs:
                    dirs.remove(name)   # never walk through a link
            elif name in files:
                total_files += 1
                try:
                    total_bytes += os.path.getsize(s)
                except OSError:
                    pass
                if total_bytes > _MAX_COPY_BYTES or total_files > _MAX_COPY_FILES:
                    raise ValueError(
                        "roslyn-secguard: target copy exceeds the cap (%d files / "
                        "%d bytes > %d / %d) -- refusing to duplicate an untrusted "
                        "tree this large" % (total_files, total_bytes,
                                             _MAX_COPY_FILES, _MAX_COPY_BYTES))
                shutil.copy2(s, d)
    return skipped


# The version of DotnetariumSCS `_ROSLYN_CWE` below was generated from -- a
# version bump that regenerates the table without updating this, or updates
# this without regenerating the table, now fails a test instead of going
# stale silently (#2325). Nothing at run time reads it; the provenance
# comment below already names it.
_TABLE_DOTNETARIUM_SCS_VERSION = "1.1.0"

# Every CWE DotnetariumSCS 1.1.0 itself assigns to a rule (#2325,
# COD-1750030735), from `DotnetariumSCS.Config.Messages.yml`, the resource
# embedded in `DotnetariumSCS.dll` (sha256
# c8613ceeffab1d1d7d9188183f7df97de226997425b4d28348a83014fdbaedc8) inside
# the tool the Dockerfile installs (`ARG DOTNETARIUM_SCS_VERSION=1.1.0`),
# measured against the pinned tools image on 2026-09-28. The assembly ships
# 32 diagnostics: SCS0000, its own proof-of-run notice, carries no `cwe` and
# stays uncited on purpose; the other 31 -- SCS0001-SCS0034 less the retired
# SCS0014/SCS0020/SCS0025 -- each carry one. The SARIF this adapter reads
# never carries a CWE: no field of a rule descriptor (`helpUri`, the two
# descriptions, `properties.category`) names one, and the scanner's `--cwe`
# flag decorates just the console line, leaving the SARIF byte-identical
# (probed both ways against the pinned image) -- so there is no
# SARIF-carried CWE to read and no reason to pass the flag. The table this
# replaces named nine rules and mis-cited SCS0026 (LDAP injection) as
# CWE-79, cross-site scripting's own code -- XSS is SCS0029 -- and listed
# SCS0041, which this tool has never shipped.
_ROSLYN_CWE = {
    "SCS0001": "CWE-78",
    "SCS0002": "CWE-89",
    "SCS0003": "CWE-643",
    "SCS0004": "CWE-295",
    "SCS0005": "CWE-338",
    "SCS0006": "CWE-327",
    "SCS0007": "CWE-611",
    "SCS0008": "CWE-614",
    "SCS0009": "CWE-1004",
    "SCS0010": "CWE-327",
    "SCS0011": "CWE-611",
    "SCS0012": "CWE-284",
    "SCS0013": "CWE-327",
    "SCS0015": "CWE-259",
    "SCS0016": "CWE-352",
    "SCS0017": "CWE-554",
    "SCS0018": "CWE-22",
    "SCS0019": "CWE-524",
    "SCS0021": "CWE-554",
    "SCS0022": "CWE-554",
    "SCS0023": "CWE-554",
    "SCS0024": "CWE-554",
    "SCS0026": "CWE-90",
    "SCS0027": "CWE-601",
    "SCS0028": "CWE-502",
    "SCS0029": "CWE-79",
    "SCS0030": "CWE-554",
    "SCS0031": "CWE-90",
    "SCS0032": "CWE-521",
    "SCS0033": "CWE-521",
    "SCS0034": "CWE-521",
}


# Directories that never hold the application's own project. Pruned from the
# build-target search so a vendored/sample/generated project cannot be picked
# over the app's real solution (#1119).
_ROSLYN_VENDOR_DIRS = {".git", "node_modules", "bin", "obj", "packages",
                       "vendor", "third_party", "thirdparty", "examples", "samples"}


def _rebase_sarif_uris(raw, tmp):
    """Rewrite SARIF artifactLocation/resultFile URIs from the ephemeral build
    copy (`tmp`) to repo-relative paths, so findings report a stable path and the
    host-local `/tmp/roslyn-XXX/` prefix never leaks (#1116). invoke() builds in a
    temp copy, so the standalone scanner roots every URI there; _location only strips
    the `file://` scheme, not the tmp prefix. Best-effort: unparseable SARIF or a
    uri outside `tmp` is returned unchanged."""
    try:
        data = parse_json_bytes(raw)
    except Exception:  # noqa: BLE001 - tolerant: leave unparseable SARIF untouched
        return raw
    if not isinstance(data, dict):
        return raw
    bases = {tmp, os.path.realpath(tmp)}

    def _rel(uri):
        if not isinstance(uri, str) or not uri:
            return uri
        p = uri[7:] if uri.startswith("file://") else uri
        cand = os.path.realpath(p) if os.path.isabs(p) else p
        for base in bases:
            if cand == base:
                return ""
            if cand.startswith(base + os.sep):
                return os.path.relpath(cand, base)
        return uri

    for run in data.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for res in run.get("results") or []:
            if not isinstance(res, dict):
                continue
            for loc in res.get("locations") or []:
                if not isinstance(loc, dict):
                    continue
                art = (loc.get("physicalLocation") or {}).get("artifactLocation")
                if isinstance(art, dict) and "uri" in art:
                    art["uri"] = _rel(art["uri"])
                rf = loc.get("resultFile")
                if isinstance(rf, dict) and "uri" in rf:
                    rf["uri"] = _rel(rf["uri"])
    return json.dumps(data).encode("utf-8")


class RoslynSecGuardAdapter:
    name = "roslyn-secguard"
    prefix = "RS"
    DROP_IF_NO_LOCATION = True

    def is_applicable(self, target: str) -> bool:
        """A C# project WITH ITS DEPENDENCIES ALREADY RESTORED.

        #calibration-6 (btcpayserver): a .csproj/.sln alone is not enough.
        DotnetariumSCS compiles the target through Roslyn, and without restored
        reference assemblies every single file fails to compile:

            error CS0518: Predefined type 'System.Object' is not defined

        It then writes a well-formed SARIF with `"results": []` and exits 2 --
        so the adapter discards it, roslyn-secguard lands in
        `tool_manifest.missing`, and the run is GATED on `tools_absent`. That is
        the fzf/brakeman shape (#1452) and the gosec shape (#1457) in a third
        costume: a scanner that cannot read the target, reporting nothing.

        Scans mount the target read-only with `--network none`, so `dotnet
        restore` can never run during a scan. A freshly cloned C# repo therefore
        CANNOT be analysed, and selecting the tool only manufactures a gate.
        btcpayserver has zero project.assets.json, obj/ or bin/.

        The AspGoat fixture passes only because Dockerfile.fixtures runs
        `dotnet restore && dotnet build` at IMAGE BUILD time, with network. That
        is what made this look supported for so long: the fixture is restored,
        every real target is not.

        So require the restore output. A target whose dependencies are already
        restored (a CI workspace, a developer checkout) still gets scanned; a
        bare clone is disclosed as inapplicable rather than gating the run.
        """
        if not os.path.isdir(target):
            return False
        has_project = any(
            f.endswith(".csproj") or f.endswith(".sln")
            for f in os.listdir(target)
            if os.path.isfile(os.path.join(target, f))
        )
        if not has_project:
            return False
        return self._has_restored_dependencies(target)

    @staticmethod
    def _has_restored_dependencies(target: str) -> bool:
        """True when NuGet restore output is present somewhere in the tree.

        `project.assets.json` is the definitive marker -- it is what restore
        writes and what the compiler reads to resolve reference assemblies.

        NOTE the prune list is deliberately NOT _ROSLYN_VENDOR_DIRS: that set
        exists for FINDING PROJECT FILES and includes `obj`, which is precisely
        where restore writes project.assets.json. Reusing it here made the check
        always return False -- caught by the tests below.
        """
        skip = {".git", "node_modules", "packages", ".vs"}
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in skip]
            if "project.assets.json" in files:
                return True
        return False

    def _build_target(self, target: str) -> str:
        sln_files = []
        csproj_files = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in _ROSLYN_VENDOR_DIRS]
            for file in files:
                full_path = os.path.join(root, file)
                if file.endswith(".sln"):
                    sln_files.append(full_path)
                elif file.endswith(".csproj"):
                    csproj_files.append(full_path)
        # Prefer a solution over a bare project; within each, the target closest
        # to the repo root, breaking ties deterministically by path. A nested
        # vendored/sample project can no longer sort ahead of the app's own
        # root-level solution the way `sorted(...)[0]` allowed (#1119).
        candidates = sln_files or csproj_files
        if not candidates:
            return target
        chosen = min(candidates, key=lambda p: (os.path.relpath(p, target).count(os.sep), p))
        if len(candidates) > 1:
            print("roslyn-secguard: %d build targets found; analyzing %s"
                  % (len(candidates), os.path.relpath(chosen, target)),
                  file=sys.stderr)
        return chosen

    def invoke(self, target: str) -> tuple[bytes, int]:
        # Run the target through the DotnetariumSCS standalone scanner and output SARIF.
        # The project is copied to a temporary directory so read-only mounts and
        # stale incremental build state do not break analysis.
        tmp = tempfile.mkdtemp(prefix="roslyn-")
        try:
            build_target = self._build_target(target)
            rel_target = os.path.relpath(build_target, target)
            tmp_target = os.path.join(tmp, rel_target)
            skipped = _safe_copytree(target, tmp)
            if skipped:
                print("roslyn-secguard: skipped %d out-of-tree symlink(s)" % skipped, file=sys.stderr)

            sarif = os.path.join(tmp, "out.sarif")
            cmd = [
                "dotnetarium-scs", tmp_target,
                "--export=" + sarif,
                "--ignore-msbuild-errors",
                "--no-banner",
            ]
            try:
                # #1576 (OPS-2007447947): watch the export path WHILE the
                # scanner writes it. read_capped_report below is the read-time
                # half of the same 50 MiB ceiling; without this one the temp
                # volume is already full by the time it refuses the file.
                #
                # #1877: a FRESH scratch as the cwd, deliberately NOT `tmp`.
                # `tmp` is a COPY of the target (_safe_copytree above), so it
                # carries any config the target planted just as the mount
                # does. The project path and `--export` are absolute, so argv
                # is byte-unchanged.
                with scratch_cwd("roslyn-secguard-cwd-") as cwd:
                    _stdout, rc = run_tool(cmd, timeout=600, watch_path=sarif,
                                           start_new_session=True, cwd=cwd)
            except OutputCapExceeded as exc:
                print("roslyn-secguard: %s; recording as failed" % exc,
                      file=sys.stderr)
                return b"", _NO_OUTPUT_RC
            if os.path.exists(sarif):
                # #run8 OPS-D1A: the scanner writes SARIF to disk, so this read
                # bypasses run_tool's stdout cap; bound it and fail closed on an
                # oversize (attacker-influenced) report rather than slurp it whole.
                raw = read_capped_report(sarif)
                if raw is not None:
                    # #1116: rebase tmp-rooted uris to repo-relative before ingest
                    return _rebase_sarif_uris(raw, tmp), rc
            # #run9 OPS-E1A: the scanner exited within ok_codes but produced NO
            # usable SARIF (absent, or oversize/unreadable). Returning b"{}" with
            # the tool's own ok rc reports a silent "zero findings" for a scan that
            # never actually analyzed -- a clean gate on no evidence. Fail closed so
            # run_tools records the tool as missing (-> INCONCLUSIVE), not clean.
            print("roslyn-secguard: no usable SARIF at %s (tool rc=%s); "
                  "recording as failed" % (sarif, rc), file=sys.stderr)
            return b"", _NO_OUTPUT_RC
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _location(self, loc: dict) -> dict:
        # SARIF v1 uses resultFile; v2 uses physicalLocation/artifactLocation.
        if not isinstance(loc, dict):
            raise ValueError("expected location object")
        phys = loc.get("physicalLocation", {})
        if phys:
            artifact = phys.get("artifactLocation", {})
            region = phys.get("region", {})
            uri = artifact.get("uri", "")
            line = region.get("startLine", 1)
        else:
            result_file = loc.get("resultFile", {})
            region = result_file.get("region", {})
            uri = result_file.get("uri", "")
            line = region.get("startLine", 1)
        if not isinstance(uri, str) or not uri:
            raise ValueError("expected location URI")
        # Strip the file:// scheme and temporary build prefix if present.
        if uri.startswith("file://"):
            uri = uri[7:]
        return {"file": uri, "line_start": line}

    @staticmethod
    def _message_text(result: dict, default: str = "") -> str:
        """Return the message text from a SARIF result.

        SARIF allows ``message`` to be either a plain string or a dict with a
        ``text`` property. Some tools (including older DotnetariumSCS builds)
        emit the string form, so handle both.
        """
        message = result.get("message", default)
        if isinstance(message, dict):
            return message.get("text", default)
        if isinstance(message, str):
            return message
        return default

    @staticmethod
    def _source_path(result):
        """Best-effort attribution of a malformed result, without parsing it."""
        locations = result.get("locations")
        if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
            return None
        location = locations[0]
        physical = location.get("physicalLocation")
        artifact = (physical.get("artifactLocation") if isinstance(physical, dict)
                    else location.get("resultFile"))
        return artifact.get("uri") if isinstance(artifact, dict) else None

    def parse(self, raw: bytes, group: str) -> list[dict]:
        return self.parse_with_file_coverage(raw, group)[0]

    def parse_with_file_coverage(self, raw: bytes, group: str) -> tuple[list[dict], dict]:
        data = parse_json_bytes(raw)
        if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
            raise ValueError("roslyn-secguard: expected an object with a runs array")
        coverage = CaptureCoverage()
        out = []
        n = 1
        for ri, run in enumerate(data["runs"]):
            record = "runs[%d]" % ri
            run = coverage.object(run, record)
            if run is None:
                continue
            # SARIF may omit results for a run without findings; a present
            # non-array value is malformed, not the same as an omitted key.
            results = coverage.array(run.get("results", []), record + ".results")
            for fi, result in enumerate(results):
                result_record = record + ".results[%d]" % fi
                result = coverage.object(result, result_record)
                if result is None:
                    continue
                path = self._source_path(result)
                rule_id = result.get("ruleId")
                if not isinstance(rule_id, str) or not rule_id:
                    coverage.malformed(result_record + ".ruleId", "expected_identifier", path)
                    continue
                # Only SCS rules are findings. Compiler/restore diagnostics are
                # intentionally dropped: they can quote source (#86).
                if not rule_id.startswith("SCS"):
                    continue
                # Preserve DROP_IF_NO_LOCATION (#476). Wrong container types
                # are errors even when falsey; absent/null/[] remain policy drops.
                locs = result.get("locations")
                if locs is None or locs == []:
                    continue
                locs = coverage.array(locs, result_record + ".locations", path)
                if not locs:
                    continue
                try:
                    location = self._location(locs[0])
                    cwe = _ROSLYN_CWE.get(rule_id)
                    message = self._message_text(result, rule_id)
                    level = str(result.get("level", "warning")).lower()
                    severity = LEVEL_TO_SEV.get(level, "INFO")
                    finding = make_finding(
                        self, n, group,
                        title=message,
                        severity=severity,
                        confidence="LIKELY",
                        category="csharp_security",
                        location=location,
                        description=message or "No description provided.",
                        impact="Potential security issue in C# code.",
                        remediation="Review the DotnetariumSCS (SCS) rule and refactor.",
                        citations={"cwe": as_list(cwe)},
                        tool_evidence=omit_none({"rule_id": rule_id}),
                    )
                except (AttributeError, TypeError, ValueError):
                    # Do not echo the capture or an exception containing its
                    # values. One bad result must not discard usable siblings.
                    coverage.malformed(result_record, "invalid_result", path)
                    continue
                coverage.seen(path)
                out.append(finding)
                n += 1
        return out, coverage.finish(self.name)

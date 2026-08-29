"""Roslyn Security Guard / DotnetariumSCS adapter for C# security findings."""
from __future__ import annotations
import json
import os
import shutil
import sys
import tempfile
from .base import (as_list, make_finding, omit_none, parse_json_bytes,
                   read_capped_report, run_tool)
from .sarif_utils import LEVEL_TO_SEV


# #run9 OPS-D1A: the scanned repo is untrusted under redteam. _safe_copytree
# duplicates it into a temp dir before scanning; with no ceiling a hostile C#
# project (a giant generated file, or a huge fan-out of files) can exhaust the
# build volume. Bound the copy by total bytes and file count. Env-overridable for
# a legitimately large repo. (Neighbor of run-8 #1415, which capped the container
# and the report READ but not this host-side copy.)
_MAX_COPY_BYTES = int(os.environ.get("PANOPTICON_ROSLYN_MAX_COPY_BYTES", 2 * 1024 ** 3))
_MAX_COPY_FILES = int(os.environ.get("PANOPTICON_ROSLYN_MAX_COPY_FILES", 200_000))
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
    """
    root = os.path.realpath(src)
    skipped = 0
    total_bytes = 0
    total_files = 0
    os.makedirs(dst, exist_ok=True)
    for cur, dirs, files in os.walk(src, followlinks=False):
        rel = os.path.relpath(cur, src)
        out_dir = dst if rel == "." else os.path.join(dst, rel)
        os.makedirs(out_dir, exist_ok=True)
        for name in list(dirs) + files:
            s = os.path.join(cur, name)
            d = os.path.join(out_dir, name)
            if os.path.islink(s):
                real = os.path.realpath(s)
                if real == root or real.startswith(root + os.sep):
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


_ROSLYN_CWE = {
    "SCS0001": "CWE-78",
    "SCS0002": "CWE-89",
    "SCS0007": "CWE-611",
    "SCS0016": "CWE-352",
    "SCS0018": "CWE-22",
    "SCS0026": "CWE-79",
    "SCS0027": "CWE-601",
    "SCS0028": "CWE-502",
    "SCS0041": "CWE-22",
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
        if not os.path.isdir(target):
            return False
        return any(
            f.endswith(".csproj") or f.endswith(".sln")
            for f in os.listdir(target)
            if os.path.isfile(os.path.join(target, f))
        )

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
            _stdout, rc = run_tool(cmd, timeout=600)
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
            loc = {}
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

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = parse_json_bytes(raw)
        out = []
        n = 1
        runs = data.get("runs") or []
        if not isinstance(runs, list):
            return []
        for run in runs:
            if not isinstance(run, dict):
                continue
            results = run.get("results") or []
            if not isinstance(results, list):
                continue
            for result in results:
                try:
                    rule_id = result.get("ruleId", "")
                    # Only DotnetariumSCS (SCS) rules are findings. Compiler/restore
                    # diagnostics (CS####, NU####, MSB####) are dropped: they are
                    # noise from offline builds and can quote file content into
                    # the report (the #86 exfiltration channel).
                    if not rule_id.startswith("SCS"):
                        continue
                    # Omitted key and present-but-empty/null are the SAME
                    # case - a location-less diagnostic (#476). Both drop:
                    # previously an omitted key emitted a placeholder-location
                    # finding while an empty list was dropped, an asymmetry
                    # with no basis in SARIF semantics.
                    # Policy: DROP_IF_NO_LOCATION (see adapter constant).
                    locs = result.get("locations") or []
                    if not locs:
                        continue
                    loc = locs[0]
                    location = self._location(loc)
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
                except Exception as exc:  # noqa: BLE001 - tolerant by design: skip only this result
                    print(f"roslyn-secguard: skipping result {result.get('ruleId', 'unknown')}: {exc!r}", file=sys.stderr)
                    continue
                out.append(finding)
                n += 1
        return out

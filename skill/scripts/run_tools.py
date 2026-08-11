#!/usr/bin/env python3
"""Detect the panopticon-tools Docker image and run selected scanners against a
read-only mount of the target. Scan-time network is DISABLED for all tools
(assets are baked into the image); parse-only adapters never execute target
code; roslyn-secguard executes target build logic inside a no-egress,
no-secret container (recorded in report meta); pip-audit/npm-audit run only
under --online. Degrades gracefully when Docker is absent. Stdlib-only.
"""
import fnmatch
import os
import json
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.tools import ADAPTERS, EXECUTES_TARGET_BUILD, ONLINE_ONLY  # noqa: F401
from scripts import plan_contract
from scripts.tools.legacy_sarif import LEGACY_SARIF_TOOLS, TOOL_CMD

# JS/TS SAST runs via the eslint-security ADAPTER (bundled flat config);
# the legacy bare-eslint tool can never run on arbitrary targets (eslint >=9
# requires a project eslint.config.js) and was retired from language selection
# (calibration 2026-08-03: perpetual "tool eslint exited 2; skipping").
LANG_TOOL = {"python": "bandit", "go": "gosec"}

# Phase 1 adapters selected by ecosystem detection; they are dispatched through
# _run_adapter.py inside the panopticon-tools container.
PHASE1_ADAPTERS = {"pip-audit", "npm-audit", "osv-scanner", "eslint-security"}

# Phase 2 adapters selected by applicability to the target repo.
PHASE2_ADAPTERS = {
    "brakeman", "bundler-audit", "spotbugs", "dependency-check",
    "cargo-audit", "roslyn-secguard",
}

# Max seconds to let a single docker-run tool invocation run before it's killed;
# prevents a hung tool from blocking the whole batch (CD-007).
TOOL_TIMEOUT = 900


def validate_output_dir(target, out_dir):
    """Reject default artifact output through a target-controlled symlink."""
    logical_root = os.path.join(os.path.abspath(target), ".panopticon")
    candidate = os.path.abspath(out_dir)
    try:
        under_artifacts = os.path.commonpath([logical_root, candidate]) == logical_root
    except ValueError:
        under_artifacts = False
    if under_artifacts:
        safe_root = plan_contract.artifact_root(target)
        if os.path.commonpath([os.path.realpath(safe_root), os.path.realpath(candidate)]) \
                != os.path.realpath(safe_root):
            raise ValueError("scanner output escapes the target artifact directory")
    return out_dir


def docker_available(image="panopticon-tools", runner=None):
    """Check if the specified Docker image is available."""
    runner = runner or subprocess.run
    try:
        res = runner(["docker", "image", "inspect", image],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return getattr(res, "returncode", 1) == 0
    except Exception:  # noqa: BLE001
        return False


_LANG_EXTS = {".py": "python", ".go": "go",
              ".js": "javascript", ".jsx": "javascript",
              ".ts": "typescript", ".tsx": "typescript"}
_DETECT_PRUNE = {".git", ".venv", "venv", "node_modules", "__pycache__",
                 ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", "tmp"}


def detect_languages(target):
    """Best-effort language detection by source-file extension.

    The bare CLI invocation (README/CI) passes no --languages, which previously
    meant the language-keyed SAST tools (bandit/gosec/eslint) NEVER ran
    (calibration 2026-08-03). Walks with noise-dir pruning; stops once every
    known language is seen.
    """
    found = set()
    want = set(_LANG_EXTS.values())
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames
                       if d not in _DETECT_PRUNE and not d.startswith(".")]
        for fn in filenames:
            lang = _LANG_EXTS.get(os.path.splitext(fn)[1].lower())
            if lang:
                found.add(lang)
                if found == want:
                    return sorted(found)
    return sorted(found)


def select_tools(languages, has_deps):
    """Select security scanners based on detected languages and dependency status."""
    tools = ["semgrep", "gitleaks"]
    if has_deps:
        tools.append("trivy")
    for lang in languages or []:
        t = LANG_TOOL.get(str(lang).lower())
        if t and t not in tools:
            tools.append(t)
    return tools


def select_adapters(target: str, adapters: dict | None = None) -> dict:
    """Return the subset of adapters applicable to the target repo."""
    adapters = adapters or ADAPTERS
    return {name: adapter for name, adapter in adapters.items() if adapter.is_applicable(target)}


def _is_excluded(rel, exclude_globs):
    """True if a repo-relative path matches any exclusion glob (fnmatch `*`
    spans `/`, so `tests/fixtures/*` covers the whole subtree)."""
    rel = str(rel).replace(os.sep, "/")
    return any(fnmatch.fnmatch(rel, g) for g in exclude_globs or [])


def partition_by_exclusion(adapters, target, exclude_globs):
    """Split applicable adapters into (required, excluded_scope).

    An adapter is `excluded_scope` when it exposes ``applicable_files`` and
    EVERY such file matches an --exclude glob: its entire surface is outside the
    gate's scope, so a missing run cannot hide a gate-relevant finding — it is
    disclosed, not required. Adapters without file-level applicability (their
    trigger is a manifest/lockfile, not an excludable source tree) stay
    required. With no exclusions, nothing is demoted.
    """
    required, excluded_scope = [], []
    for name, adapter in adapters.items():
        lister = getattr(adapter, "applicable_files", None)
        files = list(lister(target)) if callable(lister) else []
        if exclude_globs and files and all(
                _is_excluded(os.path.relpath(f, target), exclude_globs) for f in files):
            excluded_scope.append(name)
        else:
            required.append(name)
    return required, excluded_scope


def filter_online(chosen, online):
    """Drop ONLINE_ONLY adapters unless --online was given, with a notice."""
    if online:
        return list(chosen)
    kept = [t for t in chosen if t not in ONLINE_ONLY]
    for t in chosen:
        if t in ONLINE_ONLY:
            print("adapter %s needs network; skipped (offline substitute: "
                  "osv-scanner). Re-run with --online to include it." % t,
                  file=sys.stderr)
    return kept


def _capture_run(label, tool, docker, out_path, runner):
    """Run one docker tool/adapter invocation and land its stdout at out_path.

    The single home for the run/rc-check/write/warn-on-empty/timeout sequence
    both run_tools branches share. rc 1 is accepted (== findings for most
    scanners); other exits print a capped stderr excerpt so 'exited N;
    skipping' is diagnosable. Returns out_path on success, None on skip.
    """
    try:
        os.remove(out_path)
    except OSError:
        pass
    try:
        res = runner(docker, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                     timeout=TOOL_TIMEOUT)
        if getattr(res, "returncode", 1) not in (0, 1):  # 1 == findings for many tools
            excerpt = (getattr(res, "stderr", b"") or b"")[-500:].decode(
                "utf-8", errors="replace").strip()
            print("%s %s exited %s; skipping%s" % (
                label, tool, res.returncode,
                (" — " + excerpt) if excerpt else ""), file=sys.stderr)
            return None
        fd, temp_path = tempfile.mkstemp(
            prefix=".%s-" % os.path.basename(out_path),
            dir=os.path.dirname(out_path) or ".")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(res.stdout or b"")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temp_path, out_path)
        finally:
            try:
                os.remove(temp_path)
            except OSError:
                pass
        if not (res.stdout or b"").strip():
            print("%s %s produced no output" % (label, tool), file=sys.stderr)
        return out_path
    except subprocess.TimeoutExpired:
        print("%s %s timed out after %ss; skipping" % (label, tool, TOOL_TIMEOUT),
              file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print("%s %s failed: %s; skipping" % (label, tool, e), file=sys.stderr)
    return None


def run_tools(target, tools, out_dir, image="panopticon-tools", runner=None, online=False):
    """Run selected security tools and adapters in Docker against target.

    Legacy SARIF tools use their hard-coded ``TOOL_CMD`` invocation. New Phase 1
    adapters are dispatched through ``scripts/_run_adapter.py`` inside the
    container so the same fat image is used for local and CI runs.
    """
    runner = runner or subprocess.run
    validate_output_dir(target, out_dir)
    os.makedirs(out_dir, exist_ok=True)
    tools = filter_online(tools, online)
    written = []
    for tool in tools:
        # Legacy SARIF path (kept for backward compatibility).
        cmd = TOOL_CMD.get(tool)
        if cmd:
            out_path = os.path.join(out_dir, "%s.sarif" % tool)
            docker = ["docker", "run", "--rm", "--network", "none",
                      "-v", "%s:/src:ro" % os.path.abspath(target), image] + cmd
            done = _capture_run("tool", tool, docker, out_path, runner)
            if done:
                written.append(done)
            continue

        # Phase 1 adapter dispatch path.
        adapter = ADAPTERS.get(tool)
        if adapter:
            ext = "sarif" if tool in LEGACY_SARIF_TOOLS else "json"
            out_path = os.path.join(out_dir, "%s.%s" % (tool, ext))
            docker = ["docker", "run", "--rm"]
            if tool not in ONLINE_ONLY:
                docker.extend(["--network", "none"])
            # Mount the checkout's adapter code over the image's baked-in copy
            # so local adapter fixes take effect without an image rebuild
            # (calibration 2026-08-03: fixed adapters silently kept failing
            # because the image carried the stale code).
            scripts_dir = os.path.dirname(os.path.abspath(__file__))
            docker.extend([
                "-v", "%s:/src:ro" % os.path.abspath(target),
                "-v", "%s:/opt/panopticon/scripts:ro" % scripts_dir, image,
                "python3", "/opt/panopticon/scripts/_run_adapter.py", tool])
            done = _capture_run("adapter", tool, docker, out_path, runner)
            if done:
                written.append(done)
    return written


def write_manifest(path, selected, written, excluded_scope=()):
    """Write the exact selected/produced scanner set for coverage gating.

    `excluded_scope` names adapters that were applicable but whose entire
    surface fell under the gate's --exclude globs; they are disclosed (never
    required), and are kept out of `selected` so the missing-set invariant
    holds.
    """
    selected = list(dict.fromkeys(str(tool) for tool in selected))
    produced = sorted({os.path.splitext(os.path.basename(p))[0] for p in written})
    payload = {"selected": selected, "produced": produced,
               "missing": sorted(set(selected) - set(produced)),
               "excluded_scope": sorted(dict.fromkeys(str(t) for t in excluded_scope))}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    return payload


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="panopticon tool runner")
    ap.add_argument("--target", default=".")
    ap.add_argument("--out", default=os.path.join(".panopticon", "tools"))
    ap.add_argument("--tools", nargs="*", default=None)
    ap.add_argument("--languages", nargs="*", default=[])
    ap.add_argument("--deps", action="store_true")
    ap.add_argument("--online", action="store_true", help="allow pip-audit/npm-audit to reach their advisory APIs")
    ap.add_argument("--manifest", default=None,
                    help="Write selected/produced scanner coverage JSON")
    ap.add_argument("--exclude", action="append", default=[],
                    help="Path glob whose files are out of gate scope; an "
                         "adapter applicable only to excluded files is disclosed "
                         "as excluded_scope, not required (repeatable). Pass the "
                         "same globs the gate uses.")
    a = ap.parse_args()
    if not docker_available():
        print("panopticon-tools image not available; skipping tool scan", file=sys.stderr)
        sys.exit(0)
    excluded_scope = []
    if a.tools:
        chosen = a.tools
    else:
        selected_adapters = select_adapters(a.target)
        required_names, excluded_scope = partition_by_exclusion(
            selected_adapters, a.target, a.exclude)
        phase1 = [name for name in required_names if name in PHASE1_ADAPTERS]
        phase2 = [name for name in required_names if name in PHASE2_ADAPTERS]
        languages = a.languages or detect_languages(a.target)
        chosen = select_tools(languages, a.deps) + phase1 + phase2
    effective = filter_online(chosen, a.online)
    paths = run_tools(a.target, effective, a.out, online=a.online)
    if a.manifest:
        write_manifest(a.manifest, effective, paths, excluded_scope=excluded_scope)
    print("\n".join(paths))

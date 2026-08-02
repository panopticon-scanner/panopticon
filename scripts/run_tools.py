#!/usr/bin/env python3
"""Detect the panopticon-tools Docker image and run selected scanners against a
read-only mount of the target. Network is allowed (tools only parse source,
never execute it). Degrades gracefully when Docker is absent.
Stdlib-only.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.tools import ADAPTERS

LANG_TOOL = {"python": "bandit", "go": "gosec",
             "javascript": "eslint", "typescript": "eslint"}

LEGACY_SARIF_TOOLS = {"semgrep", "bandit", "trivy", "gitleaks", "gosec", "eslint"}

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

# Per-tool argv producing SARIF on stdout or to /out (kept minimal; extended per tool).
TOOL_CMD = {
    "semgrep": ["semgrep", "scan", "--config", "auto", "--sarif", "--quiet", "/src"],
    "gitleaks": ["gitleaks", "detect", "--no-git", "--source", "/src", "--report-format", "sarif",
                 "--report-path", "/dev/stdout", "--no-banner"],
    "trivy": ["trivy", "fs", "--format", "sarif", "/src"],
    "bandit": ["bandit", "-r", "/src", "-f", "sarif"],
    "gosec": ["gosec", "-fmt=sarif", "./..."],
    "eslint": ["eslint", "-f", "@microsoft/eslint-formatter-sarif", "/src"],
}


def docker_available(image="panopticon-tools", runner=None):
    """Check if the specified Docker image is available."""
    runner = runner or subprocess.run
    try:
        res = runner(["docker", "image", "inspect", image],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return getattr(res, "returncode", 1) == 0
    except Exception:  # noqa: BLE001
        return False


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


def run_adapters(adapters: dict, target: str, out_dir: str, runner=None) -> list[str]:
    """Run each adapter and write raw output to out_dir."""
    runner = runner or subprocess.run
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name, adapter in adapters.items():
        ext = "sarif" if name in LEGACY_SARIF_TOOLS else "json"
        out_path = os.path.join(out_dir, f"{name}.{ext}")
        try:
            stdout, rc = adapter.invoke(target)
            if rc not in (0, 1):
                print(f"adapter {name} exited {rc}; skipping", file=sys.stderr)
                continue
            with open(out_path, "wb") as fh:
                fh.write(stdout)
            written.append(out_path)
        except Exception as e:
            print(f"adapter {name} failed: {e}; skipping", file=sys.stderr)
    return written


def run_tools(target, tools, out_dir, image="panopticon-tools", runner=None):
    """Run selected security tools and adapters in Docker against target.

    Legacy SARIF tools use their hard-coded ``TOOL_CMD`` invocation. New Phase 1
    adapters are dispatched through ``scripts/_run_adapter.py`` inside the
    container so the same fat image is used for local and CI runs.
    """
    runner = runner or subprocess.run
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for tool in tools:
        # Legacy SARIF path (kept for backward compatibility).
        cmd = TOOL_CMD.get(tool)
        if cmd:
            out_path = os.path.join(out_dir, "%s.sarif" % tool)
            docker = ["docker", "run", "--rm",
                      "-v", "%s:/src:ro" % os.path.abspath(target), image] + cmd
            try:
                res = runner(docker, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=TOOL_TIMEOUT)
                if getattr(res, "returncode", 1) not in (0, 1):  # 1 == findings for many tools
                    print("tool %s exited %s; skipping" % (tool, res.returncode), file=sys.stderr)
                    continue
                with open(out_path, "wb") as fh:
                    fh.write(res.stdout or b"")
                written.append(out_path)
            except subprocess.TimeoutExpired:
                print("tool %s timed out after %ss; skipping" % (tool, TOOL_TIMEOUT), file=sys.stderr)
            except Exception as e:  # noqa: BLE001
                print("tool %s failed: %s; skipping" % (tool, e), file=sys.stderr)
            continue

        # Phase 1 adapter dispatch path.
        adapter = ADAPTERS.get(tool)
        if adapter:
            ext = "sarif" if tool in LEGACY_SARIF_TOOLS else "json"
            out_path = os.path.join(out_dir, "%s.%s" % (tool, ext))
            docker = ["docker", "run", "--rm"]
            if os.environ.get("NVD_API_KEY"):
                docker.extend(["-e", "NVD_API_KEY"])
            docker.extend([
                "-v", "%s:/src:ro" % os.path.abspath(target), image,
                "python3", "/opt/panopticon/scripts/_run_adapter.py", tool])
            try:
                res = runner(docker, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=TOOL_TIMEOUT)
                if getattr(res, "returncode", 1) not in (0, 1):
                    print("adapter %s exited %s; skipping" % (tool, res.returncode), file=sys.stderr)
                    continue
                with open(out_path, "wb") as fh:
                    fh.write(res.stdout or b"")
                written.append(out_path)
            except subprocess.TimeoutExpired:
                print("adapter %s timed out after %ss; skipping" % (tool, TOOL_TIMEOUT), file=sys.stderr)
            except Exception as e:  # noqa: BLE001
                print("adapter %s failed: %s; skipping" % (tool, e), file=sys.stderr)
    return written


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="panopticon tool runner")
    ap.add_argument("--target", default=".")
    ap.add_argument("--out", default=os.path.join(".panopticon", "tools"))
    ap.add_argument("--tools", nargs="*", default=None)
    ap.add_argument("--languages", nargs="*", default=[])
    ap.add_argument("--deps", action="store_true")
    a = ap.parse_args()
    if not docker_available():
        print("panopticon-tools image not available; skipping tool scan", file=sys.stderr)
        sys.exit(0)
    if a.tools:
        chosen = a.tools
    else:
        selected_adapters = select_adapters(a.target)
        phase1 = [name for name in selected_adapters if name in PHASE1_ADAPTERS]
        phase2 = [name for name in selected_adapters if name in PHASE2_ADAPTERS]
        chosen = select_tools(a.languages, a.deps) + phase1 + phase2
    paths = run_tools(a.target, chosen, a.out)
    print("\n".join(paths))

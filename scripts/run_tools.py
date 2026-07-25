#!/usr/bin/env python3
"""Detect the panopticon-tools Docker image and run selected scanners against a
read-only mount of the target. Network is allowed (tools only parse source,
never execute it). Degrades gracefully when Docker is absent.
Stdlib-only.
"""
import os
import subprocess
import sys

LANG_TOOL = {"python": "bandit", "ruby": "brakeman", "go": "gosec",
             "javascript": "eslint", "typescript": "eslint"}

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
    "brakeman": ["brakeman", "-f", "sarif", "/src"],
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


def run_tools(target, tools, out_dir, image="panopticon-tools", runner=None):
    """Run selected security tools in Docker against target and write SARIF output."""
    runner = runner or subprocess.run
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for tool in tools:
        cmd = TOOL_CMD.get(tool)
        if not cmd:
            continue
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
    chosen = a.tools or select_tools(a.languages, a.deps)
    paths = run_tools(a.target, chosen, a.out)
    print("\n".join(paths))

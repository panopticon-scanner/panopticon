"""pip-audit adapter for Python dependency CVEs."""
from __future__ import annotations
import glob
import os
import sys
import tempfile
import tomllib
from .base import cve_ids, make_finding, normalize_severity, omit_none, parse_json_bytes, run_tool


def _deps_from_pyproject(target: str) -> list[str] | None:
    """Static PEP 621 read — never invokes a build backend (#218)."""
    path = os.path.join(target, "pyproject.toml")
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError):
        return None
    project = data.get("project")
    if not isinstance(project, dict):
        return None
    if "dependencies" in (project.get("dynamic") or []):
        return None
    deps = list(project.get("dependencies") or [])
    for extra in (project.get("optional-dependencies") or {}).values():
        deps.extend(extra)
    return deps


class PipAuditAdapter:
    name = "pip-audit"
    prefix = "PA"

    def __init__(self) -> None:
        self._manifest_path: str | None = None

    def is_applicable(self, target: str) -> bool:
        patterns = ["requirements.txt", "requirements*.txt", "pyproject.toml"]
        for pat in patterns:
            path = os.path.join(target, pat)
            if "*" in pat:
                if glob.glob(path):
                    return True
            elif os.path.exists(path):
                return True
        return False

    def invoke(self, target: str) -> tuple[bytes, int]:
        # --desc takes an optional value; the bare form swallows a following
        # positional path (calibration 2026-08-03: --desc /src -> argparse
        # error, exit 2). Always use the explicit-value form.
        # --progress-spinner=off: some pip-audit builds emit an ANSI progress
        # spinner into stdout ahead of the JSON, which corrupts parsing.
        cmd = ["pip-audit", "--format=json", "--desc=on", "--progress-spinner=off"]
        req = self._find_requirement(target)
        if req:
            self._manifest_path = req
            cmd.extend(["--requirement", req])
        else:
            # Never pass the project directory positionally: resolving a
            # source tree can invoke its PEP 517 build backend (#218).
            deps = _deps_from_pyproject(target)
            if not deps:
                print("pip-audit: no static [project.dependencies] in %s; "
                      "skipping (osv-scanner covers this target)" % target,
                      file=sys.stderr)
                return b'{"dependencies": [], "fixes": []}', 0
            self._manifest_path = os.path.join(target, "pyproject.toml")
            tmp = tempfile.NamedTemporaryFile(
                "w", suffix=".txt", delete=False)
            try:
                tmp.write("\n".join(deps) + "\n")
                tmp.close()
                cmd.extend(["--requirement", tmp.name])
                return run_tool(cmd, timeout=300)
            finally:
                os.unlink(tmp.name)
        return run_tool(cmd, timeout=300)

    def _find_requirement(self, target: str) -> str | None:
        # Prefer the canonical requirements.txt (#707). The glob fallback
        # returns the lexicographically-first match, and '-' (0x2D) sorts
        # before '.' (0x2E), so requirements-dev.txt would otherwise win over
        # requirements.txt and the PRIMARY manifest would go unaudited.
        exact = os.path.join(target, "requirements.txt")
        if os.path.isfile(exact):
            return exact
        matches = sorted(glob.glob(os.path.join(target, "requirements*.txt")))
        return matches[0] if matches else None

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = parse_json_bytes(raw)
        out = []
        n = 1
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                out.append(make_finding(
                    self, n, group,
                    title=f"{dep['name']} {dep['version']}: {vuln.get('id', 'vulnerability')}",
                    severity=normalize_severity(vuln.get("severity") or "MEDIUM"),
                    category="dependency_vulnerability",
                    location={"file": self._manifest_path or "requirements.txt", "line_start": 1},
                    description=vuln.get("description", "No description provided."),
                    impact=f"Vulnerable dependency {dep['name']}=={dep['version']} is used.",
                    remediation=f"Upgrade to a fixed version: {', '.join(vuln.get('fix_versions', [])) or 'see advisory'}",
                    citations={"cve": cve_ids(vuln.get("aliases"))},
                    tool_evidence=omit_none({
                        "rule_id": vuln.get("id"),
                        "package_name": dep["name"],
                        "vulnerable_versions": dep["version"],
                        "fixed_version": (vuln.get("fix_versions") or [None])[0],
                    }),
                ))
                n += 1
        return out

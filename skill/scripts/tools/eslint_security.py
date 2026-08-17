"""eslint-plugin-security adapter for JS/TS security anti-patterns."""
from __future__ import annotations
import glob
import os
from .base import make_finding, omit_none, parse_json_bytes, run_tool


# CWE mappings for eslint-plugin-security rules (best-effort).
RULE_CWE = {
    "security/detect-eval-with-expression": "CWE-95",
    "security/detect-non-literal-require": "CWE-114",
    "security/detect-non-literal-fs-filename": "CWE-22",
    "security/detect-unsafe-regex": "CWE-185",
    "security/detect-buffer-noassert": "CWE-119",
    "security/detect-child-process": "CWE-78",
    "security/detect-disable-mustache-escape": "CWE-79",
    "security/detect-no-csrf-before-method-override": "CWE-352",
    "security/detect-object-injection": "CWE-94",
    "security/detect-possible-timing-attacks": "CWE-208",
    "security/detect-pseudoRandomBytes": "CWE-338",
}


class EslintSecurityAdapter:
    name = "eslint-security"
    prefix = "ESS"

    def applicable_files(self, target: str) -> list[str]:
        """The concrete files that make this adapter applicable.

        Coverage gating (run_tools + security_gate) uses this to decide whether
        the adapter has any in-scope surface once the gate's --exclude globs are
        applied: an adapter whose every applicable file is excluded cannot
        produce a gate-relevant finding, so a missing run is disclosed, not a
        coverage failure.
        """
        matched: list[str] = []
        for pattern in ("**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx"):
            matched.extend(glob.glob(os.path.join(target, pattern), recursive=True))
        pkg = os.path.join(target, "package.json")
        if os.path.isfile(pkg):
            matched.append(pkg)
        return matched

    def is_applicable(self, target: str) -> bool:
        return bool(self.applicable_files(target))

    def _lintable_sources(self, target: str) -> list[str]:
        """The actual source files eslint would lint: applicable_files minus the
        package.json manifest and anything under node_modules (eslint ignores
        node_modules by default). Empty means the adapter was selected only by a
        manifest, or its source is all excluded -- there is nothing to lint.
        """
        return [f for f in self.applicable_files(target)
                if os.path.basename(f) != "package.json"
                and "node_modules" not in f.replace("\\", "/").split("/")]

    def invoke(self, target: str) -> tuple[bytes, int]:
        # #984: applicable via a manifest but with no lintable source (or its
        # source all excluded) -> eslint would find "no files matching" and exit
        # 2, which run_tools discards as a skip, sinking coverage. Distinguish
        # ran-clean-no-source from could-not-run: emit a valid empty result so
        # this counts as PRODUCED (disposition "empty"), not missing. A genuine
        # eslint failure (source present, tool errors) still exits non-zero and
        # is honestly skipped.
        if not self._lintable_sources(target):
            return b"[]", 0
        cmd = [
            "eslint", "--no-config-lookup", "--parser-options", "ecmaVersion:latest",
            "--plugin", "security",
        ]
        for rule in RULE_CWE:
            cmd.extend(["--rule", f"{rule}: error"])
        cmd.extend(["--format", "json", os.path.abspath(target)])
        env = os.environ.copy()
        # eslint v10 resolves plugins relative to the *child process's cwd*,
        # not the linted path on argv - if cwd stayed inside the scanned
        # target, a hostile target-controlled node_modules/eslint-plugin-security
        # would load and execute ahead of the trusted global plugin (#83).
        # Pin cwd to this adapter's own directory (never contains
        # node_modules) so plugin resolution always finds the trusted copy
        # via the NODE_PATH fallback below.
        # Set NODE_PATH EXCLUSIVELY to the trusted global dir; never prepend an
        # inherited NODE_PATH (#715). Node searches NODE_PATH left-to-right, so
        # an inherited entry like /evil/node_modules would shadow the trusted
        # eslint-plugin-security and execute during the scan. Also drop any
        # inherited value so a stale entry can't leak in when neither global
        # dir exists.
        env.pop("NODE_PATH", None)
        for global_node in ["/usr/local/lib/node_modules", "/usr/lib/node_modules"]:
            if os.path.isdir(global_node):
                env["NODE_PATH"] = global_node
                break
        trusted_cwd = os.path.dirname(os.path.abspath(__file__))
        return run_tool(cmd, timeout=300, env=env, cwd=trusted_cwd)

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = parse_json_bytes(raw)
        out = []
        n = 1
        for file_result in data:
            file_path = file_result.get("filePath", "")
            rel = self._strip_prefix(file_path)
            for msg in file_result.get("messages", []):
                rule = msg.get("ruleId", "")
                if not rule.startswith("security/"):
                    continue
                out.append(make_finding(
                    self, n, group,
                    title=msg.get("message", rule),
                    severity="HIGH" if msg.get("severity") == 2 else "MEDIUM",
                    category="code_security",
                    location={"file": rel, "line_start": msg.get("line", 1)},
                    description=f"eslint-plugin-security rule {rule} triggered.",
                    impact="Potential security weakness in JavaScript/TypeScript code.",
                    remediation="Review the flagged code and follow the plugin's guidance.",
                    citations={"cwe": [RULE_CWE[rule]] if rule in RULE_CWE else []},
                    tool_evidence=omit_none({"rule_id": rule}),
                ))
                n += 1
        return out

    def _strip_prefix(self, path: str) -> str:
        for prefix in ["/src/", "src/", "/"]:
            if path.startswith(prefix):
                return path[len(prefix):]
        return path

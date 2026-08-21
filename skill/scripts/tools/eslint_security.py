"""eslint-plugin-security adapter for JS/TS security anti-patterns."""
from __future__ import annotations
import os
from .base import make_finding, omit_none, parse_json_bytes, run_tool
from .sarif_utils import norm_uri


# CWE mappings for eslint-plugin-security rules (best-effort).
RULE_CWE = {
    "security/detect-eval-with-expression": "CWE-95",
    "security/detect-non-literal-require": "CWE-114",
    "security/detect-non-literal-fs-filename": "CWE-22",
    "security/detect-unsafe-regex": "CWE-1333",
    "security/detect-buffer-noassert": "CWE-119",
    "security/detect-child-process": "CWE-78",
    "security/detect-disable-mustache-escape": "CWE-79",
    "security/detect-no-csrf-before-method-override": "CWE-352",
    "security/detect-object-injection": "CWE-1321",
    "security/detect-possible-timing-attacks": "CWE-208",
    "security/detect-pseudoRandomBytes": "CWE-338",
}


# Per-rule severity by impact class (#1118). invoke() forces every rule to
# eslint 'error' level purely to ENABLE it, so the eslint level carries no
# severity signal -- severity is derived here from what each rule detects:
# direct code/command execution -> HIGH; traversal, XSS/CSRF, DoS, weak-crypto,
# and the heuristic (false-positive-prone) checks -> MEDIUM. This is the
# calibration surface; adjust the assignments here.
RULE_SEVERITY = {
    "security/detect-eval-with-expression": "HIGH",       # arbitrary code execution
    "security/detect-non-literal-require": "HIGH",        # arbitrary module load -> code exec
    "security/detect-child-process": "HIGH",              # command execution
    "security/detect-non-literal-fs-filename": "MEDIUM",  # path traversal
    "security/detect-unsafe-regex": "MEDIUM",             # ReDoS
    "security/detect-buffer-noassert": "MEDIUM",          # out-of-bounds buffer access
    "security/detect-disable-mustache-escape": "MEDIUM",  # XSS
    "security/detect-no-csrf-before-method-override": "MEDIUM",  # CSRF
    "security/detect-object-injection": "MEDIUM",         # heuristic, FP-prone
    "security/detect-possible-timing-attacks": "MEDIUM",  # heuristic, FP-prone
    "security/detect-pseudoRandomBytes": "MEDIUM",        # weak randomness
}


class EslintSecurityAdapter:
    name = "eslint-security"
    prefix = "ESS"

    def applicable_files(self, target: str) -> list[str]:
        """The concrete files that make this adapter applicable."""
        matched: list[str] = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d != "node_modules"]
            for f in files:
                if f.endswith((".js", ".ts", ".jsx", ".tsx")):
                    matched.append(os.path.join(root, f))
        pkg = os.path.join(target, "package.json")
        if os.path.isfile(pkg):
            matched.append(pkg)
        return matched

    def is_applicable(self, target: str) -> bool:
        if os.path.isfile(os.path.join(target, "package.json")):
            return True
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d != "node_modules"]
            for f in files:
                if f.endswith((".js", ".ts", ".jsx", ".tsx")):
                    return True
        return False

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
        env.pop("NODE_PATH", None)
        for global_node in ["/usr/local/lib/node_modules", "/usr/lib/node_modules"]:
            if os.path.isdir(global_node):
                env["NODE_PATH"] = global_node
                break
        trusted_cwd = os.path.dirname(os.path.abspath(__file__))
        return run_tool(cmd, timeout=300, env=env, cwd=trusted_cwd, ok_codes=(0, 1))

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = parse_json_bytes(raw)
        out = []
        n = 1
        for f in data:
            fpath = f.get("filePath", "")
            rel = self._strip_prefix(fpath)
            for msg in f.get("messages", []):
                rule = msg.get("ruleId") or "unknown"
                if not rule.startswith("security/"):
                    continue
                out.append(make_finding(
                    self, n, group,
                    title=msg.get("message", rule),
                    severity=RULE_SEVERITY.get(rule, "MEDIUM"),
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
        return norm_uri(path)

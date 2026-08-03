"""eslint-plugin-security adapter for JS/TS security anti-patterns."""
from __future__ import annotations
import glob
import json
import os
import subprocess
from .base import attach_tool_provenance, new_finding_id, omit_none


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

    def is_applicable(self, target: str) -> bool:
        return bool(glob.glob(os.path.join(target, "**/*.js"), recursive=True) or
                    glob.glob(os.path.join(target, "**/*.ts"), recursive=True) or
                    glob.glob(os.path.join(target, "**/*.jsx"), recursive=True) or
                    glob.glob(os.path.join(target, "**/*.tsx"), recursive=True) or
                    os.path.isfile(os.path.join(target, "package.json")))

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = [
            "eslint", "--no-config-lookup", "--parser-options", "ecmaVersion:latest",
            "--plugin", "security",
        ]
        for rule in RULE_CWE:
            cmd.extend(["--rule", f"{rule}: error"])
        cmd.extend(["--format", "json", target])
        env = os.environ.copy()
        # eslint v10 resolves plugins relative to the project root; ensure the
        # globally installed plugin is discoverable inside the container.
        for global_node in ["/usr/local/lib/node_modules", "/usr/lib/node_modules"]:
            if os.path.isdir(global_node):
                existing = env.get("NODE_PATH", "")
                env["NODE_PATH"] = f"{existing}:{global_node}" if existing else global_node
                break
        res = subprocess.run(cmd, capture_output=True, timeout=300, env=env)
        return res.stdout, res.returncode

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for file_result in data:
            file_path = file_result.get("filePath", "")
            rel = self._strip_prefix(file_path)
            for msg in file_result.get("messages", []):
                rule = msg.get("ruleId", "")
                if not rule.startswith("security/"):
                    continue
                severity = "HIGH" if msg.get("severity") == 2 else "MEDIUM"
                cwe = RULE_CWE.get(rule)
                finding = {
                    "id": new_finding_id(self.prefix, n),
                    "title": msg.get("message", rule),
                    "severity": severity,
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "code_security",
                    "source": f"tool:{self.name}",
                    "location": {"file": rel, "line_start": msg.get("line", 1)},
                    "description": f"eslint-plugin-security rule {rule} triggered.",
                    "impact": "Potential security weakness in JavaScript/TypeScript code.",
                    "remediation": "Review the flagged code and follow the plugin's guidance.",
                    "references": [],
                    "tool_evidence": omit_none({"rule_id": rule}),
                    "_group": group,
                }
                if cwe:
                    finding["citations"] = {"cwe": [cwe]}
                attach_tool_provenance(finding, self.name, reasoning=finding["tool_evidence"].get("rule_id"))
                out.append(finding)
                n += 1
        return out

    def _strip_prefix(self, path: str) -> str:
        for prefix in ["/src/", "src/", "/"]:
            if path.startswith(prefix):
                return path[len(prefix):]
        return path

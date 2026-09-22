"""eslint-plugin-security adapter for JS/TS security anti-patterns."""
from __future__ import annotations
import json
import os
from .base import make_finding, omit_none, parse_json_bytes, run_tool, scratch_cwd
from .sarif_utils import norm_uri

# node_modules locations in the tools image, in priority order. The first is
# the image's own prefix, installed by `npm ci --ignore-scripts` from the
# lockfile this repo commits (#1734); the two global dirs are where the
# superseded `npm install -g` put things, and stay so that an older published
# image -- which a pinned digest can still pull -- keeps resolving the plugin.
_GLOBAL_NODE_DIRS = ("/opt/panopticon-node/node_modules",
                     "/usr/local/lib/node_modules", "/usr/lib/node_modules")


def _plugin_entry() -> str:
    """Absolute ESM entry file for eslint-plugin-security in the tools image.

    #run7: eslint 10 resolves plugins relative to the LINTED files, not the
    global install, and ignores NODE_PATH; ESM also cannot import a bare
    directory. So a flat config must import the explicit index.js by absolute
    path -- the old `--plugin security` CLI form failed with "Cannot find module
    'eslint-plugin-security'" and produced empty output (selected-but-unproduced,
    which silently blocked coverage certification)."""
    for d in _GLOBAL_NODE_DIRS:
        entry = os.path.join(d, "eslint-plugin-security", "index.js")
        if os.path.isfile(entry):
            return entry
    return "eslint-plugin-security/index.js"   # last resort; still explicit .js for ESM


def _flat_config(target: str) -> str:
    """A minimal eslint flat config (ESM) that loads eslint-plugin-security and
    turns every mapped rule ON at error level. The eslint level is used only to
    ENABLE the rule; severity is derived in parse() from RULE_SEVERITY.

    `basePath` is the ABSOLUTE *target* (#1877 C1). A flat config resolves its
    `files`/`ignores` patterns against a BASE PATH, and when the config is
    named with `--config` that base is the process CWD -- which #1877 moved
    off the target mount. Everything we lint then sits outside the base:
    measured on this image (eslint 10.9.0), the adapter produced NO output and
    exit 2, "...of a matching ignore pattern, check global ignores in your
    config file", where the same scan on the old cwd produced a finding.
    Pinning the base here puts the SCOPE back on the target while the process
    still runs from a scratch directory, so the cwd carries no target-authored
    resolution surface and the scan still covers the tree. (eslint >= 9.30;
    the image pins 10.9.0 -- `tools-image/node/package-lock.json`.)

    The path is interpolated into a JS string literal, so it is written with
    `json.dumps` rather than bare quotes. It is controller data, not the
    target's, but the escaping does not depend on knowing that.
    """
    rules = ",\n      ".join('"%s": "error"' % r for r in RULE_CWE)
    return (
        'import security from "%s";\n'
        'export default [\n'
        '  {\n'
        '    basePath: %s,\n'
        '    plugins: { security },\n'
        '    languageOptions: { ecmaVersion: "latest" },\n'
        '    rules: {\n      %s\n    }\n'
        '  }\n'
        '];\n' % (_plugin_entry(), json.dumps(os.path.abspath(target)), rules)
    )


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


_HEURISTIC_RULES = frozenset({
    "security/detect-object-injection",
    "security/detect-possible-timing-attacks",
})


def _iter_source_files(target):
    """Yield JS/TS source files under *target*, pruning node_modules."""
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d != "node_modules"]
        for f in files:
            if f.endswith((".js", ".ts", ".jsx", ".tsx")):
                yield os.path.join(root, f)


class EslintSecurityAdapter:
    name = "eslint-security"
    prefix = "ESS"

    def applicable_files(self, target: str) -> list[str]:
        """The concrete files that make this adapter applicable."""
        matched = list(_iter_source_files(target))
        pkg = os.path.join(target, "package.json")
        if os.path.isfile(pkg):
            matched.append(pkg)
        return matched

    def is_applicable(self, target: str) -> bool:
        if os.path.isfile(os.path.join(target, "package.json")):
            return True
        return any(_iter_source_files(target))

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
        # #run7: generate an eslint 9/10 flat config that imports the plugin by
        # explicit path (see _plugin_entry) and run it. The config lives in a
        # container-writable temp dir because the /src mount is read-only.
        # #1877: the config dir doubles as the WORKING DIRECTORY -- it holds
        # only our generated config and nothing the target controls, so a
        # second scratch would buy nothing. What matters is that it is not
        # the target (the container's `WORKDIR /src`), which is where eslint
        # would otherwise resolve anything cwd-relative from.
        with scratch_cwd("eslint-cfg-") as cfg_dir:
            cfg_path = os.path.join(cfg_dir, "eslint.config.mjs")
            with open(cfg_path, "w", encoding="utf-8") as fh:
                fh.write(_flat_config(target))
            # --config pins OUR generated config and --no-config-lookup stops
            # eslint from also discovering + EXECUTING the scanned target's own
            # eslint.config.js (arbitrary JS -> RCE). The plugin is imported by
            # ABSOLUTE path in that config, so no cwd- or NODE_PATH-relative
            # resolution can be hijacked by a hostile target node_modules
            # (#83/#715).
            cmd = ["eslint", "--config", cfg_path, "--no-config-lookup",
                   "--format", "json", os.path.abspath(target)]
            return run_tool(cmd, timeout=300, ok_codes=(0, 1), cwd=cfg_dir)

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
                    confidence="LIKELY" if rule in _HEURISTIC_RULES else "CERTAIN",
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

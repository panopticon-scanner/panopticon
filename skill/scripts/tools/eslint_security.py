"""eslint-plugin-security adapter for JS/TS security anti-patterns."""
from __future__ import annotations
import os
import json
import re
from .base import make_finding, omit_none, parse_json_bytes, run_tool, scratch_cwd
from .sarif_utils import norm_uri

# node_modules locations in the tools image, in priority order. The first is
# the image's own prefix, installed by `npm ci --ignore-scripts` from the
# lockfile this repo commits (#1734); the two global dirs are where the
# superseded `npm install -g` put things, and stay so that an older published
# image -- which a pinned digest can still pull -- keeps resolving the plugin.
_GLOBAL_NODE_DIRS = ("/opt/panopticon-node/node_modules",
                     "/usr/local/lib/node_modules", "/usr/lib/node_modules")
_TS_PARSER_ENTRY = "/opt/panopticon-node/node_modules/@typescript-eslint/parser/dist/index.js"


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


def _flat_config(ts_available: bool = True) -> str:
    """A minimal eslint flat config (ESM) that loads eslint-plugin-security and
    turns every mapped rule ON at error level. The eslint level is used only to
    ENABLE the rule; severity is derived in parse() from RULE_SEVERITY.

    No `basePath` (#1877, round 2): a config-OBJECT `basePath` narrows the
    `files`/`ignores` base but cannot widen it past the ConfigArray's ROOT
    base, which ESLint builds from the process cwd when the config is named
    with `--config`. Emitting one made no difference to a real round -- still
    exit 2, still no output -- so it is not carried here implying otherwise.
    The cwd is what decides eslint's scope, and `invoke` sets it.
    """
    rules = ",\n      ".join('"%s": "error"' % r for r in RULE_CWE)
    # The parser package publishes a CommonJS ./dist/index.js entry, whose
    # module.exports object is the default import in this ESM config. The path
    # is image-owned: target node_modules and tsconfig cannot select a parser.
    ts_import = 'import tsParser from "%s";\n' % _TS_PARSER_ENTRY if ts_available else ''
    ts_block = (
        '  { files: ["**/*.{ts,tsx}"],\n'
        '    languageOptions: { parser: tsParser, '
        'parserOptions: { project: false } },\n'
        '    linterOptions: { noInlineConfig: true },\n'
        '    plugins: { security }, rules },\n'
    ) if ts_available else ''
    return (
        'import security from "%s";\n'
        '%s'
        'const rules = {\n      %s\n};\n'
        'export default [\n'
        '  { files: ["**/*.{js,jsx}"],\n'
        '    languageOptions: { ecmaVersion: "latest", '
        'parserOptions: { ecmaFeatures: { jsx: true } } },\n'
        '    linterOptions: { noInlineConfig: true },\n'
        '    plugins: { security }, rules },\n'
        '%s'
        '];\n' % (_plugin_entry(), ts_import, rules, ts_block)
    )


# Scanner-owned envelope v1 exists only when the trusted TS parser is absent.
# Native ESLint arrays remain valid; metadata never masquerades as ESLint rows.
MAX_COVERAGE_FILES = 100
MAX_COVERAGE_PATH = 240


def _safe_path(path):
    from scripts.redact import redact
    path = norm_uri(path)
    path = re.sub(r"[^a-zA-Z0-9_./@+ -]", "_", redact(path))
    return path[:MAX_COVERAGE_PATH] or "<unknown>"


def _fatal_message(msg):
    return msg.get("fatal") is True or (
        msg.get("ruleId") is None
        and isinstance(msg.get("message"), str)
        and msg["message"].startswith("Parsing error:"))


def _capture(data):
    """Validate native output and the optional, strictly typed adapter envelope."""
    metadata = None
    if isinstance(data, dict):
        if set(data) != {"panopticon_eslint", "results"}:
            raise ValueError("invalid ESLint capture envelope")
        metadata = data["panopticon_eslint"]
        if (not isinstance(metadata, dict)
                or set(metadata) != {"version", "typescript_parser", "files", "files_count"}
                or type(metadata["version"]) is not int or metadata["version"] != 1
                or metadata["typescript_parser"] != "unavailable"
                or type(metadata["files_count"]) is not int
                or not 0 <= metadata["files_count"] <= 1_000_000_000
                or not isinstance(metadata["files"], list)
                or len(metadata["files"]) != min(metadata["files_count"], MAX_COVERAGE_FILES)
                or any(not isinstance(p, str) or not p or len(p) > MAX_COVERAGE_PATH
                       for p in metadata["files"])):
            raise ValueError("invalid ESLint capture metadata")
        data = data["results"]
    if not isinstance(data, list):
        raise ValueError("invalid ESLint results")
    for row in data:
        if (not isinstance(row, dict) or not isinstance(row.get("filePath"), str)
                or not row["filePath"]
                or not isinstance(row.get("messages"), list)
                or type(row.get("fatalErrorCount", 0)) is not int
                or row.get("fatalErrorCount", 0) < 0):
            raise ValueError("invalid ESLint result")
        for msg in row["messages"]:
            if (not isinstance(msg, dict)
                    or not isinstance(msg.get("message"), str)
                    or (msg.get("ruleId") is not None and not isinstance(msg["ruleId"], str))
                    or ("fatal" in msg and type(msg["fatal"]) is not bool)):
                raise ValueError("invalid ESLint diagnostic")
    return data, metadata


def file_coverage(data):
    """Bounded coverage facts, independent of findings and scanner success."""
    rows, metadata = _capture(data)
    failed = [r for r in rows if r.get("fatalErrorCount", 0)
              or any(_fatal_message(m) for m in r["messages"])]
    unavailable = metadata["files_count"] if metadata else 0
    facts = [{"file": _safe_path(r["filePath"]), "reason": "parse_error"}
             for r in failed[:MAX_COVERAGE_FILES]]
    if metadata:
        facts.extend({"file": _safe_path(p), "reason": "typescript_parser_unavailable"}
                     for p in metadata["files"][:MAX_COVERAGE_FILES - len(facts)])
    return {"status": "partial" if failed or metadata else "complete",
            "parsed_files": len(rows) - len(failed), "unparsed_files": len(failed),
            "unavailable_files": unavailable, "files": facts,
            "files_omitted": len(failed) + unavailable - len(facts),
            "capabilities_unavailable": ["typescript_parser"] if metadata else []}


def sanitize_capture(data):
    """Remove arbitrary parser text/source before raw artifacts are written.

    Keep native fatal indicators, so re-ingesting a sanitized legacy array
    yields the same file facts. Never repair malformed shapes into valid ones.
    """
    rows, _ = _capture(data)
    for row in rows:
        if row.get("fatalErrorCount", 0) or any(_fatal_message(m) for m in row["messages"]):
            for key in ("source", "output", "suppressedMessages"):
                row.pop(key, None)
            for msg in row["messages"]:
                if _fatal_message(msg) or msg.get("ruleId") is None:
                    fatal = _fatal_message(msg)
                    msg.clear()
                    msg.update(ruleId=None, fatal=fatal, message=("Parsing error: source unavailable"
                               if fatal else "ESLint diagnostic unavailable"))
    return data


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
        sources = self._lintable_sources(target)
        if not sources:
            return b"[]", 0
        # #run7: generate an eslint 9/10 flat config that imports the plugin by
        # explicit path (see _plugin_entry) and run it. The config lives in a
        # container-writable temp dir -- the /src mount is read-only, and a
        # config inside the tree is one the target could collide with. Only
        # the WORKING DIRECTORY is the target, for the reason below.
        ts_available = os.path.isfile(_TS_PARSER_ENTRY)
        missing = [p for p in sources if p.endswith((".ts", ".tsx"))] if not ts_available else []
        with scratch_cwd("eslint-cfg-") as cfg_dir:
            cfg_path = os.path.join(cfg_dir, "eslint.config.mjs")
            with open(cfg_path, "w", encoding="utf-8") as fh:
                fh.write(_flat_config(ts_available))
            # --config pins OUR generated config and --no-config-lookup stops
            # eslint from also discovering + EXECUTING the scanned target's own
            # eslint.config.js (arbitrary JS -> RCE). The plugin is imported by
            # ABSOLUTE path in that config, so no cwd- or NODE_PATH-relative
            # resolution can be hijacked by a hostile target node_modules
            # (#83/#715).
            abs_target = os.path.abspath(target)
            cmd = ["eslint", "--config", cfg_path, "--no-config-lookup",
                   "--format", "json", abs_target]
            # #1877 round 2: cwd IS the target, the second documented
            # exception after gosec and for the same KIND of reason -- the cwd
            # is a SCAN INPUT here, not a config-lookup surface. Under flat
            # config the `files`/`ignores` base path is the process cwd
            # whenever the config is named with `--config`, and
            # @eslint/config-array treats anything outside that base as
            # "external"; a config-object `basePath` narrows it but cannot
            # widen it back. Measured on the pinned eslint 10.9.0 with a real
            # container round: from a scratch cwd, NO output and exit 2
            # ("located outside of the base path") -- the whole JS/TS axis
            # lost, the #1452 "selected but unproduced" class. What the cwd
            # would otherwise buy an attacker is already closed above and does
            # not depend on it: --config + --no-config-lookup close the
            # config-execution vector, the plugin import is absolute, and flat
            # config takes no ignore RULES from `.eslintignore` (ESLint >= 9 is
            # documented to reject a present one, which is the same on main --
            # cwd or not, the file sits at the scan root). Recorded again, with
            # the argument, in tests/tools/test_adapter_cwd_confinement.py and
            # run_tools.DISPATCH_KEEPS_TARGET_CWD.
            if len(missing) == len(sources):
                raw, rc = b"[]", 0  # No supported source; adapter metadata discloses every gap.
            else:
                raw, rc = run_tool(cmd, timeout=300, ok_codes=(0, 1), cwd=abs_target)
            if not ts_available and rc in (0, 1):
                # A broken import/config still fails normally; never reinterpret
                # arbitrary initialization failure as a missing parser.
                results = parse_json_bytes(raw)
                _capture(results)
                raw = json.dumps({"panopticon_eslint": {
                    "version": 1, "typescript_parser": "unavailable",
                    "files": [_safe_path(os.path.relpath(p, target))
                              for p in sorted(missing)[:MAX_COVERAGE_FILES]],
                    "files_count": len(missing)}, "results": results}).encode()
            return raw, rc

    def parse(self, raw: bytes, group: str) -> list[dict]:
        return self.parse_with_file_coverage(raw, group)[0]

    def parse_with_file_coverage(self, raw: bytes, group: str) -> tuple[list[dict], dict]:
        document = parse_json_bytes(raw)
        data, _ = _capture(document)
        coverage = file_coverage(document)
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
        return out, coverage

    def _strip_prefix(self, path: str) -> str:
        return norm_uri(path)

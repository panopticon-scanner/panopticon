"""Adapter that preserves the existing SARIF ingestion for semgrep/bandit/etc."""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

from scripts import plan_contract
from scripts import semgrep_targets
from scripts.inert import surrogate_free
from scripts.tolerant_json import depth_checked
from . import sarif_utils as su
from .base import REDTEAM, STANDARD, inert_text, ingest_policy_cv, scratch_cwd
from .exec import run_tool


# Tools that produce SARIF output and are dispatched through this adapter.
# "eslint" retired (F-CAL-5): eslint >=9 requires a project flat config, so a
# bare invocation can never run on arbitrary targets; JS/TS SAST is the
# eslint-security adapter with its bundled config.
LEGACY_SARIF_TOOLS = {"semgrep", "bandit", "trivy", "gitleaks", "gosec"}

# Semgrep 1.177.0 embeds these defaults before it reads a target's
# `.semgrepignore`. Keep its administrative, generated and package-manager
# exclusions, but deliberately omit the four "Common test paths" entries:
# `test/`, `tests/`, `testsuite/` and `*_test.go`. The final entries cover
# Panopticon's own run/worktree/coordination roots and ordinary Python caches;
# `--no-git-ignore` would otherwise walk them when present below a target.
SEMGREP_SCANNER_EXCLUDES = (
    ".git", ".svn", "_darcs", "build/", "vendor/", "dist/", "*.min.js",
    ".env/", ".tox/", "node_modules/", ".npm/", ".yarn/", ".venv/",
    "_opam/", "_build/", "_cargo/", plan_contract.ARTIFACT_DIR + "/", ".worktrees/",
    ".superpowers/", "__pycache__/", ".ruff_cache/",
    ".pytest_cache/", ".mypy_cache/", "*.egg-info/", ".DS_Store",
)
SEMGREP_SCANNER_SCOPE_ARGS = [
    "--jobs=3",
    "--x-ignore-semgrepignore-files",
    "--no-git-ignore",
] + ["--exclude=%s" % pattern for pattern in SEMGREP_SCANNER_EXCLUDES]

# #2957: Semgrep's per-file limits, STATED rather than inherited. A rule that
# runs past the timeout on one file loses its findings there, and a file on
# which the threshold's worth of rules time out is abandoned for EVERY rule.
# Raising them only moves the file size a target needs (a 900 KB file still ran
# past 400 s with both off, beyond TOOL_TIMEOUT), so they stay at Semgrep's own
# defaults and every hit is disclosed as partial file coverage instead
# (`semgrep_file_coverage`). Not scope arguments: they do not change which
# files are scanned, so the scanner-scope baseline does not move.
# #3193: likewise the size limit. A file over it is skipped with no SARIF trace,
# so the host lists those files (`semgrep_targets`) and stamps the capture.
SEMGREP_RULE_TIMEOUT = 5
SEMGREP_TIMEOUT_THRESHOLD = 3
SEMGREP_MAX_TARGET_BYTES = 1_000_000
SEMGREP_LIMIT_ARGS = ["--timeout=%d" % SEMGREP_RULE_TIMEOUT,
                      "--timeout-threshold=%d" % SEMGREP_TIMEOUT_THRESHOLD,
                      "--max-target-bytes=%d" % SEMGREP_MAX_TARGET_BYTES]


def with_semgrep_excludes(tool, cmd, patterns):
    """Add disclosed Panopticon exclusions to Semgrep before its scan root."""
    if tool != "semgrep" or not patterns:
        return cmd
    at = cmd.index("/src")
    return cmd[:at] + ["--exclude=%s" % pattern for pattern in patterns] + cmd[at:]


# Per-tool argv producing SARIF on stdout. /src is substituted with the actual
# target path at invocation time.
TOOL_CMD = {
    # --disable-version-check is NOT covered by --metrics=off: they are two
    # separate calls home, and in a --network none container the version check
    # blocks until it times out. Measured on one trivial file: 2m10s with it,
    # 35s without.
    # The x-flag is internal, so the pin and the strict live-tool regression
    # travel together. It disables both the embedded defaults and every target
    # `.semgrepignore`; the explicit list above restores the non-test defaults.
    # `--no-git-ignore` independently stops a target `.gitignore` hiding
    # untracked review input. Neither file can now narrow the scanner silently.
    # NO --quiet (#3194): it removed the closing "Ran N rules on M files" line,
    # the only scanned-file signal Semgrep emits (its SARIF has none), so
    # #1335's noscan disposition could never fire. Without it stderr is a few
    # KB of summary, well inside the capture's retained tail.
    "semgrep": (["semgrep", "scan", "--config", "/opt/semgrep-rules", "--metrics=off",
                 "--disable-version-check"] + SEMGREP_SCANNER_SCOPE_ARGS
                + SEMGREP_LIMIT_ARGS + ["--sarif", "/src"]),
    # `--redact` is scanner-native redaction (#1639 P11): the one tool here
    # whose output is a list of other people's credentials masks them itself,
    # so the secret never leaves the container -- and it keeps every field
    # panopticon ingests. Read off the pinned version, gitleaks v8.18.4
    # (Dockerfile `ARG GITLEAKS_VERSION=8.18.4`):
    #   cmd/root.go   `rootCmd.PersistentFlags().Uint("redact", 0, "redact
    #                 secrets from logs and stdout. To redact only parts of the
    #                 secret just apply a percent value from 0..100...")` with
    #                 `rootCmd.Flag("redact").NoOptDefVal = "100"`, read back as
    #                 `detector.Redact, err = cmd.Flags().GetUint("redact")`.
    #                 PERSISTENT, so `detect` inherits it; the BARE form (no
    #                 `=value`) is what NoOptDefVal is for and is the spelling
    #                 that also survives a pin moved back to the older bool.
    #   report/finding.go  `func (f *Finding) Redact(percent uint)` rewrites
    #                 Line, Match and Secret and nothing else -- RuleID, File,
    #                 StartLine/EndLine, Tags and Fingerprint are untouched.
    #   report/sarif.go    maps Secret -> `region.snippet.text`, and RuleID/File
    #                 -> `ruleId`, `message.text`, `physicalLocation`; so the
    #                 masked field is exactly the snippet, and the rule and
    #                 location the tool axis reads come through intact.
    # Defence in depth, not a substitute: tool_capture._redact_capture still runs
    # over this capture like every other.
    "gitleaks": ["gitleaks", "detect", "--no-git", "--source", "/src", "--report-format", "sarif",
                 "--report-path", "/dev/stdout", "--no-banner", "--redact"],
    "trivy": ["trivy", "fs", "--skip-db-update", "--offline-scan", "--format", "sarif", "/src"],
    "bandit": ["bandit", "-q", "-r", "/src", "-s", "B101,B404,B110,B112", "-f", "sarif"],
    "gosec": ["gosec", "-fmt=sarif", "./..."],
}

# Max seconds to let a single tool invocation run before it's killed.
TOOL_TIMEOUT = 300

# Semgrep 1.179.0 names the file and rule of a timeout ONLY in this prose; the
# notification carries no `locations`. Its syntax-error notes likewise put the
# path (and sometimes the rule) only in prose. `.` stops at a newline, so a path
# that holds one does not match and is counted unlocated rather than misread.
_SEMGREP_TIMEOUT_TEXT = re.compile(r"\ATimeout when running (\S+) on (.+):\n ?\Z")
_SEMGREP_SYNTAX_TEXT = re.compile(
    r"\A(?:Syntax|Other syntax) error at line (.+):[0-9]+:\n")
_SEMGREP_SYNTAX_RULE = re.compile(
    r"\n When parsing a snippet [^\r\n]* for metavariable-pattern in rule "
    r"['`]([^'`\r\n]+)['`]")
_SEMGREP_SYNTAX_IDS = frozenset({"Syntax error", "Other syntax error"})
_SEMGREP_DISCLOSED_FILES = 100
_SEMGREP_DISCLOSED_RULES = 100


def _sarif_path(path):
    """A SARIF path in the findings' path space, at full identity (bounded only
    when published, so a shared long prefix cannot merge two files)."""
    return path.removeprefix("file://").removeprefix(su._TARGET_PREFIX).lstrip("/")


def _notifications(sarif):
    """Yield Semgrep execution notes, tolerating every malformed container."""
    runs = sarif.get("runs") if isinstance(sarif, dict) else None
    for run in runs if isinstance(runs, list) else []:
        invocations = run.get("invocations") if isinstance(run, dict) else None
        for invocation in invocations if isinstance(invocations, list) else []:
            notes = (invocation.get("toolExecutionNotifications")
                     if isinstance(invocation, dict) else None)
            yield from (notes if isinstance(notes, list) else [])


def _result_paths(sarif):
    """Paths that still produced at least one result in this capture."""
    located: set[str] = set()
    runs = sarif.get("runs") if isinstance(sarif, dict) else None
    for run in runs if isinstance(runs, list) else []:
        results = run.get("results") if isinstance(run, dict) else None
        for result in results if isinstance(results, list) else []:
            try:
                located.add(_sarif_path(result["locations"][0]["physicalLocation"]
                                        ["artifactLocation"]["uri"]))
            except (KeyError, IndexError, TypeError, AttributeError):
                pass
    return located


def _timeouts(sarif):
    """#2957: (per-file counts, per-file rules, unlocated, result paths).

    Only `toolExecutionNotifications` whose descriptor id is `Timeout` count;
    the `Missing plugin` notes every run carries are not coverage gaps here. A
    timeout whose file cannot be read off the message is counted unlocated, and
    its text is never published."""
    per_file: dict[str, int] = {}
    per_file_rules: dict[str, set[str]] = {}
    unlocated = 0
    for note in _notifications(sarif):
        descriptor = note.get("descriptor") if isinstance(note, dict) else None
        if not isinstance(descriptor, dict) or descriptor.get("id") != "Timeout":
            continue
        message = note.get("message")
        text = message.get("text") if isinstance(message, dict) else None
        match = _SEMGREP_TIMEOUT_TEXT.match(text) if isinstance(text, str) else None
        rule = match.group(1) if match else ""
        path = _sarif_path(match.group(2)) if match else ""
        if path:
            per_file[path] = per_file.get(path, 0) + 1
            per_file_rules.setdefault(path, set()).add(rule)
        else:
            unlocated += 1
    return per_file, per_file_rules, unlocated, _result_paths(sarif)


def _syntax_errors(sarif):
    """#3229: (per-file counts/rules, all-rule files, unlocated errors).

    `Syntax error` and `Other syntax error` both mean Semgrep could not apply
    its ordinary coverage to the named bytes. Some notes identify one
    metavariable-pattern rule; a note with no rule is a file-parser failure and
    therefore applies to every applicable rule. No diagnostic prose is ever
    published."""
    per_file: dict[str, int] = {}
    per_file_rules: dict[str, set[str]] = {}
    all_applicable: set[str] = set()
    unlocated = 0
    for note in _notifications(sarif):
        descriptor = note.get("descriptor") if isinstance(note, dict) else None
        if (not isinstance(descriptor, dict)
                or descriptor.get("id") not in _SEMGREP_SYNTAX_IDS):
            continue
        message = note.get("message")
        text = message.get("text") if isinstance(message, dict) else None
        if not isinstance(text, str):
            unlocated += 1
            continue
        match = _SEMGREP_SYNTAX_TEXT.match(text)
        path = _sarif_path(match.group(1)) if match else ""
        if not path:
            unlocated += 1
            continue
        per_file[path] = per_file.get(path, 0) + 1
        rule = _SEMGREP_SYNTAX_RULE.search(text)
        if rule:
            per_file_rules.setdefault(path, set()).add(rule.group(1))
        else:
            all_applicable.add(path)
    return per_file, per_file_rules, all_applicable, unlocated


def _published_rules(rules):
    """A bounded, inert rule-id list plus the count that did not fit."""
    ordered = sorted(rules)
    published = [inert_text(rule, limit=239) for rule in
                 ordered[:_SEMGREP_DISCLOSED_RULES]]
    return published, max(0, len(ordered) - len(published))


def _disclose_semgrep_rows(rows, omitted):
    """Name each bounded file/rule gap without printing scanner prose."""
    for row in rows:
        detail = []
        if row.get("rule_timeouts"):
            detail.append("%d rule timeout(s)" % row["rule_timeouts"])
        if row.get("syntax_errors"):
            detail.append("%d syntax error(s)" % row["syntax_errors"])
        if row.get("reason") == "size_skipped" or row.get("size_skipped"):
            detail.append("over the size limit")
        if row.get("rules"):
            detail.append("rules: %s" % ", ".join(row["rules"]))
        if row.get("rule_scope") == "all_applicable":
            detail.append("all applicable rules")
        if row.get("rules_omitted"):
            detail.append("%d additional rule(s) omitted" % row["rules_omitted"])
        print("semgrep: partial file coverage: %s: %s"
              % (row["file"], "; ".join(detail)), file=sys.stderr)
    if omitted:
        print("semgrep: partial file coverage: %d additional file(s) omitted"
              % omitted, file=sys.stderr)


def _size_listing(sarif):
    """#3193: (files, count, limit, state) from the host's capture stamp.

    `state` is "listed" only for a well-formed, complete listing. A capture with
    NO stamp is "absent" and reads exactly like a malformed one (coordinator
    ruling): no stamp never means nothing was skipped."""
    try:
        listing = sarif["runs"][0]["properties"][semgrep_targets.STAMP_KEY]
    except (KeyError, IndexError, TypeError):
        return [], 0, None, "absent"
    if not (isinstance(listing, dict) and type(listing.get("limit")) is int
            and type(listing.get("count")) is int and type(listing.get("complete")) is bool
            and isinstance(listing.get("files"), list)
            and all(isinstance(f, str) and f for f in listing["files"])
            and len(listing["files"]) <= listing["count"]):
        return [], 0, None, "malformed"
    return (listing["files"], listing["count"], listing["limit"],
            "listed" if listing["complete"] else "incomplete")


def semgrep_file_coverage(sarif):
    """Semgrep's file gaps as partial file coverage, or None when it has none.

    #2957: a file with SEMGREP_TIMEOUT_THRESHOLD or more rule timeouts was
    abandoned (no rule's findings from it survive); fewer means those rules'
    findings are missing. #3229: either syntax-error descriptor means the
    named file/rule was not fully parsed. #3193: a file over the size limit was
    never read. A size listing that is absent, malformed or cut short is one
    unlocated gap."""
    per_file, timeout_rules, timeouts_unlocated, located = _timeouts(sarif)
    syntax, syntax_rules, syntax_all, syntax_unlocated = _syntax_errors(sarif)
    sized, size_count, limit, state = _size_listing(sarif)
    unlocated = timeouts_unlocated + syntax_unlocated + (state != "listed")
    if not per_file and not syntax and not unlocated and not size_count:
        return None
    timeouts = sum(per_file.values()) + timeouts_unlocated
    syntax_count = sum(syntax.values()) + syntax_unlocated
    if timeouts:
        print("semgrep: partial file coverage: %d rule timeout(s) on %d file(s), %d "
              "without an identifiable file; usable findings retained"
              % (timeouts, len(per_file), timeouts_unlocated), file=sys.stderr)
    if syntax_count:
        print("semgrep: partial file coverage: %d syntax error(s) on %d file(s), %d "
              "without an identifiable file; usable findings retained"
              % (syntax_count, len(syntax), syntax_unlocated), file=sys.stderr)
    if size_count or state != "listed":
        print("semgrep: partial file coverage: %d file(s) over the size limit not "
              "scanned (listing %s)" % (size_count, state), file=sys.stderr)
    facts_by_path: dict[str, dict[str, object]] = {}
    for path in set(per_file) | set(syntax):
        timed_out, failed_parse = per_file.get(path, 0), syntax.get(path, 0)
        reason = ("rule_timeout_and_syntax_error" if timed_out and failed_parse
                  else "syntax_error" if failed_parse
                  else "timeout_abandoned" if timed_out >= SEMGREP_TIMEOUT_THRESHOLD
                  else "rule_timeout")
        facts: dict[str, object] = {"reason": reason}
        if timed_out:
            facts["rule_timeouts"] = timed_out
        if failed_parse:
            facts["syntax_errors"] = failed_parse
        rules, rules_omitted = _published_rules(
            timeout_rules.get(path, set()) | syntax_rules.get(path, set()))
        facts.update({"rules": rules, "rules_omitted": rules_omitted})
        if path in syntax_all:
            facts["rule_scope"] = "all_applicable"
        facts_by_path[path] = facts
    for path in sized:
        if path in facts_by_path:
            facts_by_path[path]["reason"] = "multiple_gaps"
            facts_by_path[path]["size_skipped"] = True
        else:
            facts_by_path[path] = {"reason": "size_skipped"}
    rows = [(path, facts_by_path[path]) for path in sorted(facts_by_path)]
    known_size_files = len(set(sized))
    unparsed = len(facts_by_path) + max(0, size_count - known_size_files)
    published_rows = [dict(file=inert_text(path, limit=239, mode="path"), **facts)
                      for path, facts in rows[:_SEMGREP_DISCLOSED_FILES]]
    files_omitted = max(0, unparsed - len(published_rows))
    _disclose_semgrep_rows(published_rows, files_omitted)
    return {
        "status": "partial",
        "parsed_files": len(located - set(facts_by_path)),
        "unparsed_files": unparsed, "unavailable_files": 0,
        "files": published_rows,
        "files_omitted": files_omitted,
        "capabilities_unavailable": [],
        "rule_timeouts": timeouts, "syntax_errors": syntax_count,
        "size_skipped": size_count, "size_limit": limit,
        "size_listing": state, "unlocated_records": unlocated,
    }


class LegacySarifAdapter:
    # `_run_adapter.py` hands `invoke` the run's `--security` mode only to the
    # adapters that declare they read it (#1839). Gitleaks is the one tool on
    # this path whose argv is built HERE rather than by the dispatcher, so the
    # mode has to cross the container boundary to reach it.
    reads_security_mode = True

    def __init__(self, name: str):
        self.name = name

    @property
    def prefix(self) -> str:
        return su.PREFIX.get(self.name, "TL")

    def is_applicable(self, target: str) -> bool:
        return True

    def invoke(self, target: str,
               security_mode: str = STANDARD) -> tuple[bytes, int]:
        """Run the legacy SARIF tool against target and return its raw output.

        `security_mode` (#1839) decides one thing here: whether gitleaks still
        honours a `gitleaks:allow` comment in the target's own source.
        """
        if self.name not in TOOL_CMD:
            raise NotImplementedError(f"no command defined for tool {self.name}")
        cmd = [target if arg == "/src" else arg for arg in TOOL_CMD[self.name]]
        # Most security scanners exit 1 when findings are present; run_tool
        # treats (0, 1) as clean and logs a stderr excerpt on anything else.
        if self.name == "gosec":
            # gosec scans relative to the working directory: its argv is the
            # CWD-RELATIVE go package pattern `./...`, so the module root is
            # the cwd by necessity. The one documented exception (#1877);
            # see tests/tools/test_adapter_cwd_confinement.py for why that is
            # acceptable for this tool and no other.
            return run_tool(cmd, timeout=TOOL_TIMEOUT, cwd=target)
        # #1877: every other tool here names its scan root on argv (semgrep,
        # trivy, bandit positionally; gitleaks via `--source`), so the cwd is
        # a scratch, so cwd-relative scanner configuration comes from there.
        with scratch_cwd("%s-cwd-" % self.name) as cwd:
            if self.name == "gitleaks":
                # An explicit scanner-owned config wins over a target's
                # .gitleaks.toml (and GITLEAKS_CONFIG). Extend all built-ins.
                config = Path(cwd) / "gitleaks.toml"
                config.write_bytes(b"[extend]\nuseDefault = true\n")
                cmd.extend(("--config", str(config)))
                # The host dispatcher handles the source-root `.gitleaksignore`:
                # redteam mounts a scanner-owned empty file over a safe existing
                # file. At v8.18.4 an explicit empty ignore-path does not stop
                # the binary's unconditional source-root read (#1957), so this
                # adapter must keep the source path and config behavior intact.
                if security_mode == REDTEAM:
                    # An inline `gitleaks:allow` comment is in the target's
                    # SOURCE, not its config. `standard` is an operator scanning
                    # their own repository, so it stands there, DISCLOSED on the
                    # manifest (`suppression_comments`); this repository's own CI
                    # (`security.yml` and the fork-PR `security-fork.yml`) scans
                    # in `redteam`, so nothing target-authored is honoured on
                    # either check. Under redteam the tree is untrusted and a
                    # comment may not silence a finding.
                    cmd.append("--ignore-gitleaks-allow")
            return run_tool(cmd, timeout=TOOL_TIMEOUT, cwd=cwd)

    def parse(self, raw: bytes, group: str) -> list[dict]:
        return self.parse_with_file_coverage(raw, group)[0]

    def parse_with_file_coverage(self, raw: bytes, group: str) -> tuple[list[dict], dict | None]:
        """The findings, plus Semgrep's file gaps (#2957 timeouts, #3193 size
        skips, #3229 syntax errors); None for other tools and gapless Semgrep."""
        sarif = surrogate_free(json.loads(depth_checked(raw)))    # #2951, #2959: as `parse_json_bytes`
        # #1839: the INGEST decides whether an inline suppression comment in
        # the scanned tree's own source stands, because the pinned scanners
        # report a suppressed result either way (semgrep marks it
        # `suppressions: [{"kind": "inSource"}]` with or without
        # `--disable-nosem`). `parse` takes no policy argument, so the mode
        # arrives the way the scanned root does -- a ContextVar the ingest
        # sets around this call -- and is handed to the converter EXPLICITLY,
        # so that function stays directly testable in both modes.
        policy = ingest_policy_cv.get() or {}
        findings = su.sarif_to_findings(
            sarif, self.name, group, self.prefix,
            security_mode=policy.get("security_mode"),
            suppressed_in_source=policy.get("suppressed_in_source"))
        return findings, (semgrep_file_coverage(sarif) if self.name == "semgrep" else None)

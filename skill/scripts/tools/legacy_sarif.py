"""Adapter that preserves the existing SARIF ingestion for semgrep/bandit/etc."""
from __future__ import annotations
import json
from pathlib import Path

from . import sarif_utils as su
from .base import (REDTEAM, STANDARD, ingest_policy_cv, run_tool,
                   scratch_cwd)


# Tools that produce SARIF output and are dispatched through this adapter.
# "eslint" retired (F-CAL-5): eslint >=9 requires a project flat config, so a
# bare invocation can never run on arbitrary targets; JS/TS SAST is the
# eslint-security adapter with its bundled config.
LEGACY_SARIF_TOOLS = {"semgrep", "bandit", "trivy", "gitleaks", "gosec"}

# Per-tool argv producing SARIF on stdout. /src is substituted with the actual
# target path at invocation time.
TOOL_CMD = {
    # --disable-version-check is NOT covered by --metrics=off: they are two
    # separate calls home, and in a --network none container the version check
    # blocks until it times out. Measured on one trivial file: 2m10s with it,
    # 35s without.
    "semgrep": ["semgrep", "scan", "--config", "/opt/semgrep-rules", "--metrics=off",
                "--disable-version-check", "--sarif", "--quiet", "/src"],
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
        sarif = json.loads(raw)
        # #1839: the INGEST decides whether an inline suppression comment in
        # the scanned tree's own source stands, because the pinned scanners
        # report a suppressed result either way (semgrep marks it
        # `suppressions: [{"kind": "inSource"}]` with or without
        # `--disable-nosem`). `parse` takes no policy argument, so the mode
        # arrives the way the scanned root does -- a ContextVar the ingest
        # sets around this call -- and is handed to the converter EXPLICITLY,
        # so that function stays directly testable in both modes.
        policy = ingest_policy_cv.get() or {}
        return su.sarif_to_findings(
            sarif, self.name, group, self.prefix,
            security_mode=policy.get("security_mode"),
            suppressed_in_source=policy.get("suppressed_in_source"))

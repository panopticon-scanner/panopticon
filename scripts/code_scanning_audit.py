#!/usr/bin/env python3
"""Fail closed unless current main has complete analyses and zero open alerts.

This is the post-merge half of the repository's code-scanning policy.  It reads
GitHub state only; it does not upload, dismiss, or otherwise mutate alerts.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import re
import subprocess
import sys
import time
from typing import Callable
from urllib.parse import urlsplit
import uuid

import triage


MAIN_REF = "refs/heads/main"
SECURITY_ANALYSIS_KEY = ".github/workflows/security.yml:scan"
SECURITY_TOOLS = frozenset({"Bandit", "Gitleaks", "Semgrep OSS", "Trivy"})
CODEQL_ANALYSIS_KEY = ".github/workflows/codeql.yml:analyze"
CODEQL_CATEGORY = "/language:python"
# One bound for both asynchronous-ingestion waits (Security analyses,
# CodeQL): the same GitHub pipeline is what either check is waiting on.
POLL_ATTEMPTS = 6
POLL_DELAY_SECONDS = 10
PER_PAGE = 100
MAX_ALERT_PAGES = 1000
MAX_RESPONSE_CHARS = 5 * 1024 * 1024

_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")


class AuditError(RuntimeError):
    """The audit could not prove a clean, complete current-main state."""


@dataclass(frozen=True)
class Target:
    repository: str
    server_url: str
    hostname: str
    ref: str
    sha: str
    security_sarif_id: str


def _repository(value: str) -> str:
    parts = value.split("/") if isinstance(value, str) else []
    if (len(parts) != 2 or any(not _NAME.fullmatch(part) for part in parts)
            or any(part in {".", ".."} for part in parts)):
        raise AuditError("repository must be one validated owner/repository pair")
    return value


def _server(value: str) -> tuple[str, str]:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        raise AuditError("server URL is malformed") from None
    if (parsed.scheme != "https" or parsed.hostname is None
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or parsed.hostname.lower() != "github.com" or port not in (None, 443)):
        raise AuditError("server URL must identify trusted https://github.com")
    hostname = parsed.hostname.lower()
    return "https://" + hostname, hostname


def _full_sha(value: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise AuditError("commit SHA must be a full lowercase 40-hex ID")
    return value


def _sarif_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuditError("%s SARIF upload ID is missing" % label)
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise AuditError("%s SARIF upload ID is malformed" % label) from None
    canonical = str(parsed)
    if value != canonical:
        raise AuditError("%s SARIF upload ID is not canonical" % label)
    return canonical


def validate_target(repository: str, server_url: str, ref: str, sha: str,
                    security_sarif_id: str) -> Target:
    repository = _repository(repository)
    server_url, hostname = _server(server_url)
    if ref != MAIN_REF:
        raise AuditError("audit ref must be refs/heads/main")
    return Target(repository, server_url, hostname, ref, _full_sha(sha),
                  _sarif_id(security_sarif_id, "Security"))


class GitHubReader:
    """Small fixed-host JSON reader over the repository's hardened gh runner."""

    def __init__(self, target: Target, runner: Callable[..., object]):
        self.target = target
        self.runner = runner

    def get(self, endpoint: str, label: str,
            params: tuple[tuple[str, object], ...] = ()) -> object:
        argv = [
            "gh", "api", "--hostname", self.target.hostname,
            "--method", "GET",
            "-H", "Accept: application/vnd.github+json",
            "-H", "X-GitHub-Api-Version: 2022-11-28",
            endpoint,
        ]
        for key, value in params:
            argv.extend(["-f", "%s=%s" % (key, value)])
        try:
            result = self.runner(argv, capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            raise AuditError("GitHub API request timed out for %s" % label) from None
        except (OSError, RuntimeError):
            raise AuditError("GitHub API request could not start for %s" % label) from None
        if getattr(result, "returncode", None) != 0:
            # stderr can contain response bodies or scanner-controlled strings.
            raise AuditError("GitHub API request failed for %s" % label)
        raw = getattr(result, "stdout", None)
        if not isinstance(raw, str) or not raw.strip():
            raise AuditError("GitHub API returned no JSON for %s" % label)
        if len(raw) > MAX_RESPONSE_CHARS:
            raise AuditError("GitHub API response exceeded the bound for %s" % label)
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            raise AuditError("GitHub API returned malformed JSON for %s" % label) from None


class MainAudit:
    def __init__(self, target: Target, runner: Callable[..., object],
                 sleep: Callable[[float], None] = time.sleep,
                 output: Callable[[str], None] = print,
                 poll_attempts: int = POLL_ATTEMPTS,
                 poll_delay: float = POLL_DELAY_SECONDS):
        if poll_attempts < 1 or poll_delay < 0:
            raise ValueError("invalid polling bound")
        self.target = target
        self.api = GitHubReader(target, runner)
        self.sleep = sleep
        self.output = output
        self.poll_attempts = poll_attempts
        self.poll_delay = poll_delay
        self.base = "repos/%s" % target.repository

    def _head_sha(self, label: str) -> str:
        data = self.api.get(self.base + "/git/ref/heads/main", label)
        if not isinstance(data, dict) or not isinstance(data.get("object"), dict):
            raise AuditError("GitHub API returned a malformed main ref")
        sha = data["object"].get("sha")
        if not isinstance(sha, str) or not _SHA.fullmatch(sha):
            raise AuditError("GitHub API returned a malformed main ref SHA")
        return sha

    def _require_current_head(self, label: str) -> None:
        if self._head_sha(label) != self.target.sha:
            raise AuditError("main moved; this audit is superseded and incomplete")

    def _upload_status(self, sarif_id: str, label: str,
                       pending_ok: bool = False) -> str:
        data = self.api.get(
            self.base + "/code-scanning/sarifs/" + sarif_id,
            "%s SARIF status" % label,
        )
        if not isinstance(data, dict):
            raise AuditError("GitHub API returned malformed %s SARIF status" % label)
        errors = data.get("errors")
        if errors not in (None, []):
            raise AuditError("%s SARIF upload reports processing errors" % label)
        status = data.get("processing_status")
        if status == "complete":
            return status
        if status == "pending" and pending_ok:
            return status
        if status in {"pending", "failed"}:
            raise AuditError("%s SARIF upload is %s" % (label, status))
        raise AuditError("GitHub API returned malformed %s SARIF status" % label)

    @staticmethod
    def _environment(row: dict[str, object], label: str) -> dict[str, object]:
        raw = row.get("environment")
        if not isinstance(raw, str):
            raise AuditError("%s analysis environment is malformed" % label)
        try:
            environment = json.loads(raw)
        except ValueError:
            raise AuditError("%s analysis environment is malformed" % label) from None
        if not isinstance(environment, dict):
            raise AuditError("%s analysis environment is malformed" % label)
        return environment

    def _validate_analysis(self, row: object, *, label: str, tool_name: str,
                           sarif_id: str, analysis_key: str, category: str,
                           environment: dict[str, object]) -> dict[str, object]:
        if not isinstance(row, dict):
            raise AuditError("%s analysis row is malformed" % label)
        tool = row.get("tool")
        if not isinstance(tool, dict) or tool.get("name") != tool_name:
            raise AuditError("%s analysis tool identity is wrong" % label)
        expected = {
            "sarif_id": sarif_id,
            "ref": self.target.ref,
            "commit_sha": self.target.sha,
            "analysis_key": analysis_key,
            "category": category,
            "error": "",
            "warning": "",
        }
        for key, value in expected.items():
            if row.get(key) != value:
                raise AuditError("%s analysis %s is wrong or incomplete" % (label, key))
        if self._environment(row, label) != environment:
            raise AuditError("%s analysis environment is wrong" % label)
        return row

    def _security_analyses(self) -> None:
        rows = self.api.get(
            self.base + "/code-scanning/analyses",
            "Security analyses",
            (("sarif_id", self.target.security_sarif_id),
             ("per_page", PER_PAGE)),
        )
        if not isinstance(rows, list):
            raise AuditError("GitHub API returned malformed Security analyses")
        if len(rows) != len(SECURITY_TOOLS):
            raise AuditError(
                "Security upload must contain exactly %d analyses" % len(SECURITY_TOOLS))
        seen: set[str] = set()
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("tool"), dict):
                raise AuditError("Security analysis row is malformed")
            tool = row["tool"].get("name")
            if not isinstance(tool, str) or tool not in SECURITY_TOOLS:
                raise AuditError("Security upload contains an unexpected tool")
            if tool in seen:
                raise AuditError("Security upload contains a duplicate tool")
            seen.add(tool)
            self._validate_analysis(
                row, label=tool, tool_name=tool,
                sarif_id=self.target.security_sarif_id,
                analysis_key=SECURITY_ANALYSIS_KEY,
                category=SECURITY_ANALYSIS_KEY,
                environment={},
            )
        if seen != SECURITY_TOOLS:
            raise AuditError("Security upload is missing an expected tool")

    def _codeql(self) -> None:
        last_pending = "CodeQL analysis is not available"
        for attempt in range(self.poll_attempts):
            rows = self.api.get(
                self.base + "/code-scanning/analyses",
                "CodeQL analysis",
                (("ref", self.target.ref), ("tool_name", "CodeQL"),
                 ("sort", "created"), ("direction", "desc"),
                 ("per_page", 1)),
            )
            if not isinstance(rows, list) or len(rows) > 1:
                raise AuditError("GitHub API returned malformed CodeQL analyses")
            if not rows:
                self._require_current_head("main ref during CodeQL wait")
                last_pending = "CodeQL analysis is not available"
            else:
                row = rows[0]
                if not isinstance(row, dict) or not isinstance(row.get("commit_sha"), str):
                    raise AuditError("CodeQL analysis row is malformed")
                if row["commit_sha"] != self.target.sha:
                    self._require_current_head("main ref during CodeQL wait")
                    last_pending = "CodeQL analysis is not current"
                else:
                    codeql_sarif_id = _sarif_id(row.get("sarif_id"), "CodeQL")
                    self._validate_analysis(
                        row, label="CodeQL", tool_name="CodeQL",
                        sarif_id=codeql_sarif_id,
                        analysis_key=CODEQL_ANALYSIS_KEY,
                        category=CODEQL_CATEGORY,
                        environment={"language": "python"},
                    )
                    status = self._upload_status(
                        codeql_sarif_id, "CodeQL", pending_ok=True)
                    if status == "complete":
                        return
                    self._require_current_head("main ref during CodeQL wait")
                    last_pending = "CodeQL SARIF upload is pending"
            if attempt + 1 < self.poll_attempts:
                self.sleep(self.poll_delay)
        raise AuditError("%s after %d attempts" %
                         (last_pending, self.poll_attempts))

    @staticmethod
    def _display(value: object, label: str, limit: int = 200) -> str:
        if not isinstance(value, str) or not value:
            raise AuditError("open alert %s is malformed" % label)
        clean = "".join(ch if ch.isprintable() and ch not in "\r\n\t" else "?"
                        for ch in value)
        return clean[:limit]

    def _alert_summary(self, row: object) -> tuple[int, str]:
        if not isinstance(row, dict):
            raise AuditError("open alert row is malformed")
        number = row.get("number")
        if isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise AuditError("open alert number is malformed")
        if row.get("state") != "open":
            raise AuditError("open-alert query returned a non-open alert")
        instance = row.get("most_recent_instance")
        if not isinstance(instance, dict):
            raise AuditError("open alert instance is malformed")
        if (instance.get("ref") != self.target.ref
                or instance.get("commit_sha") != self.target.sha):
            raise AuditError("open alert instance is stale for the audited main SHA")
        tool = row.get("tool")
        rule = row.get("rule")
        location = instance.get("location")
        if not isinstance(tool, dict) or not isinstance(rule, dict):
            raise AuditError("open alert identity is malformed")
        if not isinstance(location, dict):
            raise AuditError("open alert location is malformed")
        start_line = location.get("start_line")
        if (isinstance(start_line, bool) or not isinstance(start_line, int)
                or start_line < 1):
            raise AuditError("open alert location is malformed")
        tool_name = self._display(tool.get("name"), "tool")
        rule_id = self._display(rule.get("id"), "rule")
        level = self._display(rule.get("severity"), "level")
        path = self._display(location.get("path"), "path", limit=500)
        link = "%s/%s/security/code-scanning/%d" % (
            self.target.server_url, self.target.repository, number)
        return number, "#%d %s | %s | %s | %s:%d | %s" % (
            number, tool_name, rule_id, level, path, start_line, link)

    def _alerts(self) -> list[str]:
        seen: set[int] = set()
        summaries: list[str] = []
        for page in range(1, MAX_ALERT_PAGES + 1):
            rows = self.api.get(
                self.base + "/code-scanning/alerts",
                "open alerts page %d" % page,
                (("state", "open"), ("ref", self.target.ref),
                 ("per_page", PER_PAGE), ("page", page)),
            )
            if not isinstance(rows, list) or len(rows) > PER_PAGE:
                raise AuditError("GitHub API returned malformed open alerts page %d" % page)
            for row in rows:
                number, summary = self._alert_summary(row)
                if number in seen:
                    raise AuditError("open-alert pagination returned a duplicate alert number")
                seen.add(number)
                summaries.append(summary)
            if len(rows) < PER_PAGE:
                return summaries
        raise AuditError("open-alert pagination exceeded the fail-closed page bound")

    def run(self) -> dict[str, int]:
        self._require_current_head("initial main ref")
        self._upload_status(self.target.security_sarif_id, "Security")
        self._security_analyses()
        self._codeql()
        alerts = self._alerts()
        self._require_current_head("final main ref")
        self.output("Validated complete code-scanning analyses: 5")
        self.output("Open code-scanning alerts on refs/heads/main: %d" % len(alerts))
        for summary in alerts:
            self.output(summary)
        if alerts:
            raise AuditError("%d open code-scanning alert(s) remain" % len(alerts))
        return {"analyses": 5, "open_alerts": 0}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--server-url", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--sarif-id", required=True,
                        help="singular sarif-id output from upload-sarif")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        target = validate_target(args.repository, args.server_url, args.ref,
                                 args.sha, args.sarif_id)
        MainAudit(target, triage.default_gh_runner()).run()
    except AuditError as exc:
        print("Code-scanning audit failed: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Split CI SARIF into actionable Security results and visible AI inventory."""

import argparse
import copy
import html
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any


INVENTORY_RULE_IDS = frozenset({
    "opt.semgrep-rules.ai.generic.detect-generic-ai-anthprop",
    "opt.semgrep-rules.ai.generic.detect-generic-ai-oai",
})
SARIF_LEVELS = frozenset({"none", "note", "warning", "error"})


class ReportError(ValueError):
    """The raw capture set cannot be split without losing information."""


def _object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReportError(f"{where} must be an object")
    return value


def _list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReportError(f"{where} must be an array")
    return value


def _rules_for(run: dict[str, Any], where: str) -> tuple[str, list[dict[str, Any]]]:
    tool = _object(run.get("tool"), f"{where}.tool")
    driver = _object(tool.get("driver"), f"{where}.tool.driver")
    driver_name = driver.get("name")
    if not isinstance(driver_name, str) or not driver_name:
        raise ReportError(f"{where}.tool.driver.name must be a non-empty string")
    raw_rules = driver.get("rules", [])
    rules = _list(raw_rules, f"{where}.tool.driver.rules")
    checked = []
    for index, value in enumerate(rules):
        rule = _object(value, f"{where}.tool.driver.rules[{index}]")
        rule_id = rule.get("id")
        if rule_id is not None and (not isinstance(rule_id, str) or not rule_id):
            raise ReportError(f"{where}.tool.driver.rules[{index}].id must be a non-empty string")
        default = rule.get("defaultConfiguration")
        if default is not None:
            default = _object(default, f"{where}.tool.driver.rules[{index}].defaultConfiguration")
            level = default.get("level")
            if level is not None and level not in SARIF_LEVELS:
                raise ReportError(
                    f"{where}.tool.driver.rules[{index}].defaultConfiguration.level "
                    "is not a SARIF level")
        properties = rule.get("properties")
        if properties is not None:
            _object(properties, f"{where}.tool.driver.rules[{index}].properties")
        checked.append(rule)
    return driver_name, checked


def _resolve_rule(result: dict[str, Any], rules: list[dict[str, Any]],
                  where: str) -> tuple[str | None, dict[str, Any] | None]:
    has_id = "ruleId" in result
    has_index = "ruleIndex" in result
    rule_id = result.get("ruleId")
    if has_id and (not isinstance(rule_id, str) or not rule_id):
        raise ReportError(f"{where}.ruleId must be a non-empty string")

    rule_index = result.get("ruleIndex")
    indexed_rule = None
    if has_index:
        if isinstance(rule_index, bool) or not isinstance(rule_index, int):
            raise ReportError(f"{where}.ruleIndex must be an integer")
        if rule_index < 0 or rule_index >= len(rules):
            raise ReportError(f"{where}.ruleIndex {rule_index} is outside the rule array")
        indexed_rule = rules[rule_index]
        indexed_id = indexed_rule.get("id")
        if has_id and indexed_id != rule_id:
            raise ReportError(
                f"{where} has inconsistent ruleId {rule_id!r} and ruleIndex {rule_index}")
        if not has_id:
            rule_id = indexed_id

    if indexed_rule is not None:
        return rule_id, indexed_rule
    if not has_id:
        return None, None

    matches = [rule for rule in rules if rule.get("id") == rule_id]
    if len(matches) > 1:
        raise ReportError(f"{where}.ruleId {rule_id!r} is ambiguous in the rule array")
    return rule_id, matches[0] if matches else None


def _effective_level(result: dict[str, Any], rule: dict[str, Any],
                     where: str) -> str:
    level = result.get("level")
    if level is not None:
        if level not in SARIF_LEVELS:
            raise ReportError(f"{where}.level is not a SARIF level")
        return level
    default = rule.get("defaultConfiguration") or {}
    return default.get("level", "warning")


def _security_marker(value: Any, key: str = "") -> bool:
    normalized_key = key.lower().replace("_", "-")
    if ("security" in normalized_key or "severity" in normalized_key or
            normalized_key in {"cwe", "owasp", "vulnerability", "vulnerabilities"}):
        return True
    if isinstance(value, dict):
        return any(_security_marker(item, str(item_key))
                   for item_key, item in value.items())
    if isinstance(value, list):
        return any(_security_marker(item, key) for item in value)
    if isinstance(value, str):
        lowered = value.lower()
        return ("cwe-" in lowered or "owasp" in lowered or
                "security" in lowered or "vulnerability" in lowered)
    return False


def _has_security_metadata(result: dict[str, Any], rule: dict[str, Any]) -> bool:
    return (_security_marker(rule.get("properties", {})) or
            _security_marker(result.get("properties", {})) or
            _security_marker(rule.get("relationships", [])))


def _is_semgrep(driver_name: str) -> bool:
    return driver_name.casefold().startswith("semgrep")


def _inventory_candidate(driver_name: str, rule_id: str | None,
                         result: dict[str, Any], rule: dict[str, Any] | None,
                         where: str) -> bool:
    if not _is_semgrep(driver_name) or rule_id not in INVENTORY_RULE_IDS or rule is None:
        return False
    return (_effective_level(result, rule, where) == "note" and
            not _has_security_metadata(result, rule))


def _split_document(document: Any, source: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    original = _object(document, source)
    runs = _list(original.get("runs"), f"{source}.runs")
    security = copy.deepcopy(original)
    inventory = []
    for run_index, value in enumerate(runs):
        where = f"{source}.runs[{run_index}]"
        run = _object(value, where)
        driver_name, rules = _rules_for(run, where)
        raw_results = run.get("results", [])
        results = _list(raw_results, f"{where}.results")
        actionable = []
        for result_index, value in enumerate(results):
            result_where = f"{where}.results[{result_index}]"
            result = _object(value, result_where)
            properties = result.get("properties")
            if properties is not None:
                _object(properties, f"{result_where}.properties")
            rule_id, rule = _resolve_rule(result, rules, result_where)
            if _inventory_candidate(driver_name, rule_id, result, rule, result_where):
                inventory.append({
                    "source": source,
                    "run_index": run_index,
                    "result_index": result_index,
                    "tool": driver_name,
                    "rule_id": rule_id,
                    "rule": copy.deepcopy(rule),
                    "result": copy.deepcopy(result),
                })
            else:
                actionable.append(copy.deepcopy(result))
        if len(actionable) != len(results):
            security["runs"][run_index]["results"] = actionable
    return security, inventory


def _markdown_text(value: Any) -> str:
    text = " ".join(str(value or "").split())
    escaped = html.escape(text, quote=False)
    for character in ("\\", "`", "|", "*", "_", "[", "]", "(", ")", "#", "!"):
        escaped = escaped.replace(character, f"&#{ord(character)};")
    return escaped


def _location(result: dict[str, Any]) -> str:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        return ""
    physical = locations[0].get("physicalLocation")
    if not isinstance(physical, dict):
        return ""
    artifact = physical.get("artifactLocation")
    region = physical.get("region")
    uri = artifact.get("uri", "") if isinstance(artifact, dict) else ""
    line = region.get("startLine") if isinstance(region, dict) else None
    return f"{uri}:{line}" if uri and isinstance(line, int) else str(uri)


def _render_markdown(rows: list[dict[str, Any]]) -> str:
    lines = ["## AI usage inventory", "", f"Authorized inventory results: **{len(rows)}**", ""]
    if not rows:
        lines.append("No authorized AI inventory results were found.")
        return "\n".join(lines) + "\n"
    lines.extend(["| Tool | Rule | Location | Message |",
                  "| --- | --- | --- | --- |"])
    for row in rows:
        result = row["result"]
        message = result.get("message")
        text = message.get("text", "") if isinstance(message, dict) else ""
        lines.append("| %s | `%s` | `%s` | %s |" % (
            _markdown_text(row["tool"]), _markdown_text(row["rule_id"]),
            _markdown_text(_location(result)), _markdown_text(text)))
    return "\n".join(lines) + "\n"


def prepare_reports(input_dir: str | os.PathLike[str],
                    output_dir: str | os.PathLike[str]) -> dict[str, Any]:
    source = Path(input_dir)
    destination = Path(output_dir)
    if not source.is_dir():
        raise ReportError(f"input directory does not exist: {source}")
    captures = sorted(source.glob("*.sarif"), key=lambda path: path.name)
    if not captures:
        raise ReportError(f"input directory contains no .sarif captures: {source}")
    if destination.exists():
        raise ReportError(f"output path already exists: {destination}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.",
                                    dir=destination.parent))
    try:
        security_dir = staging / "security"
        inventory_dir = staging / "inventory"
        security_dir.mkdir()
        inventory_dir.mkdir()
        inventory_rows = []
        for capture in captures:
            try:
                document = json.loads(capture.read_bytes())
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ReportError(f"cannot read {capture.name}: {exc}") from exc
            security, rows = _split_document(document, capture.name)
            inventory_rows.extend(rows)
            (security_dir / capture.name).write_text(
                json.dumps(security, indent=2, sort_keys=False) + "\n", encoding="utf-8")

        payload = {"version": 1, "count": len(inventory_rows),
                   "results": inventory_rows}
        (inventory_dir / "ai-inventory.json").write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        (inventory_dir / "ai-inventory.md").write_text(
            _render_markdown(inventory_rows), encoding="utf-8")
        os.replace(staging, destination)
        return payload
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True,
                        help="directory containing redacted raw .sarif captures")
    parser.add_argument("--output-dir", required=True,
                        help="new directory to atomically publish")
    args = parser.parse_args(argv)
    try:
        payload = prepare_reports(args.input_dir, args.output_dir)
    except (OSError, ReportError) as exc:
        print(f"code-scanning report preparation failed: {exc}", file=sys.stderr)
        return 1
    print(f"prepared Security SARIF and {payload['count']} AI inventory result(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

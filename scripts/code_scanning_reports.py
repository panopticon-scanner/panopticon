#!/usr/bin/env python3
"""Split CI SARIF into actionable Security results and visible AI inventory."""

import argparse
import copy
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from typing import Any, cast

import jsonschema


INVENTORY_RULE_IDS = frozenset({
    "opt.semgrep-rules.ai.generic.detect-generic-ai-anthprop",
    "opt.semgrep-rules.ai.generic.detect-generic-ai-oai",
})
SUPPORTED_SEMGREP_DRIVERS = frozenset({"Semgrep OSS"})
HARMLESS_RULE_PROPERTIES = {
    "precision": "very-high",
    "tags": ["LOW CONFIDENCE"],
}
SARIF_SCHEMA_SOURCE = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/"
    "sarif-schema-2.1.0.json")
SARIF_SCHEMA_SHA256 = "ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25"
SARIF_REFERENCE_DIR = Path(__file__).with_name("reference")
SARIF_SCHEMA_PATH = SARIF_REFERENCE_DIR / "sarif-schema-2.1.0.json"
SARIF_NOTICE_PATH = SARIF_REFERENCE_DIR / "SARIF-2.1.0-NOTICES.md"
_PLACEHOLDER = re.compile(r"(?<!\{)\{([0-9]+)\}(?!\})")


class ReportError(ValueError):
    """The raw capture set cannot be split without losing information."""


class _DuplicateKeyError(ValueError):
    pass


class _NonJSONConstantError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise _NonJSONConstantError


def _strict_json(raw: bytes, source: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except _DuplicateKeyError as exc:
        raise ReportError(f"{source}: duplicate object key in JSON") from exc
    except _NonJSONConstantError as exc:
        raise ReportError(f"{source}: non-JSON constant in JSON") from exc
    except UnicodeDecodeError as exc:
        raise ReportError(f"{source}: JSON is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ReportError(
            f"{source}: invalid JSON syntax at line {exc.lineno}, "
            f"column {exc.colno} ({exc.msg})") from exc


def _sarif_validator() -> jsonschema.Draft7Validator:
    try:
        raw = SARIF_SCHEMA_PATH.read_bytes()
    except OSError as exc:
        raise ReportError(
            f"local SARIF schema is unavailable: {SARIF_SCHEMA_PATH.name}") from exc
    if hashlib.sha256(raw).hexdigest() != SARIF_SCHEMA_SHA256:
        raise ReportError(
            f"local SARIF schema checksum mismatch: {SARIF_SCHEMA_PATH.name}")
    schema = _strict_json(raw, SARIF_SCHEMA_PATH.name)
    try:
        jsonschema.Draft7Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        raise ReportError("local SARIF schema is invalid") from exc
    return jsonschema.Draft7Validator(schema)


def _json_path(parts: Any) -> str:
    path = "$"
    for part in parts:
        if isinstance(part, int):
            path += f"[{part}]"
        elif isinstance(part, str) and part.isidentifier():
            path += f".{part}"
        else:
            path += "[" + json.dumps(str(part), ensure_ascii=True) + "]"
    return path


def _validate_sarif(validator: jsonschema.Draft7Validator,
                    document: Any, source: str) -> None:
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: tuple(f"{type(part).__name__}:{part}"
                                for part in error.absolute_path))
    if errors:
        error = errors[0]
        raise ReportError(
            f"{source}: SARIF schema validation failed at "
            f"{_json_path(error.absolute_path)} "
            f"(constraint: {error.validator}; {len(errors)} error(s))")


def _rules_for(run: dict[str, Any]) -> tuple[
        str, list[dict[str, Any]], dict[str, dict[str, Any]]]:
    driver = run["tool"]["driver"]
    return (driver["name"], driver.get("rules", []),
            driver.get("globalMessageStrings", {}))


def _resolve_rule(result: dict[str, Any], rules: list[dict[str, Any]],
                  where: str) -> tuple[str | None, dict[str, Any] | None]:
    has_id = "ruleId" in result
    has_index = "ruleIndex" in result
    rule_id = result.get("ruleId")
    rule_index = cast(int, result.get("ruleIndex", -1))
    indexed_rule = None
    if has_index and rule_index >= 0:
        if rule_index >= len(rules):
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
        return level
    default = rule.get("defaultConfiguration") or {}
    return default.get("level", "warning")


def _contains_unreviewed_metadata(value: Any, *, root_rule: bool = False,
                                  at_root: bool = True) -> bool:
    if isinstance(value, list):
        return any(_contains_unreviewed_metadata(item, at_root=False)
                   for item in value)
    if not isinstance(value, dict):
        return False
    for key, item in value.items():
        if key == "properties":
            if at_root and root_rule:
                if item != HARMLESS_RULE_PROPERTIES:
                    return True
            elif item:
                return True
        if key in {"taxa", "relationships"} and item:
            return True
        if _contains_unreviewed_metadata(item, at_root=False):
            return True
    return False


def _metadata_is_verified_harmless(result: dict[str, Any],
                                   rule: dict[str, Any],
                                   referenced_message: dict[str, Any] | None) -> bool:
    """Whether all candidate metadata has the exact reviewed inventory shape.

    Unknown metadata is valid input and remains actionable; it is not a report
    preparation error. Only the current Semgrep shape is authorized to leave
    Security. This covers CVE/CVSS/CWE/OWASP without relying on their spelling.
    """
    return (not _contains_unreviewed_metadata(rule, root_rule=True) and
            not _contains_unreviewed_metadata(result) and
            (referenced_message is None or
             not _contains_unreviewed_metadata(referenced_message)))


def _is_semgrep(driver_name: str) -> bool:
    return driver_name in SUPPORTED_SEMGREP_DRIVERS


def _inventory_candidate(driver_name: str, rule_id: str | None,
                         result: dict[str, Any], rule: dict[str, Any] | None,
                         where: str,
                         referenced_message: dict[str, Any] | None = None) -> bool:
    if rule is None:
        return False
    return (_inventory_scope_candidate(driver_name, rule_id, result, rule, where) and
            _metadata_is_verified_harmless(result, rule, referenced_message))


def _inventory_scope_candidate(driver_name: str, rule_id: str | None,
                               result: dict[str, Any],
                               rule: dict[str, Any] | None,
                               where: str) -> bool:
    if not _is_semgrep(driver_name) or rule_id not in INVENTORY_RULE_IDS or rule is None:
        return False
    return _effective_level(result, rule, where) == "note"


def _substitute_arguments(text: str, arguments: list[str]) -> str:
    def replace(match: re.Match[str]) -> str:
        index = int(match.group(1))
        return arguments[index] if index < len(arguments) else match.group(0)

    return _PLACEHOLDER.sub(replace, text).replace("{{", "{").replace("}}", "}")


def _resolved_message(result: dict[str, Any], rule: dict[str, Any],
                      global_messages: dict[str, dict[str, Any]],
                      where: str) -> tuple[dict[str, Any] | None, str]:
    message = result["message"]
    referenced = None
    if "id" in message:
        message_id = message["id"]
        referenced = rule.get("messageStrings", {}).get(message_id)
        if referenced is None:
            referenced = global_messages.get(message_id)
        if referenced is None:
            raise ReportError(
                f"{where}.message.id does not resolve in rule.messageStrings "
                "or driver.globalMessageStrings")
    display = message.get("text")
    if display is None:
        # The schema requires text on every multiformatMessageString.
        assert referenced is not None
        display = referenced["text"]
    return referenced, _substitute_arguments(display, message.get("arguments", []))


def _split_document(document: dict[str, Any],
                    source: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    original = document
    runs = original["runs"]
    security = copy.deepcopy(original)
    inventory = []
    for run_index, run in enumerate(runs):
        where = f"{source}.runs[{run_index}]"
        driver_name, rules, global_messages = _rules_for(run)
        results = run.get("results", [])
        actionable = []
        for result_index, result in enumerate(results):
            result_where = f"{where}.results[{result_index}]"
            rule_id, rule = _resolve_rule(result, rules, result_where)
            referenced_message = None
            display_message = None
            if _inventory_scope_candidate(
                    driver_name, rule_id, result, rule, result_where):
                assert rule is not None
                referenced_message, display_message = _resolved_message(
                    result, rule, global_messages, result_where)
            if _inventory_candidate(
                    driver_name, rule_id, result, rule, result_where,
                    referenced_message):
                inventory.append({
                    "source": source,
                    "run_index": run_index,
                    "result_index": result_index,
                    "tool": driver_name,
                    "rule_id": rule_id,
                    "rule": copy.deepcopy(rule),
                    "result": copy.deepcopy(result),
                    "display_message": display_message,
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
        text = row["display_message"]
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

    validator = _sarif_validator()

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
                raw = capture.read_bytes()
            except OSError as exc:
                raise ReportError(f"cannot read {capture.name}: {exc}") from exc
            document = _strict_json(raw, capture.name)
            _validate_sarif(validator, document, capture.name)
            security, rows = _split_document(document, capture.name)
            inventory_rows.extend(rows)
            (security_dir / capture.name).write_text(
                json.dumps(security, indent=2, sort_keys=False, allow_nan=False) + "\n",
                encoding="utf-8")

        payload = {"version": 1, "count": len(inventory_rows),
                   "results": inventory_rows}
        (inventory_dir / "ai-inventory.json").write_text(
            json.dumps(payload, indent=2, sort_keys=False, allow_nan=False) + "\n",
            encoding="utf-8")
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

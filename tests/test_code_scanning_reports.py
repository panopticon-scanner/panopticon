import copy
import hashlib
import json
import os
import subprocess
import sys

import pytest

from scripts import code_scanning_reports as reports


ANTHROPIC = "opt.semgrep-rules.ai.generic.detect-generic-ai-anthprop"
OPENAI = "opt.semgrep-rules.ai.generic.detect-generic-ai-oai"


def _rule(rule_id, level="note", properties=None):
    return {
        "id": rule_id,
        "name": rule_id,
        "defaultConfiguration": {"level": level},
        "properties": ({"precision": "very-high", "tags": ["LOW CONFIDENCE"]}
                       if properties is None else properties),
    }


def _result(rule_id=None, rule_index=None, level=None, path="src/app.py"):
    result = {
        "message": {"text": "observed SDK usage"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": 7},
        }}],
        "fingerprints": {"matchBasedId/v1": "stable-fingerprint"},
        "properties": {},
    }
    if rule_id is not None:
        result["ruleId"] = rule_id
    if rule_index is not None:
        result["ruleIndex"] = rule_index
    if level is not None:
        result["level"] = level
    return result


def _sarif(rules, results, driver="Semgrep OSS", run_properties=None,
           global_messages=None):
    driver_data = {"name": driver, "version": "1.2.3", "rules": rules}
    if global_messages is not None:
        driver_data["globalMessageStrings"] = global_messages
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": driver_data},
            "properties": run_properties or {"kept": ["byte", "for", "byte"]},
            "results": results,
        }],
    }


def _write(root, name, document):
    root.mkdir(exist_ok=True)
    path = root / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _prepare(tmp_path, documents):
    raw = tmp_path / "raw"
    raw.mkdir()
    before = {}
    for name, document in documents.items():
        path = _write(raw, name, document)
        before[name] = path.read_bytes()
    output = tmp_path / "reports"
    reports.prepare_reports(raw, output)
    return raw, output, before


def test_split_preserves_non_inventory_data_and_raw_inputs(tmp_path):
    rules = [_rule(ANTHROPIC), _rule("security.sql-injection", "error")]
    inventory = _result(ANTHROPIC, 0)
    actionable = _result("security.sql-injection", 1, "error", "src/db.py")
    document = _sarif(rules, [inventory, actionable],
                      run_properties={"automationDetails": "unchanged"})
    raw, output, before = _prepare(tmp_path, {
        "semgrep.sarif": document,
        "bandit.sarif": _sarif([_rule(ANTHROPIC)], [_result(ANTHROPIC, 0)],
                                driver="Bandit"),
    })

    security_semgrep = json.loads((output / "security" / "semgrep.sarif").read_text())
    expected = copy.deepcopy(document)
    expected["runs"][0]["results"] = [actionable]
    assert security_semgrep == expected
    assert json.loads((output / "security" / "bandit.sarif").read_text()) == json.loads(
        (raw / "bandit.sarif").read_text())
    assert {p.name: p.read_bytes() for p in raw.iterdir()} == before

    inventory_report = json.loads(
        (output / "inventory" / "ai-inventory.json").read_text())
    assert inventory_report["count"] == 1
    assert inventory_report["results"][0]["rule"] == rules[0]
    assert inventory_report["results"][0]["result"] == inventory
    markdown = (output / "inventory" / "ai-inventory.md").read_text()
    assert ANTHROPIC in markdown
    assert "src/app.py:7" in markdown


def test_both_exact_note_rules_route_and_inventory_only_run_survives(tmp_path):
    rules = [_rule(ANTHROPIC), _rule(OPENAI)]
    _raw, output, _before = _prepare(
        tmp_path, {"semgrep.sarif": _sarif(
            rules, [_result(ANTHROPIC), _result(None, 1)])})

    security = json.loads((output / "security" / "semgrep.sarif").read_text())
    assert len(security["runs"]) == 1
    assert security["runs"][0]["results"] == []
    assert security["runs"][0]["tool"]["driver"]["rules"] == rules
    inventory = json.loads((output / "inventory" / "ai-inventory.json").read_text())
    assert [row["rule_id"] for row in inventory["results"]] == [ANTHROPIC, OPENAI]


@pytest.mark.parametrize("result,rule,driver", [
    (_result("opt.semgrep-rules.ai.generic.detect-generic-ai-openai"),
     _rule("opt.semgrep-rules.ai.generic.detect-generic-ai-openai"), "Semgrep OSS"),
    (_result(ANTHROPIC, level="warning"), _rule(ANTHROPIC), "Semgrep OSS"),
    (_result(ANTHROPIC), _rule(ANTHROPIC, "error"), "Semgrep OSS"),
    (_result(ANTHROPIC), _rule(ANTHROPIC), "another-scanner"),
    (_result(ANTHROPIC), _rule(ANTHROPIC), "Semgrep Compatible"),
    (_result(ANTHROPIC), _rule(ANTHROPIC), "semgrep-wrapper"),
    (_result(ANTHROPIC), _rule(ANTHROPIC), "semgrep oss"),
    (_result(ANTHROPIC),
     _rule(ANTHROPIC, properties={"tags": ["LOW CONFIDENCE"],
                                  "security-severity": "8.0"}),
     "Semgrep OSS"),
])
def test_similar_elevated_other_scanner_and_security_metadata_stay_actionable(
        tmp_path, result, rule, driver):
    _raw, output, _before = _prepare(
        tmp_path, {"capture.sarif": _sarif([rule], [result], driver=driver)})
    security = json.loads((output / "security" / "capture.sarif").read_text())
    assert security["runs"][0]["results"] == [result]
    inventory = json.loads((output / "inventory" / "ai-inventory.json").read_text())
    assert inventory["count"] == 0


def test_rule_index_and_all_other_result_fields_are_preserved(tmp_path):
    rules = [_rule("security.first", "warning"), _rule(OPENAI)]
    inventory = _result(OPENAI, 1)
    inventory["stacks"] = [{"frames": [], "message": {"text": "keep me"}}]
    _raw, output, _before = _prepare(
        tmp_path, {"semgrep.sarif": _sarif(rules, [inventory])})
    row = json.loads((output / "inventory" / "ai-inventory.json").read_text())[
        "results"][0]
    assert row["result"] == inventory
    assert row["result"]["ruleIndex"] == 1


def test_security_metadata_on_the_result_stays_actionable(tmp_path):
    result = _result(ANTHROPIC)
    result["properties"] = {"security-severity": "7.5"}
    _raw, output, _before = _prepare(
        tmp_path, {"semgrep.sarif": _sarif([_rule(ANTHROPIC)], [result])})
    security = json.loads((output / "security" / "semgrep.sarif").read_text())
    assert security["runs"][0]["results"] == [result]
    assert json.loads((output / "inventory" / "ai-inventory.json").read_text())[
        "count"] == 0


@pytest.mark.parametrize("rule_update,result_update", [
    ({"properties": {"precision": "very-high",
                     "tags": ["LOW CONFIDENCE", "CVE-2026-1234"]}}, {}),
    ({"properties": {"precision": "very-high", "tags": ["LOW CONFIDENCE"],
                     "cvss": "3.1/AV:N/AC:L"}}, {}),
    ({"properties": {"precision": "very-high",
                     "tags": ["LOW CONFIDENCE", "OWASP-A03"]}}, {}),
    ({"relationships": [{"target": {"id": "CWE-79"}}]}, {}),
    ({"help": {"text": "help", "properties": {
        "futureSecurityMetadata": {"score": 9.8}}}}, {}),
    ({}, {"taxa": [{"id": "CWE-79", "index": 0}]}),
    ({}, {"properties": {"cve": "CVE-2026-1234"}}),
    ({}, {"message": {"text": "observed SDK usage",
                       "properties": {"cvss": "9.8"}}}),
])
def test_any_known_or_unknown_security_metadata_stays_actionable(
        tmp_path, rule_update, result_update):
    rule = _rule(ANTHROPIC)
    rule.update(rule_update)
    result = _result(ANTHROPIC)
    result.update(result_update)
    document = _sarif([rule], [result])
    _raw, output, _before = _prepare(
        tmp_path, {"semgrep.sarif": document})
    assert json.loads((output / "security" / "semgrep.sarif").read_text()) == document
    assert json.loads((output / "inventory" / "ai-inventory.json").read_text())[
        "count"] == 0


def test_explicitly_empty_taxa_and_relationships_are_harmless(tmp_path):
    rule = _rule(ANTHROPIC)
    rule["relationships"] = []
    result = _result(ANTHROPIC)
    result["taxa"] = []
    _raw, output, _before = _prepare(
        tmp_path, {"semgrep.sarif": _sarif([rule], [result])})
    security = json.loads((output / "security" / "semgrep.sarif").read_text())
    assert security["runs"][0]["results"] == []
    assert json.loads((output / "inventory" / "ai-inventory.json").read_text())[
        "count"] == 1


def test_nested_artifact_location_security_metadata_stays_actionable(tmp_path):
    result = _result(ANTHROPIC)
    result["locations"][0]["physicalLocation"]["artifactLocation"]["properties"] = {
        "cve": "CVE-2026-1234",
    }
    document = _sarif([_rule(ANTHROPIC)], [result])
    _raw, output, _before = _prepare(tmp_path, {"semgrep.sarif": document})
    assert json.loads((output / "security" / "semgrep.sarif").read_text()) == document
    assert json.loads((output / "inventory" / "ai-inventory.json").read_text())[
        "count"] == 0


def test_deep_stack_frame_metadata_stays_actionable(tmp_path):
    result = _result(ANTHROPIC)
    result["stacks"] = [{"frames": [{
        "location": {"physicalLocation": {
            "artifactLocation": {"uri": "src/deep.py"},
        }},
        "properties": {"future-classification": "security"},
    }]}]
    document = _sarif([_rule(ANTHROPIC)], [result])
    _raw, output, _before = _prepare(tmp_path, {"semgrep.sarif": document})
    assert json.loads((output / "security" / "semgrep.sarif").read_text()) == document


def test_empty_nested_property_bags_are_harmless(tmp_path):
    result = _result(ANTHROPIC)
    result["locations"][0]["physicalLocation"]["artifactLocation"]["properties"] = {}
    result["stacks"] = [{"frames": [{"properties": {}}]}]
    _raw, output, _before = _prepare(
        tmp_path, {"semgrep.sarif": _sarif([_rule(ANTHROPIC)], [result])})
    assert json.loads((output / "security" / "semgrep.sarif").read_text())[
        "runs"][0]["results"] == []


@pytest.mark.parametrize("document", [
    {"version": "2.1.0", "runs": "not-a-list"},
    _sarif([_rule(ANTHROPIC)], [_result(ANTHROPIC, 3)]),
    _sarif([_rule(ANTHROPIC), _rule(OPENAI)], [_result(ANTHROPIC, 1)]),
])
def test_malformed_or_inconsistent_sarif_fails_without_publishing(tmp_path, document):
    raw = tmp_path / "raw"
    _write(raw, "semgrep.sarif", document)
    output = tmp_path / "reports"
    with pytest.raises(reports.ReportError):
        reports.prepare_reports(raw, output)
    assert not output.exists()


@pytest.mark.parametrize("message", [
    None,
    {},
    {"text": 17},
    {"markdown": ""},
    {"id": "message-id", "arguments": ["ok", 17]},
    {"text": "valid text", "unknownMetadata": {}},
])
def test_malformed_inventory_candidate_message_fails_atomically(tmp_path, message):
    result = _result(ANTHROPIC)
    if message is None:
        del result["message"]
    else:
        result["message"] = message
    raw = tmp_path / "raw"
    _write(raw, "semgrep.sarif", _sarif([_rule(ANTHROPIC)], [result]))
    output = tmp_path / "reports"
    with pytest.raises(reports.ReportError, match="schema validation"):
        reports.prepare_reports(raw, output)
    assert not output.exists()


@pytest.mark.parametrize("message", [
    {"markdown": "**markdown alone is invalid**"},
    {"text": "bad location"},
])
def test_official_schema_rejects_malformed_candidates_atomically(
        tmp_path, message):
    result = _result(ANTHROPIC)
    result["message"] = message
    if "bad location" in message.get("text", ""):
        result["locations"] = "not-an-array"
    raw = tmp_path / "raw"
    _write(raw, "semgrep.sarif", _sarif([_rule(ANTHROPIC)], [result]))
    output = tmp_path / "reports"
    with pytest.raises(reports.ReportError) as caught:
        reports.prepare_reports(raw, output)
    error = str(caught.value)
    assert "semgrep.sarif" in error
    assert "$" in error
    assert "constraint" in error
    assert "not-an-array" not in error
    assert not output.exists()


@pytest.mark.parametrize("message,visible", [
    ({"text": "plain text"}, "plain text"),
    ({"text": "plain", "markdown": "**markdown**"}, "plain"),
    ({"id": "localized-message", "arguments": ["one", "two"]},
     "localized one two"),
])
def test_all_sarif_message_forms_route_and_render_consistently(
        tmp_path, message, visible):
    result = _result(ANTHROPIC)
    result["message"] = message
    rule = _rule(ANTHROPIC)
    if "id" in message:
        rule["messageStrings"] = {
            message["id"]: {"text": "localized {0} {1}"},
        }
    _raw, output, _before = _prepare(
        tmp_path, {"semgrep.sarif": _sarif([rule], [result])})
    assert json.loads((output / "security" / "semgrep.sarif").read_text())[
        "runs"][0]["results"] == []
    assert visible in (output / "inventory" / "ai-inventory.md").read_text()


def test_resolved_global_message_id_routes_without_mutating_result(tmp_path):
    result = _result(ANTHROPIC)
    result["message"] = {"id": "global-message", "arguments": ["SDK"]}
    original = copy.deepcopy(result)
    _raw, output, _before = _prepare(tmp_path, {"semgrep.sarif": _sarif(
        [_rule(ANTHROPIC)], [result],
        global_messages={"global-message": {"text": "Observed {0}"}})})
    row = json.loads((output / "inventory" / "ai-inventory.json").read_text())[
        "results"][0]
    assert row["result"] == original
    assert "Observed SDK" in (output / "inventory" / "ai-inventory.md").read_text()


def test_text_with_arguments_and_no_id_is_valid(tmp_path):
    result = _result(ANTHROPIC)
    result["message"] = {"text": "Observed SDK", "arguments": ["unused"]}
    _raw, output, _before = _prepare(
        tmp_path, {"semgrep.sarif": _sarif([_rule(ANTHROPIC)], [result])})
    assert json.loads((output / "security" / "semgrep.sarif").read_text())[
        "runs"][0]["results"] == []


@pytest.mark.parametrize("message_strings,global_strings", [
    (None, None),
    ({"different": {"text": "Different"}}, None),
])
def test_dangling_message_id_fails_atomically(
        tmp_path, message_strings, global_strings):
    rule = _rule(ANTHROPIC)
    if message_strings is not None:
        rule["messageStrings"] = message_strings
    result = _result(ANTHROPIC)
    result["message"] = {"id": "missing-message-string"}
    raw = tmp_path / "raw"
    _write(raw, "semgrep.sarif", _sarif(
        [rule], [result], global_messages=global_strings))
    output = tmp_path / "reports"
    with pytest.raises(reports.ReportError, match="message.id"):
        reports.prepare_reports(raw, output)
    assert not output.exists()


def test_malformed_referenced_message_string_fails_schema_validation(tmp_path):
    rule = _rule(ANTHROPIC)
    rule["messageStrings"] = {"bad": {"markdown": "missing required text"}}
    result = _result(ANTHROPIC)
    result["message"] = {"id": "bad"}
    raw = tmp_path / "raw"
    _write(raw, "semgrep.sarif", _sarif([rule], [result]))
    output = tmp_path / "reports"
    with pytest.raises(reports.ReportError, match="schema"):
        reports.prepare_reports(raw, output)
    assert not output.exists()


def test_missing_and_invalid_inputs_fail_visibly_without_publishing(tmp_path):
    output = tmp_path / "reports"
    with pytest.raises(reports.ReportError, match="does not exist"):
        reports.prepare_reports(tmp_path / "missing", output)
    assert not output.exists()

    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(reports.ReportError, match="no .sarif"):
        reports.prepare_reports(empty, output)
    assert not output.exists()

    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "broken.sarif").write_text("{broken", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, reports.__file__, "--input-dir", os.fspath(raw),
         "--output-dir", os.fspath(output)],
        capture_output=True, text=True, check=False,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    assert proc.returncode != 0
    assert "broken.sarif" in proc.stderr
    assert not output.exists()


@pytest.mark.parametrize("raw_json,problem", [
    ('{"version":"2.1.0","version":"2.1.0","runs":[]}', "duplicate object key"),
    ('{"version":"2.1.0","runs":[],"rank":NaN}', "non-JSON constant"),
    ('{"version":"2.1.0","runs":[],"rank":Infinity}', "non-JSON constant"),
])
def test_strict_json_rejects_duplicates_and_non_json_constants_atomically(
        tmp_path, raw_json, problem):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "malformed.sarif").write_text(raw_json, encoding="utf-8")
    output = tmp_path / "reports"
    with pytest.raises(reports.ReportError, match=problem) as caught:
        reports.prepare_reports(raw, output)
    assert "malformed.sarif" in str(caught.value)
    assert not output.exists()


def test_schema_is_the_unmodified_official_sarif_2_1_0_release():
    schema = reports.SARIF_SCHEMA_PATH.read_bytes()
    assert hashlib.sha256(schema).hexdigest() == reports.SARIF_SCHEMA_SHA256
    notice = reports.SARIF_NOTICE_PATH.read_text(encoding="utf-8")
    assert "Copyright © OASIS Open 2020" in notice
    assert "Notices" in notice
    assert reports.SARIF_SCHEMA_SOURCE in notice


def test_missing_or_modified_schema_fails_without_publishing(tmp_path, monkeypatch):
    raw = tmp_path / "raw"
    _write(raw, "semgrep.sarif", _sarif([_rule(ANTHROPIC)], [_result(ANTHROPIC)]))
    output = tmp_path / "reports"
    monkeypatch.setattr(reports, "SARIF_SCHEMA_PATH", tmp_path / "missing-schema.json")
    with pytest.raises(reports.ReportError, match="schema"):
        reports.prepare_reports(raw, output)
    assert not output.exists()

    modified = tmp_path / "modified-schema.json"
    modified.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(reports, "SARIF_SCHEMA_PATH", modified)
    with pytest.raises(reports.ReportError, match="checksum"):
        reports.prepare_reports(raw, output)
    assert not output.exists()


def test_failure_after_a_valid_capture_does_not_publish_partial_output(tmp_path):
    raw = tmp_path / "raw"
    _write(raw, "a-valid.sarif", _sarif([_rule(ANTHROPIC)], [_result(ANTHROPIC)]))
    (raw / "z-broken.sarif").write_text("{broken", encoding="utf-8")
    output = tmp_path / "reports"
    with pytest.raises(reports.ReportError, match="z-broken.sarif"):
        reports.prepare_reports(raw, output)
    assert not output.exists()


def test_unknown_exact_rule_id_stays_actionable_without_rule_metadata(tmp_path):
    document = _sarif([], [_result(ANTHROPIC)])
    _raw, output, _before = _prepare(
        tmp_path, {"semgrep.sarif": document})
    assert json.loads((output / "security" / "semgrep.sarif").read_text()) == document
    assert json.loads((output / "inventory" / "ai-inventory.json").read_text())[
        "count"] == 0


def test_multiple_runs_and_no_inventory_are_supported(tmp_path):
    first = _sarif([_rule("security.one")], [_result("security.one")])
    second_run = _sarif([_rule("security.two")], [_result("security.two")])["runs"][0]
    first["runs"].append(second_run)
    _raw, output, _before = _prepare(tmp_path, {"semgrep.sarif": first})
    assert json.loads((output / "security" / "semgrep.sarif").read_text()) == first
    inventory = json.loads((output / "inventory" / "ai-inventory.json").read_text())
    assert inventory["count"] == 0
    assert "No authorized AI inventory results" in (
        output / "inventory" / "ai-inventory.md").read_text()

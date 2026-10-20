"""#2088: a report must name the scope the driver actually reviewed."""

import ast
import inspect
import json
from pathlib import Path

import pytest

import scripts.driver as driver
import scripts.synthesize as synthesize
from scripts.synth import findings, plan, report, validate_schema
from tests.synth.helpers import DEFAULT_TIMESTAMP, _cli_args


def test_every_driver_scope_mode_has_a_schema_valid_review_type():
    # Read the producer, rather than copying its vocabulary into this test:
    # adding a new return arm must fail until the report knows its mode too.
    tree = ast.parse(inspect.getsource(driver._scope_from_args))
    modes = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and key.value == "mode":
                assert isinstance(value, ast.Constant) and isinstance(value.value, str), \
                    "scope producer changed shape; extend the completeness walk"
                modes.add(value.value)
    assert modes, "the completeness walk must observe the driver's modes"
    assert modes <= findings.MODE_TO_REVIEW_TYPE.keys()
    schema_path = Path(__file__).resolve().parents[2] / "skill/reference/report-schema.json"
    schema = json.loads(schema_path.read_text())
    allowed = schema["properties"]["meta"]["properties"]["review_type"]["enum"]
    assert set(findings.MODE_TO_REVIEW_TYPE.values()) <= set(allowed)


@pytest.mark.parametrize("flags, expected", [
    (["--file", "app.py"], "file"),
    (["--directory", "src"], "directory"),
    (["--group", "Core"], "group"),
    (["--changes"], "changes"),
    (["--files", "app.py", "test_app.py"], "changes"),
])
def test_driver_scope_reaches_run_config(flags, expected):
    args = driver.build_parser().parse_args(["run", ".", *flags])
    scope = driver._scope_from_args(args)
    run = report.RunConfig.from_args(_cli_args(), scope, DEFAULT_TIMESTAMP)
    assert run.review_type == expected


@pytest.mark.parametrize("mode, expected", [
    ("repo", "repo"), ("file", "file"), ("directory", "directory"),
    ("group", "group"), ("files", "changes"), ("changes", "changes"),
    ("changed", "changes"), ("pr", "pr"),
])
def test_report_publishes_the_inventory_scope(tmp_path, monkeypatch, mode, expected):
    monkeypatch.chdir(tmp_path)
    inventory = tmp_path / "groups.json"
    inventory.write_text(json.dumps({"mode": mode, "groups": []}))
    output = tmp_path / "report.json"
    result = synthesize.main(["--groups", str(inventory), "--out", str(output)])
    assert result == 0
    document = json.loads(output.read_text())
    assert document["meta"]["review_type"] == expected


@pytest.mark.parametrize("inventory", [
    {"groups": []},
    {"mode": "unrecognized-scope", "groups": []},
    {"mode": [], "groups": []},
    {"mode": None, "groups": []},
], ids=["missing", "unknown", "repaired-list", "repaired-null"])
def test_unnameable_inventory_scope_halts_without_writing(
        tmp_path, monkeypatch, capsys, inventory):
    monkeypatch.chdir(tmp_path)
    groups = tmp_path / "groups.json"
    groups.write_text(json.dumps(inventory))
    if "mode" in inventory and not isinstance(inventory["mode"], str):
        assert "mode" not in plan.load_groups_json(str(groups))
    output = tmp_path / "report.json"
    html = tmp_path / "report.html"
    output.write_bytes(b"previous report stays intact\n")
    result = synthesize.main([
        "--groups", str(groups), "--out", str(output), "--html-out", str(html)])
    assert result == validate_schema.ARTIFACT_INVALID
    assert "review scope refused" in capsys.readouterr().err
    assert output.read_bytes() == b"previous report stays intact\n"
    assert not html.exists()


def test_a_missing_named_inventory_does_not_become_repo(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "report.json"
    result = synthesize.main([
        "--groups", str(tmp_path / "absent.json"), "--out", str(output)])
    assert result == validate_schema.ARTIFACT_INVALID
    assert "review scope refused" in capsys.readouterr().err
    assert not output.exists()


def test_explicit_changes_still_names_the_scope(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "report.json"
    assert synthesize.main(["--changes", "--out", str(output)]) == 0
    assert json.loads(output.read_text())["meta"]["review_type"] == "changes"


def test_standalone_scope_must_be_explicit(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "report.json"
    assert synthesize.main(["--out", str(output)]) == validate_schema.ARTIFACT_INVALID
    error = capsys.readouterr().err
    assert "review scope refused" in error
    assert "--repo" in error
    assert not output.exists()


@pytest.mark.parametrize("inventory", [None, {"mode": [], "groups": []}])
def test_explicit_repo_names_a_standalone_scope(tmp_path, monkeypatch, inventory):
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "report.json"
    args = ["--repo", "--out", str(output)]
    if inventory is not None:
        groups = tmp_path / "groups.json"
        groups.write_text(json.dumps(inventory))
        args += ["--groups", str(groups)]
    assert synthesize.main(args) == 0
    assert json.loads(output.read_text())["meta"]["review_type"] == "repo"


def test_explicit_repo_and_changes_are_mutually_exclusive():
    with pytest.raises(SystemExit) as error:
        synthesize.build_parser().parse_args(["--repo", "--changes"])
    assert error.value.code == 2


def test_scope_refusal_cannot_advance_the_driver_using_an_old_report(tmp_path, monkeypatch):
    from scripts.phases import runio, synthesize as phase

    monkeypatch.chdir(tmp_path)
    pano = tmp_path / ".panopticon"
    pano.mkdir()
    (pano / "groups.json").write_text(json.dumps({"groups": []}))
    output = pano / "report.json"
    previous = json.dumps({"summary": {}, "meta": {"review_type": "repo"}}).encode()
    output.write_bytes(previous)
    with pytest.raises(runio.DriverError, match="review scope refused"):
        phase.synthesize_execute(str(tmp_path), {"host": "codex", "flags": {}})
    assert output.read_bytes() == previous

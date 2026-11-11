"""#3528: a health grade names the run layout that made it."""

import copy
import os
from pathlib import Path

import pytest

import scripts.discovery as discovery
import scripts.html_report as html_report
import scripts.synth.findings as findings_mod
import scripts.synth.plan as plan_mod
import scripts.synth.render as render_mod
import scripts.synth.report as report_mod
import scripts.synth.tool_axis as tool_axis_mod
import scripts.synth.validate_schema as validate_schema_mod
from tests.synth.helpers import DEFAULT_TIMESTAMP, _cli_args, _target_with_files


NOTE_PREFIX = (
    "policy score pending calibration; comparable only with runs of the same "
    "version, review type and layout (fingerprint "
)
LEGACY_NOTE = "basis unknown (report predates #3528)"


def _report(groups, root, *, cap=8, max_groups=12, review_type="repo",
            coverages=None, answered=None):
    tools = tool_axis_mod.ToolAxis(
        ingested_paths=None if answered is None else [
            os.path.join(root, "findings-%s-%s.json" % pair) for pair in answered
        ])
    return report_mod.build_report(report_mod.ReportInputs(
        run=report_mod.RunConfig(
            target=root, fail_on="high", timestamp=DEFAULT_TIMESTAMP,
            review_type=review_type, max_per_group=cap, max_groups=max_groups),
        findings=findings_mod.FindingSet(findings=[]),
        plan=plan_mod.PlanInputs(groups_meta=groups, coverages=coverages),
        tools=tools,
    ))


def test_basis_uses_the_layout_and_cell_counts_the_report_already_carries():
    groups = [
        {"name": "zeta", "files": ["z.py", "shared.py"]},
        {"name": "alpha", "files": ["shared.py", "a.py"]},
    ]
    coverages = [
        {"group": "alpha", "floor": ["COD"], "effective": ["COD", "SEC"]},
        {"group": "zeta", "floor": ["COD"], "effective": ["COD", "SEC"]},
    ]
    answered = [("alpha", "COD"), ("alpha", "SEC"), ("zeta", "COD")]
    with _target_with_files(groups) as root:
        report = _report(groups, root, coverages=coverages, answered=answered)

    health = report["summary"]["health"]
    basis = health["basis"]
    assert basis == {
        "review_type": "full",
        "groups": 2,
        "cells_planned": 4,
        "cells_answered": 3,
        "max_per_group": 8,
        "max_groups": 12,
        "layout_fingerprint": basis["layout_fingerprint"],
        "version": report["meta"]["version"],
        "ocrdb_version": report["meta"]["ocrdb_version"],
    }
    assert basis["layout_fingerprint"].startswith("sha256:")
    assert len(basis["layout_fingerprint"]) == len("sha256:") + 64
    assert health["note"] == NOTE_PREFIX + basis["layout_fingerprint"] + ")"


@pytest.mark.parametrize(
    ("raw", "published"),
    [("repo", "full"), ("changes", "delta"), ("pr", "delta"),
     ("file", "file-scoped"), ("directory", "file-scoped"),
     ("group", "file-scoped")],
)
def test_basis_normalizes_review_type_without_changing_meta(raw, published):
    with _target_with_files([]) as root:
        report = _report([], root, review_type=raw)
    assert report["meta"]["review_type"] == raw
    assert report["summary"]["health"]["basis"]["review_type"] == published


def test_changing_the_cap_recuts_the_layout_but_not_the_score_or_letter():
    files = ["src/%s.py" % name for name in "abcd"]
    with _target_with_files([{"name": "all", "files": files}]) as root:
        reports = []
        for cap in (2, 4):
            groups = discovery.build_result(
                root, "repo", ".", None, files, [], cap, group_files=files)["groups"]
            reports.append(_report(groups, root, cap=cap))

    first, second = reports
    first_health = {key: value for key, value in first["summary"]["health"].items()
                    if key not in ("basis", "note")}
    second_health = {key: value for key, value in second["summary"]["health"].items()
                     if key not in ("basis", "note")}
    assert first_health == second_health
    assert first["summary"]["overall_grade"] == second["summary"]["overall_grade"]
    assert first["summary"]["gate"] == second["summary"]["gate"]
    assert (first["summary"]["health"]["basis"]["layout_fingerprint"]
            != second["summary"]["health"]["basis"]["layout_fingerprint"])
    assert (first["summary"]["health"]["basis"]["max_per_group"],
            second["summary"]["health"]["basis"]["max_per_group"]) == (2, 4)


def test_layout_fingerprint_is_stable_under_group_and_file_order():
    left = [{"name": "b", "files": ["2.py", "1.py"]},
            {"name": "a", "files": ["4.py", "3.py"]}]
    right = [{"name": "a", "files": ["3.py", "4.py"]},
             {"name": "b", "files": ["1.py", "2.py"]}]
    with _target_with_files(left) as root:
        a = _report(left, root)
        b = _report(right, root)
    fingerprint = a["summary"]["health"]["basis"]["layout_fingerprint"]
    assert fingerprint == b["summary"]["health"]["basis"]["layout_fingerprint"]
    assert fingerprint == (
        "sha256:d7564de4462a6a1a7714caf820a33507b93cb5ff0eb59d40c50498e75d546dfe")


def test_layout_fingerprint_accepts_a_filename_with_a_lone_surrogate():
    groups = [{"name": "g", "files": ["caf\udcff.py"]}]
    with _target_with_files([]) as root:
        report = _report(groups, root)
    fingerprint = report["summary"]["health"]["basis"]["layout_fingerprint"]
    assert fingerprint.startswith("sha256:") and len(fingerprint) == 71


def test_run_config_prefers_the_cap_discovery_actually_used_and_clamped_config_ceiling():
    config = {"effective": {"max_per_group": 48, "max_groups": 9}}
    run = report_mod.RunConfig.from_args(
        _cli_args(repo=True), {"mode": "repo", "max_per_group": 17},
        DEFAULT_TIMESTAMP, config=config)
    assert run.max_per_group == 17
    assert run.max_groups == 9
    fallback = report_mod.RunConfig.from_args(
        _cli_args(repo=True), {"mode": "repo"}, DEFAULT_TIMESTAMP, config=config)
    assert fallback.max_per_group == 48


def test_discovery_records_the_effective_cap_in_its_run_inventory():
    result = discovery.build_result("/repo", "repo", ".", None, ["a.py"], [], 17)
    assert result["max_per_group"] == 17


def test_schema_requires_basis_and_note_only_for_new_reports():
    with _target_with_files([]) as root:
        report = _report([], root)
    assert validate_schema_mod.schema_errors(report) == []

    for field in ("basis", "note"):
        current = copy.deepcopy(report)
        del current["summary"]["health"][field]
        assert any(field in error for error in validate_schema_mod.schema_errors(current))

        for old_version in (1, None):
            legacy = copy.deepcopy(current)
            if old_version is None:
                legacy.pop("schema_version")
            else:
                legacy["schema_version"] = old_version
            assert validate_schema_mod.schema_errors(legacy) == []


def test_qualifier_is_rendered_in_json_terminal_and_html_header():
    with _target_with_files([]) as root:
        report = _report([], root)
    note = report["summary"]["health"]["note"]
    assert note.startswith(NOTE_PREFIX)
    assert note in render_mod.render_summary(report)
    assert note in html_report._render_header(report)


def test_legacy_report_renders_the_explicit_unknown_basis_in_both_human_outputs():
    with _target_with_files([]) as root:
        report = _report([], root)
    report["schema_version"] = 1
    report["summary"]["health"].pop("basis")
    report["summary"]["health"].pop("note")
    assert LEGACY_NOTE in render_mod.render_summary(report)
    assert LEGACY_NOTE in html_report._render_header(report)


def test_human_renderers_do_not_trust_a_planted_note_without_a_valid_basis():
    with _target_with_files([]) as root:
        report = _report([], root)
    report["summary"]["health"]["note"] = "<planted> comparable"
    report["summary"]["health"].pop("basis")
    terminal = render_mod.render_summary(report)
    header = html_report._render_header(report)
    assert LEGACY_NOTE in terminal and LEGACY_NOTE in header
    assert "planted" not in terminal and "planted" not in header


def test_compare_panels_qualify_both_current_and_legacy_grades():
    with _target_with_files([]) as root:
        current = _report([], root)
    legacy = copy.deepcopy(current)
    legacy["schema_version"] = 1
    legacy["summary"]["health"].pop("basis")
    legacy["summary"]["health"].pop("note")
    rendered = html_report.render(current, compare_report=legacy)
    assert current["summary"]["health"]["note"] in rendered
    assert LEGACY_NOTE in rendered


def test_two_committed_legacy_report_fixtures_still_render_with_unknown_basis():
    fixtures = Path(__file__).resolve().parents[1] / "fixtures" / "reconcile"
    for name in ("run2.json", "run3.json"):
        report = render_mod._read_json_report(str(fixtures / name))
        assert report is not None
        assert LEGACY_NOTE in html_report.render(report)

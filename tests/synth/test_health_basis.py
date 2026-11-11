"""#3528: a health grade names the run layout that made it."""

import copy
import os
from pathlib import Path

import pytest

import scripts.discovery as discovery
import scripts.html_report as html_report
import scripts.synth.findings as findings_mod
import scripts.synth.health_basis as health_basis
import scripts.synth.plan as plan_mod
import scripts.synth.render as render_mod
import scripts.synth.report as report_mod
import scripts.synth.tool_axis as tool_axis_mod
import scripts.synth.validate_schema as validate_schema_mod
from tests.synth.helpers import DEFAULT_TIMESTAMP, _agentic, _cli_args, _target_with_files


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
        "profile": "custom",
        # #3548: these records predate the lever fields, so nothing is measured.
        "config_levers": {"domain_exclude": None, "domain_exclude_scout": None,
                          "panels_added": None, "exclude_paths": None},
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


# --- #1495: a certified letter only at the default scan profile -----------------------------

DEFAULT_CAP = discovery.DEFAULT_MAX_PER_GROUP
GROUPS = [{"name": "app", "files": ["app.py", "lib.py"]}]


def _graded(root, *, cap, max_groups=None, review_type="repo", findings=(), config=None):
    return report_mod.build_report(report_mod.ReportInputs(
        run=report_mod.RunConfig(
            target=root, fail_on="high", timestamp=DEFAULT_TIMESTAMP, gate_unverified=True,
            review_type=review_type, max_per_group=cap, max_groups=max_groups,
            config=config or {}),
        findings=findings_mod.FindingSet(findings=[dict(f) for f in findings]),
        plan=plan_mod.PlanInputs(groups_meta=GROUPS),
    ))["summary"]


def test_the_default_profile_is_discoverys_default_cap():
    assert health_basis.GRADED_MAX_PER_GROUP == discovery.DEFAULT_MAX_PER_GROUP


def test_a_full_review_at_a_custom_cap_carries_its_letter_as_provisional():
    with _target_with_files(GROUPS) as root:
        default = _graded(root, cap=DEFAULT_CAP)
        custom = _graded(root, cap=15)
    assert default["overall_grade"] and default["provisional_grade"] is None
    assert default["health"]["basis"]["profile"] == "default"
    assert (custom["overall_grade"], custom["provisional_grade"]) == (
        None, default["overall_grade"])
    assert custom["health"]["basis"]["profile"] == "custom"
    assert custom["health"]["score"] == default["health"]["score"]
    note = custom["coverage_note"]
    assert note.startswith("grade provisional: this scan used a non-default group size of 15 "
                           "files (set by the run's --max-per-group flag; the default is %d)"
                           % DEFAULT_CAP)
    assert "non-default" not in (default["coverage_note"] or "")
    assert render_mod._grade_text(custom) == "%s (provisional)" % default["overall_grade"]
    assert html_report._grade_badge(custom) == "%s (provisional)" % default["overall_grade"]
    assert html_report._grade_badge(default) == default["overall_grade"]


def test_both_human_outputs_say_why_a_custom_profile_letter_is_provisional():
    with _target_with_files(GROUPS) as root:
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target=root, fail_on="high", timestamp=DEFAULT_TIMESTAMP,
                                     review_type="repo", max_per_group=15),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=GROUPS)))
    note = report["summary"]["coverage_note"]
    assert report["summary"]["coverage_certified"] is True
    assert "**Grade provisional:** " + note in render_mod.render_summary(report)
    header = html_report._render_header(report)
    assert "<div class='provisional-grade'>" in header and "group size of 15 files" in header
    assert "NOT CERTIFIED" not in header


def test_the_gate_and_coverage_certification_do_not_see_the_profile():
    findings = [_agentic(location={"file": "app.py", "line_start": 3})]
    for case in ((), findings):
        with _target_with_files(GROUPS) as root:
            default = _graded(root, cap=DEFAULT_CAP, findings=case)
            custom = _graded(root, cap=15, findings=case)
        assert default["gate"] == custom["gate"]
        assert default["coverage_certified"] == custom["coverage_certified"]
    assert default["gate"] == "FAIL"


def test_a_custom_cap_alone_with_max_groups_unset_goes_provisional():
    with _target_with_files(GROUPS) as root:
        summary = _graded(root, cap=20, max_groups=None)
    assert summary["overall_grade"] is None and summary["provisional_grade"]


def test_a_config_max_groups_below_the_formula_ceiling_still_certifies_at_the_default_cap():
    # Ruling (A): a review run never applies a max_groups ceiling (only setup does), so it is
    # provenance in the basis, not part of the profile. Re-adding it needs a ruling.
    with _target_with_files(GROUPS) as root:
        summary = _graded(root, cap=DEFAULT_CAP, max_groups=4,
                          config={"effective": {"max_groups": 4}})
    assert summary["overall_grade"] and summary["provisional_grade"] is None
    assert summary["health"]["basis"]["max_groups"] == 4


def test_a_clamped_config_value_equal_to_the_default_certifies():
    clamped = {"requested": {"max_per_group": 500}, "effective": {"max_per_group": DEFAULT_CAP},
               "clamped": [{"key": "max_per_group", "requested": 500, "effective": DEFAULT_CAP}]}
    run = report_mod.RunConfig.from_args(
        _cli_args(repo=True), {"mode": "repo", "max_per_group": DEFAULT_CAP},
        DEFAULT_TIMESTAMP, config=clamped)
    assert health_basis.profile(run) == "default"
    assert health_basis.custom_profile_reason(run) is None
    explicit = report_mod.RunConfig.from_args(
        _cli_args(repo=True), {"mode": "repo", "max_per_group": DEFAULT_CAP}, DEFAULT_TIMESTAMP)
    assert health_basis.custom_profile_reason(explicit) is None


def test_the_note_names_where_a_custom_cap_came_from():
    by_config = report_mod.RunConfig.from_args(
        _cli_args(repo=True), {"mode": "repo", "max_per_group": 20}, DEFAULT_TIMESTAMP,
        config={"effective": {"max_per_group": 20}})
    by_flag = report_mod.RunConfig.from_args(
        _cli_args(repo=True), {"mode": "repo", "max_per_group": 30}, DEFAULT_TIMESTAMP,
        config={"effective": {"max_per_group": 20}})
    assert ("20 files (set by max_per_group in the target's panopticon.yml, or a "
            "--max-per-group flag of the same value; the default is %d)" % DEFAULT_CAP) in (
        health_basis.custom_profile_reason(by_config))
    assert "30 files (set by the run's --max-per-group flag;" in (
        health_basis.custom_profile_reason(by_flag))
    assert health_basis.custom_profile_reason(by_flag).endswith("in the same code.")


@pytest.mark.parametrize("review_type", ["changes", "pr", "file", "directory", "group"])
def test_delta_and_file_scoped_reviews_keep_their_letter_at_a_custom_cap(review_type):
    with _target_with_files(GROUPS) as root:
        summary = _graded(root, cap=15, review_type=review_type)
    assert summary["provisional_grade"] is None
    assert "non-default" not in (summary["coverage_note"] or "")


def test_an_unrecorded_cap_keeps_the_letter():
    with _target_with_files(GROUPS) as root:
        summary = _graded(root, cap=None)
    assert summary["overall_grade"] and summary["provisional_grade"] is None
    assert summary["health"]["basis"]["profile"] == "unknown"


def test_a_stored_report_without_the_profile_stamp_keeps_its_stored_letter():
    with _target_with_files(GROUPS) as root:
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target=root, fail_on="high", timestamp=DEFAULT_TIMESTAMP,
                                     review_type="repo", max_per_group=15),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=GROUPS)))
    report["summary"]["health"]["basis"].pop("profile")
    report["summary"]["overall_grade"], report["summary"]["provisional_grade"] = "D", None
    assert validate_schema_mod.schema_errors(report) == []
    assert "**Grade:** D  **Risk:**" in render_mod.render_summary(report)
    assert "Grade: D<" in html_report._render_header(report)


def _certified(panels_incomplete, custom):
    import scripts.synth.grading as grading
    return grading.certify("B", [], "high", panels_incomplete, [],
                           custom_profile=health_basis.custom_profile_reason(custom))


def _custom_run(cap=15):
    return report_mod.RunConfig(target="t", fail_on="high", timestamp=DEFAULT_TIMESTAMP,
                                review_type="repo", max_per_group=cap)


def test_a_custom_cap_beside_a_low_value_panel_gap_keeps_both_reasons_once():
    cert = _certified({"docs"}, _custom_run())
    assert (cert["overall_grade"], cert["provisional_grade"], cert["gate"]) == (None, "B", "PASS")
    note = cert["coverage_note"]
    assert note.startswith("gate certified; grade provisional \u2014 low-value panel(s) "
                           "incomplete: docs; this scan used a non-default group size of 15")
    assert note.count("grade provisional") == 1


def test_a_custom_cap_beside_a_gate_relevant_gap_keeps_the_gate_reason_first():
    import scripts.synth.grading as grading
    cert = _certified({"security"}, _custom_run())
    assert (cert["provisional_grade"], cert["gate"], cert["coverage_certified"]) == (
        "B", "INCONCLUSIVE", False)
    assert cert["coverage_note"].startswith(
        grading.GATE_GAP_NOTE + "; grade provisional: this scan used a non-default group size")
    plain = grading.certify("B", [], "high", {"security"}, [])
    assert plain["coverage_note"] is None          # unchanged without a custom cap
    # and both human outputs show the gate reason, not the group size alone
    with _target_with_files(GROUPS) as root:
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target=root, fail_on="high", timestamp=DEFAULT_TIMESTAMP,
                                     review_type="repo", max_per_group=15),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=GROUPS)))
    for key in ("overall_grade", "provisional_grade", "gate", "coverage_certified",
                "coverage_note"):
        report["summary"][key] = cert[key]
    header = html_report._render_header(report)
    assert "NOT CERTIFIED &mdash; " + grading.GATE_GAP_NOTE + "; grade provisional: " in header
    terminal = render_mod.render_summary(report)
    assert "**Coverage:** NOT CERTIFIED" in terminal and grading.GATE_GAP_NOTE in terminal
    assert "group size of 15 files" in terminal

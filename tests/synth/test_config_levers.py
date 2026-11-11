"""#3548: target-authored `exclude:` / `panels:` / `exclude_paths:` and the certified letter."""

import copy

import pytest

import scripts.discovery as discovery
import scripts.html_report as html_report
import scripts.repo_config as repo_config
import scripts.synth.findings as findings_mod
import scripts.synth.grading as grading
import scripts.synth.health_basis as health_basis
import scripts.synth.plan as plan_mod
import scripts.synth.render as render_mod
import scripts.synth.report as report_mod
import scripts.synth.validate_schema as validate_schema_mod
from tests.synth.helpers import DEFAULT_TIMESTAMP, _cli_args, _target_with_files


DEFAULT_CAP = discovery.DEFAULT_MAX_PER_GROUP
GROUPS = [{"name": "app", "files": ["app.py", "lib.py"]}]
CONFIG = repo_config.CONFIG_NAMES[0]
BITE = "grade provisional: this scan skipped review areas the target's %s excludes (" % CONFIG


def _cov(group="app", *, deterministic=(), scout=(), panels=()):
    """A coverage record as `phases/coverage.py` writes it since #3548. `floor` is empty so
    the floor-cell audit has nothing to miss and the gate stays out of these tests."""
    return {"group": group, "floor": [], "excluded": sorted(set(deterministic) | set(scout)),
            "effective": ["COD"], "exclude_deterministic": list(deterministic),
            "exclude_scout": list(scout), "panels_added": list(panels)}


def _report(coverages, *, review_type="repo", cap=DEFAULT_CAP, exclude_paths=None):
    with _target_with_files(GROUPS) as root:
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target=root, fail_on="high", timestamp=DEFAULT_TIMESTAMP,
                review_type=review_type, max_per_group=cap, exclude_paths=exclude_paths),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=GROUPS, coverages=coverages)))


def _summary(coverages, **kw):
    return _report(coverages, **kw)["summary"]


def _outcome(summary):
    return (summary["overall_grade"], summary["provisional_grade"],
            summary["health"]["basis"]["profile"])


def test_an_exclude_that_removes_a_fixed_floor_domain_makes_the_letter_provisional():
    plain = _summary([_cov()])
    bitten = _summary([_cov(deterministic=["COD"])])
    assert plain["overall_grade"] and plain["provisional_grade"] is None
    assert _outcome(bitten) == (None, plain["overall_grade"], "custom")
    assert bitten["coverage_note"] == BITE + (
        "app:COD). A letter is certified only when every applicable review area ran, because "
        "skipping one finds less in the same code.")
    # the letter only: score, gate and coverage certification are what they were
    for key in ("gate", "coverage_certified"):
        assert bitten[key] == plain[key]
    assert bitten["health"]["score"] == plain["health"]["score"]
    assert bitten["health"]["basis"]["config_levers"]["domain_exclude"] == ["app:COD"]


def test_an_exclude_that_removes_nothing_keeps_the_letter_certified():
    summary = _summary([_cov(deterministic=[], scout=[])])
    assert _outcome(summary)[1:] == (None, "default")
    assert summary["overall_grade"]
    assert summary["coverage_note"] is None


def test_a_scout_only_exclude_is_named_and_never_moves_the_letter():
    summary = _summary([_cov(scout=["OPS"])])
    assert summary["overall_grade"] and summary["provisional_grade"] is None
    assert summary["health"]["basis"]["profile"] == "default"
    assert summary["coverage_note"] == (
        "the scout asked for review areas the target's %s excludes (app:OPS)" % CONFIG)
    assert summary["health"]["basis"]["config_levers"]["domain_exclude_scout"] == ["app:OPS"]


@pytest.mark.parametrize("deterministic", [(), ("TST",)])
def test_the_same_config_under_two_scout_sets_gives_the_same_letter_outcome(deterministic):
    # The coordinator's 5.4 test: the scout is an LLM, so what it asked for must not decide
    # whether a pinned repo and config certify.
    first = _summary([_cov(deterministic=deterministic, scout=[])])
    second = _summary([_cov(deterministic=deterministic, scout=["OPS", "DAT"])])
    assert _outcome(first) == _outcome(second)
    assert (first["provisional_grade"] is None) is (not deterministic)


def test_a_record_written_before_the_lever_fields_keeps_the_letter_and_measures_nothing():
    legacy = {"group": "app", "floor": [], "excluded": ["COD"], "effective": []}
    summary = _summary([legacy])
    assert summary["overall_grade"] and summary["provisional_grade"] is None
    assert summary["health"]["basis"]["config_levers"] == {
        "domain_exclude": None, "domain_exclude_scout": None, "panels_added": None,
        "exclude_paths": None}


@pytest.mark.parametrize("review_type", ["changes", "files"])
def test_delta_and_file_scoped_reviews_keep_their_letter_and_notes(review_type):
    summary = _summary([_cov(deterministic=["COD"], scout=["OPS"])], review_type=review_type,
                       exclude_paths={"globs": 1, "pruned": 3, "sec_carved": 1})
    assert summary["overall_grade"] and summary["provisional_grade"] is None
    assert summary["coverage_note"] is None
    # the basis still records what the config did
    assert summary["health"]["basis"]["config_levers"]["domain_exclude"] == ["app:COD"]


def test_a_custom_cap_and_a_biting_exclude_give_both_reasons_under_one_prefix():
    summary = _summary([_cov(deterministic=["COD"])], cap=15)
    note = summary["coverage_note"]
    assert note.startswith("grade provisional: this scan used a non-default group size of 15")
    assert ("same code. This scan skipped review areas the target's %s excludes (app:COD)"
            % CONFIG) in note
    assert note.count("grade provisional") == 1
    assert summary["health"]["basis"]["profile"] == "custom"


def test_a_biting_exclude_beside_panel_gaps_keeps_the_1495_composition():
    reasons = health_basis.custom_profile_reasons(_run(), [_cov(deterministic=["COD"])])
    low = grading.certify("B", [], "high", {"docs"}, [], custom_profile=reasons)
    assert low["coverage_note"].startswith(
        "gate certified; grade provisional — low-value panel(s) incomplete: docs; "
        "this scan skipped review areas")
    assert low["coverage_note"].count("grade provisional") == 1
    gate = grading.certify("B", [], "high", {"security"}, [], custom_profile=reasons)
    assert (gate["provisional_grade"], gate["gate"]) == ("B", "INCONCLUSIVE")
    assert gate["coverage_note"].startswith(grading.GATE_GAP_NOTE + "; " + BITE)


def test_certify_takes_one_reason_or_a_list_and_ignores_empty_ones():
    one = grading.certify("B", [], "high", set(), [], custom_profile="x happened.")
    many = grading.certify("B", [], "high", set(), [], custom_profile=["x happened.", ""])
    assert one == many
    assert one["coverage_note"] == grading.PROVISIONAL_PREFIX + "x happened."
    none = grading.certify("B", [], "high", set(), [], custom_profile=[])
    assert (none["overall_grade"], none["coverage_note"]) == ("B", None)


def test_exclude_paths_is_named_with_its_counts_and_keeps_the_letter():
    summary = _summary([_cov()], exclude_paths={"globs": 2, "pruned": 7, "sec_carved": 3})
    assert summary["overall_grade"] and summary["provisional_grade"] is None
    assert summary["coverage_note"] == (
        "exclude_paths in the target's %s removed 7 file(s) from review (3 more code file(s) "
        "kept for security review only)" % CONFIG)
    assert summary["health"]["basis"]["config_levers"]["exclude_paths"] == {
        "globs": 2, "pruned": 7, "sec_carved": 3}


def test_exclude_paths_that_removed_nothing_is_recorded_but_not_named():
    summary = _summary([_cov()], exclude_paths={"globs": 1, "pruned": 0, "sec_carved": 0})
    assert summary["coverage_note"] is None
    assert summary["health"]["basis"]["config_levers"]["exclude_paths"]["globs"] == 1


def test_an_unrecorded_exclude_paths_count_says_so():
    summary = _summary([_cov()], exclude_paths={"globs": 1, "pruned": 4, "sec_carved": None})
    assert "removed 4 file(s) from review (an unrecorded number of more code" in (
        summary["coverage_note"])


def test_discoverys_exclude_paths_record_reaches_the_run_config():
    groups_json = {"mode": "repo", "exclude_paths": ["vendor/**", "dist/**"],
                   "excluded_count": 12,
                   "exclude_paths_sec_carve_out": {"globs": ["vendor/**"], "files": ["v.c"],
                                                   "count": 1}}
    run = report_mod.RunConfig.from_args(_cli_args(repo=True), groups_json, DEFAULT_TIMESTAMP)
    assert run.exclude_paths == {"globs": 2, "pruned": 12, "sec_carved": 1}
    bare = report_mod.RunConfig.from_args(_cli_args(repo=True), {"mode": "repo"},
                                          DEFAULT_TIMESTAMP)
    assert bare.exclude_paths is None


@pytest.mark.parametrize("planted", [-1, True, "7", 1.5, None])
def test_a_malformed_exclude_paths_count_reads_as_unrecorded(planted):
    record = health_basis.exclude_paths_record(
        {"exclude_paths": ["x/**"], "excluded_count": planted,
         "exclude_paths_sec_carve_out": {"count": planted}})
    assert record == {"globs": 1, "pruned": None, "sec_carved": None}


def test_panels_added_is_recorded_only():
    summary = _summary([_cov(panels=["OPS"])])
    assert summary["overall_grade"] and summary["provisional_grade"] is None
    assert summary["coverage_note"] is None
    assert summary["health"]["basis"]["profile"] == "default"
    assert summary["health"]["basis"]["config_levers"]["panels_added"] == ["app:OPS"]


def test_lever_lists_are_sorted_across_groups_and_capped_in_the_basis():
    many = [_cov("g%03d" % i, deterministic=["COD", "TST"]) for i in range(200)]
    levers = health_basis.config_levers(_run(), list(reversed(many)))
    assert len(levers["domain_exclude"]) == health_basis.MAX_LEVER_CELLS
    assert levers["domain_exclude"][:3] == ["g000:COD", "g000:TST", "g001:COD"]
    reason = health_basis.exclude_reason(_run(), many)
    assert "(g000:COD, g000:TST, " in reason and " and 390 more)" in reason


def test_a_planted_non_string_domain_or_group_is_skipped():
    planted = [{"group": 7, "exclude_deterministic": ["COD"]},
               {"group": "app", "exclude_deterministic": ["COD", 3, None]},
               {"group": "lib", "exclude_deterministic": "COD"}]
    assert health_basis.lever_cells(planted, "exclude_deterministic") == ["app:COD"]


def test_a_report_with_levers_round_trips_the_schema():
    report = _report([_cov(deterministic=["COD"], scout=["OPS"], panels=["DAT"])],
                     exclude_paths={"globs": 1, "pruned": 2, "sec_carved": None})
    assert validate_schema_mod.schema_errors(report) == []
    legacy = copy.deepcopy(report)
    del legacy["summary"]["health"]["basis"]["config_levers"]
    assert validate_schema_mod.schema_errors(legacy) == []
    bad = copy.deepcopy(report)
    bad["summary"]["health"]["basis"]["config_levers"]["domain_exclude"] = "app:COD"
    assert validate_schema_mod.schema_errors(bad)


def test_both_human_outputs_say_why_an_exclude_made_the_letter_provisional():
    report = _report([_cov(deterministic=["COD"])])
    note = report["summary"]["coverage_note"]
    assert "**Grade provisional:** " + note in render_mod.render_summary(report)
    header = html_report._render_header(report)
    assert "<div class='provisional-grade'>" in header and "excludes (app:COD)" in header
    assert "NOT CERTIFIED" not in header


def _run(review_type="repo"):
    return report_mod.RunConfig(target="t", fail_on="high", timestamp=DEFAULT_TIMESTAMP,
                                review_type=review_type, max_per_group=DEFAULT_CAP)

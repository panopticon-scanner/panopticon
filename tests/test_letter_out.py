"""#3672 (owner ruling, 2026-11-23): the letter grade leaves everything a person reads.

The terminal summary and the HTML page lead with the health score. The letter stays
in the report JSON and its schema for one release, with the values it had. What the
letter carried for a reader moves to the score: a held-back result still says
"provisional" and why."""
import copy
import html as html_lib
import re

import pytest

import scripts.evidence as evidence_mod
import scripts.html_report as html_report
import scripts.synth.coverage_io as coverage_io
import scripts.synth.findings as findings_mod
import scripts.synth.grading as grading_mod
import scripts.synth.health_basis as health_basis
import scripts.synth.plan as plan_mod
import scripts.synth.render as render_mod
import scripts.synth.report as report_mod
import scripts.synth.validate_schema as validate_schema_mod
from tests.synth.helpers import _agentic, _target_with_files

# "grade", "grades", "Grade:", "provisional-grade"; not "upgrade" or "degraded".
GRADE_WORD = re.compile(r"(?i)\bgrad(?:e|es|ed|ing)\b")
LETTER_WORD = re.compile(r"(?i)\bletters?\b")
SHORTFALL = "145 tool findings unanswered by their advisors"


def _report(confirmed=(), lines=5000):
    groups = [{"name": "g1", "files": ["a.py"]}]
    verdicts = {evidence_mod.finding_fingerprint(f): {
        "finding_id": f["id"], "verdict": "CONFIRMED", "reasoning": "v"} for f in confirmed}
    with _target_with_files(groups, lines=lines) as tgt:
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target=tgt, fail_on="high",
                                     timestamp="2026-01-01T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=list(confirmed), verdicts=verdicts),
            plan=plan_mod.PlanInputs(groups_meta=groups)))
    report["meta"]["target"] = "t"
    return report


def _critical():
    return _agentic(fid="AG-001", sev="CRITICAL", title="an open door",
                    location={"file": "a.py", "line_start": 1})


def _with(report, **summary):
    out = copy.deepcopy(report)
    out["summary"].update(summary)
    return out


def _every_optional_section(report):
    """The sections a report prints only when it has something for them, so the test
    that no surface says "grade" reads them too."""
    report["meta"]["rejected_scanner_findings"] = {"count": 3, "rows": [
        {"severity": "HIGH", "title": "a rejected scanner finding", "file": "a.py",
         "line_start": 4, "tool": "bandit", "rule": "B602", "occurrences": 2,
         "reasoning": "the argument is a constant"}]}
    coverage = report["meta"].setdefault("coverage", {})
    coverage["tools_context_not_gated"] = {"test-path": 2}
    coverage["tools_suppressed_gated"] = {"vendored": 1}
    coverage["tools_unpinned"] = {"osv-scanner": [{
        "manifest": "requirements.txt", "packages": ["requests"], "packages_more": 0,
        "advisories": 1, "ids": ["GHSA-aaaa-0001"], "ids_more": 0}]}
    return report


def _kinds():
    """One report per thing the letter used to say, each carrying letters that would be
    recognised if they were printed."""
    clean, capped = _report(), _report(confirmed=[_critical()])
    assert (clean["summary"]["overall_grade"], capped["summary"]["overall_grade"]) == ("S", "D")
    assert capped["summary"]["grade_cap"]["note"] == "capped from A by 1 confirmed CRITICAL"
    no_health = _with(clean, overall_grade=None, provisional_grade=None)
    no_health["summary"]["health"] = dict(clean["summary"]["health"], score=None)
    legacy = _with(clean, overall_grade="ZQXA")
    del legacy["summary"]["health"]
    # No score and coverage not certified: an old report, or one nothing was measured
    # for. 545 of the suite's reports are of this kind (seat review of #3796).
    unscored = _with(legacy, overall_grade=None, provisional_grade=None,
                     coverage_certified=False, gate="PASS")
    kinds = {
        "certified": _with(clean, overall_grade="ZQXA"),
        "capped": _with(capped, overall_grade="ZQXD", grade_cap=dict(
            capped["summary"]["grade_cap"], band_grade="ZQXB", grade="ZQXD",
            note="capped from ZQXB by 1 confirmed CRITICAL")),
        "provisional": _with(clean, overall_grade=None, provisional_grade="ZQXP",
                             grade_shortfalls=[SHORTFALL]),
        "provisional and capped": _with(
            capped, overall_grade=None, provisional_grade="ZQXP", grade_shortfalls=[SHORTFALL],
            grade_cap=dict(capped["summary"]["grade_cap"], band_grade="ZQXB",
                           note="capped from ZQXB by 1 confirmed CRITICAL")),
        "held back by its profile": _with(
            clean, overall_grade=None, provisional_grade="ZQXP",
            coverage_note=grading_mod.PROVISIONAL_PREFIX + "a custom scan profile"),
        "not certified": _with(clean, overall_grade="ZQXA", coverage_certified=False,
                               gate="INCONCLUSIVE", coverage_note="a scanner did not run"),
        "no reviewed lines": no_health,
        "a report from before health": legacy,
        "no score and not certified": unscored,
        "no score and held back": _with(legacy, overall_grade=None, provisional_grade="ZQXP",
                                        grade_shortfalls=[SHORTFALL]),
    }
    return {kind: _every_optional_section(report) for kind, report in kinds.items()}


KINDS = _kinds()


def _page_text(page):
    """What a person reads on the page: the markup, styles and scripts taken out."""
    page = re.sub(r"(?s)<(script|style)\b.*?</\1>", " ", page)
    return html_lib.unescape(re.sub(r"<[^>]+>", " ", page))


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_no_surface_a_person_reads_shows_a_letter_grade(kind):
    report = KINDS[kind]
    said = render_mod.render_summary(report)
    page = html_report.render(report)
    for label, text in (("terminal", said), ("page", page)):
        assert "ZQX" not in text, (kind, label)
        assert "capped from" not in text, (kind, label)
    assert not GRADE_WORD.search(said), (kind, GRADE_WORD.search(said))
    assert not LETTER_WORD.search(said), kind
    # The whole page, markup and styles included: no `badge grade`, no `provisional-grade`.
    assert not GRADE_WORD.search(page), (kind, GRADE_WORD.search(page))
    assert not LETTER_WORD.search(_page_text(page)), kind


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_the_compare_panel_shows_no_letter_either(kind):
    page = html_report.render(KINDS["certified"], compare_report=KINDS[kind])
    assert "ZQX" not in page and not GRADE_WORD.search(page)


def _headline(said):
    return said.splitlines()[2]


@pytest.mark.parametrize("kind", ["certified", "capped", "not certified"])
def test_the_headline_leads_with_the_score(kind):
    report = KINDS[kind]
    score = report["summary"]["health"]["score"]
    headline = _headline(render_mod.render_summary(report))
    assert headline.startswith("**Health:** %s / 100  **Risk:** " % score), headline
    assert "**Gate:** %s" % report["summary"]["gate"] in headline
    assert "provisional" not in headline
    page = html_report.render(report)
    badges = page[page.index("<div class='badges'>"):]
    assert badges.index("Health: %s / 100" % score) < badges.index("Risk:") < badges.index("Gate:")


@pytest.mark.parametrize("summary, held", [
    ({"overall_grade": None, "provisional_grade": "C"}, True),
    ({"provisional_grade": "C"}, True),
    ({"overall_grade": "B", "provisional_grade": None}, False),
    # A letter that is certified is not held back, whatever else the summary carries.
    ({"overall_grade": "B", "provisional_grade": "C"}, False),
    # No letter of either kind is nothing held back: there was no result to hold.
    ({"overall_grade": None, "provisional_grade": None}, False),
    ({}, False),
])
def test_held_back_is_a_provisional_letter_with_no_certified_one(summary, held):
    assert render_mod.held_back(summary) is held
    report = _with(KINDS["certified"], **{"overall_grade": None, "provisional_grade": None,
                                          **summary})
    headline = _headline(render_mod.render_summary(report))
    assert ("(provisional)" in headline) is held, headline


def test_the_compare_panel_leads_with_the_score_too():
    other = KINDS["provisional"]
    page = html_report.render(KINDS["certified"], compare_report=other)
    panel = page[page.index('<div class="compare-panel">'):]
    assert '<span class="badge health">Health: %s / 100 (provisional; %s)</span>' % (
        other["summary"]["health"]["score"], SHORTFALL) in panel


def test_a_capped_report_still_names_its_worst_severity():
    """The cap sentence is gone with the letter; Risk says what it said."""
    report = KINDS["capped"]
    assert "**Risk:** CRITICAL" in _headline(render_mod.render_summary(report))
    assert "Risk: CRITICAL" in html_report.render(report)


@pytest.mark.parametrize("kind", ["provisional", "provisional and capped"])
def test_a_held_back_result_says_provisional_and_why_beside_the_score(kind):
    report = KINDS[kind]
    score = report["summary"]["health"]["score"]
    headline = _headline(render_mod.render_summary(report))
    assert headline.startswith("**Health:** %s / 100 (provisional; %s)  **Risk:** "
                               % (score, SHORTFALL)), headline
    page = _page_text(html_report.render(report))
    assert "Health: %s / 100 (provisional; %s)" % (score, SHORTFALL) in page


def test_a_result_held_back_by_its_profile_says_so_on_its_own_line():
    report = KINDS["held back by its profile"]
    said = render_mod.render_summary(report)
    note = report["summary"]["coverage_note"]
    assert _headline(said).startswith("**Health:** %s / 100 (provisional)  "
                                      % report["summary"]["health"]["score"])
    # The label says "provisional" once; the note's own prefix is not repeated after it.
    assert "**Health provisional:** a custom scan profile" in said.splitlines()
    assert "provisional: health provisional" not in said
    page = html_report.render(report)
    assert "<div class='provisional-health'>%s</div>" % html_lib.escape(note) in page


def test_only_a_leading_prefix_is_left_off_the_provisional_line():
    """A note that names another reason first keeps every word: "health provisional"
    in the middle of it is part of what it says."""
    note = "an earlier reason; " + grading_mod.PROVISIONAL_PREFIX + "a custom scan profile"
    report = _with(KINDS["held back by its profile"], coverage_note=note)
    assert "**Health provisional:** " + note in render_mod.render_summary(report).splitlines()


def test_the_provisional_line_is_inert_in_the_terminal_and_escaped_on_the_page():
    note = grading_mod.PROVISIONAL_PREFIX + "a\x1b[2Jb <script>x</script>\nc"
    report = _with(KINDS["held back by its profile"], coverage_note=note)
    said = render_mod.render_summary(report)
    assert "\x1b" not in said
    assert "**Health provisional:** a\\x1b[2Jb <script>x</script> c" in said.splitlines()
    page = html_report.render(report)
    assert "<script>x</script>" not in page
    assert "<div class='provisional-health'>%s</div>" % html_lib.escape(note) in page


def test_a_page_whose_coverage_is_not_certified_marks_the_score_provisional():
    """As the page's letter was: `provisional` beside it whenever coverage is not certified."""
    report = KINDS["not certified"]
    page = _page_text(html_report.render(report))
    assert "Health: %s / 100 (provisional)" % report["summary"]["health"]["score"] in page
    assert "NOT CERTIFIED" in page


def test_a_shortfall_reason_is_made_inert_beside_the_score():
    report = _with(KINDS["provisional"], grade_shortfalls=["a\x1b[2Jb <b>c</b>"])
    headline = _headline(render_mod.render_summary(report))
    assert "\x1b" not in headline and "(provisional; a" in headline
    page = html_report.render(report)
    assert "<b>c</b>" not in page and "&lt;b&gt;c&lt;/b&gt;" in page


@pytest.mark.parametrize("kind, terminal, page_badge", [
    # Not certified: the page's badge said "(provisional)" for the letter and still does.
    ("no score and not certified", "**Health:** n/a  **Risk:** ", "Health: n/a (provisional)"),
    ("no score and held back", "**Health:** n/a (provisional; %s)  **Risk:** " % SHORTFALL,
     "Health: n/a (provisional; %s)" % SHORTFALL),
])
def test_a_held_back_report_with_no_score_still_says_provisional(kind, terminal, page_badge):
    """Seat review of #3796: `n/a` alone read as settled. On the compare panel the
    badge is the only sign, since that panel has no NOT CERTIFIED line."""
    report = KINDS[kind]
    assert _headline(render_mod.render_summary(report)).startswith(terminal)
    assert "<span class='badge health'>%s</span>" % page_badge in html_report.render(report)
    page = html_report.render(KINDS["certified"], compare_report=report)
    panel = page[page.index('<div class="compare-panel">'):]
    assert '<span class="badge health">%s</span>' % page_badge in panel
    assert "Gate: %s" % report["summary"]["gate"] in panel


@pytest.mark.parametrize("kind", ["no reviewed lines", "a report from before health"])
def test_a_report_with_no_score_says_so_and_invents_none(kind):
    report = KINDS[kind]
    said = render_mod.render_summary(report)
    assert _headline(said).startswith("**Health:** n/a  **Risk:** "), _headline(said)
    page = _page_text(html_report.render(report))
    assert "Health: n/a" in page and "/ 100" not in page
    if kind == "no reviewed lines":
        assert "**Health:** n/a (no reviewed lines of code to measure against)" in said.splitlines()


def test_the_basis_line_is_the_scores():
    report = KINDS["certified"]
    said = render_mod.render_summary(report)
    assert "**Health basis:** %s" % health_basis.rendered_note(
        report["summary"]["health"]) in said.splitlines()


# ---- the groups section: the worst severity, not a letter ---------------------------------

def test_each_panel_of_a_group_shows_its_worst_severity():
    report = KINDS["capped"]
    assert report["groups"][0]["panel_grades"]["security"] == "F"
    said = render_mod.render_summary(report)
    assert ("- **g1** — code none / test none / security CRITICAL / architecture none / "
            "database none / redteam none") in said.splitlines()


def test_the_worst_severity_is_read_back_from_the_stored_letter():
    """The JSON keeps `panel_grades`; the words come from the same table `grade` assigns by."""
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        letter = grading_mod.grade([{"severity": severity}])
        assert grading_mod.worst_severity_of(letter) == severity
    for nothing in ([], [{"severity": "INFO"}]):
        assert grading_mod.worst_severity_of(grading_mod.grade(nothing)) == "none"
    for unknown in ("S", "X", "Z", "", None, 3, ["F"], "f"):
        assert grading_mod.worst_severity_of(unknown) == "unknown"


def test_a_group_whose_stored_letters_cannot_be_read_says_unknown():
    report = copy.deepcopy(KINDS["certified"])
    report["groups"][0]["panel_grades"] = {"code": "ZQXG", "security": "D"}
    said = render_mod.render_summary(report)
    line = next(line for line in said.splitlines() if line.startswith("- **g1**"))
    assert line == ("- **g1** — code unknown / test unknown / security HIGH / "
                    "architecture unknown / database unknown / redteam unknown")


@pytest.mark.parametrize("stored", [None, "F", ["F"], 3])
def test_a_group_with_no_stored_letters_still_renders(stored):
    report = copy.deepcopy(KINDS["certified"])
    if stored is None:
        del report["groups"][0]["panel_grades"]
    else:
        report["groups"][0]["panel_grades"] = stored
    line = next(line for line in render_mod.render_summary(report).splitlines()
                if line.startswith("- **g1**"))
    assert line.count("unknown") == len(findings_mod.PANEL_ORDER)


# ---- the coverage note on a certified run ----------------------------------------------------

JS = ("javascript not audited: no npm-shrinkwrap.json, package-lock.json, yarn.lock or "
      "pnpm-lock.yaml; npm-audit and osv-scanner need one")


def test_a_certified_run_shows_its_coverage_note():
    """#3648: a certified report can carry a note (an ecosystem with nothing to audit),
    and only the JSON showed it."""
    report = _with(KINDS["certified"], coverage_note=JS)
    assert report["summary"]["coverage_certified"] is True
    assert "**Coverage note:** %s" % JS in render_mod.render_summary(report).splitlines()
    assert "<div class='coverage-note'>Coverage note: %s</div>" % html_lib.escape(JS) in (
        html_report.render(report))


@pytest.mark.parametrize("note", [None, "", [], 0, ["a note"], {"note": "a"}, 7, True])
def test_no_note_no_line(note):
    report = _with(KINDS["certified"], coverage_note=note)
    assert "Coverage note" not in render_mod.render_summary(report)
    assert "Coverage note" not in html_report.render(report)


@pytest.mark.parametrize("kind", ["not certified", "held back by its profile"])
def test_the_note_is_said_once_where_another_line_already_carries_it(kind):
    report = KINDS[kind]
    note = report["summary"]["coverage_note"]
    said = render_mod.render_summary(report)
    page = html_report.render(report)
    assert "Coverage note" not in said and "Coverage note" not in page
    # The terminal's provisional line drops the note's own "health provisional: ".
    reason = note[len(grading_mod.PROVISIONAL_PREFIX):] if note.startswith(
        grading_mod.PROVISIONAL_PREFIX) else note
    assert said.count(reason) == 1 and page.count(html_lib.escape(note)) == 1


def test_the_note_is_made_inert_on_both_surfaces():
    report = _with(KINDS["certified"], coverage_note="a\x1b[2Jb <script>x</script>")
    said = render_mod.render_summary(report)
    assert "\x1b" not in said and "**Coverage note:** a" in said
    page = html_report.render(report)
    assert "<script>x</script>" not in page and "\x1b" not in page
    assert "Coverage note: a\\x1b[2Jb &lt;script&gt;" in page


# ---- the JSON keeps the letter ------------------------------------------------------------------

def test_the_report_json_keeps_every_letter_field_with_its_value():
    clean, capped = _report(), _report(confirmed=[_critical()])
    assert (clean["summary"]["overall_grade"], clean["summary"]["provisional_grade"],
            clean["summary"]["grade_cap"]) == ("S", None, None)
    assert capped["summary"]["overall_grade"] == "D"
    assert capped["summary"]["grade_cap"] == {
        "band_grade": "A", "grade": "D", "severity": "CRITICAL", "count": 1,
        "note": "capped from A by 1 confirmed CRITICAL"}
    assert capped["groups"][0]["panel_grades"] == {
        "code": "A", "test": "A", "security": "F", "architecture": "A", "database": "A",
        "redteam": "A"}
    assert "grade_shortfalls" in capped["summary"]
    for report in (clean, capped):
        assert validate_schema_mod.schema_errors(report) == []


def test_the_schema_says_the_letter_fields_are_not_shown_and_go_in_5_6():
    summary = validate_schema_mod._report_doc()["properties"]["summary"]["properties"]
    for field in ("overall_grade", "provisional_grade", "grade_cap"):
        assert field in summary
        assert "5.6" in summary[field]["description"], field


# ---- the sentences that are stored, and printed ------------------------------------------------

def test_stored_sentences_say_health_where_they_said_grade():
    assert grading_mod.PROVISIONAL_PREFIX == "health provisional: "
    for sentence in (grading_mod.PROVISIONAL_PREFIX, grading_mod.GATE_GAP_NOTE,
                     coverage_io.REVIEW_MATRIX_MISSING_NOTE, health_basis.PROFILE_REASON,
                     health_basis.EXCLUDE_REASON, health_basis.LEGACY_NOTE):
        assert not GRADE_WORD.search(sentence), sentence
        assert not LETTER_WORD.search(sentence), sentence


@pytest.mark.parametrize("kwargs", [
    {"panels_incomplete": {"test"}},
    {"panels_incomplete": {"security"}, "shortfalls": [SHORTFALL]},
    {"custom_profile": "this scan used a non-default group size."},
    {"custom_profile": ["one reason.", "another reason."], "tools_absent": {"bandit"}},
    {"shortfalls": [SHORTFALL]},
    {"panels_incomplete": {"test"}, "custom_profile": "a reason."},
    {"dependency_audit_gap": True, "custom_profile": "a reason."},
    {"tools_manifest_invalid": "torn"},
])
def test_no_coverage_note_says_grade(kwargs):
    kwargs = dict(kwargs)
    cert = grading_mod.certify("B", [], "high", kwargs.pop("panels_incomplete", set()),
                               kwargs.pop("tools_absent", set()), **kwargs)
    note = cert["coverage_note"]
    assert note and not GRADE_WORD.search(note) and not LETTER_WORD.search(note), note


def test_a_low_value_panel_gap_reads_health_provisional():
    cert = grading_mod.certify("B", [], "high", {"test"}, set())
    assert cert["coverage_note"] == (
        "gate certified; health provisional — low-value panel(s) incomplete: test")
    assert (cert["overall_grade"], cert["provisional_grade"]) == (None, "B")


def test_the_lines_about_what_counts_do_not_name_a_grade():
    assert not GRADE_WORD.search(render_mod._context_not_gated_line({"test-path": 2}))
    gated = render_mod._suppressed_gated_line({"vendored": 1})
    assert gated and not GRADE_WORD.search(gated)


def test_the_pages_lines_about_what_counts_do_not_name_a_grade():
    report = copy.deepcopy(KINDS["certified"])
    report["meta"]["coverage"]["tools_context_not_gated"] = {"test-path": 2}
    report["meta"]["coverage"]["tools_suppressed_gated"] = {"vendored": 1}
    page = html_report.render(report)
    assert "Not counted toward the gate: 2 scanner findings" in page
    assert "Tool findings suppressed but GATED" in page
    assert not GRADE_WORD.search(page), GRADE_WORD.search(page)


def test_the_command_line_help_does_not_promise_grades():
    import scripts.synthesize as synthesize
    text = synthesize.build_parser().format_help()
    assert "--gate-unverified" in text and not GRADE_WORD.search(text), GRADE_WORD.search(text)

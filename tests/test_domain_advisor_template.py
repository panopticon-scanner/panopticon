import pytest

import scripts.dispatch as dispatch


def test_domain_advisor_is_scoped_write():
    meta, _ = dispatch.load_template("domain-advisor.md")
    assert meta["tool_policy"]["allowed"] == ["Read", "Grep", "Glob", "Write"]
    assert meta["tool_policy"]["forbidden"] == ["Bash", "Edit", "Agent"]


def test_domain_advisor_writes_bundle_to_out_file():
    _, body = dispatch.load_template("domain-advisor.md")
    assert "{out_file}" in body  # self-writes its bundle
    assert body.count("## Output") == 1  # one authoritative write instruction
    assert "verdicts" in body and "_panopticon" in body and "finding_id" in body


def test_domain_advisor_renders_with_driver_mapping():
    prompt = dispatch.render_prompt(
        "domain-advisor.md",
        {
            "domain": "SEC",
            "group": "app",
            "file_list": "- a.py",
            "findings": "[]",
            "menu": "SEC-A1A n (HIGH)",
            "criteria": "SEC-A1A n — qualifies when X",  # #1035
            "run_id": "RID",
            "stage": "primary",
            "out_file": "/abs/verdicts-app-SEC.json",
        },
        "claude",
    )
    assert "SEC" in prompt and "RID" in prompt and "/abs/verdicts-app-SEC.json" in prompt
    assert "{" + "out_file}" not in prompt  # placeholder fully substituted


def test_domain_advisor_renders_criteria_lens():  # #1035
    _, body = dispatch.load_template("domain-advisor.md")
    assert "{criteria}" in body  # the lens placeholder exists
    prompt = dispatch.render_prompt(
        "domain-advisor.md",
        {
            "domain": "SEC",
            "group": "app",
            "file_list": "- a.py",
            "findings": "[]",
            "menu": "SEC-A1A n (HIGH)",
            "criteria": "SEC-A1A n — qualifies when the sentinel CRITERIONTEXT holds",
            "run_id": "RID",
            "stage": "primary",
            "out_file": "/abs/verdicts-app-SEC.json",
        },
        "claude",
    )
    assert "CRITERIONTEXT" in prompt  # criteria block is rendered
    assert "explicit grading criteria" in prompt.lower()  # the lens section header


def test_domain_advisor_missing_placeholder_raises():
    # render_prompt is fail-fast: omitting a required placeholder is an error
    # rather than a silent partial render (#1196).
    with pytest.raises(ValueError, match="no value for placeholder"):
        dispatch.render_prompt(
            "domain-advisor.md",
            {"domain": "SEC", "group": "app"},  # many required keys missing
            "claude",
        )


def test_domain_advisor_renders_unknown_domain():
    # The template does not validate the domain value; it is substituted as-is
    # into the prompt (#1196).
    prompt = dispatch.render_prompt(
        "domain-advisor.md",
        {
            "domain": "UNKNOWN",
            "group": "app",
            "file_list": "- a.py",
            "findings": "[]",
            "menu": "UNKNOWN-A1A n (HIGH)",
            "criteria": "UNKNOWN-A1A n — qualifies when X",
            "run_id": "RID",
            "stage": "primary",
            "out_file": "/abs/verdicts-app-UNKNOWN.json",
        },
        "claude",
    )
    assert "UNKNOWN" in prompt
    assert "/abs/verdicts-app-UNKNOWN.json" in prompt


def test_load_unknown_template_raises():
    with pytest.raises(ValueError, match="template not found"):
        dispatch.load_template("does-not-exist.md")

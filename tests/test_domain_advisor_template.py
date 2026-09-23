import json
import re
from pathlib import Path

import pytest

import scripts.dispatch as dispatch


@pytest.mark.parametrize("role_file", ["advisor.md", "domain-advisor.md"])
def test_scoped_advisor_verdict_matches_published_schema(role_file):
    values = {"claim_json": "{}"} if role_file == "advisor.md" else {
        "domain": "SEC", "group": "app", "file_list": "- a.py",
        "findings": "[]", "menu": "SEC-A1A n (HIGH)",
        "criteria": "SEC-A1A n — qualifies when X", "run_id": "RID",
        "stage": "primary", "out_file": "/abs/verdicts-app-SEC.json",
    }
    prompt = dispatch.render_prompt(role_file, values, "claude")
    scope_fence = re.search(
        r"Scope fence \(host-enforced\).*?(?=\n## |\Z)", prompt, re.DOTALL | re.IGNORECASE
    )
    assert scope_fence is not None
    verdict = re.search(r"\bis `([A-Z_]+)`", scope_fence.group())
    assert verdict is not None
    schema_path = Path(__file__).resolve().parents[1] / "skill/reference/advisor-verdict-schema.json"
    verdict_enum = json.loads(schema_path.read_text(encoding="utf-8"))["properties"]["verdict"]["enum"]
    assert verdict.group(1) in verdict_enum
    assert verdict.group(1) == "NEEDS_MORE_INFO"
    assert "reasoning" in scope_fence.group()


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


def test_domain_advisor_is_told_to_record_the_evidence_scope():
    # #1638 P16 ruling 2: the driver records the grant in the prompt; the
    # advisor copies it into every verdict, and names what it could not reach
    # rather than returning a bare NEEDS_MORE_INFO the pipeline reads as a
    # refutation.
    _, body = dispatch.load_template("domain-advisor.md")
    assert "Evidence granted for this check (bounded closure)" in body
    assert "evidence_scope" in body
    assert "missing_evidence" in body
    assert "verbatim" in body

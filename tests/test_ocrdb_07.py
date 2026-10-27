"""OCRDb 0.7 guide/range compatibility without changing the shipped bundle.

The fixture is the byte-identical ``tools/build_bundle.py`` output from OCRDb
commit d5221444229a2af8b73c4ae80c0d75e36a56d0b4 (SHA-256 999f73112e73b77d),
the coordinator-pinned 0.7 schema snapshot for #3330.
"""

import hashlib
import json
from pathlib import Path

from scripts import dispatch, ocrdb
from scripts.phases import review, verify


FIXTURE = Path(__file__).parent / "fixtures" / "ocrdb-0.7.0-dev.json"


def _bundle_07():
    with FIXTURE.open(encoding="utf-8") as fh:
        return json.load(fh)


def test_vendored_06_tst_menu_is_byte_for_byte_legacy():
    """#3330: a pre-guide bundle keeps the exact menu reviewers see today."""
    bundle = ocrdb.load_bundle()
    assert bundle is not None
    assert bundle["version"] == "0.6.0"
    rendered = review._render_menu(bundle, "TST")
    assert len(rendered) == 3759
    assert rendered.count("\n") + 1 == 76
    assert hashlib.sha256(rendered.encode()).hexdigest() == (
        "252ed791a4a6efc2a6f1f33788285024a8bcd7dc2ef0dfcdcfd788a1a698bcad"
    )


def test_07_tst_guides_render_top_down_before_all_76_codes():
    bundle = _bundle_07()
    rendered = review._render_menu(bundle, "TST")
    domain = "Domain guide — " + bundle["domains"]["TST"]["guide"]
    area = bundle["domains"]["TST"]["areas"]["A"]
    area_line = "Area A coverage — " + area["guide"]
    category_line = "Category A1 untested-units — " + area["category_guides"]["1"]
    entry_line = "TST-A1A zero-coverage-script (default HIGH; permitted LOW..HIGH)"
    assert rendered.index(domain) < rendered.index(area_line)
    assert rendered.index(area_line) < rendered.index(category_line)
    assert rendered.index(category_line) < rendered.index(entry_line)

    codes = list(bundle["domains"]["TST"]["entries"])
    assert len(codes) == 76
    lines = rendered.splitlines()
    assert all(sum(line.startswith(code + " ") for line in lines) == 1 for code in codes)


def test_07_menu_names_ranges_and_citable_conditions():
    bundle = _bundle_07()
    rendered = review._render_menu(bundle, "TST")
    severity_range = bundle["domains"]["TST"]["entries"]["TST-A2E"][
        "severity_range"
    ]
    assert "TST-A2E single-case-enum-mapping-coverage (default LOW; permitted INFO..MEDIUM)" in rendered
    assert (
        "lower_when[0] -> INFO — " + severity_range["lower_when"][0]["condition"]
        in rendered
    )
    assert (
        "raise_when[0] -> MEDIUM — " + severity_range["raise_when"][0]["condition"]
        in rendered
    )
    assert ocrdb.severity_range(bundle, "TST-A2E") == severity_range
    assert ocrdb.severity_range(ocrdb.load_bundle(), "TST-A2E") is None


def test_advisor_receives_the_panel_rung_and_grades_its_condition():
    bundle = _bundle_07()
    finding = {
        "id": "TST-1",
        "code": "TST-A1D",
        "severity": "MEDIUM",
        "title": "flag is untested",
        "category": "coverage",
        "description": "the enforcement flag is not exercised",
        "location": {"file": "tests/test_cli.py", "line_start": 10},
        "severity_override": {
            "from": "LOW",
            "to": "MEDIUM",
            "reason": "the flag controls an enforcement mode",
            "rung": "raise_when[0]",
        },
    }
    rendered_claim = json.loads(verify._render_findings("/repo", [finding]))[0]
    assert rendered_claim["severity_override"]["rung"] == "raise_when[0]"

    entry = verify._verify_entry(
        "/repo",
        {"run_id": "R", "host": "claude"},
        "tests",
        "TST",
        ["tests/test_cli.py"],
        [finding],
        "claude",
        bundle,
        "primary",
    )
    assert "raise_when[0]" in entry["prompt"]
    assert "condition actually holds" in entry["prompt"]


def test_panel_prompt_requires_citable_rungs_and_controlled_modifiers():
    template = dispatch.load_template("domain-panel.md")[1]
    assert '"rung": "raise_when[0]"' in template
    assert "test-or-fixture-scope" in template
    assert "criteria win" in template

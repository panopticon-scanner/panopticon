"""OCRDb 0.7 guide/range compatibility without changing the shipped bundle.

The fixture is the byte-identical ``tools/build_bundle.py`` output from OCRDb
commit d5221444229a2af8b73c4ae80c0d75e36a56d0b4 (SHA-256 999f73112e73b77d),
the coordinator-pinned 0.7 schema snapshot for #3330.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from unittest import mock

from scripts import dispatch, ocrdb
from scripts.phases import review, runio, verify


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


def test_07_tst_prompt_keeps_only_the_domain_guide_before_all_76_codes():
    bundle = _bundle_07()
    rendered = review._render_menu(bundle, "TST")
    domain = "Domain guide — " + bundle["domains"]["TST"]["guide"]
    area = bundle["domains"]["TST"]["areas"]["A"]
    area_line = "Area A coverage — " + area["guide"]
    category_line = "Category A1 untested-units — " + area["category_guides"]["1"]
    entry_line = "TST-A1A zero-coverage-script (default HIGH; permitted LOW..HIGH)"
    assert rendered.index(domain) < rendered.index(entry_line)
    assert area_line not in rendered
    assert category_line not in rendered

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


def test_07_guide_tsv_is_deterministic_one_record_per_line_and_all_domain():
    bundle = _bundle_07()
    first = ocrdb.render_guide_tsv(bundle)
    second = ocrdb.render_guide_tsv(copy.deepcopy(bundle))
    assert first == second
    assert first is not None
    lines = first.splitlines()
    assert first.endswith("\n")
    assert lines
    assert all(line and line.count("\t") in (3, 4) for line in lines)
    assert [line.split("\t", 1)[0] for line in lines
            if line.split("\t", 2)[1] == "domain"] == sorted(bundle["domains"])
    assert {line.split("\t", 1)[0] for line in lines
            if line.split("\t", 2)[1] == "domain"} == set(bundle["domains"])


def test_07_guide_tsv_collapses_embedded_tabs_and_newlines_without_wrapping():
    bundle = copy.deepcopy(_bundle_07())
    bundle["domains"]["TST"]["guide"] = "first\nsecond\tthird"
    bundle["domains"]["TST"]["areas"]["F"]["category_guides"]["1"] = (
        "timeouts\r\n retries\tand clocks"
    )
    rendered = ocrdb.render_guide_tsv(bundle)
    assert rendered is not None
    rows = rendered.splitlines()
    domain = next(row for row in rows if row.startswith("TST\tdomain\t"))
    category = next(row for row in rows if row.startswith("TST-F1\tcategory\t"))
    assert domain.endswith("\tfirst second third")
    assert category.endswith("\ttimeouts retries and clocks")
    assert all(row.count("\t") in (3, 4) for row in rows)


def test_07_guide_tsv_supports_prefix_subtree_and_cross_domain_grep_shapes():
    rendered = ocrdb.render_guide_tsv(_bundle_07())
    assert rendered is not None
    rows = rendered.splitlines()
    subtree = [row for row in rows if row.startswith("TST-F1")]
    assert subtree[0].startswith("TST-F1\tcategory\t")
    assert any(row.startswith("TST-F1A\tcode\t") for row in subtree)
    timeout_domains = {row.split("-", 1)[0].split("\t", 1)[0]
                       for row in rows if "timeout" in row.lower()}
    assert {"AGT", "COD", "OPS", "SEC", "TST"} <= timeout_domains


def test_07_guide_tsv_sorts_areas_categories_numerically_and_codes():
    bundle = {"domains": {"TST": {
        "name": "testing",
        "guide": "domain",
        "areas": {
            "B": {"name": "later", "guide": "later", "categories": {},
                  "category_guides": {}},
            "A": {"name": "first", "guide": "first",
                  "categories": {"10": "ten", "2": "two"},
                  "category_guides": {"10": "ten guide", "2": "two guide"}},
        },
        "entries": {
            "TST-A2B": {"name": "second-code", "default_severity": "LOW",
                         "severity_range": {"floor": "INFO", "ceiling": "LOW"}},
            "TST-A10A": {"name": "tenth", "default_severity": "MEDIUM",
                          "severity_range": {"floor": "LOW", "ceiling": "HIGH"}},
            "TST-A2A": {"name": "first-code", "default_severity": "LOW",
                         "severity_range": {"floor": "INFO", "ceiling": "LOW"}},
        },
    }}}
    rendered = ocrdb.render_guide_tsv(bundle)
    assert rendered is not None
    assert [row.split("\t", 1)[0] for row in rendered.splitlines()] == [
        "TST", "TST-A", "TST-A2", "TST-A2A", "TST-A2B",
        "TST-A10", "TST-A10A", "TST-B",
    ]


def test_07_code_rows_are_compact_and_omit_criteria_but_keep_cross_references():
    rendered = ocrdb.render_guide_tsv(_bundle_07())
    assert rendered is not None
    row = next(line for line in rendered.splitlines()
               if line.startswith("ACC-A1A\tcode\t"))
    assert row.split("\t") == [
        "ACC-A1A",
        "code",
        "Icon only control missing accessible name",
        "HIGH (MEDIUM-HIGH)",
        "see_also: ACC-A1B, ACC-B1A, ACC-C1A, LNG-A1A",
    ]
    criteria = _bundle_07()["domains"]["ACC"]["entries"]["ACC-A1A"]["criteria"]
    assert criteria not in row


def test_06_has_no_guide_document_or_pointer(tmp_path):
    bundle = ocrdb.load_bundle()
    assert ocrdb.render_guide_tsv(bundle) is None
    absent = tmp_path / "ocrdb-guide.tsv"
    rendered = review._render_menu(bundle, "TST", str(absent))
    assert "ocrdb-guide.tsv" not in rendered
    assert "grep '^TST-F1'" not in rendered


def test_07_pointer_requires_the_document_and_immediately_follows_domain_guide(tmp_path):
    bundle = _bundle_07()
    guide = tmp_path / "ocrdb-guide.tsv"
    without = review._render_menu(bundle, "TST", str(guide))
    assert "grep '^TST-F1'" not in without
    guide.write_text(ocrdb.render_guide_tsv(bundle), encoding="utf-8")
    rendered = review._render_menu(bundle, "TST", str(guide))
    lines = rendered.splitlines()
    domain_index = next(i for i, line in enumerate(lines)
                        if line.startswith("Domain guide — "))
    pointer_index = next(i for i, line in enumerate(lines)
                         if "ocrdb-guide.tsv" in line)
    assert pointer_index == domain_index + 1
    assert "grep '^TST-F1'" in rendered
    assert "grep -i 'timeout'" in rendered
    assert "Before choosing between close codes or citing outside TST" in rendered


def test_07_run_guide_is_written_once_and_granted_to_panel_and_advisor():
    bundle = _bundle_07()
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, ".panopticon"))
        with mock.patch("scripts.phases.review.safe_write.write_text",
                        wraps=review.safe_write.write_text) as writer:
            guide = review._ensure_ocrdb_guide(root, bundle)
            assert review._ensure_ocrdb_guide(root, bundle) == guide
        assert writer.call_count == 1
        assert guide == os.path.abspath(runio._pano(root, "ocrdb-guide.tsv"))

        manifest = {"run_id": "R", "host": "claude", "security_mode": "standard"}
        panel = review._cell_entry(
            root, manifest, "tests", "TST", [], [], "claude", bundle,
            inventory=("complete", "inventory complete"), guide_path=guide,
        )
        advisor = verify._verify_entry(
            root, manifest, "tests", "TST", [], [], "claude", bundle,
            "primary", guide_path=guide,
        )
        for entry in (panel, advisor):
            assert guide in entry["scope"]["reads"]
            assert guide in entry["prompt"]


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
    assert "linked all-domain routing guide" in template
    advisor = dispatch.load_template("domain-advisor.md")[1]
    assert "linked all-domain routing guide" in advisor

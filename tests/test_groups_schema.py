# tests/test_groups_schema.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skill", "scripts"))
import groups_schema as gs

def test_parses_full_group():
    doc = {"groups": {"Checkout": {
        "match": ["src/checkout/**"], "tests": ["tests/checkout/**"],
        "panels": ["SEC", "DAT", "ACC"], "exclude": ["OPS"]}}}
    groups, errors = gs.parse_groups(doc)
    assert errors == []
    g = groups["Checkout"]
    assert g["match"] == ["src/checkout/**"]
    assert g["tests"] == ["tests/checkout/**"]
    assert g["floor"] == {"SEC", "DAT", "ACC"}
    assert g["exclude"] == {"OPS"}

def test_defaults_missing_optionals():
    groups, errors = gs.parse_groups({"groups": {"G": {"match": ["a/**"]}}})
    assert errors == []
    assert groups["G"]["tests"] == [] and groups["G"]["floor"] == set()
    assert groups["G"]["exclude"] == set()

def test_unknown_domain_is_error():
    doc = {"groups": {"G": {"match": ["a/**"], "panels": ["ZZZ"]}}}
    _g, errors = gs.parse_groups(doc)
    assert any("ZZZ" in e and "domain" in e for e in errors)

def test_floor_and_exclude_overlap_is_error():
    doc = {"groups": {"G": {"match": ["a/**"], "panels": ["SEC"], "exclude": ["SEC"]}}}
    _g, errors = gs.parse_groups(doc)
    assert any("SEC" in e and "both floor and exclude" in e for e in errors)

def test_empty_match_is_error():
    _g, errors = gs.parse_groups({"groups": {"G": {"match": []}}})
    assert any("match" in e for e in errors)

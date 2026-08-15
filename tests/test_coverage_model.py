# tests/test_coverage_model.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skill", "scripts"))
import coverage_model as cov

def test_floor_always_on():
    eff, disc = cov.effective_panels({"SEC", "DAT"}, set(), set())
    assert eff == {"SEC", "DAT"}
    assert disc["floor"] == ["DAT", "SEC"]

def test_scout_widens_the_middle():
    eff, _ = cov.effective_panels({"SEC"}, {"ACC"}, set())
    assert eff == {"SEC", "ACC"}

def test_exclude_forces_off_and_is_disclosed():
    eff, disc = cov.effective_panels({"SEC"}, {"OPS"}, {"OPS"})
    assert eff == {"SEC"}                 # OPS excluded despite scout adding it
    assert disc["excluded"] == ["OPS"]
    assert "OPS" not in disc["scout_added"]

def test_disclosure_lists_are_sorted():
    _eff, disc = cov.effective_panels({"DAT", "SEC"}, {"LNG", "ACC"}, set())
    assert disc["scout_added"] == ["ACC", "LNG"]

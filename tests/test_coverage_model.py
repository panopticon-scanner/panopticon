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

def test_floor_exclude_overlap_exclude_wins():
    # upstream validation forbids overlap; coverage_model must still degrade safe
    eff, disc = cov.effective_panels({"SEC", "DAT"}, set(), {"DAT"})
    assert eff == {"SEC"}
    assert disc["excluded"] == ["DAT"]

def test_all_empty_inputs():
    eff, disc = cov.effective_panels(set(), set(), set())
    assert eff == set()
    assert disc == {"floor": [], "scout_added": [], "excluded": []}

def test_excluded_disclosure_sorted_multi():
    _eff, disc = cov.effective_panels({"SEC"}, set(), {"OPS", "ACC"})
    assert disc["excluded"] == ["ACC", "OPS"]

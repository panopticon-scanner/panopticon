# tests/test_coverage_model.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skill", "scripts"))
import coverage_model as cov

# The existing cases isolate the core (floor|scout)-exclude logic by passing
# global_floor=set(); the global-floor injection is exercised separately below.


def test_floor_always_on():
    eff, disc = cov.effective_panels({"SEC", "DAT"}, set(), set(), global_floor=set())
    assert eff == {"SEC", "DAT"}
    assert disc["floor"] == ["DAT", "SEC"]

def test_scout_widens_the_middle():
    eff, _ = cov.effective_panels({"SEC"}, {"ACC"}, set(), global_floor=set())
    assert eff == {"SEC", "ACC"}

def test_exclude_forces_off_and_is_disclosed():
    eff, disc = cov.effective_panels({"SEC"}, {"OPS"}, {"OPS"}, global_floor=set())
    assert eff == {"SEC"}                 # OPS excluded despite scout adding it
    assert disc["excluded"] == ["OPS"]
    assert "OPS" not in disc["scout_added"]

def test_disclosure_lists_are_sorted():
    _eff, disc = cov.effective_panels({"DAT", "SEC"}, {"LNG", "ACC"}, set(), global_floor=set())
    assert disc["scout_added"] == ["ACC", "LNG"]

def test_floor_exclude_overlap_exclude_wins():
    # upstream validation forbids overlap; coverage_model must still degrade safe
    eff, disc = cov.effective_panels({"SEC", "DAT"}, set(), {"DAT"}, global_floor=set())
    assert eff == {"SEC"}
    assert disc["excluded"] == ["DAT"]

def test_all_empty_inputs():
    eff, disc = cov.effective_panels(set(), set(), set(), global_floor=set())
    assert eff == set()
    assert disc == {"floor": [], "scout_added": [], "excluded": []}

def test_excluded_disclosure_sorted_multi():
    _eff, disc = cov.effective_panels({"SEC"}, set(), {"OPS", "ACC"}, global_floor=set())
    assert disc["excluded"] == ["ACC", "OPS"]


# --- #5.0-11: universal-tier global floor injected by default ---

def test_global_floor_injected_by_default():
    # every group reviews COD/DAT/TST/ARC even with only a vertical committed floor
    eff, disc = cov.effective_panels({"SEC"}, set(), set())
    assert eff == {"SEC", "COD", "DAT", "TST", "ARC"}
    assert set(disc["floor"]) == {"SEC", "COD", "DAT", "TST", "ARC"}

def test_global_floor_present_even_with_empty_floor():
    eff, _ = cov.effective_panels(set(), set(), set())
    assert eff == {"COD", "DAT", "TST", "ARC"}

def test_global_floor_still_subject_to_exclude():
    # a group with no database can opt DAT out
    eff, disc = cov.effective_panels({"SEC"}, set(), {"DAT"})
    assert "DAT" not in eff
    assert eff == {"SEC", "COD", "TST", "ARC"}
    assert disc["excluded"] == ["DAT"]

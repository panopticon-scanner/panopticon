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


# --- #5.0-19: applicable_global_floor surface gate --------------------------

def test_applicable_floor_cod_is_universal():
    # a docs-only, single-dir, testless, db-free group still reviews code
    got = cov.applicable_global_floor(["README.md"],
                                      {"surfaces": [], "has_tests": False})
    assert got == frozenset({"COD"})

def test_applicable_floor_surfaceless_group_drops_dat_tst_arc():
    got = cov.applicable_global_floor(["src/app/page.tsx"],
                                      {"surfaces": ["http_web", "templating"]})
    assert got == frozenset({"COD"})

def test_applicable_floor_keeps_dat_on_all_db_file_hints():
    for hint in cov._DB_FILE_HINTS:
        if hint.startswith("/") and hint.endswith("/"):
            fname = f"src{hint}file.py"
        elif hint.startswith("/"):
            fname = f"src{hint}py"
        else:
            fname = f"src/sub/{hint}"
        got = cov.applicable_global_floor([fname], {"surfaces": []})
        assert "DAT" in got, f"Hint {hint} on {fname} failed to trigger DAT"

def test_applicable_floor_keeps_tst_on_all_test_file_hints():
    for hint in cov._TEST_FILE_HINTS:
        if hint.startswith("/") and hint.endswith("/"):
            fname = f"src{hint}file.py"
        elif hint.startswith("/"):
            fname = f"src{hint}py"
        else:
            fname = f"src/sub/{hint}"
        got = cov.applicable_global_floor([fname], {"surfaces": []})
        assert "TST" in got, f"Hint {hint} on {fname} failed to trigger TST"

def test_applicable_floor_keeps_dat_on_db_file():
    got = cov.applicable_global_floor(["prisma/schema.prisma", "src/lib/db.ts"],
                                      {"surfaces": []})
    assert "DAT" in got

def test_applicable_floor_keeps_dat_on_scout_db_surface():
    # no db-named file, but the scout saw a persistence surface
    got = cov.applicable_global_floor(["src/app/api/x/route.ts"],
                                      {"surfaces": ["db_sql"]})
    assert "DAT" in got

def test_applicable_floor_keeps_tst_on_test_file():
    got = cov.applicable_global_floor(["src/x.ts", "src/x.test.ts"],
                                      {"surfaces": []})
    assert "TST" in got

def test_applicable_floor_keeps_tst_on_scout_has_tests():
    got = cov.applicable_global_floor(["src/x.ts"], {"has_tests": True})
    assert "TST" in got

def test_applicable_floor_no_tests_drops_tst():
    # the dominant calibration win: a testless group spends no TST cell
    got = cov.applicable_global_floor(["src/a.ts", "lib/b.ts"],
                                      {"surfaces": [], "has_tests": False})
    assert "TST" not in got

def test_applicable_floor_keeps_arc_on_multi_directory():
    got = cov.applicable_global_floor(
        ["src/app/api/x/route.ts", "src/lib/session.ts"], {"surfaces": []})
    assert "ARC" in got

def test_applicable_floor_keeps_arc_on_scout_arch_surface():
    got = cov.applicable_global_floor(["README.md", "package.json"],
                                      {"surfaces": ["architecture"]})
    assert "ARC" in got

def test_applicable_floor_single_dir_no_arch_drops_arc():
    got = cov.applicable_global_floor(["src/app/layout.tsx", "src/app/page.tsx"],
                                      {"surfaces": ["http_web"]})
    assert "ARC" not in got

def test_applicable_floor_is_subset_of_global_floor():
    got = cov.applicable_global_floor(
        ["a/x.ts", "b/y.sql", "a/x.test.ts"],
        {"surfaces": ["architecture"], "has_tests": True})
    assert got <= cov.GLOBAL_FLOOR
    assert got == {"COD", "DAT", "TST", "ARC"}   # every surface present

def test_applicable_floor_respects_reduced_global_floor():
    # a caller passing a reduced floor never gets COD back
    got = cov.applicable_global_floor(["x.sql"], {},
                                      global_floor=frozenset({"DAT"}))
    assert got == frozenset({"DAT"})

def test_applicable_floor_tolerates_missing_scout_fields():
    got = cov.applicable_global_floor(["a/x.ts", "b/y.ts"], {})
    assert got == frozenset({"COD", "ARC"})   # 2 dirs -> ARC; no db/tests

def test_applicable_floor_same_dir_pair_drops_arc():
    # two files in one directory is not cross-module structure
    got = cov.applicable_global_floor(["x.ts", "y.ts"], {"surfaces": []})
    assert got == frozenset({"COD"})

# tests/test_coverage_model.py
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skill", "scripts"))
import coverage_model as cov

# The existing cases isolate the core (floor|scout)-exclude logic by passing
# global_floor=set(); the global-floor injection is exercised separately below.


def test_floor_always_on():
    eff, disc = cov.effective_panels({"SEC", "DAT"}, set(), set(), global_floor=set())
    if not (eff == {"SEC", "DAT"}): raise AssertionError()
    if not (disc["floor"] == ["DAT", "SEC"]): raise AssertionError()

def test_scout_widens_the_middle():
    eff, _ = cov.effective_panels({"SEC"}, {"ACC"}, set(), global_floor=set())
    if not (eff == {"SEC", "ACC"}): raise AssertionError()

def test_exclude_forces_off_and_is_disclosed():
    eff, disc = cov.effective_panels({"SEC"}, {"OPS"}, {"OPS"}, global_floor=set())
    if not (eff == {"SEC"}): raise AssertionError()                 # OPS excluded despite scout adding it
    if not (disc["excluded"] == ["OPS"]): raise AssertionError()
    if not ("OPS" not in disc["scout_added"]): raise AssertionError()

def test_disclosure_lists_are_sorted():
    _eff, disc = cov.effective_panels({"DAT", "SEC"}, {"LNG", "ACC"}, set(), global_floor=set())
    if not (disc["scout_added"] == ["ACC", "LNG"]): raise AssertionError()

def test_floor_exclude_overlap_exclude_wins():
    # upstream validation forbids overlap; coverage_model must still degrade safe
    eff, disc = cov.effective_panels({"SEC", "DAT"}, set(), {"DAT"}, global_floor=set())
    if not (eff == {"SEC"}): raise AssertionError()
    if not (disc["excluded"] == ["DAT"]): raise AssertionError()

def test_all_empty_inputs():
    eff, disc = cov.effective_panels(set(), set(), set(), global_floor=set())
    if not (eff == set()): raise AssertionError()
    if not (disc == {"floor": [], "scout_added": [], "excluded": []}): raise AssertionError()

def test_excluded_disclosure_sorted_multi():
    _eff, disc = cov.effective_panels({"SEC"}, set(), {"OPS", "ACC"}, global_floor=set())
    if not (disc["excluded"] == ["ACC", "OPS"]): raise AssertionError()


# --- #5.0-11: universal-tier global floor injected by default ---

def test_global_floor_injected_by_default():
    # every group reviews COD/DAT/TST/ARC even with only a vertical committed floor
    eff, disc = cov.effective_panels({"SEC"}, set(), set())
    if not (eff == {"SEC", "COD", "DAT", "TST", "ARC"}): raise AssertionError()
    if not (set(disc["floor"]) == {"SEC", "COD", "DAT", "TST", "ARC"}): raise AssertionError()

def test_global_floor_present_even_with_empty_floor():
    eff, _ = cov.effective_panels(set(), set(), set())
    if not (eff == {"COD", "DAT", "TST", "ARC"}): raise AssertionError()

def test_global_floor_still_subject_to_exclude():
    # a group with no database can opt DAT out
    eff, disc = cov.effective_panels({"SEC"}, set(), {"DAT"})
    if not ("DAT" not in eff): raise AssertionError()
    if not (eff == {"SEC", "COD", "TST", "ARC"}): raise AssertionError()
    if not (disc["excluded"] == ["DAT"]): raise AssertionError()


# --- #5.0-19: applicable_global_floor surface gate --------------------------

def test_applicable_floor_cod_is_universal():
    # a docs-only, single-dir, testless, db-free group still reviews code
    got = cov.applicable_global_floor(["README.md"],
                                      {"surfaces": [], "has_tests": False})
    if not (got == frozenset({"COD"})): raise AssertionError()

def test_applicable_floor_surfaceless_group_drops_dat_tst_arc():
    got = cov.applicable_global_floor(["src/app/page.tsx"],
                                      {"surfaces": ["http_web", "templating"]})
    if not (got == frozenset({"COD"})): raise AssertionError()

def test_applicable_floor_keeps_dat_on_all_db_file_hints():
    for hint in cov._DB_FILE_HINTS:
        if hint.startswith("/") and hint.endswith("/"):
            fname = f"src{hint}file.py"
        elif hint.startswith("/"):
            fname = f"src{hint}py"
        else:
            fname = f"src/sub/{hint}"
        got = cov.applicable_global_floor([fname], {"surfaces": []})
        if not ("DAT" in got, f"Hint {hint} on {fname} failed to trigger DAT"): raise AssertionError()

def test_applicable_floor_keeps_tst_on_all_test_file_hints():
    for hint in cov._TEST_FILE_HINTS:
        if hint.startswith("/") and hint.endswith("/"):
            fname = f"src{hint}file.py"
        elif hint.startswith("/"):
            fname = f"src{hint}py"
        else:
            fname = f"src/sub/{hint}"
        got = cov.applicable_global_floor([fname], {"surfaces": []})
        if not ("TST" in got, f"Hint {hint} on {fname} failed to trigger TST"): raise AssertionError()

def test_applicable_floor_keeps_dat_on_db_file():
    got = cov.applicable_global_floor(["prisma/schema.prisma", "src/lib/db.ts"],
                                      {"surfaces": []})
    if "DAT" not in got: raise AssertionError()

def test_applicable_floor_keeps_dat_on_scout_db_surface():
    # no db-named file, but the scout saw a persistence surface
    got = cov.applicable_global_floor(["src/app/api/x/route.ts"],
                                      {"surfaces": ["db_sql"]})
    if "DAT" not in got: raise AssertionError()

def test_applicable_floor_keeps_tst_on_test_file():
    got = cov.applicable_global_floor(["src/x.ts", "src/x.test.ts"],
                                      {"surfaces": []})
    if "TST" not in got: raise AssertionError()

def test_applicable_floor_keeps_tst_on_scout_has_tests():
    got = cov.applicable_global_floor(["src/x.ts"], {"has_tests": True})
    if "TST" not in got: raise AssertionError()

def test_applicable_floor_no_tests_drops_tst():
    # the dominant calibration win: a testless group spends no TST cell
    got = cov.applicable_global_floor(["src/a.ts", "lib/b.ts"],
                                      {"surfaces": [], "has_tests": False})
    if not ("TST" not in got): raise AssertionError()

def test_applicable_floor_keeps_arc_on_multi_directory():
    got = cov.applicable_global_floor(
        ["src/app/api/x/route.ts", "src/lib/session.ts"], {"surfaces": []})
    if "ARC" not in got: raise AssertionError()

def test_applicable_floor_keeps_arc_on_scout_arch_surface():
    got = cov.applicable_global_floor(["README.md", "package.json"],
                                      {"surfaces": ["architecture"]})
    if "ARC" not in got: raise AssertionError()

def test_applicable_floor_single_dir_no_arch_drops_arc():
    got = cov.applicable_global_floor(["src/app/layout.tsx", "src/app/page.tsx"],
                                      {"surfaces": ["http_web"]})
    if not ("ARC" not in got): raise AssertionError()

def test_applicable_floor_is_subset_of_global_floor():
    got = cov.applicable_global_floor(
        ["a/x.ts", "b/y.sql", "a/x.test.ts"],
        {"surfaces": ["architecture"], "has_tests": True})
    if not (got <= cov.GLOBAL_FLOOR): raise AssertionError()
    if not (got == {"COD", "DAT", "TST", "ARC"}): raise AssertionError()   # every surface present

def test_applicable_floor_respects_reduced_global_floor():
    # a caller passing a reduced floor never gets COD back
    got = cov.applicable_global_floor(["x.sql"], {},
                                      global_floor=frozenset({"DAT"}))
    if not (got == frozenset({"DAT"})): raise AssertionError()

def test_applicable_floor_tolerates_missing_scout_fields():
    got = cov.applicable_global_floor(["a/x.ts", "b/y.ts"], {})
    if not (got == frozenset({"COD", "ARC"})): raise AssertionError()   # 2 dirs -> ARC; no db/tests

def test_applicable_floor_same_dir_pair_drops_arc():
    # two files in one directory is not cross-module structure
    got = cov.applicable_global_floor(["x.ts", "y.ts"], {"surfaces": []})
    if not (got == frozenset({"COD"})): raise AssertionError()

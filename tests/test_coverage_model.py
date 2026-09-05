# tests/test_coverage_model.py
import scripts.coverage_model as cov

# The existing cases isolate the core (floor|scout)-exclude logic by passing
# global_floor=set(); the global-floor injection is exercised separately below.


def test_floor_always_on():
    eff, disc = cov.effective_panels({"SEC", "DAT"}, set(), set(), global_floor=set())
    if not (eff == {"SEC", "DAT"}): raise AssertionError()
    if not (disc["floor"] == ["DAT", "SEC"]): raise AssertionError()

def test_scout_widens_the_middle():
    eff, _ = cov.effective_panels({"SEC"}, {"ACC"}, set(), global_floor=set())
    if not (eff == {"SEC", "ACC"}): raise AssertionError()

def test_scout_added_widens_coverage_without_objective_signal():
    # #1193: a scout-requested domain still reaches effective_panels even when
    # applicable_global_floor drops it for lack of objective file signals.
    eff, disc = cov.effective_panels(set(), {"TST"}, set(), global_floor=set())
    if not (eff == {"TST"}): raise AssertionError()
    if not (disc["scout_added"] == ["TST"]): raise AssertionError()

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

def test_applicable_floor_cod_kept_for_any_non_asset_file():
    # a docs-only, single-dir, testless, db-free group still reviews code
    got = cov.applicable_global_floor(["README.md"],
                                      {"surfaces": [], "has_tests": False})
    if not (got == frozenset({"COD"})): raise AssertionError()

def test_applicable_floor_drops_cod_on_a_pure_asset_group():
    # #1489: COD was unconditional, so an image folder still spent a review cell.
    # chunk_files packs by directory, so pure-asset chunks are a reliable shape,
    # not a rare one -- and across 7 calibration runs those COD cells returned
    # ZERO findings in every instance (corpus baseline 2.71-5.83 per cell).
    files = ["wwwroot/img/logo.png", "wwwroot/img/sprite.svg",
             "wwwroot/fonts/inter.woff2"]
    got = cov.applicable_global_floor(files, {"surfaces": []})
    if "COD" in got:
        raise AssertionError("COD kept on a group with no code surface")
    # ARC must SURVIVE: its >=2-directory gate is what found the one real defect
    # these groups produced (a sprite set drifted out of parity with the logos).
    if "ARC" not in got:
        raise AssertionError("ARC wrongly dropped from an asset group")

def test_applicable_floor_cod_gate_fails_open_on_unknown_extensions():
    # The gate is a denylist of known asset types, so anything unfamiliar counts
    # as reviewable source. Dropping a floor domain wrongly is worse than
    # spending one cell.
    got = cov.applicable_global_floor(["a/thing.zzz", "b/other.zzz"],
                                      {"surfaces": []})
    if "COD" not in got:
        raise AssertionError("COD dropped for an unrecognized extension")

def test_applicable_floor_keeps_cod_when_one_source_file_is_present():
    got = cov.applicable_global_floor(["wwwroot/img/a.png", "src/Home.cs"],
                                      {"surfaces": []})
    if "COD" not in got:
        raise AssertionError("COD dropped from a group that contains source")

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
        # #run7 TST-B2A: `not (cond, "msg")` is a truthy 2-tuple -> the assertion
        # never fired; this calibration-invariant test asserted NOTHING.
        if "DAT" not in got:
            raise AssertionError(f"Hint {hint} on {fname} failed to trigger DAT")

def test_applicable_floor_keeps_tst_on_all_test_file_hints():
    for hint in cov._TEST_FILE_HINTS:
        if hint.startswith("/") and hint.endswith("/"):
            fname = f"src{hint}file.py"
        elif hint.startswith("/"):
            fname = f"src{hint}py"
        else:
            fname = f"src/sub/{hint}"
        got = cov.applicable_global_floor([fname], {"surfaces": []})
        if "TST" not in got:   # #run7 TST-B2A: was a vacuous truthy-tuple assert
            raise AssertionError(f"Hint {hint} on {fname} failed to trigger TST")

def test_applicable_floor_keeps_dat_on_db_file():
    got = cov.applicable_global_floor(["prisma/schema.prisma", "src/lib/db.ts"],
                                      {"surfaces": []})
    if "DAT" not in got: raise AssertionError()

def test_applicable_floor_keeps_tst_on_test_file():
    got = cov.applicable_global_floor(["src/x.ts", "src/x.test.ts"],
                                      {"surfaces": []})
    if "TST" not in got: raise AssertionError()

def test_applicable_floor_scout_db_surface_does_not_keep_dat():
    # #1193: scout-asserted surfaces are not trusted to gate the global floor.
    got = cov.applicable_global_floor(["src/app/api/x/route.ts"],
                                      {"surfaces": ["db_sql"]})
    if not ("DAT" not in got): raise AssertionError()

def test_applicable_floor_scout_has_tests_does_not_keep_tst():
    # #1193: scout-asserted has_tests is not trusted to gate the global floor.
    got = cov.applicable_global_floor(["src/x.ts"], {"has_tests": True})
    if not ("TST" not in got): raise AssertionError()

def test_applicable_floor_no_tests_drops_tst():
    # the dominant calibration win: a testless group spends no TST cell
    got = cov.applicable_global_floor(["src/a.ts", "lib/b.ts"],
                                      {"surfaces": [], "has_tests": False})
    if not ("TST" not in got): raise AssertionError()

def test_applicable_floor_keeps_arc_on_multi_directory():
    got = cov.applicable_global_floor(
        ["src/app/api/x/route.ts", "src/lib/session.ts"], {"surfaces": []})
    if "ARC" not in got: raise AssertionError()

def test_applicable_floor_scout_arch_surface_does_not_keep_arc():
    # #1193: scout-asserted surfaces are not trusted to gate the global floor.
    got = cov.applicable_global_floor(["README.md", "package.json"],
                                      {"surfaces": ["architecture"]})
    if not ("ARC" not in got): raise AssertionError()

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

def test_sec_is_non_excludable():
    # #1084: a committed exclude cannot silence SEC -- a scout-added SEC survives
    # `exclude: [SEC]`, and the ignored attempt is disclosed, never silent.
    eff, disc = cov.effective_panels(set(), {"SEC"}, {"SEC"}, global_floor=set())
    if not (eff == {"SEC"}): raise AssertionError()                  # SEC kept despite exclude
    if not (disc["exclude_rejected"] == ["SEC"]): raise AssertionError()
    if not (disc["excluded"] == []): raise AssertionError()          # SEC not counted as excluded

def test_non_sec_exclude_still_applies_alongside_rejected_sec():
    # excluding SEC is ignored, but excluding another domain (OPS) still works
    eff, disc = cov.effective_panels(set(), {"SEC", "OPS"}, {"SEC", "OPS"}, global_floor=set())
    if not (eff == {"SEC"}): raise AssertionError()                  # SEC kept, OPS excluded
    if not (disc["excluded"] == ["OPS"]): raise AssertionError()
    if not (disc["exclude_rejected"] == ["SEC"]): raise AssertionError()


# --- #run8 SEC-G2A: objective-signal SEC floor -----------------------------

def test_sec_floor_on_supply_chain_surface():
    # CI/CD, container, and dependency/build manifests each floor SEC (E1-E3).
    for f in ["requirements.txt", "app/package.json", ".github/workflows/ci.yml",
              "Dockerfile", "docker-compose.yml", "go.mod", "pom.xml",
              "Cargo.toml", "Gemfile", "pyproject.toml"]:
        if cov.applicable_sec_floor([f]) != frozenset({"SEC"}):
            raise AssertionError(f"{f} failed to floor SEC")

def test_sec_floor_on_db_sqli_surface():
    # a migrations/ORM-models-only group (raw query builders = the SQLi surface).
    if cov.applicable_sec_floor(["db/migrations/0001_init.sql"]) != frozenset({"SEC"}):
        raise AssertionError()
    if cov.applicable_sec_floor(["src/models/user.py"]) != frozenset({"SEC"}):
        raise AssertionError()

def test_sec_floor_on_auth_crypto_secrets_markers():
    for f in ["src/auth/login.py", "lib/session.ts", "crypto/cipher.go",
              "config/secrets.py", "app/password_reset.rb", "mw/jwt_check.js",
              "oauth_token.go"]:
        if cov.applicable_sec_floor([f]) != frozenset({"SEC"}):
            raise AssertionError(f"{f} failed to floor SEC")

def test_sec_floor_on_secret_bearing_files():
    # #run10 SEC-G2A: the highest-value secret surface is the secret-bearing FILE
    # itself, and none of these match the auth/secret/password NAME hints -- so a
    # groups.yml that never lists SEC used to exempt exactly the files most worth
    # reviewing. Each must force the SEC floor on its own.
    for f in ["app/.env", "deploy/.env.production", "certs/server.pem",
              "certs/tls.key", "keys/id_rsa", "config/.npmrc", "home/.netrc",
              "db/.pgpass", "nginx/htpasswd", "store/prod.jks", "app/keystore.p12",
              "infra/vault/policy.hcl", "conf/secrets.yaml", "aws/credentials.ini"]:
        if cov.applicable_sec_floor([f]) != frozenset({"SEC"}):
            raise AssertionError(f"{f} failed to floor SEC")

def test_sec_floor_absent_on_surfaceless_group():
    # #5.0-19 stays honored: a docs-only group with no security surface spends
    # no SEC cell -- the floor widens coverage, it does not blanket every group.
    if cov.applicable_sec_floor(["README.md", "docs/intro.md", "LICENSE"]) != frozenset():
        raise AssertionError()

def test_sec_floor_keys_on_files_not_scout_or_missing():
    # #1193: applicable_sec_floor takes only files; no scout claim can conjure it,
    # and empty/None file lists are tolerated (never crash the coverage phase).
    if cov.applicable_sec_floor([]) != frozenset(): raise AssertionError()
    if cov.applicable_sec_floor(None) != frozenset(): raise AssertionError()

def test_signal_floor_forces_domain_on_and_discloses_it():
    # a group whose committed panels never list SEC and whose scout never adds it
    # still gets SEC when the objective signal floor supplies it.
    eff, disc = cov.effective_panels(set(), set(), set(),
                                     global_floor=set(),
                                     signal_floor=frozenset({"SEC"}))
    if "SEC" not in eff: raise AssertionError()
    if "SEC" not in disc["floor"]: raise AssertionError()

def test_signal_floor_sec_survives_committed_exclude():
    # SEC via the objective floor is NON_EXCLUDABLE: a committed exclude: [SEC]
    # cannot silence it, and the ignored attempt is disclosed, never silent.
    eff, disc = cov.effective_panels(set(), set(), {"SEC"},
                                     global_floor=set(),
                                     signal_floor=frozenset({"SEC"}))
    if eff != {"SEC"}: raise AssertionError()
    if disc["exclude_rejected"] != ["SEC"]: raise AssertionError()

def test_signal_floor_defaults_empty_leaves_existing_callers_unchanged():
    # the new param is opt-in: a caller passing only global_floor is unaffected.
    eff, _ = cov.effective_panels({"COD"}, set(), set(), global_floor=set())
    if eff != {"COD"}: raise AssertionError()

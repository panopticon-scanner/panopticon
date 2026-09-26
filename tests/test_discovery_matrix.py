"""Matrix root-config tests: parse_groups normalization, scalar-match guards,
and scope integration."""
import json
import os

import pytest

from discovery_test_helpers import (
    _git_repo, git_cmd, git_output, repo_with_matrix, repo_with_scalar_match_group,
    repo_with_only_malformed_group, setup_flow, GIT_TIMEOUT,
)

import scripts.discovery as discovery  # noqa: E402
orchestrator = discovery   # #run7 COD-X0X: one module identity


def test_repo_scan_reads_matrix_via_parse_groups(tmp_path, monkeypatch):
    # A matrix root config (match/panels) drives --repo-scan grouping identically
    # whether read by load_catalog or _committed_matrix, since assign_by_catalog
    # keys on `match`. Guards the SEC-3 migration: no grouping regression.
    repo = tmp_path
    (repo / "src").mkdir(); (repo / "src" / "a.py").write_text("x=1\n")
    (repo / "panopticon.yml").write_text(
        "version: 1\ngroups:\n  Core:\n    match: ['src/**']\n    panels: [SEC]\n")
    cat = orchestrator._committed_matrix(str(repo))
    assert cat["Core"]["match"] == ["src/**"]
    # assign_by_catalog uses only `match` -> Core claims src/a.py
    assigned, leftovers = orchestrator.assign_by_catalog(["src/a.py"], cat)
    assert assigned == {"Core": ["src/a.py"]} and leftovers == []


def test_repo_scan_scalar_match_disclosed_not_silently_coerced(tmp_path, capsys):
    (tmp_path / "panopticon.yml").write_text(
        "version: 1\ngroups:\n  Bad:\n    match: 'src/**'\n")   # scalar, not a list
    orchestrator._committed_matrix(str(tmp_path))   # parse_groups validates
    err = capsys.readouterr().err
    assert "match must be a non-empty list" in err   # disclosed, not silent-coerced


def test_repo_scan_scope_group_restricts_to_named_group(tmp_path):
    repo = repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-group", "Checkout",
                       str(repo), "--out", str(out)])
    groups = json.loads(out.read_text())["groups"]
    names = {g["name"] for g in groups}
    files = sorted(f for g in groups for f in g["files"])
    assert names == {"Checkout"}
    assert files == ["src/checkout/cart.py", "src/checkout/pay.py"]


def test_scope_group_preserves_earlier_catalog_ownership_and_tests(tmp_path):
    repo = _git_repo(tmp_path, ["src/shared.py", "src/owned.py", "tests/broad/test_owned.py"],
                     "groups:\n"
                     "  Narrow:\n    match: ['src/shared.py']\n"
                     "  Broad:\n    match: ['src/**']\n    tests: ['tests/broad/**']\n")
    out = repo / ".panopticon" / "groups.json"
    assert discovery.main(["--repo-scan", "--scope-group", "Broad",
                           str(repo), "--out", str(out)]) == 0
    report = json.loads(out.read_text())
    assert [(g["name"], g["files"]) for g in report["groups"]] == [
        ("Broad", ["src/owned.py", "tests/broad/test_owned.py"])]
    assert report["ungrouped_files"] == []

    assert discovery.main(["--repo-scan", str(repo), "--out", str(out)]) == 0
    report = json.loads(out.read_text())
    by_name = {g["name"]: g["files"] for g in report["groups"]}
    assert by_name["Narrow"] == ["src/shared.py"]
    assert by_name["Broad"] == ["src/owned.py", "tests/broad/test_owned.py"]


def test_scope_subgroup_preserves_earlier_sibling_ownership(tmp_path):
    repo = _git_repo(tmp_path, ["src/shared.py", "src/owned.py"],
                     "groups:\n  Product:\n"
                     "    Narrow:\n      match: ['src/shared.py']\n"
                     "    Broad:\n      match: ['src/**']\n")
    out = repo / ".panopticon" / "groups.json"
    assert discovery.main(["--repo-scan", "--scope-group", "Product:Broad",
                           str(repo), "--out", str(out)]) == 0
    assert [(g["name"], g["files"]) for g in json.loads(out.read_text())["groups"]] == [
        ("Product:Broad", ["src/owned.py"])]


def test_scope_group_with_only_earlier_owned_matches_is_empty(tmp_path, capsys):
    repo = _git_repo(tmp_path, ["src/shared.py"],
                     "groups:\n  Narrow:\n    match: ['src/shared.py']\n"
                     "  Broad:\n    match: ['src/**']\n")
    out = repo / ".panopticon" / "groups.json"
    assert discovery.main(["--repo-scan", "--scope-group", "Broad",
                           str(repo), "--out", str(out)]) == 2
    assert "Broad' matched no tracked files" in capsys.readouterr().err


@pytest.mark.parametrize("authored,expected_name,automatic", [
    ("  docs:\n    match: ['src/**']\n", "docs", "Docs"),
    ("  docs:\n    Core:\n      match: ['src/**']\n", "docs:Core", "Docs"),
    ("  commons:\n    match: ['src/**']\n", "commons", "Commons"),
    ("  commons:\n    Core:\n      match: ['src/**']\n", "commons:Core", "Commons"),
])
def test_authored_case_variant_suppresses_automatic_name(
        tmp_path, authored, expected_name, automatic):
    files = ["src/owned.py", "README.md", "Dockerfile"]
    repo = _git_repo(tmp_path, files, "groups:\n" + authored)
    out = repo / ".panopticon" / "groups.json"
    assert discovery.main(["--repo-scan", str(repo), "--out", str(out)]) == 0
    report = json.loads(out.read_text())
    names = [g["name"] for g in report["groups"]]
    assert expected_name in names
    assert automatic not in names
    assert len(names) == len({n.casefold() for n in names})
    grouped = [f for g in report["groups"] for f in g["files"]]
    assert sorted(grouped) == sorted(files + ["panopticon.yml"])
    assert report["ungrouped_files"] == sorted(
        f for f in grouped if any(f in g["files"] for g in report["groups"]
                                if g["name"].startswith("Ungrouped_")))


@pytest.mark.parametrize("groups,offender", [
    ("  API:\n    match: ['src/a.py']\n  api:\n    match: ['src/b.py']\n", "api"),
    ("  API:\n    match: ['src/a.py']\n  api_1:\n    match: ['src/b.py']\n", "api_1"),
    ("  Product:\n    API:\n      match: ['src/a.py']\n"
     "  product:\n    api_1:\n      match: ['src/b.py']\n", "product:api_1"),
    ("  ungrouped_1:\n    match: ['src/a.py']\n", "ungrouped_1"),
])
def test_authored_case_variant_artifact_collision_fails_cli(tmp_path, capsys, groups, offender):
    repo = _git_repo(tmp_path, ["src/a.py", "src/b.py"], "groups:\n" + groups)
    out = repo / ".panopticon" / "groups.json"
    assert discovery.main(["--repo-scan", str(repo), "--out", str(out)]) == 1
    err = capsys.readouterr().err.casefold()
    assert offender in err
    assert "findings" in err or "artifact" in err
    assert not out.exists()


def test_repo_scan_scope_file_restricts_to_file_and_its_group(tmp_path):
    repo = repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-file", "src/checkout/pay.py",
                       str(repo), "--out", str(out)])
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py"]           # only the file (no related tests here)
    assert {g["name"] for g in groups} == {"Checkout"}   # assigned to its group, nothing else


def test_repo_scan_scope_file_accepts_dotslash_and_absolute(tmp_path):
    # #5.0-17: `-f ./src/checkout/pay.py` and `-f <abs>` must normalize to the
    # discovered repo-relative path, not hard-fail 'not found among discovered'.
    for spelling in ("./src/checkout/pay.py",):
        repo = repo_with_matrix(tmp_path / spelling.replace("/", "_").replace(".", "d"))
        out = repo / "groups.json"
        rc = orchestrator.main(["--repo-scan", "--scope-file", spelling,
                                str(repo), "--out", str(out)])
        assert rc == 0, spelling
        files = sorted(f for g in json.loads(out.read_text())["groups"] for f in g["files"])
        assert files == ["src/checkout/pay.py"], spelling
    # absolute path
    repo = repo_with_matrix(tmp_path / "abs")
    out = repo / "groups.json"
    abs_target = os.path.join(str(repo), "src/checkout/pay.py")
    rc = orchestrator.main(["--repo-scan", "--scope-file", abs_target,
                            str(repo), "--out", str(out)])
    assert rc == 0
    files = sorted(f for g in json.loads(out.read_text())["groups"] for f in g["files"])
    assert files == ["src/checkout/pay.py"]


def test_repo_scan_scope_file_includes_sibling_related_test(tmp_path):
    # related_tests()'s filtering (discovery.py) actually pulls a real
    # co-located sibling test file into a --scope-file scope -- the sibling
    # case: test_candidates("src/checkout/pay.py") generates "src/checkout/
    # test_pay.py" as its first same-directory candidate (before falling
    # back to spec/test/tests dirs); commit that file for real and confirm
    # it surfaces alongside the impl file. Complements
    # test_repo_scan_scope_file_restricts_to_file_and_its_group's negative
    # case ("no related tests here").
    repo = repo_with_matrix(tmp_path)
    (repo / "src" / "checkout" / "test_pay.py").write_text("def test_x():\n    pass\n")
    git_cmd(repo, "add", "-A")
    git_cmd(repo, "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-qm", "add sibling test")
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-file", "src/checkout/pay.py",
                       str(repo), "--out", str(out)])
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py", "src/checkout/test_pay.py"]
    assert {g["name"] for g in groups} == {"Checkout"}


def test_repo_scan_scope_dir_restricts_to_directory(tmp_path):
    repo = repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-dir", "src/checkout",
                       str(repo), "--out", str(out)])
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/cart.py", "src/checkout/pay.py"]
    assert {g["name"] for g in groups} == {"Checkout"}


def test_repo_scan_scope_group_unknown_name_errors(tmp_path, capsys):
    repo = repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-group", "Nope",
                            str(repo), "--out", str(out)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "Nope" in err


def test_repo_scan_scope_dir_no_catalog_match_falls_back_to_leftover(tmp_path):
    # A scoped file with no `match` coverage still surfaces via the ._N
    # leftover chunk naming AND is disclosed in ungrouped_files -- the same
    # coverage-honesty contract the unscoped --repo-scan path guarantees.
    repo = repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-dir", "src/misc",
                       str(repo), "--out", str(out)])
    data = json.loads(out.read_text())
    groups = data["groups"]
    assert [g["files"] for g in groups] == [["src/misc/other.py"]]
    assert groups[0]["name"].startswith("Ungrouped_")
    assert data["ungrouped_files"] == ["src/misc/other.py"]
    assert data["counts"]["ungrouped"] == 1


# --- SEC-3: --repo-scan/setup_readiness must read a parse_groups-NORMALIZED
# matrix, not _committed_matrix's raw (byte-faithful, un-validated) bodies. A
# scalar `match:` is valid YAML but invalid per the schema (must be a
# non-empty list); the raw path used to char-split the scalar string, and a
# lone `*` character compiles to a match-everything glob -- silently
# mis-scoping the whole repo into one group. -----------------------------


def test_matrix_catalog_normalizes_scalar_match_to_empty_list(tmp_path, capsys):
    (tmp_path / "panopticon.yml").write_text(
        "version: 1\ngroups:\n  Bad:\n    match: 'src/auth/**'\n")   # scalar, not a list
    cat = orchestrator._matrix_catalog(str(tmp_path))
    assert cat["Bad"]["match"] == []                      # never char-split
    err = capsys.readouterr().err
    assert "match must be a non-empty list" in err        # disclosed, not silent


def test_matrix_catalog_empty_when_no_config(tmp_path):
    assert orchestrator._matrix_catalog(str(tmp_path)) == {}


def test_repo_scan_bare_scalar_match_group_does_not_swallow_whole_repo(tmp_path):
    # Unscoped --repo-scan: the scalar-match group ("Bad") must NOT collapse
    # the entire repo into one group. Its own target file falls to the
    # leftover ._N chunk (disclosed via ungrouped_files); the well-formed
    # group ("Auth") groups its file normally, unaffected.
    repo = repo_with_scalar_match_group(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", str(repo), "--out", str(out)])
    data = json.loads(out.read_text())
    by_name = {g["name"]: g["files"] for g in data["groups"]}
    assert by_name.get("Auth") == ["src/auth/login.py"]
    assert "Bad" not in by_name                     # never grouped -- match=[]
    # #1681 Task 7: the committed root config is an ordinary repo file, but the
    # Commons vocabulary claims it under `Config` -- it is not a genuine
    # leftover, only the unclaimed source file is.
    assert by_name.get("Config") == ["panopticon.yml"]
    assert data["ungrouped_files"] == ["src/bad/thing.py"]
    leftover = [g for g in data["groups"] if g["name"].startswith("Ungrouped_")]
    assert [f for g in leftover for f in g["files"]] == ["src/bad/thing.py"]


def test_repo_scan_scope_group_scalar_match_does_not_claim_whole_repo(tmp_path, capsys):
    # Scoping directly to the corrupted group must NOT fall back to "every
    # file in the repo" (the old char-split bug) -- a well-formed OTHER
    # group's files must never leak into this scope.
    #
    # Fix round 1 F3: the no-leak outcome is now the loud one. `Bad`'s match is
    # invalid, so it assigns nothing, and a scope that assigns nothing exits 2
    # without writing an artifact instead of writing an empty "successful"
    # scan. The guard is unchanged in force -- the char-split bug would assign
    # the whole repo, which is a non-empty scope and would exit 0 with
    # Auth's file in the artifact.
    repo = repo_with_scalar_match_group(tmp_path)
    out = repo / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-group", "Bad",
                            str(repo), "--out", str(out)])
    assert rc == 2
    assert not out.exists()                          # nothing claimed at all
    assert "matched no tracked files" in capsys.readouterr().err


def test_repo_scan_bare_well_formed_matrix_groups_unchanged(tmp_path):
    # Guard: a well-formed matrix groups IDENTICALLY before/after the SEC-3
    # fix -- assign_by_catalog keys only on `match`, which parse_groups
    # returns unchanged for valid input.
    repo = repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", str(repo), "--out", str(out)])
    data = json.loads(out.read_text())
    by_name = {g["name"]: sorted(g["files"]) for g in data["groups"]}
    assert by_name["Auth"] == ["src/auth/login.py"]
    assert by_name["Checkout"] == ["src/checkout/cart.py", "src/checkout/pay.py"]
    # #1681 Task 7: the committed root config is claimed by the Commons
    # `Config` category, not left as a genuine leftover.
    assert by_name.get("Config") == ["panopticon.yml"]
    leftover = [g for g in data["groups"] if g["name"].startswith("Ungrouped_")]
    assert [f for g in leftover for f in g["files"]] == ["src/misc/other.py"]
    assert data["ungrouped_files"] == ["src/misc/other.py"]


def test_repo_scan_fails_loud_when_all_declared_groups_malformed(tmp_path, capsys):
    # #run8 COD-B1A: a committed root config that DECLARES groups but whose
    # entries ALL fail schema validation must FAIL LOUD -- not silently degrade
    # to whole-repo default chunking, which would discard the operator's
    # committed scoping with only an easy-to-miss stderr line as evidence.
    repo = repo_with_only_malformed_group(tmp_path)
    out = repo / "groups.json"
    rc = orchestrator.main(["--repo-scan", str(repo), "--out", str(out)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "match must be a non-empty list" in err        # per-entry disclosure
    assert "declares groups but none survived" in err      # the loud refusal
    assert not out.exists()                                # no degraded catalog written


def test_repo_scan_absent_config_adopts_whole_repo_default(tmp_path):
    # Counterpart to the above: an ABSENT root config is NOT an error -- it is
    # the adopt-all default. Corrupt-vs-absent must not be conflated (#run8
    # COD-B1A distinguishes them via _declares_groups).
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x=1\n")
    git_cmd(tmp_path, "init", "-q")
    git_cmd(tmp_path, "add", "-A")
    git_cmd(tmp_path, "-c", "user.email=t@t", "-c", "user.name=t",
            "commit", "-qm", "x")
    out = tmp_path / "groups.json"
    rc = orchestrator.main(["--repo-scan", str(tmp_path), "--out", str(out)])
    assert rc == 0
    assert out.exists()


def test_declares_groups_distinguishes_absent_declared_and_exclude_only(tmp_path):
    cfg = tmp_path / "panopticon.yml"
    assert discovery._declares_groups(str(tmp_path)) is False   # absent file
    cfg.write_text("version: 1\ngroups:\n  Bad:\n    match: src/**\n")
    assert discovery._declares_groups(str(tmp_path)) is True    # declares a group
    cfg.write_text("version: 1\nexclude_paths: ['vendor/**']\n")
    assert discovery._declares_groups(str(tmp_path)) is False   # exclude_paths only
    cfg.write_text("version: 1\ngroups: {}\n")
    assert discovery._declares_groups(str(tmp_path)) is False   # explicit empty mapping


def test_setup_readiness_scalar_match_only_reports_gap_not_ok(tmp_path):
    # setup_readiness's groups-manifest check must see the NORMALIZED match
    # (empty for a scalar) -- not the raw char-split list, which used to
    # read as a non-empty `match` and falsely report "OK -- 1 group(s)".
    # setup_readiness itself lives in setup_flow.py (orchestrator only ever
    # re-exported it); the SEC-3 regression it guards is discovery-side
    # (setup_flow.setup_readiness calls discovery._matrix_catalog directly),
    # so this stays a discovery-side regression test.
    os.makedirs(str(tmp_path / ".git"))
    (tmp_path / "panopticon.yml").write_text(
        "version: 1\ngroups:\n  Bad:\n    match: src/bad/**\n")   # scalar, not a list
    def ok_runner(argv, capture_output, text, timeout=None):
        class R: returncode = 0; stdout = ""; stderr = ""
        return R()

    checks = setup_flow.setup_readiness(str(tmp_path), host="claude",
                                        runner=ok_runner,
                                        environ={"NVD_API_KEY": "k"})
    by = {c[0]: c for c in checks}
    ok, detail = by["groups-manifest"][1], by["groups-manifest"][2]
    assert ok is False                # not silently "OK -- 1 group(s)"
    assert "Bad" in detail


# --- --scope-file/--scope-dir must loudly reject a target that resolves to
# no discovered files, instead of silently producing a phantom cell or an
# empty-but-"successful" scan (mirrors --scope-group's unknown-name error).


def test_repo_scan_scope_file_untracked_target_errors(tmp_path, capsys):
    repo = repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-file", "src/ghost.py",
                            str(repo), "--out", str(out)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "src/ghost.py" in err


def test_repo_scan_scope_group_no_tracked_files_errors(tmp_path, capsys):
    # Fix round 1 F3: the third member of this family, and the one that was
    # missing. A KNOWN group whose `match` assigns no tracked file exited 0
    # with `groups: []` -- which the driver's new done-predicate (#1643) reads
    # as a broken artifact and, after a second identical round, ends the run
    # `error` blaming the artifact. The scope is what is wrong, and only
    # discovery.py can say so.
    repo = repo_with_matrix(tmp_path)
    (repo / "panopticon.yml").write_text(
        "version: 1\n"
        "groups:\n"
        "  Auth:\n    match: ['src/auth/**']\n    panels: [SEC]\n"
        "  Ghost:\n    match: ['src/ghost/**']\n")
    out = repo / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-group", "Ghost",
                            str(repo), "--out", str(out)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "Ghost" in err
    assert "matched no tracked files" in err


def test_repo_scan_scope_dir_no_tracked_files_errors(tmp_path, capsys):
    repo = repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-dir", "no/such/dir",
                            str(repo), "--out", str(out)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "no/such/dir" in err


def test_write_diff_hunks_schema_version_and_atomic(tmp_path):
    hunks_out = tmp_path / "diff-hunks.json"
    discovery.write_diff_hunks(str(tmp_path), None, "none", str(hunks_out), 0, False)
    assert hunks_out.exists()
    data = json.loads(hunks_out.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["files_changed"] == 0



@pytest.mark.parametrize("available, selected, refs", [
    ({"main": "main-base"}, "main-base", ["main"]),
    ({"master": "master-base"}, "master-base", ["main", "master"]),
    ({}, "parent-base", ["main", "master", "HEAD~1"]),
])
def test_collect_changed_files_default_branch_fallback(available, selected, refs):
    from types import SimpleNamespace
    from unittest.mock import patch

    calls = []

    def git(repo, argv, **kwargs):
        assert repo == "/tmp/x"
        calls.append((argv, kwargs))
        if argv[:2] == ["merge-base", "HEAD"]:
            ref = argv[2]
            if ref not in available:
                raise RuntimeError("missing ref: " + ref)
            return SimpleNamespace(stdout=available[ref] + "\n")
        if argv == ["rev-parse", "HEAD~1"]:
            return SimpleNamespace(stdout="parent-base\n")
        if argv == ["-c", "core.quotepath=false", "diff", "--name-only",
                    "--diff-filter=d", "--find-renames", "-z", selected]:
            assert kwargs == {"text": False}
            return SimpleNamespace(stdout=b"file1.py\0")
        if argv == ["-c", "core.quotepath=false", "ls-files", "--others",
                    "--exclude-standard", "-z"]:
            assert kwargs == {"text": False}
            return SimpleNamespace(stdout=b"")
        raise AssertionError("unexpected git argv: %r" % argv)

    with patch("scripts.discovery._git", side_effect=git), \
         patch("scripts.discovery._on_allowed_dotdir_path", return_value=True), \
         patch("os.path.isfile", return_value=True):
        assert discovery.collect_changed_files("/tmp/x", base=None) == ["file1.py"]
    actual_refs = [argv[2] for argv, _ in calls if argv[:2] == ["merge-base", "HEAD"]]
    if "HEAD~1" in refs:
        actual_refs.append(next(argv[1] for argv, _ in calls if argv[0] == "rev-parse"))
    assert actual_refs == refs
    assert calls[-2][0][-1] == selected


def test_matrix_catalog_fails_loud_on_broken_yaml(tmp_path):
    (tmp_path / "panopticon.yml").write_text(
        "version: 1\ngroups:\n  Bad:\n    match: [unclosed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unreadable"):
        discovery._matrix_catalog(str(tmp_path))


def test_load_catalog_fails_loud_on_broken_yaml(tmp_path):
    (tmp_path / "panopticon.yml").write_text(
        "version: 1\ngroups:\n  Bad: [\n", encoding="utf-8")
    with pytest.raises(ValueError, match="catalog parse error"):
        discovery.load_catalog(str(tmp_path))


def test_repo_scan_fails_loud_on_broken_config(tmp_path, capsys):
    (tmp_path / "panopticon.yml").write_text(
        "version: 1\ngroups:\n  Bad:\n    match: [unclosed\n", encoding="utf-8")
    rc = discovery.main(["--repo", str(tmp_path), "--repo-scan"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "panopticon.yml unreadable: while parsing a flow sequence" in err
    assert "expected ',' or ']'" in err
    assert "--max-per-group" not in err


def test_matrix_catalog_refuses_a_legacy_tree_loud(tmp_path):
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text("groups:\n  A:\n    match: ['a/**']\n")
    with pytest.raises(ValueError, match="migrate-config"):
        discovery._matrix_catalog(str(tmp_path))


def test_declares_groups_ignores_a_legacy_file(tmp_path):
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text("groups:\n  A:\n    match: ['a/**']\n")
    assert discovery._declares_groups(str(tmp_path)) is False


def test_repo_scan_refuses_a_config_without_version(tmp_path, capsys):
    (tmp_path / "panopticon.yml").write_text("groups:\n  A:\n    match: ['a/**']\n")
    rc = discovery.main(["--repo", str(tmp_path), "--repo-scan",
                         "--out", str(tmp_path / "g.json")])
    assert rc == 1
    assert "version: 1" in capsys.readouterr().err


def test_committed_exclude_paths_read_the_root_file(tmp_path):
    (tmp_path / "panopticon.yml").write_text(
        "version: 1\ngroups: {}\nexclude_paths: ['vendor/**']\n")
    assert discovery._committed_exclude_paths(str(tmp_path)) == ["vendor/**"]


def test_matrix_catalog_discloses_a_refused_symlink_config(tmp_path, capsys):
    # `repo_config` refuses to FOLLOW a symlink at the config path, which
    # resolves to "no document" with NO error -- the one shape that reaches
    # _matrix_catalog's `{}` exit without an exception. Returning {} silently
    # is a fall back to whole-repo chunking on a target that authored a
    # config, so the refusal has to be on stderr.
    (tmp_path / "real.yml").write_text(
        "version: 1\ngroups:\n  A:\n    match: ['a/**']\n")
    os.symlink("real.yml", str(tmp_path / "panopticon.yml"))
    assert discovery._matrix_catalog(str(tmp_path)) == {}
    assert "symlink" in capsys.readouterr().err
    assert discovery._declares_groups(str(tmp_path)) is False


def test_committed_matrix_ignores_a_legacy_tree(tmp_path, capsys):
    # The non-raising half of the legacy refusal: `_committed_matrix` feeds
    # the never-clobber merge, so it degrades to "nothing committed" rather
    # than raise -- but it must say why, or setup silently proposes a catalog
    # over one the operator already wrote.
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text(
        "groups:\n  A:\n    match: ['a/**']\n")
    assert discovery._committed_matrix(str(tmp_path)) == {}
    assert "migrate-config" in capsys.readouterr().err


def test_committed_exclude_paths_ignores_a_legacy_tree(tmp_path, capsys):
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text(
        "exclude_paths: ['vendor/**']\n")
    assert discovery._committed_exclude_paths(str(tmp_path)) == []
    assert "migrate-config" in capsys.readouterr().err


def test_git_helpers_convert_timeout_to_assertion_error(tmp_path):
    """TimeoutExpired from a hung git subprocess must become AssertionError."""
    import subprocess
    from unittest.mock import patch
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(
            cmd=["git", "x"], timeout=GIT_TIMEOUT)):
        with pytest.raises(AssertionError, match="git subprocess timed out"):
            git_cmd(tmp_path, "x")
        with pytest.raises(AssertionError, match="git subprocess timed out"):
            git_output(tmp_path, "x")

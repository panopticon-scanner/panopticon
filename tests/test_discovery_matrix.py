"""Matrix groups.yml tests: parse_groups normalization, scalar-match guards,
and scope integration."""
import json
import os

import pytest

from discovery_test_helpers import (
    git_cmd, git_output, repo_with_matrix, repo_with_scalar_match_group,
    setup_flow, GIT_TIMEOUT,
)

import discovery  # noqa: E402


def test_repo_scan_reads_matrix_via_parse_groups(tmp_path, monkeypatch):
    # A matrix groups.yml (match/panels) drives --repo-scan grouping identically
    # whether read by load_catalog or _committed_matrix, since assign_by_catalog
    # keys on `match`. Guards the SEC-3 migration: no grouping regression.
    import discovery as orchestrator
    repo = tmp_path
    (repo / ".panopticon").mkdir()
    (repo / "src").mkdir(); (repo / "src" / "a.py").write_text("x=1\n")
    (repo / ".panopticon" / "groups.yml").write_text(
        "groups:\n  Core:\n    match: ['src/**']\n    panels: [SEC]\n")
    cat = orchestrator._committed_matrix(str(repo))
    assert cat["Core"]["match"] == ["src/**"]
    # assign_by_catalog uses only `match` -> Core claims src/a.py
    assigned, leftovers = orchestrator.assign_by_catalog(["src/a.py"], cat)
    assert assigned == {"Core": ["src/a.py"]} and leftovers == []


def test_repo_scan_scalar_match_disclosed_not_silently_coerced(tmp_path, capsys):
    import discovery as orchestrator
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text(
        "groups:\n  Bad:\n    match: 'src/**'\n")   # scalar, not a list
    orchestrator._committed_matrix(str(tmp_path))   # parse_groups validates
    err = capsys.readouterr().err
    assert "match must be a non-empty list" in err   # disclosed, not silent-coerced


def test_repo_scan_scope_group_restricts_to_named_group(tmp_path):
    import discovery as orchestrator
    repo = repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-group", "Checkout",
                       str(repo), "--out", str(out)])
    groups = json.loads(out.read_text())["groups"]
    names = {g["name"] for g in groups}
    files = sorted(f for g in groups for f in g["files"])
    assert names == {"Checkout"}
    assert files == ["src/checkout/cart.py", "src/checkout/pay.py"]


def test_repo_scan_scope_file_restricts_to_file_and_its_group(tmp_path):
    import discovery as orchestrator
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
    import discovery as orchestrator, os
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
    import discovery as orchestrator
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
    import discovery as orchestrator
    repo = repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-dir", "src/checkout",
                       str(repo), "--out", str(out)])
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/cart.py", "src/checkout/pay.py"]
    assert {g["name"] for g in groups} == {"Checkout"}


def test_repo_scan_scope_group_unknown_name_errors(tmp_path, capsys):
    import discovery as orchestrator
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
    import discovery as orchestrator
    repo = repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-dir", "src/misc",
                       str(repo), "--out", str(out)])
    data = json.loads(out.read_text())
    groups = data["groups"]
    assert [g["files"] for g in groups] == [["src/misc/other.py"]]
    assert groups[0]["name"].startswith("._")
    assert data["ungrouped_files"] == ["src/misc/other.py"]
    assert data["counts"]["ungrouped"] == 1


# --- SEC-3: --repo-scan/setup_readiness must read a parse_groups-NORMALIZED
# matrix, not _committed_matrix's raw (byte-faithful, un-validated) bodies. A
# scalar `match:` is valid YAML but invalid per the schema (must be a
# non-empty list); the raw path used to char-split the scalar string, and a
# lone `*` character compiles to a match-everything glob -- silently
# mis-scoping the whole repo into one group. -----------------------------


def test_matrix_catalog_normalizes_scalar_match_to_empty_list(tmp_path, capsys):
    import discovery as orchestrator
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text(
        "groups:\n  Bad:\n    match: 'src/auth/**'\n")   # scalar, not a list
    cat = orchestrator._matrix_catalog(str(tmp_path))
    assert cat["Bad"]["match"] == []                      # never char-split
    err = capsys.readouterr().err
    assert "match must be a non-empty list" in err        # disclosed, not silent


def test_matrix_catalog_empty_when_no_groups_yml(tmp_path):
    import discovery as orchestrator
    assert orchestrator._matrix_catalog(str(tmp_path)) == {}


def test_repo_scan_bare_scalar_match_group_does_not_swallow_whole_repo(tmp_path):
    # Unscoped --repo-scan: the scalar-match group ("Bad") must NOT collapse
    # the entire repo into one group. Its own target file falls to the
    # leftover ._N chunk (disclosed via ungrouped_files); the well-formed
    # group ("Auth") groups its file normally, unaffected.
    import discovery as orchestrator
    repo = repo_with_scalar_match_group(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", str(repo), "--out", str(out)])
    data = json.loads(out.read_text())
    by_name = {g["name"]: g["files"] for g in data["groups"]}
    assert by_name.get("Auth") == ["src/auth/login.py"]
    assert "Bad" not in by_name                     # never grouped -- match=[]
    assert data["ungrouped_files"] == ["src/bad/thing.py"]
    leftover = [g for g in data["groups"] if g["name"].startswith("._")]
    assert [f for g in leftover for f in g["files"]] == ["src/bad/thing.py"]


def test_repo_scan_scope_group_scalar_match_does_not_claim_whole_repo(tmp_path):
    # Scoping directly to the corrupted group must NOT fall back to "every
    # file in the repo" (the old char-split bug) -- a well-formed OTHER
    # group's files must never leak into this scope.
    import discovery as orchestrator
    repo = repo_with_scalar_match_group(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-group", "Bad",
                       str(repo), "--out", str(out)])
    data = json.loads(out.read_text())
    files = sorted(f for g in data["groups"] for f in g["files"])
    assert "src/auth/login.py" not in files          # Auth's file never leaks in
    assert files == []                               # Bad's own match is invalid -> nothing


def test_repo_scan_bare_well_formed_matrix_groups_unchanged(tmp_path):
    # Guard: a well-formed matrix groups IDENTICALLY before/after the SEC-3
    # fix -- assign_by_catalog keys only on `match`, which parse_groups
    # returns unchanged for valid input.
    import discovery as orchestrator
    repo = repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", str(repo), "--out", str(out)])
    data = json.loads(out.read_text())
    by_name = {g["name"]: sorted(g["files"]) for g in data["groups"]}
    assert by_name["Auth"] == ["src/auth/login.py"]
    assert by_name["Checkout"] == ["src/checkout/cart.py", "src/checkout/pay.py"]
    leftover = [g for g in data["groups"] if g["name"].startswith("._")]
    assert [f for g in leftover for f in g["files"]] == ["src/misc/other.py"]
    assert data["ungrouped_files"] == ["src/misc/other.py"]


def test_setup_readiness_scalar_match_only_reports_gap_not_ok(tmp_path):
    # setup_readiness's groups-manifest check must see the NORMALIZED match
    # (empty for a scalar) -- not the raw char-split list, which used to
    # read as a non-empty `match` and falsely report "OK -- 1 group(s)".
    # setup_readiness itself lives in setup_flow.py (orchestrator only ever
    # re-exported it); the SEC-3 regression it guards is discovery-side
    # (setup_flow.setup_readiness calls discovery._matrix_catalog directly),
    # so this stays a discovery-side regression test.
    os.makedirs(str(tmp_path / ".git"))
    os.makedirs(str(tmp_path / ".panopticon"))
    (tmp_path / ".panopticon" / "groups.yml").write_text(
        "groups:\n  Bad:\n    match: src/bad/**\n")   # scalar, not a list

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
    import discovery as orchestrator
    repo = repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-file", "src/ghost.py",
                            str(repo), "--out", str(out)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "src/ghost.py" in err


def test_repo_scan_scope_dir_no_tracked_files_errors(tmp_path, capsys):
    import discovery as orchestrator
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



def test_collect_changed_files_default_branch_fallback():
    from unittest.mock import patch, MagicMock
    with patch('discovery._git') as mock_git:
        mock_git.side_effect = [
            Exception("not main"),  # fails on main
            MagicMock(stdout="fake_master_hash\n"), # succeeds on master
            MagicMock(stdout="file1.py\n"), MagicMock(stdout="")
        ]
        with patch('discovery._on_allowed_dotdir_path', return_value=True), patch('os.path.isfile', return_value=True):
            res = discovery.collect_changed_files("/tmp/x", base=None)
        assert res == ["file1.py"]


def test_matrix_catalog_fails_loud_on_broken_yaml(tmp_path):
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text(
        "groups:\n  Bad:\n    match: [unclosed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="groups.yml unreadable"):
        discovery._matrix_catalog(str(tmp_path))


def test_load_catalog_fails_loud_on_broken_yaml(tmp_path):
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text(
        "groups:\n  Bad: [\n", encoding="utf-8")
    with pytest.raises(ValueError, match="catalog parse error"):
        discovery.load_catalog(str(tmp_path))


def test_repo_scan_fails_loud_on_broken_groups_yml(tmp_path):
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text(
        "groups:\n  Bad:\n    match: [unclosed\n", encoding="utf-8")
    rc = discovery.main(["--repo", str(tmp_path), "--repo-scan"])
    assert rc != 0


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

"""Scope orchestration tests: fixture pruning, exclude paths, the SEC carve-out,
and --scope-files confinement. (Delta review's half went in 5.5, #3736.)"""
import ast
import json
import os
import shutil
import unittest
from unittest import mock

from scripts import discovery_catalog
from scripts import discovery_scope
from scripts import groups_schema
from tests.discovery_test_helpers import (
    orchestrator, repo_with_matrix, repo_with_exclude,
    repo_with_exclude_and_sec_surface, git_cmd,
)


_SCOPE_OWNER_NAMES = {
    "EXCLUDE_DIRS",
    "EXCLUDE_DIR_GLOBS",
    "FIXTURE_DIR_BASENAMES",
    "FIXTURE_PARENT_DIRS",
    "_git",
    "test_candidates",
    "related_tests",
    "_is_excluded_dir",
    "_is_fixture_dir",
    "_ancestor_dirs",
    "prune_fixture_files",
    "DISCOVERED_FILES_MAX",
    "_cap_discovered",
    "_is_confined_regular",
    "_PRUNE_CLASSES",
    "_filter_reviewable",
    "_norm_scope_path",
    "_SCOPE_ECHO_LIMIT",
    "_echo_scope_path",
    "_confine_scope_path",
    "_resolve_scope",
}


def _top_level_names(module):
    with open(module.__file__, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), module.__file__)
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names.update(target.id for target in targets if isinstance(target, ast.Name))
    return names


def test_scope_family_has_one_owner():
    """#3457: the extracted scope family has one source owner, not aliases."""
    assert _SCOPE_OWNER_NAMES.isdisjoint(_top_level_names(orchestrator))
    assert _SCOPE_OWNER_NAMES <= _top_level_names(discovery_scope)


class TestFixturePruning(unittest.TestCase):

    def test_prune_fixture_files_standard_vs_redteam(self):
        paths = ["src/app.py", "tests/fixtures/vuln/main.rs"]
        self.assertEqual(discovery_scope.prune_fixture_files(paths, include_fixtures=False),
                         ["src/app.py"])
        self.assertEqual(discovery_scope.prune_fixture_files(paths, include_fixtures=True), paths)


def test_repo_scan_scope_files_without_base_emits_no_diff_hunks(tmp_path):
    repo = repo_with_matrix(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan", "--scope-files",
                            "src/checkout/pay.py", "--out", str(out)])
    assert rc == 0
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py"]
    assert not (repo/".panopticon"/"diff-hunks.json").exists()


def test_repo_scan_scope_files_applies_exclude_paths(tmp_path):
    # #1136 delta-path parity: --scope-files rebuilds the file set from the
    # user's explicit list, NOT from the exclude-pruned `allf`. A vendored file
    # named in the delta must still be pruned by committed exclude_paths (never
    # grouped/reviewed), and the disclosed count must reflect the delta set (1),
    # not the whole-repo count.
    repo = repo_with_exclude(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan", "--scope-files",
                            "src/checkout/pay.py", "vendor/README.md",
                            "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    files = sorted(f for g in doc["groups"] for f in g["files"])
    assert files == ["src/checkout/pay.py"]            # vendor/README.md pruned
    assert doc["exclude_paths"] == ["vendor/**"]
    assert doc["excluded_count"] == 1                  # delta count, not whole-repo


def test_repo_scan_scope_files_carves_the_sec_surface_out_of_the_exclusion(tmp_path):
    # #1757 delta-path parity: the carve-out works the same on the delta paths as
    # on the whole-repo one. `--scope-files` names both excluded files; the one
    # a code-shaped file reaches the SEC-only carve-out group instead
    # of no reviewer at all, and the other is still pruned from every domain. The
    # ruling is explicit that an operator-authored `--pr` config gets this too.
    repo = repo_with_exclude_and_sec_surface(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan", "--scope-files",
                            "src/checkout/pay.py", "vendor/README.md",
                            "vendor/requirements.txt", "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    by_name = {g["name"]: g["files"] for g in doc["groups"]}
    assert by_name[groups_schema.SEC_CARVE_OUT_SINK] == ["vendor/requirements.txt"]
    assert by_name["Checkout"] == ["src/checkout/pay.py"]
    assert doc["excluded_count"] == 1                  # vendor/README.md, every domain
    assert doc["exclude_paths_sec_carve_out"] == {
        "globs": ["vendor/**"], "files": ["vendor/requirements.txt"], "count": 1}


def test_exclude_paths_does_not_carve_a_security_named_png_back_in(tmp_path):
    # #3338: applicable_sec_floor is also the per-file SEC carve-out predicate.
    # A binary named auth-token.png used to match two filename hints and return
    # from exclude_paths in a SEC-only group. The manifest remains carved; the
    # PNG remains excluded from every review domain. The ordinary Python module
    # and an extensionless executable-like name join the manifest in the
    # SEC-only carve-out.
    repo = repo_with_exclude_and_sec_surface(tmp_path)
    module = repo / "vendor" / "dep.py"
    module.write_text("value = 1\n")
    script = repo / "vendor" / "security-scan"
    script.write_text("#!/bin/sh\nexit 0\n")
    png = repo / "vendor" / "auth-token.png"
    png.write_bytes(b"not-real-png")
    git_cmd(repo, "add", "vendor/dep.py", "vendor/security-scan",
            "vendor/auth-token.png")
    git_cmd(repo, "-c", "user.email=t@t", "-c", "user.name=t",
            "commit", "-qm", "add planted png")
    out = repo / ".panopticon" / "groups.json"

    rc = orchestrator.main([
        "--repo", str(repo), "--repo-scan", "--scope-files",
        "src/checkout/pay.py", "vendor/README.md", "vendor/dep.py",
        "vendor/requirements.txt", "vendor/security-scan",
        "vendor/auth-token.png", "--out", str(out),
    ])

    assert rc == 0
    doc = json.loads(out.read_text())
    by_name = {g["name"]: g["files"] for g in doc["groups"]}
    assert by_name[groups_schema.SEC_CARVE_OUT_SINK] == [
        "vendor/dep.py", "vendor/requirements.txt", "vendor/security-scan"]
    assert doc["excluded_count"] == 2
    assert doc["exclude_paths_sec_carve_out"] == {
        "globs": ["vendor/**"],
        "files": ["vendor/dep.py", "vendor/requirements.txt", "vendor/security-scan"],
        "count": 3,
    }


def test_a_narrowing_scope_flag_does_not_review_an_out_of_scope_carved_file(tmp_path):
    # #1757: `--scope-dir` / `--scope-file` / `--scope-group` narrow the
    # already-pruned whole-repo listing, so unlike the two delta flags they never
    # re-derive the exclusion -- and the carve-out universe sits OUTSIDE the
    # narrowed one by construction. Without this the carve-out group carried
    # `vendor/requirements.txt` into a `--scope-dir src` run: a review cell, and a
    # read grant, over a path the operator had just scoped out.
    repo = repo_with_exclude_and_sec_surface(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    sink = groups_schema.SEC_CARVE_OUT_SINK
    for flag, value in (("--scope-dir", "src"),
                        ("--scope-file", "src/checkout/pay.py"),
                        ("--scope-group", "Checkout")):
        rc = orchestrator.main(["--repo", str(repo), "--repo-scan", flag, value,
                                "--out", str(out)])
        assert rc == 0, flag
        doc = json.loads(out.read_text())
        assert sink not in {g["name"] for g in doc["groups"]}, flag
        assert doc["exclude_paths_sec_carve_out"]["count"] == 0, flag
        assert doc["exclude_paths_sec_carve_out"]["globs"] == ["vendor/**"], flag
    # Each of the three counts WHAT SURVIVED ITS OWN SCOPE, which is 0 for the
    # two whose universes come out of pruned `allf` -- so `count: 0` on a scoped
    # run means "nothing in this run's surface", never "nothing in the repo"
    # (the schema and driver-setup.md say so; review round 1 item 7).
    #
    # A carved file INSIDE the narrowed directory still gets its SEC cell: the
    # scope narrows the carve-out, it does not switch the policy off.
    (repo / "src" / "helm").mkdir(parents=True)
    (repo / "src" / "helm" / "values.yaml").write_text("x: 1\n")
    # #3273 P1: the scans above marked `.panopticon/` ours; it is never committed.
    with open(repo / ".git" / "info" / "exclude", "a") as fh:
        fh.write(".panopticon/\n")
    git_cmd(repo, "add", "-A")
    git_cmd(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c2")
    (repo / "panopticon.yml").write_text(
        "version: 1\ngroups:\n  Checkout:\n    match: ['src/checkout/**']\n"
        "exclude_paths: ['vendor/**', 'src/helm/**']\n")
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan", "--scope-dir",
                            "src", "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    by_name = {g["name"]: g["files"] for g in doc["groups"]}
    assert by_name[sink] == ["src/helm/values.yaml"]
    assert doc["exclude_paths_sec_carve_out"]["files"] == ["src/helm/values.yaml"]


def _repo_with_fixture_corpus(tmp_path, exclude_paths=True):
    # One scaffold for this file (#2272 review, finding 6): `_repo_tracking` below.
    yml = "groups:\n  Real:\n    match: ['src/**']\n    panels: [SEC]\n"
    if exclude_paths:
        yml += "exclude_paths: ['tests/fixtures/**']\n"
    return _repo_tracking(tmp_path, ["src/real.py", "tests/fixtures/vuln/app.py"],
                          config="version: 1\n" + yml)


def test_redteam_exclude_paths_keeps_fixture_code_for_sec_only(tmp_path):
    # #3338 changes #8c/#1757's boundary deliberately: target-authored
    # exclude_paths still removes fixture code from every OTHER domain, but an
    # excluded Python file is code and therefore returns in the SEC-only sink.
    # This is the same non-excludable floor as a natural code group; only known
    # docs/assets (the PNG pin above) can be pruned from SEC too.
    repo = _repo_with_fixture_corpus(tmp_path, exclude_paths=True)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan",
                            "--security", "redteam", "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    files = sorted(f for g in doc["groups"] for f in g["files"])
    # #3642: `panopticon.yml`, the committed root config, is not reviewed in a
    # full-repo scan (it used to land in the residual sink, #1681).
    assert files == ["src/real.py", "tests/fixtures/vuln/app.py"]
    assert doc["excluded"]["scanner_config"] == ["panopticon.yml"]
    sink = next(g for g in doc["groups"]
                if g["name"] == groups_schema.SEC_CARVE_OUT_SINK)
    assert sink["files"] == ["tests/fixtures/vuln/app.py"]
    assert "panels" not in sink
    assert doc["exclude_paths"] == ["tests/fixtures/**"]
    assert doc["excluded_count"] == 0
    assert doc["exclude_paths_sec_carve_out"]["files"] == [
        "tests/fixtures/vuln/app.py"]


def test_redteam_without_exclude_paths_keeps_fixture_corpus(tmp_path):
    # Control proving exclude_paths did the work above, not #434 fixture pruning:
    # in redteam mode WITHOUT exclude_paths the fixture corpus IS grouped (the
    # #434 prune is standard-mode-only), which is exactly the run-6 leak vector.
    repo = _repo_with_fixture_corpus(tmp_path, exclude_paths=False)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan",
                            "--security", "redteam", "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    files = sorted(f for g in doc["groups"] for f in g["files"])
    assert "tests/fixtures/vuln/app.py" in files           # kept -> the leak vector
    assert "exclude_paths" not in doc


def _reviewed_files(out_path):
    """Every file discovery.py --repo-scan actually dispatched: grouped, plus
    the ungrouped leftovers a changed root config (unmatched by any committed
    group's globs) lands in."""
    data = json.loads(out_path.read_text())
    return {f for g in data["groups"] for f in g["files"]} | set(
        data.get("ungrouped_files") or [])


# --- #1740 fix round 2: one glob means one thing on both sides --------------
#
# `exclude_paths:` is compiled by discovery with GITIGNORE semantics (`*` stays
# inside a segment, a trailing `/` claims the subtree, a pattern with no `/`
# matches the basename at any depth) and was matched on the tool side with
# `fnmatch` (`*` crosses `/`, a trailing `/` matches nothing at all). The same
# committed line therefore meant two different things: `tests/*` excluded the
# whole subtree from the gate but only the direct children from discovery, and
# `docs/` excluded a tree from discovery and NOTHING from the gate. The tool
# side now compiles through the same translator.

_PARITY_GLOBS = ["tests/*", "docs/"]
_PARITY_PATHS = ("tests/test_a.py",          # direct child: both exclude it
                 "tests/unit/test_b.py",     # nested: gitignore `*` stops at /
                 "docs/guide/intro.md")      # trailing `/` claims the subtree


def _discovery_excludes(path, globs):
    """Exactly what `discovery`'s `_apply_exclude` asks of a file."""
    return any(discovery_catalog._glob_to_re(g).match(path) for g in globs)


def test_the_tool_exclusion_agrees_with_discovery_on_every_path():
    import scripts.ingest_tools as it
    import scripts.run_tools as rt
    for path in _PARITY_PATHS:
        want = _discovery_excludes(path, _PARITY_GLOBS)
        # the scan side (adapter demotion)
        assert rt._is_excluded(path, _PARITY_GLOBS) is want, path
        # the ingest side (what the report and the gate see)
        kept, gl, _sup = it._filter_parsed_findings(
            [{"location": {"file": path}}], True, _PARITY_GLOBS)
        assert (gl == 1) is want, path
        assert (kept == []) is want, path


def test_the_parity_check_is_not_vacuous():
    # The three paths really do split three ways under gitignore semantics, so
    # a tool side that answered "everything" or "nothing" could not pass above.
    assert [_discovery_excludes(p, _PARITY_GLOBS) for p in _PARITY_PATHS] \
        == [True, False, True]


# --------------------------------------------------------------------------
# #2023 (external review, HIGH — confinement): `--scope-files` is confined
# exactly as `-f/--scope-file` is.
#
# The singular refused any path that was not among the discovered files (`if sf
# not in allf`). The plural only normalized each entry and pruned, so
# `--files ../../../../private/tmp/x` was ACCEPTED and landed verbatim in
# groups.json — and from there in the dispatch plan, the reviewed file set and
# a report attached to a PR, naming a path that was never in the repository.
# Both branches now route through `_confine_scope_path` and fail closed on the
# FIRST bad entry instead of silently dropping it.
# --------------------------------------------------------------------------


def _outside_file(tmp_path, name="escapee.py"):
    """A real file one directory ABOVE the repo root (`repo_with_matrix` makes
    `tmp_path` itself the repo, so its parent is outside the tree)."""
    outside = tmp_path.parent / ("pano-2023-%s-%s" % (tmp_path.name, name))
    outside.write_text("x = 1\n", encoding="utf-8")
    return outside


def _scope_files_run(repo, *entries, extra=()):
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan", *extra,
                            "--scope-files", *entries, "--out", str(out)])
    return rc, out


def test_scope_files_refuses_a_relative_path_that_escapes_the_repo(tmp_path, capsys):
    repo = repo_with_matrix(tmp_path)
    rel = os.path.relpath(_outside_file(tmp_path), repo)     # ../pano-2023-…py
    rc, out = _scope_files_run(repo, rel)
    err = capsys.readouterr().err
    assert rc == 2
    assert not out.exists()                  # no artifact can carry the path
    assert "--scope-files" in err and rel in err


def test_scope_files_refuses_an_absolute_path_outside_the_repo(tmp_path, capsys):
    repo = repo_with_matrix(tmp_path)
    outside = _outside_file(tmp_path)
    rc, out = _scope_files_run(repo, str(outside))
    err = capsys.readouterr().err
    assert rc == 2
    assert not out.exists()
    assert "--scope-files" in err


def test_scope_files_refuses_a_symlink_that_leaves_the_repo(tmp_path, capsys):
    # The realpath arm of the clamp, on the case a string check cannot see: a
    # TRACKED path inside the tree whose target is outside it.
    repo = repo_with_matrix(tmp_path)
    outside = _outside_file(tmp_path)
    (repo / "src" / "escape.py").symlink_to(outside)
    git_cmd(repo, "add", "-A")
    git_cmd(repo, "-c", "user.email=t@t", "-c", "user.name=t",
            "commit", "-qm", "a symlink out of the tree")
    rc, out = _scope_files_run(repo, "src/escape.py")
    err = capsys.readouterr().err
    assert rc == 2
    assert not out.exists()
    assert "outside the repository root" in err


def test_scope_files_refuses_an_inside_but_undiscovered_path(tmp_path, capsys):
    repo = repo_with_matrix(tmp_path)
    rc, out = _scope_files_run(repo, "src/checkout/nope.py")
    err = capsys.readouterr().err
    assert rc == 2
    assert not out.exists()
    assert "not found among discovered repo files" in err


def test_scope_files_refuses_an_empty_entry(tmp_path):
    repo = repo_with_matrix(tmp_path)
    rc, out = _scope_files_run(repo, "")
    assert rc == 2
    assert not out.exists()


def test_scope_files_fails_closed_on_the_first_bad_entry(tmp_path):
    # Not a silent drop: one bad entry refuses the WHOLE run, so the operator
    # never gets a narrower review than the one they asked for with no line
    # saying which path went missing.
    repo = repo_with_matrix(tmp_path)
    rc, out = _scope_files_run(repo, "src/checkout/pay.py", "../escapee.py")
    assert rc == 2
    assert not out.exists()                 # not even the GOOD entry reviewed


def test_scope_files_refuses_a_fixture_path_in_standard_mode(tmp_path, capsys):
    # Parity with the singular, which has always refused one: in standard mode
    # a fixture corpus is NOT among the discovered files, and accepting it used
    # to hand back `groups: []` with rc 0 — the scope's own mistake wearing the
    # face of a finished scan (#1643's lesson, on this flag).
    repo = _repo_with_fixture_corpus(tmp_path, exclude_paths=False)
    rc, out = _scope_files_run(repo, "tests/fixtures/vuln/app.py")
    err = capsys.readouterr().err
    assert rc == 2
    assert not out.exists()
    assert "not found among discovered repo files" in err


def test_scope_files_happy_path_groups_only_in_tree_paths(tmp_path):
    # The happy path is untouched, including #5.0-17's './' and absolute
    # spellings, and every path groups.json carries is repo-relative.
    repo = repo_with_matrix(tmp_path)
    rc, out = _scope_files_run(repo, "./src/checkout/pay.py",
                               str(repo / "src" / "auth" / "login.py"))
    assert rc == 0
    files = _reviewed_files(out)
    assert files == {"src/checkout/pay.py", "src/auth/login.py"}
    for f in files:
        assert not os.path.isabs(f)
        assert ".." not in f.split("/")


def test_both_scope_flags_route_through_one_confinement_helper(tmp_path):
    # The pin: mutate the single helper and BOTH branches must refuse a path
    # they otherwise accept. #2023 WAS the drift between these two branches.
    repo = repo_with_matrix(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    good = "src/checkout/pay.py"
    singular = ["--repo", str(repo), "--repo-scan", "--out", str(out),
                "--scope-file", good]
    plural = ["--repo", str(repo), "--repo-scan", "--out", str(out),
              "--scope-files", good]
    assert orchestrator.main(singular) == 0
    assert orchestrator.main(plural) == 0
    with mock.patch.object(discovery_scope, "_confine_scope_path",
                           return_value=None):
        assert orchestrator.main(singular) == 2
        assert orchestrator.main(plural) == 2


def test_scope_file_refuses_an_empty_entry_instead_of_reviewing_everything(tmp_path):
    # Review M6 on #2023: `-f "$FILE"` with FILE unset used to be falsy, skip
    # the scope branch entirely, and review the WHOLE repository at rc 0 --
    # the same #1643 failure in the other direction. The plural refused an
    # empty entry; now the singular does too, through the same helper.
    repo = repo_with_matrix(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan",
                            "--scope-file", "", "--out", str(out)])
    assert rc == 2
    assert not out.exists()


def test_scope_files_refusal_echoes_a_bounded_repr_of_the_entry(tmp_path, capsys):
    # Review M1 on #2023: the refused entry is echoed as repr() of a bounded
    # string, so a control character cannot break the stderr line and an
    # absurd argv cannot make it unreadable. Both pinned here.
    repo = repo_with_matrix(tmp_path)
    long_entry = "x" * (discovery_scope._SCOPE_ECHO_LIMIT + 50) + ".py"
    rc, _out = _scope_files_run(repo, long_entry)
    err = capsys.readouterr().err
    assert rc == 2
    assert "x" * discovery_scope._SCOPE_ECHO_LIMIT + "…" in err
    assert long_entry not in err
    rc, _out = _scope_files_run(repo, "src/\nnot-a-line.py")
    err = capsys.readouterr().err
    assert rc == 2
    assert "\\n" in err and "not-a-line" in err
    assert err.count("\n") == 1                  # one line, the refusal


# --------------------------------------------------------------------------
# #2450 (ARC-2262-F1): both confinement sites ask `claim_scope.
# confined_to_root`, which JOINS the path onto the root it resolved. So each
# caller hands over the REPO-RELATIVE path; a pre-joined candidate would
# double-prefix a relative repository root and ask about `<repo>/<repo>/...`
# -- a directory the reviewed tree can simply commit, which is what would
# launder the escape. Both tests use a relative `--repo` spelling and plant
# that decoy, so a pre-joined call MISCLASSIFIES and these fail.
# --------------------------------------------------------------------------


def _relative_repo_with_decoy(tmp_path, monkeypatch):
    """`repo_with_matrix`, re-spelled relative to its parent, with the
    `<repo>/<repo>/` decoy a double join would land in."""
    repo = repo_with_matrix(tmp_path)
    (repo / repo.name).mkdir()
    monkeypatch.chdir(tmp_path.parent)
    return repo, repo.name


def test_confine_scope_path_does_not_double_join_a_relative_repo(tmp_path, capsys,
                                                                 monkeypatch):
    repo, rel_repo = _relative_repo_with_decoy(tmp_path, monkeypatch)
    outside = _outside_file(tmp_path)
    (repo / "escape.py").symlink_to(outside)
    (repo / rel_repo / "escape.py").write_text("x = 1\n", encoding="utf-8")
    universe = {"escape.py", "src/checkout/pay.py"}
    # The in-tree file still confines under a relative root...
    assert discovery_scope._confine_scope_path(
        rel_repo, "src/checkout/pay.py", universe, "--scope-files") == "src/checkout/pay.py"
    # ...and the escaping symlink is still refused, decoy copy or not.
    assert discovery_scope._confine_scope_path(
        rel_repo, "escape.py", universe, "--scope-files") is None
    assert "resolves outside the repository root" in capsys.readouterr().err


def test_is_confined_regular_refuses_a_file_behind_an_escaping_dir_symlink(tmp_path,
                                                                           monkeypatch):
    # The listing site's own arm, on the case its `islink` guard cannot see:
    # the FINAL component is a regular file and an ANCESTOR is the symlink
    # that leaves the tree, so only the realpath confinement answers it.
    repo, rel_repo = _relative_repo_with_decoy(tmp_path, monkeypatch)
    outside_dir = tmp_path.parent / ("pano-2450-%s" % tmp_path.name)
    outside_dir.mkdir()
    (outside_dir / "x.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "dirlink").symlink_to(outside_dir, target_is_directory=True)
    (repo / rel_repo / "dirlink").mkdir()
    (repo / rel_repo / "dirlink" / "x.py").write_text("x = 1\n", encoding="utf-8")
    assert not discovery_scope._is_confined_regular(rel_repo, "dirlink/x.py")
    assert discovery_scope._is_confined_regular(rel_repo, "src/checkout/pay.py")


# --- #2272: every path a listing can hold meets the one policy ----------------

# Every dot-path shape `dot_paths.allowed` distinguishes, plus the two non-dot
# classes `_filter_reviewable` prunes (a TRACKED dependency tree, a fixture
# corpus). A `.git`-SEGMENT path is not here: `git add` refuses to track one, so
# that arm of the filter is unreachable from a real listing on either path.
_DOT_PATH_SHAPES = (
    ".github/workflows/ci.yml",      # allowed root dot-DIR (dot_paths.DIRS)
    ".github/CODEOWNERS",            # allowed: a file DIRECTLY under a DIRS root (#1771)
    ".gitignore",                    # allowed root dot-FILE (dot_paths.FILES)
    ".env.local",                    # allowed root dot-file STEM (.env*)
    "config/.env",                   # allowed NESTED dot-file ("unchanged behaviour")
    ".hidden/a.py",                  # denied root dot-dir: not in DIRS
    ".venv/lib/x.py",                # denied root dot-dir, also EXCLUDE_DIRS
    ".notarc",                       # denied root dot-file: no FILES/stem entry
    "src/.mypy_cache/b.py",          # denied NESTED dot-dir (tool state)
    ".github/.cache/x.yml",          # denied dot segment UNDER an allowed DIRS root
    "node_modules/c.js",             # tracked dependency tree (EXCLUDE_DIRS)
    "tests/fixtures/vuln/app.py",    # fixture corpus (#434)
)


def _repo_tracking(tmp_path, paths, links=(), config=None):
    """Commit `paths`, plus `links` as (name, target) SYMLINK pairs and `config` as
    the committed `panopticon.yml` -- `add -f`, so a tracked `.venv`/`node_modules`
    really is tracked whatever the ambient ignore rules say."""
    repo = tmp_path
    (repo / ".panopticon").mkdir(parents=True)
    for p in paths:
        os.makedirs(os.path.dirname(repo / p), exist_ok=True)
        (repo / p).write_text("x = 1\n")
    for name, target in links:
        os.symlink(target, repo / name)
    if config is not None:
        (repo / "panopticon.yml").write_text(config)
    git_cmd(repo, "init", "-q")
    git_cmd(repo, "add", "-Af")
    git_cmd(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x")
    return repo


def test_a_whole_repo_scan_asks_the_dot_path_policy_of_every_shape(tmp_path):
    # #2272 pinned this by parity with the delta path, which is gone (#3736), so the
    # reviewed set is named here. `link.py` is a TRACKED symlink: the listing drops it
    # (`_is_confined_regular` is the shared `isfile`).
    tree = ["src/app.py", "src/untouched.py", *_DOT_PATH_SHAPES]
    repo = _repo_tracking(tmp_path, tree, links=[("link.py", "src/app.py")])
    out = repo / ".panopticon" / "whole.json"
    assert orchestrator.main(["--repo-scan", str(repo), "--out", str(out)]) == 0
    assert _reviewed_files(out) == {
        "src/app.py", "src/untouched.py", ".github/workflows/ci.yml", ".github/CODEOWNERS",
        ".gitignore", ".env.local", "config/.env"}


# --- #2376/#2377: the block says whose numbers it carries ----------------------


def test_a_narrowing_scope_publishes_the_listings_numbers(tmp_path):
    # #2376: a NARROWING branch keeps the LISTING's numbers and `surface: "repo"`,
    # because it narrows the already-pruned `allf` instead of rebuilding a surface --
    # so `exclude_dir` still counts a `node_modules` file that was never inside the
    # scope asked for. (The surface that was rebuilt, a delta's changed set, went
    # with delta review in 5.5; `surface` has one value now.)
    tree = ["src/app.py", "node_modules/x.js", ".hidden/a.py"]
    repo = _repo_tracking(tmp_path, tree)
    whole = repo / ".panopticon" / "whole.json"
    assert orchestrator.main(["--repo-scan", str(repo), "--out", str(whole)]) == 0
    listing = json.loads(whole.read_text())["discovery"]
    assert listing["surface"] == "repo"
    assert listing["files_seen"] == 1
    assert listing["files_truncated"] == 0
    assert listing["pruned"]["exclude_dir"] == 1
    assert listing["pruned"]["dot_path"] >= 1
    for flags in (["--scope-dir", "src"], ["--scope-files", "src/app.py"]):
        narrowed = repo / ".panopticon" / "narrowed.json"
        assert orchestrator.main(["--repo-scan", str(repo), "--out", str(narrowed), *flags]) == 0
        scoped_block = json.loads(narrowed.read_text())["discovery"]
        assert scoped_block["surface"] == "repo"
        assert scoped_block["files_seen"] == listing["files_seen"]
        assert scoped_block["pruned"]["exclude_dir"] == 1
        assert scoped_block["pruned"]["dot_path"] >= 1


def test_scope_dir_fixture_disclosure_keeps_the_listings_roots(tmp_path, capsys):
    # The branch asymmetry #2410 leaves in place, pinned on the tree the two
    # tests above use: a NARROWING scope keeps the LISTING's fixture roots,
    # because it narrows the already-pruned `allf` instead of rebuilding a
    # surface -- the same reason its block still says `surface: "repo"`.
    repo = _repo_tracking(tmp_path, ["src/app.py", "tests/fixtures/x.rb"])
    out = repo / ".panopticon" / "dir.json"
    assert orchestrator.main(["--repo-scan", "--scope-dir", "src",
                              str(repo), "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    assert _reviewed_files(out) == {"src/app.py"}
    assert doc["excluded"]["fixture_dirs"] == ["tests/fixtures"]
    assert doc["discovery"]["surface"] == "repo"
    assert "fixture exclusion" in capsys.readouterr().err


def test_the_pruned_disclosure_is_one_line_per_run(tmp_path, capsys):
    # #2377 asks for one line, not per-path lines: a listing that drops tens of
    # thousands of `node_modules` paths would drown the terminal.
    repo = _repo_tracking(tmp_path, ["src/app.py", "node_modules/x.js"])
    out = repo / ".panopticon" / "groups.json"
    assert orchestrator.main(["--repo-scan", str(repo), "--out", str(out)]) == 0
    err = capsys.readouterr().err
    assert err.count("discovery pruned") == 1
    assert "repo surface" in err               # nit 6: the line names its surface
    clean = _repo_tracking(tmp_path / "clean", ["src/app.py"])
    assert orchestrator.main(["--repo-scan", str(clean), "--out",
                              str(clean / ".panopticon" / "g.json")]) == 0
    assert "discovery pruned" not in capsys.readouterr().err


# #3395: the four refusals the _repo_scan split moved that no test pinned by
# exact code -- each exits 2 with its own sentence and writes no artifact.
def test_repo_scan_refuses_a_panopticon_that_is_not_a_directory(tmp_path, capsys):
    repo = repo_with_matrix(tmp_path)
    shutil.rmtree(repo / ".panopticon", ignore_errors=True)
    (repo / ".panopticon").write_text("not a dir\n")
    assert orchestrator.main(["--repo-scan", str(repo)]) == 2
    assert capsys.readouterr().err == "panopticon: .panopticon exists but is not a directory\n"


def test_repo_scan_refuses_an_out_that_escapes_the_artifact_directory(tmp_path, capsys):
    repo = repo_with_matrix(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (repo / ".panopticon").mkdir(exist_ok=True)
    (repo / ".panopticon" / "link").symlink_to(elsewhere)
    out = repo / ".panopticon" / "link" / "groups.json"
    assert orchestrator.main(["--repo-scan", str(repo), "--out", str(out)]) == 2
    assert capsys.readouterr().err == \
        "panopticon: artifact output escapes the target .panopticon directory\n"
    assert not (elsewhere / "groups.json").exists()



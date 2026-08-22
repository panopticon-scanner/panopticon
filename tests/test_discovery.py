import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from unittest import mock

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "skill", "scripts")

sys.path.insert(0, SCRIPTS)
import discovery  # noqa: E402
import discovery as orch  # noqa: E402  (P6.5 Slice A: orchestrator.py retired)
import setup_flow  # noqa: E402

orchestrator = orch


def _run(script, *args, cwd=None):
    return subprocess.run([sys.executable, os.path.join(SCRIPTS, script), *args],
                          cwd=cwd, capture_output=True, text=True)


class TestDiscoveryRepoScanParity(unittest.TestCase):
    """discovery.py --repo-scan produces a stable groups.json on a real
    committed-matrix repo (regression guard for the P6.5 Slice A discovery/
    matrix core)."""

    def _repo(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        g = ["git", "-C", d]
        subprocess.run(g + ["init", "-q"], check=True)
        subprocess.run(g + ["config", "user.name", "Test"], check=True)
        subprocess.run(g + ["config", "user.email", "test@example.com"], check=True)
        os.makedirs(os.path.join(d, "src", "checkout"))
        with open(os.path.join(d, "src", "checkout", "pay.py"), "w", encoding="utf-8") as fh:
            fh.write("# pay\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w", encoding="utf-8") as fh:
            fh.write("groups:\n  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n")
        subprocess.run(g + ["add", "-A"], check=True)
        subprocess.run(g + ["commit", "-qm", "init"], check=True)
        subprocess.run(g + ["branch", "-M", "main"], check=True)
        return d

    def test_repo_scan_writes_groups_json(self):
        d = self._repo()
        out = os.path.join(d, ".panopticon", "groups.json")
        proc = _run("discovery.py", "--repo-scan", "--security", "standard",
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


class TestIsTestFile(unittest.TestCase):
    def test_recognizes_test_files_across_languages(self):
        for path in [
            "spec/models/user_spec.rb",
            "internal/svc/handler_test.go",
            "src/components/Button.test.tsx",
            "src/util.spec.js",
            "tests/test_parser.py",
            "app/parser_test.py",
            "src/main/java/FooTest.java",
            "Widget.Tests.cs",
        ]:
            self.assertTrue(orch.is_test_file(path), path)

    def test_recognizes_additional_test_conventions(self):
        # #676: these widely-used conventions were unmatched, so such files were
        # miscounted as impl and never scheduled the 'test' panel.
        for path in [
            "web/__tests__/button.js",          # Jest suite by directory
            "web/components/Button.test.mjs",   # ESM test
            "web/components/Button.spec.cts",   # CJS TS spec
            "app/foo_tests.py",                 # plural stem
            "src/App/UserTest.php",             # PHPUnit
            "lib/parser_test.exs",              # Elixir ExUnit
        ]:
            self.assertTrue(orch.is_test_file(path), path)

    def test_rejects_implementation_files(self):
        for path in [
            "app/models/user.rb",
            "internal/svc/handler.go",
            "src/components/Button.tsx",
            "src/parser.py",
            "src/main/java/Foo.java",
            "src/app.mjs",                      # ESM impl, not a test
            "app/tests_helper.py",              # 'tests' not as a stem suffix
        ]:
            self.assertFalse(orch.is_test_file(path), path)


class TestSurfaceClassifiers(unittest.TestCase):
    """#668/#669: direct coverage for the surface classifiers that feed panel
    scheduling and depth."""

    def test_is_architecture_file(self):
        for p in ["Dockerfile", "svc/Dockerfile.prod", "docker-compose.yml",
                  ".github/workflows/ci.yml", "k8s/deploy.yaml", "README.md",
                  ".gitignore", "helm/chart/values.yaml"]:
            self.assertTrue(orch.is_architecture_file(p), p)
        for p in ["src/app.py", "lib/user.rb", "main.go"]:
            self.assertFalse(orch.is_architecture_file(p), p)

    def test_is_database_file(self):
        for p in ["db/schema.sql", "migrations/0001_init.py",
                  "app/db/user.migration.rb"]:
            self.assertTrue(orch.is_database_file(p), p)
        for p in ["src/app.py", "README.md", "Dockerfile"]:
            self.assertFalse(orch.is_database_file(p), p)

    def test_compute_group_surfaces(self):
        self.assertEqual(orch.compute_group_surfaces(["Dockerfile", "db/schema.sql"]),
                         ["architecture", "database"])
        self.assertEqual(orch.compute_group_surfaces(["src/app.py"]), [])
        self.assertEqual(orch.compute_group_surfaces(["k8s/deploy.yaml"]), ["architecture"])
        self.assertEqual(orch.compute_group_surfaces(["migrations/001.sql"]), ["database"])

    def test_looks_risky(self):
        for p in ["src/auth/service.py", "src/login_handler.ts", "models/password.go",
                  "controllers/payment.rb", "lib/encrypt.rs", "config/api_token.json"]:
            self.assertTrue(orch._looks_risky(p), p)
        for p in ["src/utils/math.py", "assets/style.css", "docs/index.html"]:
            self.assertFalse(orch._looks_risky(p), p)


class TestTestCandidates(unittest.TestCase):
    """#670: direct coverage for test_candidates() name/dir generation."""

    def test_python_candidates_cover_stem_and_dirs(self):
        # Use a nested path so the src/ -> test(s)/ remap branch is exercised.
        cands = orch.test_candidates("src/pkg/parser.py")
        self.assertIn("src/pkg/test_parser.py", cands)
        self.assertIn("src/pkg/parser_test.py", cands)
        self.assertIn("tests/pkg/test_parser.py", cands)  # src/ -> tests/ remap
        self.assertIn("test/pkg/test_parser.py", cands)   # src/ -> test/ remap

    def test_ruby_app_dir_maps_to_spec(self):
        cands = orch.test_candidates("app/models/user.rb")
        self.assertIn("spec/models/user_spec.rb", cands)  # app/ -> spec/ remap

    def test_language_specific_suffixes(self):
        self.assertIn("internal/svc/handler_test.go",
                      orch.test_candidates("internal/svc/handler.go"))
        self.assertTrue(any(c.endswith("Button.test.tsx")
                            for c in orch.test_candidates("ui/Button.tsx")))
        self.assertTrue(any(c.endswith("FooTest.java")
                            for c in orch.test_candidates("src/Foo.java")))

    def test_unknown_extension_yields_no_names(self):
        # No language match -> no candidate filenames (dirs alone produce none).
        self.assertEqual(orch.test_candidates("notes.md"), [])


class TestChunkFiles(unittest.TestCase):
    def test_never_exceeds_max_per(self):
        files = ["a/f%02d.py" % i for i in range(37)]
        chunks = orch.chunk_files(files, max_per=15)
        self.assertTrue(all(len(c) <= 15 for c in chunks))
        self.assertEqual(sum(len(c) for c in chunks), 37)

    def test_merges_small_directories(self):
        files = ["a/one.py", "b/two.py", "c/three.py"]
        chunks = orch.chunk_files(files, max_per=15)
        self.assertEqual(chunks, [["a/one.py", "b/two.py", "c/three.py"]])

    def test_empty_input(self):
        self.assertEqual(orch.chunk_files([], max_per=15), [])

    def test_chunk_files_rejects_nonpositive_max(self):
        with self.assertRaises(ValueError) as cm:
            orch.chunk_files(["a/b.py"], max_per=0)
        self.assertIn("max_per must be >= 1", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            orch.chunk_files(["a/b.py"], max_per=-1)
        self.assertIn("max_per must be >= 1", str(cm.exception))


class TestDepth(unittest.TestCase):
    def test_clean_group_is_shallow(self):
        depth = orch._compute_depth(["docs/style.md"], ["code"], "standard")
        self.assertEqual(depth, "shallow")

    def test_security_panel_is_standard(self):
        result = orch.build_result(".", "repo", ".", None, ["app/views.py"], [], 15, security_mode="standard")
        self.assertEqual(result["groups"][0]["depth"], "standard")

    def test_redteam_is_deep(self):
        result = orch.build_result(".", "repo", ".", None, ["app/auth.py"], [], 15, security_mode="redteam")
        self.assertEqual(result["groups"][0]["depth"], "deep")


def _touch(root, rel, content=""):
    full = os.path.join(root, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(content)


def _run_scan_helper(d, *extra):
    buf = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        rc = orch.main(["--repo", d, "--repo-scan", *extra])
    val = buf.getvalue().strip()
    data = json.loads(val) if val else {}
    return rc, data, err.getvalue()


class TestRepoScanDiscovery(unittest.TestCase):
    """Discovery-gap regressions for --repo-scan: noise exclusion, targeted
    dotdir inclusion (.github/workflows), and real test-file surfacing."""

    def _touch(self, root, rel, content=""):
        _touch(root, rel, content)

    def _run_scan(self, d, *extra):
        rc, data, _err = _run_scan_helper(d, *extra)
        self.assertEqual(rc, 0)
        return data

    def _grouped(self, out):
        return [f for g in out["groups"] for f in g["files"]]

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
                rc = orch.main(["--repo", d, "--repo-scan",
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
            out = self._run_scan(d)
            grouped = self._grouped(out)
            self.assertIn("src/app.py", grouped)
            for noisy in [
                "tmp/audit-x/copy.py",
                "venv/lib/thing.py",
                ".venv/lib/thing.py",
                "node_modules/pkg/index.js",
                "htmlcov/index.html",
                "pkg.egg-info/PKG-INFO",
                "src/__pycache__/app.cpython-311.pyc",
            ]:
                self.assertNotIn(noisy, grouped, noisy)
                self.assertNotIn(noisy, out["tests"], noisy)

    def test_repo_scan_includes_github_workflows(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            self._touch(d, ".github/workflows/ci.yml")
            self._touch(d, ".github/workflows/release.yaml")
            out = self._run_scan(d)
            grouped = self._grouped(out)
            self.assertIn(".github/workflows/ci.yml", grouped)
            self.assertIn(".github/workflows/release.yaml", grouped)

    def test_repo_scan_surfaces_test_files_in_groups(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/foo.py")
            self._touch(d, "tests/test_foo.py")
            self._touch(d, "tests/__pycache__/test_foo.cpython-311.pyc")
            out = self._run_scan(d)
            grouped = self._grouped(out)
            self.assertIn("tests/test_foo.py", grouped)          # real test surfaced in a group
            self.assertIn("tests/test_foo.py", out["tests"])     # still tracked in tests list
            self.assertNotIn(
                "tests/__pycache__/test_foo.cpython-311.pyc", grouped
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
            out = self._run_scan(d)
            grouped = self._grouped(out)
            for hidden in [
                ".git/config",
                ".github/CODEOWNERS",
                ".github/ISSUE_TEMPLATE/bug.md",
                ".hidden/secret.py",
            ]:
                self.assertNotIn(hidden, grouped, hidden)


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

    def _run_scan(self, d, *extra):
        rc, data, err = _run_scan_helper(d, *extra)
        self.assertEqual(rc, 0)
        return data, err

    def _grouped(self, out):
        return [f for g in out["groups"] for f in g["files"]]

    def test_standard_scan_prunes_fixture_corpora_and_discloses(self):
        with tempfile.TemporaryDirectory() as d:
            _touch(d, "src/app.py")
            _touch(d, "tests/test_app.py")
            for rel in self._FIXTURE_LAYOUT:
                _touch(d, rel)
            out, err = self._run_scan(d)
            grouped = self._grouped(out)
            self.assertIn("src/app.py", grouped)
            self.assertIn("tests/test_app.py", grouped)  # real tests stay
            for rel in self._FIXTURE_LAYOUT:
                self.assertNotIn(rel, grouped, rel)
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
            _touch(d, "src/app.py")
            for rel in self._FIXTURE_LAYOUT:
                _touch(d, rel)
            out, err = self._run_scan(d, "--security", "redteam")
            grouped = self._grouped(out)
            for rel in self._FIXTURE_LAYOUT:
                self.assertIn(rel, grouped, rel)
            self.assertNotIn("excluded", out)
            self.assertNotIn("fixture exclusion", err)

    def test_plain_fixtures_dir_outside_test_parents_is_kept(self):
        # Only (tests|test|spec)/fixtures and the testdata/__fixtures__
        # conventions are corpus markers; a product dir merely named
        # "fixtures" is real code and must not be silently dropped.
        with tempfile.TemporaryDirectory() as d:
            _touch(d, "src/fixtures/loader.py")
            _touch(d, "fixtures/catalog.py")
            out, _ = self._run_scan(d)
            grouped = self._grouped(out)
            self.assertIn("src/fixtures/loader.py", grouped)
            self.assertIn("fixtures/catalog.py", grouped)
            self.assertNotIn("excluded", out)

    def test_no_disclosure_when_nothing_pruned(self):
        with tempfile.TemporaryDirectory() as d:
            _touch(d, "src/app.py")
            out, err = self._run_scan(d)
            self.assertNotIn("excluded", out)
            self.assertNotIn("fixture exclusion", err)

    def test_max_per_group_validation(self):
        with tempfile.TemporaryDirectory() as d:
            _touch(d, "src/app.py")
            rc, _data, err = _run_scan_helper(d, "--max-per-group", "0")
            self.assertEqual(rc, 2)
            self.assertIn("--max-per-group must be >= 1", err)

    def test_diff_context_cli_flag(self):
        with tempfile.TemporaryDirectory() as d:
            _touch(d, "src/app.py")
            rc, data, _err = _run_scan_helper(d, "--diff-context", "10")
            self.assertEqual(rc, 0)
            self.assertIn("groups", data)


def _git(d, *args):
    subprocess.run(["git", "-C", d, *args], check=True, capture_output=True)


def _init_repo(d):
    subprocess.run(["git", "init", "-q", d], check=True)
    _git(d, "config", "user.email", "t@e.com")
    _git(d, "config", "user.name", "Test")


class TestGitAwareDiscovery(unittest.TestCase):
    """#500: discovery respects the TARGET's own ignore rules. A raw walk swept
    17,253 files on an ordinary project (94% gitignored runtime data, including
    encrypted user blobs) vs 528 tracked; git ls-files IS the target's notion
    of reviewable surface. Non-git targets keep the walk fallback."""

    def _touch(self, root, rel, content=""):
        _touch(root, rel, content)

    def _run_scan(self, d, *extra):
        rc, data, err = _run_scan_helper(d, *extra)
        self.assertEqual(rc, 0)
        return data, err

    def _grouped(self, out):
        return [f for g in out["groups"] for f in g["files"]]

    def test_gitignored_paths_are_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            _touch(d, "src/app.py")
            _touch(d, ".gitignore", "storage/\n.env\n")
            _init_repo(d)
            _git(d, "add", ".")
            _git(d, "commit", "-q", "-m", "init")
            _touch(d, "storage/data.txt")       # runtime data, ignored
            _touch(d, "storage/blob.enc")
            self._touch(d, ".env", "SECRET=1")       # ignored credential
            out, _ = self._run_scan(d)
            grouped = self._grouped(out)
            self.assertIn("src/app.py", grouped)
            for noise in ["storage/data.txt", "storage/blob.enc", ".env"]:
                self.assertNotIn(noise, grouped, noise)
            self.assertEqual(out["discovery"]["method"], "git-ls-files")

    def test_untracked_non_ignored_files_are_included(self):
        # New files join the review surface before anyone remembers to commit.
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            _init_repo(d)
            _git(d, "add", ".")
            _git(d, "commit", "-q", "-m", "init")
            self._touch(d, "src/brand_new.py")
            out, _ = self._run_scan(d)
            self.assertIn("src/brand_new.py", self._grouped(out))

    def test_git_paths_are_nul_safe(self):
        with tempfile.TemporaryDirectory() as d:
            names = ["src/line\nbreak.py", "src/tab\tname.py", 'src/quote"name.py']
            for name in names:
                self._touch(d, name)
            _init_repo(d)
            _git(d, "add", ".")
            _git(d, "commit", "-q", "-m", "init")
            out, _ = self._run_scan(d)
            grouped = self._grouped(out)
            for name in names:
                self.assertIn(name, grouped)

    def test_external_symlink_is_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo")
            os.makedirs(repo)
            self._touch(d, "outside.txt", "sentinel")
            os.symlink("../outside.txt", os.path.join(repo, "external.txt"))
            _init_repo(repo)
            _git(repo, "add", ".")
            _git(repo, "commit", "-q", "-m", "init")
            out, _ = self._run_scan(repo)
            self.assertNotIn("external.txt", self._grouped(out))

    def test_tracked_noise_dirs_still_excluded(self):
        # A repo that TRACKS node_modules still shouldn't review it.
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            self._touch(d, "node_modules/pkg/index.js")
            _init_repo(d)
            _git(d, "add", "-f", ".")
            _git(d, "commit", "-q", "-m", "init")
            out, _ = self._run_scan(d)
            self.assertNotIn("node_modules/pkg/index.js", self._grouped(out))

    def test_fixture_corpora_pruned_from_git_listing(self):
        # tests/fixtures IS tracked in real targets — the #434 exclusion must
        # hold on the git path too, with the same disclosure and redteam bypass.
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            self._touch(d, "tests/fixtures/vuln/main.rs")
            _init_repo(d)
            _git(d, "add", ".")
            _git(d, "commit", "-q", "-m", "init")
            out, err = self._run_scan(d)
            self.assertNotIn("tests/fixtures/vuln/main.rs", self._grouped(out))
            self.assertEqual(out["excluded"]["fixture_dirs"], ["tests/fixtures"])
            self.assertIn("fixture exclusion", err)
            out2, _ = self._run_scan(d, "--security", "redteam")
            self.assertIn("tests/fixtures/vuln/main.rs", self._grouped(out2))

    def test_nested_git_paths_never_reviewable(self):
        # A gitlink / nested-repo .git entry is never a reviewable file (#500
        # observed design-system/.git leaking into group lists on Kimi).
        filtered = orch._filter_reviewable(
            ["src/app.py", "design-system/.git", "vendor/lib/.git/config"],
            include_fixtures=True, pruned_fixtures=None,
            isfile=lambda rel: True)
        self.assertEqual(filtered, ["src/app.py"])

    def test_non_git_target_falls_back_to_walk(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            out, _ = self._run_scan(d)
            self.assertIn("src/app.py", self._grouped(out))
            self.assertEqual(out["discovery"]["method"], "walk")


class TestGlobSemantics(unittest.TestCase):
    """#499 match patterns are gitignore-flavored: '*' stays inside a path
    segment, '**' crosses segments, a pattern with no '/' matches the basename
    at any depth, and '!' re-excludes with last-match-wins."""

    def _m(self, path, patterns):
        return orch.match_patterns(path, patterns)

    def test_star_does_not_cross_slash(self):
        self.assertTrue(self._m("skill/scripts/run.py", ["skill/scripts/*.py"]))
        self.assertFalse(self._m("skill/scripts/tools/x.py", ["skill/scripts/*.py"]))

    def test_double_star_crosses_slash(self):
        self.assertTrue(self._m("skill/scripts/tools/x.py", ["skill/scripts/**"]))
        self.assertTrue(self._m("a/b/c/d.py", ["a/**/d.py"]))

    def test_adjacent_double_stars_collapse_no_redos(self):
        # A repo-supplied groups.yml `match:` pattern with many adjacent `**/`
        # segments used to compile to sequential `(?:[^/]+/)*` quantifiers --
        # the catastrophic-backtracking ReDoS shape that could hang discovery.
        # Adjacent runs now fold to one; matching stays correct.
        rx = orch._glob_to_re("**/" * 25 + "x")
        self.assertLessEqual(rx.pattern.count("(?:[^/]+/)*"), 1)
        self.assertTrue(rx.match("a/b/c/x"))
        self.assertFalse(rx.match("a/b/c/y"))
        self.assertTrue(self._m("a/b/x", ["**/" * 25 + "x"]))

    def test_single_star_chain_no_redos(self):
        rx = orch._glob_to_re("*/" * 20 + "file.py")
        path = "a/" * 20 + "file.py"
        self.assertTrue(rx.match(path))
        self.assertFalse(rx.match("a/" * 19 + "file.py"))
        self.assertTrue(self._m(path, ["*/" * 20 + "file.py"]))

    def test_no_slash_matches_basename_at_any_depth(self):
        self.assertTrue(self._m("README.md", ["*.md"]))
        self.assertTrue(self._m("docs/deep/notes.md", ["*.md"]))
        self.assertFalse(self._m("docs/notes.md.bak", ["*.md"]))

    def test_negation_last_match_wins(self):
        pats = ["skill/scripts/**", "!skill/scripts/tools/**"]
        self.assertTrue(self._m("skill/scripts/run.py", pats))
        self.assertFalse(self._m("skill/scripts/tools/x.py", pats))
        # a later positive can re-include
        self.assertTrue(self._m(
            "skill/scripts/tools/base.py",
            pats + ["skill/scripts/tools/base.py"]))

    def test_question_mark_single_segment_char(self):
        self.assertTrue(self._m("a/v1.py", ["a/v?.py"]))
        self.assertFalse(self._m("a/v12.py", ["a/v?.py"]))


class TestCatalogMatchGroups(unittest.TestCase):
    """#499: intensional groups. A groups.yml with match: patterns gives files
    stable group identities; files matching no group are auto-chunked AND
    disclosed as ungrouped_files — coverage honesty at the discovery layer."""

    CATALOG = (
        "groups:\n"
        "  pipeline:\n"
        "    match: ['skill/scripts/*.py', '!skill/scripts/tools/**']\n"
        "  adapters:\n"
        "    match:\n"
        "      - 'skill/scripts/tools/**'\n"
        "  docs:\n"
        "    match: ['*.md']\n"
    )

    def _setup(self, d):
        for rel in ["skill/scripts/run.py", "skill/scripts/tools/pip.py",
                    "README.md", "docs/notes.md", "orphan/loner.py"]:
            _touch(d, rel)
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w", encoding="utf-8") as fh:
            fh.write(self.CATALOG)

    def _run_scan(self, d):
        rc, data, err = _run_scan_helper(d)
        self.assertEqual(rc, 0)
        return data, err

    def test_files_assigned_to_stable_named_groups(self):
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            out, err = self._run_scan(d)
            by_name = {g["name"]: g["files"] for g in out["groups"]}
            self.assertEqual(by_name["pipeline"], ["skill/scripts/run.py"])
            self.assertEqual(by_name["adapters"], ["skill/scripts/tools/pip.py"])
            self.assertEqual(sorted(by_name["docs"]), ["README.md", "docs/notes.md"])
            # leftover chunks keep the legacy ._N naming
            self.assertIn("orphan/loner.py",
                          [f for n, fs in by_name.items() if n.startswith("._")
                           for f in fs])
            self.assertEqual(out["ungrouped_files"], ["orphan/loner.py"])
            self.assertEqual(out["counts"]["ungrouped"], 1)
            self.assertIn("ungrouped", err)  # loud, not silent

    def test_first_matching_group_wins(self):
        # docs also glob-matches nothing else here, but a file matching two
        # groups must land in the FIRST (catalog order), exactly once.
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            out, _ = self._run_scan(d)
            all_files = [f for g in out["groups"] for f in g["files"]]
            self.assertEqual(len(all_files), len(set(all_files)))

    def test_oversize_match_group_chunks_with_suffixes(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(20):
                full = os.path.join(d, "pkg", "m%02d.py" % i)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                open(full, "w").close()
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
                fh.write("groups:\n  pkg:\n    match: ['pkg/**']\n")
            out, _ = self._run_scan(d)
            names = [g["name"] for g in out["groups"]]
            self.assertEqual(names, ["pkg_1", "pkg_2"])
            self.assertEqual(sum(len(g["files"]) for g in out["groups"]), 20)

    def test_catalog_without_match_keys_keeps_legacy_chunking(self):
        with tempfile.TemporaryDirectory() as d:
            full = os.path.join(d, "src", "app.py")
            os.makedirs(os.path.dirname(full), exist_ok=True)
            open(full, "w").close()
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
                fh.write("groups:\n  Products:\n    patterns: ['**/product*']\n")
            out, _ = self._run_scan(d)
            self.assertTrue(all(g["name"].startswith("._") for g in out["groups"]))
            self.assertNotIn("ungrouped_files", out)

    def test_exclude_paths_pruned_before_grouping_and_disclosed(self):
        # Task 4 (#1136): a committed top-level `exclude_paths:` glob prunes
        # matching files BEFORE catalog_groups/assign_by_catalog runs, so they
        # land in NEITHER a named group NOR the ._N leftover chunk -- and the
        # prune is disclosed (globs + count), never silently dropped.
        # (Uses paths NOT already pruned by the unrelated fixture-dir heuristic
        # -- docs/secret/** would otherwise match the `docs` group's `*.md`,
        # vendor/** would otherwise fall to a ._N leftover -- to prove this is
        # exclude_paths doing the work, not #434's fixture pruning.)
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            _touch(d, "docs/secret/leak.md")
            _touch(d, "vendor/dep.py")
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w", encoding="utf-8") as fh:
                fh.write(self.CATALOG + "exclude_paths: ['docs/secret/**', 'vendor/**']\n")
            out, _err = self._run_scan(d)
            all_files = [f for g in out["groups"] for f in g["files"]]
            self.assertNotIn("docs/secret/leak.md", all_files)
            self.assertNotIn("vendor/dep.py", all_files)
            self.assertNotIn("docs/secret/leak.md", out.get("ungrouped_files", []))
            self.assertNotIn("vendor/dep.py", out.get("ungrouped_files", []))
            self.assertEqual(sorted(out["exclude_paths"]), ["docs/secret/**", "vendor/**"])
            self.assertEqual(out["excluded_count"], 2)

    def test_exclude_paths_absent_is_zero_behavior_change(self):
        # Back-compat: no `exclude_paths:` key -> no disclosure fields, and
        # the previously-covered "orphan" leftover behavior is untouched.
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            out, _err = self._run_scan(d)
            self.assertNotIn("exclude_paths", out)
            self.assertNotIn("excluded_count", out)
            self.assertEqual(out["ungrouped_files"], ["orphan/loner.py"])


class TestGroupObjParent(unittest.TestCase):
    """Task 7: every group `discovery` emits carries a `parent` field, so
    `groups.json` records it for Task 6's synthesize roll-up. Back-compat:
    a leaf/leftover group self-parents (parent == name)."""

    def test_group_obj_defaults_to_self_parent(self):
        g = orch._group_obj("leaf", ["a.py"], "standard")
        self.assertEqual(g["parent"], "leaf")

    def test_group_obj_uses_explicit_parent(self):
        g = orch._group_obj("UI:Admin", ["a.py"], "standard", parent="UI")
        self.assertEqual(g["parent"], "UI")

    def test_catalog_groups_subgroup_carries_parent(self):
        # Mimics _matrix_catalog's parse_groups-shaped output for a
        # `UI: {Admin: {match: [...]}}` subgroup, alongside a flat leaf.
        catalog = {
            "UI:Admin": {"match": ["ui/admin/**"], "tests": [], "floor": set(),
                         "exclude": set(), "parent": "UI"},
            "docs": {"match": ["*.md"], "tests": [], "floor": set(),
                    "exclude": set(), "parent": "docs"},
        }
        files = ["ui/admin/panel.py", "README.md", "orphan.py"]
        groups, leftovers = orch.catalog_groups(files, catalog, 15, "standard")
        by_name = {g["name"]: g for g in groups}
        self.assertEqual(by_name["UI:Admin"]["parent"], "UI")
        # leaf group self-parents
        self.assertEqual(by_name["docs"]["parent"], "docs")
        # leftover ._N chunk self-parents
        leftover_groups = [g for g in groups if g["name"].startswith("._")]
        self.assertEqual(len(leftover_groups), 1)
        self.assertEqual(leftover_groups[0]["parent"], leftover_groups[0]["name"])
        self.assertEqual(leftovers, ["orphan.py"])

    def test_catalog_groups_oversize_subgroup_chunks_keep_parent(self):
        catalog = {
            "UI:Admin": {"match": ["ui/admin/**"], "tests": [], "floor": set(),
                         "exclude": set(), "parent": "UI"},
        }
        files = ["ui/admin/m%02d.py" % i for i in range(20)]
        groups, _leftovers = orch.catalog_groups(files, catalog, 15, "standard")
        names = sorted(g["name"] for g in groups)
        self.assertEqual(names, ["UI:Admin_1", "UI:Admin_2"])
        self.assertTrue(all(g["parent"] == "UI" for g in groups))


class TestCommonsCatalog(unittest.TestCase):
    """Task 5 (#499): a curated Commons vocabulary (Docs/CI/Build/Config/Deps)
    names committed-unmatched leftover files before the true residual falls
    to `._N`. Committed groups always win -- Commons only ever sees
    leftovers."""

    def test_commons_names_leftovers_before_dot_n(self):
        catalog = {"App": {"match": ["src/**"]}}
        groups, leftovers = orch.catalog_groups(
            ["src/app.py", "README.md", "Dockerfile", "weird.xyz"],
            catalog, max_per_group=50, security_mode="standard")
        names = {g["name"] for g in groups}
        self.assertIn("Docs", names)   # README.md -> Docs
        self.assertIn("Build", names)  # Dockerfile -> Build
        self.assertTrue(any(n.startswith("._") for n in names))  # weird.xyz -> residual
        self.assertIn("src/app.py",
                       next(g["files"] for g in groups if g["name"] == "App"))
        # weird.xyz is the true residual -- disclosed, not silently absorbed.
        self.assertEqual(leftovers, ["weird.xyz"])

    def test_committed_group_wins_over_commons(self):
        # A committed `src/**` group claims src/app.py -- Commons never sees it.
        catalog = {"App": {"match": ["src/**"]}}
        groups, _leftovers = orch.catalog_groups(
            ["src/app.py"], catalog, max_per_group=50, security_mode="standard")
        names = {g["name"] for g in groups}
        self.assertEqual(names, {"App"})

    def test_commons_group_self_parents(self):
        groups, _leftovers = orch.catalog_groups(
            ["README.md"], {}, max_per_group=50, security_mode="standard")
        by_name = {g["name"]: g for g in groups}
        self.assertEqual(by_name["Docs"]["parent"], "Docs")

    def test_commons_never_collides_with_committed_group_name(self):
        # A committed group named `Docs` (a Commons category name a user may
        # plausibly author) must NOT be re-emitted by the Commons pass: two
        # groups named `Docs` would write to the SAME findings-Docs-<domain>.json
        # (silent clobber) and produce a duplicate report node. Committed wins;
        # the leftover README falls to the committed `Docs` group's `match`, and
        # Commons is suppressed for that name entirely -> exactly one `Docs`.
        catalog = {"Docs": {"match": ["docs/**", "README.md"]}}
        groups, _leftovers = orch.catalog_groups(
            ["docs/guide.md", "README.md"],
            catalog, max_per_group=50, security_mode="standard")
        docs_groups = [g for g in groups if g["name"] == "Docs"]
        self.assertEqual(len(docs_groups), 1)              # no duplicate node
        self.assertEqual(sorted(docs_groups[0]["files"]),
                         ["README.md", "docs/guide.md"])   # committed group owns both
        self.assertEqual(docs_groups[0]["parent"], "Docs")  # committed leaf, not Commons


class TestPanelPriority(unittest.TestCase):
    def test_compute_group_panels_emits_priority_order(self):
        # Whatever panels are present, they must appear in PANEL_PRIORITY order.
        files = ["app.py", "models.py", "schema.sql", "infra/main.tf", "tests/test_app.py"]
        panels = orch.compute_group_panels(files, "standard")
        assert panels == [p for p in orch.PANEL_PRIORITY if p in panels]
        # security must precede code; code must precede test
        assert panels.index("security") < panels.index("code")
        assert panels.index("code") < panels.index("test")

    def test_compute_group_panels_redteam_mode_ordered(self):
        panels = orch.compute_group_panels(["app.py", "tests/test_app.py"], "redteam")
        if "redteam" not in panels or "security" in panels: raise AssertionError()
        if panels != [p for p in orch.PANEL_PRIORITY if p in panels]: raise AssertionError()

    def test_panels_in_priority_order_puts_unknown_last(self):
        assert orch.panels_in_priority_order(
            ["test", "zzz", "security"]) == ["security", "test", "zzz"]


class _FakeRun:
    """Fake subprocess.run: returncode 0 iff the git ref arg is in ok_refs."""
    def __init__(self, ok_refs):
        self.ok = set(ok_refs)
        self.calls = []
    def __call__(self, argv, **kw):
        self.calls.append(argv)
        return types.SimpleNamespace(returncode=0 if argv[-1] in self.ok else 1,
                                     stdout="", stderr="")


class TestDeltaOrchestration(unittest.TestCase):
    def test_resolve_base_precedence(self):
        # explicit wins even if others resolve
        self.assertEqual(
            orch.resolve_base(".", explicit="v1.0", pr_base="main",
                              runner=_FakeRun({"v1.0^{commit}", "main^{commit}"})),
            ("v1.0", "explicit"))
        self.assertEqual(
            orch.resolve_base(".", pr_base="release",
                              runner=_FakeRun({"release^{commit}"}))[1],
            "pr-base")

    def test_resolve_base_bad_explicit_fails_loud_no_fallthrough(self):
        # explicit given but unresolvable -> (None,'unresolved'); NOT main.
        self.assertEqual(
            orch.resolve_base(".", explicit="nope",
                              runner=_FakeRun({"main^{commit}"})),
            (None, "unresolved"))

    def test_resolve_base_fallback_and_no_head1(self):
        self.assertEqual(orch.resolve_base(".", runner=_FakeRun({"main^{commit}"})),
                         ("main", "fallback"))
        self.assertEqual(orch.resolve_base(".", runner=_FakeRun({"master^{commit}"})),
                         ("master", "fallback"))
        # nothing resolves (no main/master, no HEAD~1 tried) -> unresolved
        self.assertEqual(orch.resolve_base(".", runner=_FakeRun(set())),
                         (None, "unresolved"))

    def test_prune_fixture_files_standard_vs_redteam(self):
        paths = ["src/app.py", "tests/fixtures/vuln/main.rs"]
        self.assertEqual(orch.prune_fixture_files(paths, include_fixtures=False),
                         ["src/app.py"])
        self.assertEqual(orch.prune_fixture_files(paths, include_fixtures=True), paths)


class TestResolveBaseOriginFallback(unittest.TestCase):
    """#947 FIXME-3: a machine-derived pr_base prefers origin/<name> (fresh
    remote) over a possibly-stale local branch; explicit --base never falls
    through."""

    def _runner_resolving(self, *refs):
        def run(argv, *args, **kwargs):
            class R:
                pass
            r = R()
            ref = argv[-1]
            r.returncode = 0 if ref.rstrip("^{commit}") in refs else 1
            r.stdout = "abc\n" if r.returncode == 0 else ""
            return r
        return run

    def test_pr_base_prefers_origin_ref(self):
        base, src = orch.resolve_base("/r", pr_base="main",
                                      runner=self._runner_resolving("origin/main", "main"))
        self.assertEqual((base, src), ("origin/main", "pr-base"))

    def test_pr_base_falls_back_to_local_when_origin_absent(self):
        base, src = orch.resolve_base("/r", pr_base="main",
                                      runner=self._runner_resolving("main"))
        self.assertEqual((base, src), ("main", "pr-base"))

    def test_explicit_base_never_tries_origin(self):
        base, src = orch.resolve_base("/r", explicit="release-2",
                                      runner=self._runner_resolving("origin/release-2"))
        self.assertEqual((base, src), (None, "unresolved"))


class TestArtifactOutputGuard(unittest.TestCase):
    """Symlink-escape guards on the --out artifact root, migrated out of
    test_orchestrator.py::TestSetup (the rest of that class -- --setup
    scaffolding/readiness -- is covered by test_setup_flow.py and
    test_driver.py::TestDriverSetup)."""

    def test_artifact_output_rejects_symlinked_panopticon(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, os.path.join(d, ".panopticon"))
            with self.assertRaisesRegex(ValueError, "not a symlink"):
                orch._validate_artifact_output(
                    d, os.path.join(d, ".panopticon", "groups.json"))

    def test_main_rejects_symlinked_artifact_root(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, os.path.join(d, ".panopticon"))
            self.assertEqual(orch.main(["--repo", d, "--repo-scan"]), 2)
            self.assertEqual(orch.main(["--repo", d, "--repo-scan", "--out", os.path.join(d, ".panopticon", "out.json")]), 2)

    def test_scope_changed_fails_when_not_git_repo(self):
        with tempfile.TemporaryDirectory() as d:
            _touch(d, "src/app.py")
            # d is not a git repo, so collect_changed_files returns None
            self.assertEqual(orch.main(["--repo", d, "--repo-scan", "--scope-changed"]), 2)

    def test_scope_files_fails_with_bad_base(self):
        with tempfile.TemporaryDirectory() as d:
            _touch(d, "src/app.py")
            _init_repo(d)
            _git(d, "add", ".")
            _git(d, "commit", "-q", "-m", "init")
            # bad base -> resolve_base_or_die returns None -> return 2
            self.assertEqual(orch.main(["--repo", d, "--repo-scan", "--scope-files", "src/app.py", "--base", "nope"]), 2)


class TestChangedFilesRenameParity(unittest.TestCase):
    """#978: discovery's changed-file diff must use the same rename semantics
    as diff_map.hunk_map (--find-renames), so the reviewed file set and the
    on-diff hunk map can never diverge on a similarity-threshold edge."""

    def test_diff_invocation_includes_find_renames(self):
        calls = []

        def fake_git(repo, args):
            calls.append(list(args))
            r = types.SimpleNamespace(stdout="")
            if args and args[0] == "merge-base":
                r.stdout = "abc123\n"
            return r

        # orch IS discovery (import discovery as orch); patching orch._git
        # patches discovery._git directly, which is also what
        # discovery.collect_changed_files's bare _git(...) global lookup
        # resolves through -- no cross-module duplication needed post-A2.
        with mock.patch.object(orch, "_git", side_effect=fake_git):
            orch.collect_changed_files("/tmp/x", base="main")
        diff_calls = [a for a in calls if a and a[0] == "diff"]
        self.assertTrue(diff_calls, "no git diff invocation captured")
        for a in diff_calls:
            self.assertIn("--find-renames", a)


class TestGroupsFormatReconciliation(unittest.TestCase):
    """Task 5: groups.yml mapping form is canonical; load_catalog reads a
    legacy list form (with a one-time notice) so old seeded files still
    load instead of silently collapsing to {} on raw.items()."""

    def _repo(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        return d

    def test_seed_writes_mapping_form_that_load_catalog_reads(self):
        # _seed_groups_manifest lives in setup_flow.py (orchestrator only ever
        # re-exported it); load_catalog is the discovery primitive this test
        # actually guards.
        d = self._repo()
        for sub in ("src", "tests"):
            os.makedirs(os.path.join(d, sub))
            with open(os.path.join(d, sub, "a.py"), "w", encoding="utf-8") as fh:
                pass
        path, created, names = setup_flow._seed_groups_manifest(d)
        self.assertTrue(created)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("- name:", text)          # not the legacy list form
        catalog = orch.load_catalog(d)
        self.assertTrue(catalog)                    # actually loads (was silent {})
        self.assertEqual(catalog["src"]["match"], ["src/**"])

    def test_load_catalog_normalizes_legacy_list_form(self):
        d = self._repo()
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write(textwrap.dedent("""\
                groups:
                  - name: src
                    match:
                      - src/**
            """))
        catalog = orch.load_catalog(d)
        self.assertIn("src", catalog)
        self.assertEqual(catalog["src"]["match"], ["src/**"])

    def test_assignment_identical_across_forms(self):
        files = ["src/a.py", "tests/b.py", "docs/c.md"]
        mapping = {"src": {"match": ["src/**"]}, "tests": {"match": ["tests/**"]}}
        assigned, leftovers = orch.assign_by_catalog(files, mapping)
        self.assertEqual(assigned, {"src": ["src/a.py"], "tests": ["tests/b.py"]})
        self.assertEqual(leftovers, ["docs/c.md"])

    def test_tests_globs_claim_files_into_their_group(self):
        catalog = {"Auth": {"match": ["src/auth/**"], "tests": ["tests/auth/**"]}}
        assigned, leftovers = orch.assign_by_catalog(
            ["src/auth/login.py", "tests/auth/test_login.py", "misc/x.py"], catalog)
        self.assertIn("src/auth/login.py", assigned["Auth"])
        self.assertIn("tests/auth/test_login.py", assigned["Auth"])   # was a leftover before
        self.assertEqual(leftovers, ["misc/x.py"])


def _repo_with_matrix(tmp_path):
    import subprocess, os
    repo = tmp_path
    (repo / ".panopticon").mkdir(parents=True)
    for p in ["src/auth/login.py", "src/checkout/pay.py", "src/checkout/cart.py",
              "src/misc/other.py"]:                    # matches no catalog group
        os.makedirs(os.path.dirname(repo / p), exist_ok=True)
        (repo / p).write_text("x=1\n")
    (repo / ".panopticon" / "groups.yml").write_text(
        "groups:\n"
        "  Auth:\n    match: ['src/auth/**']\n    panels: [SEC]\n"
        "  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC, DAT]\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-qm", "x"], cwd=repo, check=True)
    return repo


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
    # assign_by_catalog uses only `match` → Core claims src/a.py
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
    import discovery as orchestrator, json
    repo = _repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-group", "Checkout",
                       str(repo), "--out", str(out)])
    groups = json.loads(out.read_text())["groups"]
    names = {g["name"] for g in groups}
    files = sorted(f for g in groups for f in g["files"])
    assert names == {"Checkout"}
    assert files == ["src/checkout/cart.py", "src/checkout/pay.py"]


def test_repo_scan_scope_file_restricts_to_file_and_its_group(tmp_path):
    import discovery as orchestrator, json
    repo = _repo_with_matrix(tmp_path)
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
    import discovery as orchestrator, json, os
    for spelling in ("./src/checkout/pay.py",):
        repo = _repo_with_matrix(tmp_path / spelling.replace("/", "_").replace(".", "d"))
        out = repo / "groups.json"
        rc = orchestrator.main(["--repo-scan", "--scope-file", spelling,
                                str(repo), "--out", str(out)])
        assert rc == 0, spelling
        files = sorted(f for g in json.loads(out.read_text())["groups"] for f in g["files"])
        assert files == ["src/checkout/pay.py"], spelling
    # absolute path
    repo = _repo_with_matrix(tmp_path / "abs")
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
    import discovery as orchestrator, json
    repo = _repo_with_matrix(tmp_path)
    (repo / "src" / "checkout" / "test_pay.py").write_text("def test_x():\n    pass\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-qm", "add sibling test"], cwd=repo, check=True)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-file", "src/checkout/pay.py",
                       str(repo), "--out", str(out)])
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py", "src/checkout/test_pay.py"]
    assert {g["name"] for g in groups} == {"Checkout"}


def test_repo_scan_scope_dir_restricts_to_directory(tmp_path):
    import discovery as orchestrator, json
    repo = _repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-dir", "src/checkout",
                       str(repo), "--out", str(out)])
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/cart.py", "src/checkout/pay.py"]
    assert {g["name"] for g in groups} == {"Checkout"}


def test_repo_scan_scope_group_unknown_name_errors(tmp_path, capsys):
    import discovery as orchestrator
    repo = _repo_with_matrix(tmp_path)
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
    import discovery as orchestrator, json
    repo = _repo_with_matrix(tmp_path)
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

def _repo_with_scalar_match_group(tmp_path):
    """groups.yml with a SCALAR `match:` group ("Bad") ahead of a
    well-formed one ("Auth") -- the worst-case catalog order for the
    char-split bug (Bad, if corrupted, would shadow every later group)."""
    import subprocess
    repo = tmp_path
    (repo / ".panopticon").mkdir(parents=True)
    for p in ["src/auth/login.py", "src/bad/thing.py"]:
        os.makedirs(os.path.dirname(repo / p), exist_ok=True)
        (repo / p).write_text("x=1\n")
    (repo / ".panopticon" / "groups.yml").write_text(
        "groups:\n"
        "  Bad:\n    match: src/bad/**\n"           # scalar -- NOT a list
        "  Auth:\n    match: ['src/auth/**']\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-qm", "x"], cwd=repo, check=True)
    return repo


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
    import discovery as orchestrator, json
    repo = _repo_with_scalar_match_group(tmp_path)
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
    import discovery as orchestrator, json
    repo = _repo_with_scalar_match_group(tmp_path)
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
    import discovery as orchestrator, json
    repo = _repo_with_matrix(tmp_path)
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
    repo = _repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-file", "src/ghost.py",
                            str(repo), "--out", str(out)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "src/ghost.py" in err


def test_repo_scan_scope_dir_no_tracked_files_errors(tmp_path, capsys):
    import discovery as orchestrator
    repo = _repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-dir", "no/such/dir",
                            str(repo), "--out", str(out)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "no/such/dir" in err


# --- P6.3: --scope-changed/--scope-files -- delta scopes on --repo-scan.
# These narrow the discovered file universe to a changed-vs-base set (or an
# explicit list) BEFORE the same matrix assignment runs (like --scope-file/
# -dir/-group), and additionally emit .panopticon/diff-hunks.json so
# synthesize's on-diff gate has a hunk map to scope findings against.

def test_repo_scan_scope_changed_restricts_and_emits_diff_hunks(tmp_path):
    import discovery as orchestrator, json, subprocess
    repo = _repo_with_matrix(tmp_path)   # commits Auth + Checkout matrix + files
    # create a new commit changing one checkout file
    (repo / "src/checkout/pay.py").write_text("x=2\n")
    subprocess.run(["git","-c","user.email=t@t","-c","user.name=t","commit","-aqm","c2"],
                   cwd=repo, check=True)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-changed", "--base", "HEAD~1",
                            str(repo), "--out", str(out)])
    assert rc == 0
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py"]                       # restricted to changed
    hunks = json.loads((repo/".panopticon"/"diff-hunks.json").read_text())
    assert hunks["base"] and "src/checkout/pay.py" in hunks["hunks"]


def test_repo_scan_scope_changed_bad_base_exits_2_no_artifact(tmp_path):
    import discovery as orchestrator
    repo = _repo_with_matrix(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    assert orchestrator.main(["--repo-scan","--scope-changed","--base","nope", str(repo), "--out", str(out)]) == 2
    assert not (repo/".panopticon"/"diff-hunks.json").exists()


def test_repo_scan_scope_files_with_base_emits_diff_hunks(tmp_path):
    import discovery as orchestrator, json, subprocess
    repo = _repo_with_matrix(tmp_path)
    (repo / "src/checkout/pay.py").write_text("x=2\n")
    subprocess.run(["git","-c","user.email=t@t","-c","user.name=t","commit","-aqm","c2"],
                   cwd=repo, check=True)
    out = repo / ".panopticon" / "groups.json"
    # --repo (not the positional target) precedes --scope-files here -- nargs="+"
    # would otherwise greedily swallow a trailing positional target (same
    # convention as the existing --files tests).
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan", "--scope-files",
                            "src/checkout/pay.py", "--base", "HEAD~1",
                            "--out", str(out)])
    assert rc == 0
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py"]
    hunks = json.loads((repo/".panopticon"/"diff-hunks.json").read_text())
    assert hunks["base"] and "src/checkout/pay.py" in hunks["hunks"]


def test_repo_scan_scope_files_without_base_emits_no_diff_hunks(tmp_path):
    import discovery as orchestrator, json
    repo = _repo_with_matrix(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan", "--scope-files",
                            "src/checkout/pay.py", "--out", str(out)])
    assert rc == 0
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py"]
    assert not (repo/".panopticon"/"diff-hunks.json").exists()


def _repo_with_exclude(tmp_path):
    """Repo whose committed groups.yml carries `exclude_paths: ['vendor/**']`,
    with a vendored file a delta scope would otherwise pick up."""
    import subprocess, os
    repo = tmp_path
    (repo / ".panopticon").mkdir(parents=True)
    for p in ["src/checkout/pay.py", "vendor/dep.py"]:
        os.makedirs(os.path.dirname(repo / p), exist_ok=True)
        (repo / p).write_text("x=1\n")
    (repo / ".panopticon" / "groups.yml").write_text(
        "groups:\n"
        "  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n"
        "exclude_paths: ['vendor/**']\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-qm", "x"], cwd=repo, check=True)
    return repo


def test_repo_scan_scope_files_applies_exclude_paths(tmp_path):
    # #1136 delta-path parity: --scope-files rebuilds the file set from the
    # user's explicit list, NOT from the exclude-pruned `allf`. A vendored file
    # named in the delta must still be pruned by committed exclude_paths (never
    # grouped/reviewed), and the disclosed count must reflect the delta set (1),
    # not the whole-repo count.
    import discovery as orchestrator, json
    repo = _repo_with_exclude(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan", "--scope-files",
                            "src/checkout/pay.py", "vendor/dep.py",
                            "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    files = sorted(f for g in doc["groups"] for f in g["files"])
    assert files == ["src/checkout/pay.py"]            # vendor/dep.py pruned
    assert doc["exclude_paths"] == ["vendor/**"]
    assert doc["excluded_count"] == 1                  # delta count, not whole-repo


def test_repo_scan_scope_changed_applies_exclude_paths(tmp_path):
    # Same parity guard on the --scope-changed path (rebuilds from git-diff
    # output). A changed vendored file must not slip past exclude_paths.
    import discovery as orchestrator, json, subprocess
    repo = _repo_with_exclude(tmp_path)
    (repo / "src/checkout/pay.py").write_text("x=2\n")
    (repo / "vendor/dep.py").write_text("y=2\n")
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-aqm", "c2"], cwd=repo, check=True)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-changed", "--base", "HEAD~1",
                            str(repo), "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    files = sorted(f for g in doc["groups"] for f in g["files"])
    assert files == ["src/checkout/pay.py"]            # vendor/dep.py pruned
    assert doc["excluded_count"] == 1


def test_repo_scan_scope_changed_pr_base_resolves_origin_only_base(tmp_path):
    # Finding B (B1 regression lock): the gh-detected PR base must flow through
    # the --pr-base channel so resolve_base applies its origin/<base> preference
    # (#947). This repo has the base ONLY as refs/remotes/origin/main -- there is
    # NO local `main` branch -- exactly the shape acquire_pr leaves (it fetches
    # only the PR head). Under the OLD code path (the base threaded as an explicit
    # --base main) resolve_base would treat "main" as explicit, fail to resolve
    # it, and return 2 with no artifact. With --pr-base it resolves to origin/main.
    import discovery as orchestrator, json, subprocess
    repo = _repo_with_matrix(tmp_path)   # commits Auth + Checkout matrix + files
    base_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                              capture_output=True, text=True,
                              check=True).stdout.strip()
    # Base lives ONLY as a remote-tracking ref; rename the local default branch
    # away so no local `main` (or `master`) can satisfy an explicit resolve.
    subprocess.run(["git", "update-ref", "refs/remotes/origin/main", base_sha],
                   cwd=repo, check=True)
    subprocess.run(["git", "branch", "-m", "work"], cwd=repo, check=True)
    # A committed change on top of the origin/main base so there IS a delta.
    (repo / "src/checkout/pay.py").write_text("x=2\n")
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-aqm", "c2"], cwd=repo, check=True)
    # Sanity: no local `main` branch exists (only origin/main).
    branches = subprocess.run(["git", "branch", "--format=%(refname:short)"],
                              cwd=repo, capture_output=True, text=True,
                              check=True).stdout.split()
    assert "main" not in branches

    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-changed", "--pr-base", "main",
                            str(repo), "--out", str(out)])
    assert rc == 0                                              # did NOT return 2
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py"]                    # restricted to changed
    hunks = json.loads((repo/".panopticon"/"diff-hunks.json").read_text())
    assert hunks["base"] == "origin/main"                      # origin-preference won
    assert "src/checkout/pay.py" in hunks["hunks"]


def test_repo_scan_scope_changed_explicit_base_ignores_pr_base(tmp_path):
    # --base (explicit user override) still takes precedence over --pr-base and
    # never falls through: a bad explicit base fails loudly even when a valid
    # --pr-base is present (resolve_base's explicit-never-fallthrough contract).
    import discovery as orchestrator
    repo = _repo_with_matrix(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-changed",
                            "--base", "nope", "--pr-base", "main",
                            str(repo), "--out", str(out)])
    assert rc == 2
    assert not (repo/".panopticon"/"diff-hunks.json").exists()


def test_write_diff_hunks_schema_version_and_atomic(tmp_path):
    import discovery
    hunks_out = tmp_path / "diff-hunks.json"
    discovery.write_diff_hunks(str(tmp_path), None, "none", str(hunks_out), 0, False)
    assert hunks_out.exists()
    data = json.loads(hunks_out.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["files_changed"] == 0



def test_collect_changed_files_default_branch_fallback():
    from unittest.mock import patch, MagicMock
    import discovery
    with patch('discovery._git') as mock_git:
        mock_git.side_effect = [
            Exception("not main"),  # fails on main
            MagicMock(stdout="fake_master_hash\n"), # succeeds on master
            MagicMock(stdout="file1.py\n"), MagicMock(stdout="")
        ]
        with patch('discovery._on_allowed_dotdir_path', return_value=True), patch('os.path.isfile', return_value=True):
            res = discovery.collect_changed_files("/tmp/x", base=None)
        assert res == ["file1.py"]

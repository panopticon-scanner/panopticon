import json
import os
import subprocess
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import orchestrator as orch


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

    def test_rejects_implementation_files(self):
        for path in [
            "app/models/user.rb",
            "internal/svc/handler.go",
            "src/components/Button.tsx",
            "src/parser.py",
            "src/main/java/Foo.java",
        ]:
            self.assertFalse(orch.is_test_file(path), path)


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


class TestGroupArg(unittest.TestCase):
    def test_plain_group(self):
        self.assertEqual(orch.parse_group_arg("Products"), ("Products", None))

    def test_group_with_facet(self):
        self.assertEqual(orch.parse_group_arg("Products[Uploads]"), ("Products", "Uploads"))

    def test_strips_whitespace(self):
        self.assertEqual(orch.parse_group_arg(" Products [ Uploads ] "), ("Products", "Uploads"))


class TestCatalog(unittest.TestCase):
    CATALOG = (
        "groups:\n"
        "  Products:\n"
        "    patterns:\n"
        "      - '**/product*'\n"
        "      - '**/*product*/**'\n"
        "    facets:\n"
        "      Uploads: [upload, attachment, multipart]\n"
        "      Pricing:\n"
        "        - price\n"
        "        - discount\n"
    )

    def test_fallback_parser(self):
        data = orch._parse_catalog_yaml(self.CATALOG)
        self.assertIn("Products", data)
        self.assertEqual(data["Products"]["patterns"], ["**/product*", "**/*product*/**"])
        self.assertEqual(data["Products"]["facets"]["Uploads"], ["upload", "attachment", "multipart"])
        self.assertEqual(data["Products"]["facets"]["Pricing"], ["price", "discount"])

    def test_load_catalog_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(orch.load_catalog(d), {})

    def test_load_catalog_reads_file(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
                fh.write(self.CATALOG)
            data = orch.load_catalog(d)
            self.assertIn("Products", data)

    def test_load_catalog_tolerates_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
                fh.write("groups:\n  : : :\n   ??? not valid\n")
            self.assertEqual(orch.load_catalog(d), {})   # tolerant, no raise


class TestExpandAndTests(unittest.TestCase):
    def _touch(self, root, rel):
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        open(full, "w").close()

    def test_expand_patterns_recursive(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "app/models/product.rb")
            self._touch(d, "app/models/product_variant.rb")
            self._touch(d, "app/models/user.rb")
            hits = orch.expand_patterns(d, ["app/models/product*.rb"])
            self.assertEqual(hits, ["app/models/product.rb", "app/models/product_variant.rb"])

    def test_related_tests_found(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "app/models/user.rb")
            self._touch(d, "spec/models/user_spec.rb")
            self._touch(d, "src/parser.py")
            self._touch(d, "tests/test_parser.py")
            found = orch.related_tests(d, ["app/models/user.rb", "src/parser.py"])
            self.assertIn("spec/models/user_spec.rb", found)
            self.assertIn("tests/test_parser.py", found)

    def test_expand_patterns_stays_within_repo(self):
        with tempfile.TemporaryDirectory() as d:
            outside = os.path.join(d, "secret.txt")
            open(outside, "w").close()
            repo = os.path.join(d, "repo"); os.makedirs(repo)
            open(os.path.join(repo, "in.py"), "w").close()
            hits = orch.expand_patterns(repo, ["../secret.txt", "in.py"])
            self.assertEqual(hits, ["in.py"])          # the ../ escape is excluded


class TestCli(unittest.TestCase):
    def _touch(self, root, rel):
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        open(full, "w").close()

    def test_directory_mode_separates_tests(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/a.py")
            self._touch(d, "src/b.py")
            self._touch(d, "tests/test_a.py")
            res = orch.build_result(
                d, "directory", "src",
                None,
                impl=["src/a.py", "src/b.py"],
                tests=["tests/test_a.py"],
            )
            self.assertEqual(res["counts"]["implementation"], 2)
            self.assertEqual(res["counts"]["tests"], 1)
            self.assertEqual(len(res["groups"]), 1)

    def test_main_group_unknown_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            rc = orch.main(["--repo", d, "--group", "Nope"])
            self.assertEqual(rc, 2)

    def test_main_file_mode_emits_json(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/parser.py")
            self._touch(d, "tests/test_parser.py")
            import io
            import contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = orch.main(["--repo", d, "--file", "src/parser.py"])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["mode"], "file")
            self.assertEqual(out["groups"][0]["files"], ["src/parser.py"])
            self.assertIn("tests/test_parser.py", out["tests"])

    def test_main_group_success_emits_group(self):
        import io, contextlib
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/pay/charge.py")
            os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
                fh.write("groups:\n  Payments:\n    patterns:\n      - src/pay/**/*\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = orch.main(["--repo", d, "--group", "Payments"])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["mode"], "group")
            self.assertEqual(out["target"], "Payments")
            allfiles = [f for g in out["groups"] for f in g["files"]]
            self.assertIn("src/pay/charge.py", allfiles)   # catalog->expand->group wiring

    def test_main_files_mode_partitions_impl_and_tests(self):
        import io, contextlib
        with tempfile.TemporaryDirectory() as d:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = orch.main(["--repo", d, "--files", "src/a.py", "tests/test_a.py"])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["mode"], "files")
            impl = [f for g in out["groups"] for f in g["files"]]
            self.assertIn("src/a.py", impl)
            self.assertNotIn("tests/test_a.py", impl)      # test partitioned out of impl
            self.assertIn("tests/test_a.py", out["tests"])

    def test_main_repo_scan_excludes_dotfiles(self):
        import io, contextlib
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/main.py")
            self._touch(d, ".hidden/secret.py")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = orch.main(["--repo", d, "--repo-scan"])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["mode"], "repo")
            impl = [f for g in out["groups"] for f in g["files"]]
            self.assertIn("src/main.py", impl)
            self.assertFalse(any(f.startswith(".") or "/." in f for f in impl))  # dotfiles excluded

    def test_max_per_group_flag_limits_group_size(self):
        files = ["pkg/f%02d.py" % i for i in range(5)]
        res = orch.build_result("/tmp", "files", "changeset", None, files, [], max_per_group=2)
        self.assertTrue(all(len(g["files"]) <= 2 for g in res["groups"]))
        self.assertEqual(res["counts"]["groups"], 3)

    def test_build_result_includes_security_mode(self):
        res = orch.build_result("/tmp", "repo", ".", None, [], [],
                                security_mode="redteam")
        self.assertEqual(res["security_mode"], "redteam")

    def test_main_repo_scan_honors_security_mode_flag(self):
        import io, contextlib
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/a.py")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = orch.main(["--repo", d, "--repo-scan", "--security", "redteam"])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["security_mode"], "redteam")

    def test_main_repo_scan_writes_to_out_file(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/a.py")
            out_path = os.path.join(d, "groups.json")
            rc = orch.main(["--repo", d, "--repo-scan", "--out", out_path])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(out_path))
            with open(out_path, encoding="utf-8") as fh:
                out = json.load(fh)
            self.assertEqual(out["mode"], "repo")
            self.assertIn("src/a.py", [f for g in out["groups"] for f in g["files"]])

    def test_main_repo_scan_accepts_positional_target_and_out(self):
        """Regression for the brief's invocation style: --repo-scan TARGET --out PATH."""
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/a.py")
            out_path = os.path.join(d, "groups.json")
            rc = orch.main(["--repo-scan", d, "--out", out_path])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(out_path))
            with open(out_path, encoding="utf-8") as fh:
                out = json.load(fh)
            self.assertEqual(out["mode"], "repo")
            self.assertIn("src/a.py", [f for g in out["groups"] for f in g["files"]])

    def test_main_changes_mode_uses_git_diff(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/a.py")
            self._touch(d, "src/b.py")
            subprocess.run(["git", "init", "-q", d], check=True)
            subprocess.run(["git", "-C", d, "config", "user.email", "t@e.com"], check=True)
            subprocess.run(["git", "-C", d, "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", d, "add", "."], check=True)
            subprocess.run(["git", "-C", d, "commit", "-q", "-m", "init"], check=True)
            # modify a.py and add c.py on a feature branch
            with open(os.path.join(d, "src", "a.py"), "w") as fh:
                fh.write("# changed")
            self._touch(d, "src/c.py")
            out_path = os.path.join(d, "groups.json")
            rc = orch.main(["--repo", d, "--changes", "--out", out_path])
            self.assertEqual(rc, 0)
            with open(out_path, encoding="utf-8") as fh:
                out = json.load(fh)
            self.assertEqual(out["mode"], "changes")
            grouped = [f for g in out["groups"] for f in g["files"]]
            self.assertIn("src/a.py", grouped)
            self.assertIn("src/c.py", grouped)
            self.assertNotIn("src/b.py", grouped)

    def test_main_changes_without_git_warns(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/a.py")
            rc = orch.main(["--repo", d, "--changes"])
            self.assertEqual(rc, 2)

    def test_build_result_computes_surfaces_and_panels(self):
        impl = ["Dockerfile", "src/models.py", "migrations/001.sql"]
        res = orch.build_result("/tmp", "repo", ".", None, impl, [],
                                security_mode="standard")
        g = res["groups"][0]
        self.assertEqual(sorted(g["surfaces"]), ["architecture", "database"])
        self.assertIn("code", g["panels"])
        self.assertIn("security", g["panels"])
        self.assertIn("architecture", g["panels"])
        self.assertIn("database", g["panels"])

    def test_redteam_replaces_security_panel(self):
        impl = ["src/web.py"]
        res = orch.build_result("/tmp", "repo", ".", None, impl, [],
                                security_mode="redteam")
        g = res["groups"][0]
        self.assertIn("redteam", g["panels"])
        self.assertNotIn("security", g["panels"])
        self.assertEqual(res["security_mode"], "redteam")


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


class TestRepoScanDiscovery(unittest.TestCase):
    """Discovery-gap regressions for --repo-scan: noise exclusion, targeted
    dotdir inclusion (.github/workflows), and real test-file surfacing."""

    def _touch(self, root, rel):
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        open(full, "w").close()

    def _run_scan(self, d):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = orch.main(["--repo", d, "--repo-scan"])
        self.assertEqual(rc, 0)
        return json.loads(buf.getvalue())

    def _grouped(self, out):
        return [f for g in out["groups"] for f in g["files"]]

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


if __name__ == "__main__":
    unittest.main()

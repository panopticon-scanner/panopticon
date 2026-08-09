import json
import os
import subprocess
import sys
import types
import unittest
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill", "scripts"))
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
            # No --out: without --base, --files does not emit diff-hunks.json at
            # all, so no chdir/cwd concern remains here (#449 rework).
            with contextlib.redirect_stdout(buf), contextlib.chdir(d):
                rc = orch.main(["--repo", d, "--files", "src/a.py", "tests/test_a.py"])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["mode"], "files")
            impl = [f for g in out["groups"] for f in g["files"]]
            self.assertIn("src/a.py", impl)
            self.assertNotIn("tests/test_a.py", impl)      # test partitioned out of impl
            self.assertIn("tests/test_a.py", out["tests"])
            # No --base given: --files does NOT emit diff-hunks.json (#449 rework).
            self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "diff-hunks.json")))

    def test_main_files_mode_with_base_emits_diff_hunks(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/a.py")
            subprocess.run(["git", "init", "-q", d], check=True)
            subprocess.run(["git", "-C", d, "config", "user.email", "t@e.com"], check=True)
            subprocess.run(["git", "-C", d, "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", d, "add", "."], check=True)
            subprocess.run(["git", "-C", d, "commit", "-q", "-m", "init"], check=True)
            with open(os.path.join(d, "src", "a.py"), "w") as fh:
                fh.write("# changed")
            out_path = os.path.join(d, "groups.json")
            rc = orch.main(["--repo", d, "--files", "src/a.py", "--base", "main",
                            "--out", out_path])
            self.assertEqual(rc, 0)
            hunks_path = os.path.join(d, "diff-hunks.json")
            self.assertTrue(os.path.isfile(hunks_path))    # --base given: DOES emit
            with open(hunks_path, encoding="utf-8") as fh:
                hunks = json.load(fh)
            self.assertEqual(hunks["base"], "main")
            self.assertEqual(hunks["base_source"], "explicit")
            self.assertTrue(hunks["includes_uncommitted"])
            self.assertIsNotNone(hunks["base_commit"])
            self.assertIsNotNone(hunks["delta_start"])
            self.assertIsNotNone(hunks["delta_end"])

    def test_main_files_mode_bad_base_fails_loud(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/a.py")
            subprocess.run(["git", "init", "-q", d], check=True)
            subprocess.run(["git", "-C", d, "config", "user.email", "t@e.com"], check=True)
            subprocess.run(["git", "-C", d, "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", d, "add", "."], check=True)
            subprocess.run(["git", "-C", d, "commit", "-q", "-m", "init"], check=True)
            out_path = os.path.join(d, "groups.json")
            rc = orch.main(["--repo", d, "--files", "src/a.py", "--base", "no-such-ref",
                            "--out", out_path])
            self.assertEqual(rc, 2)
            self.assertFalse(os.path.isfile(out_path))                          # no groups.json
            self.assertFalse(os.path.isfile(os.path.join(d, "diff-hunks.json")))  # no artifact

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
            hunks_path = os.path.join(d, "diff-hunks.json")
            self.assertTrue(os.path.isfile(hunks_path))    # --changes always emits
            with open(hunks_path, encoding="utf-8") as fh:
                hunks = json.load(fh)
            self.assertEqual(hunks["base"], "main")
            self.assertEqual(hunks["base_source"], "fallback")
            self.assertTrue(hunks["includes_uncommitted"])
            self.assertIsNotNone(hunks["base_commit"])
            self.assertIsNotNone(hunks["delta_start"])
            self.assertIsNotNone(hunks["delta_end"])

    def test_main_changes_without_git_warns(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/a.py")
            rc = orch.main(["--repo", d, "--changes"])
            self.assertEqual(rc, 2)

    def test_main_changes_bad_base_fails_loud_no_artifact(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/a.py")
            subprocess.run(["git", "init", "-q", d], check=True)
            subprocess.run(["git", "-C", d, "config", "user.email", "t@e.com"], check=True)
            subprocess.run(["git", "-C", d, "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", d, "add", "."], check=True)
            subprocess.run(["git", "-C", d, "commit", "-q", "-m", "init"], check=True)
            with open(os.path.join(d, "src", "a.py"), "w") as fh:
                fh.write("# changed")
            out_path = os.path.join(d, "groups.json")
            rc = orch.main(["--repo", d, "--changes", "--base", "no-such-ref",
                            "--out", out_path])
            self.assertEqual(rc, 2)
            self.assertFalse(os.path.isfile(out_path))
            self.assertFalse(os.path.isfile(os.path.join(d, "diff-hunks.json")))

    def test_main_changes_base_coherence_file_set_matches_hunk_map(self):
        """Finding A (final whole-branch review): the reviewed FILE SET and the
        on-diff HUNK MAP must share ONE base. Build a repo where `main` and an
        explicit `--base` ref (`divergent-base`) have DIVERGED -- each gets its
        own commit after the fork -- then branch a `feature` branch off
        `divergent-base` and change one more file there. `--changes --base
        divergent-base` must review AND hunk-map the SAME file set, scoped to
        divergent-base, not to main:
          - divergent-only.txt (added on divergent-base itself, before the
            fork used by `feature`) must be ABSENT from both.
          - main-only.txt (only ever on `main`) must be ABSENT from both.
          - common.txt (changed on `feature`, on top of divergent-base) must
            be the ONLY member of both sets.
        Under the pre-fix bug, collect_changed_files(repo) ignored --base and
        always resolved its own base via main/master, so the reviewed file set
        would include divergent-only.txt (present relative to main's fork
        point) while diff-hunks.json's hunks (correctly base-scoped by
        diff_map.hunk_map) would not -- the two artifacts would disagree.
        """
        with tempfile.TemporaryDirectory() as d:
            def run(*args):
                subprocess.run(["git", "-C", d, *args], check=True,
                               capture_output=True, text=True)
            run("init", "-q")
            run("config", "user.email", "t@e.com")
            run("config", "user.name", "Test")
            self._touch(d, "common.txt")
            run("add", ".")
            run("commit", "-q", "-m", "init")
            run("branch", "-M", "main")   # fork point, named 'main' regardless
                                          # of this git's init.defaultBranch

            run("checkout", "-q", "-b", "divergent-base")
            self._touch(d, "divergent-only.txt")
            run("add", ".")
            run("commit", "-q", "-m", "divergent-base commit")

            run("checkout", "-q", "main")
            self._touch(d, "main-only.txt")
            run("add", ".")
            run("commit", "-q", "-m", "main commit")

            run("checkout", "-q", "-b", "feature", "divergent-base")
            with open(os.path.join(d, "common.txt"), "w") as fh:
                fh.write("changed on feature\n")
            run("add", ".")
            run("commit", "-q", "-m", "feature commit")

            out_path = os.path.join(d, "groups.json")
            rc = orch.main(["--repo", d, "--changes", "--base", "divergent-base",
                            "--out", out_path])
            self.assertEqual(rc, 0)

            with open(out_path, encoding="utf-8") as fh:
                groups_out = json.load(fh)
            reviewed_files = sorted({f for g in groups_out["groups"] for f in g["files"]})

            hunks_path = os.path.join(d, "diff-hunks.json")
            with open(hunks_path, encoding="utf-8") as fh:
                hunks = json.load(fh)
            hunk_files = sorted(hunks["hunks"].keys())

            self.assertEqual(hunks["base"], "divergent-base")
            self.assertEqual(hunks["base_source"], "explicit")
            self.assertEqual(reviewed_files, ["common.txt"])
            self.assertEqual(hunk_files, ["common.txt"])
            self.assertEqual(reviewed_files, hunk_files)   # THE coherence assertion
            self.assertNotIn("divergent-only.txt", reviewed_files)
            self.assertNotIn("main-only.txt", reviewed_files)

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

    def _touch(self, root, rel):
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        open(full, "w").close()

    def _run_scan(self, d, *extra):
        import io
        import contextlib
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = orch.main(["--repo", d, "--repo-scan", *extra])
        self.assertEqual(rc, 0)
        return json.loads(buf.getvalue()), err.getvalue()

    def _grouped(self, out):
        return [f for g in out["groups"] for f in g["files"]]

    def test_standard_scan_prunes_fixture_corpora_and_discloses(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            self._touch(d, "tests/test_app.py")
            for rel in self._FIXTURE_LAYOUT:
                self._touch(d, rel)
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
            self._touch(d, "src/app.py")
            for rel in self._FIXTURE_LAYOUT:
                self._touch(d, rel)
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
            self._touch(d, "src/fixtures/loader.py")
            self._touch(d, "fixtures/catalog.py")
            out, _ = self._run_scan(d)
            grouped = self._grouped(out)
            self.assertIn("src/fixtures/loader.py", grouped)
            self.assertIn("fixtures/catalog.py", grouped)
            self.assertNotIn("excluded", out)

    def test_no_disclosure_when_nothing_pruned(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            out, err = self._run_scan(d)
            self.assertNotIn("excluded", out)
            self.assertNotIn("fixture exclusion", err)


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
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fh:
            fh.write(content)

    def _run_scan(self, d, *extra):
        import io
        import contextlib
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = orch.main(["--repo", d, "--repo-scan", *extra])
        self.assertEqual(rc, 0)
        return json.loads(buf.getvalue()), err.getvalue()

    def _grouped(self, out):
        return [f for g in out["groups"] for f in g["files"]]

    def test_gitignored_paths_are_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            self._touch(d, "src/app.py")
            self._touch(d, ".gitignore", "storage/\n.env\n")
            _init_repo(d)
            _git(d, "add", ".")
            _git(d, "commit", "-q", "-m", "init")
            self._touch(d, "storage/data.txt")       # runtime data, ignored
            self._touch(d, "storage/blob.enc")
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
            full = os.path.join(d, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            open(full, "w").close()
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write(self.CATALOG)

    def _run_scan(self, d):
        import io
        import contextlib
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = orch.main(["--repo", d, "--repo-scan"])
        self.assertEqual(rc, 0)
        return json.loads(buf.getvalue()), err.getvalue()

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
        assert "redteam" in panels and "security" not in panels
        assert panels == [p for p in orch.PANEL_PRIORITY if p in panels]

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


class TestPrMode(unittest.TestCase):
    ACQ = {"worktree": "/tmp/wt", "base": "main", "head_sha": "abc"}

    def test_pr_success_records_worktree_and_emits_hunks(self):
        import io, contextlib
        from unittest import mock
        released = {}
        with mock.patch.object(orch.diff_map, "acquire_pr", return_value=self.ACQ), \
             mock.patch.object(orch.diff_map, "release_worktree",
                               side_effect=lambda p, **k: released.setdefault("p", p)), \
             mock.patch.object(orch, "collect_changed_files", return_value=["a.py"]), \
             mock.patch.object(orch, "resolve_base", return_value=("main", "pr-base")), \
             mock.patch.object(orch, "write_diff_hunks") as wdh, \
             mock.patch.object(orch, "build_result",
                               return_value={"groups": [], "counts": {}, "tests": []}):
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "groups.json")
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = orch.main(["--pr", "7", "--out", out])
                data = json.load(open(out))
        self.assertEqual(rc, 0)
        self.assertEqual(data["worktree"], "/tmp/wt")   # recorded for the agent
        self.assertIsNone(released.get("p"))            # NOT released on success
        wdh.assert_called()                             # hunks emitted (PR base)
        self.assertFalse(wdh.call_args.args[-1])         # --pr: includes_uncommitted=False

    def test_pr_failure_releases_worktree_then_raises(self):
        from unittest import mock
        released = {}
        with mock.patch.object(orch.diff_map, "acquire_pr", return_value=self.ACQ), \
             mock.patch.object(orch.diff_map, "release_worktree",
                               side_effect=lambda p, **k: released.setdefault("p", p)), \
             mock.patch.object(orch, "resolve_base", return_value=("main", "pr-base")), \
             mock.patch.object(orch, "collect_changed_files", return_value=["a.py"]), \
             mock.patch.object(orch, "build_result", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                orch.main(["--pr", "7", "--out", "/tmp/x.json"])
        self.assertEqual(released.get("p"), "/tmp/wt")  # released on error

    def test_pr_bad_base_releases_worktree_and_fails_loud(self):
        import io, contextlib
        from unittest import mock
        released = {}
        with mock.patch.object(orch.diff_map, "acquire_pr", return_value=self.ACQ), \
             mock.patch.object(orch.diff_map, "release_worktree",
                               side_effect=lambda p, **k: released.setdefault("p", p)), \
             mock.patch.object(orch, "collect_changed_files", return_value=["a.py"]), \
             mock.patch.object(orch, "resolve_base", return_value=(None, "unresolved")), \
             mock.patch.object(orch, "write_diff_hunks") as wdh, \
             mock.patch.object(orch, "build_result",
                               return_value={"groups": [], "counts": {}, "tests": []}):
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "groups.json")
                with contextlib.redirect_stdout(io.StringIO()), \
                     contextlib.redirect_stderr(io.StringIO()):
                    rc = orch.main(["--pr", "7", "--out", out])
                self.assertFalse(os.path.isfile(out))   # no artifact written on loud fail
        self.assertEqual(rc, 2)
        self.assertEqual(released.get("p"), "/tmp/wt")  # worktree released before returning
        wdh.assert_not_called()


if __name__ == "__main__":
    unittest.main()

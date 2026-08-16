import json
import os
import subprocess
import sys
import textwrap
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
            subprocess.run(["git", "-C", d, "branch", "-M", "main"], check=True)
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
            subprocess.run(["git", "-C", d, "branch", "-M", "main"], check=True)
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


class TestResolveBaseOriginFallback(unittest.TestCase):
    """#947 FIXME-3: a machine-derived pr_base prefers origin/<name> (fresh
    remote) over a possibly-stale local branch; explicit --base never falls
    through."""

    def _runner_resolving(self, *refs):
        def run(argv, capture_output, text):
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

    def test_pr_stages_pipeline_artifacts_into_worktree(self):
        # #955: the worktree must be pipeline-ready on exit -- groups.json and
        # diff-hunks.json staged into <wt>/.panopticon/, not just the invoking
        # cwd/--out. The SKILL runs the pipeline with the worktree as cwd.
        import io, contextlib
        from unittest import mock
        with tempfile.TemporaryDirectory() as wt, tempfile.TemporaryDirectory() as d:
            acq = {"worktree": wt, "base": "main", "head_sha": "abc"}
            with mock.patch.object(orch.diff_map, "acquire_pr", return_value=acq), \
                 mock.patch.object(orch.diff_map, "release_worktree"), \
                 mock.patch.object(orch, "collect_changed_files", return_value=["a.py"]), \
                 mock.patch.object(orch, "resolve_base", return_value=("main", "pr-base")), \
                 mock.patch.object(orch, "write_diff_hunks") as wdh, \
                 mock.patch.object(orch, "build_result",
                                   return_value={"groups": [], "counts": {}, "tests": []}):
                out = os.path.join(d, "groups.json")
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = orch.main(["--pr", "7", "--out", out])
            self.assertEqual(rc, 0)
            # hunks written to BOTH the --out-derived path and the worktree
            hunk_targets = {c.args[3] for c in wdh.call_args_list}
            self.assertIn(os.path.join(wt, ".panopticon", "diff-hunks.json"),
                          hunk_targets)
            self.assertEqual(len(hunk_targets), 2)
            # groups.json staged in the worktree, with the worktree recorded
            staged = os.path.join(wt, ".panopticon", "groups.json")
            with open(staged, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["worktree"], wt)

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


class TestSetup(unittest.TestCase):
    """#485: --setup = seed + scaffold + readiness gate."""

    def _repo(self, d):
        os.makedirs(os.path.join(d, ".git"))
        os.makedirs(os.path.join(d, "appdir"))
        with open(os.path.join(d, "appdir", "x.py"), "w") as fh:
            fh.write("x = 1\n")
        return d

    def _ok_runner(self, argv, capture_output, text):
        class R: returncode = 0; stdout = ""; stderr = ""
        return R()

    def _fail_runner(self, argv, capture_output, text):
        class R: returncode = 1; stdout = ""; stderr = ""
        return R()

    def test_seed_groups_manifest_creates_once_never_clobbers(self):
        with tempfile.TemporaryDirectory() as d:
            self._repo(d)
            path, created, names = orch._seed_groups_manifest(d)
            self.assertTrue(created)
            self.assertIn("appdir", names)
            text = open(path).read()
            self.assertIn("appdir/**", text)
            with open(path, "a") as fh:
                fh.write("# user edit\n")
            _, created2, _ = orch._seed_groups_manifest(d)
            self.assertFalse(created2)                 # never clobbers
            self.assertIn("# user edit", open(path).read())

    def test_ensure_gitignore_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            added = orch._ensure_gitignore(d)
            self.assertEqual(added, orch.SETUP_GITIGNORE_ENTRIES)
            self.assertEqual(orch._ensure_gitignore(d), [])   # second run no-op
            content = open(os.path.join(d, ".gitignore")).read()
            self.assertEqual(content.count(".panopticon/*"), 1)
            self.assertIn("!.panopticon/", content)
            self.assertIn("!.panopticon/groups.yml", content)

    def test_seeded_groups_manifest_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            _init_repo(d)
            os.makedirs(os.path.join(d, "appdir"))
            with open(os.path.join(d, "appdir", "x.py"), "w") as fh:
                fh.write("x = 1\n")
            path, _, _ = orch._seed_groups_manifest(d)
            orch._ensure_gitignore(d)
            ignored = subprocess.run(
                ["git", "-C", d, "check-ignore", path], capture_output=True)
            self.assertNotEqual(ignored.returncode, 0)

    def test_readiness_accepts_linked_worktree_root(self):
        from unittest import mock
        import dispatch
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as reg:
            _init_repo(d)
            with open(os.path.join(d, "a.py"), "w") as fh:
                fh.write("x\n")
            _git(d, "add", ".")
            _git(d, "commit", "-qm", "init")
            wt = os.path.join(d, "linked")
            _git(d, "worktree", "add", "-q", wt)
            with mock.patch.object(dispatch, "_registration_dir", return_value=reg):
                checks = orch.setup_readiness(
                    wt, host="claude", runner=self._fail_runner, environ={})
            self.assertTrue(next(c for c in checks if c[0] == "target-root")[1])

    def test_codex_readiness_checks_cli_not_profiles(self):
        with tempfile.TemporaryDirectory() as d:
            self._repo(d)
            checks = orch.setup_readiness(
                d, host="codex", runner=self._ok_runner, environ={})
            by = {c[0]: c for c in checks}
            self.assertTrue(by["codex-cli"][1])
            self.assertTrue(by["enforced-shells"][1])
            self.assertIn("optional", by["enforced-shells"][2])

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

    def test_readiness_reports_gaps_with_fixes(self):
        from unittest import mock
        import dispatch
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as reg:
            with mock.patch.object(dispatch, "_registration_dir",
                                   return_value=reg):     # empty = unregistered
                checks = orch.setup_readiness(d, host="claude",
                                              runner=self._fail_runner, environ={})
        by = {c[0]: c for c in checks}
        self.assertFalse(by["docker"][1])
        self.assertIn("--no-tools", by["docker"][2])   # every gap carries a fix
        self.assertFalse(by["target-root"][1])
        self.assertIsNone(by["nvd-api-key"][1])        # informational, not gating
        self.assertFalse(by["enforced-shells"][1])

    def test_run_setup_ready_and_exit_codes(self):
        import io
        from unittest import mock
        import dispatch
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as reg:
            self._repo(d)
            for rf in ("panel-review.md", "lens-sweep.md"):
                open(os.path.join(reg, "panopticon-" + rf[:-3] + ".md"), "w").write("x")
            out = io.StringIO()
            with mock.patch.object(dispatch, "_registration_dir",
                                   return_value=reg):
                rc_ready = orch.run_setup(d, host="claude",
                                          runner=self._ok_runner,
                                          environ={"NVD_API_KEY": "k"}, out=out)
                rc_gap = orch.run_setup(d, host="claude",
                                        runner=self._fail_runner,
                                        environ={}, out=io.StringIO())
        self.assertEqual(rc_ready, 0)
        self.assertIn("READY", out.getvalue())
        self.assertEqual(rc_gap, 1)


class TestChangedFilesRenameParity(unittest.TestCase):
    """#978: discovery's changed-file diff must use the same rename semantics
    as diff_map.hunk_map (--find-renames), so the reviewed file set and the
    on-diff hunk map can never diverge on a similarity-threshold edge."""

    def test_diff_invocation_includes_find_renames(self):
        from unittest import mock
        calls = []

        def fake_git(repo, args):
            calls.append(list(args))
            r = types.SimpleNamespace(stdout="")
            if args and args[0] == "merge-base":
                r.stdout = "abc123\n"
            return r

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
        d = self._repo()
        for sub in ("src", "tests"):
            os.makedirs(os.path.join(d, sub))
            open(os.path.join(d, sub, "a.py"), "w").close()
        path, created, names = orch._seed_groups_manifest(d)
        self.assertTrue(created)
        text = open(path, encoding="utf-8").read()
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


def _fake_runner(cmd, **kwargs):
    class R:  # docker/codex/etc. all "succeed" so readiness never blocks the flow test
        returncode = 0
        stdout = ""
        stderr = ""
    return R()


class TestSetupScanFlow(unittest.TestCase):
    """Task 6: wires setup_proposal (Tasks 1-3) + setup-scan.md (Task 4) +
    the groups.yml mapping form (Task 5) into `panopticon setup` /
    `panopticon setup --ingest`."""

    def _repo_with_files(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, ".git"))
        for sub in ("src/auth", "src/checkout", "tests"):
            os.makedirs(os.path.join(d, sub))
        open(os.path.join(d, "src/auth/login.py"), "w").close()
        open(os.path.join(d, "src/checkout/pay.py"), "w").close()
        return d

    def test_setup_renders_scan_brief(self):
        import io
        d = self._repo_with_files()
        buf = io.StringIO()
        orch.run_setup(d, host="generic", runner=_fake_runner, out=buf)
        brief = os.path.join(d, ".panopticon", "setup-scan-brief.md")
        self.assertTrue(os.path.isfile(brief))
        text = open(brief).read()
        self.assertIn("Checkout", text)          # vocabulary injected
        self.assertIn("scan brief", buf.getvalue().lower())

    def test_ingest_writes_draft_with_affinity_floor(self):
        import io
        d = self._repo_with_files()
        proposal = {"groups": [
            {"capability": "Auth", "match": ["src/auth/**"], "tests": []},
            {"capability": "Checkout", "match": ["src/checkout/**"], "tests": []}]}
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        os.makedirs(os.path.dirname(pp), exist_ok=True)
        json.dump(proposal, open(pp, "w"))
        rc = orch.run_setup_ingest(d, proposal_path=pp, out=io.StringIO())
        self.assertEqual(rc, 0)
        draft = os.path.join(d, ".panopticon", "groups.yml.draft")
        self.assertTrue(os.path.isfile(draft))
        doc = __import__("yaml").safe_load(open(draft))
        self.assertEqual(doc["groups"]["Checkout"]["panels"],
                         ["SEC", "DAT", "ACC", "OPS"])

    def test_ingest_is_additive_against_committed(self):
        import io
        d = self._repo_with_files()
        # commit a groups.yml that already covers Auth (owner-edited floor)
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n  Auth:\n    match:\n      - src/auth/**\n"
                     "    panels: [SEC, ACC]\n")
        proposal = {"groups": [
            {"capability": "Auth", "match": ["src/auth/**"], "tests": []},
            {"capability": "Checkout", "match": ["src/checkout/**"], "tests": []}]}
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        json.dump(proposal, open(pp, "w"))
        orch.run_setup_ingest(d, proposal_path=pp, out=io.StringIO())
        doc = __import__("yaml").safe_load(
            open(os.path.join(d, ".panopticon", "groups.yml.draft")))
        self.assertEqual(doc["groups"]["Auth"]["panels"], ["SEC", "ACC"])  # untouched
        self.assertIn("Checkout", doc["groups"])                           # added
        # never overwrote the committed file itself
        committed = __import__("yaml").safe_load(
            open(os.path.join(d, ".panopticon", "groups.yml")))
        self.assertNotIn("Checkout", committed["groups"])

    def test_ingest_malformed_proposal_fails_loudly_no_draft(self):
        import io
        d = self._repo_with_files()
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        os.makedirs(os.path.dirname(pp), exist_ok=True)
        json.dump({"groups": [{"capability": "Auth", "match": []}]}, open(pp, "w"))
        buf = io.StringIO()
        rc = orch.run_setup_ingest(d, proposal_path=pp, out=buf)
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.isfile(
            os.path.join(d, ".panopticon", "groups.yml.draft")))

    def test_setup_without_vocabulary_falls_back_to_seed(self):
        import io
        d = self._repo_with_files()
        buf = io.StringIO()
        # point the loader at a missing vocabulary
        orch.run_setup(d, host="generic", runner=_fake_runner, out=buf,
                       vocabulary_path="/nonexistent/vocab.yml")
        self.assertIn("vocabulary", buf.getvalue().lower())
        self.assertFalse(os.path.isfile(
            os.path.join(d, ".panopticon", "setup-scan-brief.md")))

    def test_setup_then_ingest_does_not_drop_capability_groups(self):
        """C1 regression: the documented setup -> --ingest flow must not
        silently discard the classification. run_setup with a vocabulary
        present must NOT seed the flat top-dir groups.yml (that's the
        vocabulary-absent fallback ONLY, spec §6/§7/§8) -- otherwise
        run_setup_ingest's committed-baseline read finds the flat catalog
        already "covers" everything and additive-merge drops every real
        capability group as redundant."""
        import io
        d = self._repo_with_files()
        orch.run_setup(d, host="generic", runner=_fake_runner, out=io.StringIO())
        # the scan path (vocabulary present) must stop at the brief -- no
        # flat groups.yml, so nothing is "committed" yet for --ingest to
        # (mis)read as a baseline.
        self.assertFalse(os.path.isfile(
            os.path.join(d, ".panopticon", "groups.yml")))
        proposal = {"groups": [
            {"capability": "Auth", "match": ["src/auth/**"], "tests": []},
            {"capability": "Checkout", "match": ["src/checkout/**"], "tests": []}]}
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        json.dump(proposal, open(pp, "w"))
        rc = orch.run_setup_ingest(d, proposal_path=pp, out=io.StringIO())
        self.assertEqual(rc, 0)
        doc = __import__("yaml").safe_load(
            open(os.path.join(d, ".panopticon", "groups.yml.draft")))
        # both capability groups must survive -- NOT dropped as redundant
        self.assertIn("Auth", doc["groups"])
        self.assertIn("Checkout", doc["groups"])

    def test_ingest_discloses_collision(self):
        """#6: a collided duplicate capability (same post-custom: group name)
        must be surfaced in the ingest disclosure, not silently merged."""
        import io
        d = self._repo_with_files()
        proposal = {"groups": [
            {"capability": "Auth", "match": ["src/auth/**"], "tests": []},
            {"capability": "custom:Auth", "match": ["src/auth/legacy/**"],
             "tests": []}]}
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        os.makedirs(os.path.dirname(pp), exist_ok=True)
        json.dump(proposal, open(pp, "w"))
        buf = io.StringIO()
        rc = orch.run_setup_ingest(d, proposal_path=pp, out=buf)
        self.assertEqual(rc, 0)
        self.assertIn(
            "merged duplicate capability custom:Auth into group Auth",
            buf.getvalue())

    def test_ingest_without_bundled_data_fails_loudly(self):
        """#7: run_setup_ingest must guard the vocab/affinity load the same
        way run_setup does -- a missing bundled data file is a loud "data
        error", never an uncaught FileNotFoundError."""
        import io
        from unittest import mock
        d = self._repo_with_files()
        buf = io.StringIO()
        with mock.patch.object(orch, "_VOCAB_PATH", "/nonexistent/vocab.yml"):
            rc = orch.run_setup_ingest(d, out=buf)
        self.assertEqual(rc, 1)
        self.assertIn("data error", buf.getvalue().lower())

    def test_ingest_never_writes_committed_groups_yml(self):
        """Global constraint: run_setup_ingest must only ever write the
        .draft file, never .panopticon/groups.yml itself."""
        import io
        d = self._repo_with_files()
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n  Auth:\n    match:\n      - src/auth/**\n")
        before = open(os.path.join(d, ".panopticon", "groups.yml")).read()
        proposal = {"groups": [
            {"capability": "Checkout", "match": ["src/checkout/**"],
             "tests": []}]}
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        json.dump(proposal, open(pp, "w"))
        orch.run_setup_ingest(d, proposal_path=pp, out=io.StringIO())
        after = open(os.path.join(d, ".panopticon", "groups.yml")).read()
        self.assertEqual(before, after)


def test_repo_scan_reads_matrix_via_parse_groups(tmp_path, monkeypatch):
    # A matrix groups.yml (match/panels) drives --repo-scan grouping identically
    # whether read by load_catalog or _committed_matrix, since assign_by_catalog
    # keys on `match`. Guards the SEC-3 migration: no grouping regression.
    import orchestrator
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
    import orchestrator
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text(
        "groups:\n  Bad:\n    match: 'src/**'\n")   # scalar, not a list
    orchestrator._committed_matrix(str(tmp_path))   # parse_groups validates
    err = capsys.readouterr().err
    assert "match must be a non-empty list" in err   # disclosed, not silent-coerced


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


def test_repo_scan_scope_group_restricts_to_named_group(tmp_path):
    import orchestrator, json
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
    import orchestrator, json
    repo = _repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-file", "src/checkout/pay.py",
                       str(repo), "--out", str(out)])
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py"]           # only the file (no related tests here)
    assert {g["name"] for g in groups} == {"Checkout"}   # assigned to its group, nothing else


def test_repo_scan_scope_dir_restricts_to_directory(tmp_path):
    import orchestrator, json
    repo = _repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    orchestrator.main(["--repo-scan", "--scope-dir", "src/checkout",
                       str(repo), "--out", str(out)])
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/cart.py", "src/checkout/pay.py"]
    assert {g["name"] for g in groups} == {"Checkout"}


def test_repo_scan_scope_group_unknown_name_errors(tmp_path, capsys):
    import orchestrator
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
    import orchestrator, json
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
    import orchestrator
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text(
        "groups:\n  Bad:\n    match: 'src/auth/**'\n")   # scalar, not a list
    cat = orchestrator._matrix_catalog(str(tmp_path))
    assert cat["Bad"]["match"] == []                      # never char-split
    err = capsys.readouterr().err
    assert "match must be a non-empty list" in err        # disclosed, not silent


def test_matrix_catalog_empty_when_no_groups_yml(tmp_path):
    import orchestrator
    assert orchestrator._matrix_catalog(str(tmp_path)) == {}


def test_repo_scan_bare_scalar_match_group_does_not_swallow_whole_repo(tmp_path):
    # Unscoped --repo-scan: the scalar-match group ("Bad") must NOT collapse
    # the entire repo into one group. Its own target file falls to the
    # leftover ._N chunk (disclosed via ungrouped_files); the well-formed
    # group ("Auth") groups its file normally, unaffected.
    import orchestrator, json
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
    import orchestrator, json
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
    import orchestrator, json
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
    import orchestrator
    os.makedirs(str(tmp_path / ".git"))
    os.makedirs(str(tmp_path / ".panopticon"))
    (tmp_path / ".panopticon" / "groups.yml").write_text(
        "groups:\n  Bad:\n    match: src/bad/**\n")   # scalar, not a list

    def ok_runner(argv, capture_output, text):
        class R: returncode = 0; stdout = ""; stderr = ""
        return R()

    checks = orchestrator.setup_readiness(str(tmp_path), host="claude",
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
    import orchestrator
    repo = _repo_with_matrix(tmp_path)
    out = repo / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-file", "src/ghost.py",
                            str(repo), "--out", str(out)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "src/ghost.py" in err


def test_repo_scan_scope_dir_no_tracked_files_errors(tmp_path, capsys):
    import orchestrator
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
    import orchestrator, json, subprocess
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
    import orchestrator
    repo = _repo_with_matrix(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    assert orchestrator.main(["--repo-scan","--scope-changed","--base","nope",
                              str(repo),"--out",str(out)]) == 2
    assert not (repo/".panopticon"/"diff-hunks.json").exists()


def test_repo_scan_scope_files_with_base_emits_diff_hunks(tmp_path):
    import orchestrator, json, subprocess
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
    import orchestrator, json
    repo = _repo_with_matrix(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan", "--scope-files",
                            "src/checkout/pay.py", "--out", str(out)])
    assert rc == 0
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py"]
    assert not (repo/".panopticon"/"diff-hunks.json").exists()


def test_repo_scan_scope_changed_pr_base_resolves_origin_only_base(tmp_path):
    # Finding B (B1 regression lock): the gh-detected PR base must flow through
    # the --pr-base channel so resolve_base applies its origin/<base> preference
    # (#947). This repo has the base ONLY as refs/remotes/origin/main -- there is
    # NO local `main` branch -- exactly the shape acquire_pr leaves (it fetches
    # only the PR head). Under the OLD code path (the base threaded as an explicit
    # --base main) resolve_base would treat "main" as explicit, fail to resolve
    # it, and return 2 with no artifact. With --pr-base it resolves to origin/main.
    import orchestrator, json, subprocess
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
    import orchestrator
    repo = _repo_with_matrix(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-changed",
                            "--base", "nope", "--pr-base", "main",
                            str(repo), "--out", str(out)])
    assert rc == 2
    assert not (repo/".panopticon"/"diff-hunks.json").exists()

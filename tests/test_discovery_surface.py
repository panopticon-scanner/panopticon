"""Surface classification tests: test-file detection, surface classifiers,
and test-candidate generation."""
import unittest

from discovery_test_helpers import orchestrator


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
            self.assertTrue(orchestrator.is_test_file(path), path)

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
            self.assertTrue(orchestrator.is_test_file(path), path)

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
            self.assertFalse(orchestrator.is_test_file(path), path)


class TestSurfaceClassifiers(unittest.TestCase):
    """#668/#669: direct coverage for the surface classifiers that feed panel
    scheduling and depth."""

    def test_is_architecture_file(self):
        for p in ["Dockerfile", "svc/Dockerfile.prod", "docker-compose.yml",
                  ".github/workflows/ci.yml", "k8s/deploy.yaml", "README.md",
                  ".gitignore", "helm/chart/values.yaml"]:
            self.assertTrue(orchestrator.is_architecture_file(p), p)
        for p in ["src/app.py", "lib/user.rb", "main.go"]:
            self.assertFalse(orchestrator.is_architecture_file(p), p)

    def test_is_database_file(self):
        for p in ["db/schema.sql", "migrations/0001_init.py",
                  "app/db/user.migration.rb"]:
            self.assertTrue(orchestrator.is_database_file(p), p)
        for p in ["src/app.py", "README.md", "Dockerfile"]:
            self.assertFalse(orchestrator.is_database_file(p), p)

class TestTestCandidates(unittest.TestCase):
    """#670: direct coverage for test_candidates() name/dir generation."""

    def test_python_candidates_cover_stem_and_dirs(self):
        # Use a nested path so the src/ -> test(s)/ remap branch is exercised.
        cands = orchestrator.test_candidates("src/pkg/parser.py")
        self.assertIn("src/pkg/test_parser.py", cands)
        self.assertIn("src/pkg/parser_test.py", cands)
        self.assertIn("tests/pkg/test_parser.py", cands)  # src/ -> tests/ remap
        self.assertIn("test/pkg/test_parser.py", cands)   # src/ -> test/ remap

    def test_ruby_app_dir_maps_to_spec(self):
        cands = orchestrator.test_candidates("app/models/user.rb")
        self.assertIn("spec/models/user_spec.rb", cands)  # app/ -> spec/ remap

    def test_language_specific_suffixes(self):
        self.assertIn("internal/svc/handler_test.go",
                      orchestrator.test_candidates("internal/svc/handler.go"))
        self.assertTrue(any(c.endswith("Button.test.tsx")
                            for c in orchestrator.test_candidates("ui/Button.tsx")))
        self.assertTrue(any(c.endswith("FooTest.java")
                            for c in orchestrator.test_candidates("src/Foo.java")))

    def test_unknown_extension_yields_no_names(self):
        # No language match -> no candidate filenames (dirs alone produce none).
        self.assertEqual(orchestrator.test_candidates("notes.md"), [])

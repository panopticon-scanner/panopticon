"""Test-file detection and test-candidate generation."""
import unittest

from scripts import discovery_scope
from tests.discovery_test_helpers import orchestrator


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
        # miscounted as implementation and never reached the test inventory.
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

class TestTestCandidates(unittest.TestCase):
    """#670: direct coverage for test_candidates() name/dir generation."""

    def test_python_candidates_cover_stem_and_dirs(self):
        # Use a nested path so the src/ -> test(s)/ remap branch is exercised.
        cands = discovery_scope.test_candidates("src/pkg/parser.py")
        self.assertIn("src/pkg/test_parser.py", cands)
        self.assertIn("src/pkg/parser_test.py", cands)
        self.assertIn("tests/pkg/test_parser.py", cands)  # src/ -> tests/ remap
        self.assertIn("test/pkg/test_parser.py", cands)   # src/ -> test/ remap

    def test_ruby_app_dir_maps_to_spec(self):
        cands = discovery_scope.test_candidates("app/models/user.rb")
        self.assertIn("spec/models/user_spec.rb", cands)  # app/ -> spec/ remap

    def test_language_specific_suffixes(self):
        self.assertIn("internal/svc/handler_test.go",
                      discovery_scope.test_candidates("internal/svc/handler.go"))
        self.assertTrue(any(c.endswith("Button.test.tsx")
                            for c in discovery_scope.test_candidates("ui/Button.tsx")))
        self.assertTrue(any(c.endswith("FooTest.java")
                            for c in discovery_scope.test_candidates("src/Foo.java")))

    def test_unknown_extension_yields_no_names(self):
        # No language match -> no candidate filenames (dirs alone produce none).
        self.assertEqual(discovery_scope.test_candidates("notes.md"), [])

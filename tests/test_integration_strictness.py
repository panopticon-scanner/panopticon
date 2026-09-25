"""#1422: an environment that is MEANT to run the live-tool tests must not be
allowed to pass by skipping them.

Every adapter integration test guards itself on a precondition -- the fixture is
vendored, the toolchain is installed, the adapter is registered. Outside the
image none of those hold, so the tests skip, which is correct on a dev machine
and on the standard runner. The failure mode is that it is ALSO what happens in
the environment built to run them: a green tick over zero executed assertions.

#1410 fixed exactly one test that way (`PANOPTICON_REQUIRE_INTEGRATION=1` turns
its unmet preconditions into failures) and left the pattern local to that file.
This module makes it the rule rather than the exception, and pins it so the next
integration test cannot quietly reintroduce a silent skip.
"""
import ast
import io
import os
import tempfile
import tokenize
import unittest
from unittest import mock

import yaml
import shell_reader
from workflow_forms import regions

from conftest import REPO_ROOT
import _test_helpers as helpers

TOOLS_TESTS = os.path.join(REPO_ROOT, "tests", "tools")

# A skip that is NOT a coverage loss opts out in the source, on the line itself,
# so the exemption travels with the code instead of living in a list here that
# drifts from it.
_EXEMPT = "strict-skip-exempt:"
_SKIP_NAMES = {
    "unittest.SkipTest", "unittest.skip", "unittest.skipIf",
    "unittest.skipUnless", "pytest.skip", "pytest.mark.skip",
    "pytest.mark.skipif",
}


def _skip_sites_in_source(source, name):
    """Find executable skip sites; syntax errors are guard failures too."""
    lines = source.splitlines()
    try:
        tree = ast.parse(source, filename=name)
    except SyntaxError as exc:
        return ["%s:%d malformed Python: %s" %
                (name, exc.lineno or 1, exc.msg)]

    aliases = {"unittest": "unittest", "pytest": "pytest"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.name in ("unittest", "pytest"):
                    aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module in ("unittest", "pytest"):
            for item in node.names:
                aliases[item.asname or item.name] = node.module + "." + item.name

    def resolved(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return resolved(node.value) + "." + node.attr
        return ""

    comments = {}
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            comments[token.start[0]] = token.string

    def exempt(line):
        for candidate in (line, line - 1):
            if candidate < 1:
                continue
            comment = comments.get(candidate, "")
            if candidate != line and not lines[candidate - 1].lstrip().startswith("#"):
                continue
            if _EXEMPT in comment and comment.split(_EXEMPT, 1)[1].strip():
                return True
        return False

    sites = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = node.func
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call) and resolved(decorator) in _SKIP_NAMES:
                    if not exempt(decorator.lineno):
                        sites.append("%s:%d %s" %
                                     (name, decorator.lineno, lines[decorator.lineno - 1].strip()))
            continue
        else:
            continue
        spelling = resolved(target)
        if spelling not in _SKIP_NAMES and not spelling.endswith(".skipTest"):
            continue
        if not exempt(node.lineno):
            sites.append("%s:%d %s" %
                         (name, node.lineno, lines[node.lineno - 1].strip()))
    return sorted(sites)


def _skip_sites(root):
    sites = []
    for name in sorted(os.listdir(root)):
        if not name.endswith(".py"):
            continue
        path = os.path.join(root, name)
        try:
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
        except (OSError, UnicodeError) as exc:
            sites.append("%s unreadable Python: %s" % (name, exc))
            continue
        sites.extend(_skip_sites_in_source(source, name))
    return sites


class TestRequireIntegrationFlag(unittest.TestCase):
    def test_reads_the_environment_at_call_time(self):
        # NOT a module-level constant: `_REQUIRE_INTEGRATION = os.environ...`
        # evaluated at import means the variable is fixed before any test can
        # set it, so the behaviour is untestable without reloading the module
        # and un-settable by a fixture. Read it when asked.
        with mock.patch.dict(os.environ, {helpers.REQUIRE_INTEGRATION_ENV: "1"}):
            self.assertTrue(helpers.require_integration())
        with mock.patch.dict(os.environ,
                             {helpers.REQUIRE_INTEGRATION_ENV: "0"}):
            self.assertFalse(helpers.require_integration())
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(helpers.require_integration())

    def test_only_the_exact_opt_in_counts(self):
        # "true"/"yes"/"" must not switch on a mode that turns skips into
        # failures -- an ambiguous value should leave the safe behaviour.
        for value in ("true", "yes", "", "2"):
            with mock.patch.dict(os.environ,
                                 {helpers.REQUIRE_INTEGRATION_ENV: value}):
                self.assertFalse(helpers.require_integration(), value)


class TestSkipOrFail(unittest.TestCase):
    def test_strict_mode_turns_an_unmet_precondition_into_a_failure(self):
        case = unittest.TestCase()
        with mock.patch.object(helpers, "require_integration", return_value=True):
            with self.assertRaises(AssertionError) as caught:
                helpers.skip_or_fail(case, "cargo not installed")
        self.assertIn("cargo not installed", str(caught.exception))
        self.assertIn(helpers.REQUIRE_INTEGRATION_ENV, str(caught.exception),
                      "the failure must name the flag that made it a failure")

    def test_otherwise_it_stays_a_clean_skip(self):
        case = unittest.TestCase()
        with mock.patch.object(helpers, "require_integration", return_value=False):
            with self.assertRaises(unittest.SkipTest):
                helpers.skip_or_fail(case, "cargo not installed")


class TestAssertAdapterFindsHonoursTheFlag(unittest.TestCase):
    """The single chokepoint every fixture-backed test already goes through
    (#1422: 'teach assert_adapter_finds to honor it too')."""

    def test_missing_fixture_fails_when_integration_is_required(self):
        with mock.patch.object(helpers, "require_integration", return_value=True):
            with self.assertRaises(AssertionError) as caught:
                helpers.assert_adapter_finds(self, "brakeman", "no-such-fixture")
        self.assertIn("no-such-fixture", str(caught.exception))

    def test_missing_fixture_skips_when_it_is_not(self):
        with mock.patch.object(helpers, "require_integration", return_value=False):
            with self.assertRaises(unittest.SkipTest):
                helpers.assert_adapter_finds(self, "brakeman", "no-such-fixture")


class TestFixtureResolution(unittest.TestCase):
    """#1528: FIXTURE_ROOT is the IMAGE's corpus, not the repo's.

    Measured in strict mode inside the fixtures image: four tests failed on
    fixtures that were present in the checkout mounted at /work the whole time.
    Only fixtures needing a build step (vulnerable-rust) or an external clone
    (the goats) are copied into the image; the static ones are read from the
    mount, so resolution has to look in both places.
    """

    # Vendored in the repo and deliberately NOT copied into the image.
    REPO_ONLY = ("insecure-js", "vulnerable-node", "vulnerable-python")

    def test_the_repo_vendored_fixtures_are_still_there(self):
        # Guards the guard: if these were renamed, the resolution tests below
        # would pass over nothing.
        for name in self.REPO_ONLY:
            self.assertTrue(
                os.path.isdir(os.path.join(helpers.REPO_FIXTURES, name)),
                "%s is gone from tests/fixtures/" % name)

    def test_they_resolve_when_fixture_root_is_the_image(self):
        image_root = os.path.join(tempfile.gettempdir(), "no-such-image-root")
        with mock.patch.object(helpers, "_FIXTURE_ROOTS",
                               (image_root, helpers.REPO_FIXTURES)):
            for name in self.REPO_ONLY:
                with self.subTest(fixture=name):
                    self.assertEqual(
                        helpers.fixture_path(name),
                        os.path.join(helpers.REPO_FIXTURES, name))

    def test_the_image_copy_wins_where_both_carry_it(self):
        # vulnerable-rust lives in both, and only the image's has been built --
        # cargo-audit needs the lockfile's dependency graph, not bare source.
        with tempfile.TemporaryDirectory() as image_root, \
                tempfile.TemporaryDirectory() as repo_root:
            for root in (image_root, repo_root):
                os.mkdir(os.path.join(root, "vulnerable-rust"))
            with mock.patch.object(helpers, "_FIXTURE_ROOTS",
                                   (image_root, repo_root)):
                self.assertEqual(helpers.fixture_path("vulnerable-rust"),
                                 os.path.join(image_root, "vulnerable-rust"))

    def test_an_absent_fixture_resolves_to_nothing(self):
        self.assertIsNone(helpers.fixture_path("no-such-fixture"))


class TestNoSilentSkipsRemain(unittest.TestCase):
    """The durable half. Without this, the next integration test added is one
    bare `self.skipTest(...)` away from being invisible again."""

    def _skip_sites(self):
        return _skip_sites(TOOLS_TESTS)

    def test_every_precondition_skip_goes_through_skip_or_fail(self):
        self.assertEqual(
            [], self._skip_sites(),
            "a bare skipTest in an adapter test is invisible in the very "
            "environment built to run it. Use _test_helpers.skip_or_fail, or "
            "mark the line `# %s <why this one is not a coverage loss>`:\n%s"
            % (_EXEMPT, "\n".join(self._skip_sites())))

    def test_the_scanner_actually_reads_the_directory(self):
        # Guards the guard: a glob that matched nothing would report a clean
        # pass over an unread directory.
        names = [n for n in os.listdir(TOOLS_TESTS) if n.endswith(".py")]
        self.assertGreater(len(names), 15, "tools test scan found almost "
                                           "nothing; the scanner is broken")

    def test_planted_files_detect_calls_decorators_multiline_and_aliases(self):
        planted = {
            "test_calls.py": """import unittest as unit
import pytest as pt
from unittest import SkipTest as Halt
from pytest import skip as stop
self.skipTest(
    'missing tool'
)
raise Halt('missing tool')
pt.skip('missing tool')
stop('missing tool')
""",
            "test_decorators.py": """import unittest as unit
import pytest as pt
from unittest import skipUnless as only_when
from pytest import mark as marks
@unit.skipIf(
    True,
    'missing tool',
)
class First: pass
@only_when(False, 'missing tool')
class Second: pass
@pt.mark.skip(reason='missing tool')
def third(): pass
@marks.skipif(True, reason='missing tool')
def fourth(): pass
@unit.skip('missing tool')
def fifth(): pass
@pt.mark.skip
def sixth(): pass
""",
        }
        with tempfile.TemporaryDirectory() as root:
            for name, source in planted.items():
                with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
                    fh.write(source)
            sites = _skip_sites(root)
        self.assertEqual(10, len(sites), sites)
        self.assertTrue(any("test_calls.py" in site for site in sites))
        self.assertTrue(any("test_decorators.py" in site for site in sites))

    def test_comments_strings_and_justified_exemption_are_ignored(self):
        source = """import unittest
# self.skipTest('comment decoy')
text = "strict-skip-exempt: string decoy; unittest.skip('decoy')"
value = object()
value.skip('ordinary method')
# strict-skip-exempt: genuine opt-in probe
@unittest.skip('opt-in')
def optional(): pass
"""
        self.assertEqual([], _skip_sites_in_source(source, "test_decoys.py"))
        misleading = """import unittest
text = 'strict-skip-exempt: not a comment'
unittest.skip('real')
"""
        self.assertEqual(1, len(_skip_sites_in_source(misleading, "test_real.py")))

    def test_exemption_requires_a_reason_at_the_skip(self):
        source = """import unittest
# strict-skip-exempt:
@unittest.skip('missing tool')
def test_one(): pass
# strict-skip-exempt: distant reason
value = 1
@unittest.skip('missing tool')
def test_two(): pass
"""
        self.assertEqual(2, len(_skip_sites_in_source(source, "test_unjustified.py")))

    def test_malformed_planted_source_fails_the_guard(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "test_broken.py"), "w", encoding="utf-8") as fh:
                fh.write("def broken(:\n")
            sites = _skip_sites(root)
        self.assertEqual(1, len(sites), sites)
        self.assertIn("test_broken.py", sites[0])


def _strict_pytest_containers(script):
    """Read the currently supported docker/sh invocation, without expansion.
    Unknown Docker options or extra shell commands cannot prove this contract.
    """
    found = []
    statements = shell_reader.statements(script)
    conditional_regions = regions(statements)
    for index, statement in enumerate(statements):
        if index in conditional_regions:
            continue
        for stage in statement.stages:
            argv = shell_reader.command(stage.argv)
            if shell_reader.conditional(stage.argv) or argv[:2] != ["docker", "run"]:
                continue
            options, i = {}, 2
            while i < len(argv) and argv[i].startswith("-"):
                flag = argv[i]
                if flag == "--rm":
                    i += 1
                    continue
                if flag not in ("-v", "-w", "-e", "--entrypoint") or i + 1 == len(argv):
                    break
                options.setdefault(flag, []).append(argv[i + 1])
                i += 2
            if argv[i:i + 2] != ["panopticon-fixtures:latest", "-c"] or len(argv[i:]) != 3:
                continue
            commands = [shell_reader.command(part.argv)
                        for line in shell_reader.statements(argv[i + 2]) for part in line.stages]
            if commands != [["python3", "-m", "pytest", "tests/tools/", "-q", "-rs",
                             "-p", "no:cacheprovider"]]:
                continue
            if (options.get("--entrypoint") == ["sh"]
                    and options.get("-v") == ["$PWD:/work:ro"]
                    and options.get("-w") == ["/work"]
                    and set(options.get("-e", [])) == {
                        "FIXTURE_ROOT=/opt/panopticon-fixtures",
                        "PANOPTICON_REQUIRE_INTEGRATION=1", "PYTHONDONTWRITEBYTECODE=1"}):
                found.append(argv)
    return found


def _pull_fails_closed(script):
    # Deliberately support the simple published if/then shape; no shell interpreter.
    lines = shell_reader.statements(script)
    argv = [list(part.argv) for line in lines for part in line.stages]
    if len(argv) > 2 and argv[1] == ["then"]:
        argv[1:3] = [["then", *argv[2]]]
    return (len(argv) == 5 and argv[0] == ["if", "!", "docker", "pull", "$IMAGE"]
            and argv[1][:2] == ["then", "echo"]
            and len(argv[1]) == 3 and argv[1][2].startswith("::error::")
            and argv[2] == ["exit", "1"] and argv[3] == ["fi"]
            and argv[4] == ["docker", "tag", "$IMAGE", "panopticon-tools:latest"])


class TestThereIsSomewhereTheyAreRequiredToRun(unittest.TestCase):
    """The other half of #1422. Strict mode is only worth having if some
    environment actually sets it; otherwise every adapter test still skips
    everywhere and the flag is decoration."""

    def setUp(self):
        path = os.path.join(REPO_ROOT, ".github", "workflows",
                            "adapter-integration.yml")
        self.assertTrue(os.path.isfile(path), "no adapter-integration workflow")
        with open(path, encoding="utf-8") as fh:
            self.wf = yaml.safe_load(fh.read())
        self.steps = self.wf["jobs"]["integration"]["steps"]
        self.scripts = [step.get("run", "") for step in self.steps]

    def test_strict_mode_mounts_image_and_whole_suite_are_on_the_same_invocation(self):
        runs = [argv for script in self.scripts for argv in _strict_pytest_containers(script)]
        self.assertEqual(len(runs), 1)

    def test_comments_echoes_wrong_image_command_and_deselection_cannot_satisfy_guard(self):
        script = ('docker run --rm -v "$PWD:/work:ro" -w /work '
                  '-e FIXTURE_ROOT=/opt/panopticon-fixtures '
                  '-e PANOPTICON_REQUIRE_INTEGRATION=1 -e PYTHONDONTWRITEBYTECODE=1 '
                  '--entrypoint sh panopticon-fixtures:latest '
                  '-c "python3 -m pytest tests/tools/ -q -rs -p no:cacheprovider"')
        self.assertEqual(len(_strict_pytest_containers(script)), 1)
        for bad in ('# ' + script, "echo '" + script + "'",
                    'if false; then ' + script + '; fi',
                    script.replace("panopticon-fixtures:latest", "wrong-image"),
                    script.replace("python3 -m pytest", "echo pytest"),
                    script.replace("-e PANOPTICON_REQUIRE_INTEGRATION=1", ""),
                    script.replace("-v ", "-e "),
                    script.replace("tests/tools/", "tests/tools/test_one.py"),
                    script.replace(" -q -rs", " -k integration -q -rs"),
                    script.replace(" -q -rs", " -m integration -q -rs"),
                    script.replace("PANOPTICON_REQUIRE_INTEGRATION=1", "PANOPTICON_REQUIRE_INTEGRATION=0")
                    + '\n# PANOPTICON_REQUIRE_INTEGRATION=1'):
            with self.subTest(script=bad):
                self.assertEqual(_strict_pytest_containers(bad), [])

    def test_it_is_scheduled_not_only_manual(self):
        on = self.wf.get(True, {})
        self.assertTrue((on or {}).get("schedule"),
                        "a dispatch-only job is one nobody remembers to run")
        self.assertIn("workflow_dispatch", on)

    def test_it_does_not_substitute_a_degraded_image(self):
        self.assertEqual(sum(_pull_fails_closed(script) for script in self.scripts), 1)

    def test_pull_failure_requires_exit_in_its_failure_arm(self):
        good = ('if ! docker pull "$IMAGE"; then echo "::error::unavailable"; '
                'exit 1; fi; docker tag "$IMAGE" panopticon-tools:latest')
        self.assertTrue(_pull_fails_closed(good))
        for bad in (good.replace("exit 1;", 'echo "exit 1";'),
                    good.replace("exit 1;", "# exit 1\n"),
                    good.replace("exit 1;", "") + "; if false; then exit 1; fi",
                    good.replace("! docker pull", "docker pull"),
                    good + "; docker build ."):
            with self.subTest(script=bad):
                self.assertFalse(_pull_fails_closed(bad))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

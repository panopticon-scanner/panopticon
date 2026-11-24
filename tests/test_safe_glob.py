"""#3701: a directory is matched as it is spelled, and only a pattern is a pattern.

`glob.glob(os.path.join(directory, "findings-*.json"))` reads the directory as part
of the pattern. A review root at `repo[x]/` then found none of its own findings
files, plans, scout replies or coverage files, and lost every agent finding with no
reason given. `scripts.safe_glob.under` takes the directory as it is spelled, and it
is the one matcher in `skill/scripts`: the ratchet below fails on any module that
calls `glob`, with one exception it names (`guard_rules.py`, which cannot import
the helper and escapes its directory itself).

`glob` also returns nothing for a directory it cannot list. `under` raises
`Unlistable` there, and `TestADirectoryThatCannotBeListedIsNotAnEmptyOne` holds each
caller to what that means for it.
"""
import ast
import contextlib
import contextvars
import errno
import glob
import io
import json
import os
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from tests._test_helpers import REPO_ROOT, adopt_panopticon

import scripts.collect_usage as collect_usage
import scripts.phases.readiness as readiness
import scripts.probes.kimi_snapshot as kimi_snapshot
import scripts.phases.run_artifacts as run_artifacts
import scripts.phases.runio as runio
import scripts.runners.kimi as kimi_runner
import scripts.safe_glob as safe_glob
import scripts.synthesize as synthesize_script
import scripts.synth.cost as cost_mod
import scripts.synth.coverage_io as coverage_io
import scripts.synth.plan as plan_mod
import scripts.tools.pip_audit as pip_audit
import scripts.tools_manifest as tools_manifest

SCANNED = "skill/scripts"
#: The one module that still calls `glob`. It is loaded under `python -I` with the
#: standard library alone on `sys.path`, so it cannot import the helper. It escapes its
#: directory itself; `test_the_exception_escapes` holds it to that.
STDLIB_ONLY = "skill/scripts/guard_rules.py"
MATCHERS = frozenset({"glob", "iglob", "glob0", "glob1"})
#: What the `glob` module holds that matches nothing: the only uses of it that are not counted.
HARMLESS = frozenset({"escape", "has_magic"})
#: The helper's own entry points, and the first arguments that hand it no directory.
HELPERS = frozenset({"under", "iter_under"})
NO_DIRECTORY = frozenset({"", "."})


@contextlib.contextmanager
def unlistable(*directories):
    """`os.scandir` fails on these directories as it does on one whose mode denies
    reading it. Every other directory is listed."""
    real, denied = os.scandir, {os.path.realpath(directory) for directory in directories}

    def scandir(path="."):
        if isinstance(path, (str, os.PathLike)) and os.path.realpath(path) in denied:
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        return real(path)

    with mock.patch.object(os, "scandir", scandir):
        yield


@contextlib.contextmanager
def owned_by_another_user(directory):
    """`os.lstat` reports `directory` as owned by a user who is not us, which no test
    can arrange for real without being root. Everything else is reported as it is."""
    real = os.lstat

    def lstat(path, *args, **kwargs):
        info = real(path, *args, **kwargs)
        if isinstance(path, (str, os.PathLike)) and os.fspath(path) == directory:
            fields = list(info)
            fields[4] = info.st_uid + 1                              # st_uid
            return os.stat_result(fields)
        return info

    with mock.patch.object(os, "lstat", lstat):
        yield


#: A directory name that is two lines and an escape sequence when it is printed raw.
FORGED = "run\nFAKE PASS\x1b[2J"
FORGED_SHOWN = "run\\x0aFAKE PASS\\x1b[2J"
#: Where each text says that nothing but the helper matches under a directory. Each
#: passage runs from these words to the next blank line or list item.
ONLY_MATCHER_CLAIMS = (("skill/scripts/safe_glob.py", "No module in the package calls `glob`"),
                       ("panopticon.yml", "the one matcher in `skill/scripts`"),
                       ("CHANGELOG.md", "One helper does the matching"))


def claim_passage(text, opening):
    """The passage of `text` that starts at `opening`, its line breaks and comment
    marks folded away, or None when the words are not there exactly once."""
    if text.count(opening) != 1:
        return None
    lines = text[text.index(opening):].split("\n")
    passage = [lines[0]]
    for line in lines[1:]:
        bare = line.lstrip("# ").rstrip()
        if not bare or bare.startswith("- "):
            break
        passage.append(bare)
    return " ".join(passage)


def glob_uses(source):
    """The line numbers where `source` reaches the `glob` module's matchers, or hands the
    helper no directory:

    - the module named for anything but `glob.escape` and `glob.has_magic`, which match
      nothing: a call, an alias (`match = glob.glob`, `g = glob`), an argument;
    - a matcher imported by name (`from glob import iglob as find`);
    - another module's `glob` (`safe_glob.glob.glob(d)`);
    - `safe_glob.under("", os.path.join(d, ...))`: the directory is back in the pattern.

    A `.glob()` on anything that is not the module is not counted (a `pathlib.Path` takes
    a pattern only)."""
    tree = ast.parse(source)
    modules, names = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.asname or alias.name for alias in node.names
                           if alias.name == "glob")
        elif isinstance(node, ast.ImportFrom) and node.module == "glob":
            for alias in node.names:
                if alias.name == "*":
                    names.update(MATCHERS)
                elif alias.name in MATCHERS:
                    names.add(alias.asname or alias.name)
    lines, harmless = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if (node.attr in HARMLESS and isinstance(node.value, ast.Name)
                    and node.value.id in modules):
                harmless.add(id(node.value))
            elif (node.attr in MATCHERS and isinstance(node.value, ast.Attribute)
                    and node.value.attr == "glob"):
                lines.add(node.lineno)
        elif isinstance(node, ast.Call) and _hands_the_helper_no_directory(node):
            lines.add(node.lineno)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and (
                node.id in names or (node.id in modules and id(node) not in harmless)):
            lines.add(node.lineno)
    return sorted(lines)


def _hands_the_helper_no_directory(call):
    func = call.func
    helper = (isinstance(func, ast.Attribute) and func.attr in HELPERS
              and ast.unparse(func.value).split(".")[-1] == "safe_glob")
    first = call.args[0] if call.args else None
    return (helper and isinstance(first, ast.Constant) and isinstance(first.value, str)
            and first.value in NO_DIRECTORY)


def offenders(root=REPO_ROOT):
    """{relative path: lines} for every scanned module that reaches a matcher."""
    found = {}
    for path in sorted((Path(root) / SCANNED).rglob("*.py")):
        lines = glob_uses(path.read_text(encoding="utf-8"))
        if lines:
            found[path.relative_to(root).as_posix()] = lines
    return found


class TestOnlyTheOwnerCallsGlob(unittest.TestCase):
    def test_no_module_but_the_named_exception_reaches_a_matcher(self):
        """The helper itself does not call `glob`: `glob` reads a directory it cannot
        list as an empty one."""
        self.assertEqual([STDLIB_ONLY], sorted(offenders()),
                         "match under a directory with scripts.safe_glob.under, which "
                         "takes the directory as it is spelled")

    def test_the_exception_escapes(self):
        """`guard_rules` cannot import the helper, so its one call is held to the same
        shape: `glob.glob(os.path.join(glob.escape(<directory>), ...))`."""
        with open(os.path.join(REPO_ROOT, STDLIB_ONLY), encoding="utf-8") as fh:
            source = fh.read()
        self.assertEqual(1, len(glob_uses(source)))
        calls = [node for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Call) and ast.unparse(node.func) == "glob.glob"]
        self.assertEqual(1, len(calls))
        (pattern,) = calls[0].args
        self.assertEqual("os.path.join", ast.unparse(pattern.func))
        self.assertEqual("glob.escape", ast.unparse(pattern.args[0].func))

    def test_the_detector_sees_every_ordinary_way_to_reach_one(self):
        reaches = ("import glob\nglob.glob(d)\n",
                   "import glob\nglob.iglob(d)\n",
                   "import glob as _glob\n_glob.glob(d)\n",
                   "import os, glob\nglob.glob(os.path.join(d, '*'))\n",
                   "from glob import glob\nglob(d)\n",
                   "from glob import iglob as find\nfind(d)\n",
                   "from glob import *\niglob(d)\n",
                   "import glob\nmatch = glob.glob\nmatch(d)\n",
                   "import glob\nsorted(map(glob.glob, dirs))\n",
                   "def f():\n    import glob\n    return glob.glob(d)\n",
                   "import glob\nglob.glob1(d, '*')\n",
                   "import glob\ng = glob\ng.glob(d)\n",
                   "import glob\nfind(glob, d)\n",
                   "import scripts.safe_glob as safe_glob\nsafe_glob.glob.glob(d)\n",
                   "from scripts import safe_glob\nsafe_glob.glob.iglob(d)\n",
                   "import scripts.safe_glob as safe_glob\n"
                   "safe_glob.under('', os.path.join(d, '*'))\n",
                   "import scripts.safe_glob as safe_glob\n"
                   "safe_glob.iter_under('.', os.path.join(d, '*'))\n",
                   "import scripts.safe_glob\nscripts.safe_glob.under('', d + '/*')\n")
        for source in reaches:
            with self.subTest(source=source):
                self.assertNotEqual([], glob_uses(source))

    def test_the_detector_leaves_what_matches_nothing_alone(self):
        clean = ("import glob\nglob.escape(d)\n",
                 "import glob\nglob.has_magic(d)\n",
                 "from pathlib import Path\nPath(d).glob('*.py')\n",
                 "paths = tree.glob('*')\n",
                 "note = 'glob.glob(d) reads d as a pattern'\n",
                 "import scripts.safe_glob as safe_glob\nsafe_glob.under(d, '*')\n",
                 "import scripts.safe_glob as safe_glob\nsafe_glob.iter_under(d, '.*')\n",
                 "published.under('')\n",
                 "import glob\nglob.has_magic(glob.escape(d))\n",
                 "def glob(d):\n    return []\nglob(d)\n",
                 "from fnmatch import fnmatch\nfnmatch(name, '*.py')\n")
        for source in clean:
            with self.subTest(source=source):
                self.assertEqual([], glob_uses(source))

    def test_each_text_that_says_so_names_the_exception(self):
        """#3706 five-gate review, item 6: the helper's docstring, the ownership note
        and the changelog each say no module calls `glob`. Each could lose the one
        exception and go on saying it; none may."""
        exception = "`%s`" % os.path.basename(STDLIB_ONLY)
        passages = {}
        for relative, opening in ONLY_MATCHER_CLAIMS:
            with open(os.path.join(REPO_ROOT, relative), encoding="utf-8") as fh:
                passages[relative] = claim_passage(fh.read(), opening)
        self.assertEqual({}, {relative: passage for relative, passage in passages.items()
                              if passage is None or exception not in passage},
                         "each of these says nothing but the helper matches; each must "
                         "name %s, which still calls glob" % exception)

    def test_a_passage_ends_where_the_next_one_starts(self):
        text = ("# - one: only the helper matches,\n#   but `x.py`.\n# - two: `y.py`\n\n"
                "after a blank line: `z.py`\n")
        self.assertEqual("only the helper matches, but `x.py`.",
                         claim_passage(text, "only the helper"))
        self.assertEqual("two: `y.py`", claim_passage(text, "two:"))
        self.assertIsNone(claim_passage(text, "not there"))
        self.assertIsNone(claim_passage(text + text, "only the helper"))

    def test_every_module_under_the_scanned_root_is_read(self):
        with tempfile.TemporaryDirectory() as directory:
            expected = {}
            for relative in ("a.py", "phases/b.py", "synth/deep/c.py"):
                path = Path(directory) / SCANNED / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("import glob\n\nglob.glob(d)\n", encoding="utf-8")
                expected["%s/%s" % (SCANNED, relative)] = [3]
            (Path(directory) / SCANNED / "clean.py").write_text("import os\n", encoding="utf-8")
            self.assertEqual(expected, offenders(directory))


class TestUnder(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.base = os.path.realpath(d.name)

    def make(self, *parts):
        path = os.path.join(self.base, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{}")
        return path

    def test_the_directory_is_taken_as_it_is_spelled(self):
        for name in ("repo[x]", "re*po", "re?po", "repo[!a]", "repo[", "repo]", "[repo]",
                     "repo[a-z]", "repo[[]", "*", "[x]/inner[y]"):
            with self.subTest(name=name):
                mine = self.make(name, "findings-a.json")
                self.assertEqual([mine], safe_glob.under(os.path.join(self.base, name),
                                                         "findings-*.json"))

    def test_a_sibling_the_spelling_would_match_as_a_pattern_is_not_searched(self):
        """`repo[x]` as a pattern is `repox`: the run read another directory's files."""
        self.make("repox", "findings-theirs.json")
        self.make("repoab", "findings-theirs.json")
        for name in ("repo[x]", "repo*", "repo??", "repo[a-z][a-z]"):
            with self.subTest(name=name):
                os.makedirs(os.path.join(self.base, name), exist_ok=True)
                self.assertEqual([], safe_glob.under(os.path.join(self.base, name),
                                                     "findings-*.json"))
                mine = self.make(name, "findings-mine.json")
                self.assertEqual([mine], safe_glob.under(os.path.join(self.base, name),
                                                         "findings-*.json"))

    def test_the_pattern_is_still_a_pattern_in_every_part(self):
        root = os.path.join(self.base, "home[1]")
        wires = sorted(self.make("home[1]", "sessions", day, session, "wire.jsonl")
                       for day, session in (("d1", "s1"), ("d1", "s2"), ("d2", "s3")))
        self.make("home[1]", "sessions", "d1", "s1", "other.txt")
        self.assertEqual(wires, sorted(safe_glob.under(root, "sessions", "*", "*", "wire.jsonl")))
        self.assertEqual(wires[:2], sorted(safe_glob.under(root, "sessions", "d1", "s?",
                                                           "wire.jsonl")))
        self.assertEqual(wires[2:], safe_glob.under(root, "sessions", "*", "s[3-9]", "*.jsonl"))
        self.assertEqual([], safe_glob.under(root, "sessions", "*", "*", "nothing-*"))

    def test_a_directory_that_is_not_there_matches_nothing(self):
        self.assertEqual([], safe_glob.under(os.path.join(self.base, "absent[x]"), "*"))
        self.assertEqual([], safe_glob.under(os.path.join(self.base, "absent"), "a", "*"))
        self.assertEqual([], safe_glob.under(os.path.join(self.base, "absent"), "a.json"))

    def test_a_file_where_a_directory_is_expected_matches_nothing(self):
        self.make("home", "sessions")
        root = os.path.join(self.base, "home")
        self.assertEqual([], safe_glob.under(root, "sessions", "*"))
        self.assertEqual([], safe_glob.under(root, "sessions", "wire.jsonl"))
        self.assertEqual([], safe_glob.under(os.path.join(root, "sessions"), "*"))

    def test_a_directory_that_cannot_be_listed_is_not_an_empty_one(self):
        """`glob` swallows the error of a directory it cannot list and returns nothing,
        so "no such file" and "could not look" read the same (#3706 review, item 1)."""
        there = os.path.dirname(self.make("locked", "findings-a.json"))
        with unlistable(there):
            self.assertEqual([], glob.glob(os.path.join(glob.escape(there), "findings-*.json")))
            with self.assertRaises(safe_glob.Unlistable) as caught:
                safe_glob.under(there, "findings-*.json")
        self.assertEqual(there, caught.exception.directory)
        self.assertEqual("%s could not be listed: Permission denied" % there,
                         str(caught.exception))
        self.assertEqual("Permission denied", caught.exception.reason)
        # Not an OSError: this package is full of readers that skip a file they cannot
        # read (`except OSError: continue`), and a failed listing must not be skipped too.
        self.assertNotIsInstance(caught.exception, OSError)

    def test_the_message_is_one_line_whatever_the_directory_is_named(self):
        """#3706 five-gate review, item 3: every caller prints the message. A directory
        named with a newline printed a second line of its own choosing, and an escape
        sequence reached the terminal."""
        there = os.path.dirname(self.make(FORGED, "findings-a.json"))
        with unlistable(there), self.assertRaises(safe_glob.Unlistable) as caught:
            safe_glob.under(there, "findings-*.json")
        self.assertEqual("%s could not be listed: Permission denied"
                         % os.path.join(self.base, FORGED_SHOWN), str(caught.exception))
        self.assertEqual(there, caught.exception.directory)          # the path itself
        self.assertEqual(os.path.join(self.base, FORGED_SHOWN), safe_glob.shown(Path(there)))
        # The reason is the system's, and one that carries no `strerror` is spelled too.
        self.assertEqual("/d could not be listed: a\\x0ab",
                         str(safe_glob.Unlistable("/d", OSError("a\nb"))))

    def test_two_names_are_never_printed_alike(self):
        """#3706 seat review at eccba175, item 2: a newline was spelled `\\x0a` and a
        backslash was left alone, so a directory named with a newline and one named
        with those four characters printed the same line. A backslash is doubled."""
        newline, four_characters = "a\nb", "a\\x0ab"
        self.assertEqual(("a\\x0ab", "a\\\\x0ab"),
                         (safe_glob.shown(newline), safe_glob.shown(four_characters)))
        self.assertEqual("C:\\\\dir\\\\", safe_glob.shown("C:\\dir\\"))
        self.assertEqual("plain/[x] *?", safe_glob.shown("plain/[x] *?"))
        shown = {str(safe_glob.Unlistable(name, OSError(reason)))
                 for name in (newline, four_characters) for reason in (newline, four_characters)}
        self.assertEqual(4, len(shown))
        self.assertEqual([], [line for line in shown if "\n" in line])

    def test_a_byte_that_is_not_utf8_is_not_printed_like_text_a_name_can_hold(self):
        """Five gates at 908f005e, item 5. A file name with a byte that is not UTF-8
        reaches us with a lone surrogate in it, and `scripts.inert` spells that
        `U+DCE9`, which is also six characters a name can hold. Here it is `\\udce9`."""
        undecodable, text = os.fsdecode(b"caf\xe9"), "cafU+DCE9"
        self.assertEqual("caf\udce9", undecodable)
        self.assertEqual(("caf\\udce9", "cafU+DCE9", "caf\\\\udce9"),
                         (safe_glob.shown(undecodable), safe_glob.shown(text),
                          safe_glob.shown("caf\\udce9")))
        self.assertEqual("\\ud800\\udfff", safe_glob.shown("\ud800\udfff"))
        # What is printed can always be encoded: no surrogate survives in it.
        message = str(safe_glob.Unlistable(undecodable, OSError(undecodable)))
        self.assertEqual("caf\\udce9 could not be listed: caf\\udce9", message)
        message.encode("utf-8")

    def test_a_credential_in_the_directory_name_is_not_printed(self):
        """#3706 five gates at 590d2946, item 2. A directory can be named with anything.
        Before this PR nothing printed the name; now every caller's message does."""
        token, key = "ghp_" + "A" * 36, "AKIA" + "1234567890ABCDEF"
        there = os.path.dirname(self.make("%s-%s" % (token, key), "findings-a.json"))
        with unlistable(there), self.assertRaises(safe_glob.Unlistable) as caught:
            safe_glob.under(there, "findings-*.json")
        message = str(caught.exception)
        self.assertEqual("%s could not be listed: Permission denied"
                         % os.path.join(self.base, "[REDACTED_TOKEN]-[REDACTED_AWS_KEY]"), message)
        self.assertEqual(there, caught.exception.directory)          # the path itself
        self.assertEqual(os.path.join(self.base, "[REDACTED_TOKEN]-[REDACTED_AWS_KEY]"),
                         safe_glob.shown(there))
        # The reason is the system's, but one with no `strerror` can quote the path.
        self.assertEqual("/d could not be listed: no such thing as [REDACTED_TOKEN]",
                         str(safe_glob.Unlistable("/d", OSError("no such thing as " + token))))
        # Spelled first, then redacted: what is printed is what was checked.
        self.assertEqual("[REDACTED_TOKEN]\\x0aFAKE", safe_glob.shown(token + "\nFAKE"))

    def test_a_listing_that_fails_after_it_has_started_is_not_what_was_read_so_far(self):
        """#3706 five gates at 590d2946, item 3. `scandir` can open a directory and fail
        while it is read (a network mount, a removed medium). Every other fixture here
        fails at the open, so returning the names read so far went unseen: a run then
        finished on part of its findings files."""
        for name in ("findings-a.json", "findings-b.json", "findings-c.json"):
            self.make("run", name)
        there = os.path.join(self.base, "run")
        real = os.scandir

        class FailsPartway:
            def __init__(self, path):
                self.entries = real(path)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.entries.close()

            def __iter__(self):
                yield next(self.entries)
                raise OSError(errno.EIO, "Input/output error")

        self.assertEqual(3, len(safe_glob.under(there, "findings-*.json")))
        with mock.patch.object(os, "scandir", FailsPartway):
            with self.assertRaises(safe_glob.Unlistable) as caught:
                safe_glob.under(there, "findings-*.json")
            found = safe_glob.iter_under(there, "findings-*.json")
            with self.assertRaises(safe_glob.Unlistable):
                next(found)                                  # not the one name it had read
        self.assertEqual((there, "Input/output error"),
                         (caught.exception.directory, caught.exception.reason))

    def test_a_name_no_file_can_have_matches_nothing(self):
        """A path with a NUL in it names no file: nothing is there, which is not a
        directory that could not be listed. Both the listing and the lookup say so."""
        self.make("d", "a.json")
        there = os.path.join(self.base, "d")
        self.assertEqual([], safe_glob.under(there + "\0", "*.json"))          # the listing
        self.assertEqual([], safe_glob.under(there, "a\0.json"))               # the lookup
        self.assertEqual([], safe_glob.under(there, "x\0y", "*.json"))
        self.assertEqual([], list(safe_glob.iter_under(there + "\0", "a.json")))

    def test_a_name_the_listing_gave_is_not_looked_up_again(self):
        """A name matched by a wildcard came from the listing, so it is there. A literal
        name was given by the caller, so it is looked up. One `lstat` per literal last
        part, none per match."""
        for name in ("a.json", "b.json"):
            self.make("d", name)
        there = os.path.join(self.base, "d")
        with mock.patch.object(os, "lstat", side_effect=AssertionError("looked up")):
            self.assertEqual(2, len(safe_glob.under(there, "*.json")))
            self.assertEqual(2, len(safe_glob.under(self.base, "d", "[ab].json")))
        real, looked_up = os.lstat, []

        def lstat(path, *args, **kwargs):
            looked_up.append(path)
            return real(path, *args, **kwargs)

        with mock.patch.object(os, "lstat", lstat):
            self.assertEqual([os.path.join(there, "a.json")], safe_glob.under(self.base, "*", "a.json"))
            self.assertEqual([], safe_glob.under(there, "missing.json"))
        self.assertEqual([os.path.join(there, "a.json"), os.path.join(there, "missing.json")],
                         looked_up)

    def test_a_directory_under_a_wildcard_that_cannot_be_listed_raises(self):
        seen = self.make("home", "sessions", "d1", "s1", "wire.jsonl")
        locked = os.path.dirname(os.path.dirname(
            self.make("home", "sessions", "d2", "s2", "wire.jsonl")))
        root = os.path.join(self.base, "home")
        with unlistable(locked):
            with self.assertRaises(safe_glob.Unlistable) as caught:
                safe_glob.under(root, "sessions", "*", "*", "wire.jsonl")
            self.assertEqual(locked, caught.exception.directory)
            self.assertEqual([seen], safe_glob.under(root, "sessions", "d1", "*", "wire.jsonl"))

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "root lists a directory whatever its mode")
    def test_a_directory_whose_mode_denies_it_raises(self):
        """The real thing, not the injected one: search without read finds a name it is
        given and cannot list; no permission at all cannot even look a name up."""
        there = os.path.dirname(self.make("locked", "findings-a.json"))
        self.addCleanup(os.chmod, there, 0o700)
        os.chmod(there, 0o300)
        with self.assertRaises(safe_glob.Unlistable):
            safe_glob.under(there, "findings-*.json")
        self.assertEqual([os.path.join(there, "findings-a.json")],
                         safe_glob.under(there, "findings-a.json"))
        os.chmod(there, 0o000)
        for pattern in ("findings-*.json", "findings-a.json"):
            with self.subTest(pattern=pattern), self.assertRaises(safe_glob.Unlistable):
                safe_glob.under(there, pattern)

    def test_it_matches_what_glob_matches(self):
        """The helper no longer calls `glob`, so it is held to `glob`'s answers: hidden
        names, character classes, a literal part, a part that is a file."""
        for relative in ("a.json", ".hidden.json", "b.txt", "[x].json", "sub/c.json",
                         "sub/.d.json", "sub/deep/e.json", ".dot/f.json", "sub2/c.json",
                         "s-1/agents/main/wire.jsonl", "s-2/agents/other/wire.jsonl"):
            self.make("tree[1]", *relative.split("/"))
        root = os.path.join(self.base, "tree[1]")
        for pattern in (("*",), ("*.json",), (".*",), (".*.json",), ("[[]x].json",), ("?.json",),
                        ("[ab].*",), ("*", "*.json"), ("sub", "*"), ("sub", ".*"),
                        ("*", "c.json"), ("sub*", "c.json"), ("*", "*", "*.json"),
                        ("a.json",), ("missing.json",), ("a.json", "x"), ("*", "agents", "*",
                                                                          "wire.jsonl"),
                        ("s-[0-9]", "agents", "main", "wire.jsonl"), ("**",), ("**", "c.json"),
                        ("*/c.json",), ("sub/deep/*.json",), ("[",), ("sub", "[!.]*")):
            with self.subTest(pattern=pattern):
                expected = glob.glob(os.path.join(glob.escape(root), *pattern))
                self.assertEqual(sorted(expected), sorted(safe_glob.under(root, *pattern)))

    def test_the_iterator_lists_a_directory_only_when_it_reaches_it(self):
        """The existence question (#3706 review, item 2): the first match costs the
        directories on the way to it, not the whole tree."""
        for n in range(3):
            self.make("t", "d%d" % n, "requirements-dev.txt")
        root = os.path.join(self.base, "t")
        listed, real = [], os.scandir

        def scandir(path):
            listed.append(path)
            return real(path)

        with mock.patch.object(os, "scandir", scandir):
            found = safe_glob.iter_under(root, "*", "requirements*.txt")
            self.assertEqual([], listed)
            first = next(found)
            self.assertEqual([root, os.path.dirname(first)], listed)
            rest = list(found)
        self.assertEqual(4, len(listed))
        self.assertEqual(sorted(safe_glob.under(root, "*", "requirements*.txt")),
                         sorted([first] + rest))

    def test_what_it_refuses(self):
        """Every match is under the directory (#3706 review, item 3). Each of these left
        it, or returned the directory itself; each is refused at the call."""
        inside = os.path.dirname(self.make("d", "a.json"))
        outside = self.make("a.json")
        for directory, pattern in ((inside, ()),
                                   (inside, ("",)),
                                   (inside, ("..", "a.json")),
                                   (inside, ("../a.json",)),
                                   (inside, ("*", "..", "..", "a.json")),
                                   (inside, (outside,)),
                                   (inside, ("/",)),
                                   (inside, (".",)),
                                   (inside, ("./a.json",)),
                                   (inside, ("a.json/",)),
                                   (inside, ("x//a.json",)),
                                   (inside, ("*", "")),
                                   (inside, ("..\\a.json",)),
                                   (inside, ("sub\\a.json",)),
                                   (inside, ("*", "a\\")),
                                   (inside, ("C:",)),
                                   (inside, ("C:a.json",)),
                                   (inside, ("*", "c:a.json")),
                                   ("", ("*",)),
                                   ("", (os.path.join(inside, "*"),))):
            with self.subTest(directory=directory, pattern=pattern):
                with self.assertRaises(ValueError):
                    safe_glob.under(directory, *pattern)
                with self.assertRaises(ValueError):
                    safe_glob.iter_under(directory, *pattern)

    def test_the_iterator_checks_its_arguments_at_the_call(self):
        """#3706 review round 2, item 3: an iterator that checked at its first `next`
        would hand a caller that never iterates a pattern outside the directory."""
        inside = os.path.dirname(self.make("d", "a.json"))
        refused = []
        shapes = ((inside, ("..", "a.json")), (inside, ("",)), (inside, ()),
                  (inside, ("/etc/*",)), ("", ("*",)),
                  # #3706 five-gate review, item 5: a backslash and a drive are path
                  # syntax where this package does not run. Refused everywhere, so
                  # "every match is under the directory" needs no platform beside it.
                  (inside, ("..\\a.json",)), (inside, ("C:",)), (inside, ("C:a.json",)),
                  (inside, ("*", "c:a.json")))
        for directory, pattern in shapes:
            try:
                safe_glob.iter_under(directory, *pattern)            # never iterated
            except ValueError:
                refused.append((directory, pattern))
        # No `subTest`: one plain assertion, for a harness that does not count subtests.
        self.assertEqual(list(shapes), refused, "nothing was checked until the first match")
        # A good call returns an iterator and has listed nothing yet.
        with mock.patch.object(os, "scandir", side_effect=AssertionError("listed")):
            found = safe_glob.iter_under(inside, "*.json")
        self.assertEqual([os.path.join(inside, "a.json")], list(found))

    def test_a_part_may_hold_separators(self):
        mine = self.make("home", "vendor", "skills", "leaf", "SKILL.md")
        self.assertEqual([mine], safe_glob.under(os.path.join(self.base, "home"),
                                                 "*/skills/leaf", "SKILL.md"))

    def test_a_path_object_is_a_directory_too(self):
        mine = self.make("repo[x]", "a.json")
        self.assertEqual([mine], safe_glob.under(Path(self.base) / "repo[x]", "*.json"))


class TestEveryReaderOfADirectoryTakesItAsSpelled(unittest.TestCase):
    """Each site that used to glob with its directory in the pattern, under a directory
    named `x[y]`, with a decoy in the sibling `xy` that the name matches as a pattern."""

    NAME, DECOY = "x[y]", "xy"

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.base = os.path.realpath(d.name)
        self.here = os.path.join(self.base, self.NAME)
        self.decoy = os.path.join(self.base, self.DECOY)

    def write(self, root, relative, document):
        path = os.path.join(root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(document if isinstance(document, str) else json.dumps(document))
        return path

    def both(self, relative, mine, theirs):
        self.write(self.decoy, relative, theirs)
        return self.write(self.here, relative, mine)

    def test_the_dispatch_plans(self):
        mine = [{"group": "mine", "domain": "SEC", "out_file": "findings-mine-SEC.json"}]
        self.both("dispatch-plan-driver.json", mine,
                  [{"group": "theirs", "domain": "SEC", "out_file": "findings-theirs-SEC.json"}])
        plans, seen, invalid = plan_mod.load_dispatch_plans_detailed(self.here)
        self.assertEqual(([mine], 1, []), (plans, seen, invalid))
        self.assertEqual([mine], plan_mod.load_dispatch_plans(self.here))

    def test_the_scout_replies(self):
        self.both("scout-app.json", {"domains": [], "files": [], "tools": ["semgrep"]},
                  {"domains": [], "files": [], "tools": ["bandit"]})
        self.assertEqual(({"semgrep"}, 1), plan_mod.load_scout_requests(self.here))

    def test_the_coverage_files(self):
        self.both("coverage-app.json", {"group": "mine", "effective": ["SEC"]},
                  {"group": "theirs", "effective": ["SEC"]})
        self.assertEqual(["mine"], [cell["group"]
                                    for cell in coverage_io.load_coverage_files(self.here)])

    def test_the_dispatch_counts(self):
        self.both("dispatch-plan-driver.json",
                  [{"group": "app", "domain": "SEC", "out_file": "findings-app-SEC.json"}], [])
        for name in ("verdicts-app-SEC.json", "verdicts-app-SEC-backup.json", "0123abcd.json"):
            self.write(self.here, os.path.join("verdicts", name), {})
        for folder in (None, os.path.join(self.here, "verdicts")):
            with self.subTest(verdicts_dir=folder):
                counts = cost_mod.driver_cost_counts(self.here, folder, [])
                self.assertEqual((1, 1, 1, 1), tuple(counts[key] for key in (
                    "review_cells", "verify_primary", "verify_backup", "verify_tools")))

    def test_the_findings_files(self):
        mine = self.both(os.path.join(".panopticon", "findings-app-SEC.json"), [], [])
        self.assertEqual([mine], runio._findings_files(self.here))

    def test_the_reset_sweep(self):
        """`--reset` under such a root left the run's flat artifacts in place and deleted
        the sibling's, which is what the pattern matched. It said nothing."""
        stale = ("findings-app-SEC.json", "coverage-app.json", "scout-app.json",
                 "verify-attempts.json", "dispatch-plan-driver.json")
        kept = [self.write(self.decoy, os.path.join(".panopticon", name), "theirs")
                for name in stale]
        mine = [self.write(self.here, os.path.join(".panopticon", name), "stale")
                for name in stale]
        run_artifacts._clear_run_artifacts(self.here)
        self.assertEqual([], [path for path in mine if os.path.exists(path)])
        self.assertEqual(kept, [path for path in kept if os.path.exists(path)])

    def test_a_sub_skill_under_such_a_home(self):
        mine = self.write(self.here, os.path.join("plugins", "vendor", "skills", "leaf", "SKILL.md"), "#")
        self.write(self.decoy, os.path.join("plugins", "leaf", "SKILL.md"), "#")
        with mock.patch.object(readiness, "SUB_SKILL_ROOTS", (os.path.join(self.here, "plugins"),)):
            self.assertEqual(mine, readiness._find_sub_skill("leaf"))

    def test_the_hosts_transcripts(self):
        project = os.path.join(self.base, "project")
        slug = collect_usage.project_slug(project)
        mine = self.write(self.here, os.path.join(".claude", "projects", slug, "s1.jsonl"), "")
        self.write(self.decoy, os.path.join(".claude", "projects", slug, "s2.jsonl"), "")
        self.assertEqual(mine, collect_usage.find_controller_transcript(project, home=self.here))
        tasks = [self.write(self.here, os.path.join("tasks", name), "") for name in ("a", "b")]
        self.write(self.decoy, os.path.join("tasks", "c"), "")
        self.assertEqual(tasks, collect_usage.find_task_transcripts(
            None, tasks_dir=os.path.join(self.here, "tasks")))
        agents = [
            self.write(self.here, os.path.join(".claude", "projects", slug, "s1", "subagents",
                                               "agent-1.jsonl"), ""),
            self.write(self.here, os.path.join(".claude", "projects", slug, "s1", "subagents",
                                               "workflows", "w", "agent-2.jsonl"), "")]
        self.assertEqual(sorted(agents), sorted(collect_usage.find_task_transcripts(mine)))

    def test_the_dependency_manifests_of_a_target(self):
        self.write(self.decoy, "requirements-dev.txt", "x==1\n")
        os.makedirs(self.here)
        self.assertEqual([], tools_manifest.dependency_audit_applicable(self.here))
        self.write(self.here, "requirements-dev.txt", "x==1\n")
        self.assertEqual(["python"], tools_manifest.dependency_audit_applicable(self.here))

    def test_the_kimi_wire_files(self):
        wire = os.path.join("sessions", "d", "s1", "agents", "main", "wire.jsonl")
        mine = self.write(self.here, wire, "")
        self.write(self.decoy, wire.replace("s1", "s2"), "")
        self.assertEqual(mine, kimi_runner.wire_path(self.here, "s1"))
        self.assertIsNone(kimi_runner.wire_path(self.here, "s2"))

    def test_the_kimi_tool_snapshots(self):
        record = {"type": "llm.tools_snapshot", "tools": ["Read"], "agent": "mine.md"}
        wire = os.path.join("sessions", "d", "s1", "agents", "main", "wire.jsonl")
        mine = self.write(self.here, wire, json.dumps(record) + "\n")
        self.write(self.decoy, wire, json.dumps(dict(record, agent="theirs.md")) + "\n")
        self.assertEqual(([({"Read"}, "mine", mine)], ""),
                         kimi_snapshot._kimi_wire_snapshots(self.here))


class TestADirectoryThatCannotBeListedIsNotAnEmptyOne(unittest.TestCase):
    """#3706 review, item 1: each caller of the helper, with the directory it lists
    there and unreadable. Before, every one of them read "nothing here"."""

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.base = os.path.realpath(d.name)
        self.target = os.path.join(self.base, "target")
        os.makedirs(self.target)

    def write(self, root, relative, document):
        path = os.path.join(root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(document if isinstance(document, str) else json.dumps(document))
        return path

    # --- the dependency audit ----------------------------------------------------------

    def test_the_dependency_surface_reads_as_applicable(self):
        """An existing `requirements-dev.txt` was not seen, pip-audit read as not
        applicable, and the certification gap (applicable, nothing produced) was false:
        an unmeasured dependency surface looked clean."""
        self.write(self.target, "requirements-dev.txt", "x==1\n")
        adapter = pip_audit.PipAuditAdapter()
        with unlistable(self.target):
            self.assertEqual(["python"], tools_manifest.dependency_audit_applicable(self.target))
            self.assertTrue(adapter.has_audit_file(self.target, "requirements*.txt"))
            self.assertTrue(adapter.is_applicable(self.target))
            # An auditor reads the ecosystem, so the reason is never "no auditable file".
            self.assertEqual({"python": "not_run"}, tools_manifest.dependency_audit_unaudited(
                self.target, selected=[], online=True))
        self.assertEqual(["python"], tools_manifest.dependency_audit_applicable(self.target))

    def test_the_existence_questions_do_not_build_the_list(self):
        """#3706 review, item 2: both ask only whether a requirements file is there."""
        for n in range(3):
            self.write(self.target, "requirements-%d.txt" % n, "x==1\n")
        with mock.patch.object(safe_glob, "under", side_effect=AssertionError("built the list")):
            self.assertEqual(["python"], tools_manifest.dependency_audit_applicable(self.target))
            self.assertTrue(pip_audit.PipAuditAdapter.has_audit_file(
                self.target, "requirements*.txt"))

    def test_an_unreadable_target_with_no_python_in_it_still_reads_as_applicable(self):
        """It cannot be told from the one above, so it reads the same: worse than the truth."""
        with unlistable(self.target):
            self.assertEqual(["python"], tools_manifest.dependency_audit_applicable(self.target))
        self.assertEqual([], tools_manifest.dependency_audit_applicable(self.target))

    def test_pip_audit_fails_instead_of_auditing_less(self):
        """With no `requirements.txt`, the listing decides which file is audited. Unable
        to list, pip-audit audited `pyproject.toml` alone and reported a complete run."""
        self.write(self.target, "requirements-dev.txt", "x==1\n")
        self.write(self.target, "pyproject.toml",
                   '[project]\nname = "p"\nversion = "1"\ndependencies = ["y==2"]\n')
        err = io.StringIO()
        with unlistable(self.target), contextlib.redirect_stderr(err), \
                mock.patch.object(pip_audit, "run_tool", side_effect=AssertionError("launched")):
            self.assertEqual((b"", 2), pip_audit.PipAuditAdapter().invoke(self.target))
        self.assertEqual("pip-audit: %s could not be listed: Permission denied; "
                         "nothing was audited\n" % self.target, err.getvalue())

    def synthesize_a_captured_advisory(self, manifest, locked, advisories=1):
        """(exit code, stderr, report) of a synthesis over a pip-audit capture made while
        the target could be listed: `requirements-app.txt` and CRITICAL advisories. (Not
        `requirements-dev.txt`: an advisory there is in a dev-only manifest and does not
        gate in standard mode, #3755, and these tests are about the gate.)"""
        target = os.path.join(self.base, "audited-%d" % len(os.listdir(self.base)))
        run = os.path.join(target, ".panopticon")
        self.write(target, "requirements-app.txt", "leftpad==1.0\n")
        self.write(run, os.path.join("tools", "pip-audit.json"), {"fixes": [], "dependencies": [{
            "name": "leftpad", "version": "1.0", "vulns": [
                {"id": "PYSEC-2026-%d" % n, "severity": "CRITICAL", "description": "RCE",
                 "fix_versions": ["2.0"], "aliases": []} for n in range(advisories)]}]})
        adopt_panopticon(target)
        if manifest:
            tools_manifest.write_manifest(
                os.path.join(run, "tools-manifest.json"), ["pip-audit"],
                [os.path.join(run, "tools", "pip-audit.json")], run_id="R")
        out, err = os.path.join(self.base, "report-%d.json" % len(os.listdir(self.base))), io.StringIO()
        # A run id makes the manifest's output receipt owed, so it is given only with one.
        argv = ["--repo", "--root", target, "--target", "t", "--run-dir", run,
                "--tools-dir", os.path.join(run, "tools"), "--fail-on", "critical",
                "--gate-unverified", "--out", out] + (["--run-id", "R"] if manifest else [])
        with contextlib.ExitStack() as stack:
            if locked:
                stack.enter_context(unlistable(target))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(err))
            # In a context of its own, as the host's parse is in a process of its own:
            # an `invoke` earlier in this process must not have chosen the manifest.
            rc = contextvars.Context().run(synthesize_script.main, argv)
        with open(out, encoding="utf-8") as fh:
            return target, rc, err.getvalue(), json.load(fh)

    def test_a_captured_audit_survives_a_target_that_cannot_be_listed_at_synthesis(self):
        """#3706 five gates, item 1 (CRITICAL). pip-audit runs in the tools container and
        its capture is parsed on the host, where one lookup only labels each finding with
        the requirements file it came from. That lookup raised when the target could not
        be listed, ingest recorded the tool as failed with nothing found, and a captured
        CRITICAL advisory left the report: the gate passed where it had failed."""
        for manifest in (False, True):
            with self.subTest(manifest=manifest):
                _target, rc, err, seen = self.synthesize_a_captured_advisory(manifest, locked=False)
                target, locked_rc, locked_err, kept = self.synthesize_a_captured_advisory(
                    manifest, locked=True)
                self.assertEqual((1, 1), (rc, locked_rc), locked_err)          # the gate: FAIL
                self.assertEqual(["requirements-app.txt"],
                                 [f["location"]["file"] for f in seen["findings"]], err)
                # Kept, at the location a tree with no requirements file is given.
                self.assertEqual([("tool:pip-audit", "PYSEC-2026-0", "CRITICAL", "requirements.txt")],
                                 [(f["source"], f["tool_evidence"]["rule_id"], f["severity"],
                                   f["location"]["file"]) for f in kept["findings"]], locked_err)
                self.assertEqual(seen["findings"][0]["title"], kept["findings"][0]["title"])
                self.assertEqual(1, locked_err.count(
                    "pip-audit: %s could not be listed: Permission denied; its findings are "
                    "kept, and which requirements file they came from is not known\n" % target))
                self.assertNotIn("ingest error", locked_err)

    def test_the_labelling_lookup_is_said_once_however_many_findings_it_labels(self):
        _target, rc, err, report = self.synthesize_a_captured_advisory(
            manifest=False, locked=True, advisories=3)
        self.assertEqual((1, 3), (rc, len(report["findings"])), err)
        self.assertEqual(1, err.count("which requirements file they came from is not known"))

    def test_the_label_falls_back_as_it_does_for_a_tree_with_no_requirements_file(self):
        """The lookup's own two answers, with the target unlistable: `pyproject.toml`
        when there is one, the default when there is not, and the reason once each."""
        adapter = pip_audit.PipAuditAdapter()

        def located():
            pip_audit.target_root_cv.set(self.target)
            err = io.StringIO()
            with unlistable(self.target), contextlib.redirect_stderr(err):
                return adapter._located_at(), err.getvalue()

        self.write(self.target, "requirements-dev.txt", "x==1\n")
        said = ("pip-audit: %s could not be listed: Permission denied; its findings are kept, "
                "and which requirements file they came from is not known\n" % self.target)
        self.assertEqual(("requirements.txt", said), contextvars.Context().run(located))
        self.write(self.target, "pyproject.toml", '[project]\nname = "p"\nversion = "1"\n')
        self.assertEqual(("pyproject.toml", said), contextvars.Context().run(located))
        # `requirements.txt` is found by name, so nothing is listed and nothing is said.
        self.write(self.target, "requirements.txt", "x==1\n")
        self.assertEqual(("requirements.txt", ""), contextvars.Context().run(located))

    def test_a_rejected_requirements_txt_is_judged_once(self):
        """`requirements.txt` is tried by name and then again matches `requirements*.txt`.
        It is one candidate: a rejected one is disclosed once, not twice."""
        outside = self.write(self.base, "elsewhere.txt", "x==1\n")
        os.symlink(outside, os.path.join(self.target, "requirements.txt"))
        dev = self.write(self.target, "requirements-dev.txt", "y==2\n")
        self.assertEqual((dev, ["requirements.txt"]), pip_audit._requirement_candidate(self.target))
        os.remove(dev)
        self.assertEqual((None, ["requirements.txt"]), pip_audit._requirement_candidate(self.target))

    def test_pip_audit_needs_no_listing_when_requirements_txt_is_there(self):
        """`requirements.txt` is preferred over anything the listing would add, so a
        target that has one is audited as before."""
        self.write(self.target, "requirements.txt", "x==1\n")
        with unlistable(self.target), \
                mock.patch.object(pip_audit, "run_tool", return_value=(b"{}", b"", 0)) as run:
            self.assertEqual((b"{}", 0), pip_audit.PipAuditAdapter().invoke(self.target))
            report = pip_audit.PipAuditAdapter().sanitization_report(self.target)
        run.assert_called_once()
        self.assertEqual(("requirements.txt", 1), (report["source"], report["kept"]))

    def test_the_sanitization_disclosure_is_announced_as_lost(self):
        self.write(self.target, "requirements-dev.txt", "x==1\n")
        err = io.StringIO()
        with unlistable(self.target), contextlib.redirect_stderr(err):
            found = tools_manifest.collect_sanitization(
                {"pip-audit": pip_audit.PipAuditAdapter()}, self.target)
        self.assertEqual({}, found)
        self.assertEqual("adapter pip-audit could not report what it sanitized: %s could not "
                         "be listed: Permission denied\n" % self.target, err.getvalue())

    # --- --reset -----------------------------------------------------------------------

    def test_reset_clears_nothing_and_says_why(self):
        """`--reset` left `findings-*.json` in place and printed nothing."""
        pano = os.path.join(self.target, ".panopticon")
        # `groups.json` and `tools-ran.json` are literal names: they are found without a
        # listing, ahead of the first pattern that needs one. A reset that removed each
        # path as it found it would have taken them before it stopped.
        stale = [self.write(pano, name, "stale")
                 for name in ("groups.json", "tools-ran.json", "findings-app-SEC.json",
                              "scout-app.json", "verify-attempts.json")]
        kept = [self.write(pano, os.path.join(sub, "x.json"), "stale")
                for sub in ("tools", "verdicts")]
        with unlistable(pano):
            with self.assertRaises(runio.DriverError) as caught:
                run_artifacts._clear_run_artifacts(self.target)
        self.assertEqual("%s could not be listed: Permission denied; nothing was cleared" % pano,
                         str(caught.exception))
        # Nothing is removed before everything is listed: a half-cleared run is worse.
        self.assertEqual(stale + kept, [path for path in stale + kept if os.path.exists(path)])
        run_artifacts._clear_run_artifacts(self.target)
        self.assertEqual([], [path for path in stale + kept if os.path.exists(path)])

    # --- the worktree's report ---------------------------------------------------------

    # --- the run folder ----------------------------------------------------------------

    def test_the_readers_of_a_run_folder_stop(self):
        """Its plans, scout replies, coverage files and verdict bundles: a run folder
        that cannot be listed is not a run with none of them."""
        run = os.path.join(self.base, "run")
        self.write(run, "dispatch-plan-driver.json",
                   [{"group": "app", "domain": "SEC", "out_file": "findings-app-SEC.json"}])
        self.write(run, "scout-app.json", {"domains": [], "files": [], "tools": ["semgrep"]})
        self.write(run, "coverage-app.json", {"group": "app", "effective": ["SEC"]})
        verdicts = os.path.dirname(self.write(run, os.path.join("verdicts", "v.json"), {}))
        readers = (("the dispatch plans, with diagnostics", run,
                    lambda: plan_mod.load_dispatch_plans_detailed(run)),
                   ("the dispatch plans", run, lambda: plan_mod.load_dispatch_plans(run)),
                   ("the scout replies", run, lambda: plan_mod.load_scout_requests(run)),
                   ("the coverage files", run, lambda: coverage_io.load_coverage_files(run)),
                   ("the verdict bundles, by default", verdicts,
                    lambda: cost_mod.driver_cost_counts(run, None, [])),
                   ("the verdict bundles, named", verdicts,
                    lambda: cost_mod.driver_cost_counts(run, verdicts, [])))
        for what, locked, read in readers:
            with self.subTest(what=what):
                read()
                with unlistable(locked), self.assertRaises(safe_glob.Unlistable) as caught:
                    read()
                self.assertEqual(locked, caught.exception.directory)

    def test_each_listing_of_the_verdicts_stops_the_count_alone(self):
        """#3706 five-gate review, item 4: the verdict directory is listed twice, and a
        locked directory fails both, so each listing hid the other. One fails here
        while the other answers, each way round."""
        run = os.path.join(self.base, "run")
        self.write(run, "dispatch-plan-driver.json", [])
        verdicts = os.path.join(run, "verdicts")
        for name in ("verdicts-app-SEC.json", "verdicts-app-SEC-backup.json", "q1.json"):
            self.write(verdicts, name, {})
        real = safe_glob.under

        def failing(pattern):
            def under(directory, *parts):
                if parts == (pattern,):
                    raise safe_glob.Unlistable(directory, PermissionError(
                        errno.EACCES, "Permission denied"))
                return real(directory, *parts)
            return under

        counts = cost_mod.driver_cost_counts(run, None, [])
        self.assertEqual((1, 1, 1), (counts["verify_primary"], counts["verify_backup"],
                                     counts["verify_tools"]))
        raised = []
        for pattern in ("verdicts-*.json", "*.json"):
            with mock.patch.object(safe_glob, "under", failing(pattern)):
                try:
                    cost_mod.driver_cost_counts(run, None, [])
                except safe_glob.Unlistable as exc:
                    raised.append((pattern, exc.directory))
        self.assertEqual([("verdicts-*.json", verdicts), ("*.json", verdicts)], raised)

    def test_synthesis_stops_with_the_directory_and_the_reason(self):
        """#3706 review round 2, item 4: the readers above raise out of the synthesize
        child, and the driver shows the first 400 characters of its stderr. That was
        the top of a traceback. It is one line now, with exit 3 (invalid input)."""
        run = os.path.join(self.base, FORGED)
        tools = os.path.join(run, "tools")
        os.makedirs(tools)
        self.write(run, "scout-g1.json", {"group": "g1", "tools": ["semgrep"], "domains": []})
        findings = self.write(run, "findings-g1-COD.json", {"findings": []})
        out = os.path.join(self.base, "r.json")
        argv = ["--repo", "--target", "src", "--run-dir", run, "--tools-dir", tools,
                "--fail-on", "critical", "--out", out, findings]

        def synthesize():
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                return synthesize_script.main(argv), err.getvalue()

        rc, err = synthesize()
        self.assertTrue(os.path.exists(out), err)
        os.remove(out)
        with unlistable(run):
            rc, err = synthesize()
        self.assertEqual(3, rc, err)
        # One line whatever the run folder is named (five-gate review, item 3): the
        # name's own newline and escape sequence are spelled out, not printed.
        self.assertEqual("synthesize: %s could not be listed: Permission denied"
                         % os.path.join(self.base, FORGED_SHOWN),
                         err.strip().splitlines()[-1])
        self.assertNotIn("Traceback", err)
        self.assertFalse(os.path.exists(out))

    def test_the_findings_of_a_run_are_not_none(self):
        """The synthesize and verify phases both ask for the run's findings files. A
        `DriverError` is the phase failure the driver reports as `status: error`."""
        pano = os.path.join(self.target, ".panopticon")
        mine = self.write(pano, "findings-app-SEC.json", [])
        self.assertEqual([mine], runio._findings_files(self.target))
        with unlistable(pano), self.assertRaises(runio.DriverError) as caught:
            runio._findings_files(self.target)
        self.assertEqual("%s could not be listed: Permission denied" % pano,
                         str(caught.exception))

    # --- the host's transcripts --------------------------------------------------------

    def transcripts(self, temp="tmp"):
        """(controller transcript, the session's task directory under a temp root). The
        one task transcript there holds 17 tokens."""
        project = os.path.join(self.base, "project")
        slug = collect_usage.project_slug(project)
        home = os.path.join(self.base, "home")
        controller = self.write(home, os.path.join(".claude", "projects", slug, "s1.jsonl"), "")
        temp = os.path.join(self.base, temp)
        tasks = os.path.join(temp, "claude-505", slug, "s1", "tasks")
        self.write(tasks, "t1.output", json.dumps(
            {"type": "assistant", "message": {"role": "assistant", "model": "m", "usage": {
                "input_tokens": 10, "output_tokens": 7}}}) + "\n")
        patch = mock.patch.object(collect_usage, "TEMP_ROOTS", (temp,))
        patch.start()
        self.addCleanup(patch.stop)
        return project, home, controller, tasks

    def test_the_session_transcripts_that_cannot_be_listed_are_not_no_transcripts(self):
        project, home, controller, tasks = self.transcripts()
        sessions = os.path.dirname(controller)
        subagents = os.path.dirname(self.write(sessions, os.path.join(
            "s1", "subagents", "agent-1.jsonl"), ""))
        self.assertEqual(2, len(collect_usage.find_task_transcripts(controller)))
        for what, locked, read in (
                ("the project's sessions", sessions,
                 lambda: collect_usage.find_controller_transcript(project, home=home)),
                ("a directory named with --tasks-dir", tasks,
                 lambda: collect_usage.find_task_transcripts(None, tasks_dir=tasks)),
                ("this session's task directory", tasks,
                 lambda: collect_usage.find_task_transcripts(controller)),
                ("the temp root", os.path.join(self.base, "tmp"),
                 lambda: collect_usage.find_task_transcripts(controller)),
                ("this session's subagents", subagents,
                 lambda: collect_usage.find_task_transcripts(controller))):
            with self.subTest(what=what):
                with unlistable(locked), self.assertRaises(safe_glob.Unlistable) as caught:
                    read()
                self.assertEqual(locked, caught.exception.directory)

    def collect(self, project, controller):
        """(exit code, stderr, the usage document or None) of one collector run."""
        run = os.path.join(self.base, "run")
        os.makedirs(run, exist_ok=True)
        written = os.path.join(run, "usage.json")
        if os.path.exists(written):
            os.remove(written)
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = collect_usage.main(["--run-dir", run, "--project-dir", project, "--transcript",
                                     controller, "--since", "none", "--until", "none"])
        self.assertEqual(["usage.json"] if os.path.exists(written) else [], os.listdir(run))
        document = None
        if os.path.exists(written):
            with open(written, encoding="utf-8") as fh:
                document = json.load(fh)
        return rc, err.getvalue(), document

    def test_usage_collection_says_which_directory_it_could_not_list(self):
        """#3706 review round 2, item 4: the collector is a child of the driver too, and
        it ended in a traceback. One line, exit 2, and nothing written. The line stays
        one line when the directory's name is two (five-gate review, item 3)."""
        project, _home, controller, tasks = self.transcripts(temp=FORGED)
        with unlistable(tasks):
            rc, err, document = self.collect(project, controller)
        self.assertEqual((2, None), (rc, document), err)
        self.assertEqual("collect-usage: %s could not be listed: Permission denied; usage "
                         "was not collected\n"
                         % tasks.replace(FORGED, FORGED_SHOWN), err)
        rc, err, document = self.collect(project, controller)
        self.assertEqual((0, 17), (rc, document["total"]), err)

    @unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0,
                     "root lists a directory whatever its mode")
    def test_our_own_temp_directory_closed_to_us_stops_the_collection(self):
        """#3706 five-gate review, item 2. `claude-<our uid>` at mode 000 was passed
        over as if it were another user's, because all that was asked was whether we
        could enter it: exit 0, nothing on stderr, and a total of 0 for a session that
        had spent 17 tokens."""
        project, _home, controller, tasks = self.transcripts()
        ours = os.path.join(self.base, "tmp", "claude-505")
        rc, err, document = self.collect(project, controller)
        self.assertEqual((0, 17), (rc, document["total"]), err)
        self.addCleanup(os.chmod, ours, 0o700)
        os.chmod(ours, 0o000)
        rc, err, document = self.collect(project, controller)
        self.assertEqual((2, None), (rc, document), err)
        self.assertEqual("collect-usage: %s could not be listed: Permission denied; usage "
                         "was not collected\n" % tasks, err)

    def test_only_a_temp_directory_another_user_owns_is_passed_over(self):
        """A shared machine has one `claude-<uid>` per user under the temp root, and the
        others' are closed to us. This session's tasks are not in them: one that
        another user owns is passed over, and ours is still read. Its name does not
        make it another's, and neither does being closed to us."""
        _project, _home, controller, tasks = self.transcripts()
        theirs = os.path.join(self.base, "tmp", "claude-501")
        os.makedirs(theirs)
        closed = os.path.join(theirs, os.path.basename(os.path.dirname(os.path.dirname(tasks))),
                              "s1", "tasks")
        with unlistable(closed):
            with owned_by_another_user(theirs):
                self.assertEqual([os.path.join(tasks, "t1.output")],
                                 collect_usage.find_task_transcripts(controller))
            with self.assertRaises(safe_glob.Unlistable) as caught:
                collect_usage.find_task_transcripts(controller)
        self.assertEqual(closed, caught.exception.directory)

    def test_whose_a_temp_directory_is(self):
        mine = os.path.join(self.base, "claude-1")
        os.makedirs(mine)
        self.assertIs(False, collect_usage._another_users(mine))
        with owned_by_another_user(mine):
            self.assertIs(True, collect_usage._another_users(mine))
        # One that cannot be asked is not known to be another's, so it is not skipped.
        self.assertIs(False, collect_usage._another_users(os.path.join(self.base, "gone")))

    def test_both_temp_roots_are_searched(self):
        """#3706 five-gate review, item 4: every other test here replaces the roots, so
        either could be dropped from the list unseen. This one leaves the list alone
        and watches the helper."""
        controller = self.write(self.base, os.path.join("projects", "slug", "s1.jsonl"), "")
        real, roots = safe_glob.under, []

        def under(directory, *parts):
            if parts == ("claude-*",):
                roots.append(directory)
                return []                              # this machine's are not read
            return real(directory, *parts)

        with mock.patch.object(safe_glob, "under", under):
            collect_usage.find_task_transcripts(controller)
        self.assertEqual(["/private/tmp", "/tmp"], roots)

    def test_the_temp_task_directory_is_taken_as_it_is_spelled(self):
        """#3706 review, item 6: the one site of #3701 with no test. A session named
        `s[1]` read the tasks of the session named `s1`."""
        project = os.path.join(self.base, "project")
        slug = collect_usage.project_slug(project)
        sessions = os.path.join(self.base, "home", ".claude", "projects", slug)
        controller = self.write(sessions, "s[1].jsonl", "")
        temp = os.path.join(self.base, "tmp[1]")
        mine = self.write(temp, os.path.join("claude-505", slug, "s[1]", "tasks", "mine.output"), "")
        self.write(temp, os.path.join("claude-505", slug, "s1", "tasks", "theirs.output"), "")
        self.write(self.base, os.path.join("tmp1", "claude-505", slug, "s[1]", "tasks",
                                           "elsewhere.output"), "")
        with mock.patch.object(collect_usage, "TEMP_ROOTS", (temp,)):
            self.assertEqual([mine], collect_usage.find_task_transcripts(controller))

    # --- kimi --------------------------------------------------------------------------

    def test_a_kimi_home_that_cannot_be_listed(self):
        home = os.path.join(self.base, "kimi")
        record = {"type": "llm.tools_snapshot", "tools": ["Read"], "agent": "mine.md"}
        wire = self.write(home, os.path.join("sessions", "d", "s1", "agents", "main", "wire.jsonl"),
                          json.dumps(record) + "\n")
        sessions = os.path.join(home, "sessions")
        self.assertEqual(wire, kimi_runner.wire_path(home, "s1"))
        with unlistable(sessions):
            # The snapshot reader says it could not look. The runner keeps the reply and
            # reports its usage as unknown: `tests/runners/test_kimi.py` holds that
            # (`test_a_reply_survives_a_wire_directory_that_cannot_be_listed`).
            self.assertEqual(([], "the per-run home's wire files could not be listed: %s could "
                              "not be listed: Permission denied" % sessions),
                             kimi_snapshot._kimi_wire_snapshots(home))

    # --- readiness ---------------------------------------------------------------------

    def test_a_sub_skill_root_that_cannot_be_listed_says_so(self):
        """Readiness never stops for a sub-skill, so this one is a row, not an error: the
        row no longer reads as "not installed"."""
        root = os.path.join(self.base, "plugins")
        mine = self.write(root, os.path.join("vendor", "skills", "leaf", "SKILL.md"), "#")
        with mock.patch.object(readiness, "SUB_SKILL_ROOTS", (root,)), \
                mock.patch.object(readiness, "REQUIRED_SUB_SKILLS", ("pack:leaf", "pack:absent")):
            found = [{"name": "pack:leaf", "found_at": mine},
                     {"name": "pack:absent", "found_at": None}]
            self.assertEqual(found, readiness._sub_skill_rows())
            self.assertEqual("leaf: %s; absent: not found" % mine,
                             readiness._sub_skill_line(found))
            with unlistable(root):
                rows = readiness._sub_skill_rows()
            # A name is looked up without listing its directory, so the sub-skill inside
            # an unlistable one is still found. The deeper patterns do list it, so the one
            # that is not found says where the search could not look.
            skills = os.path.join(root, "vendor", "skills")
            with unlistable(skills):
                self.assertEqual([found[0], dict(found[1], unlistable=skills)],
                                 readiness._sub_skill_rows())
            # The search goes on past a root it could not list, and what it finds
            # elsewhere is simply found.
            other = os.path.join(self.base, "skills")
            there = self.write(other, os.path.join("leaf", "SKILL.md"), "#")
            with mock.patch.object(readiness, "SUB_SKILL_ROOTS", (root, other)), unlistable(root):
                self.assertEqual([{"name": "pack:leaf", "found_at": there},
                                  {"name": "pack:absent", "found_at": None, "unlistable": root}],
                                 readiness._sub_skill_rows())
        self.assertEqual([{"name": "pack:leaf", "found_at": None, "unlistable": root},
                          {"name": "pack:absent", "found_at": None, "unlistable": root}], rows)
        self.assertEqual("leaf: not found ({0} could not be listed); "
                         "absent: not found ({0} could not be listed)".format(root),
                         readiness._sub_skill_line(rows))
        # The line is one line whatever the directory is named; the row holds the path.
        self.assertEqual("absent: not found (%s could not be listed)" % FORGED_SHOWN,
                         readiness._sub_skill_line([dict(found[1], unlistable=FORGED)]))


if __name__ == "__main__":
    unittest.main()

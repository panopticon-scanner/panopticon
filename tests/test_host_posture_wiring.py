"""#1344 F2: the seven sites that decide a run's posture read ONE source.

This file exists to be rewritten by F3. When probe evidence lands, every
assertion here becomes an assertion about `posture()` instead of `declares()`,
and the behavior change spec §7.1 describes shows up as edits to exactly this
file. Keeping the sites uniform is what makes that swap mechanical.

The guard below is AST-based, not text-based. Two text-based versions were
tried and rejected in review: a raw regex scan flags requests.py's own
docstring, which quotes the idiom while explaining it, and a token scan that
blanks string-bearing lines flags nothing at all -- every instance of the
idiom carries a string literal on the same line, so blanking the line blanks
the evidence. An `ast.Compare` walk cannot see prose and cannot be fooled by
the literal it is looking for.
"""
import ast
import os
import shutil
import tempfile
import unittest

from conftest import REPO_ROOT
from scripts import hosts

PHASES = os.path.join(REPO_ROOT, "skill", "scripts", "phases")

_HOST_NAMES = frozenset(hosts.known_hosts())


def _host_name_comparisons(path):
    """Every real comparison against a host-name literal in one file.

    AST, not text. Two text-based versions were tried and were wrong in
    opposite directions: a raw scan flags `requests.py`'s own docstring, which
    quotes the idiom while explaining it, and a token scan that blanks
    string-bearing lines flags nothing at all -- every instance of the idiom
    carries a string literal on the same line, so blanking the line blanks the
    evidence. An `ast.Compare` walk cannot see prose and cannot be fooled by
    the literal it is looking for.
    """
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    lines = source.splitlines()
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left] + list(node.comparators)
        flat = []
        for operand in operands:
            if isinstance(operand, (ast.Tuple, ast.List, ast.Set)):
                flat.extend(operand.elts)   # `host in ("claude", "kimi")`
            else:
                flat.append(operand)
        if any(isinstance(o, ast.Constant) and isinstance(o.value, str)
               and o.value in _HOST_NAMES for o in flat):
            found.append((node.lineno, lines[node.lineno - 1].strip()))
    return found


def _offenders():
    """Every host-name comparison left anywhere in `phases/`."""
    found = []
    for name in sorted(os.listdir(PHASES)):
        if name.endswith(".py"):
            found.extend(
                "%s:%d %s" % (name, lineno, text)
                for lineno, text in _host_name_comparisons(
                    os.path.join(PHASES, name)))
    return sorted(found)


class TestNoSiteTestsAHostName(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_the_scanner_reads_the_directory(self):
        # Guards the guard.
        names = [n for n in os.listdir(PHASES) if n.endswith(".py")]
        self.assertGreater(len(names), 5)

    def test_no_phase_decides_posture_from_a_host_name(self):
        self.assertEqual(
            [], _offenders(),
            "posture comes from hosts.declares(), not from a name:\n%s"
            % "\n".join(_offenders()))

    def test_the_guard_can_actually_flag_something(self):
        # Guards the guard. One earlier version of this scanner flagged prose;
        # another, measured, flagged nothing at all in any file.
        probe = os.path.join(self.tmp, "probe.py")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write('host = "x"\nenforced = host == "claude"\n')
        self.assertEqual(1, len(_host_name_comparisons(probe)))

    def test_the_guard_cannot_see_prose(self):
        # requests.py's docstring quotes `host == "claude"` while explaining
        # the idiom being removed. A text scan flags it; this must not.
        probe = os.path.join(self.tmp, "prose.py")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write('def f():\n'
                     '    """`enforced` is `host == "claude"` in the driver."""\n'
                     '    return 1  # host == "claude" once lived here\n')
        self.assertEqual([], _host_name_comparisons(probe))


class TestTheAnswersAreUnchanged(unittest.TestCase):
    """F2 is a refactor. These pin the answers the seven sites gave before it."""

    def test_claude_enforces_and_nothing_else_the_driver_accepts_does(self):
        self.assertTrue(hosts.declares("claude", hosts.TOOL_POLICY_ENFORCED))
        for name in ("generic", "gemini"):
            with self.subTest(host=name):
                self.assertFalse(
                    hosts.declares(name, hosts.TOOL_POLICY_ENFORCED))

    def test_only_claude_collects_usage(self):
        self.assertTrue(hosts.declares("claude", hosts.USAGE_LEDGER))
        for name in ("generic", "gemini"):
            with self.subTest(host=name):
                self.assertFalse(hosts.declares(name, hosts.USAGE_LEDGER))

    def test_an_absent_host_key_is_treated_as_claude(self):
        # requests.py reads `manifest.get("host", "claude")`. Preserve that
        # default exactly -- a manifest written before the key existed must
        # keep resolving the same way.
        self.assertTrue(
            hosts.declares({}.get("host", "claude"), hosts.TOOL_POLICY_ENFORCED))

    def test_only_claude_has_a_write_guard(self):
        # requests.py:185 -- require_unenforced_ack returns early when the
        # host's hook mediates Write. Same answer as before the migration.
        self.assertTrue(hosts.declares("claude", hosts.ARTIFACT_WRITE_GUARD))
        for name in ("generic", "gemini"):
            with self.subTest(host=name):
                self.assertFalse(hosts.declares(name, hosts.ARTIFACT_WRITE_GUARD))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

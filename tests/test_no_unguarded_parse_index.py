"""Guard the TST-B3A class itself: no unguarded index into a parse/build result.

Three consecutive self-scans re-found the same defect -- a test indexing an
adapter's parse result (`findings[0]`, `build_candidates(...)[0]`) with no
preceding length assertion, so an empty-list REGRESSION surfaces as a bare
IndexError naming the test's plumbing instead of the invariant that broke
(run-8 #1399/#1420, run-9 x3, run-10 x6). Fixing the cited files each time left
the class alive; this test makes it self-policing.

Scope: the parse-result family (tests/tools/ + the ingest/x0x report and e2e
tests), where the pattern actually recurs. A site is acceptable when it is
guarded by a nearby `len(...)` assertion, or goes through
`_test_helpers.first`/`only`.

Run-11 (#1524) re-found the class a fourth time, in a file the FAMILY scope did
not cover AND in a form the detector could not see: `groups["groups"][0]` reaches
the index through a SUBSCRIPT CHAIN, so no word character precedes the `[0]` and
`_VAR_INDEX` never matched. Both holes are closed here.

Reads only. `sarif["runs"][0]["results"] = []` and `...[0].update(...)` are the
test BUILDING its own fixture -- a literal the test authored cannot regress to
empty, so demanding a length assertion there would be noise, not safety.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
FAMILY = sorted(ROOT.joinpath("tools").glob("test_*.py")) + [
    ROOT / "test_ingest_tools.py",
    ROOT / "test_x0x_report.py",
    ROOT / "test_e2e.py",          # #1524
]

# `name[0]` (a bare variable index) and `...)[0]` (an inline call-result index).
_VAR_INDEX = re.compile(r"\b(\w+)\[0\]")
_CALL_INDEX = re.compile(r"\)\[0\]")
# `root["a"]["b"][0]` -- the index is reached through a subscript chain, so
# nothing word-like precedes it and _VAR_INDEX is blind to it (#1524).
_CHAIN_INDEX = re.compile(r"(\w+(?:\.\w+)*(?:\[[^\[\]]*\])+)\[0\]")
# Names that are not parse results: mock introspection, argv, path splits, and
# SARIF fixtures the ingest tests author themselves (a literal cannot regress).
_NOT_A_RESULT = frozenset({
    "sys", "os", "argv", "parts", "cmd", "calls", "args", "call_args",
    "m", "g", "runs", "row", "mock_calls",
    "SARIF", "b101", "b608",
})
# NOT exempt, though it was until #1524: `groups`. Nothing in FAMILY needed the
# exemption, and it was silently swallowing the very sites run-11 re-found
# (`groups["groups"][0]`). A regex `.groups()[0]` is caught by _CALL_INDEX.
# Statements that BUILD a fixture rather than read a result.
_MUTATOR = re.compile(r"\.(update|insert|append|setdefault|pop)\(")
_ASSIGN = re.compile(r"[^=!<>+\-*/%|&^]=[^=]")
_GUARD_WINDOW = 6          # lines to look back for a length assertion


def _is_fixture_write(line, end):
    """True when the `[0]` at `end` is part of the test constructing its own
    fixture -- left of an assignment, or the receiver of a mutating call."""
    assign = _ASSIGN.search(line)
    if assign and end <= assign.start() + 1:
        return True
    return bool(_MUTATOR.search(line[end:]))


def _unguarded_sites(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    out = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        window = "\n".join(lines[max(0, i - _GUARD_WINDOW):i])
        for m in _VAR_INDEX.finditer(line):
            var = m.group(1)
            if var in _NOT_A_RESULT:
                continue
            if re.search(r"len\(\s*%s\s*\)" % re.escape(var), window):
                continue          # guarded by a nearby length assertion
            out.append((i + 1, stripped))
        if _CALL_INDEX.search(line):
            out.append((i + 1, stripped))
        for m in _CHAIN_INDEX.finditer(line):
            chain = m.group(1)
            root = chain.split("[")[0].split(".")[-1]
            if root in _NOT_A_RESULT:
                continue
            if _is_fixture_write(line, m.end()):
                continue
            if re.search(r"len\(\s*%s\s*\)" % re.escape(chain), window):
                continue          # guarded by a nearby length assertion
            out.append((i + 1, stripped))
    return out


class TestNoUnguardedParseIndex(unittest.TestCase):
    def test_parse_result_family_has_no_unguarded_index(self):
        offenders = []
        for path in FAMILY:
            if not path.exists():
                continue
            for lineno, text in _unguarded_sites(path):
                offenders.append("%s:%d  %s" % (path.relative_to(ROOT.parent), lineno, text))
        self.assertEqual(
            offenders, [],
            "Unguarded index into a parse/build result (TST-B3A). Assert the "
            "length first, or use _test_helpers.first()/only():\n  "
            + "\n  ".join(offenders))

    def test_detector_catches_a_planted_offender(self):
        # The guard is only worth having if it actually fires -- prove it on a
        # synthetic file rather than trusting the scan above to be non-vacuous.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "test_planted.py"
            p.write_text("def t():\n    findings = parse(raw)\n"
                         "    assert findings[0]['x'] == 1\n")
            self.assertTrue(_unguarded_sites(p), "detector missed a bare index")
            p.write_text("def t():\n    findings = parse(raw)\n"
                         "    assert len(findings) == 1\n"
                         "    assert findings[0]['x'] == 1\n")
            self.assertEqual(_unguarded_sites(p), [], "detector flagged a guarded index")

    def test_detector_catches_a_planted_subscript_chain(self):
        # #1524: the form the detector was blind to -- no word character
        # precedes the `[0]`, so only _CHAIN_INDEX can see it.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "test_planted_chain.py"
            p.write_text("def t():\n    out = parse(raw)\n"
                         "    name = out['groups'][0]['name']\n")
            self.assertTrue(_unguarded_sites(p), "detector missed a chain index")
            p.write_text("def t():\n    out = parse(raw)\n"
                         "    assert len(out['groups']) == 1\n"
                         "    name = out['groups'][0]['name']\n")
            self.assertEqual(_unguarded_sites(p), [],
                             "detector flagged a guarded chain index")

    def test_detector_ignores_fixture_construction(self):
        # A literal the test authored cannot regress to empty, so building one
        # is not the defect -- demanding a length assertion there is noise.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "test_planted_fixture.py"
            p.write_text("def t():\n    doc = {'runs': [{'results': []}]}\n"
                         "    doc['runs'][0]['results'] = [1]\n"
                         "    doc['runs'][0]['results'].append(2)\n")
            self.assertEqual(_unguarded_sites(p), [],
                             "detector flagged the test building its own fixture")


if __name__ == "__main__":
    unittest.main()

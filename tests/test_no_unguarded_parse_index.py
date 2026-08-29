"""Guard the TST-B3A class itself: no unguarded index into a parse/build result.

Three consecutive self-scans re-found the same defect -- a test indexing an
adapter's parse result (`findings[0]`, `build_candidates(...)[0]`) with no
preceding length assertion, so an empty-list REGRESSION surfaces as a bare
IndexError naming the test's plumbing instead of the invariant that broke
(run-8 #1399/#1420, run-9 x3, run-10 x6). Fixing the cited files each time left
the class alive; this test makes it self-policing.

Scope: the parse-result family (tests/tools/ + the ingest/x0x report tests),
where the pattern actually recurs. A site is acceptable when it is guarded by a
nearby `len(...)` assertion, or goes through `_test_helpers.first`/`only`.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
FAMILY = sorted(ROOT.joinpath("tools").glob("test_*.py")) + [
    ROOT / "test_ingest_tools.py",
    ROOT / "test_x0x_report.py",
]

# `name[0]` (a bare variable index) and `...)[0]` (an inline call-result index).
_VAR_INDEX = re.compile(r"\b(\w+)\[0\]")
_CALL_INDEX = re.compile(r"\)\[0\]")
# Names that are not parse results: mock introspection, argv, path splits.
_NOT_A_RESULT = frozenset({
    "sys", "os", "argv", "parts", "cmd", "calls", "args", "call_args",
    "m", "g", "runs", "row", "groups", "mock_calls",
})
_GUARD_WINDOW = 6          # lines to look back for a length assertion


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


if __name__ == "__main__":
    unittest.main()

"""#3193: the files Semgrep skipped for size, listed on the host (`scripts.semgrep_targets`).

The matcher is pinned by a DIFFERENTIAL against Semgrep itself: the table below is
the pinned Semgrep 1.179.0's own `--x-ls-long` verdict for each `--exclude`
pattern over a tree of spellings (measured once on the forge, 43 patterns x 56
paths = 2408 rows; 0 where the matcher dropped a path Semgrep kept). Every pattern
form the matcher claims to know must agree with it row for row. The forms it was
not measured on read as "unknown", so their files stay LISTED (fail-closed,
coordinator ruling): over-disclosure costs a certification, under-disclosure hides
a payload.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

from scripts import semgrep_targets as st
import scripts.ingest_tools as ingest
from scripts.synth import findings as findings_mod, plan, report, tool_axis
from scripts.tools.legacy_sarif import SEMGREP_SCANNER_EXCLUDES, TOOL_CMD

PATHS = (
    '.git/config', 'a/.git/x', '.gitx/y', '.DS_Store', 'a/.DS_Store', 'x.DS_Store', '_darcs/d',
    '.svn/s', 'build/b.py', 'a/build/b.py', 'c/build', 'buildx/b.py', 'Build/b.py', 'vendor/v.py',
    'a/vendor/v.py', 'dist/d.py', 'x/dist/d.py', 'x.min.js', 'a/x.min.js', 'min.js',
    'a.min.js/f.py', 'UPPER.MIN.JS', 'pkg.egg-info/e.py', 'a/pkg.egg-info/e.py', 'file.egg-info',
    '.hidden.egg-info/z.py', '.venv/lib/x.py', 'sub/.venv/lib/x.py', 'other/sub/.venv/x.py',
    'sub/.venvx/y.py', 'sub/.venv2', 'node_modules/m.js', 'a/node_modules/m.js',
    '__pycache__/c.pyc', 'a/__pycache__/c.pyc', '.panopticon/p.json', '.worktrees/w/x.py',
    '.env/e.py', '.envrc', 'gen/x_hit.py', 'a/gen/x_hit.py', 'gen/sub/x_hit.py', 'gen/hit.py',
    'tests/fixtures/a.py', 'tests/fixtures/deep/b.py', 'x/tests/fixtures/c.py',
    'tests/fixturesx/d.py', 'top_only/t.py', 'a/top_only/t.py', 'top_only2/t.py',
    '.test_durations', 'a/.test_durations', '.test_durations_x', 'a/b/c.py', 'x/a/b/c.py',
    'a/bc.py',
)

# For each --exclude pattern: the PATHS Semgrep's own --x-ls-long excluded.
EXCLUDED_BY_SEMGREP = {
    '.git': (
        '.git/config', 'a/.git/x',
    ),
    '.svn': (
        '.svn/s',
    ),
    '_darcs': (
        '_darcs/d',
    ),
    'build/': (
        'build/b.py', 'a/build/b.py',
    ),
    'vendor/': (
        'vendor/v.py', 'a/vendor/v.py',
    ),
    'dist/': (
        'dist/d.py', 'x/dist/d.py',
    ),
    '*.min.js': (
        'x.min.js', 'a/x.min.js', 'a.min.js/f.py',
    ),
    '.env/': (
        '.env/e.py',
    ),
    '.tox/': (),
    'node_modules/': (
        'node_modules/m.js', 'a/node_modules/m.js',
    ),
    '.npm/': (),
    '.yarn/': (),
    '.venv/': (
        '.venv/lib/x.py', 'sub/.venv/lib/x.py', 'other/sub/.venv/x.py',
    ),
    '_opam/': (),
    '_build/': (),
    '_cargo/': (),
    '.panopticon/': (
        '.panopticon/p.json',
    ),
    '.worktrees/': (
        '.worktrees/w/x.py',
    ),
    '.superpowers/': (),
    '__pycache__/': (
        '__pycache__/c.pyc', 'a/__pycache__/c.pyc',
    ),
    '.ruff_cache/': (),
    '.pytest_cache/': (),
    '.mypy_cache/': (),
    '*.egg-info/': (
        'pkg.egg-info/e.py', 'a/pkg.egg-info/e.py', '.hidden.egg-info/z.py',
    ),
    '.DS_Store': (
        '.DS_Store', 'a/.DS_Store',
    ),
    '.venv': (
        '.venv/lib/x.py', 'sub/.venv/lib/x.py', 'other/sub/.venv/x.py',
    ),
    'sub/.venv': (
        'sub/.venv/lib/x.py',
    ),
    'gen/*_hit.py': (
        'gen/x_hit.py',
    ),
    'tests/fixtures/**': (
        'tests/fixtures/a.py', 'tests/fixtures/deep/b.py',
    ),
    '/top_only': (
        'top_only/t.py',
    ),
    '.test_durations': (
        '.test_durations', 'a/.test_durations',
    ),
    'a/b': (
        'a/b/c.py',
    ),
    '*.py': (
        'build/b.py', 'a/build/b.py', 'buildx/b.py', 'Build/b.py', 'vendor/v.py', 'a/vendor/v.py',
        'dist/d.py', 'x/dist/d.py', 'a.min.js/f.py', 'pkg.egg-info/e.py', 'a/pkg.egg-info/e.py',
        '.hidden.egg-info/z.py', '.venv/lib/x.py', 'sub/.venv/lib/x.py', 'other/sub/.venv/x.py',
        'sub/.venvx/y.py', '.worktrees/w/x.py', '.env/e.py', 'gen/x_hit.py', 'a/gen/x_hit.py',
        'gen/sub/x_hit.py', 'gen/hit.py', 'tests/fixtures/a.py', 'tests/fixtures/deep/b.py',
        'x/tests/fixtures/c.py', 'tests/fixturesx/d.py', 'top_only/t.py', 'a/top_only/t.py',
        'top_only2/t.py', 'a/b/c.py', 'x/a/b/c.py', 'a/bc.py',
    ),
    '/a/b': (
        'a/b/c.py',
    ),
    'a/b/': (
        'a/b/c.py',
    ),
    'gen/*': (
        'gen/x_hit.py', 'gen/sub/x_hit.py', 'gen/hit.py',
    ),
    '*/build': (
        'a/build/b.py', 'c/build',
    ),
    'dist': (
        'dist/d.py', 'x/dist/d.py',
    ),
    '**/x_hit.py': (
        'gen/x_hit.py', 'a/gen/x_hit.py', 'gen/sub/x_hit.py',
    ),
    'x?_hit.py': (),
    'a/**/c.py': (
        'a/b/c.py',
    ),
    '[ab]/b': (
        'a/b/c.py',
    ),
    '!x.py': (),
}

# Glob shapes outside the measured forms. Semgrep excludes some of these paths;
# the matcher must say "unknown" so the walk keeps them listed.
UNMEASURED = ['**/x_hit.py', 'x?_hit.py', 'a/**/c.py', '[ab]/b', '!x.py']


def _rel(path):
    return tuple(path.split("/"))


class TestTheMatcherAgreesWithSemgrep(unittest.TestCase):
    def test_the_table_covers_every_scanner_exclude(self):
        self.assertTrue(set(SEMGREP_SCANNER_EXCLUDES) <= set(EXCLUDED_BY_SEMGREP))

    def test_every_measured_form_agrees_with_semgrep_row_for_row(self):
        for pattern, excluded in EXCLUDED_BY_SEMGREP.items():
            if pattern in UNMEASURED:
                continue
            for path in PATHS:
                with self.subTest(pattern=pattern, path=path):
                    self.assertIs(st.pattern_drops(pattern, _rel(path), False), path in excluded)

    def test_an_unmeasured_pattern_form_leaves_the_file_listed(self):
        for pattern in UNMEASURED:
            with self.subTest(pattern=pattern):
                self.assertTrue(all(st.pattern_drops(pattern, _rel(p), False) is None for p in PATHS))
                self.assertFalse(any(st.excluded(_rel(p), False, [pattern]) for p in PATHS))
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "a", "b"))
            with open(os.path.join(root, "a", "b", "c.py"), "w") as fh:
                fh.write("x" * 11)
            self.assertEqual(st.oversized(root, ["a/**/c.py", "[ab]/b"], 10)["files"], ["a/b/c.py"])


class TestTheWalk(unittest.TestCase):
    """The walk lists what Semgrep would select and skip for size, and nothing it
    would not reach: a symlink is never followed or listed (measured)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = os.path.join(tmp.name, "target")
        self.outside = os.path.join(tmp.name, "outside")
        os.makedirs(self.root)
        os.makedirs(self.outside)

    def _file(self, rel, size, base=None):
        path = os.path.join(base or self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(b"x" * size)
        return path

    def test_over_the_limit_is_listed_and_exactly_the_limit_is_not(self):
        self._file("over.py", 11)
        self._file("at.py", 10)
        self._file("deep/er/over.bin", 11)
        self.assertEqual(st.oversized(self.root, [], 10),
                         {"limit": 10, "count": 2, "files": ["deep/er/over.bin", "over.py"],
                          "complete": True})

    @unittest.skipIf(sys.platform == "win32", "POSIX symlinks")
    def test_no_symlink_is_followed_or_listed(self):
        big_out = self._file("big.py", 11, self.outside)
        os.symlink(big_out, os.path.join(self.root, "link_out_big.py"))
        os.symlink(self.outside, os.path.join(self.root, "link_out_dir"))
        self._file("big_in.py", 11)
        os.symlink("big_in.py", os.path.join(self.root, "link_in_big.py"))
        self.assertEqual(st.oversized(self.root, [], 10)["files"], ["big_in.py"])

    def test_the_argv_excludes_are_honoured(self):
        cmd = [a for a in TOOL_CMD["semgrep"]] + ["--exclude=gen/*_hit.py"]
        for rel in ("build/b.py", "a/node_modules/m.js", "x.min.js", "gen/x_hit.py", "kept.py"):
            self._file(rel, 11)
        self.assertEqual(st.oversized(self.root, st.argv_excludes(cmd), 10)["files"], ["kept.py"])

    def test_awkward_names_are_listed(self):
        names = ["with space.py", "nl\nname.py"]
        if sys.platform.startswith("linux"):
            names.append(os.fsdecode(b"bad\xffutf8.py"))
        for name in names:
            self._file(name, 11)
        listing = st.oversized(self.root, [], 10)
        self.assertEqual(sorted(listing["files"]), sorted(names))
        json.dumps(listing)    # a non-UTF-8 name still serializes (as a surrogate escape)

    def test_the_listing_is_bounded_and_counts_the_rest(self):
        for i in range(st.MAX_LISTED + 5):
            self._file("f%03d.py" % i, 11)
        listing = st.oversized(self.root, [], 10)
        self.assertEqual((listing["count"], len(listing["files"])), (st.MAX_LISTED + 5, st.MAX_LISTED))

    def test_a_walk_cut_short_is_incomplete(self):
        for i in range(5):
            self._file("d/f%d.py" % i, 11)
        self.assertFalse(st.oversized(self.root, [], 10, max_entries=3)["complete"])

    @unittest.skipIf(sys.platform == "win32" or os.geteuid() == 0, "needs POSIX modes, not root")
    def test_an_unreadable_directory_is_incomplete(self):
        self._file("locked/f.py", 1)
        locked = os.path.join(self.root, "locked")
        os.chmod(locked, 0)
        self.addCleanup(os.chmod, locked, 0o755)
        self.assertFalse(st.oversized(self.root, [], 10)["complete"])


class TestTheStamp(unittest.TestCase):
    def test_the_limit_is_read_off_the_launched_argv(self):
        self.assertEqual(st.argv_limit(TOOL_CMD["semgrep"]), 1_000_000)
        self.assertEqual(st.argv_limit(["semgrep", "--max-target-bytes=5"]), 5)
        self.assertEqual(st.argv_limit(["semgrep"]), st.SEMGREP_DEFAULT_MAX_TARGET_BYTES)

    def test_only_semgrep_is_stamped(self):
        self.assertIsNone(st.stamper("bandit", "/nonexistent", TOOL_CMD["semgrep"]))

    def test_the_stamp_keeps_the_runs_other_properties(self):
        payload = json.dumps({"runs": [{"results": [], "properties": {"panopticon_scanned_files": 3}}]})
        listing = {"limit": 1, "count": 0, "files": [], "complete": True}
        doc = json.loads(st.stamp(payload.encode(), listing))
        self.assertEqual(doc["runs"][0]["properties"],
                         {"panopticon_scanned_files": 3, st.STAMP_KEY: listing})

    def test_output_that_is_not_sarif_is_untouched(self):
        for payload in (b"not json", b"[]", b'{"runs": []}', b'{"runs": ["x"]}'):
            with self.subTest(payload=payload):
                self.assertEqual(st.stamp(payload, {}), payload)


def _canary_capture():
    return {"runs": [{"tool": {"driver": {"name": "Semgrep OSS", "rules": []}},
                      "results": [{"ruleId": "eval-detected", "level": "error",
                                   "message": {"text": "Detected the use of eval()."},
                                   "locations": [{"physicalLocation": {
                                       "artifactLocation": {"uri": "/src/small.py"},
                                       "region": {"startLine": 2}}}]}],
                      "invocations": [{"executionSuccessful": True}]}]}


class TestASkippedFileReachesTheReport(unittest.TestCase):
    """The issue's done-when: a >1 MB file with a canary is listed as skipped and
    certification is withheld; the argv states the limit."""

    def _ingest(self, payload):
        with tempfile.TemporaryDirectory() as tools:
            with open(os.path.join(tools, "semgrep.sarif"), "wb") as fh:
                fh.write(payload)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                findings, dispositions = ingest.ingest_dir_detailed(tools, "g1")
        return findings, dispositions["semgrep"], stderr.getvalue()

    def _report(self, findings, disposition):
        dispositions = {"semgrep": disposition}
        return report.build_report(report.ReportInputs(
            run=report.RunConfig(target="t", fail_on="high", timestamp="2026-10-20T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan.PlanInputs(scout_requested=["semgrep"]),
            tools=tool_axis.ToolAxis(tools_ran=tool_axis.tools_ran_from_dispositions(dispositions),
                                     dispositions=dispositions)))

    def test_a_file_over_one_megabyte_is_disclosed_and_uncertified(self):
        self.assertIn("--max-target-bytes=1000000", TOOL_CMD["semgrep"])
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "big.py"), "w") as fh:
                fh.write("x = 1\n" * 170_000 + "\n\ndef zz_canary(s):\n    return eval(s)\n")
            with open(os.path.join(root, "small.py"), "w") as fh:
                fh.write("def t(s):\n    return eval(s)\n")
            stamp = st.stamper("semgrep", root, TOOL_CMD["semgrep"])
            payload = stamp(json.dumps(_canary_capture()).encode())
        findings, disposition, diagnostic = self._ingest(payload)
        facts = disposition["file_coverage"]
        self.assertEqual(facts["files"], [{"file": "big.py", "reason": "size_skipped"}])
        self.assertEqual((facts["status"], facts["size_skipped"], facts["size_limit"], facts["size_listing"]),
                         ("partial", 1, 1_000_000, "listed"))
        self.assertIn("1 file(s) over the size limit not scanned", diagnostic)
        published = self._report(findings, disposition)
        self.assertEqual(published["meta"]["coverage"]["tools_file_partial"], {"semgrep": facts})
        self.assertFalse(published["summary"]["coverage_certified"])
        self.assertIn("partial scanner file coverage: semgrep", published["summary"]["coverage_note"])

    def test_nothing_over_the_limit_stays_complete(self):
        with tempfile.TemporaryDirectory() as root:
            payload = st.stamper("semgrep", root, TOOL_CMD["semgrep"])(json.dumps(_canary_capture()).encode())
        _, disposition, diagnostic = self._ingest(payload)
        self.assertNotIn("file_coverage", disposition)
        self.assertEqual(diagnostic, "")

    def test_a_missing_or_bad_listing_is_partial_and_unlocated(self):
        good = {"limit": 10, "count": 0, "files": [], "complete": True}
        cases = {"absent": None, "malformed": "lots", "incomplete": dict(good, complete=False)}
        cases.update({"malformed-" + key: dict(good, **{key: value}) for key, value in (
            ("limit", True), ("count", -1), ("count", "1"), ("files", "big.py"), ("files", [7]),
            ("files", [""]), ("complete", 1))})
        cases["malformed-more-files-than-count"] = dict(good, files=["a.py"])
        for name, listing in cases.items():
            with self.subTest(case=name):
                doc = _canary_capture()
                if listing is not None:
                    doc["runs"][0]["properties"] = {st.STAMP_KEY: listing}
                findings, disposition, _ = self._ingest(json.dumps(doc).encode())
                facts = disposition["file_coverage"]
                self.assertEqual((facts["status"], facts["unlocated_records"], facts["size_listing"]),
                                 ("partial", 1, name.split("-")[0]))
                self.assertEqual(len(findings), 1)
                self.assertFalse(self._report(findings, disposition)["summary"]["coverage_certified"])

    def test_a_long_listing_counts_what_it_does_not_name(self):
        doc = _canary_capture()
        doc["runs"][0]["properties"] = {st.STAMP_KEY: {
            "limit": 10, "count": 150, "files": ["f%03d" % i for i in range(100)], "complete": True}}
        _, disposition, _ = self._ingest(json.dumps(doc).encode())
        facts = disposition["file_coverage"]
        self.assertEqual((facts["unparsed_files"], len(facts["files"]), facts["files_omitted"]), (150, 100, 50))

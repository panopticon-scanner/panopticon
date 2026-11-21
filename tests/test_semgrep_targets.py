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
import unittest.mock

from scripts import semgrep_targets as st
import scripts.ingest_tools as ingest
import scripts.run_tools as run_tools
import scripts.tools_manifest as tools_manifest
from scripts.synth import findings as findings_mod, plan, report, tool_axis
from scripts.tools.legacy_sarif import SEMGREP_SCANNER_EXCLUDES, TOOL_CMD
from tests._test_helpers import REPO_ROOT
from tests.run_tools_test_helpers import _FakeResult

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

    def test_a_file_named_like_a_trailing_doublestar_prefix_stays_selected(self):
        # Measured beside the table: under `tests/fixtures/**` Semgrep still
        # selects a FILE named `tests/fixtures`; it excludes only what is inside.
        self.assertIs(st.pattern_drops("tests/fixtures/**", ("tests", "fixtures"), False), False)
        self.assertIs(st.pattern_drops("tests/fixtures/**", ("tests", "fixtures", "a.py"), False), True)

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

    def test_an_excluded_directory_is_not_walked(self):
        # Pruned, not merely filtered: a vast excluded tree (node_modules) must
        # not exhaust the walk's bound and make the listing incomplete.
        for i in range(10):
            self._file("node_modules/m%d.js" % i, 11)
        self._file("kept.py", 11)
        listing = st.oversized(self.root, ["node_modules/"], 10, max_entries=5)
        self.assertEqual((listing["files"], listing["complete"]), (["kept.py"], True))

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

    def test_the_walk_reads_no_further_than_the_entry_cap(self):
        # #3246: the directory is iterated lazily, so a huge one is never read
        # whole before the cap is counted against it.
        for i in range(50):
            self._file("f%02d.py" % i, 1)
        pulled = [0]
        real = os.scandir

        class Counting:
            def __init__(self, path):
                self.inner = real(path)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.inner.close()

            def __iter__(self):
                for entry in self.inner:
                    pulled[0] += 1
                    yield entry

        with unittest.mock.patch.object(st.os, "scandir", Counting):
            listing = st.oversized(self.root, [], 10, max_entries=3)
        self.assertFalse(listing["complete"])
        self.assertLessEqual(pulled[0], 4)

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

    def test_a_completed_process_capture_is_stamped_too(self):
        import subprocess
        from scripts import tool_capture
        sarif = json.dumps({"runs": [{"results": []}]}).encode()
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, "semgrep.sarif")
            runner = lambda *a, **k: subprocess.CompletedProcess(a, 0, sarif, b"")  # noqa: E731
            tool_capture._capture_run("tool", "semgrep", ["semgrep"], out, runner,
                                      stamp=st.stamper("semgrep", root, TOOL_CMD["semgrep"]))
            with open(out) as fh:
                listing = json.load(fh)["runs"][0]["properties"][st.STAMP_KEY]
        self.assertEqual(listing, {"limit": 1_000_000, "count": 0, "files": [], "complete": True})

    def test_output_that_is_not_sarif_is_untouched(self):
        for payload in (b"not json", b"[]", b'{"runs": []}', b'{"runs": ["x"]}'):
            with self.subTest(payload=payload):
                self.assertEqual(st.stamp(payload, {}), payload)


def _dockerfile_capture(covered, cross_language=False):
    result = ({"ruleId": "dockerfile.security.last-user-is-root.last-user-is-root",
               "level": "error",
               "message": {"text": "The last user in the container is 'root'."},
               "locations": [{"physicalLocation": {
                   "artifactLocation": {"uri": "/src/Dockerfile.prod"},
                   "region": {"startLine": 2, "endLine": 2}}}]}
              if covered else None)
    syntax = ([
        {"descriptor": {"id": "Other syntax error"},
         "level": "warning", "message": {"text":
             "Other syntax error at line /src/Dockerfile.prod:%d:\n %s"
             % (line, detail)}}
        for line, detail in (
            (1, "`FROM` was unexpected"),
            (1, "Failure: not a program"),
            (2, "`USER root` was unexpected"),
            (2, "Failure: not a program"),
            (2, "expected a Python statement"),
            (2, "expected a JavaScript statement"),
        )] if cross_language else [])
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Semgrep OSS", "rules": [{
            "id": "dockerfile.security.last-user-is-root.last-user-is-root",
            "defaultConfiguration": {"level": "error"}}]}},
        "results": [result] if result else [],
        "invocations": [{"executionSuccessful": True,
                         "toolExecutionNotifications": syntax}],
    }]}


class TestDockerfileVariantCoverage(unittest.TestCase):
    """#3579: Dockerfile-like names are explicit Semgrep targets, and the
    capture says exactly how many still missed Dockerfile-rule analysis."""

    FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "dockerfile-variant")

    def _run(self, mutate=False, fail_dockerfile=False):
        seen = []

        def runner(cmd, **_kwargs):
            seen.append(list(cmd))
            explicit = ("--scan-unknown-extensions" in cmd
                        and "/src/Dockerfile.prod" in cmd)
            config = cmd[cmd.index("--config") + 1]
            docker_only = config == st.DOCKERFILE_RULES_CONFIG
            payload = json.dumps(_dockerfile_capture(
                explicit, cross_language=explicit and not docker_only)).encode()
            covered = explicit and docker_only
            if fail_dockerfile and covered:
                return _FakeResult(returncode=2, stdout=payload,
                                   stderr=b"Dockerfile pass failed")
            return _FakeResult(returncode=int(covered), stdout=payload, stderr=b"")

        with tempfile.TemporaryDirectory() as out:
            mutation = (unittest.mock.patch.object(
                st, "with_dockerfile_targets", side_effect=lambda _tool, cmd, _root: cmd)
                if mutate else contextlib.nullcontext())
            with mutation:
                written = run_tools.run_tools(
                    self.FIXTURE, ["semgrep"], out,
                    image="panopticon-tools", runner=runner)
            self.assertEqual(len(written), 1)
            with open(written[0], "rb") as fh:
                capture = json.load(fh)
            findings, dispositions = ingest.ingest_dir_detailed(out, "g1")
        return seen, capture, findings, dispositions["semgrep"]

    @staticmethod
    def _report(findings, disposition):
        dispositions = {"semgrep": disposition}
        return report.build_report(report.ReportInputs(
            run=report.RunConfig(
                target="t", fail_on="high", timestamp="2026-11-12T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=findings),
            plan=plan.PlanInputs(scout_requested=["semgrep"]),
            tools=tool_axis.ToolAxis(
                tools_ran=tool_axis.tools_ran_from_dispositions(dispositions),
                dispositions=dispositions)))

    def test_variant_gets_dockerfile_rules_and_keeps_its_original_path_and_line(self):
        seen, capture, findings, disposition = self._run()
        self.assertEqual(len(seen), 2)
        self.assertNotIn("--scan-unknown-extensions", seen[0])
        self.assertEqual(seen[0][seen[0].index("--config") + 1], "/opt/semgrep-rules")
        self.assertIn("--scan-unknown-extensions", seen[1])
        self.assertIn("/src/Dockerfile.prod", seen[1])
        self.assertNotIn("/src", seen[1])
        self.assertEqual(seen[1][seen[1].index("--config") + 1],
                         st.DOCKERFILE_RULES_CONFIG)
        self.assertEqual(len(capture["runs"]), 1,
                         "GitHub code scanning accepts one SARIF run per category")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["location"], {
            "file": "Dockerfile.prod", "line_start": 2})
        coverage = capture["runs"][0]["properties"][st.DOCKERFILE_STAMP_KEY]
        self.assertEqual(coverage, {
            "count": 1, "analyzed": 1, "unanalyzed": 0,
            "files": [], "complete": True})
        self.assertNotIn("file_coverage", disposition)
        notifications = [note for run in capture["runs"]
                         for invocation in run.get("invocations", [])
                         for note in invocation.get("toolExecutionNotifications", [])]
        self.assertEqual(notifications, [],
                         "Dockerfile pass retained cross-language parser noise")

    def test_failed_dockerfile_pass_retains_primary_and_discloses_the_gap(self):
        seen, capture, findings, disposition = self._run(fail_dockerfile=True)
        self.assertEqual(len(seen), 2)
        self.assertEqual(findings, [])
        self.assertEqual(
            capture["runs"][0]["properties"][st.DOCKERFILE_STAMP_KEY],
            {"count": 1, "analyzed": 0, "unanalyzed": 1,
             "files": ["Dockerfile.prod"], "complete": True})
        self.assertEqual(disposition["file_coverage"]["files"], [{
            "file": "Dockerfile.prod", "reason": "dockerfile_rules_skipped"}])

    def test_mutant_without_explicit_target_is_counted_and_named_in_coverage_note(self):
        seen, capture, findings, disposition = self._run(mutate=True)
        self.assertEqual(len(seen), 1)
        self.assertNotIn("--scan-unknown-extensions", seen[0])
        self.assertEqual(findings, [])
        coverage = capture["runs"][0]["properties"][st.DOCKERFILE_STAMP_KEY]
        self.assertEqual(coverage, {
            "count": 1, "analyzed": 0, "unanalyzed": 1,
            "files": ["Dockerfile.prod"], "complete": True})
        facts = disposition["file_coverage"]
        self.assertEqual((facts["dockerfile_unanalyzed"], facts["unparsed_files"]), (1, 1))
        self.assertEqual(facts["files"], [{
            "file": "Dockerfile.prod", "reason": "dockerfile_rules_skipped"}])
        published = self._report(findings, disposition)
        self.assertIn("1 Dockerfile-like file(s) received no Dockerfile rule analysis",
                      published["summary"]["coverage_note"])

    def test_all_ruled_name_shapes_are_found_including_plain_containerfile(self):
        with tempfile.TemporaryDirectory() as root:
            names = ("Dockerfile.prod", "api.Dockerfile", "job.dockerfile",
                     "Containerfile.dev", "Containerfile")
            for name in names:
                with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
                    fh.write("FROM busybox\n")
            launched = st.with_dockerfile_targets(
                "semgrep", list(TOOL_CMD["semgrep"]), root)
            listing = st.dockerfile_coverage(root, launched)
        for name in names:
            self.assertIn("/src/" + name, launched)
        self.assertEqual(listing, {
            "count": 5, "analyzed": 5, "unanalyzed": 0,
            "files": [], "complete": True})

    def test_merge_deduplicates_a_native_suffix_hit_and_sums_scan_counts(self):
        primary = _dockerfile_capture(True)
        extra = _dockerfile_capture(True)
        primary["runs"][0]["properties"] = {"panopticon_scanned_files": 2}
        extra["runs"][0]["properties"] = {"panopticon_scanned_files": 1}
        merged = json.loads(st.merge_sarif(
            json.dumps(primary).encode(), json.dumps(extra).encode()))
        self.assertEqual(len(merged["runs"]), 1)
        self.assertEqual(sum(len(run["results"]) for run in merged["runs"]), 1)
        self.assertEqual(merged["runs"][0]["properties"]["panopticon_scanned_files"], 3)
        self.assertEqual(len(merged["runs"][0]["invocations"]), 2)

    def test_merge_keeps_an_extra_rule_and_remaps_its_result_index(self):
        primary = _dockerfile_capture(False)
        extra = _dockerfile_capture(True)
        extra["runs"][0]["tool"]["driver"]["rules"] = [{
            "id": "dockerfile.extra", "defaultConfiguration": {"level": "warning"}}]
        extra["runs"][0]["results"][0]["ruleId"] = "dockerfile.extra"
        extra["runs"][0]["results"][0]["ruleIndex"] = 0
        merged = json.loads(st.merge_sarif(
            json.dumps(primary).encode(), json.dumps(extra).encode()))
        run = merged["runs"][0]
        self.assertEqual([rule["id"] for rule in run["tool"]["driver"]["rules"]], [
            "dockerfile.security.last-user-is-root.last-user-is-root",
            "dockerfile.extra",
        ])
        self.assertEqual(run["results"][0]["ruleIndex"], 1)
        self.assertEqual(len(run["invocations"]), 2)

    def test_merge_keeps_same_rule_and_path_hits_on_different_lines(self):
        primary = _dockerfile_capture(True)
        extra = _dockerfile_capture(True)
        extra["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "region"] = {"startLine": 3, "endLine": 3}
        merged = json.loads(st.merge_sarif(
            json.dumps(primary).encode(), json.dumps(extra).encode()))
        results = merged["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual({result["locations"][0]["physicalLocation"]["region"][
            "startLine"] for result in results}, {2, 3})

    def test_ambiguous_multiple_configs_skip_the_dockerfile_pass(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "Dockerfile.prod"), "w", encoding="utf-8") as fh:
                fh.write("FROM busybox\n")
            command = list(TOOL_CMD["semgrep"])
            command[1:1] = ["--config", "/opt/other-rules"]
            launched = st.with_dockerfile_targets("semgrep", command, root)
        self.assertEqual(launched, command)

    @unittest.skipIf(sys.platform == "win32", "POSIX symlinks")
    def test_excluded_and_symlinked_variants_are_not_reintroduced(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            os.makedirs(os.path.join(root, "ignored"))
            for rel in ("kept/Dockerfile.prod", "ignored/Dockerfile.prod"):
                path = os.path.join(root, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("FROM busybox\n")
            external = os.path.join(outside, "Dockerfile.prod")
            with open(external, "w", encoding="utf-8") as fh:
                fh.write("FROM busybox\n")
            os.symlink(external, os.path.join(root, "linked.Dockerfile"))
            cmd = list(TOOL_CMD["semgrep"])
            at = cmd.index("/src")
            cmd.insert(at, "--exclude=ignored/**")
            launched = st.with_dockerfile_targets("semgrep", cmd, root)
        self.assertIn("/src/kept/Dockerfile.prod", launched)
        self.assertNotIn("/src/ignored/Dockerfile.prod", launched)
        self.assertNotIn("/src/linked.Dockerfile", launched)

    def test_argv_budget_leaves_the_remainder_disclosed_not_silent(self):
        with tempfile.TemporaryDirectory() as root:
            for i in range(3):
                with open(os.path.join(root, "Dockerfile.%d" % i), "w",
                          encoding="utf-8") as fh:
                    fh.write("FROM busybox\n")
            with unittest.mock.patch.object(st, "MAX_DOCKERFILE_TARGETS", 1):
                launched = st.with_dockerfile_targets(
                    "semgrep", list(TOOL_CMD["semgrep"]), root)
                listing = st.dockerfile_coverage(root, launched)
        self.assertEqual(listing, {
            "count": 3, "analyzed": 1, "unanalyzed": 2,
            "files": ["Dockerfile.1", "Dockerfile.2"], "complete": True})

    def test_missing_malformed_and_incomplete_disclosure_stamps_fail_closed(self):
        good = {"count": 0, "analyzed": 0, "unanalyzed": 0,
                "files": [], "complete": True}
        cases = {
            "absent": None,
            "malformed": dict(good, count=1),
            "incomplete": dict(good, complete=False),
        }
        for state, listing in cases.items():
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tools:
                doc = _dockerfile_capture(False)
                properties = doc["runs"][0].setdefault("properties", {})
                properties[st.STAMP_KEY] = {
                    "limit": 1_000_000, "count": 0, "files": [], "complete": True}
                if listing is not None:
                    properties[st.DOCKERFILE_STAMP_KEY] = listing
                with open(os.path.join(tools, "semgrep.sarif"), "w", encoding="utf-8") as fh:
                    json.dump(doc, fh)
                _findings, dispositions = ingest.ingest_dir_detailed(tools, "g1")
            facts = dispositions["semgrep"]["file_coverage"]
            self.assertEqual(facts["dockerfile_listing"], state)
            self.assertEqual(facts["unlocated_records"], 1)


def _located(**over):
    """A well-formed result at `src/app.py:3`, with `over` replacing its fields."""
    result = {"ruleId": "python.rule", "level": "error", "message": {"text": "m"},
              "locations": [{"physicalLocation": {
                  "artifactLocation": {"uri": "/src/app.py"},
                  "region": {"startLine": 3, "endLine": 3}}}]}
    result.update(over)
    return result


def _region(region):
    return [{"physicalLocation": {"artifactLocation": {"uri": "/src/app.py"},
                                  "region": region}}]


#: #3713: the Gate 3 reviewer's shapes, and their neighbours. Each is one field of a
#: result's identity with a type no SARIF result gives it.
MALFORMED = {
    "message.text a list": _located(message={"text": ["m"]}),
    "message.text an object": _located(message={"text": {"a": 1}}),
    "message a list": _located(message=["m"]),
    "ruleId a list": _located(ruleId=["python.rule"]),
    "ruleId an object": _located(ruleId={"a": 1}),
    "startLine a list": _located(locations=_region({"startLine": [3]})),
    "startLine an object": _located(locations=_region({"startLine": {"a": 1}})),
    "endColumn a list": _located(locations=_region({"startLine": 3, "endColumn": [9]})),
    "region a list": _located(locations=_region([{"startLine": 3}])),
    "region an empty list": _located(locations=_region([])),      # read as {} before #3713
    "region a string": _located(locations=_region("3")),
}


class TestAMalformedResultNeverLeavesTheMerge(unittest.TestCase):
    """#3713. The result identity goes into a set. A wrong-typed `message.text`,
    `ruleId` or `startLine` raised `TypeError: unhashable` there, and a `region` that
    was not an object raised `AttributeError`. That left `merge_sarif`, then the
    capture, then `run_tools`: later scanners never launched and no manifest was
    written. The merge declines such a result now, in either pass."""

    @staticmethod
    def _doc(*results):
        doc = _dockerfile_capture(False)
        doc["runs"][0]["results"] = list(results)
        return json.dumps(doc).encode()

    def test_a_result_that_cannot_be_compared_is_said_to_be_so(self):
        for label, result in MALFORMED.items():
            with self.subTest(label):
                self.assertIs(st.UNMERGEABLE, st._result_identity(result))

    def test_a_well_formed_result_has_an_identity_and_one_with_no_location_has_none(self):
        self.assertEqual(("python.rule", "app.py", 3, None, 3, None, "m"),
                         st._result_identity(_located()))
        self.assertEqual(st._result_identity(_located()),
                         st._result_identity(_located(level="warning")))
        for label, result in (("no locations", _located(locations=[])),
                              ("locations an object", _located(locations={})),
                              ("no artifact", _located(locations=[{"physicalLocation": {}}])),
                              ("physicalLocation a list", _located(locations=[
                                  {"physicalLocation": []}])),
                              ("not an object", "result")):
            with self.subTest(label):
                self.assertIsNone(st._result_identity(result))
        # What can be compared still is: a missing region, a bare-string message, a
        # number where SARIF has an integer.
        self.assertEqual(("python.rule", "app.py", None, None, None, None, "m"),
                         st._result_identity(_located(locations=_region(None))))
        self.assertEqual("bare", st._result_identity(_located(message="bare"))[-1])
        self.assertEqual(3.0, st._result_identity(_located(
            locations=_region({"startLine": 3.0})))[2])
        self.assertIsNone(st._result_identity(_located(ruleId=None))[0])

    def test_the_merge_declines_it_in_either_pass_and_raises_nothing(self):
        good = self._doc(_located())
        docker = json.dumps(_dockerfile_capture(True)).encode()
        self.assertIsNotNone(st.merge_sarif(good, docker))
        for label, result in MALFORMED.items():
            with self.subTest(label, where="primary"):
                self.assertIsNone(st.merge_sarif(self._doc(_located(), result), docker))
            with self.subTest(label, where="second pass"):
                self.assertIsNone(st.merge_sarif(good, self._doc(result)))
            with self.subTest(label, where="a later run of the primary"):
                two = json.loads(good)
                two["runs"].append(json.loads(self._doc(result))["runs"][0])
                self.assertIsNone(st.merge_sarif(json.dumps(two).encode(), docker))

    def test_a_result_with_no_location_is_kept_and_not_deduplicated(self):
        nowhere = _located(locations=[])
        merged = json.loads(st.merge_sarif(self._doc(nowhere), self._doc(nowhere)))
        self.assertEqual(2, len(merged["runs"][0]["results"]))


class TestAMalformedResultNeverLeavesTheCapture(unittest.TestCase):
    """#3713, end to end through `run_tools.run_tools` over a tree with a Dockerfile
    variant, so Semgrep runs twice. Nothing raises, the scanner after Semgrep is
    launched, and a manifest can be written."""

    FIXTURE = TestDockerfileVariantCoverage.FIXTURE

    def _run(self, primary_extra=None, docker_extra=None, patch=None, fail_docker=False,
             docker_doc=None, preset=None):
        """`preset`: what Semgrep's own output carries, in both passes, at the key
        that says a merge was declined."""
        seen = []

        def runner(cmd, **_kwargs):
            seen.append(list(cmd))
            if "--config" not in cmd:                       # the scanner after Semgrep
                return _FakeResult(returncode=0, stdout=b'{"runs": []}', stderr=b"")
            docker_only = cmd[cmd.index("--config") + 1] == st.DOCKERFILE_RULES_CONFIG
            doc = _dockerfile_capture(docker_only)
            doc["runs"][0]["results"] += [r for r in [
                docker_extra if docker_only else primary_extra] if r is not None]
            if not docker_only:
                doc["runs"][0]["results"].insert(0, _located())
            elif docker_doc is not None:
                doc = docker_doc
            if preset is not None:
                doc["runs"][0].setdefault("properties", {})[st.MERGE_DECLINED_KEY] = preset
            return _FakeResult(returncode=2 if (docker_only and fail_docker) else int(docker_only),
                               stdout=json.dumps(doc).encode(), stderr=b"")

        err = io.StringIO()
        with tempfile.TemporaryDirectory() as out, contextlib.redirect_stderr(err), \
                (patch or contextlib.nullcontext()):
            written = run_tools.run_tools(self.FIXTURE, ["semgrep", "bandit"], out,
                                          image="panopticon-tools", runner=runner)
            manifest = tools_manifest.write_manifest(
                os.path.join(out, "tools-manifest.json"), ["semgrep", "bandit"], written)
            with open(os.path.join(out, "semgrep.sarif"), "rb") as fh:
                capture = json.load(fh)
            findings, dispositions = ingest.ingest_dir_detailed(out, "g1")
        return {"seen": seen, "manifest": manifest, "capture": capture, "findings": findings,
                "written": sorted(os.path.basename(path) for path in written),
                "disposition": dispositions["semgrep"], "stderr": err.getvalue()}

    def _launched_after(self, run):
        return [cmd for cmd in run["seen"] if "--config" not in cmd]

    def _assert_the_run_went_on(self, run):
        self.assertEqual(1, len(self._launched_after(run)), "the next scanner never launched")
        self.assertEqual(["bandit.sarif", "semgrep.sarif"], run["written"])
        self.assertEqual((["bandit", "semgrep"], []), (sorted(run["manifest"]["produced"]),
                                                       run["manifest"]["missing"]))

    def _assert_the_primary_was_kept_as_partial(self, run, reason,
                                                said="output could not be merged"):
        """The second pass's finding is not there, the variant reads unanalyzed, the
        capture says why in a fixed word, and the report does not certify on it."""
        properties = run["capture"]["runs"][0]["properties"]
        rules = [result.get("ruleId") for result in run["capture"]["runs"][0]["results"]
                 if isinstance(result.get("ruleId"), str)]
        self.assertIn("python.rule", rules)
        self.assertNotIn("dockerfile.security.last-user-is-root.last-user-is-root", rules)
        self.assertEqual({"count": 1, "analyzed": 0, "unanalyzed": 1,
                          "files": ["Dockerfile.prod"], "complete": True},
                         properties[st.DOCKERFILE_STAMP_KEY])
        self.assertEqual(reason, properties[st.MERGE_DECLINED_KEY])
        self.assertIn(reason, st.DECLINED_REASONS)
        self.assertEqual("partial", run["disposition"]["file_coverage"]["status"])
        self.assertIn({"file": "Dockerfile.prod", "reason": "dockerfile_rules_skipped"},
                      run["disposition"]["file_coverage"]["files"])
        self.assertIn("semgrep Dockerfile-pass %s" % said, run["stderr"])
        self.assertIn("; retaining primary capture with partial coverage", run["stderr"])
        # Normalized as synthesis normalizes a tool finding before it reports it.
        with contextlib.redirect_stderr(io.StringIO()):
            findings = [findings_mod.normalize_finding(f) for f in run["findings"]]
        summary = TestDockerfileVariantCoverage._report(
            findings, run["disposition"])["summary"]
        self.assertIs(False, summary["coverage_certified"])
        self.assertIn("semgrep", summary["coverage_note"])
        self.assertIn("1 Dockerfile-like file(s) received no Dockerfile rule analysis",
                      summary["coverage_note"])

    def test_two_well_formed_passes_merge(self):
        run = self._run()
        self._assert_the_run_went_on(run)
        properties = run["capture"]["runs"][0]["properties"]
        rules = [result["ruleId"] for result in run["capture"]["runs"][0]["results"]]
        self.assertEqual(["python.rule",
                          "dockerfile.security.last-user-is-root.last-user-is-root"], rules)
        self.assertEqual((1, 0), tuple(properties[st.DOCKERFILE_STAMP_KEY][key]
                                       for key in ("analyzed", "unanalyzed")))
        self.assertNotIn(st.MERGE_DECLINED_KEY, properties)
        self.assertNotIn("retaining primary capture", run["stderr"])
        self.assertNotIn("file_coverage", run["disposition"])

    def test_a_malformed_second_pass_keeps_the_primary_and_the_run_goes_on(self):
        for label, result in MALFORMED.items():
            with self.subTest(label):
                run = self._run(docker_extra=result)
                self._assert_the_run_went_on(run)
                self._assert_the_primary_was_kept_as_partial(
                    run, st.DECLINED_RESULT_MALFORMED)

    def test_a_malformed_primary_result_keeps_the_primary_too(self):
        """Ruling (a): the ingest takes this capture as it stands in a tree with no
        Dockerfile variant, so a tree with one must not fail on it."""
        for label, result in MALFORMED.items():
            with self.subTest(label):
                run = self._run(primary_extra=result)
                self._assert_the_run_went_on(run)
                self._assert_the_primary_was_kept_as_partial(
                    run, st.DECLINED_RESULT_MALFORMED)
                self.assertEqual("ok", run["disposition"]["status"])

    def test_each_way_a_second_pass_is_not_folded_in_has_its_own_word(self):
        patch = unittest.mock.patch
        cases = (
            ("the pass failed", dict(fail_docker=True), st.DECLINED_PASS_FAILED,
             "semgrep Dockerfile-only pass failed"),
            ("its output could not be read back", dict(patch=patch.object(
                run_tools, "read_capped_report", side_effect=self._unreadable_second())),
             st.DECLINED_PASS_UNREADABLE, None),
            ("it is not a SARIF document that folds", dict(docker_doc={"runs": "none"}),
             st.DECLINED_NOT_MERGEABLE, None),
            ("the merged capture is too large", dict(patch=patch.object(
                run_tools, "_fold_dockerfile_pass", side_effect=self._fold_under_a_small_limit)),
             st.DECLINED_OVER_LIMIT, "semgrep Dockerfile-pass merge exceeded the output limit"),
            ("the merge raised", dict(patch=patch.object(
                st, "merge_sarif_detailed", side_effect=RuntimeError("unforeseen"))),
             st.DECLINED_MERGE_ERROR, "semgrep Dockerfile-pass merge failed (RuntimeError)"),
            ("the merge returned what cannot be stamped", dict(patch=patch.object(
                st, "merge_sarif_detailed", return_value=(object(), None))),
             st.DECLINED_MERGE_ERROR, "semgrep Dockerfile-pass merge failed (TypeError)"),
        )
        seen = set()
        for label, how, reason, line in cases:
            with self.subTest(label):
                run = self._run(**how)
                self._assert_the_run_went_on(run)
                properties = run["capture"]["runs"][0]["properties"]
                self.assertEqual(reason, properties[st.MERGE_DECLINED_KEY])
                self.assertEqual(1, properties[st.DOCKERFILE_STAMP_KEY]["unanalyzed"])
                self.assertIn(line or "semgrep Dockerfile-pass output could not be merged",
                              run["stderr"])
                self.assertIn("; retaining primary capture with partial coverage",
                              run["stderr"])
                seen.add(reason)
        self.assertEqual(set(st.DECLINED_REASONS) - {st.DECLINED_RESULT_MALFORMED}, seen)

    @staticmethod
    def _fold_under_a_small_limit(*args, real=run_tools._fold_dockerfile_pass):
        """The real fold, with the output limit below any merged capture while it runs."""
        with unittest.mock.patch.object(run_tools.tool_capture, "MAX_TOOL_OUTPUT_BYTES", 10):
            return real(*args)

    @staticmethod
    def _unreadable_second():
        """`read_capped_report`, but the second capture it is asked for reads as None."""
        real, calls = run_tools.read_capped_report, []

        def read(path, **kwargs):
            calls.append(path)
            return None if os.path.basename(path) == "dockerfile.sarif" else real(path, **kwargs)
        return read

    def test_only_a_declined_merge_carries_the_word_whatever_the_scanner_wrote_there(self):
        """#3718 N1. Both passes come back with the key already set, to scanner text. A
        merge that went through says nothing was declined, and a declined one says our
        fixed word."""
        said = "Syntax error at /src/app.py"
        merged = self._run(preset=said)["capture"]["runs"][0]
        self.assertEqual(2, len(merged["results"]))
        self.assertNotIn(st.MERGE_DECLINED_KEY, merged["properties"])
        self.assertNotIn(said, json.dumps(merged))
        declined = self._run(preset=said, fail_docker=True)["capture"]["runs"][0]
        self.assertEqual(st.DECLINED_PASS_FAILED, declined["properties"][st.MERGE_DECLINED_KEY])
        self.assertNotIn(said, json.dumps(declined))
        # The stamp every capture passes through is what drops it, one pass or two.
        carried = json.dumps({"runs": [{"properties": {st.MERGE_DECLINED_KEY: said, "other": 1},
                                        "results": []}]}).encode()
        for dockerfile_listing in (None, {"count": 0}):
            stamped = json.loads(st.stamp(carried, [], dockerfile_listing))
            self.assertNotIn(st.MERGE_DECLINED_KEY, stamped["runs"][0]["properties"])
            self.assertEqual(1, stamped["runs"][0]["properties"]["other"])

    def test_a_note_that_would_take_the_capture_over_the_limit_is_left_off(self):
        """#3718 N2. The kept primary is published bare, still partial, when the reason
        word would put it over the output limit."""
        noted = self._run(fail_docker=True)["capture"]
        bare = json.loads(json.dumps(noted))
        del bare["runs"][0]["properties"][st.MERGE_DECLINED_KEY]
        limit = len(json.dumps(bare).encode("utf-8"))
        self.assertLess(limit, len(json.dumps(noted).encode("utf-8")))
        run = self._run(fail_docker=True, patch=unittest.mock.patch.object(
            run_tools.tool_capture, "MAX_TOOL_OUTPUT_BYTES", limit))
        self._assert_the_run_went_on(run)
        self.assertEqual(bare, run["capture"])
        self.assertEqual(1, run["capture"]["runs"][0]["properties"][
            st.DOCKERFILE_STAMP_KEY]["unanalyzed"])
        self.assertIn("; retaining primary capture with partial coverage", run["stderr"])
        # One byte more room, and the word is there.
        run = self._run(fail_docker=True, patch=unittest.mock.patch.object(
            run_tools.tool_capture, "MAX_TOOL_OUTPUT_BYTES",
            len(json.dumps(noted).encode("utf-8"))))
        self.assertEqual(noted, run["capture"])

    def test_only_a_fixed_word_is_ever_stamped(self):
        primary = json.dumps(_dockerfile_capture(False)).encode()
        for reason in st.DECLINED_REASONS:
            noted = json.loads(st.note_declined(primary, reason))
            self.assertEqual(reason, noted["runs"][0]["properties"][st.MERGE_DECLINED_KEY])
        for reason in ("Syntax error at /src/x", None, "", 7, ["result_malformed"]):
            self.assertEqual(primary, st.note_declined(primary, reason))
        for payload in (b"not json", b"[]", b'{"runs": []}', b'{"runs": ["x"]}'):
            self.assertEqual(payload, st.note_declined(payload, st.DECLINED_NOT_MERGEABLE))
        kept = json.loads(st.note_declined(
            b'{"runs": [{"properties": {"other": 1}, "results": []}]}', st.DECLINED_MERGE_ERROR))
        self.assertEqual({"other": 1, st.MERGE_DECLINED_KEY: "merge_error"},
                         kept["runs"][0]["properties"])


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

    def _sized(self, names):
        with tempfile.TemporaryDirectory() as root:
            for name in names:
                os.makedirs(os.path.dirname(os.path.join(root, name)) or root, exist_ok=True)
                with open(os.path.join(root, name), "wb") as fh:
                    fh.write(b"\x89PNG" + b"\0" * 1_100_000)
            payload = st.stamper("semgrep", root, TOOL_CMD["semgrep"])(json.dumps(_canary_capture()).encode())
        findings, disposition, _ = self._ingest(payload)
        return disposition["file_coverage"], self._report(findings, disposition)

    def test_a_size_skipped_image_alone_certifies_and_is_disclosed(self):
        # #3283: httpie's animation.gif, strix's two screenshots.
        facts, published = self._sized(["docs/a.gif", ".github/s.png", "docs/images/s.png"])
        self.assertEqual(published["meta"]["coverage"]["tools_file_partial"], {"semgrep": facts})
        self.assertTrue(published["summary"]["coverage_certified"])
        self.assertEqual("3 asset file(s) over the semgrep size limit were not scanned "
                         "(not counted against certification)", published["summary"]["coverage_note"])

    def test_a_size_skipped_code_or_json_file_still_decertifies(self):
        # zincsearch's generated .go; listmonk's and tantivy's .json (D1: a target
        # can pad a security-relevant JSON past the limit, not a PNG).
        for names in (["pkg/dict.go"], ["frontend/config.json"], ["app.py"], ["docs/a.png", "pkg/dict.go"]):
            with self.subTest(names=names):
                _, published = self._sized(names)
                self.assertFalse(published["summary"]["coverage_certified"])
                self.assertIn("partial scanner file coverage: semgrep", published["summary"]["coverage_note"])
                self.assertNotIn("asset file(s)", published["summary"]["coverage_note"])

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
                doc["runs"][0]["properties"] = {st.DOCKERFILE_STAMP_KEY: {
                    "count": 0, "analyzed": 0, "unanalyzed": 0,
                    "files": [], "complete": True}}
                if listing is not None:
                    doc["runs"][0]["properties"][st.STAMP_KEY] = listing
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

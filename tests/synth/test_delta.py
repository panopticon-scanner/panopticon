"""Tests for scripts.synth.delta: diff hunks and on-diff classification.
"""
import contextlib
import copy
import io
import os
import json
import tempfile
import types
import unittest

import scripts.evidence as evidence_mod
import scripts.synth.delta as delta_mod
import scripts.synth.grading as grading_mod
import scripts.synth.verdicts as verdicts_mod

from tests.synth.helpers import _cli_args


class TestLoadDiffHunks(unittest.TestCase):
    """#449 Task 7: the orchestrator's diff-hunks.json artifact, tuple-ified."""

    def test_loads_and_converts_ranges_to_tuples(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "base": "main",
                        "base_source": "explicit",
                        "diff_context": 5,
                        "files_changed": 1,
                        "hunks": {"a.py": [[10, 12], [20, 20]]},
                    },
                    fh,
                )
            data = delta_mod.load_diff_hunks(path)
            self.assertEqual(data["base"], "main")
            self.assertEqual(data["hunks"], {"a.py": [(10, 12), (20, 20)]})

    def test_missing_file_returns_empty_dict(self):
        self.assertEqual(delta_mod.load_diff_hunks("/does/not/exist/diff-hunks.json"), {})

    def test_malformed_json_returns_empty_dict(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            self.assertEqual(delta_mod.load_diff_hunks(path), {})

    def test_non_dict_payload_returns_empty_dict(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(["not", "a", "dict"], fh)
            self.assertEqual(delta_mod.load_diff_hunks(path), {})

    def test_missing_hunks_key_defaults_to_empty(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"base": "main"}, fh)
            data = delta_mod.load_diff_hunks(path)
            self.assertEqual(data["hunks"], {})

class TestClassifyFindings(unittest.TestCase):
    """#449 Task 7: classify_findings stamps f['delta'] via diff_map.classify."""

    def test_stamps_delta_on_each_finding(self):
        findings = [
            {"id": "A-1", "location": {"file": "a.py", "line_start": 11}},
            {"id": "A-2", "location": {"file": "a.py", "line_start": 90}},
        ]
        hunks = {"a.py": [(10, 12)]}
        delta_mod.classify_findings(findings, hunks, 5)
        self.assertTrue(findings[0]["delta"]["on_diff"])
        self.assertFalse(findings[1]["delta"]["on_diff"])
        self.assertIn("hunk", findings[0]["delta"])
        self.assertIn("distance", findings[0]["delta"])

class DeltaLoaderTest(unittest.TestCase):
    def test_from_args_without_hunks_is_inactive(self):
        dc = delta_mod.DeltaContext.from_args(_cli_args(diff_context=3))
        self.assertIsNone(dc.diff_hunks)
        self.assertEqual(dc.diff_context, 3)
        self.assertFalse(dc.active)

    def test_from_args_loads_hunks_and_warns_without_fail_on(self):
        with tempfile.TemporaryDirectory() as d:
            hp = os.path.join(d, "diff-hunks.json")
            with open(hp, "w") as fh:
                json.dump({"base": "main", "hunks": {"a.py": [[1, 5]]}}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                dc = delta_mod.DeltaContext.from_args(_cli_args(diff_hunks=hp))
            self.assertTrue(dc.active)
            self.assertIn("DELTA REVIEW WITH Gate: OFF", err.getvalue())
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                delta_mod.DeltaContext.from_args(_cli_args(diff_hunks=hp, fail_on="high"))
            self.assertEqual(err.getvalue(), "")

class TestLoadDiffHunksReport(unittest.TestCase):
    """ARC-2340795244 (#1783): the loader is total, so every tolerance it
    applies has to be RECORDED. `load_diff_hunks` keeps its old contract for
    callers; the report form says what the payload cost."""

    def _write(self, d, payload, raw=None):
        path = os.path.join(d, "diff-hunks.json")
        with open(path, "w", encoding="utf-8") as fh:
            if raw is not None:
                fh.write(raw)
            else:
                json.dump(payload, fh)
        return path

    def test_unreadable_file_is_reported(self):
        data, report = delta_mod.load_diff_hunks_report("/does/not/exist/diff-hunks.json")
        self.assertEqual(data, {})
        self.assertEqual(report.payload_malformed, "unreadable")
        self.assertEqual((report.files, report.ranges, report.ranges_dropped), (0, 0, 0))
        self.assertEqual(report.paths_dropped, 0)

    def test_malformed_json_is_reported_as_unreadable(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, None, raw="{not json")
            data, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(data, {})
            self.assertEqual(report.payload_malformed, "unreadable")

    def test_non_dict_payload_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, ["not", "a", "dict"])
            data, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(data, {})
            self.assertEqual(report.payload_malformed, "not an object")

    def test_non_dict_hunks_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main", "hunks": "nope"})
            data, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(data["hunks"], {})
            self.assertEqual(report.payload_malformed, "hunks not an object")
            self.assertEqual((report.files, report.ranges), (0, 0))

    def test_missing_hunks_key_is_reported_the_same_way(self):
        # discovery.write_diff_hunks always emits a `hunks` key, so an artifact
        # without one is as broken as one carrying a non-object there.
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main"})
            _, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(report.payload_malformed, "hunks not an object")

    def test_dropped_ranges_are_counted(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main",
                                   "hunks": {"a.py": [[1, 5], [2], "x", [3, "4"]],
                                             "b.py": "not a list"}})
            data, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(data["hunks"], {"a.py": [(1, 5)]})
            self.assertIsNone(report.payload_malformed)
            self.assertEqual((report.files, report.ranges), (1, 1))
            # Three malformed ranges under a.py. b.py is a LOST PATH, and #2169
            # counts it apart: one lost path is not one lost range, and the
            # difference is what it costs -- every finding in b.py classifies
            # off-diff, where a dropped range only narrows the map.
            self.assertEqual(report.ranges_dropped, 3)
            self.assertEqual(report.paths_dropped, 1)

    def test_a_lost_path_is_counted_apart_from_a_lost_range(self):
        # #2169: the two losses were indistinguishable, so a report saying
        # `ranges_dropped: 2` could mean two narrowed files or one file gone.
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main",
                                   "hunks": {"a.py": [[1, 5], [2]],
                                             "c.py": {"not": "a list"}}})
            data, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(data["hunks"], {"a.py": [(1, 5)]})
            self.assertEqual(report.ranges_dropped, 1)
            self.assertEqual(report.paths_dropped, 1)

    def test_a_named_path_with_no_ranges_is_counted_on_its_own(self):
        # #2381: `{"c.py": []}` is WELL FORMED -- `diff_map.parse` emits it on
        # purpose for a file the diff changed without ADDING a line (a pure
        # deletion, a binary or mode-only change, a 100%-similarity rename) -- so
        # nothing was dropped and c.py stays in the map. What it costs is
        # `diff_map.classify`'s changed-file fail-open: every finding in c.py
        # classifies ON-diff. None of the other three counters can see that, and a
        # truncated map looks exactly the same, so it gets a counter of its own.
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main",
                                   "hunks": {"a.py": [[1, 5]], "c.py": []}})
            data, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(data["hunks"], {"a.py": [(1, 5)], "c.py": []})
            self.assertEqual(report.paths_without_ranges, 1)
            # #2386: c.py's list ARRIVED empty, so it is not in the broken subset.
            self.assertEqual(report.paths_emptied_by_drops, 0)
            self.assertEqual(report.paths_dropped, 0)
            self.assertEqual(report.ranges_dropped, 0)
            self.assertEqual((report.files, report.ranges), (2, 1))

    def test_a_path_whose_every_range_was_malformed_counts_in_both(self):
        # #2381: two DIFFERENT facts about b.py and a reader needs both.
        # `ranges_dropped` says the loader discarded something, so the artifact is
        # broken; `paths_without_ranges` says what the surviving map now DOES --
        # b.py is still named, so every finding in it classifies on-diff. Folding
        # either into the other would publish a broken artifact as a legitimate
        # deletion-only change, or a fail-open file as a merely narrower one.
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main",
                                   "hunks": {"a.py": [[1, 5], [2]], "b.py": ["x"]}})
            _, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(report.ranges_dropped, 2)
            self.assertEqual(report.paths_without_ranges, 1)
            # #2386: and b.py is the SUBSET a broken artifact produced -- the one
            # rangeless path here whose list did not arrive that way.
            self.assertEqual(report.paths_emptied_by_drops, 1)
            self.assertEqual(report.paths_dropped, 0)

    def test_paths_emptied_by_drops_is_the_broken_subset(self):
        # #2386: one map, both sub-populations. b.py arrived `[]` (legitimate: a
        # deletion-only, binary, mode-only or same-content rename change) and c.py
        # was EMPTIED by the range loop (a broken artifact). Before the split they
        # were one number, so a gate rule reading it could not tell a truncated
        # map from a deletion-only PR; `ranges_dropped` disambiguates only while
        # the two populations do not co-occur, which is exactly this map.
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main",
                                   "hunks": {"a.py": [[1, 5]], "b.py": [],
                                             "c.py": ["x"]}})
            data, report = delta_mod.load_diff_hunks_report(path)
            self.assertEqual(report.paths_without_ranges, 2)
            self.assertEqual(report.paths_emptied_by_drops, 1)
            self.assertEqual(report.ranges_dropped, 1)
            self.assertEqual(report.paths_dropped, 0)
            # Neither rangeless path LEFT the map: both still classify on-diff,
            # which is what the split does not change.
            self.assertEqual(data["hunks"],
                             {"a.py": [(1, 5)], "b.py": [], "c.py": []})

    def test_a_well_formed_payload_reports_nothing_dropped(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main",
                                   "hunks": {"a.py": [[1, 5], [9, 9]], "b.py": [[2, 3]]}})
            _, report = delta_mod.load_diff_hunks_report(path)
            self.assertIsNone(report.payload_malformed)
            self.assertEqual((report.files, report.ranges, report.ranges_dropped), (2, 3, 0))
            self.assertEqual(report.paths_dropped, 0)
            self.assertEqual(report.paths_without_ranges, 0)
            self.assertEqual(report.paths_emptied_by_drops, 0)

    def test_load_diff_hunks_returns_the_same_data(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, {"base": "main", "hunks": {"a.py": [[1, 5]]}})
            self.assertEqual(delta_mod.load_diff_hunks(path),
                             delta_mod.load_diff_hunks_report(path)[0])

class TestDeltaLoadDisclosure(unittest.TestCase):
    """ARC-2340795244 (#1783): from_args says on stderr what the artifact cost,
    in the #957 register. A green gate over a change with findings is the
    failure this disclosure exists to make visible."""

    NOTICE_957 = ("synthesize: DELTA REVIEW WITH Gate: OFF -- no --fail-on was "
                  "passed, so nothing can gate this change; pass --fail-on "
                  "{critical,high,medium,low} to arm the gate")

    def _from_args(self, payload, raw=None, **kw):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                if raw is not None:
                    fh.write(raw)
                else:
                    json.dump(payload, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                ctx = delta_mod.DeltaContext.from_args(
                    _cli_args(diff_hunks=path, fail_on="high", **kw))
            return ctx, err.getvalue(), path

    def test_the_957_notice_is_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"base": "main", "hunks": {"a.py": [[1, 5]]}}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                delta_mod.DeltaContext.from_args(_cli_args(diff_hunks=path))
            self.assertEqual(err.getvalue(), self.NOTICE_957 + "\n")

    def test_the_context_carries_the_load_report(self):
        ctx, err, _ = self._from_args({"base": "main", "hunks": {"a.py": [[1, 5]]}})
        self.assertEqual(err, "")
        self.assertEqual((ctx.report.files, ctx.report.ranges), (1, 1))
        self.assertIsNone(ctx.report.payload_malformed)

    def test_an_unreadable_artifact_is_disclosed_with_its_path(self):
        ctx, err, path = self._from_args(None, raw="{not json")
        self.assertIn("DELTA ARTIFACT MALFORMED", err)
        self.assertIn("unreadable", err)
        self.assertIn(path, err)
        self.assertFalse(ctx.active)

    def test_a_non_object_hunks_map_is_disclosed(self):
        _, err, _ = self._from_args({"base": "main", "hunks": 7})
        self.assertIn("DELTA ARTIFACT MALFORMED", err)
        self.assertIn("hunks not an object", err)

    def test_an_active_delta_with_zero_hunks_is_disclosed(self):
        ctx, err, path = self._from_args({"base": "main", "hunks": {}})
        self.assertTrue(ctx.active)
        self.assertIn("DELTA REVIEW WITH ZERO HUNKS", err)
        self.assertIn("off-diff", err)
        self.assertIn("on-diff", err)      # the gate scope that has nothing to fail on
        self.assertIn("empty change", err)
        self.assertIn("regenerate", err)
        self.assertIn(path, err)

    def test_an_inactive_payload_gets_no_zero_hunk_warning(self):
        # No base: the review degrades to a full-repo one, which is the WIDER
        # gate. Nothing is scoped away, so there is nothing to warn about.
        _, err, _ = self._from_args({"hunks": {}})
        self.assertNotIn("ZERO HUNKS", err)

    def test_a_populated_delta_gets_no_zero_hunk_warning(self):
        _, err, _ = self._from_args({"base": "main", "hunks": {"a.py": [[1, 5]]}})
        self.assertEqual(err, "")

    def test_dropped_ranges_are_disclosed_as_a_count(self):
        _, err, _ = self._from_args({"base": "main",
                                     "hunks": {"a.py": [[1, 5], [2], "x"]}})
        self.assertIn("2 malformed hunk range(s) dropped", err)
        self.assertNotIn("ZERO HUNKS", err)

    CONSEQUENCE = (" -- a dropped path leaves the map, so every finding in that "
                   "file classifies off-diff.")

    def _artifact_line(self, err):
        lines = [ln for ln in err.splitlines() if "DELTA ARTIFACT:" in ln]
        self.assertEqual(len(lines), 1, err)
        return lines[0]

    def test_a_dropped_path_is_disclosed_as_its_own_count(self):
        # #2169: a lost PATH is the more expensive loss -- every finding in that
        # file classifies off-diff -- so it gets its own number rather than
        # being added to the malformed-range tally.
        #
        # The WHOLE line, not a substring (#2169 review, F1): the consequence
        # clause first lived inside the count phrase, which left the line reading
        # "...classifies off-diff dropped from /...", and two substring
        # assertions could not see the missing verb.
        _, err, path = self._from_args({"base": "main",
                                        "hunks": {"a.py": [[1, 5]], "b.py": 7}})
        self.assertEqual(self._artifact_line(err),
                         "synthesize: DELTA ARTIFACT: 1 whole path(s) dropped "
                         "from %s%s" % (path, self.CONSEQUENCE))
        self.assertNotIn("malformed hunk range(s)", err)

    def test_both_losses_are_disclosed_on_one_line(self):
        # One line, both numbers: two lines for one artifact read as two
        # problems, and the operator has to reconcile them. Exact string.
        _, err, path = self._from_args({"base": "main",
                                        "hunks": {"a.py": [[1, 5], [2]], "b.py": 7}})
        self.assertEqual(self._artifact_line(err),
                         "synthesize: DELTA ARTIFACT: 1 malformed hunk range(s) "
                         "and 1 whole path(s) dropped from %s%s"
                         % (path, self.CONSEQUENCE))

    def test_only_a_dropped_path_gets_the_consequence_clause(self):
        # A dropped RANGE narrows a file it leaves in the map, so the clause
        # would be false for it -- and the pre-#2169 line stays byte-identical.
        _, err, path = self._from_args({"base": "main",
                                        "hunks": {"a.py": [[1, 5], [2], "x"]}})
        self.assertEqual(self._artifact_line(err),
                         "synthesize: DELTA ARTIFACT: 2 malformed hunk range(s) "
                         "dropped from %s" % path)

    # #2386 widened the two `%s` in the middle: the paths themselves, and the
    # broken-subset clause. Order: count, names, artifact path, subset clause.
    RANGELESS = ("synthesize: DELTA ARTIFACT: %d named path(s)%s in %s carry no "
                 "range -- every finding in those file(s) classifies on-diff "
                 "(the changed-file fail-open), so a --gate-scope on-diff gate "
                 "admits them on the artifact's word: a deletion-only, binary, "
                 "mode-only or same-content rename change looks exactly like a "
                 "truncated map from here%s.")

    def _rangeless_line(self, err):
        """The #2381 line, isolated. Not `_artifact_line` above: both lines open
        `DELTA ARTIFACT:`, and a map that dropped something AND names a rangeless
        path prints both -- they are different facts about one read."""
        lines = [ln for ln in err.splitlines() if "carry no range" in ln]
        self.assertEqual(len(lines), 1, err)
        return lines[0]

    def test_a_named_path_with_no_range_is_disclosed_though_the_map_is_not_empty(self):
        # #2381, the ONLY fail-open shape in this family: c.py is named with no
        # range, so every finding in it classifies ON-diff and a --gate-scope
        # on-diff gate judges it as if the diff had touched it. The ZERO HUNKS arm
        # below cannot say so -- it needs `ranges == 0` across the WHOLE map, and
        # a.py's one real range silences it -- which is why this line exists.
        _, err, path = self._from_args({"base": "main",
                                        "hunks": {"a.py": [[1, 5]], "c.py": []}})
        self.assertEqual(self._rangeless_line(err),
                         self.RANGELESS % (1, " ('c.py')", path, ""))
        self.assertNotIn("DELTA REVIEW WITH ZERO HUNKS", err)

    EMPTIED = ("; %d of them emptied by dropped ranges (a broken artifact, not "
               "a change shape)")

    def test_the_rangeless_paths_are_named_on_stderr(self):
        # #2386: the counter said HOW MANY files the gate admitted on the
        # artifact's word and never WHICH, so an operator had to regenerate the
        # artifact to find out. The names come from the cleaned map, not from a
        # new `HunksLoad` field, so nothing else has to publish them.
        #
        # `%r`, because these are artifact-supplied strings reaching a terminal
        # (the #2379 register): a path carrying a newline must not break the line
        # it is disclosed on, and the escaped form is what a reader can paste.
        _, err, path = self._from_args(
            {"base": "main", "hunks": {"a.py": [[1, 5]], "b.py": [],
                                       "evil\n.py": ["x"]}})
        self.assertEqual(self._rangeless_line(err),
                         self.RANGELESS % (2, " ('b.py', 'evil\\n.py')", path,
                                           self.EMPTIED % 1))
        self.assertIn("'evil\\n.py'", err)
        self.assertNotIn("'evil\n", err)          # not the raw newline

    def test_a_legitimately_rangeless_path_gets_no_emptied_clause(self):
        # The whole point of the split: b.py arrived `[]`, which is what
        # `diff_map.parse` emits for a deletion-only change, so the line must not
        # suggest a broken artifact. Nothing was dropped, so the clause is absent.
        _, err, path = self._from_args({"base": "main",
                                        "hunks": {"a.py": [[1, 5]], "b.py": []}})
        self.assertEqual(self._rangeless_line(err),
                         self.RANGELESS % (1, " ('b.py')", path, ""))
        self.assertNotIn("emptied by dropped ranges", err)

    def test_the_named_path_list_stops_at_ten_and_says_how_many_more(self):
        # A wholly truncated map can name hundreds; the line stays readable and
        # still says the count in full, so the cap cannot be mistaken for the
        # number of rangeless paths. `a.py` keeps one real range, else the
        # ZERO HUNKS arm takes this read instead.
        hunks = {"a.py": [[1, 5]]}
        hunks.update({"f%02d.py" % i: [] for i in range(12)})
        _, err, path = self._from_args({"base": "main", "hunks": hunks})
        named = ", ".join("'f%02d.py'" % i for i in range(10))
        self.assertEqual(self._rangeless_line(err),
                         self.RANGELESS % (12, " (%s, +2 more)" % named, path, ""))
        self.assertNotIn("'f10.py'", err)

    def test_a_wholly_rangeless_map_keeps_the_zero_hunk_line_and_only_that(self):
        # The whole-map case already has its own arm, which says the same thing in
        # more detail. Printing both for one read has the operator reconciling
        # what looks like two problems (#2169's lesson, F1).
        _, err, _ = self._from_args({"base": "main", "hunks": {"a.py": []}})
        self.assertIn("DELTA REVIEW WITH ZERO HUNKS", err)
        self.assertNotIn("carry no range", err)

    def test_a_map_giving_every_named_path_a_range_discloses_nothing(self):
        _, err, _ = self._from_args({"base": "main",
                                     "hunks": {"a.py": [[1, 5]], "b.py": [[2, 3]]}})
        self.assertEqual(err, "")

    def test_an_inactive_read_does_not_claim_a_rangeless_path_classified(self):
        # #2381 review, F1: with no `base` nothing classifies and the gate keeps
        # its wider, fail-closed scope, so a line saying findings "classify
        # on-diff" would describe a run that never happened. No producer writes
        # this shape (`write_diff_hunks` empties the map without a base); only a
        # hand-edited artifact reaches it, and it must not be over-warned.
        ctx, err, _ = self._from_args({"hunks": {"a.py": [[1, 5]], "c.py": []}})
        self.assertFalse(ctx.active)
        self.assertNotIn("carry no range", err)

    def test_an_inactive_read_does_not_claim_a_dropped_path_classified(self):
        # The sibling line's consequence clause ("classifies off-diff") is the
        # same claim about the same absent classification; both lines now need
        # an active delta, so they cannot disagree about that question.
        ctx, err, _ = self._from_args({"hunks": {"a.py": [[1, 5], [2]], "b.py": 7}})
        self.assertFalse(ctx.active)
        self.assertNotIn("dropped from", err)

    def test_a_named_file_with_no_range_is_disclosed_as_the_fail_open_shape(self):
        # `diff_map.classify` fails OPEN on BOTH its arms for a file the map
        # NAMES but gives no range: an unlined finding there never reaches the
        # range loop, and a lined one falls through it. So "zero ranges" has
        # two consequences, the warning has to say which one this artifact
        # bought, and it must not claim every OTHER finding is off-diff.
        _, err, _ = self._from_args({"base": "main", "hunks": {"a.py": []}})
        self.assertIn("DELTA REVIEW WITH ZERO HUNKS", err)
        self.assertIn("names 1 file(s)", err)
        self.assertIn("fails OPEN", err)
        self.assertIn("any finding without a line, and any lined one", err)
        self.assertIn("findings elsewhere classify off-diff", err)
        self.assertNotIn("every other finding classifies off-diff", err)

    def test_an_empty_map_is_disclosed_as_matching_nothing(self):
        _, err, _ = self._from_args({"base": "main", "hunks": {}})
        self.assertIn("the map is empty", err)
        self.assertNotIn("fails OPEN", err)

    def test_a_loader_drop_is_named_as_the_cause_not_called_unknown(self):
        # #2169 review, F2: `_disclose_load` branched on `payload_malformed`
        # alone, so a map emptied by a dropped PATH was called indistinguishable
        # from an empty change on one line while `zero_hunk_gate_gap` named the
        # drop as the cause on another -- for the same read. Same three arms now.
        _, err, _ = self._from_args({"base": "main", "hunks": {"a.py": 7}})
        self.assertIn("DELTA REVIEW WITH ZERO HUNKS", err)
        self.assertIn("The map is empty of ranges because 1 whole path(s) were dropped "
                      "for carrying no list of ranges, not because the change "
                      "was", err)
        self.assertNotIn("look identical", err)
        self.assertNotIn("was rejected", err)

    def test_dropped_ranges_are_named_as_the_cause_too(self):
        _, err, _ = self._from_args({"base": "main", "hunks": {"a.py": [[1]]}})
        self.assertIn("The map is empty of ranges because 1 hunk range(s) were malformed "
                      "and dropped, not because the change was", err)
        self.assertNotIn("look identical", err)

    def test_the_unknown_arm_survives_for_a_genuinely_empty_map(self):
        # Nothing rejected and nothing dropped: the operator really cannot tell
        # an empty change from a broken artifact, and the third arm says so.
        _, err, _ = self._from_args({"base": "main", "hunks": {}})
        self.assertIn("An empty change and a broken artifact look identical "
                      "from here", err)
        self.assertNotIn("was rejected", err)
        self.assertNotIn("were dropped", err)

    def test_a_rejected_payload_is_not_called_indistinguishable(self):
        # The reason is already on stderr one line up, so this artifact is
        # known-broken: the empty-change-or-broken-artifact ambiguity does not
        # hold, and the warning says what emptied the map instead.
        _, err, _ = self._from_args({"base": "main", "hunks": 7})
        self.assertIn("DELTA REVIEW WITH ZERO HUNKS", err)
        self.assertIn("because the payload was rejected", err)
        self.assertIn("hunks not an object", err)
        self.assertNotIn("look identical", err)

    def test_an_unrejected_empty_map_keeps_the_ambiguity_clause(self):
        # Nothing was rejected here, so the operator genuinely cannot tell the
        # two apart from the report alone.
        _, err, _ = self._from_args({"base": "main", "hunks": {}})
        self.assertIn("look identical from here", err)
        self.assertNotIn("was rejected", err)

    def test_no_disclosure_line_names_the_artifact_path_twice(self):
        _, err, path = self._from_args({"base": "main", "hunks": 7})
        self.assertTrue(err)
        for line in err.splitlines():
            self.assertLessEqual(line.count(path), 1, line)


class TestZeroHunkGateGap(unittest.TestCase):
    """#2178 (owner ruling 2026-09-27): the gate consequence of the shape #1783
    only disclosed. A based artifact with no diff ranges leaves a `--gate-scope
    on-diff` gate scoping against something that is not a measured diff, so a
    run carrying findings the gate would have judged must not read PASS (#2222
    narrowed that population from any active finding; `TestTheZeroHunkPopulation`
    below is where it is decided). The reason string this function returns is
    what `certify` puts in `coverage_note`; None means there is no gap, and every
    arm below is one of the four conditions."""

    def _ctx(self, payload):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                return delta_mod.DeltaContext.from_args(
                    _cli_args(diff_hunks=path, fail_on="high"))

    def test_an_empty_map_with_active_findings_on_diff_is_a_gap(self):
        gap = delta_mod.zero_hunk_gate_gap(
            self._ctx({"base": "main", "hunks": {}}), 2, "on-diff")
        self.assertIsNotNone(gap)
        self.assertIn("zero-hunk delta gate", gap)
        self.assertIn("no diff ranges", gap)
        self.assertIn("on-diff", gap)
        self.assertIn("2 gate-eligible finding(s)", gap)   # #2222: the population
        # The remedy, in the disclosure's words: this artifact is written by a
        # phase the operator can re-run, which is the whole point of naming it.
        self.assertIn("regenerate the diff-hunks artifact", gap)
        self.assertIn("the driver's discovery phase writes it", gap)

    def test_an_unrejected_empty_map_keeps_the_two_readings_clause(self):
        gap = delta_mod.zero_hunk_gate_gap(
            self._ctx({"base": "main", "hunks": {}}), 1, "on-diff")
        self.assertIn("look identical", gap)
        self.assertNotIn("was rejected", gap)

    def test_a_rejected_payload_names_that_cause_instead(self):
        # Mirrors the disclosure's split (#1783): the reason the map is empty is
        # KNOWN here, so the empty-change-or-broken-artifact ambiguity does not
        # hold and saying it would send the operator to compare a known-broken
        # artifact against itself.
        gap = delta_mod.zero_hunk_gate_gap(
            self._ctx({"base": "main", "hunks": 7}), 1, "on-diff")
        self.assertIn("because the payload was rejected", gap)
        self.assertIn(delta_mod.MALFORMED_HUNKS_NOT_OBJECT, gap)
        self.assertNotIn("look identical", gap)
        self.assertIn("regenerate the diff-hunks artifact", gap)

    def test_dropped_ranges_name_that_cause_instead(self):
        # The loader accepted the payload but dropped every range as malformed,
        # so the map is empty for a KNOWN reason too: the disclosure says so on
        # its own "malformed hunk range(s) dropped" line, and the report's note
        # must not claim the ambiguity that line already resolved.
        gap = delta_mod.zero_hunk_gate_gap(
            self._ctx({"base": "main", "hunks": {"a.py": [[1]]}}), 1, "on-diff")
        self.assertIn("1 hunk range(s) were malformed and dropped", gap)
        self.assertNotIn("look identical", gap)
        self.assertNotIn("was rejected", gap)
        self.assertIn("regenerate the diff-hunks artifact", gap)

    def test_dropped_paths_name_that_cause_too(self):
        # #2169: a map emptied by LOST PATHS is known-broken for the same reason
        # a map emptied by malformed ranges is, and the note has to name the
        # loss it actually suffered.
        gap = delta_mod.zero_hunk_gate_gap(
            self._ctx({"base": "main", "hunks": {"a.py": 7}}), 1, "on-diff")
        self.assertIn("1 whole path(s)", gap)
        self.assertNotIn("look identical", gap)
        self.assertIn("regenerate the diff-hunks artifact", gap)

    def test_both_losses_are_named_when_both_happened(self):
        gap = delta_mod.zero_hunk_gate_gap(
            self._ctx({"base": "main", "hunks": {"a.py": [[1]], "b.py": 7}}), 1,
            "on-diff")
        self.assertIn("1 hunk range(s) were malformed and dropped", gap)
        self.assertIn("1 whole path(s)", gap)

    def test_the_count_is_qualified_as_the_gate_eligible_set(self):
        # #2222 (owner ruling 2026-09-28): the population is what the GATE would
        # have judged, and the clause says which filters made it -- so a reader
        # does not take the number for the wider `active` tally the same summary
        # reports.
        gap = delta_mod.zero_hunk_gate_gap(
            self._ctx({"base": "main", "hunks": {}}), 3, "on-diff")
        self.assertIn("3 gate-eligible finding(s) (the active set after the "
                      "gate's evidence policy and any --fail-on floor, before "
                      "delta scoping)", gap)

    def test_a_named_file_with_no_range_is_still_a_gap(self):
        # ranges == 0 is the condition, not files == 0: a map that names a file
        # and gives it no range scopes the gate by `diff_map.classify`'s
        # FAIL-OPEN arms, which is not a measured diff either.
        self.assertIsNotNone(delta_mod.zero_hunk_gate_gap(
            self._ctx({"base": "main", "hunks": {"a.py": []}}), 1, "on-diff"))

    def test_no_active_findings_is_no_gap(self):
        # The owner's carve-out: an empty legitimate change still passes. #2222
        # WIDENS it -- the zero the caller passes is now the gate-eligible
        # population, so a run whose only findings could never gate lands here
        # too (`TestTheZeroHunkPopulation` below is where that is decided).
        self.assertIsNone(delta_mod.zero_hunk_gate_gap(
            self._ctx({"base": "main", "hunks": {}}), 0, "on-diff"))

    def test_the_wider_gate_scope_is_no_gap(self):
        # Falling BACK to the wider scope was rejected; a run that ASKED for it
        # gates on every active finding already, so nothing was scoped away.
        self.assertIsNone(delta_mod.zero_hunk_gate_gap(
            self._ctx({"base": "main", "hunks": {}}), 2, "all"))

    def test_a_populated_map_is_no_gap(self):
        self.assertIsNone(delta_mod.zero_hunk_gate_gap(
            self._ctx({"base": "main", "hunks": {"a.py": [[1, 5]]}}), 2, "on-diff"))

    def test_an_inactive_delta_is_no_gap(self):
        # No base: the review degrades to the WIDER gate, which fails closed.
        self.assertIsNone(delta_mod.zero_hunk_gate_gap(
            self._ctx({"hunks": {}}), 2, "on-diff"))

    def test_an_unmeasured_context_is_no_gap(self):
        # A context built straight from a payload carries no load report, so
        # nothing measured its ranges -- `_disclose_load` is silent there for
        # the same reason. `from_args` is the only builder a run uses, so an
        # active delta in production always carries a report.
        ctx = delta_mod.DeltaContext(diff_hunks={"base": "main", "hunks": {}})
        self.assertTrue(ctx.active)
        self.assertIsNone(ctx.report)
        self.assertIsNone(delta_mod.zero_hunk_gate_gap(ctx, 2, "on-diff"))


class TestArtifactFacts(unittest.TestCase):
    """#2169: `meta.coverage.delta_artifact`'s source -- a dict whenever a
    `--diff-hunks` path was given, active delta or not, None when none was; the
    key's schema node in `report-schema.json` says why."""

    def _ctx(self, payload):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "diff-hunks.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            with contextlib.redirect_stderr(io.StringIO()):
                return delta_mod.DeltaContext.from_args(
                    _cli_args(diff_hunks=path, fail_on="high"))

    def test_a_context_given_no_path_has_no_facts(self):
        # A caller that built the context from a payload it already held: no read
        # was attempted, so there is no zero to report.
        ctx = delta_mod.DeltaContext(diff_hunks={"base": "main", "hunks": {}})
        self.assertIsNone(delta_mod.artifact_facts(ctx))
        self.assertIsNone(delta_mod.artifact_facts(delta_mod.DeltaContext()))

    def test_a_path_that_does_not_exist_still_reports_the_attempt(self):
        # #2169 review, F3: `from_args` builds a HunksLoad for the FLAG, so this
        # shape reaches the report -- which is why the block is no longer
        # described as "a file was read" and no longer carries `path_read`.
        with tempfile.TemporaryDirectory() as d:
            with contextlib.redirect_stderr(io.StringIO()):
                ctx = delta_mod.DeltaContext.from_args(_cli_args(
                    diff_hunks=os.path.join(d, "absent.json"), fail_on="high"))
        self.assertEqual(delta_mod.artifact_facts(ctx),
                         {"payload_malformed": delta_mod.MALFORMED_UNREADABLE,
                          "ranges_dropped": 0, "paths_dropped": 0,
                          "paths_without_ranges": 0,
                          "paths_emptied_by_drops": 0})

    def test_a_rejected_payload_still_reports_the_read(self):
        ctx = self._ctx(["not", "an", "object"])
        self.assertFalse(ctx.active)
        self.assertEqual(delta_mod.artifact_facts(ctx),
                         {"payload_malformed": delta_mod.MALFORMED_NOT_OBJECT,
                          "ranges_dropped": 0, "paths_dropped": 0,
                          "paths_without_ranges": 0,
                          "paths_emptied_by_drops": 0})

    def test_an_active_payload_reports_no_rejection(self):
        ctx = self._ctx({"base": "main", "hunks": {"a.py": [[1, 5]]}})
        self.assertTrue(ctx.active)
        self.assertEqual(delta_mod.artifact_facts(ctx),
                         {"payload_malformed": None,
                          "ranges_dropped": 0, "paths_dropped": 0,
                          "paths_without_ranges": 0,
                          "paths_emptied_by_drops": 0})

    def test_it_carries_both_loss_counters(self):
        ctx = self._ctx({"base": "main", "hunks": {"a.py": [[1, 5], [2]], "b.py": 7}})
        self.assertEqual(delta_mod.artifact_facts(ctx)["ranges_dropped"], 1)
        self.assertEqual(delta_mod.artifact_facts(ctx)["paths_dropped"], 1)

    def test_it_carries_the_rangeless_path_counter_too(self):
        # #2381: the fourth fact, and the one the other three cannot imply -- the
        # map kept c.py, so the gate reads every finding in it as on-diff.
        ctx = self._ctx({"base": "main", "hunks": {"a.py": [[1, 5]], "c.py": []}})
        facts = delta_mod.artifact_facts(ctx)
        self.assertEqual(facts["paths_without_ranges"], 1)
        self.assertEqual((facts["ranges_dropped"], facts["paths_dropped"]), (0, 0))
        # #2386: c.py arrived `[]`, so the broken subset of that one is empty.
        self.assertEqual(facts["paths_emptied_by_drops"], 0)


class TestTheZeroHunkPopulation(unittest.TestCase):
    """#2222 (owner ruling 2026-09-28), narrowing #2178: which findings the
    zero-hunk refusal is a statement ABOUT. The empty hunk map hid findings from
    the GATE, so the population is the active set the gate would actually have
    judged -- the evidence policy, then the `--fail-on` floor -- and a run
    carrying only findings the gate would have ignored anyway keeps its PASS."""

    def _f(self, sev, status="advisor_confirmed", fid="A-1"):
        return {"id": fid, "severity": sev, "evidence": {"status": status}}

    def test_the_fail_on_floor_excludes_what_cannot_gate(self):
        pop = delta_mod.zero_hunk_population(
            [self._f("HIGH", fid="A-1"), self._f("LOW", fid="A-2"),
             self._f("INFO", fid="A-3")], "high", False)
        self.assertEqual([f["id"] for f in pop], ["A-1"])

    def test_the_floor_admits_everything_at_or_above_it(self):
        pop = delta_mod.zero_hunk_population(
            [self._f("CRITICAL", fid="A-1"), self._f("HIGH", fid="A-2"),
             self._f("MEDIUM", fid="A-3")], "medium", False)
        self.assertEqual([f["id"] for f in pop], ["A-1", "A-2", "A-3"])

    def test_an_unverified_finding_is_out_under_the_default_policy(self):
        # `confirmed_only`: an unverified HIGH is active but does not gate, so
        # the empty map scoped nothing away from the gate by hiding it.
        self.assertEqual(delta_mod.zero_hunk_population(
            [self._f("HIGH", status="unverified")], "high", False), [])

    def test_gate_unverified_takes_the_whole_active_set(self):
        # The opt-in policy gates on unverified findings, so they are exactly
        # what the map hid.
        pop = delta_mod.zero_hunk_population(
            [self._f("HIGH", status="unverified", fid="A-1"),
             self._f("HIGH", status="needs_more_info", fid="A-2")], "high", True)
        self.assertEqual([f["id"] for f in pop], ["A-1", "A-2"])

    def test_every_gate_eligible_status_counts(self):
        pop = delta_mod.zero_hunk_population(
            [self._f("HIGH", status=s, fid=s) for s in
             sorted(evidence_mod.GATE_ELIGIBLE_DEFAULT)], "high", False)
        self.assertEqual({f["id"] for f in pop},
                         set(evidence_mod.GATE_ELIGIBLE_DEFAULT))

    def test_no_fail_on_admits_every_severity(self):
        # RULING: the floor reads nothing when there is no threshold, because
        # `gate_verdict` returns OFF before reading a severity -- so an OFF gate
        # over a zero-hunk map still reports the gap it has always reported
        # (`test_grading.py::...::test_off_is_preserved`), and only the evidence
        # policy narrows the count.
        active = [self._f("INFO", fid="A-1"), self._f("CRITICAL", fid="A-2"),
                  self._f("HIGH", status="unverified", fid="A-3")]
        self.assertEqual([f["id"] for f in
                          delta_mod.zero_hunk_population(active, None, False)],
                         ["A-1", "A-2"])
        self.assertEqual(len(delta_mod.zero_hunk_population(active, None, True)), 3)

    def test_an_empty_active_set_is_an_empty_population(self):
        for fail_on in ("high", None):
            for unverified in (False, True):
                with self.subTest(fail_on=fail_on, gate_unverified=unverified):
                    self.assertEqual(
                        delta_mod.zero_hunk_population([], fail_on, unverified), [])

    def test_it_equals_what_the_gate_itself_judges(self):
        # META-TEST: the two policies are the GATE's, not copies of them. The
        # evidence half comes from `verdicts._partition_gate` (on an INACTIVE
        # delta, which is scope `all` -- the wider scope this count is about) and
        # the severity half from `grading.gate_verdict`, one finding at a time:
        # a finding the gate would FAIL on is one the empty map hid from it.
        # The floor is ONE definition (`findings.severity_floor_admits`), so
        # this equality cannot see a floor change -- it is what keeps the
        # MIRRORED evidence half from drifting, and it still trips if
        # `gate_verdict` ever re-inlines a floor of its own. `gate_verdict`'s
        # quantifier is pinned by `test_grading.py`'s `test_gate_*`, not here:
        # a one-element list makes `any` and `all` agree.
        findings = [self._f("CRITICAL", fid="A-1"),
                    self._f("HIGH", status="tool_confirmed", fid="A-2"),
                    self._f("HIGH", status="backup_scope_limited", fid="A-3"),
                    self._f("HIGH", status="unverified", fid="A-4"),
                    self._f("MEDIUM", fid="A-5"),
                    self._f("LOW", status="tool_reported", fid="A-6"),
                    self._f("INFO", fid="A-7"),
                    self._f("CRITICAL", status="rejected", fid="A-8")]
        for fail_on in ("critical", "high", "medium", "low", "info"):
            for unverified in (False, True):
                with self.subTest(fail_on=fail_on, gate_unverified=unverified):
                    run = types.SimpleNamespace(gate_scope="all", fail_on=fail_on,
                                                gate_unverified=unverified)
                    parts = verdicts_mod._partition_gate(
                        copy.deepcopy(findings), delta_mod.DeltaContext(), run)
                    expected = [f["id"] for f in parts.gate_eligible
                                if grading_mod.gate_verdict([f], fail_on) == "FAIL"]
                    pop = delta_mod.zero_hunk_population(parts.active, fail_on,
                                                         unverified)
                    self.assertEqual([f["id"] for f in pop], expected)
                    # The fixture must actually exercise whichever filter is in
                    # force, or the equality above would hold vacuously. Under
                    # `--gate-unverified` the evidence filter is a no-op by
                    # design, and at `--fail-on info` so is the floor.
                    if not unverified:
                        self.assertLess(len(parts.gate_eligible), len(parts.active))
                    if fail_on != "info":
                        self.assertLess(len(pop), len(parts.gate_eligible))

"""The boundary repairs in `scripts.synth.repair`.

`tools-manifest.json` and `.panopticon/groups.json` are written INSIDE the
reviewed tree, so a hostile target can pre-commit either one and both reach the
published report and its HTML. These are the tests that say what happens then:
a malformed row costs a warning and the row, never the run and never an
`artifact invalid` exit -- and every published value is bounded on all three
axes (rows, name length, value length) at the READ, because a producer's own
caps say nothing about a file that never passed through the producer.

Split out of `test_validate_schema.py` with the module itself (#1645 fix round
2); the agent-sourced repairs stay there with the schema-node machinery.
"""
import contextlib
import io
import unittest

import scripts.synth.repair as repair_mod



class TestWarningStreamIsBounded(unittest.TestCase):
    """#1645 fix round 3, N-1. The CONTENT is bounded; the stream of
    announcements about it was not.

    `_bounded`'s own docstring is the argument: thousands of warnings are the
    same denial-of-attention the row bound exists to prevent. A hostile
    manifest put 120,401 lines and 17.9 MB onto synthesize's stderr -- a CI-log
    flood rather than a corrupted artifact, but the bound had moved rather than
    closed.
    """

    # #3273 cut 12: the manifest blocks this used to flood through are read as
    # written now; the budget is `warn_repairs`', so it is pinned through a
    # repair that still announces per row -- the target-committed exclusion
    # globs, each over-long one dropped with a line of its own.
    def _hostile(self):
        return {"globs": ["g%d" % n + "x" * 5000 for n in range(500)], "count": 1}

    def _stderr(self, value):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            repair_mod.repair_tools_excluded(value)
        return err.getvalue()

    def test_a_hostile_manifest_does_not_flood_stderr(self):
        text = self._stderr(self._hostile())
        self.assertLessEqual(len(text.encode("utf-8")), 8192,
                             "%d bytes of stderr" % len(text.encode("utf-8")))

    def test_the_line_count_is_the_budget_plus_one_summary(self):
        lines = self._stderr(self._hostile()).splitlines()
        self.assertEqual(len(lines), repair_mod.WARN_LINES_MAX + 1)
        self.assertIn("more repairs", lines[-1])

    def test_the_summary_names_the_true_remaining_count(self):
        # Summarised, never hidden: the count is what was NOT printed, so a
        # reader can tell a lightly-damaged manifest from a hostile one.
        changes = [("path%d" % n, "dropped") for n in range(500)]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            repair_mod.warn_repairs("tools-manifest.json", changes, None)
        self.assertIn("%d more repairs" % (500 - repair_mod.WARN_LINES_MAX),
                      err.getvalue())

    def test_a_short_repair_list_is_printed_whole_with_no_summary(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            repair_mod.warn_repairs("groups.json", [("mode", "dropped")], None)
        self.assertEqual(len(err.getvalue().splitlines()), 1)
        self.assertNotIn("more repairs", err.getvalue())

    def test_an_over_long_glob_is_cut_before_it_is_echoed(self):
        # One 100 KB glob must not become one 100 KB warning line.
        text = self._stderr({"globs": ["x" * 100000], "count": 0})
        self.assertLessEqual(len(text), 1000, "%d chars" % len(text))
        self.assertIn("tools_excluded.globs", text)


class TestRepairToolsSuppressed(unittest.TestCase):
    """#1578: `meta.coverage.tools_suppressed` counts drops the VENDORED-path
    exclusion made, keyed by the directory segment that made them.

    The keys come from a closed vocabulary the controller owns
    (`ingest_tools._VENDORED_DIRS`) and the counts are the controller's own
    tally -- but the tally is derived from `location.file` values a SCANNER
    read out of the reviewed tree, and item 14's ruling is that every
    target-carried input is repaired at its boundary rather than trusted to
    match what the schema pins. Same shape as its two `tools-manifest.json`
    siblings: a malformed row costs a warning and the row, never the run and
    never an `artifact invalid` exit on a report the target authored a corner
    of. Bounded on both axes at the read, for the same reason they are.
    """

    def _repair(self, value):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            got = repair_mod.repair_tools_suppressed(value)
        return got, err.getvalue()

    def test_a_well_formed_block_passes_through(self):
        got, err = self._repair({"vendor": 592, "node_modules": 3})
        self.assertEqual(got, {"vendor": 592, "node_modules": 3})
        self.assertEqual(err, "")

    def test_nothing_measured_is_an_empty_map(self):
        for bad in (None, {}, [], 7, "vendor"):
            with self.subTest(value=repr(bad)):
                self.assertEqual(self._repair(bad)[0], {})

    def test_a_non_integer_count_is_dropped_never_coerced(self):
        got, err = self._repair({"vendor": "lots"})
        self.assertEqual(got, {})
        self.assertIn("vendor", err)

    def test_a_bool_is_not_an_integer_here(self):
        # jsonschema rejects True where `integer` is pinned, so an unrepaired
        # one would fail the artifact it rode into.
        self.assertEqual(self._repair({"vendor": True})[0], {})

    def test_a_negative_count_is_dropped(self):
        self.assertEqual(self._repair({"vendor": -1})[0], {})

    def test_a_non_string_segment_is_dropped(self):
        self.assertEqual(self._repair({7: 1})[0], {})

    def test_an_overlong_segment_is_cut_not_dropped(self):
        # #1839 review round 1 N4: `pyvenv.cfg:<dir>` is the first key shape here
        # that embeds an arbitrary target PATH, so the bound became reachable --
        # and a virtualenv nested under 190 characters of path used to lose its
        # row from the report an operator reads. Cut with a visible marker.
        key = "pyvenv.cfg:" + "v" * repair_mod.NAME_MAX
        got, err = self._repair({key: 4})
        self.assertEqual(list(got.values()), [4])
        cut = next(iter(got))
        self.assertEqual(len(cut), repair_mod.NAME_MAX)
        self.assertTrue(cut.endswith("\u2026"), cut)
        self.assertTrue(cut.startswith("pyvenv.cfg:"), cut)
        self.assertIn("cut", err)

    def test_two_keys_that_cut_to_one_row_are_summed(self):
        # The reason the bound used to DROP: a cut can collide two identities.
        # It still can -- what must not happen is a count that lies, so the
        # colliding rows add up and the marker says the name is not complete.
        long = "pyvenv.cfg:" + "v" * repair_mod.NAME_MAX
        got, _err = self._repair({long + "a": 2, long + "b": 3})
        self.assertEqual(list(got.values()), [5])

    def test_the_map_is_bounded_at_the_read(self):
        got, err = self._repair({"seg%04d" % n: 1
                                 for n in range(repair_mod.ROWS_MAX + 25)})
        self.assertEqual(len(got), repair_mod.ROWS_MAX)
        self.assertIn("%d" % repair_mod.ROWS_MAX, err)


class TestRepairToolsExcluded(unittest.TestCase):
    """#1740 fix round 2: `meta.coverage.tools_excluded` -- the `--exclude` /
    committed `exclude_paths:` policy this run's tool ingest applied, and how
    many findings it took off the axis.

    Repaired like its `tools_suppressed` sibling and for the same reason: the
    globs are authored by the REPOSITORY under review (`panopticon.yml`), so
    they are a target-carried input reaching a published artifact, and the
    schema pins their types.
    """

    def _repair(self, value):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            got = repair_mod.repair_tools_excluded(value)
        return got, err.getvalue()

    def test_a_well_formed_block_passes_through(self):
        got, err = self._repair({"globs": ["tests/fixtures/**"], "count": 3})
        self.assertEqual(got, {"globs": ["tests/fixtures/**"], "count": 3})
        self.assertEqual(err, "")

    def test_nothing_measured_is_the_empty_block_not_a_missing_key(self):
        for bad in (None, {}, [], 7, "globs"):
            with self.subTest(value=repr(bad)):
                self.assertEqual(self._repair(bad)[0], {"globs": [], "count": 0})

    def test_a_non_integer_count_is_dropped_to_zero_never_coerced(self):
        got, err = self._repair({"globs": ["a/**"], "count": "lots"})
        self.assertEqual(got, {"globs": ["a/**"], "count": 0})
        self.assertIn("count", err)

    def test_a_bool_is_not_an_integer_here(self):
        self.assertEqual(self._repair({"globs": [], "count": True})[0]["count"], 0)

    def test_a_negative_count_is_dropped(self):
        self.assertEqual(self._repair({"globs": [], "count": -1})[0]["count"], 0)

    def test_non_string_and_over_long_globs_are_dropped(self):
        got, err = self._repair({"globs": ["ok/**", 7, "x" * 500], "count": 1})
        self.assertEqual(got["globs"], ["ok/**"])
        self.assertIn("globs", err)

    def test_the_row_count_is_bounded(self):
        got, _err = self._repair({"globs": ["g%d/**" % i for i in range(500)],
                                  "count": 1})
        self.assertEqual(len(got["globs"]), repair_mod.ROWS_MAX)


class TestRepairSecCarveOut(unittest.TestCase):
    """#1757 (AGT-1355709320): `meta.coverage.exclude_paths_sec_carve_out` -- the
    objective SEC surface a target's committed `exclude_paths:` could not hide.

    Repaired like `tools_excluded` and for the same reason, twice over: the globs
    are authored in the reviewed repository's own `panopticon.yml`, and the file
    list is repo-relative paths read out of the reviewed tree. Both reach a
    published artifact, so a glob or a path that is not a bounded non-empty
    string is DROPPED rather than cut -- a cut glob is a different glob and a cut
    path names a file that does not exist.
    """

    def _repair(self, value):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            got = repair_mod.repair_sec_carve_out(value)
        return got, err.getvalue()

    def test_a_well_formed_block_passes_through(self):
        block = {"globs": ["vendor/**"], "files": ["vendor/requirements.txt"],
                 "count": 1}
        got, err = self._repair(block)
        self.assertEqual(got, block)
        self.assertEqual(err, "")

    def test_nothing_measured_is_the_empty_block_not_a_missing_key(self):
        for bad in (None, {}, [], 7, "globs"):
            with self.subTest(value=repr(bad)):
                self.assertEqual(self._repair(bad)[0],
                                 {"globs": [], "files": [], "count": 0})

    def test_a_non_integer_or_negative_count_is_dropped_to_zero(self):
        for bad in ("lots", True, -1, [1]):
            with self.subTest(count=repr(bad)):
                self.assertEqual(
                    self._repair({"globs": [], "files": [], "count": bad})[0]["count"],
                    0)

    def test_non_string_and_over_long_entries_are_dropped_from_both_lists(self):
        got, err = self._repair({"globs": ["ok/**", 7, "x" * 500],
                                 "files": ["a/ok.yaml", None, "y" * 5000],
                                 "count": 3})
        self.assertEqual(got["globs"], ["ok/**"])
        self.assertEqual(got["files"], ["a/ok.yaml"])
        self.assertIn("globs", err)
        self.assertIn("files", err)
        # The count is the MEASUREMENT and survives the bound on the list: a
        # repaired list shorter than the count is the honest reading of both.
        self.assertEqual(got["count"], 3)

    def test_both_lists_are_bounded(self):
        got, _err = self._repair({"globs": ["g%d/**" % i for i in range(500)],
                                  "files": ["f%d.yaml" % i for i in range(500)],
                                  "count": 500})
        self.assertEqual(len(got["globs"]), repair_mod.ROWS_MAX)
        self.assertEqual(len(got["files"]), repair_mod.ROWS_MAX)

    def test_a_non_list_for_either_list_is_dropped_not_exploded(self):
        got, err = self._repair({"globs": "vendor/**", "files": {"a": 1}, "count": 1})
        self.assertEqual(got["globs"], [])
        self.assertEqual(got["files"], [])
        self.assertIn("not a list", err)


if __name__ == "__main__":
    unittest.main()

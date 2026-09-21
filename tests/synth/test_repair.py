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
import copy
import io
import unittest

import scripts.synth.repair as repair_mod
import scripts.synth.validate_schema as validate_schema_mod

from tests.synth.test_validate_schema import _minimal_report


class TestRepairToolsSanitized(unittest.TestCase):
    """#1646: `tools-manifest.json` is TARGET-WRITABLE, and its `sanitized`
    block now reaches the report (`meta.tools.sanitized`) and the HTML.

    The principle #1639 P15 established applies unchanged: the schema pins the
    CONTROLLER's output, so a target-sourced input is normalized to the pinned
    types at its boundary. A hostile manifest must cost a warning and the
    malformed rows, never the run and never an `artifact invalid` exit.
    """

    def _repair(self, value):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            got = repair_mod.repair_tools_sanitized(value)
        return got, err.getvalue()

    def test_a_well_formed_block_passes_through(self):
        block = {"pip-audit": {"source": "requirements.txt", "kept": 2,
                               "dropped": [{"line": "-e .", "reason": "editable"}],
                               "hashes_stripped": True}}
        got, err = self._repair(block)
        self.assertEqual(got, block)
        self.assertEqual(err, "")

    def test_a_non_object_block_reads_as_nothing_measured(self):
        for bad in ("[]", [], 7, None, "pip-audit"):
            with self.subTest(value=repr(bad)):
                got, _err = self._repair(bad)
                self.assertEqual(got, {})

    def test_a_non_object_row_is_dropped_with_a_warning(self):
        got, err = self._repair({"pip-audit": ["-e ."]})
        self.assertEqual(got, {})
        self.assertIn("pip-audit", err)

    def test_a_non_string_tool_name_is_dropped(self):
        got, _err = self._repair({7: {"kept": 1}})
        self.assertEqual(got, {})

    def test_wrongly_typed_fields_are_dropped_not_coerced_into_a_lie(self):
        got, err = self._repair({"pip-audit": {
            "source": {"nested": "object"}, "kept": "lots",
            "hashes_stripped": "yes", "dropped": "everything"}})
        self.assertEqual(got, {"pip-audit": {}})
        for field in ("source", "kept", "hashes_stripped", "dropped"):
            self.assertIn(field, err)

    def test_a_boolean_kept_is_not_an_integer(self):
        # True == 1 in Python but `jsonschema` does not accept a bool where an
        # integer is pinned, so an unrepaired True would fail the ARTIFACT.
        got, _err = self._repair({"pip-audit": {"kept": True}})
        self.assertEqual(got, {"pip-audit": {}})

    def test_malformed_dropped_rows_are_dropped_row_by_row(self):
        got, _err = self._repair({"pip-audit": {"dropped": [
            {"line": "-e .", "reason": "editable"},
            {"line": 7, "reason": "editable"},
            "not a row",
            {"line": "./x"},
        ]}})
        self.assertEqual(got, {"pip-audit": {
            "dropped": [{"line": "-e .", "reason": "editable"}]}})

    def test_an_unknown_field_inside_a_row_is_dropped(self):
        # `meta` is closed and the parity walk is stricter still: a key the
        # schema does not describe must not ride into the artifact.
        got, _err = self._repair({"pip-audit": {"kept": 1, "surprise": "x"}})
        self.assertEqual(got, {"pip-audit": {"kept": 1}})

    def test_the_two_bound_disclosures_survive_the_repair(self):
        # #1646 fix round 1: `truncated` and `dropped_truncated` say the
        # disclosure itself was capped. Dropping them would turn a bounded
        # answer back into one that reads as complete.
        block = {"pip-audit": {"source": "requirements.txt", "kept": 1,
                               "dropped": [], "hashes_stripped": False,
                               "truncated": True, "dropped_truncated": 300}}
        got, err = self._repair(block)
        self.assertEqual(got, block)
        self.assertEqual(err, "")

    def test_wrongly_typed_bound_disclosures_are_dropped(self):
        got, err = self._repair({"pip-audit": {"truncated": "yes",
                                               "dropped_truncated": True}})
        self.assertEqual(got, {"pip-audit": {}})
        self.assertIn("truncated", err)
        self.assertIn("dropped_truncated", err)

    def test_the_row_count_is_bounded(self):
        # Fix round 2, N2. The producer's own caps (pip_audit's
        # `_MAX_DROPPED_ROWS`/`_MAX_PUBLISHED_CHARS`) are not a defence AT THIS
        # BOUNDARY: the manifest this repairer exists for is the one a hostile
        # target pre-committed into the scanned tree, which never passed
        # through that producer at all. 5000 rows would otherwise render 5000
        # escaped lines into the published HTML.
        got, err = self._repair({"t%d" % n: {"kept": 1} for n in range(5000)})
        self.assertEqual(len(got), repair_mod.ROWS_MAX)
        self.assertIn("5000", err)
        self.assertEqual(err.count("rows in"), 1, "one aggregate warning, not 4800")

    def test_the_rows_kept_are_the_same_ones_every_time(self):
        block = {"t%d" % n: {"kept": 1} for n in range(5000)}
        first, _err = self._repair(block)
        second, _err2 = self._repair(dict(reversed(list(block.items()))))
        self.assertEqual(first, second)

    def test_an_over_long_adapter_name_is_dropped_not_truncated(self):
        got, err = self._repair({"x" * 5000: {"kept": 1},
                                 "pip-audit": {"kept": 1}})
        self.assertEqual(sorted(got), ["pip-audit"])
        self.assertIn("dropped", err)

    def test_an_over_long_source_is_cut_and_says_so(self):
        got, err = self._repair({"pip-audit": {"source": "s" * 5000}})
        self.assertEqual(len(got["pip-audit"]["source"]),
                         repair_mod.VALUE_MAX)
        self.assertIn("cut", err)

    def test_the_dropped_list_is_bounded(self):
        rows = [{"line": "-e .", "reason": "editable"} for _n in range(5000)]
        got, err = self._repair({"pip-audit": {"dropped": rows}})
        self.assertEqual(len(got["pip-audit"]["dropped"]),
                         repair_mod.ROWS_MAX)
        self.assertIn("5000", err)

    def test_an_over_long_dropped_row_is_cut_and_says_so(self):
        got, err = self._repair({"pip-audit": {"dropped": [
            {"line": "l" * 5000, "reason": "r" * 5000}]}})
        kept = got["pip-audit"]["dropped"]
        self.assertEqual(len(kept), 1)
        self.assertEqual(len(kept[0]["line"]),
                         repair_mod.VALUE_MAX)
        self.assertEqual(len(kept[0]["reason"]),
                         repair_mod.VALUE_MAX)
        self.assertIn("cut", err)

    def test_a_hostile_manifest_never_makes_the_artifact_invalid(self):
        report = _minimal_report()
        report["meta"]["tools"]["sanitized"] = repair_mod.repair_tools_sanitized({"pip-audit": {"kept": "lots",
                                                  "dropped": [{"line": None}]}},
                                   warn=lambda _m: None)
        self.assertEqual(validate_schema_mod.schema_errors(report), [])


class TestRepairToolsNetwork(unittest.TestCase):
    """#1645: `tools-manifest.json`'s `network` block reaches the report
    (`meta.tools.network`) and the HTML, and the manifest is TARGET-WRITABLE.

    Same principle as `sanitized` beside it: the schema pins the CONTROLLER's
    output, so a target-sourced input is normalized to the pinned types at its
    boundary. A hostile manifest costs a warning and the malformed rows, never
    the run and never an `artifact invalid` exit.
    """

    def _repair(self, value):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            got = repair_mod.repair_tools_network(value)
        return got, err.getvalue()

    def test_a_well_formed_block_passes_through(self):
        block = {"semgrep": "none", "pip-audit": "proxied:pypi.org"}
        got, err = self._repair(block)
        self.assertEqual(got, block)
        self.assertEqual(err, "")

    def test_a_non_object_block_reads_as_nothing_measured(self):
        for bad in ("none", [], 7, None, ["semgrep"]):
            with self.subTest(value=repr(bad)):
                got, _err = self._repair(bad)
                self.assertEqual(got, {})

    def test_a_non_string_posture_is_dropped_not_coerced(self):
        # `{"semgrep": {"network": "none"}}` has no honest string, and
        # stringifying it would publish a posture nobody recorded.
        got, err = self._repair({"semgrep": {"kind": "none"}, "trivy": 7})
        self.assertEqual(got, {})
        self.assertIn("semgrep", err)
        self.assertIn("trivy", err)

    def test_a_non_string_tool_name_is_dropped(self):
        got, _err = self._repair({7: "none"})
        self.assertEqual(got, {})

    def test_a_hostile_posture_string_is_bounded(self):
        # Target-writable text bound for two published artifacts; the report
        # already bounds every other such field, and an unbounded one here
        # would ride a megabyte into the HTML.
        got, _err = self._repair({"semgrep": "x" * 5000})
        self.assertLessEqual(len(got["semgrep"]),
                             repair_mod.VALUE_MAX)

    def test_a_cut_posture_says_it_was_cut(self):
        # Fix round 2, N1. The row-count and name bounds announce themselves;
        # this one cut silently, so a reader met a 200-character posture that
        # looked complete.
        _got, err = self._repair({"semgrep": "x" * 5000})
        self.assertIn("semgrep", err)
        self.assertIn("cut", err)

    def test_the_row_count_is_bounded(self):
        # Fix round 1, F9. `sanitized` is bounded to 200 rows AT ITS PRODUCER
        # (scripts.tools.pip_audit._MAX_DROPPED_ROWS); this block's producer is
        # the controller's own ledger, so the bound has to live here -- a
        # hostile manifest with 50,000 rows would otherwise render 50,000
        # escaped lines into the HTML coverage block.
        got, err = self._repair({"t%d" % n: "none" for n in range(500)})
        self.assertEqual(len(got), repair_mod.ROWS_MAX)
        self.assertIn("500", err)

    def test_the_rows_kept_are_the_same_ones_every_time(self):
        # A bound that kept an arbitrary subset would make the report
        # unreproducible from the same manifest.
        block = {"t%d" % n: "none" for n in range(500)}
        first, _err = self._repair(block)
        second, _err2 = self._repair(dict(reversed(list(block.items()))))
        self.assertEqual(first, second)

    def test_an_over_long_tool_name_is_dropped_not_truncated(self):
        # A NAME is an identity: cutting it could collide two rows into one and
        # attribute one adapter's posture to another.
        got, err = self._repair({"x" * 5000: "none", "semgrep": "none"})
        self.assertEqual(got, {"semgrep": "none"})
        self.assertIn("dropped", err)

    def test_a_hostile_manifest_never_makes_the_artifact_invalid(self):
        report = _minimal_report()
        report["meta"]["tools"]["network"] = repair_mod.repair_tools_network({"semgrep": {"deeply": ["nested"]},
                                  "pip-audit": "proxied:pypi.org"},
                                 warn=lambda _m: None)
        self.assertEqual(validate_schema_mod.schema_errors(report), [])


if __name__ == "__main__":
    unittest.main()


class TestWarningStreamIsBounded(unittest.TestCase):
    """#1645 fix round 3, N-1. The CONTENT is bounded; the stream of
    announcements about it was not.

    `_bounded`'s own docstring is the argument: thousands of warnings are the
    same denial-of-attention the row bound exists to prevent. A hostile
    manifest put 120,401 lines and 17.9 MB onto synthesize's stderr -- a CI-log
    flood rather than a corrupted artifact, but the bound had moved rather than
    closed.
    """

    def _hostile(self):
        row = {"source": "s" * 5000, "kept": 1,
               "dropped": [{"line": "l" * 5000, "reason": "r" * 5000}
                           for _n in range(50)]}
        row.update({"undescribed%d" % f: 1 for f in range(200)})
        return {"t%d" % n: dict(row) for n in range(500)}

    def _stderr(self, value):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            repair_mod.repair_tools_sanitized(value)
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

    def test_an_undescribed_field_name_is_cut_before_it_is_echoed(self):
        # `sanitized.<name>.<extra>`: `name` was bounded, `extra` was echoed
        # uncut, so one 100 KB field name became one 100 KB warning line.
        text = self._stderr({"pip-audit": {"x" * 100000: 1}})
        self.assertLessEqual(len(text), 1000, "%d chars" % len(text))
        self.assertIn("pip-audit", text)

    def test_a_cut_warning_says_which_field_was_cut(self):
        text = self._stderr({"pip-audit": {"dropped": [
            {"line": "l" * 5000, "reason": "ok"}]}})
        self.assertIn("dropped.line", text)
        self.assertNotIn("dropped.reason", text)


class TestRepairGroupsJson(unittest.TestCase):
    """#1645 fix round 3, N-2. `groups.json` is the third boundary this module
    names, it is equally target-writable, and `groups[].name` is copied into
    the report's type-pinned `groups[]` -- but it applied none of the bounds
    the module docstring claimed for all three."""

    def _repair(self, gj):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            got = repair_mod.repair_groups_json(gj)
        return got, err.getvalue()

    def test_the_group_rows_are_bounded(self):
        got, err = self._repair(
            {"groups": [{"name": "g%d" % n, "files": []} for n in range(50000)]})
        self.assertEqual(len(got["groups"]), repair_mod.ROWS_MAX)
        self.assertIn("50000", err)
        self.assertEqual(err.count("rows in"), 1, "one aggregate warning")

    def test_a_group_name_is_cut_and_says_so(self):
        got, err = self._repair({"groups": [{"name": "x" * 50000, "files": []}]})
        kept = got["groups"]
        self.assertEqual(len(kept), 1)
        self.assertEqual(len(kept[0]["name"]), repair_mod.NAME_MAX)
        self.assertIn("cut", err)

    def test_a_parent_name_is_cut(self):
        got, _err = self._repair(
            {"groups": [{"name": "g", "parent": "p" * 50000, "files": []}]})
        self.assertEqual(len(got["groups"][0]["parent"]), repair_mod.NAME_MAX)

    def test_a_group_file_list_is_bounded_in_count(self):
        # Round-3 re-review: the 200-group cap bounds how many GROUPS survive,
        # not how many files one group may list -- one group with 100,000
        # entries reached the report and its HTML with zero warnings.
        got, err = self._repair(
            {"groups": [{"name": "g", "files": ["f%d.py" % n
                                                 for n in range(100000)]}]})
        self.assertEqual(len(got["groups"][0]["files"]), repair_mod.FILES_MAX)
        self.assertIn("100000", err)
        self.assertEqual(err.count("rows in"), 1, "one aggregate warning")

    def test_an_impossible_path_is_dropped_not_cut(self):
        # A cut path names a file that does not exist; a path longer than any
        # filesystem allows names none either, so it is dropped, and the
        # neighbouring real path survives untouched.
        long = "d/" * (repair_mod.PATH_MAX // 2) + "x.py"
        got, err = self._repair(
            {"groups": [{"name": "g", "files": ["a.py", long, "b.py"]}]})
        self.assertEqual(got["groups"][0]["files"], ["a.py", "b.py"])
        self.assertIn("dropped", err)
        self.assertLessEqual(len(err), 1000, "%d chars" % len(err))

    def test_a_correct_groups_json_is_unchanged_and_silent(self):
        gj = {"groups": [{"name": "App", "files": ["a.py"], "parent": "Core"}],
              "mode": "repo"}
        got, err = self._repair(copy.deepcopy(gj))
        self.assertEqual(got, gj)
        self.assertEqual(err, "")

    def test_a_non_dict_is_still_an_empty_mapping(self):
        got, _err = self._repair(["not", "a", "mapping"])
        self.assertEqual(got, {})


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

    def test_an_overlong_segment_is_dropped(self):
        self.assertEqual(self._repair({"v" * (repair_mod.NAME_MAX + 1): 1})[0], {})

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


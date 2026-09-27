"""Tests for scripts.phases.budget: the one owner of the persisted retry budgets.

#1767 / ARC-655791509. Five phase modules hand-copied the same read-bump-write
over a counter file under `.panopticon/` in the REVIEWED tree, and the #1809
round consolidated only the READ: `runio._load_state_json` refuses a
present-but-torn document, but the arithmetic on top of it stayed five copies
with three different answers to the same planted value. The triage probe, a
string planted at each budget's key:

    coverage._bump_scout_attempts       -> bare ValueError from int()
    discovery._bump_discovery_attempts  -> bare ValueError from int()
    verify._bump_verify_attempts        -> bare ValueError from int()
    review._record_attempts             -> tally RESET to 1 (attempts refunded)
    persist._give_back_attempts         -> silently skipped

The reset is the one outcome the file exists to prevent, in review's own words;
the bare ValueError is a message an operator cannot act on, where the read side
one line away would have named the file and `--reset`. This module is the probe
kept as a test: one owner, one behaviour -- a value that is not a count is
UNREADABLE, and unreadable refuses.
"""
import json
import os
import tempfile
import unittest

import scripts.phases.budget as budget
import scripts.phases.coverage as coverage
import scripts.phases.discovery as discovery
import scripts.phases.persist as persist
import scripts.phases.review as review
import scripts.phases.runio as runio
import scripts.phases.verify as verify


class BudgetCase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)

    def path(self, name="cell-attempts.json"):
        return runio._pano(self.root, name)

    def plant(self, path, data):
        runio._write_json(path, data)
        return path

    def read(self, path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)


class TestAValueThatIsNotACountIsUnreadable(BudgetCase):
    """The refusal, in the shape `runio._load_state_json` already uses: the
    class it raises, the path, the offending key, and the remedy. Never a bare
    ValueError, never a reset, never a silent skip."""

    WHAT = "the cell retry budget"

    def _assert_refuses(self, call, path, key):
        with self.assertRaises(runio.DriverError) as caught:
            call()
        message = str(caught.exception)
        for expected in (self.WHAT, path, key, "present but unreadable",
                         "is not a count", "--reset"):
            self.assertIn(expected, message)

    def test_a_string_value_refuses_on_every_entry_point(self):
        for name, call in (
                ("count", lambda: budget.count(self.path(), "Web/SEC", self.WHAT)),
                ("bump", lambda: budget.bump(self.path(), "Web/SEC", self.WHAT)),
                ("bump_many",
                 lambda: budget.bump_many(self.path(), ["Web/SEC"], self.WHAT)),
                ("give_back",
                 lambda: budget.give_back(self.path(), ["Web/SEC"], self.WHAT)),
        ):
            with self.subTest(entry=name):
                path = self.plant(self.path(), {"Web/SEC": "many"})
                self._assert_refuses(call, path, "Web/SEC")
                # Nothing was rewritten: no reset to 1, no decrement, no
                # rescue. The operator's `--reset` is the only way forward.
                self.assertEqual(self.read(path), {"Web/SEC": "many"})

    def test_the_offending_key_is_named_even_beside_readable_siblings(self):
        path = self.plant(self.path(), {"Web/SEC": 2, "Api/ARC": None})
        self._assert_refuses(
            lambda: budget.count(path, "Api/ARC", self.WHAT), path, "Api/ARC")
        # A sibling's bad value never blocks a key that IS a count: the refusal
        # is about the value read, not about the document being present.
        self.assertEqual(budget.count(path, "Web/SEC", self.WHAT), 2)

    def test_a_bool_is_not_a_count(self):
        # `isinstance(True, int)` is True in Python, so a bool would otherwise
        # bump to 2 and read as a tally the run never spent.
        path = self.plant(self.path(), {"Web/SEC": True})
        self._assert_refuses(
            lambda: budget.bump(path, "Web/SEC", self.WHAT), path, "Web/SEC")

    def test_a_float_is_not_a_count(self):
        path = self.plant(self.path(), {"Web/SEC": 2.5})
        self._assert_refuses(
            lambda: budget.count(path, "Web/SEC", self.WHAT), path, "Web/SEC")

    def test_a_negative_value_is_not_a_count(self):
        # persist's copy read `used <= 0` and skipped, so a planted -5 was
        # indistinguishable from an untouched key.
        path = self.plant(self.path(), {"Web/SEC": -5})
        self._assert_refuses(
            lambda: budget.give_back(path, ["Web/SEC"], self.WHAT),
            path, "Web/SEC")


class TestTheArithmeticItself(BudgetCase):
    WHAT = "the cell retry budget"

    def test_an_absent_file_counts_zero_and_the_first_bump_is_one(self):
        path = self.path()
        self.assertFalse(os.path.exists(path))
        self.assertEqual(budget.count(path, "Web/SEC", self.WHAT), 0)
        self.assertEqual(budget.bump(path, "Web/SEC", self.WHAT), 1)
        self.assertEqual(budget.bump(path, "Web/SEC", self.WHAT), 2)
        self.assertEqual(budget.count(path, "Web/SEC", self.WHAT), 2)

    def test_a_bump_preserves_the_rest_of_the_document(self):
        path = self.plant(self.path(), {"Api/ARC": 3})
        self.assertEqual(budget.bump(path, "Web/SEC", self.WHAT), 1)
        self.assertEqual(self.read(path), {"Api/ARC": 3, "Web/SEC": 1})

    def test_bump_many_charges_every_key_in_one_write(self):
        path = self.path()
        self.assertEqual(
            budget.bump_many(path, ["Web/SEC", "Api/ARC"], self.WHAT),
            {"Web/SEC": 1, "Api/ARC": 1})
        self.assertEqual(self.read(path), {"Api/ARC": 1, "Web/SEC": 1})

    def test_bump_many_charges_a_repeated_key_once_per_occurrence(self):
        # review's dispatch loop counts one charge per ENTRY, so a key listed
        # twice is two dispatches, not one. give_back is the asymmetric half.
        path = self.path()
        self.assertEqual(
            budget.bump_many(path, ["Web/SEC", "Web/SEC"], self.WHAT),
            {"Web/SEC": 2})
        self.assertEqual(self.read(path), {"Web/SEC": 2})

    def test_give_back_decrements_each_distinct_key_once(self):
        path = self.plant(self.path(), {"Web/SEC": 2, "Api/ARC": 1})
        self.assertEqual(
            budget.give_back(path, ["Web/SEC", "Web/SEC", "Api/ARC"], self.WHAT),
            ["Web/SEC", "Api/ARC"])
        self.assertEqual(self.read(path), {"Api/ARC": 0, "Web/SEC": 1})

    def test_give_back_skips_an_absent_or_spent_key_without_going_below_zero(self):
        path = self.plant(self.path(), {"Web/SEC": 0})
        self.assertEqual(
            budget.give_back(path, ["Web/SEC", "Never/DISPATCHED"], self.WHAT), [])
        self.assertEqual(self.read(path), {"Web/SEC": 0})

    def test_give_back_writes_nothing_when_it_cleared_nothing(self):
        path = self.path()
        self.assertEqual(budget.give_back(path, ["Web/SEC"], self.WHAT), [])
        self.assertFalse(os.path.exists(path))


class TestTheOwnerDoesNotBypassRunio(BudgetCase):
    """Both halves of the #1809 pair stay in force: the read refuses a present
    document it cannot parse, and the write refuses a symlink at the artifact
    path. Neither is re-implemented here, which is the point of asserting it."""

    WHAT = "the cell retry budget"

    def test_a_torn_document_refuses_on_every_entry_point(self):
        for name, call in (
                ("count", lambda: budget.count(self.path(), "Web/SEC", self.WHAT)),
                ("bump", lambda: budget.bump(self.path(), "Web/SEC", self.WHAT)),
                ("give_back",
                 lambda: budget.give_back(self.path(), ["Web/SEC"], self.WHAT)),
        ):
            with self.subTest(entry=name):
                path = self.plant(self.path(), {"Web/SEC": 3})
                with open(path, encoding="utf-8") as fh:
                    body = fh.read()
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(body[:len(body) // 2])
                with self.assertRaises(runio.DriverError) as caught:
                    call()
                self.assertIn(path, str(caught.exception))
                self.assertIn("--reset", str(caught.exception))
                os.remove(path)

    def test_a_symlink_out_of_the_run_folder_refuses_the_write(self):
        # A budget file lives in the REVIEWED tree, so the target can plant a
        # link there. A link to a readable document OUTSIDE `.panopticon` gets
        # past the read; `runio._write_json`'s confinement is what refuses, and
        # the owner must not have grown its own open() past it.
        outside = os.path.join(self.root, "elsewhere.json")
        runio._write_json(outside, {"Web/SEC": 1})
        path = self.path()
        os.symlink(outside, path)
        with self.assertRaises(ValueError) as caught:
            budget.bump(path, "Web/SEC", self.WHAT)
        self.assertIn("escapes .panopticon", str(caught.exception))
        self.assertEqual(self.read(outside), {"Web/SEC": 1})   # never clobbered

    def test_a_dangling_symlink_is_present_not_absent(self):
        # The other half of the same pair: a link the read cannot follow is
        # PRESENT (`lexists`), so calling it absent would refund in full.
        path = self.path()
        os.symlink(os.path.join(self.root, "nowhere.json"), path)
        with self.assertRaises(runio.DriverError) as caught:
            budget.count(path, "Web/SEC", self.WHAT)
        self.assertIn("--reset", str(caught.exception))


class TestTheFiveCallSitesAllRefuseAPlantedString(BudgetCase):
    """The triage probe, kept. One row per budget: its own file name, its own
    key scheme and its own `what` string -- all unchanged, because they are the
    on-disk contract a resumed run reads -- and ONE behaviour on a value that
    is not a count."""

    def _budgets(self):
        cell = runio._pano(self.root, review._ATTEMPTS_FILE)
        verify_path = runio._pano(self.root, verify._VERIFY_ATTEMPTS_FILE)
        return (
            ("coverage._bump_scout_attempts",
             runio._pano(self.root, "scout-attempts.json"), "Web",
             lambda: coverage._bump_scout_attempts(self.root, "Web")),
            ("discovery._bump_discovery_attempts",
             runio._pano(self.root, "discovery-attempts.json"), "malformed",
             lambda: discovery._bump_discovery_attempts(self.root)),
            ("verify._verify_attempts", verify_path, "Web/SEC/primary",
             lambda: verify._verify_attempts(self.root, "Web", "SEC", "primary")),
            ("verify._bump_verify_attempts", verify_path, "Web/SEC/primary",
             lambda: verify._bump_verify_attempts(self.root, "Web", "SEC",
                                                  "primary")),
            ("review._record_attempts", cell, "Web/SEC",
             lambda: review._record_attempts(self.root, ["Web/SEC"])),
            ("review._cell_exhausted", cell, "Web/SEC",
             lambda: review._cell_exhausted(self.root, "Web", "SEC")),
            ("persist._give_back_attempts", cell, "Web/SEC",
             lambda: persist._give_back_attempts(cell, ["Web/SEC"])),
        )

    def test_a_planted_string_refuses_actionably_at_every_call_site(self):
        for name, path, key, call in self._budgets():
            with self.subTest(budget=name):
                runio._write_json(path, {key: "many"})
                with self.assertRaises(runio.DriverError) as caught:
                    call()
                message = str(caught.exception)
                self.assertIn(path, message)
                self.assertIn(key, message)
                self.assertIn("is not a count", message)
                self.assertIn("--reset", message)
                # Not a bare ValueError from int(), which says only
                # "invalid literal for int() with base 10".
                self.assertNotIn("invalid literal", message)
                # And nothing was refunded, reset or skipped past.
                self.assertEqual(self.read(path), {key: "many"})
                os.remove(path)

    def test_every_call_site_still_reads_an_absent_budget_as_a_first_run(self):
        for name, path, _key, call in self._budgets():
            with self.subTest(budget=name):
                if os.path.lexists(path):
                    os.remove(path)
                call()          # no refusal: absent is a legitimate first run

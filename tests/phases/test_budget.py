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

import scripts.plan_contract as plan_contract
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

    def test_bump_many_records_set_values_in_the_same_write(self):
        # #3679: a backup cell's part count lands beside its charge. A record SETS
        # (a re-dispatch re-records the same count), it never adds.
        path = self.plant(self.path(), {"G/SEC/backup/parts": 5, "Api/ARC": 1})
        self.assertEqual(
            budget.bump_many(path, ["G/SEC/backup"], self.WHAT,
                             record={"G/SEC/backup/parts": 2}),
            {"G/SEC/backup": 1})
        self.assertEqual(self.read(path), {"Api/ARC": 1, "G/SEC/backup": 1,
                                           "G/SEC/backup/parts": 2})

    def test_a_recorded_list_of_ids_is_set_in_the_same_write(self):
        # #3695: the claim ids a backup cell was handed, beside its charge and its part
        # count. Set, never merged: a re-dispatch re-records the whole scope.
        path = self.plant(self.path(), {"G/SEC/backup/claims": ["old", "ids"], "Api/ARC": 1})
        self.assertEqual(
            budget.bump_many(path, ["G/SEC/backup"], self.WHAT,
                             record={"G/SEC/backup/parts": 1,
                                     "G/SEC/backup/claims": ["SEC-2", "SEC-1"]}),
            {"G/SEC/backup": 1})
        self.assertEqual(self.read(path), {"Api/ARC": 1, "G/SEC/backup": 1,
                                           "G/SEC/backup/parts": 1,
                                           "G/SEC/backup/claims": ["SEC-2", "SEC-1"]})
        # The charge beside it still counts as a charge.
        self.assertEqual(1, budget.count(path, "G/SEC/backup", self.WHAT))

    def test_a_recorded_value_is_a_count_or_a_list_of_ids_and_nothing_else(self):
        path = self.path()
        # An empty list too (#3697 N2): its reader takes it for no record at all.
        for value in ([], [1], [""], ["a", ""], ["a", None], ["a", ["b"]], ("a",), {"a": 1},
                      {"a"}, "a", b"a"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as caught:
                    budget.bump_many(path, ["G/SEC/backup"], self.WHAT,
                                     record={"G/SEC/backup/claims": value})
                self.assertIn("a count or a non-empty list of non-empty strings",
                              str(caught.exception))
                self.assertFalse(os.path.exists(path))

    def test_a_planted_value_of_the_other_kind_refuses(self):
        for key, planted, value, kind in (
                ("G/SEC/backup/claims", 3, ["SEC-1"], "a list of ids"),
                ("G/SEC/backup/claims", ["SEC-1", 2], ["SEC-1"], "a list of ids"),
                ("G/SEC/backup/claims", "SEC-1", ["SEC-1"], "a list of ids"),
                ("G/SEC/backup/claims", [], ["SEC-1"], "a list of ids"),
                ("G/SEC/backup/parts", ["SEC-1"], 2, "a count")):
            with self.subTest(key=key, planted=planted):
                path = self.plant(self.path(), {key: planted})
                with self.assertRaises(runio.DriverError) as caught:
                    budget.bump_many(path, ["G/SEC/backup"], self.WHAT, record={key: value})
                self.assertIn("key %s is not %s" % (key, kind), str(caught.exception))
                self.assertEqual({key: planted}, self.read(path))

    def test_a_recorded_value_must_be_a_count(self):
        path = self.path()
        for value in (True, -1, 1.0, "2", None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    budget.bump_many(path, ["G/SEC/backup"], self.WHAT,
                                     record={"G/SEC/backup/parts": value})
                self.assertFalse(os.path.exists(path))

    def test_a_planted_recorded_key_refuses_like_a_planted_charge(self):
        path = self.plant(self.path(), {"G/SEC/backup/parts": "many"})
        with self.assertRaises(runio.DriverError):
            budget.bump_many(path, ["G/SEC/backup"], self.WHAT,
                             record={"G/SEC/backup/parts": 2})

    def test_bump_many_with_no_keys_writes_nothing(self):
        path = self.path()
        self.assertEqual(budget.bump_many(path, [], self.WHAT), {})
        self.assertFalse(os.path.exists(path))


class TestADispatchIsChargedWhenItIsHandedOut(BudgetCase):
    """#3740: the marks that tell a new hand-out from one emitted again. The charge was
    made on every planning, so a run stopped before its launch, and a session re-entered
    before its agents had finished, spent a dispatch each time with nothing launched."""

    def _entry(self, name="review-app-SEC"):
        return {"id": name, "out_file": os.path.join(self.root, ".panopticon", name + ".json")}

    def _marks(self):
        with open(runio._pano(self.root, budget.MARKS_FILE), encoding="utf-8") as fh:
            return json.load(fh)

    def _emit(self, entries):
        """One planning, as a phase does it: which are new, (the charge), the marks."""
        charged = budget.new_handouts(self.root, entries)
        budget.mark_handouts(self.root, entries, charged, lambda entry: "book:" + entry["id"])
        return [entry["id"] for entry in charged]

    def _land(self, entry, text):
        with open(entry["out_file"], "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_the_first_emission_is_charged_and_the_same_one_again_is_not(self):
        a, b = self._entry("a"), self._entry("b")
        self.assertFalse(os.path.lexists(runio._pano(self.root, budget.MARKS_FILE)))
        self.assertEqual(["a", "b"], self._emit([a, b]))
        self.assertEqual({"a": 0, "b": 0}, budget.handouts_reemitted(self.root, [a, b]))
        for again in (1, 2, 3):
            self.assertEqual([], self._emit([a, b]))
            self.assertEqual({"a": again, "b": again}, budget.handouts_reemitted(self.root, [a, b]))
        # A later emission with one entry more charges that one alone.
        c = self._entry("c")
        self.assertEqual(["c"], self._emit([a, c]))
        self.assertEqual({"a": 4, "b": 3, "c": 0}, budget.handouts_reemitted(self.root, [a, b, c]))

    def test_an_output_that_landed_and_left_the_entry_pending_is_a_new_dispatch(self):
        entry = self._entry()
        self.assertEqual([entry["id"]], self._emit([entry]))
        self._land(entry, "not what was asked for")
        self.assertEqual([entry["id"]], self._emit([entry]))            # it came back, bad
        self.assertEqual(0, budget.handouts_reemitted(self.root, [entry])[entry["id"]])
        self.assertEqual([], self._emit([entry]))                       # nothing since
        self._land(entry, "another answer, also not it")                 # a different size
        self.assertEqual([entry["id"]], self._emit([entry]))
        # The same bytes moved over it again are a new file: its inode changed.
        replacement = entry["out_file"] + ".tmp"
        with open(replacement, "w", encoding="utf-8") as fh:
            fh.write("another answer, also not it")
        os.utime(replacement, ns=(os.stat(entry["out_file"]).st_atime_ns,
                                  os.stat(entry["out_file"]).st_mtime_ns))
        os.replace(replacement, entry["out_file"])
        self.assertEqual([entry["id"]], self._emit([entry]))
        # ...and so is the same file with a later time.
        found = os.stat(entry["out_file"])
        os.utime(entry["out_file"], ns=(found.st_atime_ns, found.st_mtime_ns + 1))
        self.assertEqual([entry["id"]], self._emit([entry]))
        os.remove(entry["out_file"])                                     # taken away again
        self.assertEqual([entry["id"]], self._emit([entry]))

    def test_a_refused_reply_is_a_dispatch_that_ended(self):
        import scripts.phases.rejected_replies as rejected_replies
        entry = self._entry()
        self.assertEqual([entry["id"]], self._emit([entry]))
        for attempt in (1, 2):
            kept = rejected_replies.retain_rejected(
                persist.run_dir(self.root), entry, "a reply nobody could take", "shape",
                kind=rejected_replies.REFUSAL, run_id="r")
            self.assertTrue(kept)
            self.assertEqual(attempt, budget.handout_state(self.root, entry)["rejected"])
            self.assertEqual([entry["id"]], self._emit([entry]))
            self.assertEqual([], self._emit([entry]))

    def test_one_id_handed_out_for_another_file_is_a_new_dispatch(self):
        # A tool advisor's second ask has the first's id and writes beside its answer.
        first = self._entry("verify-tool-q")
        second = dict(first, out_file=first["out_file"] + ".lift")
        self.assertEqual(["verify-tool-q"], self._emit([first]))
        self.assertEqual(["verify-tool-q"], self._emit([second]))
        self.assertEqual([], self._emit([second]))

    def test_an_ended_hand_out_is_charged_the_next_time_whatever_it_left(self):
        a, b = self._entry("a"), self._entry("b")
        self._emit([a, b])
        self.assertEqual(["a"], budget.handouts_ended(self.root, [a, {"id": "never-marked"}]))
        self.assertEqual(["b"], sorted(self._marks()))
        self.assertEqual(["a"], self._emit([a, b]))
        before = os.stat(runio._pano(self.root, budget.MARKS_FILE)).st_mtime_ns
        self.assertEqual([], budget.handouts_ended(self.root, [{"id": "never-marked"}]))
        self.assertEqual(before, os.stat(runio._pano(self.root, budget.MARKS_FILE)).st_mtime_ns)

    def test_a_give_back_ends_the_hand_out_too(self):
        cell = {"id": "review-app-SEC", "group": "app", "domain": "SEC",
                "out_file": os.path.join(self.root, ".panopticon", "findings-app-SEC.json")}
        tool = {"id": verify.verify_tools.TOOL_ENTRY_PREFIX + "q",
                "out_file": os.path.join(self.root, ".panopticon", "q.json")}
        for checkpoint, entry, counted in (
                ("review", cell, lambda: review._cell_attempts(self.root).get("app/SEC")),
                ("verify", tool, lambda: verify._verify_attempts_key(self.root, "tool/q"))):
            with self.subTest(checkpoint=checkpoint):
                charge = (lambda: review._record_attempts(self.root, ["app/SEC"])
                          ) if checkpoint == "review" else None
                if checkpoint == "review":
                    self.assertEqual([entry["id"]], self._emit([entry]))
                    charge()
                else:
                    verify._charge_verify_dispatch(self.root, [entry])
                self.assertEqual(1, counted())
                persist.rollback_markers(self.root, checkpoint, [entry])
                self.assertEqual(0, counted())
                self.assertNotIn(entry["id"], self._marks())

    def test_the_mark_holds_what_was_on_disk_when_it_was_handed_out(self):
        entry = self._entry()
        self._emit([entry])
        self.assertEqual({entry["id"]: {"key": "book:" + entry["id"], "reemitted": 0, "state": {
            "file": entry["out_file"], "out": None, "rejected": 0}}}, self._marks())
        self._land(entry, "x" * 7)
        self._emit([entry])
        found = os.stat(entry["out_file"])
        self.assertEqual([7, found.st_mtime_ns, found.st_ino], self._marks()[entry["id"]]["state"]["out"])

    def test_a_budget_is_outstanding_while_one_of_its_dispatches_is_still_out(self):
        part0, part1 = self._entry("cell-part0"), self._entry("cell-part1")
        other = self._entry("other")

        def key(entry):
            return "book:other" if entry is other else "book:cell"

        charged = budget.new_handouts(self.root, [part0, part1, other])
        budget.mark_handouts(self.root, [part0, part1, other], charged, key)
        self.assertTrue(budget.outstanding(self.root, "book:cell"))
        self.assertTrue(budget.outstanding(self.root, "book:other"))
        self.assertFalse(budget.outstanding(self.root, "book:nobody"))
        self.assertFalse(budget.outstanding(self.root, "cell"))
        self._land(part0, "an answer")                      # one part is in; one is still out
        self.assertTrue(budget.outstanding(self.root, "book:cell"))
        self._land(part1, "an answer")
        self.assertFalse(budget.outstanding(self.root, "book:cell"))
        self.assertTrue(budget.outstanding(self.root, "book:other"))
        budget.handouts_ended(self.root, [other])
        self.assertFalse(budget.outstanding(self.root, "book:other"))

    def test_each_budget_names_its_own_keys(self):
        # One marks file holds both budgets' keys, so each says whose a key is.
        self.assertEqual("review:app/SEC", review._budget_key({"group": "app", "domain": "SEC"}))
        self.assertIsNone(review._budget_key({"group": "app"}))
        self.assertEqual("verify:app/SEC/primary", verify._budget_key(
            {"group": "app", "domain": "SEC", "stage": "primary"}))
        self.assertEqual("verify:tool/q", verify._budget_key(
            {"id": verify.verify_tools.TOOL_ENTRY_PREFIX + "q"}))
        self.assertIsNone(verify._budget_key({"id": "review-app-SEC"}))

    def test_an_entry_its_budget_gives_no_key_for_gets_no_mark(self):
        entry = self._entry("setup-scan")
        budget.mark_handouts(self.root, [entry], [entry], lambda entry: None)
        self.assertFalse(os.path.lexists(runio._pano(self.root, budget.MARKS_FILE)))

    def test_an_entry_with_no_id_is_neither_charged_nor_marked(self):
        self.assertEqual([], self._emit([{"out_file": "x"}, {"id": ""}, {"id": 7}, "entry", None]))
        self.assertEqual([], budget.new_handouts(self.root, None))
        self.assertFalse(os.path.lexists(runio._pano(self.root, budget.MARKS_FILE)))

    def test_a_mark_that_is_not_one_refuses_on_every_entry_point(self):
        good = {"key": "book:a", "state": {"file": "f", "out": None, "rejected": 0},
                "reemitted": 0}
        entry = self._entry("a")
        for planted in ("outstanding", 1, None, [], {}, dict(good, reemitted=-1),
                        dict(good, reemitted=True), dict(good, reemitted="0"),
                        dict(good, extra=1), {"state": good["state"], "key": "k"},
                        {"state": good["state"], "reemitted": 0}, dict(good, key=""),
                        dict(good, key=7),
                        dict(good, state="unchanged"), dict(good, state={"out": None, "rejected": 0}),
                        dict(good, state=dict(good["state"], file=7)),
                        dict(good, state=dict(good["state"], rejected=-1)),
                        dict(good, state=dict(good["state"], rejected=False)),
                        dict(good, state=dict(good["state"], out=[1, 2])),
                        dict(good, state=dict(good["state"], out=[1, 2, "3"])),
                        dict(good, state=dict(good["state"], out=[1, 2, 3, 4])),
                        dict(good, state=dict(good["state"], out="absent")),
                        dict(good, state=dict(good["state"], more=1))):
            runio._write_json(runio._pano(self.root, budget.MARKS_FILE), {"b": good, "a": planted})
            for call in (lambda: budget.new_handouts(self.root, [entry]),
                         lambda: budget.mark_handouts(self.root, [entry], [entry], str),
                         lambda: budget.outstanding(self.root, "book:a"),
                         lambda: budget.handouts_ended(self.root, [entry]),
                         lambda: budget.handouts_reemitted(self.root, [entry])):
                with self.subTest(planted=planted), self.assertRaises(runio.DriverError) as raised:
                    call()
                message = str(raised.exception)
                self.assertIn(budget.MARKS_FILE, message)
                self.assertIn("entry a is not a mark", message)
                self.assertIn("--reset", message)
        # A whole mark of the right shape reads.
        runio._write_json(runio._pano(self.root, budget.MARKS_FILE),
                          {"a": dict(good, state=dict(good["state"], out=[1, 2, 3]))})
        self.assertEqual({"a": 0}, budget.handouts_reemitted(self.root, [entry]))

    def test_a_torn_marks_file_refuses(self):
        os.makedirs(os.path.dirname(runio._pano(self.root, budget.MARKS_FILE)), exist_ok=True)
        with open(runio._pano(self.root, budget.MARKS_FILE), "w", encoding="utf-8") as fh:
            fh.write('{"a": {"state"')
        with self.assertRaisesRegex(runio.DriverError, "the record of dispatches handed out"):
            budget.new_handouts(self.root, [self._entry("a")])

    def test_a_record_is_written_with_no_key_charged(self):
        # An entry emitted again is not charged, and what it was handed is still recorded.
        path = runio._pano(self.root, "attempts.json")
        budget.bump_many(path, ["cell"], "the budget", record={"cell/claims": ["A"]})
        self.assertEqual({}, budget.bump_many(path, [], "the budget", record={"cell/claims": ["A", "B"]}))
        with open(path, encoding="utf-8") as fh:
            self.assertEqual({"cell": 1, "cell/claims": ["A", "B"]}, json.load(fh))


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


class TestEveryCallSiteRefusesAPlantedString(BudgetCase):
    """The triage probe, kept. One row per call site: the budget's own file
    name, its own key scheme and its own `what` string -- all unchanged, because they are the
    on-disk contract a resumed run reads -- and ONE behaviour on a value that
    is not a count."""

    def _budgets(self):
        cell = runio._pano(self.root, review._ATTEMPTS_FILE)
        verify_path = runio._pano(self.root, verify._VERIFY_ATTEMPTS_FILE)
        return (
            ("coverage._bump_scout_attempts",
             runio._pano(self.root, plan_contract.SCOUT_ATTEMPTS_NAME), "Web",
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

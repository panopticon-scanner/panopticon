"""#1912: whose machine wrote a batch record, when the hostname has moved.

The owner stamp (#1698) is a LIVENESS check -- is the process that wrote this
record still running? -- and a pid may only be asked about on the machine that
issued it. `socket.gethostname()` was the whole of "this machine", and on
macOS it is not stable: the same laptop answers `mac.local`, `mac.lan` or a
DHCP-assigned name across a crash and the resume that follows, and the resume
then read its own crash record as another machine's and offered `--reset` --
the whole run of paid cells -- as the only way forward.

These are unit tests on `owner_state` and the id it compares. The integration
shape (a real run folder, a real refusal, `--discard-batch`) lives beside the
other #1698 cases in tests/test_orchestrate.py.

`owner_state`'s two inputs are patched at the MODULE's own names --
`batch.host_id` and `batch.machine_id` -- rather than at `socket.gethostname`
and `uuid.getnode`, which belong to the whole interpreter and which pytest
itself calls. `uuid.getnode` is patched only in the class that is ABOUT
`machine_id`, where it is the thing under test.
"""
import json
import os
import shutil
import tempfile
import unittest
import uuid
from unittest import mock

import scripts.runners.batch as batch_mod
import scripts.write_guard_hook as write_guard_hook
from _test_helpers import dead_pid

# getnode()'s documented random fallback: the multicast bit, set.
RANDOM_NODE = 0x010203040506 | 0x010000000000


class TestTheMachineId(unittest.TestCase):
    def test_a_real_hardware_node_is_a_fixed_width_hex_string(self):
        with mock.patch.object(uuid, "getnode", return_value=0xacde48001122):
            self.assertEqual("acde48001122", batch_mod.machine_id())

    def test_a_small_node_number_is_still_twelve_digits_wide(self):
        # `%012x`, not `hex()`: the stamp is compared as a STRING, so two
        # spellings of the same number must never read as two identities.
        with mock.patch.object(uuid, "getnode", return_value=0x1122):
            self.assertEqual("000000001122", batch_mod.machine_id())

    def test_the_multicast_fallback_is_no_identity_at_all(self):
        # getnode()'s documented fallback when it can find no hardware address:
        # a RANDOM 48-bit number with the multicast bit set, freshly chosen per
        # process. Stamping it would write a value that never matches again --
        # every resume on that machine would read its own record as foreign.
        for node in (0x010000000000, RANDOM_NODE):
            with self.subTest(node=node):
                with mock.patch.object(uuid, "getnode", return_value=node):
                    self.assertIsNone(batch_mod.machine_id())

    def test_a_nonsense_node_is_no_identity_either(self):
        for node in (0, -1, None, "acde48001122", True):
            with self.subTest(node=node):
                with mock.patch.object(uuid, "getnode", return_value=node):
                    self.assertIsNone(batch_mod.machine_id())

    def test_the_stamp_is_twelve_lowercase_hex_digits_whatever_the_node(self):
        # The FORMAT is the contract, because the stamp is compared as a string:
        # one spelling per number, lower case, always twelve wide. (Two calls
        # agreeing is not a contract -- `uuid.getnode` caches in `uuid._node`,
        # so CPython guarantees that whatever this module does. Review round 1,
        # finding 13.)
        # Every node here has bit 40 CLEAR -- `0xab...` would be the multicast
        # fallback and `machine_id()` is None for it (pinned two tests up).
        for node, expected in ((0x1, "000000000001"),
                               (0xaccdef012345, "accdef012345"),
                               (0xACCDEF012345, "accdef012345"),
                               (0xfeffffffffff, "feffffffffff")):
            with self.subTest(node=node):
                with mock.patch.object(uuid, "getnode", return_value=node):
                    stamp = batch_mod.machine_id()
                self.assertEqual(expected, stamp)
                self.assertRegex(stamp, r"^[0-9a-f]{12}$")


class TestTheOwnerStampNamesTheMachineAndNotOnlyTheHostname(unittest.TestCase):
    """#1912 hazard 1: `host` alone was the identity, and it moves."""

    MINE = "acde48001122"

    @classmethod
    def setUpClass(cls):
        cls.dead = dead_pid()

    def _doc(self, **fields):
        doc = {"pid": os.getpid(), "host": "mac.local", "machine": self.MINE}
        doc.update(fields)
        return doc

    def _state(self, doc, *, host="mac.local", machine=MINE):
        with mock.patch.object(batch_mod, "host_id", return_value=host), \
                mock.patch.object(batch_mod, "machine_id", return_value=machine):
            return batch_mod.owner_state(doc)

    def test_the_same_machine_under_a_different_hostname_is_not_foreign(self):
        # The #1912 case: a crash on `mac.office`, a resume on `mac.home`, one
        # laptop. The pid then decides, exactly as it does for a hostname that
        # did not move.
        self.assertEqual(batch_mod.OWNER_LIVE,
                         self._state(self._doc(host="mac.office"), host="mac.home"))
        self.assertEqual(batch_mod.OWNER_DEAD,
                         self._state(self._doc(host="mac.office", pid=self.dead),
                                     host="mac.home"))

    def test_a_different_hostname_and_a_different_machine_is_foreign(self):
        doc = self._doc(host="some-other-box", machine="00deadbeef00")
        self.assertEqual(batch_mod.OWNER_FOREIGN, self._state(doc, host="mac.home"))
        # ...and the pid is not consulted either way: nothing may be concluded
        # from a number issued somewhere else.
        doc = self._doc(host="some-other-box", machine="00deadbeef00", pid=self.dead)
        self.assertEqual(batch_mod.OWNER_FOREIGN, self._state(doc, host="mac.home"))

    def test_a_matching_hostname_is_enough_on_its_own(self):
        # A record from before the field existed, and one whose `machine` the
        # target mangled, are both judged by `host` -- #1698's rule, unchanged.
        for machine in (None, "", "nonsense", 17, ["acde48001122"], {}):
            with self.subTest(machine=machine):
                doc = self._doc()
                if machine is None:
                    doc.pop("machine")
                else:
                    doc["machine"] = machine
                self.assertEqual(batch_mod.OWNER_LIVE, self._state(doc))
                self.assertEqual(batch_mod.OWNER_DEAD,
                                 self._state(dict(doc, pid=self.dead)))

    def test_a_multicast_machine_stamp_is_judged_by_the_hostname_alone(self):
        # Both halves of the fallback: a record CARRYING one, and a resume
        # whose own getnode() returned one (`machine_id()` is None). Neither
        # may stand in for an identity, so `host` is the whole answer.
        doc = self._doc(machine="%012x" % RANDOM_NODE)
        self.assertEqual(batch_mod.OWNER_LIVE, self._state(doc))
        self.assertEqual(batch_mod.OWNER_FOREIGN, self._state(doc, host="elsewhere"))
        doc = self._doc(host="elsewhere")
        self.assertEqual(batch_mod.OWNER_FOREIGN, self._state(doc, machine=None))
        self.assertEqual(batch_mod.OWNER_LIVE,
                         self._state(self._doc(), machine=None))

    def test_an_unstamped_record_stays_unstamped_whatever_the_machine_says(self):
        # `machine` is not a stamp on its own: a record with no usable pid or
        # host is UNSTAMPED, and a matching machine id does not promote it.
        for missing in ("pid", "host"):
            with self.subTest(missing=missing):
                doc = self._doc()
                doc.pop(missing)
                self.assertEqual(batch_mod.OWNER_UNSTAMPED, self._state(doc))
        for pid in (0, -1, True, "1", 1.0, None):
            with self.subTest(pid=pid):
                self.assertEqual(batch_mod.OWNER_UNSTAMPED,
                                 self._state(self._doc(pid=pid)))
        self.assertEqual(batch_mod.OWNER_UNSTAMPED, batch_mod.owner_state("not a dict"))


class TestTheRecordCarriesBothIds(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_the_document_stamps_the_machine_beside_the_host(self):
        batch = batch_mod.Batch(self.root, 1, "review", [])
        with mock.patch.object(batch_mod, "machine_id", return_value="acde48001122"):
            doc = batch.document()
        self.assertEqual("acde48001122", doc["machine"])
        self.assertEqual(batch_mod.host_id(), doc["host"])
        self.assertEqual(os.getpid(), doc["pid"])

    def test_a_machine_with_no_hardware_id_stamps_no_machine_field(self):
        # Absent rather than null: the read side treats the fallback as absent,
        # and writing it down would only invite a later reader to compare it.
        batch = batch_mod.Batch(self.root, 1, "review", [])
        with mock.patch.object(batch_mod, "machine_id", return_value=None):
            self.assertNotIn("machine", batch.document())


class TestTheDiscardAcceptanceFile(unittest.TestCase):
    """#1912: `record_discard`'s three documented properties (review round 1,
    finding 6 -- each was deliberate and none was pinned).

    The file sits in the run folder, INSIDE the reviewed tree, so both its read
    and its write are boundary operations.
    """

    OWNER = {"pid": 4242, "host": "some-other-box", "machine": "00deadbeef00",
             "state": batch_mod.OWNER_FOREIGN}

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = batch_mod.discarded_path(self.root)

    def _read(self):
        with open(self.path, encoding="utf-8") as fh:
            return json.load(fh)

    def _victim(self):
        victim = os.path.join(self.root, "victim.txt")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write("PRECIOUS")
        return victim

    def test_two_acceptances_in_one_run_are_appended_not_replaced(self):
        first = batch_mod.record_discard(self.root, 1, self.OWNER,
                                         at="2026-01-01T00:00:00Z")
        second = batch_mod.record_discard(self.root, 4, dict(self.OWNER, pid=77),
                                          at="2026-01-01T00:05:00Z")
        self.assertEqual([first, second], self._read())
        self.assertEqual([1, 4], [row["batch"] for row in self._read()])
        self.assertEqual(self.OWNER, self._read()[0]["owner"])

    def test_a_symlink_at_the_path_is_replaced_never_written_through(self):
        # The name is fixed and the folder is the target's to commit into, so
        # this link is the target's to plant. `os.replace` renames over the LINK
        # (rename does not dereference) and the read side does not follow it.
        victim = self._victim()
        os.symlink(victim, self.path)
        batch_mod.record_discard(self.root, 2, self.OWNER)
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual("PRECIOUS", fh.read())
        self.assertFalse(os.path.islink(self.path))
        self.assertEqual([2], [row["batch"] for row in self._read()])

    def test_a_link_the_read_would_follow_contributes_nothing(self):
        # ...and a link to a REAL list is not read back either: whatever it
        # pointed at is not this run's acceptance history.
        planted = os.path.join(self.root, "elsewhere.json")
        write_guard_hook._atomic_write_json(planted, [{"batch": 99}])
        os.symlink(planted, self.path)
        batch_mod.record_discard(self.root, 3, self.OWNER)
        self.assertEqual([3], [row["batch"] for row in self._read()])
        self.assertEqual([{"batch": 99}], json.load(open(planted, encoding="utf-8")))

    def test_a_file_that_is_not_a_json_list_is_started_over(self):
        for planted in ('{"batch": 1}', "not json at all", "", "17", '"text"'):
            with self.subTest(planted=planted):
                with open(self.path, "w", encoding="utf-8") as fh:
                    fh.write(planted)
                batch_mod.record_discard(self.root, 5, self.OWNER)
                self.assertEqual([5], [row["batch"] for row in self._read()])

    def test_the_acceptance_carries_the_stamp_and_a_utc_timestamp(self):
        entry = batch_mod.record_discard(self.root, 6, self.OWNER)
        self.assertEqual({"batch", "owner", "accepted_at"}, set(entry))
        self.assertEqual(self.OWNER, entry["owner"])
        self.assertRegex(entry["accepted_at"],
                         r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


if __name__ == "__main__":
    unittest.main()

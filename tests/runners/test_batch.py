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
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock

import scripts.runners.batch as batch_mod

# getnode()'s documented random fallback: the multicast bit, set.
RANDOM_NODE = 0x010203040506 | 0x010000000000


def _dead_pid():
    """A pid that is certainly not running: a child spawned and reaped."""
    proc = subprocess.Popen([sys.executable, "-c", ""])
    proc.wait()
    return proc.pid


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

    def test_this_machine_answers_the_same_way_twice(self):
        # Unpatched, on whatever machine the suite is running on: the point of
        # the field is that it does NOT move between two calls.
        self.assertEqual(batch_mod.machine_id(), batch_mod.machine_id())


class TestTheOwnerStampNamesTheMachineAndNotOnlyTheHostname(unittest.TestCase):
    """#1912 hazard 1: `host` alone was the identity, and it moves."""

    MINE = "acde48001122"

    @classmethod
    def setUpClass(cls):
        cls.dead = _dead_pid()

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


if __name__ == "__main__":
    unittest.main()

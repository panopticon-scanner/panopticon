"""#3611 native Semgrep parser gaps: producer facts and deterministic routing."""
import os
import tempfile
import unittest
from unittest import mock

from scripts import native_unparsed


class NativeUnparsedFactsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _write(self, rel, body="x\n"):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path) or self.root, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)

    def test_producer_classifies_native_extensions_and_extensionless_shebang(self):
        self._write("src/broken.js")
        self._write("README.md")
        self._write("bin/launch", "#!/usr/bin/env bash\necho ready\n")
        facts = native_unparsed.producer_facts(
            self.root, ["README.md", "bin/launch", "src/broken.js"])
        self.assertEqual(native_unparsed.read_facts(self.root, facts), {
            "count": 2,
            "files": [
                {"file": "bin/launch", "language": "Shell"},
                {"file": "src/broken.js", "language": "JavaScript"},
            ],
            "files_omitted": 0,
            "unknown": 0,
        })

    def test_unmapped_extension_shebang_promotes_the_file_to_native(self):
        # N1: Semgrep selects executable languages by shebang even when the
        # suffix is not in our map. The shared classifier must do the same.
        self._write("bin/deploy.prod", "#!/bin/bash\necho ready\n")
        state = native_unparsed.read_facts(
            self.root,
            native_unparsed.producer_facts(self.root, ["bin/deploy.prod"]),
        )
        self.assertEqual(state["files"], [
            {"file": "bin/deploy.prod", "language": "Shell"}
        ])

    def test_failed_shebang_read_does_not_demote_an_unmapped_extension(self):
        # The pre-N1 answer for an unmapped suffix was known non-native. A
        # missing/unreadable optional shebang probe must preserve that answer,
        # not turn it into classification_unknown and sink certification.
        facts = native_unparsed.producer_facts(self.root, ["missing.prod"])
        self.assertEqual((facts["native_syntax_files"],
                          facts["native_syntax_unknown"]), (0, 0))

    def test_shebang_reader_rejects_a_fifo_leaf(self):
        # N2: without the descriptor's S_ISREG check, a nonblocking FIFO reads
        # as an empty ordinary file and becomes known-non-native instead of an
        # unclassifiable path.
        path = os.path.join(self.root, "deploy")
        try:
            os.mkfifo(path)
        except (AttributeError, OSError) as exc:
            self.skipTest("FIFOs unavailable: %s" % exc)
        facts = native_unparsed.producer_facts(self.root, ["deploy"])
        self.assertEqual((facts["native_syntax_files"],
                          facts["native_syntax_unknown"]), (0, 1))

    def test_shebang_reader_rejects_a_directory_leaf_before_reading(self):
        # N2: make the S_ISREG guard observable even on hosts where read(2) on
        # a directory independently fails. Removing the guard would feed the
        # planted shebang through the mocked read and misclassify the leaf.
        os.makedirs(os.path.join(self.root, "deploy"))
        with mock.patch("scripts.native_language.os.read",
                        return_value=b"#!/bin/sh\n") as read:
            facts = native_unparsed.producer_facts(self.root, ["deploy"])
        read.assert_not_called()
        self.assertEqual((facts["native_syntax_files"],
                          facts["native_syntax_unknown"]), (0, 1))

    def test_absolute_cap_is_strictly_more_than_twenty(self):
        for i in range(21):
            self._write("src/f%02d.js" % i)
        twenty = native_unparsed.read_facts(
            self.root,
            native_unparsed.producer_facts(
                self.root, ["src/f%02d.js" % i for i in range(20)]))
        twenty_one = native_unparsed.read_facts(
            self.root,
            native_unparsed.producer_facts(
                self.root, ["src/f%02d.js" % i for i in range(21)]))
        self.assertEqual((len(twenty["files"]), twenty["files_omitted"]), (20, 0))
        self.assertEqual((len(twenty_one["files"]), twenty_one["files_omitted"]),
                         (21, 0))

    def test_consumer_rejects_malformed_or_reclassified_facts(self):
        self._write("src/broken.js")
        good = native_unparsed.producer_facts(self.root, ["src/broken.js"])
        for patch in (
                {"native_syntax_files": True},
                {"native_syntax_files_omitted": 1},
                {"native_syntax": [{"file": "src/broken.js", "language": "Python"}]},
                {"native_syntax_unknown": -1}):
            with self.subTest(patch=patch):
                self.assertIsNone(native_unparsed.read_facts(
                    self.root, dict(good, **patch)))

    def test_consumer_rebuilds_a_complete_listing_and_rejects_an_omitted_native_file(self):
        self._write("src/broken.js")
        facts = native_unparsed.producer_facts(self.root, ["src/broken.js"])
        facts.update({
            "syntax_error_files": 1,
            "files": [{"file": "src/broken.js", "reason": "syntax_error",
                       "syntax_errors": 1}],
            "files_omitted": 0,
            "native_syntax_files": 0,
            "native_syntax": [],
        })
        self.assertIsNone(native_unparsed.read_facts(self.root, facts))

    def test_extensionless_shebang_read_refuses_a_symlinked_parent(self):
        self._write("real/launch", "#!/usr/bin/env bash\necho ready\n")
        try:
            os.symlink(os.path.join(self.root, "real"),
                       os.path.join(self.root, "linked"))
        except (OSError, NotImplementedError) as exc:
            self.skipTest("symlinks unavailable: %s" % exc)
        facts = native_unparsed.producer_facts(self.root, ["linked/launch"])
        self.assertEqual((facts["native_syntax_files"],
                          facts["native_syntax_unknown"]), (0, 1))

    def test_control_bearing_path_is_unknown_not_a_report_target(self):
        facts = native_unparsed.producer_facts(self.root, ["src/evil\u202e.js"])
        self.assertEqual((facts["native_syntax_files"], facts["native_syntax"],
                          facts["native_syntax_unknown"]), (0, [], 1))

    def test_group_routing_names_every_covering_group(self):
        self._write("src/broken.js")
        state = native_unparsed.read_facts(
            self.root, native_unparsed.producer_facts(self.root, ["src/broken.js"]))
        groups = [{"name": "Web", "files": ["src/broken.js"]},
                  {"name": "Shared", "files": ["src/broken.js", "src/ok.js"]},
                  {"name": "Docs", "files": ["README.md"]}]
        self.assertEqual(native_unparsed.targets_by_group(state, groups),
                         {"Shared": ["src/broken.js"], "Web": ["src/broken.js"]})

    def test_over_cap_is_not_dispatched_to_reviewers(self):
        for i in range(21):
            self._write("src/f%02d.js" % i)
        state = native_unparsed.read_facts(
            self.root,
            native_unparsed.producer_facts(
                self.root, ["src/f%02d.js" % i for i in range(21)]))
        self.assertEqual(native_unparsed.targets_by_group(
            state, [{"name": "Web", "files": ["src/f%02d.js" % i for i in range(21)]}]), {})

    def test_completed_exact_sec_attestation_covers_the_target(self):
        self._write("src/broken.js")
        state = native_unparsed.read_facts(
            self.root, native_unparsed.producer_facts(self.root, ["src/broken.js"]))
        groups = [{"name": "Web", "files": ["src/broken.js"]}]
        plan = [{"group": "Web", "domain": "SEC",
                 "targeted_review": ["src/broken.js"]}]
        block, gap = native_unparsed.reconcile(
            state, groups, plan, {("Web", "SEC"): ("src/broken.js",)})
        self.assertIsNone(gap)
        self.assertEqual(block["files"][0]["covered_by"], [["Web", "SEC"]])

    def test_missing_or_failed_in_scope_cell_leaves_target_uncovered(self):
        self._write("src/broken.js")
        state = native_unparsed.read_facts(
            self.root, native_unparsed.producer_facts(self.root, ["src/broken.js"]))
        cases = [
            ([{"name": "Web", "files": ["src/broken.js"]}],
             [{"group": "Web", "domain": "SEC",
               "targeted_review": ["src/broken.js"]}], {}),
            ([{"name": "Web", "files": ["src/broken.js"]}], [], {}),
        ]
        for groups, plan, attestations in cases:
            with self.subTest(groups=groups, plan=plan):
                block, gap = native_unparsed.reconcile(
                    state, groups, plan, attestations)
                self.assertIn("not covered", gap)
                self.assertEqual(block["files"][0]["covered_by"], [])

    def test_outside_matrix_gap_is_warning_only_and_does_not_consume_the_cap(self):
        outside = ["testdata/f%02d.js" % i for i in range(21)]
        for path in outside:
            self._write(path)
        self._write("src/broken.js")
        state = native_unparsed.read_facts(
            self.root,
            native_unparsed.producer_facts(
                self.root, outside + ["src/broken.js"]),
        )
        groups = [{"name": "Web", "files": ["src/broken.js"]}]
        plan = [{"group": "Web", "domain": "SEC",
                 "targeted_review": ["src/broken.js"]}]
        block, gap = native_unparsed.reconcile(
            state, groups, plan, {("Web", "SEC"): ("src/broken.js",)})
        self.assertIsNone(gap)
        self.assertEqual((block["native_unparsed"], block["over_cap"]), (1, False))
        self.assertEqual(block["files"][0]["file"], "src/broken.js")
        self.assertEqual(
            (block["out_of_scope"]["count"],
             len(block["out_of_scope"]["files"]),
             block["out_of_scope"]["files_omitted"]),
            (21, 20, 1),
        )

    def test_dispatch_or_attestation_mismatch_fails_closed(self):
        self._write("src/broken.js")
        state = native_unparsed.read_facts(
            self.root, native_unparsed.producer_facts(self.root, ["src/broken.js"]))
        groups = [{"name": "Web", "files": ["src/broken.js"]}]
        bad_plan = [{"group": "Web", "domain": "SEC",
                     "targeted_review": ["src/other.js"]}]
        _block, plan_gap = native_unparsed.reconcile(state, groups, bad_plan, {})
        self.assertIn("dispatch did not match", plan_gap)
        good_plan = [{"group": "Web", "domain": "SEC",
                      "targeted_review": ["src/broken.js"]}]
        _block, echo_gap = native_unparsed.reconcile(
            state, groups, good_plan, {("Web", "SEC"): ("src/other.js",)})
        self.assertIn("invalid targeted-review attestation", echo_gap)

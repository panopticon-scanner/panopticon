"""#3231 part A: the tool advisor's read fence is its claim's cell PLUS the backup
round's bounded closure (A1), and a NEEDS_MORE_INFO that names the files it could
not reach earns one re-dispatch with them, charged to the item's own budget (A2)."""
import os
import shutil
import tempfile
import unittest
from unittest import mock

import scripts.evidence as evidence
import scripts.phases.evidence_scope as evidence_scope
import scripts.phases.runio as runio
import scripts.phases.verify as verify
import scripts.phases.verify_tools as verify_tools

QID = "0123456789abcdef"


def _finding(file="synth/render.py", **kw):
    f = {"id": "SG-1", "severity": "HIGH", "source": "tool:semgrep",
         "title": "hooks path traversal", "category": "x",
         "location": {"file": file, "line_start": 3}}
    f.update(kw)
    return f


class _Tree(unittest.TestCase):
    """`Synth` holds render.py, which reaches `reconcile` through a FUNCTION-LEVEL
    import (the issue's first example); `Core` holds reconcile.py; `Phases` holds
    child.py, whose callers live in `Driver` (the second example)."""

    FILES = {
        "synth/render.py": "def f():\n    import reconcile\n    return reconcile.g()\n",
        "synth/other.py": "X = 1\n",
        "reconcile.py": "def g():\n    return 1\n",
        "phases/child.py": "import subprocess\n",
        "driver/caller.py": "from phases import child\n",
        "driver/second.py": "Y = 2\n",
    }
    GROUPS = [{"name": "Synth", "files": ["synth/render.py", "synth/other.py", "reconcile_alias.py"]},
              {"name": "Core", "files": ["reconcile.py"]},
              {"name": "Phases", "files": ["phases/child.py"]},
              {"name": "Driver", "files": ["driver/caller.py", "driver/second.py"]}]

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        os.makedirs(runio._pano(self.root), exist_ok=True)
        for rel, text in self.FILES.items():
            path = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        groups = [dict(g, files=[f for f in g["files"] if f in self.FILES]) for g in self.GROUPS]
        runio._write_json(runio._pano(self.root, "groups.json"), {"groups": groups})

    def _abs(self, rel):
        return os.path.join(self.root, rel)

    def _entry(self, finding=None, lift=None):
        return verify_tools._tool_verify_entry(self.root, {"run_id": "r"}, QID,
                                               finding or _finding(), "claude", lift)

    def _verdict(self, verdict="NEEDS_MORE_INFO", missing=None):
        body = {"finding_id": "SG-1", "verdict": verdict, "confidence": "POSSIBLE",
                "reasoning": "r", "explored": [], "references": [], "citations": {}}
        if missing is not None:
            body["missing_evidence"] = missing
        os.makedirs(os.path.dirname(verify_tools._tool_verdict_out_file(self.root, QID)),
                    exist_ok=True)
        runio._write_json(verify_tools._tool_verdict_out_file(self.root, QID), body)

    def _spent(self, n):
        for _ in range(n):
            verify._charge_verify_dispatch(self.root, [{"id": verify_tools.TOOL_ENTRY_PREFIX + QID}])

    def _attempts(self):
        return verify._verify_attempts_key(self.root, "tool/%s" % QID)


class ClosureTest(_Tree):
    def test_the_fence_is_the_cell_plus_the_one_hop_closure(self):
        entry = self._entry()
        files = set(entry["scope"]["files"])
        self.assertTrue({self._abs("synth/render.py"), self._abs("synth/other.py"),
                         self._abs("reconcile.py")} <= files)
        self.assertNotIn(self._abs("driver/caller.py"), files)
        self.assertIn(verify_tools._CLOSURE_HEADING, entry["prompt"])
        self.assertIn(self._abs("reconcile.py"), entry["prompt"])

    def test_a_named_path_outside_the_root_is_never_granted(self):
        entry = self._entry(_finding(description="see ../../outside.py and /etc/passwd.py"))
        self.assertFalse([f for f in entry["scope"]["files"]
                          if not f.startswith(self.root + os.sep)])

    def test_a_claim_with_nothing_outside_its_cell_carries_no_block(self):
        entry = self._entry(_finding(file="synth/other.py"))
        self.assertNotIn(verify_tools._CLOSURE_HEADING, entry["prompt"])
        self.assertEqual(sorted([self._abs("synth/other.py"), self._abs("synth/render.py")]),
                         sorted(entry["scope"]["files"]))

    def test_an_escaping_cited_file_still_confines_to_nothing(self):
        entry = self._entry(_finding(file="../../etc/shadow"))
        self.assertEqual([], entry["scope"]["files"])


class LiftTest(_Tree):
    def _child(self):
        return _finding(file="phases/child.py", title="Popen audit")

    def test_a_needs_more_info_naming_a_file_earns_one_re_dispatch_with_it(self):
        self._spent(1)
        self._verdict(missing=[self._abs("driver/caller.py")])
        self.assertEqual([self._abs("driver/caller.py")],
                         verify_tools._lift_owed(self.root, QID, self._child()))
        with mock.patch.object(verify_tools, "_tool_verify_queue",
                               return_value=[(QID, self._child())]):
            self.assertFalse(verify_tools._verify_tools_done(self.root, {"run_id": "r"}))
        captured = []
        with mock.patch.object(verify_tools, "_tool_verify_queue",
                               return_value=[(QID, self._child())]), \
                mock.patch.object(verify_tools.requests, "write_dispatch_request_bound",
                                  side_effect=lambda *a: captured.append(a[4]) or ("req", "sha")):
            result = verify_tools._verify_tools_execute(self.root, {"run_id": "r"}, "claude")
        self.assertEqual("checkpoint", result.kind)
        (entry,) = captured[0]
        self.assertIn(self._abs("driver/caller.py"), entry["scope"]["files"])
        self.assertIn(verify_tools._LIFTED, entry["prompt"])
        self.assertEqual(2, self._attempts())           # charged to the item's own budget

    def test_the_lift_is_owed_once(self):
        self._spent(2)
        self._verdict(missing=[self._abs("driver/caller.py")])
        self.assertIsNone(verify_tools._lift_owed(self.root, QID, self._child()))
        with mock.patch.object(verify_tools, "_tool_verify_queue",
                               return_value=[(QID, self._child())]):
            self.assertTrue(verify_tools._verify_tools_done(self.root, {"run_id": "r"}))

    def test_an_interrupted_lift_is_owed_again(self):
        self._spent(2)
        verify._give_back_verify_dispatch(self.root, [{"id": verify_tools.TOOL_ENTRY_PREFIX + QID}])
        self._verdict(missing=[self._abs("driver/caller.py")])
        self.assertIsNotNone(verify_tools._lift_owed(self.root, QID, self._child()))

    def test_names_that_grant_nothing_new_earn_nothing(self):
        self._spent(1)
        for missing in ([self._abs("phases/child.py")],          # already in the cell
                        ["does/not/exist.py"],                    # resolves to nothing
                        ["/etc/passwd"],                          # outside the root
                        []):
            with self.subTest(missing=missing):
                self._verdict(missing=missing)
                self.assertIsNone(verify_tools._lift_owed(self.root, QID, self._child()))

    def test_a_decided_verdict_is_never_lifted(self):
        self._spent(1)
        for verdict in ("CONFIRMED", "REJECTED"):
            with self.subTest(verdict=verdict):
                self._verdict(verdict, missing=[self._abs("driver/caller.py")])
                self.assertIsNone(verify_tools._lift_owed(self.root, QID, self._child()))

    def test_the_lift_is_capped_like_any_closure(self):
        names = []
        for n in range(evidence_scope.CAP + 8):
            rel = "extra/m%02d.py" % n
            path = self._abs(rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("Z = %d\n" % n)
            names.append(rel)
        cell = [self._abs("phases/child.py")]
        base, _ = verify_tools._tool_closure(self.root, self._child(), cell)
        lifted, _ = verify_tools._tool_closure(self.root, self._child(), cell, names)
        self.assertEqual(evidence_scope.CAP, len(set(lifted) - set(base)))

    def test_the_report_says_what_a_tool_advisor_could_not_see(self):
        verdict = {"verdict": "NEEDS_MORE_INFO", "reasoning": "r",
                   "missing_evidence": ["driver/caller.py"]}
        tool = evidence.derive_evidence(_finding(), verdict)
        self.assertEqual(("needs_more_info", ["driver/caller.py"]),
                         (tool["status"], tool.get("missing_evidence")))
        agent = evidence.derive_evidence(_finding(source="agent:sr"), verdict)
        self.assertNotIn("missing_evidence", agent)
        many = dict(verdict, missing_evidence=["f%d.py" % n for n in range(40)])
        self.assertEqual(evidence.SCOPE_NAMES_SHOWN,
                         len(evidence.derive_evidence(_finding(), many)["missing_evidence"]))

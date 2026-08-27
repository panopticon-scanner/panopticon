import json
import os
import tempfile
import unittest

import scripts.evidence as evidence


def _finding(fid, sev, **kw):
    f = {"id": fid, "title": "t", "severity": sev, "confidence": "POSSIBLE",
         "panel": "security", "category": "injection",
         "location": {"file": "app.py", "line_start": 10}}
    f.update(kw)
    return f


class TestTriagePriority(unittest.TestCase):
    def test_priority_ordering(self):
        self.assertEqual(evidence.triage_priority(
            _finding("A-001", "CRITICAL", corroborated=True)), 0)
        self.assertEqual(evidence.triage_priority(
            _finding("A-002", "HIGH", reinforced=True)), 0)
        self.assertEqual(evidence.triage_priority(_finding("A-003", "HIGH")), 1)
        self.assertEqual(evidence.triage_priority(
            _finding("A-004", "MEDIUM", corroborated=True)), 2)
        self.assertGreater(evidence.triage_priority(_finding("A-005", "MEDIUM")),
                           evidence.triage_priority(
                               _finding("A-004", "MEDIUM", corroborated=True)))
        self.assertGreater(evidence.triage_priority(_finding("A-006", "LOW")),
                           evidence.triage_priority(_finding("A-005", "MEDIUM")))


class TestBuildVerifyQueue(unittest.TestCase):
    def test_empty_findings_yields_empty_queue(self):
        # #run7 TST-A2D: the empty-input boundary was never exercised (35 call
        # sites, none with []). Must be ([], 0) -- no unguarded entries[0], the
        # cut stays 0, the collision counter starts empty.
        self.assertEqual(evidence.build_verify_queue([]), ([], 0))
        self.assertEqual(evidence.build_verify_queue([], max_verify=3), ([], 0))

    def test_tool_and_agentic_findings_both_queued(self):
        # P2 (#446): tool-sourced findings are claims like any other now --
        # they queue for advisor verification instead of being excluded.
        fs = [_finding("T-001", "HIGH", source="tool:semgrep"),
              _finding("AG-001", "LOW")]
        entries, cut = evidence.build_verify_queue(fs)
        self.assertEqual(cut, 0)
        # List, not set: order is fully determined by triage_priority
        # (HIGH=1 before LOW=6), and deterministic ordering is this module's
        # entire thesis -- a set comparison would pass on a queue that had
        # gone back to depending on input order.
        self.assertEqual([e["finding"]["id"] for e in entries],
                         ["T-001", "AG-001"])

    def test_self_asserted_confirmed_still_queued(self):
        f = _finding("AG-002", "HIGH",
                     provenance={"discovered_by": "agent:panel_review",
                                 "confirmation_status": "CONFIRMED"})
        entries, _ = evidence.build_verify_queue([f])
        self.assertEqual(len(entries), 1)

    def test_priority_sorted_and_queue_ids_assigned(self):
        fs = [_finding("AG-010", "LOW"),
              _finding("AG-011", "CRITICAL", corroborated=True),
              _finding("AG-012", "HIGH")]
        entries, _ = evidence.build_verify_queue(fs)
        self.assertEqual([e["finding"]["id"] for e in entries],
                         ["AG-011", "AG-012", "AG-010"])
        # queue_id is the finding's content fingerprint (#443), not a
        # position-based "NNN-id" -- all three share one fingerprint here
        # (same panel/category/file/title), so a stable -<n> collision
        # suffix distinguishes them (asserted by TestQueueIdentity below).
        base = evidence.finding_fingerprint(fs[1])
        self.assertEqual(entries[0]["queue_id"], base)
        self.assertEqual(entries[1]["queue_id"], base + "-1")

    def test_entries_reference_original_dicts(self):
        f = _finding("AG-020", "HIGH")
        entries, _ = evidence.build_verify_queue([f])
        self.assertEqual(len(entries), 1)   # #run8 TST-B3A: count diff, not IndexError
        self.assertIs(entries[0]["finding"], f)

    def test_max_verify_cuts_lowest_priority(self):
        fs = [_finding("AG-030", "LOW"), _finding("AG-031", "CRITICAL"),
              _finding("AG-032", "HIGH")]
        entries, cut = evidence.build_verify_queue(fs, max_verify=2)
        self.assertEqual(cut, 1)
        self.assertEqual([e["finding"]["id"] for e in entries],
                         ["AG-031", "AG-032"])

    def test_stable_order_for_equal_priority(self):
        fs = [_finding("AG-040", "HIGH"), _finding("AG-041", "HIGH")]
        entries, _ = evidence.build_verify_queue(fs)
        self.assertEqual([e["finding"]["id"] for e in entries],
                         ["AG-040", "AG-041"])

    def test_queue_id_never_embeds_the_raw_finding_id(self):
        # Historically the id component of queue_id embedded the raw finding
        # id verbatim (sanitized) and fed a filename downstream. Now queue_id
        # is a content fingerprint (#443) that never reads finding["id"] at
        # all, so a hostile/nonconforming id (external LLM output; real
        # agents have emitted path-shaped ids) can't leak into a filename via
        # queue_id in the first place.
        f = _finding("../../evil", "HIGH")
        entries, cut = evidence.build_verify_queue([f])
        self.assertEqual(cut, 0)
        # #run8 TST-B3A: cut==0 holds for a wholly EMPTY result too (see
        # test_empty_findings_yields_empty_queue), so it does not establish that
        # entries is non-empty -- guard the index so an empty-queue regression
        # fails as a count diff, not a bare IndexError.
        self.assertEqual(len(entries), 1)
        queue_id = entries[0]["queue_id"]
        self.assertEqual(queue_id, evidence.finding_fingerprint(f))
        self.assertNotIn("/", queue_id)
        self.assertNotIn(".", queue_id)

    def test_reinforced_finding_is_queued(self):
        # P2 (#446): reinforced (tool+agent same-locus merge) findings are
        # claims like any other now -- they queue for advisor verification
        # too. A CONFIRMED verdict is what promotes them to tool_confirmed
        # (see evidence.derive_evidence); reinforcement alone no longer
        # excludes them from the queue.
        fs = [_finding("AG-050", "HIGH", reinforced=True),
              _finding("AG-051", "HIGH")]
        entries, cut = evidence.build_verify_queue(fs)
        self.assertEqual(cut, 0)
        # List, not set: reinforced HIGH is triage_priority 0, plain HIGH is 1,
        # so the order is determined -- and it is the order --max-verify cuts
        # against.
        self.assertEqual([e["finding"]["id"] for e in entries],
                         ["AG-050", "AG-051"])


class TestWriteVerifyQueue(unittest.TestCase):
    def test_writes_payload_and_strips_private_keys(self):
        f = _finding("AG-050", "HIGH", _group="g1", _repo_root="/x")
        entries, cut = evidence.build_verify_queue([f])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "q", "verify-queue.json")
            evidence.write_verify_queue(entries, cut, path)
            with open(path) as fh:
                payload = json.load(fh)
        self.assertEqual(payload["version"], "5.0.1")
        self.assertEqual(payload["cut_by_max_verify"], 0)
        self.assertEqual(len(payload["entries"]), 1)   # #run7 TST-B3A: count diff, not IndexError
        self.assertEqual(payload["entries"][0]["queue_id"],
                         evidence.finding_fingerprint(f))
        self.assertNotIn("_group", payload["entries"][0]["finding"])
        self.assertNotIn("_repo_root", payload["entries"][0]["finding"])


class TestQueueIdentity(unittest.TestCase):
    def _f(self, fid, **over):
        f = {"id": fid, "severity": "HIGH", "panel": "code",
             "category": "logic", "title": "t-" + fid,
             "location": {"file": fid + ".py", "line_start": 1}}
        f.update(over)
        return f

    def _line_by_qid(self, order):
        # #run7 QAL-D1C: shared by the two order-independence collision tests.
        return {e["queue_id"]: e["finding"]["location"]["line_start"]
                for e in evidence.build_verify_queue(order)[0]}

    def test_queue_id_is_the_fingerprint(self):
        f = self._f("A")
        entries, _ = evidence.build_verify_queue([f])
        self.assertEqual(len(entries), 1)   # #run8 TST-B3A: count diff, not IndexError
        self.assertEqual(entries[0]["queue_id"], evidence.finding_fingerprint(f))

    def test_tool_findings_are_queued(self):
        tool = self._f("T", source="tool:bandit",
                       provenance={"confirmation_reasoning": "B105"})
        entries, _ = evidence.build_verify_queue([tool])
        self.assertEqual(len(entries), 1)

    def test_reinforced_findings_are_queued(self):
        entries, _ = evidence.build_verify_queue([self._f("R", reinforced=True)])
        self.assertEqual(len(entries), 1)

    def test_input_order_does_not_change_ids_or_survivors(self):
        findings = [self._f("A"), self._f("B", severity="CRITICAL"),
                    self._f("C", severity="LOW")]
        ids1 = [e["queue_id"] for e in evidence.build_verify_queue(findings)[0]]
        ids2 = [e["queue_id"] for e in
                evidence.build_verify_queue(list(reversed(findings)))[0]]
        self.assertEqual(ids1, ids2)
        cut1 = [e["queue_id"] for e in
                evidence.build_verify_queue(findings, max_verify=2)[0]]
        cut2 = [e["queue_id"] for e in
                evidence.build_verify_queue(list(reversed(findings)), max_verify=2)[0]]
        self.assertEqual(cut1, cut2)          # #438: no filename-order luck

    def test_fingerprint_collision_gets_stable_suffix(self):
        # Same panel+category+file+title => same fingerprint, different ids.
        a = self._f("X")
        b = self._f("Y", title=a["title"],
                    location=dict(a["location"]))
        b["category"] = a["category"]
        entries, _ = evidence.build_verify_queue([a, b])
        ids = sorted(e["queue_id"] for e in entries)
        self.assertEqual(len(set(ids)), 2)
        base = evidence.finding_fingerprint(a)
        self.assertEqual(ids, sorted([base, base + "-1"]))
        again = sorted(e["queue_id"] for e in
                       evidence.build_verify_queue([a, b])[0])
        self.assertEqual(ids, again)          # stable across rebuilds

    def test_collision_suffix_assignment_is_order_independent_by_line(self):
        # Reachable, not theoretical: finding_fingerprint deliberately
        # excludes line numbers, so two findings sharing panel/category/
        # file/title collide by design; if they ALSO share an id (here: both
        # set to "X"), the sort key up to `str(id)` ties completely too.
        # Without a further content tiebreak, `sorted`'s stability means
        # INPUT ORDER alone would decide which finding gets the bare
        # fingerprint vs. `-1` -- so a shuffled input hands each finding the
        # OTHER's advisor verdict. The two findings still differ by line, so
        # a correct fix resolves this deterministically without touching
        # input order at all.
        a = self._f("X")
        b = self._f("Y", title=a["title"], location=dict(a["location"]))
        b["category"] = a["category"]
        b["id"] = a["id"]                    # tie the id too
        b["location"]["line_start"] = 99      # ...but a real line apart
        fp = evidence.finding_fingerprint(a)
        expected = {fp: 1, fp + "-1": 99}

        self.assertEqual(self._line_by_qid([a, b]), expected)
        self.assertEqual(self._line_by_qid([b, a]), expected)

    def test_collision_suffix_assignment_is_order_independent_no_id(self):
        # Same reachable scenario, but via the OTHER way two findings share
        # the id component of the sort key: normalize_finding never assigns
        # a missing id, so two id-less findings tie there too.
        a = self._f("X")
        del a["id"]
        b = self._f("Y", title=a["title"], location=dict(a["location"]))
        b["category"] = a["category"]
        del b["id"]
        b["location"]["line_start"] = 99
        fp = evidence.finding_fingerprint(a)
        expected = {fp: 1, fp + "-1": 99}

        self.assertEqual(self._line_by_qid([a, b]), expected)
        self.assertEqual(self._line_by_qid([b, a]), expected)


class TestBothPassesAgree(unittest.TestCase):
    def _raw(self):
        # Two hits of one rule in one file: pass 2 aggregates these, pass 1
        # historically did not — the exact shape that shifted every id.
        def tool(line):
            return {"id": "T-%d" % line, "source": "tool:bandit",
                    "severity": "HIGH", "panel": "security",
                    "category": "secrets", "title": "hardcoded password",
                    "confidence": "LIKELY",
                    "tool_evidence": {"rule_id": "B105"},
                    "location": {"file": "app.py", "line_start": line}}
        agent = {"id": "A-1", "severity": "MEDIUM", "panel": "code",
                 "category": "logic", "title": "tangled branch",
                 "confidence": "POSSIBLE",
                 "location": {"file": "svc.py", "line_start": 7}}
        return [tool(10), tool(20), agent]

    def test_pass1_and_pass2_build_identical_queue_ids(self):
        import copy
        import scripts.synthesize as syn
        p1, _ = syn.prepare_for_queue(copy.deepcopy(self._raw()))
        p2, _ = syn.prepare_for_queue(copy.deepcopy(self._raw()))
        ids1 = {e["queue_id"] for e in evidence.build_verify_queue(p1)[0]}
        ids2 = {e["queue_id"] for e in evidence.build_verify_queue(p2)[0]}
        self.assertEqual(ids1, ids2)
        self.assertTrue(ids1)

    def test_aggregation_happens_before_the_queue_is_built(self):
        import copy
        import scripts.synthesize as syn
        prepared, _ = syn.prepare_for_queue(copy.deepcopy(self._raw()))
        b105 = [f for f in prepared
                if (f.get("tool_evidence") or {}).get("rule_id") == "B105"]
        self.assertEqual(len(b105), 1)   # 2 hits collapsed to 1 finding


if __name__ == "__main__":
    unittest.main()

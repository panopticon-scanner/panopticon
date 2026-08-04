import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import triage


def fix_row(**over):
    row = {"issue": 443, "set": "FIXME", "verdict": "fix",
           "rationale": "queue identity bug", "duplicate_of": None,
           "fixed_by": None, "spot_check": None, "rank": 1,
           "status": "proposed", "batch": "B1",
           "triaged_at": "2026-08-04T23:00:00Z"}
    row.update(over)
    return row


class TestLedger(unittest.TestCase):
    def test_roundtrip_preserves_rows_and_order(self):
        rows = [fix_row(), fix_row(issue=431, rank=2)]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ledger.jsonl")
            triage.save_rows(rows, path=p)
            self.assertEqual(triage.load_rows(path=p), rows)

    def test_load_missing_file_returns_empty(self):
        self.assertEqual(triage.load_rows(path="/nonexistent/x.jsonl"), [])

    def test_load_skips_blank_lines_and_reports_bad_line_number(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ledger.jsonl")
            with open(p, "w") as fh:
                fh.write(json.dumps(fix_row()) + "\n\n{not json\n")
            with self.assertRaisesRegex(ValueError, "line 3"):
                triage.load_rows(path=p)


class TestValidate(unittest.TestCase):
    def test_valid_fix_row_passes(self):
        triage.validate(fix_row())  # must not raise

    def test_fix_requires_integer_rank(self):
        with self.assertRaisesRegex(ValueError, "rank"):
            triage.validate(fix_row(rank=None))

    def test_duplicate_requires_duplicate_of(self):
        with self.assertRaisesRegex(ValueError, "duplicate_of"):
            triage.validate(fix_row(verdict="duplicate", rank=None))

    def test_already_fixed_requires_fixed_by_and_spot_check(self):
        with self.assertRaisesRegex(ValueError, "fixed_by"):
            triage.validate(fix_row(verdict="already-fixed", rank=None,
                                    spot_check="advisor: fixed"))

    def test_reject_requires_spot_check(self):
        with self.assertRaisesRegex(ValueError, "spot_check"):
            triage.validate(fix_row(verdict="reject", rank=None))

    def test_unknown_verdict_and_status_rejected(self):
        with self.assertRaisesRegex(ValueError, "verdict"):
            triage.validate(fix_row(verdict="maybe"))
        with self.assertRaisesRegex(ValueError, "status"):
            triage.validate(fix_row(status="pondering"))

    def test_empty_rationale_rejected(self):
        with self.assertRaisesRegex(ValueError, "rationale"):
            triage.validate(fix_row(rationale="  "))


class TestMutations(unittest.TestCase):
    def test_fix_comments_labels_milestones_never_closes(self):
        cmds = triage.plan_mutations(fix_row())
        self.assertEqual(cmds[0][:4], ["gh", "issue", "comment", "443"])
        self.assertIn("triage:fix", cmds[1])
        self.assertIn(triage.MILESTONE, cmds[1])
        self.assertFalse(any(c[2] == "close" for c in cmds))

    def test_duplicate_closes_not_planned(self):
        row = fix_row(verdict="duplicate", rank=None, duplicate_of=436)
        cmds = triage.plan_mutations(row)
        self.assertIn("triage:duplicate", cmds[1])
        self.assertEqual(cmds[-1], ["gh", "issue", "close", "443",
                                    "--reason", "not planned"])

    def test_already_fixed_closes_completed(self):
        row = fix_row(verdict="already-fixed", rank=None,
                      fixed_by="PR #447", spot_check="advisor: fixed")
        self.assertEqual(triage.plan_mutations(row)[-1],
                         ["gh", "issue", "close", "443",
                          "--reason", "completed"])

    def test_reject_closes_not_planned_and_defer_stays_open(self):
        rej = fix_row(verdict="reject", rank=None, spot_check="stands")
        self.assertEqual(triage.plan_mutations(rej)[-1][:3],
                         ["gh", "issue", "close"])
        defer = fix_row(verdict="defer", rank=None)
        self.assertFalse(any(c[2] == "close"
                             for c in triage.plan_mutations(defer)))

    def test_comment_carries_rationale_spec_and_spot_check(self):
        row = fix_row(verdict="reject", rank=None,
                      spot_check="advisor: not-real, fixture file")
        body = triage.comment_for(row)
        self.assertIn("queue identity bug", body)
        self.assertIn(triage.SPEC, body)
        self.assertIn("fixture file", body)

    def test_comment_for_duplicate_names_canonical(self):
        row = fix_row(verdict="duplicate", rank=None, duplicate_of=436)
        self.assertIn("#436", triage.comment_for(row))


class TestStale(unittest.TestCase):
    def test_closed_issue_is_stale(self):
        self.assertTrue(triage.is_stale(
            fix_row(), {"state": "CLOSED",
                        "updatedAt": "2026-08-01T00:00:00Z"}))

    def test_updated_after_triage_is_stale(self):
        self.assertTrue(triage.is_stale(
            fix_row(), {"state": "OPEN",
                        "updatedAt": "2026-08-05T00:00:00Z"}))

    def test_untouched_open_issue_is_fresh(self):
        self.assertFalse(triage.is_stale(
            fix_row(), {"state": "OPEN",
                        "updatedAt": "2026-08-04T12:00:00Z"}))


class FakeRunner:
    """Records argv; returns canned stdout per command prefix."""
    def __init__(self, view_json='{"state": "OPEN", "updatedAt": "2026-08-04T12:00:00Z"}'):
        self.calls, self.view_json = [], view_json

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        class R:
            returncode, stderr = 0, ""
        R.stdout = self.view_json if argv[1:3] == ["issue", "view"] else "{}"
        return R


class TestApply(unittest.TestCase):
    def test_applies_only_approved_rows_and_flips_status(self):
        rows = [fix_row(status="approved"), fix_row(issue=431, rank=2)]
        done, stale = triage.apply(rows, runner=FakeRunner(),
                                   sleep=lambda s: None)
        self.assertEqual((done, stale), (1, 0))
        self.assertEqual(rows[0]["status"], "applied")
        self.assertEqual(rows[1]["status"], "proposed")

    def test_stale_row_is_flagged_not_applied(self):
        runner = FakeRunner(view_json='{"state": "CLOSED", '
                                      '"updatedAt": "2026-08-01T00:00:00Z"}')
        rows = [fix_row(status="approved")]
        done, stale = triage.apply(rows, runner=runner, sleep=lambda s: None)
        self.assertEqual((done, stale), (0, 1))
        self.assertEqual(rows[0]["status"], "stale")
        # nothing beyond the state fetch was run
        self.assertEqual([c[1:3] for c in runner.calls], [["issue", "view"]])

    def test_dry_run_touches_nothing(self):
        runner = FakeRunner()
        rows = [fix_row(status="approved")]
        triage.apply(rows, dry=True, runner=runner, sleep=lambda s: None)
        self.assertEqual(runner.calls, [])
        self.assertEqual(rows[0]["status"], "approved")

    def test_invalid_approved_row_raises_before_any_mutation(self):
        runner = FakeRunner()
        rows = [fix_row(status="approved", rank=None)]
        with self.assertRaises(ValueError):
            triage.apply(rows, runner=runner, sleep=lambda s: None)
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()

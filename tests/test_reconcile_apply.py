import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import file_issues
import reconcile_apply


class TestLedger(unittest.TestCase):
    def test_load_missing_ledger_returns_empty_dict(self):
        self.assertEqual(reconcile_apply.load_ledger(path="/nonexistent/x.json"), {})

    def test_load_ledger_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "filed-issues.json")
            data = {"fp|F-1|app.py|finding": "https://github.com/o/r/issues/1"}
            with open(p, "w") as fh:
                json.dump(data, fh)
            self.assertEqual(reconcile_apply.load_ledger(path=p), data)

    def test_ledger_key_matches_file_issues_key_for_format(self):
        record = {"stored_fingerprint": "deadbeefdeadbeef", "id": "F-TOOL-1",
                 "location_file": "app/config.py", "kind": "finding"}
        self.assertEqual(reconcile_apply.ledger_key(record),
                         "deadbeefdeadbeef|F-TOOL-1|app/config.py|finding")

    def test_ledger_key_handles_missing_stored_fingerprint(self):
        record = {"stored_fingerprint": None, "id": "F-1",
                 "location_file": "x.py", "kind": "rejected"}
        self.assertEqual(reconcile_apply.ledger_key(record), "|F-1|x.py|rejected")


class FakeCompleted:
    def __init__(self, stdout, returncode=0, stderr=""):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class TestRecoverLinkage(unittest.TestCase):
    def test_parses_fingerprint_id_location_kind_from_issue_bodies(self):
        issues = [
            {"number": 305, "labels": [{"name": "self-scan"}],
             "body": "**Location:** `tests/test_verdict_ingest.py:12`\n\n"
                     "---\n\n**Fingerprint:** `008bafabf583e494` — stable.\n"
                     "**Finding id in report:** `NOV-003`\n"},
            {"number": 399, "labels": [{"name": "self-scan"}, {"name": "false-positive"}],
             "body": "**Location:** `skill/scripts/tools/npm_audit.py`\n\n"
                     "---\n\n**Fingerprint:** `029bc5414dc2a077` — stable.\n"
                     "**Finding id in report:** `NOV-008`\n"},
        ]

        def runner(argv, capture_output, text):
            return FakeCompleted(json.dumps(issues))

        linkage = reconcile_apply.recover_linkage_from_github(runner=runner)
        self.assertEqual(
            linkage["008bafabf583e494|NOV-003|tests/test_verdict_ingest.py|finding"],
            "https://github.com/panopticon-scanner/panopticon/issues/305")
        self.assertEqual(
            linkage["029bc5414dc2a077|NOV-008|skill/scripts/tools/npm_audit.py|rejected"],
            "https://github.com/panopticon-scanner/panopticon/issues/399")

    def test_skips_issues_missing_the_expected_footer(self):
        issues = [{"number": 1, "labels": [], "body": "no footer here"}]

        def runner(argv, capture_output, text):
            return FakeCompleted(json.dumps(issues))

        self.assertEqual(reconcile_apply.recover_linkage_from_github(runner=runner), {})

    def test_recovers_empty_location_for_no_file_sentinel(self):
        # file_issues.body_for() writes the "(no file)" sentinel when
        # location.file is absent, but file_issues.key_for() keys on an
        # EMPTY location component for that same finding. The recovered key
        # must match key_for() byte-for-byte, not the body's sentinel text.
        f = {"fingerprint": "abc123", "id": "F-42", "location": {}}
        body = file_issues.body_for(f)
        issues = [{"number": 7, "labels": [{"name": "self-scan"}], "body": body}]

        def runner(argv, capture_output, text):
            return FakeCompleted(json.dumps(issues))

        linkage = reconcile_apply.recover_linkage_from_github(runner=runner)
        expected_key = file_issues.key_for(f, rejected=False)
        self.assertEqual(expected_key, "abc123|F-42||finding")
        self.assertIn(expected_key, linkage)
        self.assertEqual(linkage[expected_key],
                         "https://github.com/panopticon-scanner/panopticon/issues/7")

    def test_raises_runtime_error_when_gh_call_fails(self):
        def runner(argv, capture_output, text):
            return FakeCompleted(stdout="", returncode=1,
                                 stderr="API rate limit exceeded")

        with self.assertRaises(RuntimeError) as ctx:
            reconcile_apply.recover_linkage_from_github(runner=runner)
        self.assertIn("API rate limit exceeded", str(ctx.exception))


class TestPlanActions(unittest.TestCase):
    def _diff(self):
        return {
            "recurring": [{"fingerprint": "fp1",
                          "run2": [{"id": "F-1", "stored_fingerprint": "old1",
                                   "location_file": "a.py", "kind": "finding"}],
                          "run3": [{"id": "F-1-R3"}], "kind_changed": False}],
            "fixed_or_gone": [{"fingerprint": "fp2",
                              "run2": [{"id": "F-2", "stored_fingerprint": "old2",
                                       "location_file": "b.py", "kind": "finding"}]}],
            "new": [{"fingerprint": "fp3", "run3": [{"id": "F-3"}]}],
        }

    def test_resolves_via_ledger(self):
        ledger = {"old1|F-1|a.py|finding": "https://github.com/o/r/issues/1"}
        record = {"stored_fingerprint": "old1", "id": "F-1",
                 "location_file": "a.py", "kind": "finding"}
        self.assertEqual(reconcile_apply.resolve_issue(record, ledger),
                         "https://github.com/o/r/issues/1")

    def test_unresolvable_record_returns_none(self):
        self.assertEqual(reconcile_apply.resolve_issue(
            {"stored_fingerprint": "nope", "id": "X", "location_file": "y.py",
             "kind": "finding"}, {}), None)

    def test_plan_covers_recurring_and_fixed_or_gone_not_new(self):
        ledger = {"old1|F-1|a.py|finding": "https://github.com/o/r/issues/1",
                 "old2|F-2|b.py|finding": "https://github.com/o/r/issues/2"}
        actions = reconcile_apply.plan_actions(self._diff(), ledger)
        cohorts = {a["cohort"] for a in actions}
        self.assertEqual(cohorts, {"recurring", "fixed_or_gone"})
        self.assertEqual(len(actions), 2)
        recur = next(a for a in actions if a["cohort"] == "recurring")
        self.assertFalse(recur["close"])
        gone = next(a for a in actions if a["cohort"] == "fixed_or_gone")
        self.assertTrue(gone["close"])

    def test_unresolvable_recurring_finding_is_omitted_not_guessed(self):
        actions = reconcile_apply.plan_actions(self._diff(), {})
        self.assertEqual(actions, [])

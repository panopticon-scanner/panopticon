import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import file_issues
import reconcile_apply
import triage


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


class TestSaveRecoveredLedger(unittest.TestCase):
    """Direct coverage for save_recovered_ledger: nested-dir creation, content
    round-trip, atomic overwrite, and no leftover temp file."""

    def test_writes_linkage_creating_nested_dirs(self):
        linkage = {"fp|F-1|a.py|finding": "https://github.com/o/r/issues/1"}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nested", "dir", "ledger.json")
            reconcile_apply.save_recovered_ledger(linkage, path=path)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), linkage)
            self.assertFalse(os.path.exists(path + ".tmp"))  # temp replaced, not left

    def test_overwrites_existing_ledger_atomically(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ledger.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{\"stale\": true}")
            new = {"fp|F-2|b.py|finding": "https://github.com/o/r/issues/2"}
            reconcile_apply.save_recovered_ledger(new, path=path)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), new)   # fully replaced, no merge

    def test_output_is_sorted_and_indented_for_stable_diffs(self):
        linkage = {"b|B|f|finding": "u2", "a|A|f|finding": "u1"}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ledger.json")
            reconcile_apply.save_recovered_ledger(linkage, path=path)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertLess(text.index('"a|A|f|finding"'),
                            text.index('"b|B|f|finding"'))  # sort_keys
            self.assertIn("\n ", text)                       # indent=1


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

    def test_absolute_path_finding_recovers_losslessly(self):
        # #607/#488: a finding whose location.file was ABSOLUTE under the repo
        # root used to be lost by recovery — key_for keyed on the raw absolute
        # path, but the issue body was scrubbed to relative. Now both key on
        # the repo-relative path, so the key reconstructed from the scrubbed
        # body matches the ledger key.
        rel = "skill/scripts/tools/npm_audit.py"
        f = {"fingerprint": "deadbeef", "id": "NOV-008",
             "location": {"file": file_issues.repo_root() + rel, "line_start": 12}}
        # Body as actually posted: scrubbed (create() wraps body_for in scrub()).
        body = file_issues.scrub(file_issues.body_for(f))
        self.assertIn("`%s:12`" % rel, body)          # relative in the body
        issues = [{"number": 9, "labels": [{"name": "self-scan"}], "body": body}]

        def runner(argv, capture_output, text):
            return FakeCompleted(json.dumps(issues))

        linkage = reconcile_apply.recover_linkage_from_github(runner=runner)
        expected_key = file_issues.key_for(f, rejected=False)
        self.assertEqual(expected_key, "deadbeef|NOV-008|%s|finding" % rel)
        self.assertIn(expected_key, linkage)          # recovered, not lost

    def test_raises_runtime_error_when_gh_call_fails(self):
        def runner(argv, capture_output, text):
            return FakeCompleted(stdout="", returncode=1,
                                 stderr="API rate limit exceeded")

        with self.assertRaises(RuntimeError) as ctx:
            reconcile_apply.recover_linkage_from_github(runner=runner)
        self.assertIn("API rate limit exceeded", str(ctx.exception))

    def test_uses_limit_1000_in_gh_issue_list(self):
        calls = []

        def runner(argv, capture_output, text):
            calls.append(argv)
            return FakeCompleted(json.dumps([]))

        reconcile_apply.recover_linkage_from_github(runner=runner)
        self.assertIn("--limit", calls[0])
        self.assertEqual(calls[0][calls[0].index("--limit") + 1], "1000")

    def test_processes_up_to_1000_issues(self):
        issues = [
            {"number": i, "labels": [{"name": "self-scan"}],
             "body": "**Location:** `f%d.py`\n\n---\n\n"
                     "**Fingerprint:** `%016x` — stable.\n"
                     "**Finding id in report:** `F-%d`\n" % (i, i, i)}
            for i in range(1000)
        ]

        def runner(argv, capture_output, text):
            return FakeCompleted(json.dumps(issues))

        with self.assertWarns(UserWarning):
            linkage = reconcile_apply.recover_linkage_from_github(runner=runner)
        self.assertEqual(len(linkage), 1000)
        self.assertIn("0000000000000000|F-0|f0.py|finding", linkage)
        self.assertIn("00000000000003e7|F-999|f999.py|finding", linkage)

    def test_warns_when_results_may_be_truncated(self):
        """A full 1000-result page equals the request limit and may be truncated."""
        issues = [
            {"number": i, "labels": [{"name": "self-scan"}],
             "body": "**Location:** `f.py`\n\n---\n\n"
                     "**Fingerprint:** `%016x` — stable.\n"
                     "**Finding id in report:** `F-1`\n" % i}
            for i in range(1000)
        ]

        def runner(argv, capture_output, text):
            return FakeCompleted(json.dumps(issues))

        with self.assertWarns(UserWarning):
            reconcile_apply.recover_linkage_from_github(runner=runner)

    def test_recovers_path_containing_colon(self):
        issues = [
            {"number": 505, "labels": [{"name": "self-scan"}],
             "body": "**Location:** `src/Foo:Bar.cs:42`\n\n"
                     "---\n\n"
                     "**Fingerprint:** `abc123defabc1234` — stable.\n"
                     "**Finding id in report:** `NOV-COLON`\n"},
        ]

        def runner(argv, capture_output, text):
            return FakeCompleted(json.dumps(issues))

        linkage = reconcile_apply.recover_linkage_from_github(runner=runner)
        self.assertIn("abc123defabc1234|NOV-COLON|src/Foo:Bar.cs|finding", linkage)


class TestPlanActions(unittest.TestCase):
    def _diff(self):
        return {
            "recurring": [{"fingerprint": "fp1",
                          "run2": [{"id": "F-1", "stored_fingerprint": "old1",
                                   "location_file": "a.py", "kind": "finding"}],
                          "run3": [{"id": "F-1-R3"}], "kind_changed": False}],
            "closed": [{"fingerprint": "fp2", "reason": "area clear",
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

    def test_resolves_via_legacy_absolute_path_key(self):
        abs_path = file_issues.repo_root() + "skill/scripts/run_tools.py"
        ledger = {"old1|F-1|%s|finding" % abs_path: "https://github.com/o/r/issues/1"}
        record = {"stored_fingerprint": "old1", "id": "F-1",
                 "location_file": abs_path, "kind": "finding"}
        self.assertEqual(reconcile_apply.resolve_issue(record, ledger),
                         "https://github.com/o/r/issues/1")

    def test_unresolvable_record_returns_none(self):
        self.assertEqual(reconcile_apply.resolve_issue(
            {"stored_fingerprint": "nope", "id": "X", "location_file": "y.py",
             "kind": "finding"}, {}), None)

    def test_plan_covers_recurring_and_closed_not_new(self):
        ledger = {"old1|F-1|a.py|finding": "https://github.com/o/r/issues/1",
                 "old2|F-2|b.py|finding": "https://github.com/o/r/issues/2"}
        actions = reconcile_apply.plan_actions(self._diff(), ledger)
        cohorts = {a["cohort"] for a in actions}
        self.assertEqual(cohorts, {"recurring", "closed"})
        self.assertEqual(len(actions), 2)
        recur = next(a for a in actions if a["cohort"] == "recurring")
        self.assertFalse(recur["close"])
        closed = next(a for a in actions if a["cohort"] == "closed")
        self.assertTrue(closed["close"])

    def test_unresolvable_recurring_finding_is_omitted_not_guessed(self):
        actions = reconcile_apply.plan_actions(self._diff(), {})
        self.assertEqual(actions, [])

    def test_hostile_reason_is_neutralized_in_posted_comment(self):
        # #953: reason strings embed scanned-repo file paths verbatim, and the
        # comments are auto-posted by an authenticated identity. A hostile repo
        # controls its paths: markdown links, @-mentions, backtick breakouts,
        # and newlines must all be inert in the posted body.
        hostile = ("x`](https://evil.example) @octocat\n"
                   "**bold** still active on a.py")
        diff = {
            "closed": [{"fingerprint": "fp2", "reason": hostile,
                        "run2": [{"id": "F-2", "stored_fingerprint": "old2",
                                  "location_file": "b.py", "kind": "finding"}]}],
            "ambiguous": [{"fingerprint": "fp3", "reason": hostile,
                           "run2": [{"id": "F-3", "stored_fingerprint": "old3",
                                     "location_file": "c.py", "kind": "finding"}]}],
        }
        ledger = {"old2|F-2|b.py|finding": "https://github.com/o/r/issues/2",
                  "old3|F-3|c.py|finding": "https://github.com/o/r/issues/3"}
        actions = reconcile_apply.plan_actions(diff, ledger)
        self.assertEqual(len(actions), 2)
        for a in actions:
            body = a["comment"]
            self.assertNotIn("\n", body)                  # CWE-117 collapse
            neutral = reconcile_apply.neutralize(hostile)
            self.assertIn(neutral, body)                  # reason present, wrapped
            # the interpolated reason sits inside ONE code span, so markdown,
            # links, and @-mentions cannot activate; no input backtick survives
            # to break out of it
            self.assertTrue(neutral.startswith("`") and neutral.endswith("`"))
            self.assertNotIn("`", neutral[1:-1])
            self.assertIn("@octocat", neutral)            # visible, but inert

    def test_neutralize_shapes(self):
        n = reconcile_apply.neutralize
        self.assertEqual(n("plain reason"), "`plain reason`")
        self.assertEqual(n("a\nb\tc"), "`a b c`")          # whitespace collapsed
        self.assertEqual(n("tick`inside"), "`tick'inside`")  # backtick neutralized to single quote
        self.assertEqual(n(""), "`(empty)`")               # never an empty span
        self.assertEqual(n(None), "`(empty)`")

    def test_neutralize_strips_terminal_escape_controls(self):
        # Non-whitespace C0/C1 controls survive str.split() and would reach
        # gh/terminal consumers as escape sequences: ESC-based ANSI, BEL
        # (OSC terminator), backspace overwrite, and the single-byte CSI
        # (\x9b). All must be stripped outright.
        n = reconcile_apply.neutralize
        self.assertEqual(n("a\x1b]0;evil\x07b"), "`a]0;evilb`")
        self.assertEqual(n("x\x9b31mred"), "`x31mred`")
        self.assertEqual(n("over\x08write\x7f"), "`overwrite`")

    def test_neutralize_preserves_unicode_visible_glyphs(self):
        # Accented characters, Cyrillic, CJK, emoji, and other multi-byte
        # UTF-8 characters are legitimate prose in issue bodies / tool findings;
        # neutralizing must preserve them verbatim rather than stripping or
        # mangling them (#768).
        n = reconcile_apply.neutralize
        self.assertEqual(n("café"), "`café`")
        self.assertEqual(n("warning: 警告"), "`warning: 警告`")
        self.assertEqual(n("hello 🌍"), "`hello 🌍`")
        self.assertEqual(n("тест"), "`тест`")

    def test_recurring_fingerprint_interpolant_is_backtick_safe(self):
        # Fingerprints are generated hex, but the comment boundary treats every
        # diff.json value as untrusted: a tampered fingerprint with a backtick
        # must not break out of the template's own code span.
        diff = {"recurring": [{"fingerprint": "fp` @evil",
                               "run2": [{"id": "F-1", "stored_fingerprint": "old1",
                                         "location_file": "a.py", "kind": "finding"}],
                               "run3": [], "kind_changed": False}]}
        ledger = {"old1|F-1|a.py|finding": "https://github.com/o/r/issues/1"}
        actions = reconcile_apply.plan_actions(diff, ledger)
        body = actions[0]["comment"]
        # template wraps the fingerprint in `...`; the interpolated value must
        # carry no backtick of its own
        self.assertIn("(`fp' @evil`)", body)


    def test_only_closed_cohort_sets_close_true(self):
        diff = {
            "recurring": [{"fingerprint": "fp1",
                          "run2": [{"id": "F-1", "stored_fingerprint": "old1",
                                   "location_file": "a.py", "kind": "finding"}]}],
            "closed": [{"fingerprint": "fp2", "reason": "(file,panel) clear: area has no findings",
                       "run2": [{"id": "F-2", "stored_fingerprint": "old2",
                                "location_file": "b.py", "kind": "finding"}]}],
            "ambiguous": [{"fingerprint": "fp3", "reason": "security still active on file",
                          "run2": [{"id": "F-3", "stored_fingerprint": "old3",
                                   "location_file": "c.py", "kind": "finding"}]}],
            "new": [{"fingerprint": "fp4", "run3": [{"id": "F-4"}]}],
        }
        ledger = {"old1|F-1|a.py|finding": "https://github.com/o/r/issues/1",
                 "old2|F-2|b.py|finding": "https://github.com/o/r/issues/2",
                 "old3|F-3|c.py|finding": "https://github.com/o/r/issues/3"}
        actions = reconcile_apply.plan_actions(diff, ledger)
        by_cohort = {a["cohort"]: a for a in actions}
        self.assertTrue(by_cohort["closed"]["close"])
        self.assertFalse(by_cohort["recurring"]["close"])
        self.assertFalse(by_cohort["ambiguous"]["close"])
        self.assertNotIn("new", by_cohort)
        self.assertIn("clear", by_cohort["closed"]["comment"])

    def test_recurring_coarse_tier_gets_coarse_comment_not_exact(self):
        # F3: a coarse-tier match's comment must not claim the rule/title
        # matched -- that's precisely what did NOT happen on that branch.
        diff = {"recurring": [{"fingerprint": "fp1", "match_tier": "coarse",
                              "run2": [{"id": "F-1", "stored_fingerprint": "old1",
                                       "location_file": "a.py", "kind": "finding"}]}],
               "closed": [], "ambiguous": [], "new": []}
        ledger = {"old1|F-1|a.py|finding": "https://github.com/o/r/issues/1"}
        actions = reconcile_apply.plan_actions(diff, ledger)
        self.assertEqual(len(actions), 1)
        self.assertIn("re-worded title", actions[0]["comment"])
        self.assertNotIn("rule/title", actions[0]["comment"])

    def test_recurring_exact_tier_gets_exact_comment(self):
        diff = {"recurring": [{"fingerprint": "fp1", "match_tier": "exact",
                              "run2": [{"id": "F-1", "stored_fingerprint": "old1",
                                       "location_file": "a.py", "kind": "finding"}]}],
               "closed": [], "ambiguous": [], "new": []}
        ledger = {"old1|F-1|a.py|finding": "https://github.com/o/r/issues/1"}
        actions = reconcile_apply.plan_actions(diff, ledger)
        self.assertEqual(len(actions), 1)
        self.assertIn("rule/title", actions[0]["comment"])
        self.assertNotIn("re-worded title", actions[0]["comment"])

    def test_recurring_missing_match_tier_defaults_to_exact_comment(self):
        # Back-compat: entries built before match_tier existed (or a diff.json
        # produced before #914) must still get the exact-tier comment.
        actions = reconcile_apply.plan_actions(self._diff(),
                                               {"old1|F-1|a.py|finding":
                                                "https://github.com/o/r/issues/1"})
        recur = next(a for a in actions if a["cohort"] == "recurring")
        self.assertIn("rule/title", recur["comment"])

    def test_fixed_or_gone_key_prints_stale_diff_note_to_stderr(self):
        # M4: a pre-branch diff.json shape (fixed_or_gone, no closed/ambiguous
        # split) must not silently be planned against as if nothing changed.
        diff = dict(self._diff())
        diff["fixed_or_gone"] = []
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            reconcile_apply.plan_actions(diff, {})
        self.assertIn("predates the closed/ambiguous split", buf.getvalue())


class TestLedgerKeyMatchesKeyFor(unittest.TestCase):
    """The load-bearing invariant: reconcile_apply.ledger_key(record) must be
    byte-identical to file_issues.key_for(finding, rejected) for the same
    finding, so an issue filed by file_issues is found by reconciliation.
    Cross-checked against the real key_for (not a hardcoded mirror)."""

    def _record(self, f, kind):
        loc = f.get("location") or {}
        return {"stored_fingerprint": f.get("fingerprint"), "id": f.get("id"),
                "location_file": loc.get("file") or "", "kind": kind}

    def test_matches_across_relative_absolute_rejected_and_no_location(self):
        cases = [
            ({"fingerprint": "abc123", "id": "F-1", "location": {"file": "app.py"}}, False),
            ({"fingerprint": "def456", "id": "F-2", "location": {"file":
              file_issues.repo_root() + "skill/scripts/tools/npm_audit.py"}}, False),
            ({"fingerprint": "aaa111", "id": "R-1", "location": {"file": "x.py"}}, True),
            ({"fingerprint": "bbb222", "id": "F-3"}, False),  # no location at all
        ]
        for f, rejected in cases:
            kind = "rejected" if rejected else "finding"
            rec = self._record(f, kind)
            self.assertEqual(reconcile_apply.ledger_key(rec),
                             file_issues.key_for(f, rejected))


class TestPreflightAuthorized(unittest.TestCase):
    def test_admin_true_authorizes(self):
        def runner(argv, capture_output, text):
            return FakeCompleted(json.dumps({"admin": True, "push": True}))
        ok, reason = reconcile_apply.preflight_authorized("o", "r", runner=runner)
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_admin_false_refuses(self):
        def runner(argv, capture_output, text):
            return FakeCompleted(json.dumps({"admin": False, "push": True}))
        ok, reason = reconcile_apply.preflight_authorized("o", "r", runner=runner)
        self.assertFalse(ok)
        self.assertTrue(reason)

    def test_nonzero_exit_or_404_refuses_without_crashing(self):
        def runner(argv, capture_output, text):
            return FakeCompleted("", returncode=1, stderr="gh: Not Found (HTTP 404)")
        ok, reason = reconcile_apply.preflight_authorized("o", "r", runner=runner)
        self.assertFalse(ok)
        self.assertIn("404", reason)

    def test_absent_permissions_payload_refuses(self):
        def runner(argv, capture_output, text):
            return FakeCompleted("")   # empty stdout, exit 0 — no .permissions
        ok, reason = reconcile_apply.preflight_authorized("o", "r", runner=runner)
        self.assertFalse(ok)


class TestApply(unittest.TestCase):
    def _actions(self):
        return [{"cohort": "recurring", "fingerprint": "fp1",
                "issue": "https://github.com/o/r/issues/1", "comment": "c1", "close": False},
               {"cohort": "closed", "fingerprint": "fp2",
                "issue": "https://github.com/o/r/issues/2", "comment": "c2", "close": True}]

    def _admin_runner(self, calls):
        # authorizes the preflight (gh api), records everything
        def runner(argv, capture_output, text):
            calls.append(argv)
            if argv[:2] == ["gh", "api"]:
                return FakeCompleted(json.dumps({"admin": True}))
            return FakeCompleted("")
        return runner

    def test_duplicates_collapse_in_all_modes_and_preserve_distinct_content(self):
        original = self._actions()[0]
        unique = [original, dict(original, comment="different"), dict(original, close=True)]
        actions = [unique[0], dict(reversed(list(unique[0].items()))),
                   unique[1], unique[0], unique[2], unique[1]]
        for dry in (True, False):
            for with_progress in (True, False):
                with self.subTest(dry=dry, with_progress=with_progress), tempfile.TemporaryDirectory() as d:
                    calls = []
                    path = os.path.join(d, "progress.json") if with_progress else None
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        result = reconcile_apply.apply(actions, dry=dry, confirm_close=True,
                                                       runner=self._admin_runner(calls),
                                                       sleep=lambda _: None, progress_path=path)
                    self.assertEqual(result, (3, 0 if dry else 1))
                    if dry:
                        self.assertEqual(calls, [])
                        self.assertEqual(out.getvalue().count("DRY comment"), 3)
                    else:
                        comments = [c for c in calls if c[:3] == ["gh", "issue", "comment"]]
                        self.assertEqual([c[-1] for c in comments], [a["comment"] for a in unique])
                        if with_progress:
                            self.assertEqual(reconcile_apply.apply(unique, dry=False,
                                confirm_close=True, runner=self._admin_runner(calls),
                                sleep=lambda _: None, progress_path=path), (0, 0))

    def test_changed_or_reordered_plan_requires_reset_before_auth(self):
        original = self._actions()
        for changed in (list(reversed(original)), original[:1],
                        [dict(original[0], comment="new"), original[1]]):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "progress.json")
                calls = []
                runner = self._admin_runner(calls)
                reconcile_apply.apply(original, False, runner=runner, sleep=lambda _: None,
                                      progress_path=path)
                before = Path(path).read_bytes()
                calls.clear()
                with self.assertRaisesRegex(ValueError, "reset-progress"):
                    reconcile_apply.apply(changed, False, runner=runner, sleep=lambda _: None,
                                          progress_path=path)
                self.assertEqual(calls, [])
                self.assertEqual(Path(path).read_bytes(), before)
                self.assertEqual(reconcile_apply.apply(changed, False, runner=runner,
                    sleep=lambda _: None, progress_path=path, reset_progress=True), (len(changed), 0))
                receipt = json.loads(Path(path).read_text())
                self.assertEqual(set(receipt["actions"]),
                                 {reconcile_apply._action_key(a, "o/r") for a in changed})

    def test_reset_replays_identical_plan_and_requires_live_path(self):
        actions = self._actions()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "progress.json")
            calls = []
            runner = self._admin_runner(calls)
            for reset in (False, True):
                self.assertEqual(reconcile_apply.apply(actions, False, True, runner=runner,
                    sleep=lambda _: None, progress_path=path, reset_progress=reset), (2, 1))
            self.assertEqual(reconcile_apply.apply(actions, False, True, runner=runner,
                sleep=lambda _: None, progress_path=path), (0, 0))
            calls.clear()
            for plan in (actions, []):
                with self.assertRaisesRegex(ValueError, "receipt path"):
                    reconcile_apply.apply(plan, False, runner=runner, reset_progress=True)
            self.assertEqual(calls, [])

    def test_empty_plan_is_noop_but_live_reset_requires_nonempty_plan(self):
        with mock.patch.object(reconcile_apply, "_load_progress", side_effect=AssertionError("read")), \
             mock.patch.object(reconcile_apply, "_save_progress", side_effect=AssertionError("write")):
            def runner(*a, **k):
                self.fail("gh called")
            self.assertEqual(reconcile_apply.apply([], False, progress_path="/missing/receipt",
                                                   runner=runner), (0, 0))
            with self.assertRaisesRegex(ValueError, "nonempty plan"):
                reconcile_apply.apply([], False, reset_progress=True,
                                      progress_path="/missing/receipt", runner=runner)
            self.assertEqual(reconcile_apply.apply([], True, reset_progress=True,
                progress_path="/missing/receipt", runner=runner), (0, 0))

    def test_v1_migration_retains_exact_acknowledgements_and_prunes_history(self):
        actions = self._actions()
        active = reconcile_apply._action_key(actions[0], "o/r")
        unrelated = reconcile_apply._action_key(dict(actions[1], comment="old"), "o/r")
        for reset in (False, True):
            with self.subTest(reset=reset), tempfile.TemporaryDirectory() as d:
                path = Path(d) / "progress.json"
                path.write_text(json.dumps({"version": 1, "repo": "o/r", "actions": {
                    active: {"commented": True, "closed": False},
                    unrelated: {"commented": True, "closed": True}}}))
                calls = []
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    result = reconcile_apply.apply(actions, False, runner=self._admin_runner(calls),
                        sleep=lambda _: None, progress_path=path, reset_progress=reset)
                self.assertEqual(result, (2 if reset else 1, 0))
                receipt = json.loads(path.read_text())
                self.assertEqual(receipt["version"], 2)
                self.assertNotIn(unrelated, receipt["actions"])
                self.assertEqual(set(receipt["actions"]),
                                 {reconcile_apply._action_key(a, "o/r") for a in actions})
                self.assertIn("migrat", out.getvalue().lower())

    def test_v1_migration_preserves_completed_and_partial_close(self):
        action = self._actions()[1]
        key = reconcile_apply._action_key(action, "o/r")
        for closed in (False, True):
            with self.subTest(closed=closed), tempfile.TemporaryDirectory() as d:
                path = Path(d) / "progress.json"
                path.write_text(json.dumps({"version": 1, "repo": "o/r", "actions": {
                    key: {"commented": True, "closed": closed}}}))
                calls = []
                self.assertEqual(reconcile_apply.apply([action], False, True,
                    runner=self._admin_runner(calls), sleep=lambda _: None, progress_path=path),
                    (0, 0 if closed else 1))
                self.assertEqual([c[2] for c in calls if c[:2] == ["gh", "issue"]],
                                 [] if closed else ["close"])
                receipt = json.loads(path.read_text())
                self.assertEqual(receipt["version"], 2)
                self.assertEqual(receipt["actions"][key], {"commented": True, "closed": True})

    def test_dry_run_makes_no_gh_calls(self):
        calls = []

        def runner(argv, capture_output, text):
            calls.append(argv)
            return FakeCompleted("")

        commented, closed = reconcile_apply.apply(self._actions(), dry=True,
                                                   runner=runner, sleep=lambda s: None)
        self.assertEqual(calls, [])            # dry: not even the preflight runs
        self.assertEqual((commented, closed), (2, 0))

    def test_live_run_comments_every_action_but_closes_only_with_confirm(self):
        calls = []
        commented, closed = reconcile_apply.apply(self._actions(), dry=False,
                                                   confirm_close=False,
                                                   runner=self._admin_runner(calls),
                                                   sleep=lambda s: None)
        self.assertEqual(commented, 2)
        self.assertEqual(closed, 0)
        issue_calls = [c for c in calls if c[:2] == ["gh", "issue"]]
        self.assertEqual(len(issue_calls), 2)
        self.assertTrue(all(c[2] == "comment" for c in issue_calls))
        self.assertEqual(calls[0][:2], ["gh", "api"])   # preflight ran first
        for c in issue_calls:
            self.assertIn("--repo", c)
            self.assertEqual(c[c.index("--repo") + 1], "o/r")
        # The posted BODY must be the action's comment text, per action —
        # asserting only that "comment" was invoked would pass even if the
        # body were dropped or swapped.
        bodies = [c[c.index("--body") + 1] for c in issue_calls]
        self.assertEqual(bodies,
                         [a["comment"] for a in self._actions()])

    def test_live_run_closes_when_confirmed(self):
        calls = []
        commented, closed = reconcile_apply.apply(self._actions(), dry=False,
                                                   confirm_close=True,
                                                   runner=self._admin_runner(calls),
                                                   sleep=lambda s: None)
        self.assertEqual(closed, 1)
        close_calls = [c for c in calls if "close" in c]
        self.assertEqual(len(close_calls), 1)
        self.assertIn("2", close_calls[0])
        self.assertIn("--repo", close_calls[0])
        self.assertEqual(close_calls[0][close_calls[0].index("--repo") + 1], "o/r")

    def test_live_run_refuses_and_makes_zero_writes_when_unauthorized(self):
        calls = []

        def runner(argv, capture_output, text):
            calls.append(argv)
            if argv[:2] == ["gh", "api"]:
                return FakeCompleted(json.dumps({"admin": False}))
            return FakeCompleted("")

        commented, closed = reconcile_apply.apply(self._actions(), dry=False,
                                                   confirm_close=True, runner=runner,
                                                   sleep=lambda s: None)
        self.assertEqual((commented, closed), (0, 0))
        writes = [c for c in calls if c[:2] == ["gh", "issue"]]
        self.assertEqual(writes, [])           # zero comment/close calls

    def test_live_run_refuses_batch_spanning_multiple_repos(self):
        calls = []
        actions = [{"cohort": "recurring", "fingerprint": "fp1",
                   "issue": "https://github.com/o/r/issues/1", "comment": "c1", "close": False},
                  {"cohort": "closed", "fingerprint": "fp2",
                   "issue": "https://github.com/o/other/issues/2", "comment": "c2", "close": True}]
        commented, closed = reconcile_apply.apply(actions, dry=False, confirm_close=True,
                                                   runner=self._admin_runner(calls),
                                                   sleep=lambda s: None)
        self.assertEqual((commented, closed), (0, 0))
        issue_calls = [c for c in calls if c[:2] == ["gh", "issue"]]
        self.assertEqual(issue_calls, [])      # multi-repo guard fires before any writes
        self.assertEqual(calls, [])            # and before the preflight gh api call too

    def test_empty_actions_live_makes_no_calls(self):
        calls = []

        def runner(argv, capture_output, text):
            calls.append(argv)
            return FakeCompleted("")

        commented, closed = reconcile_apply.apply([], dry=False, confirm_close=True,
                                                   runner=runner, sleep=lambda s: None)
        self.assertEqual((commented, closed), (0, 0))
        self.assertEqual(calls, [])            # not dry and actions guard is falsy on []

    def test_later_failure_resumes_without_repeating_acknowledged_comment(self):
        actions = self._actions()
        calls = []
        fail = [True]

        def runner(argv, capture_output, text):
            calls.append(argv)
            if argv[:2] == ["gh", "api"]:
                return FakeCompleted('{"admin": true}')
            if argv[:3] == ["gh", "issue", "comment"] and argv[3] == "2" and fail[0]:
                return FakeCompleted("", returncode=1, stderr="temporary failure")
            return FakeCompleted("")

        with tempfile.TemporaryDirectory() as d:
            progress = os.path.join(d, "actions.progress.json")
            with self.assertRaises(RuntimeError):
                reconcile_apply.apply(actions, dry=False, runner=runner,
                                      sleep=lambda s: None, progress_path=progress)
            self.assertTrue(os.path.exists(progress))
            fail[0] = False
            calls.clear()
            self.assertEqual(reconcile_apply.apply(actions, dry=False, runner=runner,
                                                   sleep=lambda s: None,
                                                   progress_path=progress), (1, 0))
        comments = [c for c in calls if c[:3] == ["gh", "issue", "comment"]]
        self.assertEqual([c[3] for c in comments], ["2"])

    def test_close_failure_resumes_only_close(self):
        actions = [self._actions()[1]]
        calls = []
        fail = [True]

        def runner(argv, capture_output, text):
            calls.append(argv)
            if argv[:2] == ["gh", "api"]:
                return FakeCompleted('{"admin": true}')
            if argv[:3] == ["gh", "issue", "close"] and fail[0]:
                return FakeCompleted("", returncode=1, stderr="temporary failure")
            return FakeCompleted("")

        with tempfile.TemporaryDirectory() as d:
            progress = os.path.join(d, "progress.json")
            with self.assertRaises(RuntimeError):
                reconcile_apply.apply(actions, dry=False, confirm_close=True,
                                      runner=runner, sleep=lambda s: None,
                                      progress_path=progress)
            fail[0] = False
            calls.clear()
            self.assertEqual(reconcile_apply.apply(actions, dry=False, confirm_close=True,
                                                   runner=runner, sleep=lambda s: None,
                                                   progress_path=progress), (0, 1))
        self.assertEqual([c[2] for c in calls if c[:2] == ["gh", "issue"]], ["close"])

    def test_confirmation_after_comment_only_run_adds_only_close(self):
        action = self._actions()[1]
        calls = []
        runner = self._admin_runner(calls)
        with tempfile.TemporaryDirectory() as d:
            progress = os.path.join(d, "progress.json")
            self.assertEqual(reconcile_apply.apply([action], dry=False,
                                                   runner=runner, sleep=lambda s: None,
                                                   progress_path=progress), (1, 0))
            with open(progress, encoding="utf-8") as fh:
                receipt = json.load(fh)
            self.assertEqual(receipt["version"], 2)
            self.assertEqual(receipt["repo"], "o/r")
            self.assertEqual(list(receipt["actions"].values()),
                             [{"commented": True, "closed": False}])
            calls.clear()
            self.assertEqual(reconcile_apply.apply([action], dry=False,
                                                   confirm_close=True,
                                                   runner=runner, sleep=lambda s: None,
                                                   progress_path=progress), (0, 1))
        self.assertEqual([c[2] for c in calls if c[:2] == ["gh", "issue"]], ["close"])

    def test_changed_comment_and_action_do_not_reuse_acknowledgement(self):
        calls = []
        runner = self._admin_runner(calls)
        original = self._actions()[0]
        with tempfile.TemporaryDirectory() as d:
            progress = os.path.join(d, "progress.json")
            for action in (original, dict(original, comment="revised"),
                           dict(original, close=True)):
                reconcile_apply.apply([action], dry=False, runner=runner,
                                      sleep=lambda s: None, progress_path=progress, reset_progress=True)
        self.assertEqual(len([c for c in calls if c[:3] == ["gh", "issue", "comment"]]), 3)

    def test_dry_run_shows_all_actions_and_creates_no_progress(self):
        with tempfile.TemporaryDirectory() as d:
            progress = os.path.join(d, "progress.json")
            with open(progress, "w", encoding="utf-8") as fh:
                fh.write("not a valid receipt")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = reconcile_apply.apply(self._actions(), dry=True,
                                               progress_path=progress,
                                               runner=lambda *a, **k: self.fail("dry run called gh"))
            self.assertEqual(result, (2, 0))
            self.assertEqual(out.getvalue().count("DRY comment"), 2)
            with open(progress, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "not a valid receipt")
            absent = os.path.join(d, "absent.json")
            reconcile_apply.apply(self._actions(), dry=True, progress_path=absent,
                                  runner=lambda *a, **k: self.fail("dry run called gh"))
            self.assertFalse(os.path.exists(absent))

    def test_corrupt_and_symlink_progress_fail_before_issue_mutation(self):
        calls = []
        runner = self._admin_runner(calls)
        with tempfile.TemporaryDirectory() as d:
            progress = os.path.join(d, "progress.json")
            for data in ('{"version": 9, "repo": "o/r", "actions": {}}',
                         '{"version": 1, "repo": "other/repo", "actions": {}}',
                         '{"version": 1, "repo": "o/r", "actions": {"bad": {"commented": true, "closed": false}}}',
                         '{"version": 1, "repo": "o/r", "actions": {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {"commented": false, "closed": true}}}',
                         '{broken json'):
                with open(progress, "w", encoding="utf-8") as fh:
                    fh.write(data)
                with self.assertRaises(ValueError):
                    reconcile_apply.apply(self._actions(), dry=False, runner=runner,
                                          sleep=lambda s: None, progress_path=progress)
            os.unlink(progress)
            target = os.path.join(d, "target.json")
            with open(target, "w", encoding="utf-8") as fh:
                fh.write('{}')
            os.symlink(target, progress)
            with self.assertRaises(ValueError):
                reconcile_apply.apply(self._actions(), dry=False, runner=runner,
                                      sleep=lambda s: None, progress_path=progress)
        self.assertEqual([c for c in calls if c[:2] == ["gh", "issue"]], [])

    def test_receipt_capacity_reserved_before_auth_and_close_resume(self):
        action = self._actions()[1]
        key = reconcile_apply._action_key(action, "o/r")
        calls = []
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "progress.json"
            # Measure a real completed comment receipt, then reproduce its exact
            # boundary from a missing receipt: reservation must precede auth.
            runner = self._admin_runner(calls)
            reconcile_apply.apply([action], False, runner=runner, sleep=lambda _: None,
                                  progress_path=path)
            capacity = path.stat().st_size
            path.unlink()
            calls.clear()
            with mock.patch.object(reconcile_apply, "PROGRESS_MAX_BYTES", capacity - 1):
                with self.assertRaisesRegex(ValueError, "too large"):
                    reconcile_apply.apply([action], False, runner=runner, sleep=lambda _: None,
                                          progress_path=path)
            self.assertEqual(calls, [])
            self.assertFalse(path.exists())
            with mock.patch.object(reconcile_apply, "PROGRESS_MAX_BYTES", capacity):
                self.assertEqual(reconcile_apply.apply([action], False, runner=runner,
                    sleep=lambda _: None, progress_path=path), (1, 0))
                calls.clear()
                self.assertEqual(reconcile_apply.apply([action], False, True, runner=runner,
                    sleep=lambda _: None, progress_path=path), (0, 1))
            self.assertEqual([c[2] for c in calls if c[:2] == ["gh", "issue"]], ["close"])
            self.assertTrue(json.loads(path.read_text())["actions"][key]["closed"])

    def test_binding_reset_and_migration_save_before_mutation_after_auth(self):
        actions = self._actions()
        for mode in ("new", "reset", "migration"):
            for failure in ("none", "auth", "save"):
                with self.subTest(mode=mode, failure=failure), tempfile.TemporaryDirectory() as d:
                    path = Path(d) / "progress.json"
                    if mode == "reset":
                        reconcile_apply.apply(actions, False, runner=self._admin_runner([]),
                                              sleep=lambda _: None, progress_path=path)
                    elif mode == "migration":
                        path.write_text(json.dumps({"version": 1, "repo": "o/r", "actions": {}}))
                    original = path.read_bytes() if path.exists() else None
                    calls = []
                    def runner(argv, **kwargs):
                        calls.append(argv)
                        if argv[:2] == ["gh", "api"]:
                            self.assertEqual(path.read_bytes() if path.exists() else None, original)
                            return FakeCompleted(json.dumps({"admin": failure != "auth"}))
                        receipt = json.loads(path.read_text())
                        self.assertEqual(receipt["version"], 2)
                        # Before first mutation, persisted receipt has no acks.
                        if len(calls) == 2:
                            self.assertEqual(receipt["actions"], {})
                        return FakeCompleted("")
                    kwargs = dict(dry=False, runner=runner, sleep=lambda _: None,
                                  progress_path=path, reset_progress=mode == "reset")
                    if failure == "save":
                        with mock.patch.object(reconcile_apply, "_save_progress", side_effect=OSError("disk full")):
                            with self.assertRaisesRegex(OSError, "disk full"):
                                reconcile_apply.apply(actions, **kwargs)
                    else:
                        self.assertEqual(reconcile_apply.apply(actions, **kwargs),
                                         (0, 0) if failure == "auth" else (2, 0))
                    if failure != "none":
                        self.assertEqual(len(calls), 1)
                        self.assertEqual(path.read_bytes() if path.exists() else None, original)

    def test_reset_does_not_bypass_unsafe_oversize_or_foreign_receipts(self):
        action = self._actions()[0]
        for reset in (False, True):
            for invalid in ("symlink", "fifo", "directory", "oversize", "foreign", "corrupt"):
                with self.subTest(reset=reset, invalid=invalid), tempfile.TemporaryDirectory() as d:
                    path = Path(d) / "progress.json"
                    if invalid == "symlink":
                        path.symlink_to(Path(d) / "missing")
                    elif invalid == "fifo":
                        os.mkfifo(path)
                    elif invalid == "directory":
                        path.mkdir()
                    elif invalid == "oversize":
                        path.write_bytes(b" " * (reconcile_apply.PROGRESS_MAX_BYTES + 1))
                    elif invalid == "foreign":
                        path.write_text(json.dumps({"version": 1, "repo": "other/repo", "actions": {}}))
                    else:
                        path.write_text("{bad json")
                    calls = []
                    with self.assertRaises(ValueError):
                        reconcile_apply.apply([action], False, runner=self._admin_runner(calls),
                            sleep=lambda _: None, progress_path=path, reset_progress=reset)
                    self.assertEqual(calls, [])

    def test_v2_corrupt_binding_and_extra_acknowledgements_rejected_even_on_reset(self):
        for reset in (False, True):
            for invalid in ("hash", "extra", "duplicate", "ack", "plan_type", "plan_entry"):
                with self.subTest(reset=reset, invalid=invalid), tempfile.TemporaryDirectory() as d:
                    path = Path(d) / "progress.json"
                    actions = self._actions()
                    reconcile_apply.apply(actions, False, runner=self._admin_runner([]),
                                          sleep=lambda _: None, progress_path=path)
                    receipt = json.loads(path.read_text())
                    if invalid == "hash":
                        receipt["plan_hash"] = "0" * 64
                    elif invalid == "extra":
                        receipt["actions"]["0" * 64] = {"commented": True, "closed": False}
                    elif invalid == "duplicate":
                        receipt["plan"].append(receipt["plan"][0])
                    elif invalid == "ack":
                        receipt["actions"][receipt["plan"][0]] = {"commented": False, "closed": True}
                    elif invalid == "plan_type":
                        receipt["plan"] = {}
                    else:
                        receipt["plan"] = [[]]
                    path.write_text(json.dumps(receipt))
                    calls = []
                    with self.assertRaises(ValueError):
                        reconcile_apply.apply(actions, False, runner=self._admin_runner(calls),
                            sleep=lambda _: None, progress_path=path, reset_progress=reset)
                    self.assertEqual(calls, [])

    def test_dry_reset_performs_no_receipt_io(self):
        with mock.patch.object(reconcile_apply, "_load_progress", side_effect=AssertionError("read")), \
             mock.patch.object(reconcile_apply, "_save_progress", side_effect=AssertionError("write")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                result = reconcile_apply.apply(self._actions(), reset_progress=True,
                    progress_path="/missing/receipt.json", runner=lambda *a, **k: self.fail("gh called"))
            self.assertEqual(result, (2, 0))
            self.assertIn("previewing replay", out.getvalue())

    def test_migration_prunes_a_full_legacy_history(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "progress.json"
            # Valid obsolete history at the old read cap must not block migration.
            legacy = {"version": 1, "repo": "o/r", "actions": {
                "%064x" % i: {"commented": True, "closed": False} for i in range(20)}}
            data = json.dumps(legacy).encode()
            path.write_bytes(data)
            with mock.patch.object(reconcile_apply, "PROGRESS_MAX_BYTES", len(data)):
                self.assertEqual(reconcile_apply.apply(self._actions(), False,
                    runner=self._admin_runner([]), sleep=lambda _: None, progress_path=path), (2, 0))
            self.assertLess(path.stat().st_size, len(data))
            self.assertEqual(len(json.loads(path.read_text())["actions"]), 2)

    def test_symlink_progress_directory_is_rejected_even_on_reset(self):
        for reset in (False, True):
            with self.subTest(reset=reset), tempfile.TemporaryDirectory() as d:
                target = Path(d) / "target"
                target.mkdir()
                link = Path(d) / "link"
                link.symlink_to(target, target_is_directory=True)
                calls = []
                with self.assertRaisesRegex(ValueError, "unsafe progress directory"):
                    reconcile_apply.apply(self._actions(), False, runner=self._admin_runner(calls),
                        sleep=lambda _: None, progress_path=link / "receipt.json", reset_progress=reset)
                self.assertEqual(calls, [])
                self.assertEqual(list(target.iterdir()), [])

    def test_missing_progress_directory_fails_before_issue_mutation(self):
        calls = []
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "missing", "progress.json")
            with self.assertRaisesRegex(ValueError, "unsafe progress directory"):
                reconcile_apply.apply(self._actions(), dry=False,
                                      runner=self._admin_runner(calls),
                                      sleep=lambda s: None, progress_path=path)
        self.assertEqual(calls, [])


class TestCliWiring(unittest.TestCase):
    def test_apply_uses_plan_adjacent_receipt_and_accepts_override(self):
        with tempfile.TemporaryDirectory() as d:
            actions_path = os.path.join(d, "actions.json")
            with open(actions_path, "w", encoding="utf-8") as fh:
                json.dump([], fh)
            with mock.patch("reconcile_apply.apply", return_value=(0, 0)) as apply_mock:
                self.assertEqual(reconcile_apply.main(["apply", actions_path,
                                                       "--no-dry-run"]), 0)
                self.assertEqual(apply_mock.call_args.kwargs["progress_path"],
                                 actions_path + ".progress.json")
                custom = os.path.join(d, "other.json")
                self.assertEqual(reconcile_apply.main(["apply", actions_path,
                                                       "--progress", custom]), 0)
                self.assertEqual(apply_mock.call_args.kwargs["progress_path"], custom)

    def test_cli_reset_flag_is_forwarded(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "actions.json"
            path.write_text("[]")
            with mock.patch.object(reconcile_apply, "apply", return_value=(0, 0)) as run:
                self.assertEqual(reconcile_apply.main(["apply", str(path), "--reset-progress"]), 0)
                self.assertTrue(run.call_args.kwargs["reset_progress"])

    def test_cli_refuses_invalid_plan_receipt_and_io_without_traceback(self):
        valid = TestApply()._actions()
        cases = ["{bad", {}, [None], [dict(valid[0], close="yes")],
                 [dict(valid[0], issue="not a URL")],
                 [dict(valid[0], comment=42)], [dict(valid[0], extra=float("nan"))]]
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as d:
                path = Path(d) / "actions.json"
                path.write_text(case if isinstance(case, str) else json.dumps(case))
                err = io.StringIO()
                with mock.patch.object(triage, "default_gh_runner", side_effect=AssertionError("gh")), \
                     contextlib.redirect_stderr(err):
                    self.assertEqual(reconcile_apply.main(["apply", str(path), "--no-dry-run"]), 1)
                self.assertIn("refusing:", err.getvalue())
                self.assertNotIn("Traceback", err.getvalue())
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "actions.json"
            path.write_text(json.dumps(valid))
            receipt = Path(str(path) + ".progress.json")
            receipt.write_text("{corrupt")
            calls = []
            with mock.patch.object(triage, "default_gh_runner", return_value=TestApply()._admin_runner(calls)):
                for reset in ([], ["--reset-progress"]):
                    err = io.StringIO()
                    with contextlib.redirect_stderr(err):
                        self.assertEqual(reconcile_apply.main(["apply", str(path), "--no-dry-run"] + reset), 1)
                    self.assertIn("refusing:", err.getvalue())
                    self.assertNotIn("Traceback", err.getvalue())
                self.assertEqual(calls, [])
                receipt.unlink()
                with mock.patch.object(reconcile_apply, "_save_progress", side_effect=OSError("disk full")), \
                     contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(reconcile_apply.main(["apply", str(path), "--no-dry-run"]), 1)
                self.assertIn("refusing: disk full", err.getvalue())
                self.assertEqual([c[2] for c in calls if c[:2] == ["gh", "issue"]], [])
                path.unlink()
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(reconcile_apply.main(["apply", str(path)]), 1)
                self.assertIn("refusing:", err.getvalue())

    def test_cli_remote_failure_returns_nonzero_and_keeps_bound_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "actions.json"
            path.write_text(json.dumps(TestApply()._actions()))
            def runner(argv, **kwargs):
                if argv[:2] == ["gh", "api"]:
                    return FakeCompleted('{"admin": true}')
                return FakeCompleted("", returncode=1, stderr="mutation failed")
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(triage, "default_gh_runner", return_value=runner), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(reconcile_apply.main(["apply", str(path), "--no-dry-run"]), 1)
            self.assertIn("mutation failed", err.getvalue())
            self.assertNotIn("LIVE:", out.getvalue())
            self.assertEqual(json.loads(Path(str(path) + ".progress.json").read_text())["actions"], {})

    def test_plan_then_dry_apply_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            diff = {"recurring": [{"fingerprint": "fp1",
                                  "run2": [{"id": "F-1", "stored_fingerprint": "old1",
                                           "location_file": "a.py", "kind": "finding"}]}],
                   "closed": [], "new": []}
            ledger = {"old1|F-1|a.py|finding": "https://github.com/o/r/issues/1"}
            diff_path = os.path.join(d, "diff.json")
            ledger_path = os.path.join(d, "ledger.json")
            actions_path = os.path.join(d, "actions.json")
            with open(diff_path, "w") as fh:
                json.dump(diff, fh)
            with open(ledger_path, "w") as fh:
                json.dump(ledger, fh)

            rc = reconcile_apply.main(["plan", diff_path, "--ledger", ledger_path,
                                       "--out", actions_path])
            self.assertEqual(rc, 0)
            with open(actions_path) as fh:
                actions = json.load(fh)
            self.assertEqual(len(actions), 1)

            # apply defaults to dry-run: must print the DRY summary AND make
            # zero real subprocess/gh calls (a live-by-default regression is the
            # single worst outcome this CLI could have).
            def _boom(*a, **k):
                raise AssertionError("dry-run apply must not call subprocess.run")

            buf = io.StringIO()
            with mock.patch("reconcile_apply.subprocess.run", _boom), \
                 mock.patch("triage.subprocess.run", _boom), \
                 contextlib.redirect_stdout(buf):
                rc = reconcile_apply.main(["apply", actions_path])
            self.assertEqual(rc, 0)
            self.assertIn("DRY RUN", buf.getvalue())

    def test_load_ledger_normalizes_legacy_absolute_keys(self):
        abs_path = file_issues.repo_root() + "skill/scripts/run_tools.py"
        rel_path = "skill/scripts/run_tools.py"
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "filed-issues.json")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump({"old1|F-1|%s|finding" % abs_path: "https://github.com/o/r/issues/1"}, fh)
            ledger = file_issues.load_ledger(p)
            self.assertIn("old1|F-1|%s|finding" % rel_path, ledger)
            self.assertEqual(ledger["old1|F-1|%s|finding" % rel_path], "https://github.com/o/r/issues/1")

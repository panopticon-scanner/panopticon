import contextlib
import io
import json
import os
import stat
import sys
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


class TestSystemAliasValidation(unittest.TestCase):
    def test_only_exact_root_owned_darwin_aliases_are_rewritten(self):
        entry = mock.Mock(st_mode=stat.S_IFLNK, st_uid=0)
        for alias in ("var", "tmp", "etc"):
            with self.subTest(alias=alias), mock.patch.object(reconcile_apply.sys, "platform", "darwin"), \
                    mock.patch.object(reconcile_apply.os, "lstat", return_value=entry) as lstat, \
                    mock.patch.object(reconcile_apply.os, "readlink", return_value="private/" + alias):
                self.assertEqual(reconcile_apply._validated_system_alias("/" + alias + "/a/file"),
                                 "/private/" + alias + "/a/file")
                lstat.assert_called_with("/" + alias)
        for mode, uid, target in ((stat.S_IFDIR, 0, "private/var"),
                                  (stat.S_IFLNK, 501, "private/var"),
                                  (stat.S_IFLNK, 0, "elsewhere"),
                                  (stat.S_IFLNK, 0, "private/var/../tmp")):
            with self.subTest(mode=mode, uid=uid, target=target), \
                    mock.patch.object(reconcile_apply.sys, "platform", "darwin"), \
                    mock.patch.object(reconcile_apply.os, "lstat",
                                      return_value=mock.Mock(st_mode=mode, st_uid=uid)), \
                    mock.patch.object(reconcile_apply.os, "readlink", return_value=target):
                self.assertEqual(reconcile_apply._validated_system_alias("/var/a/file"),
                                 "/var/a/file")
        with mock.patch.object(reconcile_apply.sys, "platform", "linux"), \
                mock.patch.object(reconcile_apply.os, "lstat", side_effect=AssertionError("lstat")):
            self.assertEqual(reconcile_apply._validated_system_alias("/var/a/file"), "/var/a/file")
        with mock.patch.object(reconcile_apply.sys, "platform", "darwin"), \
                mock.patch.object(reconcile_apply.os, "lstat", side_effect=AssertionError("lstat")):
            self.assertEqual(reconcile_apply._validated_system_alias("/variable/a/file"),
                             "/variable/a/file")


class TestSaveRecoveredLedger(unittest.TestCase):
    """Direct coverage for save_recovered_ledger: nested-dir creation, content
    round-trip, atomic overwrite, and no leftover temp file."""

    def test_writes_linkage_creating_nested_dirs(self):
        linkage = {"fp|F-1|a.py|finding": "https://github.com/o/r/issues/1"}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nested", "dir", "ledger.json")
            reconcile_apply.save_recovered_ledger(linkage, path=path)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), {"schema_version": 2, "entries": linkage})
            self.assertFalse(os.path.exists(path + ".tmp"))  # temp replaced, not left

    def test_overwrites_existing_ledger_atomically(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ledger.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{\"stale\": true}")
            new = {"fp|F-2|b.py|finding": "https://github.com/o/r/issues/2"}
            reconcile_apply.save_recovered_ledger(new, path=path, replace=True)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), {"schema_version": 2, "entries": new})   # fully replaced, no merge

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

    def test_native_temp_alias_saves_and_replaces_with_exact_backup(self):
        with tempfile.TemporaryDirectory() as d:
            if sys.platform == "darwin":
                self.assertTrue(d.startswith("/var/"), d)
            output = Path(d) / "nested" / "ledger.json"
            first = {"fp|F-1|a.py|finding": "https://github.com/o/r/issues/1"}
            second = {"fp|F-2|b.py|finding": "https://github.com/o/r/issues/2"}
            reconcile_apply.save_recovered_ledger(first, output)
            original = output.read_bytes()
            reconcile_apply.save_recovered_ledger(second, output, replace=True)
            self.assertEqual(file_issues.load_ledger(output), second)
            self.assertEqual(next(output.parent.glob("ledger.json.*.bak")).read_bytes(), original)


class FakeCompleted:
    def __init__(self, stdout, returncode=0, stderr=""):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class TestRecoverLinkage(unittest.TestCase):
    def test_matches_fingerprint_id_location_kind_with_source_report(self):
        finding = {"fingerprint": "008bafabf583e494", "id": "NOV-003",
                   "location": {"file": "tests/test_verdict_ingest.py"}}
        rejected = {"fingerprint": "029bc5414dc2a077", "id": "NOV-008",
                    "location": {"file": "skill/scripts/tools/npm_audit.py"}}
        issues = [{"number": 305, "labels": [{"name": "self-scan"}],
                   "body": file_issues.body_for(finding)},
                  {"number": 399, "labels": [{"name": "false-positive"}],
                   "body": file_issues.body_for(rejected, rejected=True)}]

        def runner(argv, capture_output, text):
            return FakeCompleted(json.dumps(issues))

        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "source.json"
            report.write_text(json.dumps({"findings": [finding], "discarded_claims": [rejected]}))
            linkage = reconcile_apply.recover_linkage_from_github(
                runner=runner, reports={file_issues.REPORT: report})
        self.assertEqual(linkage, {
            file_issues.key_for(finding, False): "https://github.com/panopticon-scanner/panopticon/issues/305",
            file_issues.key_for(rejected, True): "https://github.com/panopticon-scanner/panopticon/issues/399"})

    def test_refuses_issues_missing_the_expected_footer(self):
        issues = [{"number": 1, "labels": [], "body": "no footer here"}]

        def runner(argv, capture_output, text):
            return FakeCompleted(json.dumps(issues))

        with self.assertRaises(reconcile_apply.IncompleteRecovery):
            reconcile_apply.recover_linkage_from_github(runner=runner)

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

        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "source.json"
            report.write_text(json.dumps({"findings": [f]}))
            linkage = reconcile_apply.recover_linkage_from_github(
                runner=runner, reports={file_issues.REPORT: report})
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

        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "source.json"
            report.write_text(json.dumps({"findings": [f]}))
            linkage = reconcile_apply.recover_linkage_from_github(
                runner=runner, reports={file_issues.REPORT: report})
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

    def test_refuses_1000_issue_cap(self):
        issues = [
            {"number": i, "labels": [{"name": "self-scan"}],
             "body": "**Location:** `f%d.py`\n\n---\n\n"
                     "**Fingerprint:** `%016x` — stable.\n"
                     "**Finding id in report:** `F-%d`\n" % (i, i, i)}
            for i in range(1000)
        ]

        def runner(argv, capture_output, text):
            return FakeCompleted(json.dumps(issues))

        with self.assertRaises(reconcile_apply.IncompleteRecovery):
            reconcile_apply.recover_linkage_from_github(runner=runner)

    def test_refuses_when_results_may_be_truncated(self):
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

        with self.assertRaises(reconcile_apply.IncompleteRecovery):
            reconcile_apply.recover_linkage_from_github(runner=runner)

    def test_recovers_path_containing_colon(self):
        finding = {"fingerprint": "abc123defabc1234", "id": "NOV-COLON",
                   "location": {"file": "src/Foo:Bar.cs"}}
        issues = [{"number": 505, "labels": [{"name": "self-scan"}],
                   "body": file_issues.body_for(finding)}]

        def runner(argv, capture_output, text):
            return FakeCompleted(json.dumps(issues))

        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "source.json"
            report.write_text(json.dumps({"findings": [finding]}))
            linkage = reconcile_apply.recover_linkage_from_github(
                runner=runner, reports={file_issues.REPORT: report})
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
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.progress_path = Path(directory.name) / "progress.json"

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

    def test_native_temp_alias_live_apply_and_leaf_lock_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            if sys.platform == "darwin":
                self.assertTrue(d.startswith("/var/"), d)
            action = self._actions()[:1]
            calls = []
            receipt = Path(d) / "progress.json"
            self.assertEqual(reconcile_apply.apply(action, dry=False,
                runner=self._admin_runner(calls), sleep=lambda _: None,
                progress_path=receipt), (1, 0))
            self.assertTrue(receipt.is_file())
            self.assertEqual(reconcile_apply.apply(action, dry=False,
                runner=self._admin_runner(calls), sleep=lambda _: None,
                progress_path=receipt), (0, 0))
            sentinel = Path(d) / "sentinel"
            sentinel.write_bytes(b"unchanged")
            for leaf in ("progress.json", "progress.json.lock"):
                with self.subTest(leaf=leaf):
                    path = Path(d) / leaf
                    path.unlink()
                    path.symlink_to(sentinel)
                    before = len(calls)
                    with self.assertRaises((ValueError, OSError)):
                        reconcile_apply.apply(action, dry=False,
                            runner=self._admin_runner(calls), sleep=lambda _: None,
                            progress_path=receipt)
                    self.assertEqual(len(calls), before)
                    self.assertEqual(sentinel.read_bytes(), b"unchanged")
                    path.unlink()

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
                    if not dry and not with_progress:
                        with self.assertRaisesRegex(ValueError, "progress_path"):
                            reconcile_apply.apply(actions, dry=False, runner=self._admin_runner(calls))
                        self.assertEqual(calls, [])
                        continue
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
                        self.assertEqual([c[-1] for c in comments], [reconcile_apply._comment_body(a, "o/r") for a in unique])
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
                                                   sleep=lambda s: None, progress_path=self.progress_path)
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
                         [reconcile_apply._comment_body(a, "o/r") for a in self._actions()])

    def test_live_run_closes_when_confirmed(self):
        calls = []
        commented, closed = reconcile_apply.apply(self._actions(), dry=False,
                                                   confirm_close=True,
                                                   runner=self._admin_runner(calls),
                                                   sleep=lambda s: None, progress_path=self.progress_path)
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
                                                   sleep=lambda s: None, progress_path=self.progress_path)
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
                                                   sleep=lambda s: None, progress_path=self.progress_path)
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
                                                   runner=runner, sleep=lambda s: None, progress_path=self.progress_path)
        self.assertEqual((commented, closed), (0, 0))
        self.assertEqual(calls, [])            # not dry and actions guard is falsy on []

    def test_later_failure_resumes_without_repeating_acknowledged_comment(self):
        actions = self._actions()
        calls = []
        fail = [True]
        posted = []

        def runner(argv, capture_output, text):
            calls.append(argv)
            if argv[:2] == ["gh", "api"] and "/comments" in argv[2]:
                return FakeCompleted(json.dumps([] if fail[0] else [{"body": posted[-1]}]))
            if argv[:2] == ["gh", "api"]:
                return FakeCompleted('{"admin": true}')
            if argv[:3] == ["gh", "issue", "comment"] and argv[3] == "2" and fail[0]:
                posted.append(argv[-1])
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
                                                   progress_path=progress), (0, 0))
        comments = [c for c in calls if c[:3] == ["gh", "issue", "comment"]]
        self.assertEqual(comments, [])

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
            pending = json.loads(path.read_text())
            pending["actions"][key] = {"commented": False, "closed": False, "comment_pending": True}
            capacity = len(reconcile_apply._progress_bytes(pending))
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
                            self.assertEqual(list(receipt["actions"].values()),
                                [{"commented": False, "closed": False, "comment_pending": True}])
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

    def test_user_symlink_below_native_alias_is_rejected_before_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            if sys.platform == "darwin":
                self.assertTrue(d.startswith("/var/"), d)
            target = Path(d) / "target"
            target.mkdir()
            alias = Path(d) / "alias"
            alias.symlink_to(target, target_is_directory=True)
            calls = []
            with self.assertRaisesRegex(ValueError, "unsafe progress directory"):
                reconcile_apply.apply(self._actions(), dry=False,
                    runner=self._admin_runner(calls), sleep=lambda _: None,
                    progress_path=alias / "receipt.json")
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
    def test_unsupported_directory_alias_has_named_cli_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "target"
            target.mkdir()
            alias = Path(d) / "alias"
            alias.symlink_to(target, target_is_directory=True)
            errors = io.StringIO()
            def runner(*args, **kwargs):
                return FakeCompleted("[]")
            with mock.patch.object(triage, "default_gh_runner", return_value=runner), \
                    contextlib.redirect_stderr(errors):
                result = reconcile_apply.main(["recover-linkage", "--repo", "o/r",
                                               "--out", str(alias / "ledger.json")])
            self.assertEqual(result, 1)
            self.assertIn("refusing:", errors.getvalue())
            self.assertIn("unsafe directory component", errors.getvalue())
            self.assertEqual(list(target.iterdir()), [])

    def test_apply_uses_plan_adjacent_receipt_and_accepts_override(self):
        with tempfile.TemporaryDirectory() as d:
            actions_path = os.path.join(d, "actions.json")
            with open(actions_path, "w", encoding="utf-8") as fh:
                json.dump([], fh)
            with mock.patch("reconcile_apply._apply", return_value=(0, 0)) as apply_mock:
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
            with mock.patch.object(reconcile_apply, "_apply", return_value=(0, 0)) as run:
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

    def test_cli_auth_and_mixed_repo_refusals_are_failures_with_unchanged_receipts(self):
        original = TestApply()._actions()
        for refusal in ("authorization", "mixed repos"):
            for reset in (False, True):
                with self.subTest(refusal=refusal, reset=reset), tempfile.TemporaryDirectory() as d:
                    path = Path(d) / "actions.json"
                    receipt = Path(str(path) + ".progress.json")
                    reconcile_apply.apply(original, False, runner=TestApply()._admin_runner([]),
                                          sleep=lambda _: None, progress_path=receipt)
                    before = receipt.read_bytes()
                    actions = original if refusal == "authorization" else [
                        original[0], dict(original[1], issue="https://github.com/other/repo/issues/2")]
                    path.write_text(json.dumps(actions))
                    calls = []
                    def runner(argv, **kwargs):
                        calls.append(argv)
                        if argv[:2] == ["gh", "api"]:
                            return FakeCompleted('{"admin": false}')
                        self.fail("refusal must not mutate issues")
                    out, err = io.StringIO(), io.StringIO()
                    args = ["apply", str(path), "--no-dry-run"]
                    if reset:
                        args.append("--reset-progress")
                    with mock.patch.object(triage, "default_gh_runner", return_value=runner), \
                         contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        rc = reconcile_apply.main(args)
                    self.assertNotEqual(rc, 0)
                    self.assertIn("refusing:", err.getvalue())
                    self.assertIn("owner/admin" if refusal == "authorization" else "multiple repos",
                                  err.getvalue())
                    self.assertNotIn("LIVE:", out.getvalue())
                    self.assertNotIn("Traceback", err.getvalue())
                    self.assertEqual(len(calls), 1 if refusal == "authorization" else 0)
                    self.assertEqual(receipt.read_bytes(), before)

    def test_cli_completed_resume_and_empty_noop_remain_successful(self):
        for empty in (False, True):
            with self.subTest(empty=empty), tempfile.TemporaryDirectory() as d:
                actions = TestApply()._actions()
                path = Path(d) / "actions.json"
                receipt = Path(str(path) + ".progress.json")
                reconcile_apply.apply(actions, False, runner=TestApply()._admin_runner([]),
                                      sleep=lambda _: None, progress_path=receipt)
                before = receipt.read_bytes()
                path.write_text(json.dumps([] if empty else actions))
                calls = []
                out, err = io.StringIO(), io.StringIO()
                with mock.patch.object(triage, "default_gh_runner",
                                       return_value=TestApply()._admin_runner(calls)), \
                     contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    rc = reconcile_apply.main(["apply", str(path), "--no-dry-run"])
                self.assertEqual(rc, 0)
                self.assertIn("LIVE: commented 0, closed 0", out.getvalue())
                self.assertEqual(err.getvalue(), "")
                self.assertEqual(len(calls), 0 if empty else 1)
                self.assertTrue(all(c[:2] == ["gh", "api"] for c in calls))
                self.assertEqual(receipt.read_bytes(), before)

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
            receipts = json.loads(Path(str(path) + ".progress.json").read_text())["actions"]
            self.assertEqual(list(receipts.values()),
                             [{"commented": False, "closed": False, "comment_pending": True}])

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


class TestSafeRecovery(unittest.TestCase):
    def finding(self, path):
        return {"fingerprint": "abc123", "id": "F-1", "location": {"file": path}}

    def issue(self, finding, report="source.json", rejected=False):
        return {"number": 1, "url": "https://github.com/o/r/issues/1",
                "labels": [{"name": "false-positive"}] if rejected else [],
                "body": file_issues.scrub(file_issues.body_for(
                    finding, rejected, report=report))}

    def recover(self, issues, **kwargs):
        def runner(argv, **kw):
            self.assertIn("--repo", argv)
            self.assertEqual(argv[argv.index("--repo") + 1], "o/r")
            return FakeCompleted(json.dumps(issues))
        return reconcile_apply.recover_linkage_from_github(repo="o/r", runner=runner, **kwargs)

    def test_control_and_root_scrubbing_collisions_require_sources(self):
        pairs = [("a\u0001b.py", "ab.py"),
                 ("prefix" + file_issues.repo_root() + "suffix.py", "prefixsuffix.py")]
        for first, second in pairs:
            originals = [self.finding(first), self.finding(second)]
            self.assertEqual(self.issue(originals[0])["body"], self.issue(originals[1])["body"])
            self.assertNotEqual(*(file_issues.key_for(r, False) for r in originals))
            for record in originals:
                with self.subTest(record=record), tempfile.TemporaryDirectory() as d:
                    with self.assertRaisesRegex(reconcile_apply.IncompleteRecovery, "source report"):
                        self.recover([self.issue(record)])
                    source = Path(d) / "source.json"
                    source.write_text(json.dumps({"findings": [record]}))
                    recovered = self.recover([self.issue(record)], reports={"source.json": source})
                    key = file_issues.key_for(record, False)
                    self.assertEqual(recovered, {key: "https://github.com/o/r/issues/1"})

    def test_plain_issue_requires_matching_source_and_preserves_output(self):
        finding = self.finding("plain.py")
        issue = self.issue(finding)
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "source.json"
            source.write_text(json.dumps({"findings": [finding]}))
            for reports in ({}, {"wrong-artifact.json": source}):
                with self.subTest(reports=reports), \
                        self.assertRaisesRegex(reconcile_apply.IncompleteRecovery, "source report"):
                    self.recover([issue], reports=reports)
            output = Path(d) / "ledger.json"
            before = b'unchanged original ledger bytes\n'
            output.write_bytes(before)
            with mock.patch.object(triage, "default_gh_runner", return_value=lambda *a, **k:
                    FakeCompleted(json.dumps([issue]))):
                self.assertEqual(reconcile_apply.main(["recover-linkage", "--repo", "o/r",
                    "--out", str(output), "--replace-ledger"]), 1)
            self.assertEqual(output.read_bytes(), before)
            self.assertEqual(set(Path(d).iterdir()), {source, output})

    def test_empty_recovery_without_reports_is_valid(self):
        self.assertEqual(self.recover([]), {})
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / "ledger.json"
            with mock.patch.object(triage, "default_gh_runner", return_value=lambda *a, **k:
                    FakeCompleted("[]")):
                self.assertEqual(reconcile_apply.main(["recover-linkage", "--repo", "o/r",
                    "--out", str(output)]), 0)
            self.assertEqual(file_issues.load_ledger(output), {})

    def test_producer_source_roundtrip(self):
        for name in ("@name", "#123", "](", "https://example/a", "Foo:Bar", "a\u200bb", "@\u200bname"):
            for rejected in (False, True):
                with self.subTest(name=name, rejected=rejected), tempfile.TemporaryDirectory() as d:
                    finding = self.finding("src/" + name)
                    finding["location"]["line_start"] = 12
                    report = Path(d) / "source.json"
                    report.write_text(json.dumps({"findings": [] if rejected else [finding],
                        "discarded_claims": [finding] if rejected else []}))
                    recovered = self.recover([self.issue(finding, rejected=rejected)],
                                             reports={"source.json": str(report)})
                    self.assertEqual(recovered, {file_issues.key_for(finding, rejected):
                                                 "https://github.com/o/r/issues/1"})

    def test_producer_numeric_suffix_has_two_distinct_originals(self):
        file_with_line = self.finding("file.py")
        file_with_line["location"]["line_start"] = 12
        numeric_path = self.finding("file.py:12")
        self.assertEqual(self.issue(file_with_line)["body"], self.issue(numeric_path)["body"])
        keys = []
        for record in (file_with_line, numeric_path):
            with self.subTest(record=record), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(reconcile_apply.IncompleteRecovery, "source report"):
                    self.recover([self.issue(record)])
                source = Path(d) / "source.json"
                source.write_text(json.dumps({"findings": [record]}))
                recovered = self.recover([self.issue(record)], reports={"source.json": source})
                key = file_issues.key_for(record, False)
                self.assertIn(key, recovered)
                keys.append(key)
        self.assertNotEqual(*keys)

    def test_producer_placeholder_and_quote_collisions_require_sources(self):
        pairs = [(self.finding(""), self.finding("(no file)")),
                 (self.finding("a`b"), self.finding("a'b"))]
        for first, second in pairs:
            self.assertEqual(self.issue(first)["body"], self.issue(second)["body"])
            keys = []
            for record in (first, second):
                with self.subTest(record=record), tempfile.TemporaryDirectory() as d:
                    with self.assertRaises(reconcile_apply.IncompleteRecovery):
                        self.recover([self.issue(record)])
                    source = Path(d) / "source.json"
                    source.write_text(json.dumps({"findings": [record]}))
                    recovered = self.recover([self.issue(record)], reports={"source.json": source})
                    key = file_issues.key_for(record, False)
                    self.assertIn(key, recovered)
                    keys.append(key)
            self.assertNotEqual(*keys)

    def test_ambiguous_location_requires_source(self):
        for name in ("@name", "a\u200bb", "file:123", "has'quote", "(no file)"):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "source report"):
                self.recover([self.issue(self.finding(name))])

    def test_incomplete_recovery_preserves_existing_cli_output(self):
        valid = self.issue(self.finding("a.py"))
        for payload in ({}, [None], [valid] * 1000, [valid, valid],
                        [dict(valid, url="https://github.com/other/repo/issues/1")],
                        [dict(valid, body="missing identity")],
                        [self.issue(self.finding("@name"))],
                        [valid, dict(valid, number=2, url="https://github.com/o/r/issues/2")]):
            with self.subTest(payload=str(payload)[:60]), tempfile.TemporaryDirectory() as d:
                output = Path(d) / "ledger.json"
                original = b'{"original": "bytes"}\n'
                output.write_bytes(original)
                report = Path(d) / "source.json"
                report.write_text(json.dumps({"findings": [self.finding("a.py")]}))
                with mock.patch.object(triage, "default_gh_runner", return_value=lambda *a, **k:
                        FakeCompleted(json.dumps(payload))):
                    self.assertEqual(reconcile_apply.main(["recover-linkage", "--repo", "o/r",
                        "--out", str(output), "--replace-ledger",
                        "--report", "source.json=" + str(report)]), 1)
                self.assertEqual(output.read_bytes(), original)
                self.assertEqual(list(Path(d).glob("*.bak*")), [])

    def test_replace_requires_flag_and_backs_up_exact_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / "ledger.json"
            original = b'legacy or corrupt evidence\n'
            output.write_bytes(original)
            finding = self.finding("a.py")
            report = Path(d) / "source.json"
            report.write_text(json.dumps({"findings": [finding]}))
            linkage = self.recover([self.issue(finding)], reports={"source.json": report})
            with self.assertRaises(FileExistsError):
                reconcile_apply.save_recovered_ledger(linkage, output)
            self.assertEqual(output.read_bytes(), original)
            reconcile_apply.save_recovered_ledger(linkage, output, replace=True)
            self.assertEqual(file_issues.load_ledger(output), linkage)
            backups = list(Path(d).glob("ledger.json.*.bak"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), original)
            reconcile_apply.save_recovered_ledger(linkage, output, replace=True)
            self.assertEqual(len(list(Path(d).glob("ledger.json.*.bak"))), 2)

    def test_refuse_symlink_output_and_lock(self):
        for target_name in ("ledger.json", "ledger.json.lock"):
            with self.subTest(target=target_name), tempfile.TemporaryDirectory() as d:
                target = Path(d) / "original"
                target.write_bytes(b'original')
                (Path(d) / target_name).symlink_to(target)
                with self.assertRaises((ValueError, OSError)):
                    reconcile_apply.save_recovered_ledger({}, Path(d) / "ledger.json", replace=True)
                self.assertEqual(target.read_bytes(), b'original')


    def test_cli_report_mapping_source_root_and_backup(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "copy.json"
            original = self.finding("/original/checkout/src/@name")
            source.write_text(json.dumps({"findings": [original]}))
            posted = self.finding("src/@name")
            issue = self.issue(posted, report="reports/run.json")
            output = Path(d) / "ledger.json"
            output.write_bytes(b'old bytes\n')
            args = ["recover-linkage", "--repo", "o/r", "--out", str(output),
                    "--report", "reports/run.json=" + str(source), "--replace-ledger"]
            with mock.patch.object(triage, "default_gh_runner", return_value=lambda *a, **k:
                    FakeCompleted(json.dumps([issue]))):
                self.assertEqual(reconcile_apply.main(args), 1)
                self.assertEqual(output.read_bytes(), b'old bytes\n')
                self.assertEqual(reconcile_apply.main(args + ["--source-root", "/original/checkout"]), 0)
            self.assertEqual(file_issues.load_ledger(output),
                             {file_issues.key_for(posted, False): issue["url"]})
            self.assertEqual(next(Path(d).glob("*.bak")).read_bytes(), b'old bytes\n')

    def test_source_identity_and_pointer_conflicts_refuse(self):
        finding = self.finding("@name")
        wrong_id = dict(finding, id="F-other")
        wrong_fp = dict(finding, fingerprint="fff")
        wrong_path = self.finding("other")
        cases = [{"findings": [wrong_id]}, {"findings": [wrong_fp]},
                 {"findings": [wrong_path]}, {"discarded_claims": [finding]},
                 {"findings": [finding, finding]}]
        for document in cases:
            with self.subTest(document=document), tempfile.TemporaryDirectory() as d:
                source = Path(d) / "copy.json"
                source.write_text(json.dumps(document))
                with self.assertRaises(reconcile_apply.IncompleteRecovery):
                    self.recover([self.issue(finding)], reports={"source.json": source})
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "copy.json"
            source.write_text(json.dumps({"findings": [finding]}))
            with self.assertRaises(reconcile_apply.IncompleteRecovery):
                self.recover([self.issue(finding)], reports={"wrong-pointer.json": source})

    def test_confined_split_and_spill_reports(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d) / "reports"
            directory.mkdir()
            source = directory / "copy.json"
            finding = self.finding("src/@name")
            (directory / "part.json").write_text(json.dumps({"findings": [finding]}))
            rejected = dict(finding, id="REJECTED")
            (directory / "discarded.json").write_text(json.dumps({"discarded_claims": [rejected]}))
            document = {"meta": {"parts": ["part.json"], "discarded_claims_file": "discarded.json"}}
            source.write_text(json.dumps(document))
            rejected_issue = dict(self.issue(rejected, rejected=True), number=2,
                                  url="https://github.com/o/r/issues/2")
            recovered = self.recover([self.issue(finding), rejected_issue],
                                     reports={"source.json": source})
            self.assertEqual(set(recovered), {file_issues.key_for(finding, False),
                                             file_issues.key_for(rejected, True)})
            outside = Path(d) / "outside.json"
            outside.write_text(json.dumps({"findings": [finding]}))
            (directory / "escape.json").symlink_to(outside)
            for continuation in ("../outside.json", "escape.json"):
                for field in ("parts", "discarded_claims_file"):
                    source.write_text(json.dumps({"meta": {field:
                        [continuation] if field == "parts" else continuation}}))
                    with self.subTest(field=field, continuation=continuation), \
                            self.assertRaises(reconcile_apply.IncompleteRecovery):
                        self.recover([self.issue(finding)], reports={"source.json": source})

    def test_failed_fetch_and_malformed_json_leave_output_untouched(self):
        import subprocess
        cases = [FakeCompleted("not json"), FakeCompleted("[]", returncode=1, stderr="offline"),
                 subprocess.TimeoutExpired("gh", 120), OSError("offline")]
        for response in cases:
            with self.subTest(response=response), tempfile.TemporaryDirectory() as d:
                output = Path(d) / "ledger.json"
                output.write_bytes(b'original')
                def runner(*args, **kwargs):
                    if isinstance(response, Exception):
                        raise response
                    return response
                with mock.patch.object(triage, "default_gh_runner", return_value=runner):
                    self.assertEqual(reconcile_apply.main(["recover-linkage", "--repo", "o/r",
                        "--out", str(output), "--replace-ledger"]), 1)
                self.assertEqual(output.read_bytes(), b'original')
                self.assertEqual(list(Path(d).iterdir()), [output])

    def test_cli_create_only_and_invalid_repo(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / "ledger.json"
            finding = self.finding("safe.py")
            report = Path(d) / "source.json"
            report.write_text(json.dumps({"findings": [finding]}))
            runner = mock.Mock(return_value=FakeCompleted(json.dumps([self.issue(finding)])))
            with mock.patch.object(triage, "default_gh_runner", return_value=runner):
                args = ["recover-linkage", "--repo", "o/r", "--out", str(output),
                        "--report", "source.json=" + str(report)]
                self.assertEqual(reconcile_apply.main(args), 0)
                before = output.read_bytes()
                self.assertEqual(reconcile_apply.main(args), 1)
                self.assertEqual(output.read_bytes(), before)
                for invalid in ("--evil", "o/r/more", "../r", "https://github.com/o/r"):
                    runner.reset_mock()
                    with self.assertRaises(SystemExit):
                        reconcile_apply.main(["recover-linkage", "--repo=" + invalid, "--out", str(output)])
                    runner.assert_not_called()
                    self.assertEqual(output.read_bytes(), before)

    def test_replace_failure_preserves_old_ledger_and_backup(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / "ledger.json"
            output.write_bytes(b'old bytes\n')
            with mock.patch.object(reconcile_apply.os, "replace", side_effect=OSError("disk full")), \
                    self.assertRaises(OSError):
                reconcile_apply.save_recovered_ledger({}, output, replace=True)
            self.assertEqual(output.read_bytes(), b'old bytes\n')
            self.assertEqual(next(Path(d).glob("*.bak")).read_bytes(), b'old bytes\n')
            self.assertEqual(list(Path(d).glob(".reconcile-ledger-*")), [])

    def test_backup_collision_and_symlink_ancestor_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / "ledger.json"
            output.write_bytes(b'old')
            with mock.patch.object(reconcile_apply, "datetime") as clock, \
                    mock.patch.object(reconcile_apply.os, "urandom", return_value=b'constant'):
                clock.now.return_value.strftime.return_value = "timestamp"
                reconcile_apply.save_recovered_ledger({}, output, replace=True)
                current = output.read_bytes()
                backup = next(Path(d).glob("*.bak"))
                with self.assertRaises(FileExistsError):
                    reconcile_apply.save_recovered_ledger({}, output, replace=True)
                self.assertEqual(output.read_bytes(), current)
                self.assertEqual(backup.read_bytes(), b'old')
            alias = Path(d) / "alias"
            alias.symlink_to(d, target_is_directory=True)
            with self.assertRaises(OSError):
                reconcile_apply.save_recovered_ledger({}, alias / "ledger.json", replace=True)
            self.assertEqual(output.read_bytes(), current)


class TestPendingComment(unittest.TestCase):
    def test_timeout_pending_resume_posts_only_once(self):
        import subprocess
        action = {"issue": "https://github.com/o/r/issues/1", "comment": "hello",
                  "cohort": "recurring", "close": False}
        posted = []
        probe = []
        with tempfile.TemporaryDirectory() as d:
            progress = Path(d) / "progress.json"

            def runner(argv, **kwargs):
                if argv[:3] == ["gh", "issue", "comment"]:
                    receipt = json.loads(progress.read_text())
                    self.assertTrue(next(iter(receipt["actions"].values()))["comment_pending"])
                    posted.append(argv[argv.index("--body") + 1])
                    raise subprocess.TimeoutExpired(argv, 120)
                if argv[:2] == ["gh", "api"] and "/comments" in argv[2]:
                    self.assertIn("repos/o/r/issues/1/comments", argv[2])
                    return FakeCompleted(json.dumps(probe))
                return FakeCompleted('{"admin": true}')

            for _ in range(2):
                with self.assertRaisesRegex(RuntimeError, "pending"):
                    reconcile_apply.apply([action], dry=False, runner=runner,
                        sleep=lambda _: None, progress_path=progress)
            self.assertEqual(len(posted), 1)
            probe[:] = [{"body": posted[0]}]
            self.assertEqual(reconcile_apply.apply([action], dry=False, runner=runner,
                sleep=lambda _: None, progress_path=progress), (0, 0))
            self.assertEqual(len(posted), 1)
            receipt = next(iter(json.loads(progress.read_text())["actions"].values()))
            self.assertTrue(receipt["commented"])
            self.assertNotIn("comment_pending", receipt)

    def test_crash_and_ack_write_failure_reconcile_without_reposting(self):
        action = {"issue": "https://github.com/o/r/issues/1", "comment": "hello",
                  "cohort": "recurring", "close": False}
        for failure in ("crash", "ack-write"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as d:
                progress = Path(d) / "progress.json"
                posted = []
                def runner(argv, **kwargs):
                    if argv[:3] == ["gh", "issue", "comment"]:
                        posted.append(argv[-1])
                        if failure == "crash":
                            raise SystemExit("process died after acceptance")
                        return FakeCompleted("")
                    if "/comments" in argv[2]:
                        return FakeCompleted(json.dumps([{"body": posted[0]}]))
                    return FakeCompleted('{"admin": true}')
                save = reconcile_apply._save_progress
                def save_receipt(receipt, path):
                    if failure == "ack-write" and any(r["commented"] for r in receipt["actions"].values()):
                        raise OSError("disk full after acceptance")
                    save(receipt, path)
                with mock.patch.object(reconcile_apply, "_save_progress", side_effect=save_receipt), \
                        self.assertRaises((SystemExit, OSError)):
                    reconcile_apply.apply([action], False, runner=runner,
                        sleep=lambda _: None, progress_path=progress)
                self.assertTrue(next(iter(json.loads(progress.read_text())["actions"].values()))["comment_pending"])
                self.assertEqual(reconcile_apply.apply([action], False, runner=runner,
                    sleep=lambda _: None, progress_path=progress), (0, 0))
                self.assertEqual(len(posted), 1)

    def test_only_complete_exact_comment_probe_can_clear_pending(self):
        action = {"issue": "https://github.com/o/r/issues/1", "comment": "hello",
                  "cohort": "recurring", "close": False}
        body = reconcile_apply._comment_body(action, "o/r")
        cases = [FakeCompleted("bad json"), FakeCompleted("[]", returncode=1),
                 FakeCompleted(json.dumps({"comments": []})),
                 FakeCompleted(json.dumps([{"body": body}] * 100)),
                 FakeCompleted(json.dumps([{"body": body}] * 2)),
                 FakeCompleted(json.dumps([{"body": "changed " + body}])),
                 FakeCompleted(json.dumps([{"body": action["comment"]}])),
                 FakeCompleted(json.dumps([{"body": body}, {"missing": "body"}]))]
        for response in cases:
            with self.subTest(response=response.stdout[:60]), tempfile.TemporaryDirectory() as d:
                progress = Path(d) / "progress.json"
                key = reconcile_apply._action_key(action, "o/r")
                receipt = reconcile_apply._bind_progress(None, "o/r", [key], False)
                receipt["actions"][key] = {"commented": False, "closed": False, "comment_pending": True}
                reconcile_apply._save_progress(receipt, progress)
                before = progress.read_bytes()
                def runner(argv, **kwargs):
                    self.assertNotEqual(argv[:3], ["gh", "issue", "comment"])
                    return response if "/comments" in argv[2] else FakeCompleted('{"admin": true}')
                with self.assertRaisesRegex(RuntimeError, "pending"):
                    reconcile_apply.apply([action], False, runner=runner,
                        sleep=lambda _: None, progress_path=progress)
                self.assertEqual(progress.read_bytes(), before)

    def test_cli_timeout_resume_has_one_mutation(self):
        import subprocess
        action = {"issue": "https://github.com/o/r/issues/1", "comment": "hello",
                  "cohort": "recurring", "close": False}
        posted = []
        ready = False
        def runner(argv, **kwargs):
            if argv[:3] == ["gh", "issue", "comment"]:
                posted.append(argv[-1])
                raise subprocess.TimeoutExpired(argv, 120)
            if "/comments" in argv[2]:
                return FakeCompleted(json.dumps([{"body": posted[0]}] if ready else []))
            return FakeCompleted('{"admin": true}')
        with tempfile.TemporaryDirectory() as d:
            plan = Path(d) / "plan.json"
            plan.write_text(json.dumps([action]))
            with mock.patch.object(triage, "default_gh_runner", return_value=runner):
                args = ["apply", str(plan), "--no-dry-run", "--throttle", "0"]
                self.assertEqual(reconcile_apply.main(args), 1)
                self.assertEqual(reconcile_apply.main(args), 1)
                ready = True
                self.assertEqual(reconcile_apply.main(args), 0)
                self.assertEqual(len(posted), 1)

    def test_accepted_timeout_can_be_acknowledged_immediately(self):
        import subprocess
        action = {"issue": "https://github.com/o/r/issues/1", "comment": "hello",
                  "cohort": "recurring", "close": True}
        posted, closed = [], []
        def runner(argv, **kwargs):
            if argv[:3] == ["gh", "issue", "comment"]:
                posted.append(argv[-1])
                raise subprocess.TimeoutExpired(argv, 120)
            if argv[:3] == ["gh", "issue", "close"]:
                closed.append(argv)
                return FakeCompleted("")
            if "/comments" in argv[2]:
                return FakeCompleted(json.dumps([{"body": posted[0]}]))
            return FakeCompleted('{"admin": true}')
        with tempfile.TemporaryDirectory() as d:
            progress = Path(d) / "progress.json"
            self.assertEqual(reconcile_apply.apply([action], False, True, runner=runner,
                sleep=lambda _: None, progress_path=progress), (1, 1))
            self.assertEqual(reconcile_apply.apply([action], False, True, runner=runner,
                sleep=lambda _: None, progress_path=progress), (0, 0))
            self.assertEqual(len(posted), 1)
            self.assertEqual(len(closed), 1)

import os
import tempfile
import types
import unittest
from unittest import mock

import file_issues
import triage


def _completed(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


FINDING = {
    "fingerprint": "deadbeefcafe0001",
    "id": "SEC-007",
    "location": {"file": "skill/scripts/run_tools.py", "line_start": 42},
    "severity": "HIGH",
    "evidence": {"status": "advisor_confirmed"},
    "confidence": "LIKELY",
    "description": "example",
}


class TestBodyProvenance(unittest.TestCase):
    def test_defaults_preserve_run2_footer(self):
        """body_for() with no run overrides must still describe run 2, so the
        one existing caller (reconcile_apply's recovery test) and any bare call
        keep working."""
        body = file_issues.body_for(FINDING)
        self.assertIn("self-scan run 2, 2026-08-04", body)
        self.assertIn(file_issues.RUN_STATE_DOC, body)
        self.assertIn(
            "https://github.com/panopticon-scanner/panopticon/blob/main/"
            "docs/superpowers/2026-08-04-self-scan-report.json", body)

    def test_run_overrides_thread_into_footer(self):
        body = file_issues.body_for(
            FINDING,
            report="docs/superpowers/2026-08-08-self-scan-report.json",
            report_url="https://example.test/run3.json",
            run_label="run 3",
            run_date="2026-08-08",
            run_state_doc="docs/superpowers/2026-08-08-self-scan-run-state.md")
        self.assertIn("self-scan run 3, 2026-08-08", body)
        self.assertIn("https://example.test/run3.json", body)
        self.assertIn("docs/superpowers/2026-08-08-self-scan-run-state.md", body)
        self.assertNotIn("run 2, 2026-08-04", body)

    def test_provenance_anchor_lines_are_stable(self):
        """The Fingerprint / Finding id / Location lines are the cross-run
        identity that reconcile recovery parses; parameterizing the report
        provenance must never disturb them."""
        body = file_issues.body_for(FINDING, run_label="run 3", run_date="2026-08-08")
        self.assertIn("**Fingerprint:** `deadbeefcafe0001`", body)
        self.assertIn("**Finding id in report:** `SEC-007`", body)
        self.assertIn("**Location:** `skill/scripts/run_tools.py:42`", body)


class TestBodyIdentityGuard(unittest.TestCase):
    def test_body_for_raises_on_missing_round_trip_identity(self):
        # #run7 COD-C3A: an empty fingerprint/id renders as empty backticks and
        # silently breaks reconcile's round-trip recovery -- must fail loud.
        file_issues.body_for(FINDING)   # complete identity -> no raise
        for bad in ({**FINDING, "fingerprint": ""},
                    {**FINDING, "id": ""},
                    {k: v for k, v in FINDING.items() if k != "id"}):
            with self.assertRaises(ValueError):
                file_issues.body_for(bad)


class TestBodyDefang(unittest.TestCase):
    """Attacker-influenced finding text (from scanned repos, incl. quoted
    injection payloads) is posted to PUBLIC issues: @mentions, links and issue
    refs must not fire, control bytes are stripped, but legitimate structure
    (code spans) must survive. (run-4 self-scan C10/C11.)"""

    def _f(self, **over):
        f = {"id": "X-1", "fingerprint": "fp1", "severity": "HIGH",
             "confidence": "POSSIBLE", "location": {"file": "a.py", "line_start": 1}}
        f.update(over)
        return f

    def test_defuses_mentions_links_and_refs(self):
        body = file_issues.body_for(self._f(
            description=("@everyone see [click](http://evil.example) " \
                                "and [ref][1] and <https://evil.example> "\
                                "and https://evil.example re #1\n![img](http://evil.example)"),
            remediation="ping @maintainer at [1]: http://evil.example"))
        self.assertNotIn("@everyone", body)
        self.assertNotIn("@maintainer", body)
        self.assertIn("@​everyone", body)
        self.assertNotIn("](http://evil.example)", body)
        self.assertNotIn("][1]", body)
        self.assertNotIn("]: http://evil.example", body)
        self.assertNotIn("![img]", body)
        self.assertNotIn("<https://evil.example>", body)
        self.assertNotIn(" https://evil.example", body)
        self.assertIn("#​1", body)

    def test_strips_control_bytes(self):
        body = file_issues.body_for(self._f(description="danger\x1b[31mred\x07bell"))
        self.assertNotIn("\x1b", body)
        self.assertNotIn("\x07", body)

    def test_preserves_legitimate_code_spans(self):
        body = file_issues.body_for(self._f(
            description="the `parse()` helper mishandles input"))
        self.assertIn("`parse()`", body)

    def test_title_mention_defanged(self):
        title = file_issues.title_for(self._f(short_title="@team broken"))
        self.assertNotIn("@team", title)
        self.assertIn("@​team", title)

    def test_title_filename_suffix_is_defanged(self):
        f = {
            "title": "Some issue",
            "location": {"file": "src/@mention.py"},
        }
        title = file_issues.title_for(f)
        self.assertNotIn("@mention", title)
        self.assertIn("(@\u200bmention.py)", title)

    def test_defang_url_schemes_insert_zero_width_space(self):
        """Regression: defang() must insert a zero-width space after the
        leading 'h' in http(s) URLs so they are not rendered as clickable
        links in public GitHub issues."""
        self.assertIn("h\u200bttps://", file_issues.defang("https://example.com"))
        self.assertIn("h\u200bttp://", file_issues.defang("http://example.com"))


class TestRepoRootPortability(unittest.TestCase):
    """#602: REPO_ROOT was a hardcoded machine-specific absolute path; on any
    other machine scrub() silently no-opped and leaked local paths into public
    issues. It is now detected dynamically."""

    def test_repo_root_is_dynamic_absolute_with_trailing_sep(self):
        root = file_issues.repo_root()
        self.assertTrue(root.endswith("/"))
        self.assertTrue(os.path.isabs(root))
        # Detected root is this checkout — file_issues.py lives under it.
        self.assertTrue(os.path.abspath(__file__).startswith(root))

    def test_scrub_strips_the_detected_root(self):
        abs_path = file_issues.repo_root() + "skill/scripts/run_tools.py"
        self.assertEqual(file_issues.scrub("see %s here" % abs_path),
                         "see skill/scripts/run_tools.py here")

    def test_scrub_does_not_rewrite_sibling_prefixes(self):
        sibling = file_issues.repo_root().rstrip("/") + "-docs/guide.md"
        self.assertEqual(file_issues.scrub("see %s here" % sibling),
                         "see %s here" % sibling)

    def test_repo_relative_passes_through_relative_and_foreign_paths(self):
        self.assertEqual(file_issues.repo_relative("skill/a.py"), "skill/a.py")
        self.assertEqual(file_issues.repo_relative("/elsewhere/b.py"),
                         "/elsewhere/b.py")
        self.assertEqual(
            file_issues.repo_relative(file_issues.repo_root() + "c.py"), "c.py")


class TestKeyForNormalization(unittest.TestCase):
    """#607/#488: the ledger key's location component must be repo-relative so
    it matches the scrubbed issue body and recovers losslessly."""

    def test_absolute_location_keys_relative(self):
        f = {"fingerprint": "fp1", "id": "SEC-1",
             "location": {"file": file_issues.repo_root() + "skill/x.py"}}
        self.assertEqual(file_issues.key_for(f, rejected=False),
                         "fp1|SEC-1|skill/x.py|finding")

    def test_relative_location_unchanged(self):
        f = {"fingerprint": "fp1", "id": "SEC-1",
             "location": {"file": "skill/x.py"}}
        self.assertEqual(file_issues.key_for(f, rejected=False),
                         "fp1|SEC-1|skill/x.py|finding")

    def test_missing_location_keys_empty(self):
        self.assertEqual(file_issues.key_for({"fingerprint": "fp1", "id": "X"},
                                             rejected=True),
                         "fp1|X||rejected")


class TestCreateEmptyStdout(unittest.TestCase):
    """GitHub secondary rate limits make `gh issue create` exit 0 with empty
    stdout. create() must back off and retry, never crash on splitlines()[-1]."""

    def test_empty_stdout_then_url_retries_and_returns(self):
        # #1212 changed what happens BETWEEN the empty response and the retry:
        # the ambiguous rc=0 is now probed (`gh issue list`) before re-creating,
        # so a create that actually landed is adopted instead of duplicated.
        # Here the probe reports nothing filed, so the retry proceeds as before.
        calls = [_completed(0, ""),                        # create: rc=0, no url
                 _completed(0, "[]"),                      # probe: nothing filed
                 _completed(0, "https://gh/issues/900")]   # retry: the real url
        with mock.patch.object(file_issues.subprocess, "run",
                               side_effect=calls) as run, \
             mock.patch.object(file_issues.time, "sleep") as slept:
            url = file_issues.create("t", "b", ["self-scan"], dry=False)
        self.assertEqual(url, "https://gh/issues/900")
        self.assertEqual(run.call_count, 3)
        slept.assert_called()  # backed off between the empty response and retry

    def test_persistent_empty_stdout_returns_none_without_crashing(self):
        with mock.patch.object(file_issues.subprocess, "run",
                               return_value=_completed(0, "")), \
             mock.patch.object(file_issues.time, "sleep"):
            url = file_issues.create("t", "b", ["self-scan"], dry=False)
        self.assertIsNone(url)  # gave up after retries; run continues, no exception

    def test_create_passes_timeout_to_gh(self):
        # #1104: the network `gh issue create` call must be bounded.
        captured = {}
        def _run(cmd, **kw):
            captured.update(kw)
            return _completed(0, "https://gh/issues/1")
        with mock.patch.object(file_issues.subprocess, "run", side_effect=_run), \
             mock.patch.object(file_issues.time, "sleep"):
            url = file_issues.create("t", "b", ["self-scan"], dry=False)
        self.assertEqual(url, "https://gh/issues/1")
        self.assertEqual(captured.get("timeout"), file_issues.GH_CREATE_TIMEOUT)

    def test_persistent_timeout_returns_none_without_hanging(self):
        # A hung gh is retried, then abandoned (un-ledgered, resumable) -- bounded,
        # never an infinite block (#1104).
        def _run(cmd, **kw):
            raise file_issues.subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        with mock.patch.object(file_issues.subprocess, "run", side_effect=_run), \
             mock.patch.object(file_issues.time, "sleep") as slept:
            url = file_issues.create("t", "b", ["self-scan"], dry=False)
        self.assertIsNone(url)
        slept.assert_called()


def test_body_fingerprint_and_id_are_backtick_safe():
    f = {
        "title": "x",
        "description": "x",
        "severity": "HIGH",
        "confidence": "CERTAIN",
        "location": {"file": "src/x.py"},
        "fingerprint": "abc`def",
        "id": "SEC-001`inject",
        "citations": {"cwe": ["CWE-079`x"]},
    }
    body = file_issues.body_for(f)
    assert "`abc`def`" not in body
    assert "`SEC-001`inject`" not in body
    assert "CWE-079`x" not in body


class TestLedgerSafety(unittest.TestCase):
    def test_record_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nested", "dir", "ledger.json")
            file_issues.record({}, "k", "url", path=path)
            self.assertTrue(os.path.isfile(path))
            self.assertEqual(file_issues.load_ledger(path=path), {"k": "url"})

    def test_load_ledger_fails_loud_on_corrupt_json(self):
        # #run9 COD-B1A: a PRESENT but corrupt ledger must NOT be treated as empty
        # -- doing so reset the dedup state and re-filed every finding as a
        # duplicate. Fail loud so the operator restores/repairs it.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ledger.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            with self.assertRaises(RuntimeError) as cm:
                file_issues.load_ledger(path=path)
            self.assertIn("re-file", str(cm.exception))

    def test_load_ledger_missing_file_is_empty_first_run(self):
        # A MISSING ledger is a legitimate first run -> empty dict, no raise.
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(
                file_issues.load_ledger(path=os.path.join(d, "nope.json")), {})


if __name__ == "__main__":
    unittest.main()


class TestVerifiedByRendering(unittest.TestCase):
    """#run11 COD-D3C: evidence.derive_evidence returns verified_by as a LIST in
    some branches and a bare STRING in others. Iterating a string yields
    CHARACTERS, so the public issue body read 'a, g, e, n, t, :, ...'."""

    def _body(self, verified_by):
        f = dict(FINDING, evidence={"status": "tool_reported",
                                    "verified_by": verified_by})
        return file_issues.body_for(f, False)

    def test_string_verified_by_renders_as_one_identity(self):
        body = self._body("tool:bandit")
        self.assertIn("**Corroborating panels:** tool:bandit", body)
        self.assertNotIn("t, o, o, l", body)

    def test_list_verified_by_still_joins_the_identities(self):
        self.assertIn("**Corroborating panels:** security, database",
                      self._body(["security", "database"]))

    def test_single_character_identity_is_not_mistaken_for_a_list(self):
        self.assertIn("**Corroborating panels:** x", self._body("x"))


class TestPartPathConfinement(unittest.TestCase):
    """#1523 (SEC-D1C): this filer publishes to PERMANENT PUBLIC issues, and its
    copy of the part-path check never got the realpath re-confinement the
    reconcile.py original was hardened with, so a planted same-directory symlink
    exfiltrated an arbitrary JSON file into the issue tracker."""

    def test_rejects_parts_entry_escaping_via_symlink(self):
        with tempfile.TemporaryDirectory() as base:
            outside = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
            outside.write(b"{}")
            outside.close()
            try:
                os.symlink(outside.name, os.path.join(base, "part.json"))
                with self.assertRaises(ValueError):
                    file_issues.resolve_part_path(base, "part.json")
                real = os.path.join(base, "ok.json")
                with open(real, "w") as fh:
                    fh.write("{}")
                self.assertEqual(file_issues.resolve_part_path(base, "ok.json"),
                                 os.path.realpath(real))
            finally:
                os.unlink(outside.name)

    def test_rejects_lexical_escape_and_absolute_parts(self):
        with tempfile.TemporaryDirectory() as base:
            for bad in ("../../etc/passwd", "/etc/passwd"):
                with self.assertRaises(ValueError):
                    file_issues.resolve_part_path(base, bad)

    def test_is_the_same_function_reconcile_hardened(self):
        # The defect was a COPY that drifted. Pin the shared identity so it
        # cannot silently fork again.
        import scripts.reconcile as reconcile
        self.assertIs(file_issues.resolve_part_path,
                      reconcile._resolve_part_path)


class TestLedgerConcurrency(unittest.TestCase):
    """#run11 DAT-F1C: main() loads the ledger once, then every record() wrote
    the WHOLE in-memory dict back. A second filer running concurrently had its
    entries silently overwritten -- and a lost ledger entry means the finding is
    re-filed as a DUPLICATE public issue on the next run."""

    def test_record_preserves_an_entry_written_by_another_process(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ledger.json")
            mine = {}
            file_issues.record(mine, "a|1||finding", "url-a", path=path)
            # Another filer records its own finding while this one holds `mine`.
            file_issues.record({}, "b|2||finding", "url-b", path=path)
            # This filer records a second entry from its now-stale in-memory dict.
            file_issues.record(mine, "c|3||finding", "url-c", path=path)
            on_disk = file_issues.load_ledger(path=path)
        self.assertEqual(on_disk, {"a|1||finding": "url-a",
                                   "b|2||finding": "url-b",
                                   "c|3||finding": "url-c"})

    def test_record_takes_an_exclusive_lock(self):
        if file_issues.fcntl is None:
            self.skipTest("no fcntl on this platform")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ledger.json")
            with mock.patch.object(file_issues.fcntl, "flock",
                                   wraps=file_issues.fcntl.flock) as flock:
                file_issues.record({}, "k", "u", path=path)
        modes = [c.args[1] for c in flock.call_args_list]
        self.assertIn(file_issues.fcntl.LOCK_EX, modes)

    def test_record_still_updates_the_callers_dict(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = {}
            file_issues.record(ledger, "k", "u",
                               path=os.path.join(d, "ledger.json"))
        self.assertEqual(ledger["k"], "u")


class TestLedgerSchemaVersion(unittest.TestCase):
    """#run11 DAT-F2A: the ledger carried no version, so key-format evolution was
    detected by counting '|' fields. A row the heuristic misread was carried
    through unmigrated and silently orphaned -- never again recognised as filed."""

    def test_record_stamps_the_schema_version(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ledger.json")
            file_issues.record({}, "fp|id|p.py|finding", "u", path=path)
            with open(path, encoding="utf-8") as fh:
                raw = json.load(fh)
        self.assertEqual(raw["schema_version"], file_issues.LEDGER_SCHEMA_VERSION)
        self.assertEqual(raw["entries"], {"fp|id|p.py|finding": "u"})

    def test_legacy_flat_ledger_is_still_read_and_migrated(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ledger.json")
            legacy = {"fp|SEC-1|%sskill/x.py|finding" % file_issues.repo_root(): "u"}
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(legacy, fh)
            self.assertEqual(file_issues.load_ledger(path=path),
                             {"fp|SEC-1|skill/x.py|finding": "u"})

    def test_a_versioned_ledger_is_not_re_sniffed(self):
        # file_fixmes keys are a bare id -- one '|'-free field. The old
        # heuristic had to guess; a versioned ledger must pass them through
        # untouched rather than re-deciding what shape they are.
        import json
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ledger.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"schema_version": file_issues.LEDGER_SCHEMA_VERSION,
                           "entries": {"FIXME-12": "u"}}, fh)
            self.assertEqual(file_issues.load_ledger(path=path), {"FIXME-12": "u"})

    def test_refuses_a_ledger_from_a_newer_filer(self):
        # Reading it as empty would re-file every finding as a duplicate --
        # the same hazard #run9 COD-B1A closed for a corrupt ledger.
        import json
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ledger.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"schema_version": file_issues.LEDGER_SCHEMA_VERSION + 1,
                           "entries": {}}, fh)
            with self.assertRaises(RuntimeError) as caught:
                file_issues.load_ledger(path=path)
        self.assertIn("newer", str(caught.exception).lower())


class TestCreateIdempotence(unittest.TestCase):
    """#1212: `gh issue create` has been seen exiting 0 with EMPTY stdout under
    GitHub secondary rate limits. The old code assumed that meant the issue was
    not created and retried blind -- so whenever it HAD been created, the retry
    filed a duplicate permanent public issue. Ask before re-creating."""

    def _run_returning(self, *results):
        it = iter(results)

        def _run(cmd, **kw):
            return next(it)
        return _run

    def test_empty_stdout_adopts_an_existing_issue_instead_of_refiling(self):
        listing = '[{"title": "t", "url": "https://gh/issues/42"}]'
        run = self._run_returning(_completed(0, ""), _completed(0, listing))
        with mock.patch.object(file_issues.subprocess, "run", side_effect=run) as r, \
             mock.patch.object(file_issues.time, "sleep"):
            url = file_issues.create("t", "b", ["self-scan"], dry=False)
        self.assertEqual(url, "https://gh/issues/42")
        self.assertEqual(r.call_count, 2)          # probe, then STOP -- no re-create
        self.assertIn("issue", r.call_args_list[1].args[0])
        self.assertIn("list", r.call_args_list[1].args[0])

    def test_a_different_title_is_not_adopted(self):
        listing = '[{"title": "some other issue", "url": "https://gh/issues/9"}]'
        run = self._run_returning(_completed(0, ""), _completed(0, listing),
                                  _completed(0, "https://gh/issues/10"))
        with mock.patch.object(file_issues.subprocess, "run", side_effect=run), \
             mock.patch.object(file_issues.time, "sleep"):
            url = file_issues.create("t", "b", ["self-scan"], dry=False)
        self.assertEqual(url, "https://gh/issues/10")

    def test_an_unreadable_probe_keeps_the_old_retry_behaviour(self):
        # If we cannot tell whether the issue exists, the safe fallback is the
        # behaviour that was already shipping, not a silent give-up.
        run = self._run_returning(_completed(0, ""), _completed(1, "", "boom"),
                                  _completed(0, "https://gh/issues/11"))
        with mock.patch.object(file_issues.subprocess, "run", side_effect=run), \
             mock.patch.object(file_issues.time, "sleep"):
            url = file_issues.create("t", "b", ["self-scan"], dry=False)
        self.assertEqual(url, "https://gh/issues/11")


class TestRetryLadderHasOneOwner(unittest.TestCase):
    """#run11 ARC-A3A / QAL-D1A: triage.gh() and file_issues.create() each had
    their own 5-attempt, 60*attempt ladder with their own rate-limit check. They
    had already diverged once. One ladder, two exhaustion policies."""

    def _file_issues_backoffs(self):
        with mock.patch.object(file_issues.subprocess, "run",
                               return_value=_completed(1, "", "API rate limit exceeded")), \
             mock.patch.object(file_issues.time, "sleep") as slept:
            file_issues.create("t", "b", ["self-scan"], dry=False)
        return [c.args[0] for c in slept.call_args_list]

    def _triage_backoffs(self):
        slept = []
        runner = mock.Mock(return_value=_completed(1, "", "API rate limit exceeded"))
        with self.assertRaises(RuntimeError):
            triage.gh(["gh", "x"], runner=runner, sleep=slept.append)
        return slept

    def test_both_callers_walk_the_same_backoff_schedule(self):
        self.assertEqual(self._file_issues_backoffs(), self._triage_backoffs())

    def test_the_schedule_is_the_shared_one(self):
        self.assertEqual(self._triage_backoffs(),
                         [triage.backoff_seconds(a) for a in range(1, triage.GH_ATTEMPTS)])

    def test_exhaustion_policies_stay_different(self):
        # triage.gh() raises so a caller cannot silently continue; create()
        # returns None so the finding is left un-ledgered for a resumed run.
        with mock.patch.object(file_issues.subprocess, "run",
                               return_value=_completed(1, "", "API rate limit exceeded")), \
             mock.patch.object(file_issues.time, "sleep"):
            self.assertIsNone(file_issues.create("t", "b", ["s"], dry=False))

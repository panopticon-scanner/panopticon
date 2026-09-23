import json
import os
import shutil
import tempfile
import types
import unittest
from unittest import mock

import pytest

import file_issues
import triage


@pytest.fixture(autouse=True)
def _resolvable_gh():
    """A `gh` on the TRUSTED path, so `_gh_bin()` can resolve one.

    #1650 R1: `file_issues._gh_bin` now goes through `triage.gh_bin`, which
    REFUSES rather than falling back to a bare `gh` -- this module creates
    public issues as the automation account, so an unresolvable CLI must stop
    it. Every test here injects a fake runner, so the stub is resolved and
    never launched; it exists to let argv construction be exercised on a
    machine (CI included) that has no gh installed.
    """
    directory = tempfile.mkdtemp(prefix="trusted-bin-")
    path = os.path.join(directory, "gh")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\nexit 97\n")       # resolved, never run
    os.chmod(path, 0o755)
    with mock.patch.object(triage, "TRUSTED_PATH", directory):
        yield path
    shutil.rmtree(directory, ignore_errors=True)


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


def _split_finding(name, rejected=False):
    return {
        **FINDING,
        "fingerprint": "fingerprint-" + name,
        "id": "SEC-" + name,
        "short_title": name,
        "location": {"file": "src/" + name + ".py", "line_start": 7},
        "evidence": {"status": "rejected" if rejected else "advisor_confirmed"},
    }


def _split_report(tmp_path):
    records = {
        "active-inline": _split_finding("active-inline"),
        "active-part": _split_finding("active-part"),
        "rejected-inline": _split_finding("rejected-inline", True),
        "rejected-part": _split_finding("rejected-part", True),
        "rejected-spill": _split_finding("rejected-spill", True),
    }
    report = tmp_path / "report.json"
    report.write_text(json.dumps({
        "findings": [records["active-inline"]],
        "discarded_claims": [records["rejected-inline"]],
        "meta": {"parts": ["part.json"], "discarded_claims_file": "discarded.json"},
    }), encoding="utf-8")
    (tmp_path / "part.json").write_text(json.dumps({
        "findings": [records["active-part"]],
        "discarded_claims": [records["rejected-part"]],
    }), encoding="utf-8")
    (tmp_path / "discarded.json").write_text(json.dumps({
        "discarded_claims": [records["rejected-spill"]],
    }), encoding="utf-8")
    return report, records


def _run_split_main(monkeypatch, report, *options, ledger=None):
    monkeypatch.setattr(file_issues.sys, "argv", [
        "file_issues.py", "--report", str(report), "--report-url",
        "https://example.test/report.json", "--run-label", "run 12",
        "--run-date", "2026-09-23", "--run-state-doc", "run-state.md",
        "--throttle", "0", *options,
    ])
    with mock.patch.object(file_issues, "load_ledger", return_value=ledger or {}) as load, \
            mock.patch.object(file_issues, "create", side_effect=lambda *args, **kwargs:
                              None if args[3] else "https://example.test/issue/1") as create, \
            mock.patch.object(file_issues, "record") as record, \
            mock.patch.object(file_issues.triage, "gh_env", return_value={}) as gh_env:
        file_issues.main()
    return load, create, record, gh_env


@pytest.mark.parametrize(("options", "expected"), [
    ((), ["active-inline", "active-part", "rejected-inline", "rejected-part", "rejected-spill"]),
    (("--only", "findings"), ["active-inline", "active-part"]),
    (("--only", "rejected"), ["rejected-inline", "rejected-part", "rejected-spill"]),
    (("--limit", "3"), ["active-inline", "active-part", "rejected-inline"]),
    (("--only", "rejected", "--limit", "2"), ["rejected-inline", "rejected-part"]),
])
def test_main_files_selected_split_records_in_order(tmp_path, monkeypatch, options, expected):
    report, records = _split_report(tmp_path)
    load, create, record, gh_env = _run_split_main(monkeypatch, report, *options)
    load.assert_called_once_with()
    gh_env.assert_called_once_with()
    assert create.call_count == record.call_count == len(expected)
    for name, created, saved in zip(expected, create.call_args_list, record.call_args_list):
        finding = records[name]
        rejected = name.startswith("rejected")
        title, body, labels, dry, throttle = created.args
        assert title == file_issues.title_for(finding)
        assert "**Fingerprint:** `%s`" % finding["fingerprint"] in body
        assert "**Finding id in report:** `%s`" % finding["id"] in body
        assert "**Location:** `src/%s.py:7`" % name in body
        assert "self-scan run 12, 2026-09-23" in body
        assert "https://example.test/report.json" in body
        assert "run-state.md" in body
        assert ("evidence:rejected" in labels) == rejected
        assert ("false-positive" in labels) == rejected
        assert dry is False and throttle == 0
        assert saved.args[1:] == (
            file_issues.key_for(finding, rejected), "https://example.test/issue/1")


def test_main_skips_existing_split_record(tmp_path, monkeypatch):
    report, records = _split_report(tmp_path)
    existing = file_issues.key_for(records["rejected-part"], True)
    _, create, record, _ = _run_split_main(
        monkeypatch, report, "--only", "rejected", ledger={existing: "existing-url"})
    assert [call.args[0] for call in create.call_args_list] == [
        file_issues.title_for(records[name]) for name in ("rejected-inline", "rejected-spill")]
    assert [call.args[1] for call in record.call_args_list] == [
        file_issues.key_for(records[name], True) for name in ("rejected-inline", "rejected-spill")]


def test_main_dry_run_reads_all_split_records_without_ledger(tmp_path, monkeypatch):
    report, records = _split_report(tmp_path)
    load, create, record, gh_env = _run_split_main(monkeypatch, report, "--dry-run")
    load.assert_not_called()
    gh_env.assert_not_called()
    record.assert_not_called()
    assert [call.args[0] for call in create.call_args_list] == [
        file_issues.title_for(records[name]) for name in records]
    assert all(call.args[3] is True for call in create.call_args_list)


@pytest.mark.parametrize("channel", ["parts", "discarded_claims_file"])
@pytest.mark.parametrize("bad", ["missing", "malformed", "absolute", "traversal", "symlink"])
def test_main_validates_all_continuations_before_side_effects(
        tmp_path, monkeypatch, channel, bad):
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    report, _ = _split_report(report_dir)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    if bad == "missing":
        pointer = "missing.json"
    elif bad == "malformed":
        pointer = "malformed.json"
        (report_dir / pointer).write_text("{", encoding="utf-8")
    elif bad == "absolute":
        pointer = str(outside)
    elif bad == "traversal":
        pointer = "../outside.json"
    else:
        pointer = "outside-link.json"
        (report_dir / pointer).symlink_to(outside)
    data = json.loads(report.read_text(encoding="utf-8"))
    if channel == "parts":
        # A valid earlier part catches implementations that publish as they load.
        data["meta"]["parts"].append(pointer)
    else:
        data["meta"]["discarded_claims_file"] = pointer
    report.write_text(json.dumps(data), encoding="utf-8")
    ledger = tmp_path / file_issues.LEDGER
    ledger.parent.mkdir()
    ledger.write_text('{"sentinel": "unchanged"}', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(file_issues.sys, "argv", [
        "file_issues.py", "--report", str(report), "--throttle", "0"])
    with mock.patch.object(file_issues, "load_ledger") as load, \
            mock.patch.object(file_issues, "create") as create, \
            mock.patch.object(file_issues, "record") as record, \
            mock.patch.object(file_issues.triage, "gh_env") as gh_env:
        with pytest.raises((OSError, json.JSONDecodeError, ValueError)):
            file_issues.main()
    load.assert_not_called()
    create.assert_not_called()
    record.assert_not_called()
    gh_env.assert_not_called()
    assert ledger.read_text(encoding="utf-8") == '{"sentinel": "unchanged"}'


class TestGhBinIsTriagesResolution(unittest.TestCase):
    """#1650 R1 residual: `_gh_bin` must BE `triage.gh_bin()`, not a lookalike.

    The re-review reverted it to `shutil.which("gh") or "gh"` and the suite
    stayed green -- so the hardening this module claims was unpinned. An
    ambient-only gh (first on PATH, absent from the trusted path) is the
    CWE-427 substitute the resolution exists to refuse.
    """

    def test_an_ambient_only_gh_is_refused(self):
        with tempfile.TemporaryDirectory() as ambient, \
                tempfile.TemporaryDirectory() as empty, \
                tempfile.TemporaryDirectory() as home:
            fake = os.path.join(ambient, "gh")
            with open(fake, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\nexit 98\n")
            os.chmod(fake, 0o755)
            with mock.patch.object(triage, "TRUSTED_PATH", empty), \
                    mock.patch.dict(os.environ, {"PATH": ambient, "HOME": home}):
                with self.assertRaises(RuntimeError):
                    file_issues._gh_bin()

    def test_a_trusted_gh_is_the_one_triage_resolves(self):
        self.assertEqual(triage.gh_bin(), file_issues._gh_bin())


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

    def test_defang_reference_and_url_variants_directly(self):
        cases = {
            "owner/repo#123": "owner/repo#\u200b123",
            "HTTPS://github.com/owner/repo/issues/123":
                "H\u200bTTPS://github.com/owner/repo/issues/123",
            "Http://example.test/path": "H\u200bttp://example.test/path",
            "www.example.test/path": "w\u200bww.example.test/path",
            "#123 @team [link](https://example.test/path)":
                "#\u200b123 @\u200bteam [link]\u200b(h\u200bttps://example.test/path)",
        }
        for original, expected in cases.items():
            with self.subTest(original=original):
                self.assertEqual(file_issues.defang(original), expected)
                self.assertEqual(file_issues.defang(expected), expected)
        ordinary = "ordinary prose and `parse()` code span"
        self.assertEqual(file_issues.defang(ordinary), ordinary)

    def test_body_defangs_variants_but_keeps_trusted_report_url(self):
        untrusted = ("owner/repo#123 HTTPS://github.com/owner/repo/issues/123 "
                     "Http://example.test/path www.example.test/path "
                     "#123 @team [link](https://example.test/path) "
                     "ordinary prose and `parse()` code span")
        trusted = "https://example.test/trusted-report.json"
        body = file_issues.body_for(
            self._f(description=untrusted), report_url=trusted)
        self.assertIn(file_issues.defang(untrusted), body)
        self.assertNotIn("owner/repo#123", body)
        self.assertNotIn("HTTPS://github.com/owner/repo/issues/123", body)
        self.assertNotIn("Http://example.test/path", body)
        self.assertNotIn("www.example.test/path", body)
        self.assertIn("ordinary prose and `parse()` code span", body)
        self.assertIn("](%s)" % trusted, body)


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


MALFORMED_LEDGERS = [
    ("list", "[]"),
    ("null", "null"),
    ("scalar", "42"),
    ("missing entries", '{"schema_version": 2}'),
    ("list entries", '{"schema_version": 2, "entries": []}'),
    ("null entries", '{"schema_version": 2, "entries": null}'),
    ("boolean version", '{"schema_version": true, "entries": {}}'),
    ("float version", '{"schema_version": 2.0, "entries": {}}'),
    ("newer version", '{"schema_version": 3, "entries": {}}'),
    ("malformed JSON", "{not json"),
    ("invalid legacy value", '{"key": 42}'),
    ("invalid v2 value", '{"schema_version": 2, "entries": {"key": null}}'),
]


@pytest.mark.parametrize(("shape", "raw"), MALFORMED_LEDGERS)
def test_load_ledger_rejects_malformed_present_state(tmp_path, shape, raw):
    path = tmp_path / "ledger.json"
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(RuntimeError) as caught:
        file_issues.load_ledger(str(path))

    message = str(caught.value).lower()
    assert str(path).lower() in message, shape
    assert any(word in message for word in ("restore", "repair", "upgrade", "delete")), shape
    assert path.read_text(encoding="utf-8") == raw


@pytest.mark.parametrize(("shape", "raw"), MALFORMED_LEDGERS)
def test_record_rejects_malformed_disk_without_mutating_snapshot(tmp_path, shape, raw):
    path = tmp_path / "ledger.json"
    path.write_text(raw, encoding="utf-8")
    snapshot = {"earlier": "https://example.test/issues/1"}
    with mock.patch.object(file_issues.os, "replace", wraps=os.replace) as replace:
        with pytest.raises(RuntimeError) as caught:
            file_issues.record(snapshot, "new", "https://example.test/issues/2", str(path))

    message = str(caught.value).lower()
    assert str(path).lower() in message, shape
    assert any(word in message for word in ("restore", "repair", "upgrade", "delete")), shape
    assert path.read_text(encoding="utf-8") == raw
    assert snapshot == {"earlier": "https://example.test/issues/1"}
    assert not path.with_name(path.name + ".tmp").exists()
    replace.assert_not_called()


def test_empty_legacy_and_v2_ledgers_are_valid(tmp_path):
    path = tmp_path / "ledger.json"
    for raw in ("{}", '{"schema_version": 2, "entries": {}}'):
        path.write_text(raw, encoding="utf-8")
        assert file_issues.load_ledger(str(path)) == {}
        snapshot = {}
        file_issues.record(snapshot, "new", "https://example.test/issues/1", str(path))
        assert snapshot == {"new": "https://example.test/issues/1"}
        assert file_issues.load_ledger(str(path)) == snapshot


def test_record_migrates_legacy_key_and_preserves_v2_key(tmp_path):
    path = tmp_path / "ledger.json"
    legacy_key = "fp|SEC-1|%sskill/x.py|finding" % file_issues.repo_root()
    path.write_text(json.dumps({legacy_key: "url-old"}), encoding="utf-8")
    file_issues.record({}, "new", "url-new", str(path))
    assert file_issues.load_ledger(str(path)) == {
        "fp|SEC-1|skill/x.py|finding": "url-old", "new": "url-new"}

    path.write_text(json.dumps({"schema_version": 2,
                                "entries": {legacy_key: "url-old"}}), encoding="utf-8")
    file_issues.record({}, "new", "url-new", str(path))
    assert file_issues.load_ledger(str(path)) == {legacy_key: "url-old", "new": "url-new"}


def test_main_rejects_malformed_ledger_before_github_calls(tmp_path, monkeypatch):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": [FINDING]}), encoding="utf-8")
    ledger = tmp_path / file_issues.LEDGER
    ledger.parent.mkdir()
    ledger.write_text("[]", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with mock.patch.object(file_issues.sys, "argv", ["file_issues.py", "--report", str(report)]), \
            mock.patch.object(file_issues.triage, "gh_env") as gh_env, \
            mock.patch.object(file_issues, "create", return_value="url") as create:
        with pytest.raises(RuntimeError):
            file_issues.main()
    gh_env.assert_not_called()
    create.assert_not_called()
    assert ledger.read_text(encoding="utf-8") == "[]"


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

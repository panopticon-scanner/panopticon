import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
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


@pytest.mark.parametrize(("finding", "rejected", "expected"), [
    ({}, False, ["self-scan", "severity:info", "evidence:unverified"]),
    ({"severity": "critical", "evidence": {"status": "tool_confirmed"}}, False,
     ["self-scan", "severity:critical", "evidence:tool-confirmed"]),
    ({"severity": "UNKNOWN", "evidence": {"status": "unknown"}}, False,
     ["self-scan", "severity:info", "evidence:unverified"]),
    ({"severity": "HIGH", "evidence": {"status": "advisor_confirmed"},
      "panel": "security"}, False,
     ["self-scan", "severity:high", "evidence:advisor-confirmed", "panel:security"]),
    ({"severity": "INFO", "category": "style", "evidence": {"status": "rejected"}}, True,
     ["self-scan", "severity:info", "evidence:rejected", "false-positive"]),
    ({"severity": "HIGH", "category": "style"}, False,
     ["self-scan", "severity:high", "evidence:unverified", "cosmetic"]),
    ({"severity": "INFO"}, False,
     ["self-scan", "severity:info", "evidence:unverified", "cosmetic"]),
])
def test_labels_for_exact_order_and_cosmetic_rule(finding, rejected, expected):
    assert file_issues.labels_for(finding, rejected=rejected) == expected


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
    load.assert_called_once_with(file_issues.LEDGER)
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
        monkeypatch, report, "--only", "rejected", ledger={existing: "https://github.com/panopticon-scanner/panopticon/issues/1"})
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

    def test_title_residual_autolinks_are_defanged(self):
        title = file_issues.title_for(self._f(short_title="GH-123 _www.example.test"))
        self.assertNotIn("GH-123", title)
        self.assertNotIn("_www.example.test", title)
        self.assertIn("GH-\u200b123", title)
        self.assertIn("_w\u200bww.example.test", title)

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
                     "Http://example.test/path www.example.test/path GH-123 _www.example.test "
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
        self.assertNotIn("GH-123", body)
        self.assertNotIn("_www.example.test", body)
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


# Create is a non-idempotent mutation: ambiguous acceptance never retries.
@pytest.mark.parametrize("response", ["timeout", "empty", "transport", "nonzero", "invalid-url"])
def test_durable_create_adopts_exact_marker(tmp_path, monkeypatch, response):
    path = str(tmp_path / "ledger.json")
    calls = []
    posted = []
    url = "https://github.com/owner/project/issues/42"

    def run(cmd, **kwargs):
        calls.append(cmd)
        assert kwargs["timeout"] == file_issues.GH_CREATE_TIMEOUT
        assert kwargs["env"] == {"TOKEN": "fake"}
        if cmd[1] == "api" and cmd[2].startswith("repos/"):
            assert cmd[2] == "repos/owner/project"
            return _completed(stdout='{"full_name":"owner/project","permissions":{"admin":true}}')
        if cmd[2] == "create":
            assert cmd[cmd.index("--repo") + 1] == "owner/project"
            posted.append(cmd[cmd.index("--body") + 1])
            pending = json.loads((tmp_path / "ledger.json.pending.json").read_text())
            assert next(iter(pending["entries"].values()))["body"] == posted[0]
            if response == "timeout":
                raise file_issues.subprocess.TimeoutExpired(cmd, 60)
            if response == "transport":
                raise OSError("connection lost")
            if response == "nonzero":
                return _completed(1, stderr="remote response lost")
            if response == "invalid-url":
                return _completed(stdout="https://github.com/other/project/issues/1")
            return _completed()
        assert "repo:owner/project is:issue " in parse_qs(urlsplit(cmd[2]).query)["q"][0]
        return _completed(stdout=json.dumps({"incomplete_results": False, "total_count": 1,
                                             "items": [{"title": "same title", "body": posted[0], "html_url": url}]}))

    monkeypatch.setattr(file_issues.subprocess, "run", run)
    kwargs = dict(env={"TOKEN": "fake"}, repo="owner/project",
                  operation_id="fp|id|p.py|finding", ledger_path=path)
    assert file_issues.create("same title", "body", ["self-scan"], False, **kwargs) == url
    assert file_issues.load_ledger(path) == {kwargs["operation_id"]: url}
    count = len(calls)
    assert file_issues.create("same title", "body", ["self-scan"], False, **kwargs) == url
    assert len(calls) == count
    assert len(posted) == 1


@pytest.mark.parametrize("probe", ["failed", "invalid", "empty", "same-title", "full", "duplicate", "wrong-repo", "incomplete", "count-mismatch", "wrong-content", "pull-request"])
def test_pending_probe_refuses_replay(tmp_path, monkeypatch, probe):
    path = str(tmp_path / "ledger.json")
    creates = []
    def run(cmd, **kwargs):
        if cmd[1] == "api" and cmd[2].startswith("repos/"):
            return _completed(stdout=json.dumps({"full_name": file_issues.REPO_SLUG,
                                                "permissions": {"admin": True}}))
        if cmd[2] == "create":
            creates.append(cmd[cmd.index("--body") + 1])
            raise file_issues.subprocess.TimeoutExpired(cmd, 60)
        row = {"title": "same title", "body": creates[0],
               "html_url": "https://github.com/" + file_issues.REPO_SLUG + "/issues/1"}
        if probe == "failed":
            return _completed(1)
        if probe == "invalid":
            return _completed(stdout="{}")
        if probe == "same-title":
            row["body"] = "another finding"
        if probe == "wrong-repo":
            row["html_url"] = "https://github.com/other/project/issues/1"
        if probe == "wrong-content":
            row["body"] = "edited\n" + row["body"]
        if probe == "pull-request":
            row["pull_request"] = {}
        rows = [] if probe == "empty" else [row] * (100 if probe == "full" else 2 if probe == "duplicate" else 1)
        return _completed(stdout=json.dumps({"incomplete_results": probe == "incomplete",
                                            "total_count": len(rows) + (probe == "count-mismatch"),
                                            "items": rows}))
    monkeypatch.setattr(file_issues.subprocess, "run", run)
    for _ in range(2):
        with pytest.raises(RuntimeError, match="pending|reconcil"):
            file_issues.create("same title", "body", [], False, env={},
                               operation_id="k", ledger_path=path)
    assert len(creates) == 1
    assert not Path(path).exists()
    assert (tmp_path / "ledger.json.pending.json").exists()


@pytest.mark.parametrize("permissions", [None, {}, {"admin": False}, {"admin": 1}])
def test_create_requires_authenticated_admin(tmp_path, monkeypatch, permissions):
    calls = []
    def run(cmd, **kwargs):
        calls.append(cmd)
        return _completed(stdout=json.dumps({"full_name": file_issues.REPO_SLUG,
                                            "permissions": permissions}))
    monkeypatch.setattr(file_issues.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="admin preflight"):
        file_issues.create("t", "b", [], False, env={}, ledger_path=str(tmp_path / "l"))
    assert len(calls) == 1 and calls[0][1] == "api"
    assert not (tmp_path / "l.pending.json").exists()


@pytest.mark.parametrize("data", ["{}", "[]", "null", "bad json",
                                    '{"full_name":"other/repo","permissions":{"admin":true}}'])
def test_preflight_rejects_malformed_or_wrong_repo(tmp_path, monkeypatch, data):
    run = mock.Mock(return_value=_completed(stdout=data))
    monkeypatch.setattr(file_issues.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="admin preflight"):
        file_issues.create("t", "b", [], False, env={}, ledger_path=str(tmp_path / "l"))
    assert run.call_count == 1


@pytest.mark.parametrize("suffix,content", [('', '[]'), ('.pending.json', '[]'),
    ('.pending.json', '{"schema_version":true,"entries":{}}'),
    ('.pending.json', '{"schema_version":1,"entries":{"bad":{}}}')])
def test_create_refuses_corrupt_state_before_any_call(tmp_path, monkeypatch, suffix, content):
    path = tmp_path / "ledger"
    corrupt = tmp_path / ("ledger" + suffix)
    corrupt.write_text(content)
    run = mock.Mock(side_effect=AssertionError("no network"))
    monkeypatch.setattr(file_issues.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="ledger"):
        file_issues.create("t", "b", [], False, env={}, ledger_path=str(path))
    run.assert_not_called()
    assert corrupt.read_text() == content


def test_dry_create_writes_nothing_and_never_calls_network(tmp_path, monkeypatch):
    run = mock.Mock(side_effect=AssertionError("no network"))
    monkeypatch.setattr(file_issues.subprocess, "run", run)
    assert file_issues.create("t", "b", [], True, ledger_path=str(tmp_path / "nested/l")) is None
    assert list(tmp_path.iterdir()) == []
    run.assert_not_called()


def test_completed_key_cannot_be_adopted_in_another_repository(tmp_path, monkeypatch):
    path = str(tmp_path / "l")
    file_issues.record({}, "key", "https://github.com/other/repo/issues/1", path)
    run = mock.Mock(side_effect=AssertionError("no network"))
    monkeypatch.setattr(file_issues.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="different repository"):
        file_issues.create("t", "b", [], False, env={}, operation_id="key", ledger_path=path)
    with pytest.raises(RuntimeError, match="selected repository"):
        file_issues.load_filing_ledger(path, file_issues.REPO_SLUG)
    run.assert_not_called()


def test_crash_after_acceptance_recovers_without_second_create(tmp_path, monkeypatch):
    path = str(tmp_path / "l")
    url = "https://github.com/" + file_issues.REPO_SLUG + "/issues/1"
    posted = []
    def run(cmd, **kwargs):
        if cmd[1] == "api" and cmd[2].startswith("repos/"):
            return _completed(stdout=json.dumps({"full_name": file_issues.REPO_SLUG,
                                                "permissions": {"admin": True}}))
        if cmd[2] == "create":
            posted.append(cmd[cmd.index("--body") + 1])
            return _completed(stdout=url)
        return _completed(stdout=json.dumps({"incomplete_results": False, "total_count": 1,
                                             "items": [{"title": "t", "body": posted[0], "html_url": url}]}))
    monkeypatch.setattr(file_issues.subprocess, "run", run)
    args = dict(env={}, operation_id="key", ledger_path=path)
    with mock.patch.object(file_issues, "record", side_effect=OSError("disk full")):
        with pytest.raises(OSError, match="disk full"):
            file_issues.create("t", "b", [], False, **args)
    assert file_issues.create("t", "b", [], False, **args) == url
    assert len(posted) == 1


def test_crash_after_primary_write_completes_without_network(tmp_path, monkeypatch):
    path = str(tmp_path / "l")
    url = "https://github.com/" + file_issues.REPO_SLUG + "/issues/1"
    identity, intent = file_issues._intent(file_issues.REPO_SLUG, "finding", "key", "t", "b", [])
    (tmp_path / "l.pending.json").write_text(json.dumps({"schema_version": 1, "entries": {identity: intent}}))
    file_issues.record({}, "key", url, path)
    run = mock.Mock(side_effect=AssertionError("no network"))
    monkeypatch.setattr(file_issues.subprocess, "run", run)
    assert file_issues.load_filing_ledger(path, file_issues.REPO_SLUG) == {"key": url}
    assert json.loads((tmp_path / "l.pending.json").read_text())["entries"][identity]["state"] == "complete"
    run.assert_not_called()


def test_concurrent_observer_cannot_create_inflight_intent(tmp_path, monkeypatch):
    # Reentrant observer runs precisely while the owner is inside its network
    # create, also proving the product lock is not held around that I/O.
    path = str(tmp_path / "l")
    creates = []
    args = dict(env={}, operation_id="key", ledger_path=path)
    url = "https://github.com/" + file_issues.REPO_SLUG + "/issues/1"
    def run(cmd, **kwargs):
        if cmd[1] == "api" and cmd[2].startswith("repos/"):
            return _completed(stdout=json.dumps({"full_name": file_issues.REPO_SLUG,
                                                "permissions": {"admin": True}}))
        if cmd[2] == "create":
            creates.append(cmd)
            with pytest.raises(RuntimeError, match="pending"):
                file_issues.create("t", "b", [], False, **args)
            return _completed(stdout=url)
        return _completed(stdout='{"incomplete_results":false,"total_count":0,"items":[]}')
    monkeypatch.setattr(file_issues.subprocess, "run", run)
    assert file_issues.create("t", "b", [], False, **args) == url
    assert len(creates) == 1


def test_pending_content_change_refuses_mutation(tmp_path, monkeypatch):
    path = str(tmp_path / "l")
    identity, intent = file_issues._intent(file_issues.REPO_SLUG, "finding", "key", "t", "old", [])
    (tmp_path / "l.pending.json").write_text(json.dumps({"schema_version": 1, "entries": {identity: intent}}))
    run = mock.Mock(return_value=_completed(stdout=json.dumps({"full_name": file_issues.REPO_SLUG,
                                                              "permissions": {"admin": True}})))
    monkeypatch.setattr(file_issues.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="content changed"):
        file_issues.create("t", "new", [], False, env={}, operation_id="key", ledger_path=path)
    assert run.call_count == 1 and run.call_args.args[0][1] == "api"


@pytest.mark.parametrize("repo", ["", "owner", "../repo", "owner/repo/extra", "-o/repo", "owner/repo?x"])
def test_invalid_repo_rejected_before_runner(tmp_path, monkeypatch, repo):
    run = mock.Mock(side_effect=AssertionError("no network"))
    monkeypatch.setattr(file_issues.subprocess, "run", run)
    with pytest.raises(ValueError, match="slug"):
        file_issues.create("t", "b", [], False, repo=repo, ledger_path=str(tmp_path / "l"))
    run.assert_not_called()


def test_same_title_distinct_keys_create_distinct_operations(tmp_path, monkeypatch):
    posted = []
    def run(cmd, **kwargs):
        if cmd[1] == "api":
            return _completed(stdout=json.dumps({"full_name": file_issues.REPO_SLUG,
                                                "permissions": {"admin": True}}))
        posted.append(cmd[cmd.index("--body") + 1])
        return _completed(stdout="https://github.com/" + file_issues.REPO_SLUG + "/issues/%d" % len(posted))
    monkeypatch.setattr(file_issues.subprocess, "run", run)
    path = str(tmp_path / "l")
    for key in ("fp1|id|a.py|finding", "fp2|id|b.py|finding"):
        file_issues.create("same title", "body", [], False, env={},
                           operation_id=key, ledger_path=path)
    assert len(posted) == 2 and posted[0] != posted[1]
    assert len(file_issues.load_ledger(path)) == 2


def test_record_preserves_newer_rows_and_rejects_conflicting_key(tmp_path):
    path = str(tmp_path / "l")
    file_issues.record({}, "existing", "new-url", path)
    stale = {"existing": "old-url"}
    file_issues.record(stale, "new-key", "new-key-url", path)
    assert stale["existing"] == "new-url"
    before = Path(path).read_bytes()
    with pytest.raises(RuntimeError, match="different URL"):
        file_issues.record({}, "existing", "conflict", path)
    assert Path(path).read_bytes() == before


@pytest.mark.parametrize("keyword", [False, True])
def test_legacy_find_existing_issue_signature_is_safe(keyword):
    runner = mock.Mock(side_effect=AssertionError("title alone must not query or adopt"))
    if keyword:
        assert file_issues.find_existing_issue(title="same title", runner=runner) is None
    else:
        assert file_issues.find_existing_issue("same title", runner) is None
    runner.assert_not_called()


@pytest.mark.parametrize("matches", [True, False])
def test_find_existing_issue_optional_intent_preserves_strict_probe(matches):
    repo = "owner/project"
    _, intent = file_issues._intent(repo, "finding", "key", "same title", "body", [])
    row = {"title": "same title", "body": intent["body"] if matches else "different finding",
           "html_url": "https://github.com/owner/project/issues/1"}
    runner = mock.Mock(return_value=_completed(stdout=json.dumps({
        "incomplete_results": False, "total_count": 1, "items": [row]})))
    if matches:
        assert file_issues.find_existing_issue(
            title="same title", runner=runner, repo=repo, intent=intent) == row["html_url"]
    else:
        with pytest.raises(RuntimeError, match="pending create unresolved"):
            file_issues.find_existing_issue("same title", runner, repo=repo, intent=intent)
    assert runner.call_count == 1


@pytest.mark.parametrize("title,repo", [("other title", "owner/project"), ("t", "other/project")])
def test_find_existing_issue_refuses_mismatched_intent(title, repo):
    _, intent = file_issues._intent("owner/project", "finding", "key", "t", "body", [])
    runner = mock.Mock(side_effect=AssertionError("mismatched intent must not query"))
    with pytest.raises(ValueError, match="bound intent"):
        file_issues.find_existing_issue(title, runner, repo=repo, intent=intent)
    runner.assert_not_called()

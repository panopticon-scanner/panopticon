"""Parameterization + parse guards for file_fixmes (#606).

The DOC path, DOC_URL, and 'run-2 self-scan (2026-08-04)' body text were
hardcoded, so filing a later run's FIXMEs required editing the script. They are
now flags; defaults preserve run-2 behavior. Also pins the section parser.
"""
import os
import json
import shutil
import tempfile
import unittest
from unittest import mock

import pytest

import file_fixmes


FIXME_DOC = """# Run FIXMEs

## FIXME-1 — Scout omits a schema field
`bug`, `panel:code`

The scout returned a ScopeProfile missing `depth`.

Second paragraph.

## FIXME-2 — Group names are ._N
`enhancement`

Chunk names reshuffle across runs.

---

## Already fixed
Commentary that must not be filed.
"""


class TestParse(unittest.TestCase):
    def _doc(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "fixmes.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(FIXME_DOC)
        return path

    def test_parses_sections_and_stops_at_trailing_rule(self):
        fixmes = file_fixmes.parse(self._doc())
        self.assertEqual([f["id"] for f in fixmes], ["FIXME-1", "FIXME-2"])
        self.assertEqual(fixmes[0]["title"], "Scout omits a schema field")
        self.assertEqual(fixmes[0]["labels"], ["bug", "panel:code"])
        # label line dropped from body; body content retained
        self.assertNotIn("`bug`", fixmes[0]["body"])
        self.assertIn("missing `depth`", fixmes[0]["body"])
        self.assertNotIn("Already fixed", " ".join(f["body"] for f in fixmes))


class TestBodyProvenance(unittest.TestCase):
    F = {"id": "FIXME-1", "title": "t", "labels": [], "body": "what happened"}

    def test_defaults_describe_run2(self):
        body = file_fixmes.body_for(self.F)
        self.assertIn("run-2 self-scan (2026-08-04", body)
        self.assertIn(file_fixmes.DOC, body)
        self.assertIn("panopticon-scanner/panopticon", body)  # not stale psyberone

    def test_overrides_thread_through(self):
        body = file_fixmes.body_for(
            self.F, doc="docs/superpowers/2026-08-08-run3-fixmes.md",
            doc_url="https://example.test/run3-fixmes.md",
            run_label="run-3", run_date="2026-08-08")
        self.assertIn("run-3 self-scan (2026-08-08", body)
        self.assertIn("https://example.test/run3-fixmes.md", body)
        self.assertIn("2026-08-08-run3-fixmes.md", body)
        self.assertNotIn("run-2 self-scan (2026-08-04", body)


class TestScrubbing(unittest.TestCase):
    def test_title_and_body_scrub_repo_root(self):
        """SEC-B2C: absolute local paths in FIXME text must not reach public issues."""
        root = file_fixmes.file_issues.repo_root()
        f = {
            "id": "FIXME-99",
            "title": "Broken on %ssrc/main.py" % root,
            "labels": ["bug"],
            "body": "Crash happens under %ssrc/main.py when loaded." % root,
        }
        body = file_fixmes.body_for(f)
        self.assertNotIn(root, body)
        self.assertIn("src/main.py", body)
        title = file_fixmes.file_issues.scrub(
            file_fixmes.file_issues.defang("%s — %s" % (f["id"], f["title"])))
        self.assertNotIn(root, title)


def test_main_rejects_malformed_ledger_before_github_calls(tmp_path):
    doc = tmp_path / "fixmes.md"
    doc.write_text(FIXME_DOC, encoding="utf-8")
    ledger = tmp_path / "ledger.json"
    ledger.write_text('{"schema_version": 2, "entries": []}', encoding="utf-8")
    with mock.patch.object(file_fixmes, "LEDGER", str(ledger)), \
            mock.patch.object(file_fixmes.file_issues.sys, "argv",
                              ["file_fixmes.py", "--doc", str(doc)]), \
            mock.patch.object(file_fixmes.triage, "gh_env") as gh_env, \
            mock.patch.object(file_fixmes, "create", return_value="url") as create:
        with pytest.raises(RuntimeError):
            file_fixmes.main()
    gh_env.assert_not_called()
    create.assert_not_called()
    assert ledger.read_text(encoding="utf-8") == '{"schema_version": 2, "entries": []}'


def test_run_scoped_keys_resume_and_preserve_legacy_default(tmp_path):
    doc = tmp_path / "fixmes.md"
    doc.write_text(FIXME_DOC, encoding="utf-8")
    ledger = tmp_path / "ledger.json"
    created = []

    def file_once(*args, **kwargs):
        created.append(args)
        return "https://github.com/panopticon-scanner/panopticon/issues/%d" % len(created)

    def run(*flags):
        with mock.patch.object(file_fixmes, "LEDGER", str(ledger)), \
                mock.patch.object(file_fixmes.file_issues.sys, "argv",
                                  ["file_fixmes.py", "--doc", str(doc), *flags]), \
                mock.patch.object(file_fixmes.triage, "gh_env", return_value={}), \
                mock.patch.object(file_fixmes, "create", side_effect=file_once):
            file_fixmes.main()

    run("--run-label", "run-3", "--doc-url", "https://example.test/doc",
        "--run-date", "2026-09-23")
    assert "run-3 self-scan (2026-09-23" in created[0][1]
    assert "https://example.test/doc" in created[0][1]
    run("--run-label", "run-3")
    assert len(created) == 2
    entries = json.loads(ledger.read_text(encoding="utf-8"))["entries"]
    assert set(entries) == {json.dumps(["run-3", "FIXME-1"], separators=(",", ":")),
                            json.dumps(["run-3", "FIXME-2"], separators=(",", ":"))}

    ledger.write_text(json.dumps({"FIXME-1": "https://github.com/panopticon-scanner/panopticon/issues/99"}), encoding="utf-8")
    created.clear()
    with mock.patch.object(file_fixmes, "LEDGER", str(ledger)), \
            mock.patch.object(file_fixmes, "DOC", str(doc)), \
            mock.patch.object(file_fixmes.file_issues.sys, "argv", ["file_fixmes.py"]), \
            mock.patch.object(file_fixmes.triage, "gh_env", return_value={}), \
            mock.patch.object(file_fixmes, "create", side_effect=file_once):
        file_fixmes.main()
    assert len(created) == 1
    entries = json.loads(ledger.read_text(encoding="utf-8"))["entries"]
    assert "FIXME-1" in entries
    assert json.dumps(["run-2", "FIXME-2"], separators=(",", ":")) in entries
    created.clear()
    run("--run-label", "run-3")
    assert len(created) == 2  # the run-2 bare key never hides run-3's FIXME-1


if __name__ == "__main__":
    unittest.main()


def test_delegated_create_keeps_finding_and_fixme_intents_separate(tmp_path, monkeypatch):
    assert file_fixmes.create is file_fixmes.file_issues.create
    module = file_fixmes.file_issues
    posted = []
    def run(cmd, **kwargs):
        if cmd[1] == "api":
            return mock.Mock(returncode=0, stdout=json.dumps({
                "full_name": module.REPO_SLUG, "permissions": {"admin": True}}))
        assert cmd[2] == "create"
        posted.append(cmd[cmd.index("--body") + 1])
        return mock.Mock(returncode=0, stdout="https://github.com/" + module.REPO_SLUG + "/issues/%d" % len(posted))
    monkeypatch.setattr(module, "_gh_bin", lambda: "/fake/gh")
    monkeypatch.setattr(module.subprocess, "run", run)
    # Even equal caller keys/content get distinct operation markers by kind.
    for kind in ("finding", "fixme"):
        file_fixmes.create("t", "b", [], False, env={}, operation_id="same-key",
                           ledger_path=str(tmp_path / kind), kind=kind)
    assert len(posted) == 2 and posted[0] != posted[1]
    for kind in ("finding", "fixme"):
        pending = json.loads((tmp_path / (kind + ".pending.json")).read_text())
        assert next(iter(pending["entries"].values()))["kind"] == kind


def test_main_passes_run_key_and_repo_to_delegated_create(tmp_path, monkeypatch):
    doc = tmp_path / "fixmes.md"
    doc.write_text(FIXME_DOC)
    ledger = str(tmp_path / "ledger")
    monkeypatch.setattr(file_fixmes, "LEDGER", ledger)
    monkeypatch.setattr(file_fixmes.file_issues.sys, "argv", [
        "file_fixmes.py", "--doc", str(doc), "--repo", "owner/project",
        "--run-label", "run-8", "--dry-run"])
    create = mock.Mock(return_value=None)
    monkeypatch.setattr(file_fixmes, "create", create)
    file_fixmes.main()
    assert create.call_count == 2
    for index, call in enumerate(create.call_args_list, 1):
        assert call.kwargs["repo"] == "owner/project"
        assert call.kwargs["kind"] == "fixme"
        assert call.kwargs["ledger_path"] == ledger
        assert call.kwargs["operation_id"] == file_fixmes.key_for("run-8", "FIXME-%d" % index)
    assert not (tmp_path / "ledger").exists()
    assert not (tmp_path / "ledger.pending.json").exists()
